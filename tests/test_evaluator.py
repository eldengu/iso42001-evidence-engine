"""
pytest suite for the Zero-Trust ISO/IEC 42001 evidence engine.

Covers:
* pass scenario (clean ASL-3 input)
* fail scenario (high PII, disabled logs)
* HMAC signature validity and tamper detection
* Claude artifact JSON structure
* CLI round-trip (run -> verify)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from src.artifact_generator import (
    export_claude_artifact,
    render_html_dashboard,
    render_react_component,
)
from src.cli import app
from src.evaluator import ZeroTrustEvaluator
from src.schemas import (
    ASLLevel,
    ClaudeDashboardArtifactPayload,
    ControlStatus,
    ISOControlCategory,
    ZeroTrustEvidenceInput,
    ZeroTrustProof,
)

SECRET = "unit-test-secret-key-0123456789"
DATASET_DIGEST = hashlib.sha256(b"synthetic-manifest").hexdigest()
ALL_CONTROLS = {c for c in ISOControlCategory}


@pytest.fixture()
def evaluator() -> ZeroTrustEvaluator:
    return ZeroTrustEvaluator(SECRET)


@pytest.fixture()
def clean_input() -> ZeroTrustEvidenceInput:
    return ZeroTrustEvidenceInput(
        system_id="claude-rag-assistant-v3",
        asl_target=ASLLevel.ASL_3,
        dataset_sha256=DATASET_DIGEST,
        pii_scan_score=0.02,
        event_logging_enabled=True,
        runtime_guardrail_active=True,
    )


@pytest.fixture()
def dirty_input() -> ZeroTrustEvidenceInput:
    return ZeroTrustEvidenceInput(
        system_id="shadow-llm-prototype",
        asl_target=ASLLevel.ASL_3,
        dataset_sha256=DATASET_DIGEST,
        pii_scan_score=0.62,
        event_logging_enabled=False,
        runtime_guardrail_active=False,
    )


def _by_control(proofs: list[ZeroTrustProof]) -> dict[ISOControlCategory, ZeroTrustProof]:
    return {p.control_id: p for p in proofs}


# --------------------------------------------------------------------------- #
# Pass / fail scenarios
# --------------------------------------------------------------------------- #


def test_clean_input_passes_every_control(evaluator, clean_input):
    proofs = evaluator.evaluate_system(clean_input)

    assert {p.control_id for p in proofs} == ALL_CONTROLS
    assert all(p.status is ControlStatus.PASS for p in proofs), [p.summary for p in proofs]
    assert all(p.asl_level is ASLLevel.ASL_3 for p in proofs)
    assert evaluator.compute_overall_score(proofs) == 100.0


def test_high_pii_and_disabled_logging_fail(evaluator, dirty_input):
    proofs = _by_control(evaluator.evaluate_system(dirty_input))

    assert proofs[ISOControlCategory.A_7_4].status is ControlStatus.FAIL
    assert proofs[ISOControlCategory.A_6_2_8].status is ControlStatus.FAIL
    assert proofs[ISOControlCategory.A_9_4].status is ControlStatus.FAIL
    # ASL-3 requires strict logging + guardrails, so the impact assessment fails too.
    assert proofs[ISOControlCategory.A_5_4].status is ControlStatus.FAIL
    assert "event logging" in proofs[ISOControlCategory.A_5_4].summary
    # Provenance digest is still present, so A.4.2 passes.
    assert proofs[ISOControlCategory.A_4_2].status is ControlStatus.PASS

    score = evaluator.compute_overall_score(list(proofs.values()))
    assert score == pytest.approx(20.0)


def test_pii_review_band_yields_needs_review(evaluator, clean_input):
    borderline = clean_input.model_copy(update={"pii_scan_score": 0.15})
    proofs = _by_control(evaluator.evaluate_system(borderline))
    assert proofs[ISOControlCategory.A_7_4].status is ControlStatus.NEEDS_REVIEW


def test_asl_gating_relaxed_below_asl3(evaluator):
    low_tier = ZeroTrustEvidenceInput(
        system_id="internal-classifier",
        asl_target=ASLLevel.ASL_2,
        dataset_sha256=DATASET_DIGEST,
        pii_scan_score=0.0,
        event_logging_enabled=True,
        runtime_guardrail_active=False,
    )
    proofs = _by_control(evaluator.evaluate_system(low_tier))
    # ASL-2 impact assessment passes with logging alone...
    assert proofs[ISOControlCategory.A_5_4].status is ControlStatus.PASS
    # ...but the standalone guardrail control still fails.
    assert proofs[ISOControlCategory.A_9_4].status is ControlStatus.FAIL


def test_asl4_requires_manual_review_even_when_clean(evaluator, clean_input):
    asl4 = clean_input.model_copy(update={"asl_target": ASLLevel.ASL_4})
    proofs = _by_control(evaluator.evaluate_system(asl4))
    assert proofs[ISOControlCategory.A_5_4].status is ControlStatus.NEEDS_REVIEW


def test_missing_dataset_digest_fails_resource_documentation(evaluator, clean_input):
    no_digest = clean_input.model_copy(update={"dataset_sha256": None})
    proofs = _by_control(evaluator.evaluate_system(no_digest))
    assert proofs[ISOControlCategory.A_4_2].status is ControlStatus.FAIL


def test_overall_score_weights_and_empty_list(evaluator, clean_input):
    assert evaluator.compute_overall_score([]) == 0.0
    proofs = evaluator.evaluate_system(clean_input)
    # Force one NEEDS_REVIEW and one FAIL via model_copy (signatures irrelevant here).
    mixed = [
        proofs[0].model_copy(update={"status": ControlStatus.NEEDS_REVIEW}),
        proofs[1].model_copy(update={"status": ControlStatus.FAIL}),
        *proofs[2:],
    ]
    # 3 PASS (3.0) + 1 NEEDS_REVIEW (0.5) + 1 FAIL (0.0) = 3.5 / 5 = 70%
    assert evaluator.compute_overall_score(mixed) == pytest.approx(70.0)


# --------------------------------------------------------------------------- #
# Cryptography
# --------------------------------------------------------------------------- #


def test_signatures_verify_and_are_well_formed(evaluator, clean_input):
    proofs = evaluator.evaluate_system(clean_input)
    assert evaluator.verify_all(proofs)
    for p in proofs:
        assert len(p.signature) == 64 and int(p.signature, 16) >= 0
        assert len(p.evidence_hash) == 64 and int(p.evidence_hash, 16) >= 0
        assert p.signature != "0" * 64
    # Every control gets a distinct evidence hash and signature.
    assert len({p.evidence_hash for p in proofs}) == len(proofs)
    assert len({p.signature for p in proofs}) == len(proofs)


def test_tampered_proof_fails_verification(evaluator, dirty_input):
    proofs = evaluator.evaluate_system(dirty_input)
    failing = next(p for p in proofs if p.status is ControlStatus.FAIL)

    # Proofs are frozen: direct mutation is rejected.
    with pytest.raises(ValidationError):
        failing.status = ControlStatus.PASS  # type: ignore[misc]

    forged = failing.model_copy(update={"status": ControlStatus.PASS})
    assert not evaluator.verify_proof(forged)

    relabelled = failing.model_copy(update={"summary": "All good."})
    assert not evaluator.verify_proof(relabelled)

    # Signature survives a JSON round-trip.
    restored = ZeroTrustProof.model_validate_json(failing.model_dump_json())
    assert evaluator.verify_proof(restored)


def test_wrong_secret_cannot_verify(clean_input):
    signer = ZeroTrustEvaluator(SECRET)
    impostor = ZeroTrustEvaluator("a-completely-different-secret-key")
    proofs = signer.evaluate_system(clean_input)
    assert signer.verify_all(proofs)
    assert not impostor.verify_all(proofs)


def test_evaluator_rejects_weak_secret():
    with pytest.raises(ValueError):
        ZeroTrustEvaluator("short")
    with pytest.raises(TypeError):
        ZeroTrustEvaluator(b"bytes-are-not-allowed-here")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Schema hardening
# --------------------------------------------------------------------------- #


def test_input_schema_rejects_raw_data_fields_and_bad_values():
    base = {
        "system_id": "sys-1",
        "asl_target": "ASL-2",
        "dataset_sha256": DATASET_DIGEST,
        "pii_scan_score": 0.0,
        "event_logging_enabled": True,
        "runtime_guardrail_active": True,
    }
    with pytest.raises(ValidationError):
        ZeroTrustEvidenceInput.model_validate({**base, "raw_records": ["alice@example.com"]})
    with pytest.raises(ValidationError):
        ZeroTrustEvidenceInput.model_validate({**base, "pii_scan_score": 1.5})
    with pytest.raises(ValidationError):
        ZeroTrustEvidenceInput.model_validate({**base, "dataset_sha256": "not-a-digest"})
    # Upper-case digests are normalised.
    upper = ZeroTrustEvidenceInput.model_validate({**base, "dataset_sha256": DATASET_DIGEST.upper()})
    assert upper.dataset_sha256 == DATASET_DIGEST


# --------------------------------------------------------------------------- #
# Artifact export
# --------------------------------------------------------------------------- #


def test_claude_artifact_json_structure(evaluator, clean_input):
    proofs = evaluator.evaluate_system(clean_input)
    payload = export_claude_artifact("Claude RAG Assistant", proofs)

    required = {
        "schema_version", "generated_at", "system_name", "overall_compliance_score",
        "total_controls_tested", "passed_controls", "failed_controls",
        "needs_review_controls", "proofs", "visualization", "integrity",
    }
    assert required <= payload.keys()
    assert payload["system_name"] == "Claude RAG Assistant"
    assert payload["overall_compliance_score"] == 100.0
    assert payload["total_controls_tested"] == 5
    assert payload["passed_controls"] == 5
    assert payload["failed_controls"] == 0
    assert len(payload["proofs"]) == 5
    assert {p["control_id"] for p in payload["proofs"]} == {c.value for c in ISOControlCategory}

    # Must be plain JSON and round-trip through the typed payload model.
    text = json.dumps(payload)
    core = {k: v for k, v in json.loads(text).items() if k not in {"visualization", "integrity"}}
    model = ClaudeDashboardArtifactPayload.model_validate(core)
    assert evaluator.verify_all(model.proofs)

    dist = {row["status"]: row["count"] for row in payload["visualization"]["status_distribution"]}
    assert dist == {"PASS": 5, "NEEDS_REVIEW": 0, "FAIL": 0}
    assert payload["integrity"]["signature_algorithm"] == "HMAC-SHA256"

    # Zero-trust: no raw input values beyond digests/flags leak into the export.
    assert "raw" not in text.lower() or "raw data" in text.lower()


def test_single_file_renderers_embed_payload(evaluator, dirty_input):
    payload = export_claude_artifact("Shadow LLM", evaluator.evaluate_system(dirty_input))
    html = render_html_dashboard(payload)
    jsx = render_react_component(payload)

    assert html.lstrip().startswith("<!doctype html>")
    assert 'id="payload"' in html and "</script>" in html
    assert "export default function Iso42001Dashboard" in jsx
    for doc in (html, jsx):
        assert "Shadow LLM" in doc
        assert payload["proofs"][0]["signature"] in doc


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_run_then_verify_round_trip(tmp_path: Path, clean_input):
    runner = CliRunner()
    input_file = tmp_path / "input.json"
    input_file.write_text(clean_input.model_dump_json(), encoding="utf-8")
    report = tmp_path / "artifact_report.json"
    html = tmp_path / "dash.html"

    result = runner.invoke(
        app,
        ["run", "--input-file", str(input_file), "--secret", SECRET, "--output", str(report), "--html", str(html)],
    )
    assert result.exit_code == 0, result.output
    assert "Overall compliance score" in result.output
    assert report.exists() and html.exists()

    verified = runner.invoke(app, ["verify", "--report", str(report), "--secret", SECRET])
    assert verified.exit_code == 0, verified.output
    assert "all 5 proofs verified" in verified.output

    # Tamper with the on-disk report: verification must now fail.
    data = json.loads(report.read_text(encoding="utf-8"))
    data["proofs"][0]["status"] = "FAIL" if data["proofs"][0]["status"] == "PASS" else "PASS"
    report.write_text(json.dumps(data), encoding="utf-8")
    tampered = runner.invoke(app, ["verify", "--report", str(report), "--secret", SECRET])
    assert tampered.exit_code == 4
    assert "INVALID" in tampered.output


def test_cli_exit_code_signals_failed_controls(tmp_path: Path, dirty_input):
    runner = CliRunner()
    input_file = tmp_path / "input.json"
    input_file.write_text(dirty_input.model_dump_json(), encoding="utf-8")
    result = runner.invoke(
        app, ["run", "-i", str(input_file), "-s", SECRET, "-o", str(tmp_path / "r.json"), "-q"]
    )
    assert result.exit_code == 3


def test_cli_rejects_invalid_input(tmp_path: Path):
    runner = CliRunner()
    bad = tmp_path / "bad.json"
    bad.write_text('{"system_id": "x", "pii_scan_score": 7}', encoding="utf-8")
    result = runner.invoke(app, ["run", "-i", str(bad), "-s", SECRET, "-o", str(tmp_path / "r.json")])
    assert result.exit_code == 2
