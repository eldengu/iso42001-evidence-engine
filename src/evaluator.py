"""
Zero-Trust evaluator for ISO/IEC 42001 Annex A controls and Anthropic ASL tiers.

Threat model
------------
* The evaluator runs on the same host as the data; nothing is uploaded.
* Each proof carries a SHA-256 ``evidence_hash`` over the canonical evidence
  record, and an HMAC-SHA256 ``signature`` over the whole proof body.
* The HMAC key is derived from the operator secret with HKDF-SHA256 using a
  fixed, versioned ``info`` string so the raw secret is never used directly.
* Verification uses ``hmac.compare_digest`` to resist timing side-channels.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import Any, Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .schemas import (
    ASLLevel,
    ControlStatus,
    ISOControlCategory,
    ZeroTrustEvidenceInput,
    ZeroTrustProof,
)

# Versioned domain-separation strings. Bump when the signing payload changes.
_HKDF_INFO: Final[bytes] = b"iso42001-evidence-engine/proof-signing/v1"
_SIGNING_DOMAIN: Final[bytes] = b"iso42001-evidence-engine/proof/v1\n"
_EVIDENCE_DOMAIN: Final[bytes] = b"iso42001-evidence-engine/evidence/v1\n"

_ControlCheck = Callable[[ZeroTrustEvidenceInput], tuple[ControlStatus, str]]


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding (sorted keys, no whitespace, UTF-8)."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    ).encode("utf-8")


class ZeroTrustEvaluator:
    """
    Evaluate an AI system's metadata against ISO/IEC 42001 controls and sign
    the results.

    Parameters
    ----------
    hmac_secret_key:
        Operator-held secret. Must be at least ``MIN_SECRET_LENGTH`` characters.
        A 32-byte HMAC key is derived from it via HKDF-SHA256; the secret itself
        is never stored on the instance.
    """

    MIN_SECRET_LENGTH: Final[int] = 16
    PII_PASS_THRESHOLD: Final[float] = 0.10
    PII_REVIEW_THRESHOLD: Final[float] = 0.25

    def __init__(self, hmac_secret_key: str) -> None:
        if not isinstance(hmac_secret_key, str):
            raise TypeError("hmac_secret_key must be a str.")
        if len(hmac_secret_key) < self.MIN_SECRET_LENGTH:
            raise ValueError(
                f"hmac_secret_key must be at least {self.MIN_SECRET_LENGTH} characters."
            )
        self._signing_key: bytes = self._derive_signing_key(hmac_secret_key)
        self._checks: dict[ISOControlCategory, _ControlCheck] = {
            ISOControlCategory.A_4_2: self._check_resource_documentation,
            ISOControlCategory.A_5_4: self._check_asl_impact_assessment,
            ISOControlCategory.A_6_2_8: self._check_event_logging,
            ISOControlCategory.A_7_4: self._check_pii_hygiene,
            ISOControlCategory.A_9_4: self._check_runtime_guardrail,
        }

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def evaluate_system(self, input_data: ZeroTrustEvidenceInput) -> list[ZeroTrustProof]:
        """
        Run every control check against ``input_data`` and return signed proofs.

        Raises
        ------
        TypeError
            If ``input_data`` is not a ``ZeroTrustEvidenceInput``.
        """
        if not isinstance(input_data, ZeroTrustEvidenceInput):
            raise TypeError("input_data must be a ZeroTrustEvidenceInput instance.")

        evaluated_at = datetime.now(timezone.utc)
        proofs: list[ZeroTrustProof] = []
        for control_id, check in self._checks.items():
            status, summary = check(input_data)
            proofs.append(self._seal(input_data, control_id, status, summary, evaluated_at))
        return proofs

    @staticmethod
    def compute_overall_score(proofs: Iterable[ZeroTrustProof]) -> float:
        """
        Weighted compliance score in the range 0-100.

        PASS counts 1.0, NEEDS_REVIEW 0.5, FAIL 0.0. An empty list scores 0.0.
        """
        proof_list = list(proofs)
        if not proof_list:
            return 0.0
        total = sum(p.status.score_weight for p in proof_list)
        return round(100.0 * total / len(proof_list), 2)

    def verify_proof(self, proof: ZeroTrustProof) -> bool:
        """Return True iff ``proof.signature`` is valid under this evaluator's key."""
        expected = self._sign(self._signing_payload(proof))
        return hmac.compare_digest(expected, proof.signature)

    def verify_all(self, proofs: Iterable[ZeroTrustProof]) -> bool:
        """Return True iff every proof verifies (no short-circuit on failure)."""
        results = [self.verify_proof(p) for p in proofs]
        return all(results)

    # ------------------------------------------------------------------ #
    # Control checks - each returns (status, summary)
    # ------------------------------------------------------------------ #

    def _check_resource_documentation(
        self, data: ZeroTrustEvidenceInput
    ) -> tuple[ControlStatus, str]:
        """A.4.2 - a verifiable provenance digest must exist for the dataset."""
        if data.dataset_sha256 is None:
            return (
                ControlStatus.FAIL,
                "No dataset provenance digest supplied; resource documentation is incomplete.",
            )
        if data.has_placeholder_digest:
            return (
                ControlStatus.NEEDS_REVIEW,
                "Dataset digest is a placeholder value; confirm the real manifest hash.",
            )
        return (
            ControlStatus.PASS,
            f"Dataset provenance digest recorded (sha256:{data.dataset_sha256[:12]}...).",
        )

    def _check_asl_impact_assessment(
        self, data: ZeroTrustEvidenceInput
    ) -> tuple[ControlStatus, str]:
        """A.5.4 - impact assessment expressed as Anthropic ASL tier compliance."""
        asl = data.asl_target
        pii_ok = data.pii_scan_score < self.PII_PASS_THRESHOLD

        if asl is ASLLevel.ASL_1:
            return (
                ControlStatus.PASS,
                "ASL-1 target: no catastrophic-risk capability; baseline impact assessment satisfied.",
            )

        if asl is ASLLevel.ASL_2:
            if data.event_logging_enabled:
                return (
                    ControlStatus.PASS,
                    "ASL-2 target: event logging present; baseline safeguards satisfied.",
                )
            return (
                ControlStatus.NEEDS_REVIEW,
                "ASL-2 target without event logging; confirm compensating controls.",
            )

        # ASL-3 and ASL-4: strict logging, guardrails and PII hygiene are mandatory.
        missing: list[str] = []
        if not data.event_logging_enabled:
            missing.append("event logging")
        if not data.runtime_guardrail_active:
            missing.append("runtime guardrail")
        if not pii_ok:
            missing.append(
                f"PII hygiene (score {data.pii_scan_score:.3f} >= {self.PII_PASS_THRESHOLD})"
            )
        if missing:
            return (
                ControlStatus.FAIL,
                f"{asl.value} target requires strict safeguards; missing: {', '.join(missing)}.",
            )

        if asl is ASLLevel.ASL_4:
            return (
                ControlStatus.NEEDS_REVIEW,
                "ASL-4 automated safeguards satisfied; ASL-4 additionally requires manual security review.",
            )
        return (
            ControlStatus.PASS,
            "ASL-3 target: logging, runtime guardrail and PII hygiene all satisfied.",
        )

    @staticmethod
    def _check_event_logging(data: ZeroTrustEvidenceInput) -> tuple[ControlStatus, str]:
        """A.6.2.8 - AI system event logging must be enabled."""
        if data.event_logging_enabled:
            return ControlStatus.PASS, "Inference event logging is enabled."
        return (
            ControlStatus.FAIL,
            "Inference event logging is disabled; audit trail is unavailable.",
        )

    def _check_pii_hygiene(self, data: ZeroTrustEvidenceInput) -> tuple[ControlStatus, str]:
        """A.7.4 - PII scan score must be below the pass threshold."""
        score = data.pii_scan_score
        if score < self.PII_PASS_THRESHOLD:
            return (
                ControlStatus.PASS,
                f"PII scan score {score:.3f} is below the {self.PII_PASS_THRESHOLD} threshold.",
            )
        if score < self.PII_REVIEW_THRESHOLD:
            return (
                ControlStatus.NEEDS_REVIEW,
                f"PII scan score {score:.3f} is elevated; manual data-quality review required.",
            )
        return (
            ControlStatus.FAIL,
            f"PII scan score {score:.3f} exceeds the {self.PII_REVIEW_THRESHOLD} failure threshold.",
        )

    @staticmethod
    def _check_runtime_guardrail(data: ZeroTrustEvidenceInput) -> tuple[ControlStatus, str]:
        """A.9.4 - a runtime guardrail must enforce intended use."""
        if data.runtime_guardrail_active:
            return ControlStatus.PASS, "Runtime guardrail is active and gating model outputs."
        return (
            ControlStatus.FAIL,
            "No active runtime guardrail; intended-use enforcement is absent.",
        )

    # ------------------------------------------------------------------ #
    # Cryptographic helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _derive_signing_key(secret: str) -> bytes:
        """Derive a 32-byte HMAC key from the operator secret via HKDF-SHA256."""
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO)
        return hkdf.derive(secret.encode("utf-8"))

    @staticmethod
    def _evidence_hash(
        data: ZeroTrustEvidenceInput,
        control_id: ISOControlCategory,
        status: ControlStatus,
        evaluated_at: datetime,
    ) -> str:
        """SHA-256 over the canonical evidence record (metadata only)."""
        record = {
            "system_id": data.system_id,
            "control_id": control_id.value,
            "status": status.value,
            "asl_target": data.asl_target.value,
            "evaluated_at": evaluated_at.isoformat(),
            "evidence": data.model_dump(mode="json"),
        }
        return hashlib.sha256(_EVIDENCE_DOMAIN + _canonical_json(record)).hexdigest()

    @staticmethod
    def _signing_payload(proof: ZeroTrustProof) -> bytes:
        """Canonical bytes covered by the signature (every field except ``signature``)."""
        body = proof.model_dump(mode="json", exclude={"signature"})
        return _SIGNING_DOMAIN + _canonical_json(body)

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._signing_key, payload, hashlib.sha256).hexdigest()

    def _seal(
        self,
        data: ZeroTrustEvidenceInput,
        control_id: ISOControlCategory,
        status: ControlStatus,
        summary: str,
        evaluated_at: datetime,
    ) -> ZeroTrustProof:
        """Build an unsigned proof, sign its canonical body, and freeze it."""
        unsigned = ZeroTrustProof(
            proof_id=uuid.uuid4().hex,
            timestamp=evaluated_at,
            control_id=control_id,
            status=status,
            asl_level=data.asl_target,
            evidence_hash=self._evidence_hash(data, control_id, status, evaluated_at),
            summary=summary,
            signature="0" * 64,  # placeholder, excluded from the signed body
        )
        signature = self._sign(self._signing_payload(unsigned))
        return unsigned.model_copy(update={"signature": signature})


__all__ = ["ZeroTrustEvaluator"]
