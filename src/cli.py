"""
Command-line interface for the Zero-Trust ISO/IEC 42001 evidence engine.

Commands
--------
``run``     Evaluate a system from a JSON metadata file, print a report and
            write ``artifact_report.json`` (plus optional HTML / React exports).
``verify``  Re-verify every HMAC signature inside a previously written report.

Secret resolution order for ``run``: ``--secret`` > ``$ISO42001_HMAC_SECRET`` >
an ephemeral random secret (printed warning; proofs cannot be re-verified later).
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path
from typing import Annotated, Any, Optional

import typer
from pydantic import ValidationError

from .artifact_generator import (
    export_claude_artifact,
    render_html_dashboard,
    render_react_component,
)
from .evaluator import ZeroTrustEvaluator
from .schemas import ControlStatus, ZeroTrustEvidenceInput, ZeroTrustProof

SECRET_ENV_VAR = "ISO42001_HMAC_SECRET"

app = typer.Typer(
    name="iso42001-evidence",
    help="Zero-Trust ISO/IEC 42001 compliance engine with HMAC-signed audit proofs.",
    add_completion=False,
    no_args_is_help=True,
)

_STATUS_COLOR: dict[ControlStatus, str] = {
    ControlStatus.PASS: typer.colors.GREEN,
    ControlStatus.NEEDS_REVIEW: typer.colors.YELLOW,
    ControlStatus.FAIL: typer.colors.RED,
}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _fail(message: str, code: int = 1) -> None:
    typer.secho(f"error: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        _fail(f"input file not found: {path}")
    except UnicodeDecodeError:
        _fail(f"input file is not valid UTF-8: {path}")
    except json.JSONDecodeError as exc:
        _fail(f"invalid JSON in {path}: {exc.msg} (line {exc.lineno}, column {exc.colno})")


def _format_validation_error(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err.get("loc", ())) or "<root>"
        lines.append(f"  - {loc}: {err.get('msg')}")
    return "\n".join(lines)


def _resolve_secret(secret: Optional[str], *, allow_ephemeral: bool) -> str:
    if secret:
        return secret
    if allow_ephemeral:
        typer.secho(
            f"warning: no --secret or ${SECRET_ENV_VAR} supplied; using an ephemeral secret. "
            "Proofs from this run cannot be re-verified later.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return secrets.token_urlsafe(32)
    _fail(f"a secret is required: pass --secret or set ${SECRET_ENV_VAR}.", code=2)
    raise AssertionError("unreachable")


def _build_evaluator(secret: str) -> ZeroTrustEvaluator:
    try:
        return ZeroTrustEvaluator(secret)
    except (TypeError, ValueError) as exc:
        _fail(str(exc), code=2)
        raise AssertionError("unreachable")


def _write_text(path: Path, content: str, label: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        _fail(f"could not write {label} to {path}: {exc}")
    typer.secho(f"wrote {label}: {path}", fg=typer.colors.CYAN)


def _print_report(system_name: str, proofs: list[ZeroTrustProof], score: float) -> None:
    width = 78
    typer.echo("=" * width)
    typer.secho(f" ISO/IEC 42001 Zero-Trust Evidence Report - {system_name}", bold=True)
    typer.echo("=" * width)
    typer.echo(f" {'Control':<9} {'Status':<13} {'ASL':<6} Summary")
    typer.echo("-" * width)
    for proof in proofs:
        status = proof.status
        typer.echo(f" {proof.control_id.value:<9} ", nl=False)
        typer.secho(f"{status.value:<13}", fg=_STATUS_COLOR[status], bold=True, nl=False)
        typer.echo(f" {proof.asl_level.value:<6} {proof.summary}")
        typer.echo(f" {'':<9} {'':<13} {'':<6} {proof.control_id.title}")
        typer.echo(f" {'':<9} {'':<13} {'':<6} sig={proof.signature[:16]}...  evidence={proof.evidence_hash[:16]}...")
    typer.echo("-" * width)
    passed = sum(1 for p in proofs if p.status is ControlStatus.PASS)
    review = sum(1 for p in proofs if p.status is ControlStatus.NEEDS_REVIEW)
    failed = sum(1 for p in proofs if p.status is ControlStatus.FAIL)
    color = typer.colors.GREEN if score >= 80 else typer.colors.YELLOW if score >= 50 else typer.colors.RED
    typer.echo(" Overall compliance score: ", nl=False)
    typer.secho(f"{score:.2f}%", fg=color, bold=True, nl=False)
    typer.echo(f"   (pass={passed} review={review} fail={failed} of {len(proofs)})")
    typer.echo("=" * width)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


@app.command()
def run(
    input_file: Annotated[
        Path,
        typer.Option(
            "--input-file", "-i",
            help="JSON file matching the ZeroTrustEvidenceInput schema.",
            exists=True, dir_okay=False, readable=True, resolve_path=True,
        ),
    ],
    secret: Annotated[
        Optional[str],
        typer.Option(
            "--secret", "-s",
            envvar=SECRET_ENV_VAR,
            help="HMAC secret (>=16 chars). Falls back to $ISO42001_HMAC_SECRET, then an ephemeral value.",
            show_default=False,
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Where to write the JSON artifact payload.", dir_okay=False),
    ] = Path("artifact_report.json"),
    system_name: Annotated[
        Optional[str],
        typer.Option("--system-name", help="Display name for the dashboard (defaults to system_id)."),
    ] = None,
    html: Annotated[
        Optional[Path],
        typer.Option("--html", help="Also write a single-file HTML dashboard to this path.", dir_okay=False),
    ] = None,
    react: Annotated[
        Optional[Path],
        typer.Option("--react", help="Also write a single-file React component (.jsx) to this path.", dir_okay=False),
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q", help="Suppress the console report.")] = False,
) -> None:
    """Evaluate an AI system's metadata and emit signed ISO/IEC 42001 proofs."""
    raw = _load_json(input_file)
    try:
        evidence = ZeroTrustEvidenceInput.model_validate(raw)
    except ValidationError as exc:
        _fail(f"input does not match ZeroTrustEvidenceInput:\n{_format_validation_error(exc)}", code=2)
        raise AssertionError("unreachable")

    evaluator = _build_evaluator(_resolve_secret(secret, allow_ephemeral=True))
    proofs = evaluator.evaluate_system(evidence)
    score = evaluator.compute_overall_score(proofs)
    display_name = system_name or evidence.system_id

    if not quiet:
        _print_report(display_name, proofs, score)

    payload = export_claude_artifact(display_name, proofs)
    _write_text(output, json.dumps(payload, indent=2, ensure_ascii=False) + "\n", "artifact payload")
    if html is not None:
        _write_text(html, render_html_dashboard(payload), "HTML dashboard")
    if react is not None:
        _write_text(react, render_react_component(payload), "React component")

    if any(p.status is ControlStatus.FAIL for p in proofs):
        raise typer.Exit(3)


@app.command()
def verify(
    report: Annotated[
        Path,
        typer.Option(
            "--report", "-r",
            help="artifact_report.json produced by `run`.",
            exists=True, dir_okay=False, readable=True, resolve_path=True,
        ),
    ] = Path("artifact_report.json"),
    secret: Annotated[
        Optional[str],
        typer.Option("--secret", "-s", envvar=SECRET_ENV_VAR, help="HMAC secret used at `run` time.", show_default=False),
    ] = None,
) -> None:
    """Re-verify every HMAC signature in a report. Exit 0 if all valid, 4 otherwise."""
    raw = _load_json(report)
    if not isinstance(raw, dict) or not isinstance(raw.get("proofs"), list):
        _fail("report does not contain a `proofs` array.", code=2)

    try:
        proofs = [ZeroTrustProof.model_validate(item) for item in raw["proofs"]]
    except ValidationError as exc:
        _fail(f"report contains malformed proofs:\n{_format_validation_error(exc)}", code=2)
        raise AssertionError("unreachable")

    evaluator = _build_evaluator(_resolve_secret(secret, allow_ephemeral=False))
    bad = [p for p in proofs if not evaluator.verify_proof(p)]
    for proof in proofs:
        ok = proof not in bad
        typer.echo(f" {proof.control_id.value:<9} {proof.proof_id}  ", nl=False)
        typer.secho("VALID" if ok else "INVALID", fg=typer.colors.GREEN if ok else typer.colors.RED, bold=True)

    if bad:
        typer.secho(f"{len(bad)} of {len(proofs)} proofs failed verification.", fg=typer.colors.RED, err=True)
        raise typer.Exit(4)
    typer.secho(f"all {len(proofs)} proofs verified.", fg=typer.colors.GREEN)


def main() -> None:
    """Entry point used by ``python -m``."""
    app()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
