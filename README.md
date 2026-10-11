# iso42001-evidence-engine

**Zero-Trust ISO/IEC 42001 compliance engine for AI systems.**
Evaluates local AI model metadata against ISO/IEC 42001 Annex A controls and
Anthropic Responsible Scaling Policy (RSP) AI Safety Levels, then emits
HMAC-SHA256-signed audit proofs that render directly inside Claude Dashboards
(Artifacts). No dataset row, log line or PII value ever leaves the host.

[![python](https://img.shields.io/badge/python-3.11%2B-blue)](#quickstart)
[![pydantic](https://img.shields.io/badge/pydantic-v2-e92063)](#architecture)
[![license](https://img.shields.io/badge/license-Apache--2.0-green)](#license)

---

## Why this exists

AI governance programmes (ISO/IEC 42001, NIST AI RMF, EU AI Act, Anthropic RSP)
all ask the same question: *can you prove, after the fact, that a control was
satisfied at a given moment, without handing the auditor your data?*

This engine answers that with a **local-only evaluator** and a
**cryptographic evidence chain**:

| Property | Mechanism |
| --- | --- |
| Data never leaves the host | Input schema accepts only digests, scores and flags; `extra="forbid"` blocks raw fields |
| Evidence is tamper-evident | SHA-256 `evidence_hash` over a canonical, domain-separated record |
| Proofs are authentic | HMAC-SHA256 signature over every proof field, key derived with HKDF-SHA256 |
| Proofs are immutable | `ZeroTrustProof` is a frozen Pydantic model; any change invalidates the signature |
| Verification is side-channel aware | `hmac.compare_digest`, no short-circuit across proofs |
| Output is dashboard-ready | Typed `ClaudeDashboardArtifactPayload`, plus single-file React / HTML renderers |

---

## Architecture

```
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                        LOCAL HOST  (zero-trust boundary)                  │
 │                                                                           │
 │   datasets / logs / PII scanners                                          │
 │          │   (digests, scores, flags only)                                │
 │          ▼                                                                │
 │   ┌─────────────────────────┐    ┌───────────────────────────────────┐    │
 │   │ ZeroTrustEvidenceInput  │───▶│         ZeroTrustEvaluator        │    │
 │   │  system_id              │    │                                   │    │
 │   │  asl_target  (ASL-1..4) │    │  A.4.2   resource documentation   │    │
 │   │  dataset_sha256         │    │  A.5.4   impact assessment / ASL  │    │
 │   │  pii_scan_score         │    │  A.6.2.8 event logging            │    │
 │   │  event_logging_enabled  │    │  A.7.4   data quality / PII       │    │
 │   │  runtime_guardrail_active│   │  A.9.4   intended use / guardrail │    │
 │   └─────────────────────────┘    └───────────────┬───────────────────┘    │
 │                                                  │                        │
 │          operator secret ──HKDF-SHA256──▶ signing key                     │
 │                                                  │                        │
 │                                                  ▼                        │
 │                          ┌──────────────────────────────────────┐         │
 │                          │  ZeroTrustProof (frozen)             │         │
 │                          │   evidence_hash = SHA-256(record)    │         │
 │                          │   signature     = HMAC-SHA256(body)  │         │
 │                          └──────────────────┬───────────────────┘         │
 └─────────────────────────────────────────────┼─────────────────────────────┘
                                               │  proofs only (no raw data)
                                               ▼
                     ┌──────────────────────────────────────────────┐
                     │   Claude Dashboard / Artifact                │
                     │   ClaudeDashboardArtifactPayload (JSON)      │
                     │   ├─ overall_compliance_score                │
                     │   ├─ passed / failed / needs_review counts   │
                     │   ├─ proofs[]  (signed)                      │
                     │   └─ visualization + integrity metadata      │
                     │   single-file React (.jsx) / HTML renderers  │
                     └──────────────────────────────────────────────┘
```

---

## Control logic

| Control | ISO/IEC 42001 Annex A | NIST AI RMF | Rule |
| --- | --- | --- | --- |
| **A.4.2** | Resource documentation | MAP | PASS if a real `dataset_sha256` is present; NEEDS_REVIEW for placeholder digests; FAIL if absent |
| **A.5.4** | AI system impact assessment | MAP / MEASURE | Expressed as Anthropic ASL tier compliance (see below) |
| **A.6.2.8** | AI system event logging | MANAGE | PASS iff `event_logging_enabled` |
| **A.7.4** | Quality of data for AI systems | MEASURE | PASS if `pii_scan_score < 0.10`; NEEDS_REVIEW if `< 0.25`; FAIL otherwise |
| **A.9.4** | Intended use of the AI system | MANAGE | PASS iff `runtime_guardrail_active` |

**ASL gating (A.5.4)**

| ASL target | Requirement |
| --- | --- |
| ASL-1 | Baseline; always PASS |
| ASL-2 | PASS with event logging, otherwise NEEDS_REVIEW |
| ASL-3 | Logging **and** runtime guardrail **and** PII score `< 0.10`, otherwise FAIL |
| ASL-4 | Same strict set; if satisfied, NEEDS_REVIEW (manual security review is still mandatory) |

**Overall score** = mean of `PASS=1.0`, `NEEDS_REVIEW=0.5`, `FAIL=0.0`, expressed 0-100.

---

## Key highlights (AI Safety / GRC)

- **ISO/IEC 42001:2023** - Annex A controls A.4.2, A.5.4, A.6.2.8, A.7.4, A.9.4 with per-control rationale strings suitable for Statement of Applicability evidence.
- **NIST AI RMF 1.0** - every proof carries a MAP / MEASURE / MANAGE cross-walk for RMF-aligned reporting.
- **Anthropic RSP** - ASL-1 to ASL-4 risk tiering enforced as a first-class input; ASL-3+ hard-requires logging and guardrails.
- **Zero-knowledge style attestation** - auditors receive digests and signed statements, never the underlying data. The dataset digest proves *which* data was assessed without revealing *what* it contains.
- **Cryptographic hygiene** - HKDF key derivation with versioned domain separation, canonical JSON signing, constant-time verification, frozen proof objects.
- **Dashboard-native** - JSON payload validated by Pydantic, plus zero-dependency React and HTML renderers for Claude Artifacts.

---

## Quickstart & How to Run

### 1. Installation

Requires Python 3.11 or newer.

```bash
git clone https://github.com/eldengu/iso42001-evidence-engine.git
cd iso42001-evidence-engine

python -m venv .venv
source .venv/bin/activate          # Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -e ".[dev]"            # installs the package, the `iso42001-evidence` CLI and pytest
```

### 2. Run a CLI evaluation

The secret must be at least 16 characters. Pass it with `--secret` or export
`ISO42001_HMAC_SECRET`; keep it in a secrets manager in real deployments.

```bash
iso42001-evidence run \
  --input-file examples/sample_input.json \
  --secret "replace-with-a-long-random-secret" \
  --output artifact_report.json \
  --html dashboard.html \
  --react Iso42001Dashboard.jsx
```

This prints a per-control report to the console and writes:

| File | Purpose |
| --- | --- |
| `artifact_report.json` | Signed `ClaudeDashboardArtifactPayload` for Claude Dashboards / Artifacts |
| `dashboard.html` (optional) | Dependency-free single-file dashboard, opens offline |
| `Iso42001Dashboard.jsx` (optional) | Self-contained React component with the payload embedded |

Try the failing example to see FAIL / NEEDS_REVIEW output and a non-zero exit code:

```bash
iso42001-evidence run --input-file examples/failing_input.json --secret "replace-with-a-long-random-secret"
```

Exit codes for `run`: `0` all controls pass or need review, `2` invalid input or secret, `3` at least one control FAILED.

### 3. Verify a report

Re-check every HMAC signature in a previously written report. Any edit to a
proof (status, summary, timestamp, hash) is reported as `INVALID`.

```bash
iso42001-evidence verify --report artifact_report.json --secret "replace-with-a-long-random-secret"
```

Exit codes for `verify`: `0` all proofs valid, `2` malformed report or missing secret, `4` one or more proofs failed verification.

### 4. Run the test suite

```bash
pytest
```

### Running without installing

From the repository root, the modules also run directly:

```bash
python -m src.cli run --input-file examples/sample_input.json --secret "replace-with-a-long-random-secret"
python -m src.cli verify --report artifact_report.json --secret "replace-with-a-long-random-secret"
```

### Input schema

```json
{
  "system_id": "claude-rag-assistant-v3",
  "asl_target": "ASL-3",
  "dataset_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "pii_scan_score": 0.02,
  "event_logging_enabled": true,
  "runtime_guardrail_active": true
}
```

### Python API

```python
from src import ZeroTrustEvaluator, ZeroTrustEvidenceInput, export_claude_artifact
# (installed package: from iso42001_evidence_engine import ...)

evidence = ZeroTrustEvidenceInput.model_validate_json(open("examples/sample_input.json").read())
engine = ZeroTrustEvaluator(hmac_secret_key="replace-with-a-long-random-secret")

proofs = engine.evaluate_system(evidence)
print(engine.compute_overall_score(proofs))      # 100.0
assert engine.verify_all(proofs)

payload = export_claude_artifact("Claude RAG Assistant", proofs)   # dict, JSON-ready
```

### Tests

```bash
pytest
```

The suite covers the clean-pass path, the high-PII / no-logging failure path,
signature validity and tamper detection (including a wrong-key impostor and
an on-disk report edit), schema hardening, artifact structure, and the CLI
run → verify round-trip.

---

## Project layout

```
iso42001-evidence-engine/
├── pyproject.toml              # packaging, console script, pytest config
├── README.md
├── examples/
│   ├── sample_input.json       # clean ASL-3 system
│   └── failing_input.json      # high PII, no logging, placeholder digest
├── src/                        # installed as `iso42001_evidence_engine`
│   ├── __init__.py             # public API
│   ├── schemas.py              # Pydantic V2 enums + models
│   ├── evaluator.py            # control checks, HKDF/HMAC signing, verification
│   ├── artifact_generator.py   # JSON payload, React and HTML renderers
│   └── cli.py                  # typer CLI: run, verify
└── tests/
    ├── __init__.py
    └── test_evaluator.py
```

---

## Security notes

- The operator secret is never stored; only the HKDF-derived 32-byte key lives in memory for the evaluator's lifetime.
- Signing covers *every* proof field, including `timestamp` and `summary`, so back-dating or re-wording a proof is detectable.
- If `run` is executed without a secret, an ephemeral one is generated and a warning is printed; such reports cannot be re-verified and should not be used as audit evidence.
- Proofs are authenticity attestations, not non-repudiation: anyone holding the secret can sign. Use a per-environment secret stored in a secrets manager, and rotate by bumping the HKDF `info` version if the signing payload changes.

## License

Apache-2.0
