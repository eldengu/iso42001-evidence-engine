"""
iso42001-evidence-engine
========================

A Zero-Trust ISO/IEC 42001 compliance engine for AI systems.

The engine evaluates *metadata* about a local AI system (dataset digests,
PII scan scores, logging and guardrail flags) entirely in memory and emits
cryptographically signed ``ZeroTrustProof`` records. No raw dataset, log line
or PII value is ever included in a proof - only SHA-256 digests and
HMAC-SHA256 signatures leave the evaluator.

Public API
----------
- :class:`~.schemas.ZeroTrustEvidenceInput`     - validated evaluator input
- :class:`~.schemas.ZeroTrustProof`             - signed, immutable audit proof
- :class:`~.schemas.ClaudeDashboardArtifactPayload` - dashboard payload model
- :class:`~.evaluator.ZeroTrustEvaluator`       - the control evaluator / signer
- :func:`~.artifact_generator.export_claude_artifact` - JSON payload exporter
- :func:`~.artifact_generator.render_react_component` - single-file React export
- :func:`~.artifact_generator.render_html_dashboard`  - single-file HTML export
"""

from __future__ import annotations

from .artifact_generator import (
    export_claude_artifact,
    render_html_dashboard,
    render_react_component,
)
from .evaluator import ZeroTrustEvaluator
from .schemas import (
    ASLLevel,
    ClaudeDashboardArtifactPayload,
    ControlStatus,
    ISOControlCategory,
    ZeroTrustEvidenceInput,
    ZeroTrustProof,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "ASLLevel",
    "ClaudeDashboardArtifactPayload",
    "ControlStatus",
    "ISOControlCategory",
    "ZeroTrustEvaluator",
    "ZeroTrustEvidenceInput",
    "ZeroTrustProof",
    "export_claude_artifact",
    "render_html_dashboard",
    "render_react_component",
]
