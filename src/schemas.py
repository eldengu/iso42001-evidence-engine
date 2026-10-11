"""
Pydantic V2 schemas for the Zero-Trust ISO/IEC 42001 evidence engine.

Design principles
-----------------
* **Metadata only.** ``ZeroTrustEvidenceInput`` carries digests, scores and
  boolean flags - never raw records, log lines or PII values.
* **Strict validation.** Unknown fields are rejected (``extra="forbid"``) so a
  caller cannot accidentally smuggle raw data into the evaluator.
* **Immutable proofs.** ``ZeroTrustProof`` is frozen; any "modification" must
  produce a new object, which invalidates the HMAC signature.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #

_PLACEHOLDER_DIGESTS = frozenset({"0" * 64, "f" * 64})


class ASLLevel(str, Enum):
    """Anthropic Responsible Scaling Policy - AI Safety Level."""

    ASL_1 = "ASL-1"
    ASL_2 = "ASL-2"
    ASL_3 = "ASL-3"
    ASL_4 = "ASL-4"

    @property
    def rank(self) -> int:
        """Numeric rank (1-4) used for ordering comparisons."""
        return int(self.value.split("-")[1])

    @property
    def requires_strict_controls(self) -> bool:
        """ASL-3 and above require mandatory logging and runtime guardrails."""
        return self.rank >= 3


class ISOControlCategory(str, Enum):
    """ISO/IEC 42001:2023 Annex A controls covered by this engine."""

    A_4_2 = "A.4.2"
    A_5_4 = "A.5.4"
    A_6_2_8 = "A.6.2.8"
    A_7_4 = "A.7.4"
    A_9_4 = "A.9.4"

    @property
    def title(self) -> str:
        """Human-readable control title from Annex A."""
        return _CONTROL_TITLES[self]

    @property
    def nist_ai_rmf_function(self) -> str:
        """Closest NIST AI RMF 1.0 core function for cross-walk reporting."""
        return _NIST_CROSSWALK[self]


_CONTROL_TITLES: dict[ISOControlCategory, str] = {
    ISOControlCategory.A_4_2: "Resource documentation (data provenance)",
    ISOControlCategory.A_5_4: "AI system impact assessment (risk tiering)",
    ISOControlCategory.A_6_2_8: "AI system event logging",
    ISOControlCategory.A_7_4: "Quality of data for AI systems (PII hygiene)",
    ISOControlCategory.A_9_4: "Intended use of the AI system (runtime guardrails)",
}

_NIST_CROSSWALK: dict[ISOControlCategory, str] = {
    ISOControlCategory.A_4_2: "MAP",
    ISOControlCategory.A_5_4: "MAP / MEASURE",
    ISOControlCategory.A_6_2_8: "MANAGE",
    ISOControlCategory.A_7_4: "MEASURE",
    ISOControlCategory.A_9_4: "MANAGE",
}


class ControlStatus(str, Enum):
    """Outcome of a single control evaluation."""

    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"

    @property
    def score_weight(self) -> float:
        """Contribution to the overall compliance score (0.0 - 1.0)."""
        return {"PASS": 1.0, "NEEDS_REVIEW": 0.5, "FAIL": 0.0}[self.value]


# --------------------------------------------------------------------------- #
# Reusable field types
# --------------------------------------------------------------------------- #

Sha256Hex = Annotated[
    str,
    Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
        description="Lower-case hexadecimal SHA-256 digest.",
    ),
]

UnitInterval = Annotated[float, Field(ge=0.0, le=1.0)]


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


class ZeroTrustEvidenceInput(BaseModel):
    """
    Metadata describing an AI system under evaluation.

    Every field is either a digest, a score or a flag. The model deliberately
    has **no** field capable of carrying raw dataset rows, prompts, or logs.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    system_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$",
        description="Stable identifier of the AI system (no spaces).",
        examples=["claude-rag-assistant-v3"],
    )
    asl_target: ASLLevel = Field(
        ...,
        description="Anthropic RSP AI Safety Level the system is evaluated against.",
    )
    dataset_sha256: Sha256Hex | None = Field(
        default=None,
        description=(
            "SHA-256 digest of the training / fine-tuning / retrieval dataset "
            "manifest. Only the digest is supplied; the data never leaves the host."
        ),
    )
    pii_scan_score: UnitInterval = Field(
        ...,
        description=(
            "Fraction (0.0-1.0) of sampled records flagged as containing PII by "
            "the local scanner. 0.0 means no PII detected."
        ),
    )
    event_logging_enabled: bool = Field(
        ...,
        description="True if the system emits tamper-evident event logs for every inference.",
    )
    runtime_guardrail_active: bool = Field(
        ...,
        description="True if an inline policy / safety classifier gates model outputs.",
    )

    @field_validator("dataset_sha256", mode="before")
    @classmethod
    def _normalise_digest(cls, value: object) -> object:
        """Accept upper-case hex and strip whitespace before pattern validation."""
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @property
    def has_placeholder_digest(self) -> bool:
        """True when the digest is an obvious placeholder (all zeros / all f)."""
        return self.dataset_sha256 is not None and self.dataset_sha256 in _PLACEHOLDER_DIGESTS


class ZeroTrustProof(BaseModel):
    """
    An immutable, signed attestation that one control was evaluated.

    ``evidence_hash`` is a SHA-256 digest over the canonical evidence record.
    ``signature`` is an HMAC-SHA256 over every other field in this model, so
    changing *any* field (including the timestamp) invalidates the proof.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    proof_id: str = Field(
        ..., min_length=8, max_length=64, description="Unique proof identifier (UUID4 hex)."
    )
    timestamp: datetime = Field(..., description="UTC time of evaluation.")
    control_id: ISOControlCategory
    status: ControlStatus
    asl_level: ASLLevel = Field(..., description="ASL the control was evaluated against.")
    evidence_hash: Sha256Hex
    summary: str = Field(
        ..., min_length=1, max_length=512, description="Human-readable rationale (metadata only)."
    )
    signature: Sha256Hex = Field(..., description="HMAC-SHA256 (hex) over the canonical proof body.")

    @field_validator("timestamp")
    @classmethod
    def _require_tz(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware (UTC).")
        return value

    @property
    def control_title(self) -> str:
        """Annex A title of the evaluated control."""
        return self.control_id.title


class ClaudeDashboardArtifactPayload(BaseModel):
    """
    Structured payload consumed by a Claude Dashboard (Artifact) renderer.

    The payload is intentionally self-describing (``schema_version``) so a
    React component can validate it before rendering.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(default="1.0", description="Payload schema version.")
    generated_at: datetime = Field(..., description="UTC time the payload was generated.")
    system_name: str = Field(..., min_length=1, max_length=256)
    overall_compliance_score: float = Field(
        ..., ge=0.0, le=100.0, description="Weighted score, 0-100."
    )
    total_controls_tested: int = Field(..., ge=0)
    passed_controls: int = Field(..., ge=0)
    failed_controls: int = Field(..., ge=0)
    needs_review_controls: int = Field(..., ge=0)
    proofs: list[ZeroTrustProof] = Field(default_factory=list)


__all__ = [
    "ASLLevel",
    "ClaudeDashboardArtifactPayload",
    "ControlStatus",
    "ISOControlCategory",
    "Sha256Hex",
    "ZeroTrustEvidenceInput",
    "ZeroTrustProof",
]
