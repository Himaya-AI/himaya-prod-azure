from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


# ── Requests ──────────────────────────────────────────────────────────────────

class ReputationHint(BaseModel):
    reputation_score: int = 0           # 0–100 from reputation-service (higher = more malicious)
    spf_pass: bool | None = None
    dkim_pass: bool | None = None
    dmarc_pass: bool | None = None
    indicators: list[str] = Field(default_factory=list)


class EvaluateRequest(BaseModel):
    sender: str
    recipient: str
    org_id: str
    content_hint: str | None = None
    reputation_hint: ReputationHint | None = None


class AttachmentData(BaseModel):
    sha256: str
    filename: str = ""
    extension: str = ""


class WriteRequest(BaseModel):
    sender: str
    recipient: str
    org_id: str
    message_id: str
    subject_hash: str = ""
    received_at: str
    llm_verdict: str | None = None
    risk_score: float = 0.0
    threat_type: str | None = None
    urls: list[str] = Field(default_factory=list)
    attachments: list[AttachmentData] = Field(default_factory=list)

    def to_write_dict(self) -> dict:
        d = self.model_dump()
        d["attachments"] = [a.model_dump() for a in self.attachments]
        return d


class RetractRequest(BaseModel):
    sender: str
    threat_type: str | None = None


# ── Responses ─────────────────────────────────────────────────────────────────

class TrustVerdict(BaseModel):
    trust_score: int
    trust_method: str           # "insufficient_history" | "deterministic" | "block" | *+llm variants
    reasoning: str
    domain_spread: int
    indicators: list[str] = Field(default_factory=list)
    # populated only when LLM ran
    llm_adjustment: int | None = None
    llm_reasoning: str | None = None
    llm_confidence: float | None = None
    llm_model: str | None = None


class EvaluateResponse(BaseModel):
    sender: dict[str, Any]
    domain: dict[str, Any]
    relationship: dict[str, Any]
    intel: dict[str, Any]
    trust: TrustVerdict


class WriteResponse(BaseModel):
    accepted: bool = True


class HealthResponse(BaseModel):
    status: str
    neo4j: bool
