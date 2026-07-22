"""Typed wrapper around the classifier service's current loose JSON API."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ClassifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str
    tenant_id: str = "default"
    message_id: str | None = None
    lexicon_version: str = "v1"


class DetectionMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detector: str
    entity_type: str
    score: float = Field(ge=0.0, le=1.0)
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class DetectionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detector: str
    matches: list[DetectionMatch] = Field(default_factory=list)
    escalate: bool
    error: str | None = None


class LlmClassificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: Literal["SENSITIVE", "NOT_SENSITIVE", "UNCERTAIN"]
    confidence: float = Field(ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list)
    reasoning: str = ""


class ClassifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[DetectionResult]
    llm_result: LlmClassificationResult
