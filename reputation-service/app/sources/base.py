from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from app.api.schemas import EntityType, Verdict


@dataclass(frozen=True)
class SourceConfig:
    name: str
    enabled: bool
    priority: int
    timeout_ms: int
    supported_entities: set[str]


@dataclass
class SourceSignal:
    source: str
    entity_type: EntityType
    verdict: Verdict
    priority: int
    confidence: float
    indicators: list[str] = field(default_factory=list)
    score_impact: int = 0
    minimum_score: int | None = None
    severity: str = "info"
    detail: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    latency_ms: float | None = None
    observed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_public_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "source": self.source,
            "entity_type": self.entity_type.value,
            "verdict": self.verdict.value,
            "priority": self.priority,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "score_impact": self.score_impact,
            "minimum_score": self.minimum_score,
            "severity": self.severity,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
            "observed_at": self.observed_at.isoformat(),
        }
        if include_raw:
            data["raw"] = self.raw
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SourceSignal":
        observed_at = data.get("observed_at")
        parsed_observed = (
            datetime.fromisoformat(observed_at)
            if isinstance(observed_at, str)
            else datetime.now(timezone.utc)
        )
        return cls(
            source=data["source"],
            entity_type=EntityType(data["entity_type"]),
            verdict=Verdict(data["verdict"]),
            priority=int(data["priority"]),
            confidence=float(data.get("confidence", 0.0)),
            indicators=list(data.get("indicators", [])),
            score_impact=int(data.get("score_impact", 0)),
            minimum_score=data.get("minimum_score"),
            severity=str(data.get("severity", "info")),
            detail=data.get("detail"),
            raw=dict(data.get("raw", {})),
            latency_ms=data.get("latency_ms"),
            observed_at=parsed_observed,
        )


@dataclass
class AdapterStatus:
    name: str
    enabled: bool
    configured: bool
    priority: int
    supported_entities: set[str]
    status: str
    detail: str | None = None


class ThreatIntelAdapter(Protocol):
    config: SourceConfig

    @property
    def name(self) -> str:
        ...

    @property
    def is_configured(self) -> bool:
        ...

    def supports(self, entity_type: EntityType) -> bool:
        ...

    async def lookup(self, entity_type: EntityType, value: str) -> SourceSignal | None:
        ...

    async def health(self) -> AdapterStatus:
        ...


class BaseAdapter:
    def __init__(self, config: SourceConfig) -> None:
        self.config = config

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def is_configured(self) -> bool:
        return True

    def supports(self, entity_type: EntityType) -> bool:
        return entity_type.value in self.config.supported_entities

    async def health(self) -> AdapterStatus:
        status = "healthy" if self.is_configured else "not_configured"
        return AdapterStatus(
            name=self.name,
            enabled=self.config.enabled,
            configured=self.is_configured,
            priority=self.config.priority,
            supported_entities=self.config.supported_entities,
            status=status,
        )


class TimedLookup:
    def __enter__(self) -> "TimedLookup":
        self._start = time.perf_counter()
        self._latency_ms: float | None = None
        return self

    def __exit__(self, *_args: object) -> None:
        self._latency_ms = round((time.perf_counter() - self._start) * 1000, 2)

    @property
    def latency_ms(self) -> float:
        if self._latency_ms is not None:
            return self._latency_ms
        return round((time.perf_counter() - self._start) * 1000, 2)
