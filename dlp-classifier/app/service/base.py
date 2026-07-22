from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionMatch:
    detector: str
    entity_type: str
    score: float
    start: int
    end: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    detector: str
    matches: list[DetectionMatch]
    escalate: bool
    error: str | None = None


class BaseDetector(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    async def analyze(self, text: str, metadata: dict[str, Any]) -> DetectionResult: ...
