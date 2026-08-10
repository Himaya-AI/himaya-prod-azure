"""Versioned integration contracts for DLP v2."""

from backend.dlp.contracts.classifier import (
    ClassifyRequest,
    ClassifyResponse,
    DetectionMatch,
    DetectionResult,
    LlmClassificationResult,
)
from backend.dlp.contracts.commands import (
    CommandType,
    GatewayCommand,
    GatewayMessageState,
)
from backend.dlp.contracts.events import (
    CaptureEvent,
    DeliveryEvent,
    DeliveryOutcome,
    SmtpStage,
)

__all__ = [
    "CaptureEvent",
    "ClassifyRequest",
    "ClassifyResponse",
    "CommandType",
    "DetectionMatch",
    "DetectionResult",
    "DeliveryEvent",
    "DeliveryOutcome",
    "GatewayCommand",
    "GatewayMessageState",
    "LlmClassificationResult",
    "SmtpStage",
]
