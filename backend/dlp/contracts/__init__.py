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
    CommandAckEvent,
    CommandAckStatus,
    DeliveryEvent,
    DeliveryOutcome,
    SmtpStage,
)

__all__ = [
    "CaptureEvent",
    "ClassifyRequest",
    "ClassifyResponse",
    "CommandAckEvent",
    "CommandAckStatus",
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
