"""Client-side integration with the separate dlp-classifier service."""

from backend.dlp.classification.client import (
    ClassifierClient,
    ClassifierContractError,
    ClassifierError,
    ClassifierRejectedError,
    ClassifierUnavailableError,
)

__all__ = [
    "ClassifierClient",
    "ClassifierContractError",
    "ClassifierError",
    "ClassifierRejectedError",
    "ClassifierUnavailableError",
]
