from __future__ import annotations

from typing import Any

from app.classifier import ContentClassifier
from config.aws import KIMI_MODEL_ID


class KimiClassifier(ContentClassifier):
    def __init__(self, **kwargs: Any) -> None:
        super().__init__(model_id=KIMI_MODEL_ID, **kwargs)
