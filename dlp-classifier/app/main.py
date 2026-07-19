from __future__ import annotations

from typing import Any

import structlog

from app.service.base import BaseDetector, DetectionResult

log = structlog.get_logger(__name__)


def build_detectors() -> list[BaseDetector]:
    """Wire up all Tier 0 detectors (pii, ner, credentials, lexicon, edm) as
    they're implemented. Empty until then."""
    return []


def classify(
    text: str, metadata: dict[str, Any], detectors: list[BaseDetector]
) -> list[DetectionResult]:
    """Run every registered detector against the content and collect results."""
    results = [detector.analyze(text, metadata) for detector in detectors]

    if any(result.escalate for result in results):
        log.info("classify.escalate", message_id=metadata.get("message_id"))

    return results


def main() -> None:
    detectors = build_detectors()
    log.info("classifier.ready", detectors=len(detectors))


if __name__ == "__main__":
    main()
