from __future__ import annotations

import dataclasses
import json

from app.service.base import DetectionResult

# TODO: placeholder — real Tier 2 prompt (DLP semantic/context judgment) lands separately.
SYSTEM_PROMPT = (
    "You are a data-loss-prevention analyst. You are given the content of an "
    "email and the findings Tier 0 deterministic detection already surfaced "
    "for it. Use those findings as context and decide whether the email "
    "contains sensitive data that should not leave the organization.\n\n"
    'Respond with JSON only:\n'
    '{\n'
    '  "classification": "SENSITIVE|NOT_SENSITIVE|UNCERTAIN",\n'
    '  "confidence": 0.0,\n'
    '  "categories": ["..."],\n'
    '  "reasoning": "2-3 sentence explanation"\n'
    '}'
)


def build_classification_prompt(text: str, findings: list[DetectionResult]) -> str:
    """Builds the Tier 2 user prompt: Tier 0 findings as context, followed by
    the raw email content."""
    findings_json = json.dumps(
        [dataclasses.asdict(result) for result in findings], default=str
    )
    return f"TIER_0_FINDINGS:\n{findings_json}\n\nEMAIL_CONTENT:\n{text}"
