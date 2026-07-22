from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from app.service.base import BaseDetector, DetectionMatch, DetectionResult
from config.settings import get_settings

# BetterLeaks already filters false positives via Token Efficiency and CEL.
# By the time a finding is returned it is already high confidence.
# No per-rule scoring needed — BetterLeaks is authoritative.
CREDENTIAL_SCORE: float = 0.95


async def _run_betterleaks(text: str) -> list[dict]:
    """Runs BetterLeaks over stdin and parses its JSON report. Never raises —
    a timeout, a crash, or malformed output all just yield no findings."""
    settings = get_settings()

    try:
        proc = await asyncio.create_subprocess_exec(
            settings.BETTERLEAKS_BINARY,
            "stdin",
            "--report-format",
            "json",
            "--report-path",
            "-",
            "--no-banner",
            "--redact",
            "--exit-code",
            "0",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, _stderr = await asyncio.wait_for(
                proc.communicate(input=text.encode()),
                timeout=settings.BETTERLEAKS_TIMEOUT,
            )
        except asyncio.TimeoutError:
            proc.kill()
            return []

        if not stdout or not stdout.strip():
            return []

        return json.loads(stdout)
    except Exception:  # noqa: BLE001
        return []


def _to_entity_type(rule_id: str) -> str:
    """e.g. "github-fine-grained-pat" -> "GITHUB_FINE_GRAINED_PAT"."""
    return rule_id.upper().replace("-", "_")


def _to_detection_match(finding: dict, detector_name: str) -> DetectionMatch:
    rule_id = finding["RuleID"]
    return DetectionMatch(
        detector=detector_name,
        entity_type=_to_entity_type(rule_id),
        score=CREDENTIAL_SCORE,
        start=0,  # not needed for email DLP
        end=0,  # not needed for email DLP
        metadata={
            "rule_id": finding["RuleID"],
            "description": finding["Description"],
            "fingerprint": finding.get("Fingerprint", ""),
            "entropy": finding.get("Entropy", 0.0),
            "line_number": finding.get("StartLine", 0),
            "redacted": True,
        },
    )


class CredentialDetector(BaseDetector):
    def __init__(self) -> None:
        settings = get_settings()
        binary = settings.BETTERLEAKS_BINARY

        if not Path(binary).is_file():
            raise RuntimeError(f"BetterLeaks binary not found: {binary}")
        if not os.access(binary, os.X_OK):
            raise RuntimeError(f"BetterLeaks binary not executable: {binary}")

    @property
    def name(self) -> str:
        return "credential"

    async def analyze(self, text: str, metadata: dict[str, Any]) -> DetectionResult:
        try:
            findings = await _run_betterleaks(text)
            if not findings:
                return DetectionResult(detector=self.name, matches=[], escalate=False)

            matches = [_to_detection_match(finding, self.name) for finding in findings]
            return DetectionResult(detector=self.name, matches=matches, escalate=False)
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(
                detector=self.name, matches=[], escalate=False, error=str(exc)
            )
