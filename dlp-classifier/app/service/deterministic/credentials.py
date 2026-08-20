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


class CredentialScanError(Exception):
    """BetterLeaks did not complete a trustworthy scan."""


async def _run_betterleaks(text: str) -> list[dict]:
    """Runs BetterLeaks over stdin and parses its JSON report.

    An empty report after a successful run means no findings. Timeout, crash,
    spawn failure, or malformed output raise CredentialScanError so callers
    can fail closed instead of treating the message as clean.
    """
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
    except Exception as exc:  # noqa: BLE001
        raise CredentialScanError(
            f"BetterLeaks could not be started: {exc}"
        ) from exc

    try:
        stdout, _stderr = await asyncio.wait_for(
            proc.communicate(input=text.encode()),
            timeout=settings.BETTERLEAKS_TIMEOUT,
        )
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise CredentialScanError("BetterLeaks timed out") from exc
    except Exception as exc:  # noqa: BLE001
        proc.kill()
        await proc.wait()
        raise CredentialScanError(
            f"BetterLeaks scan failed: {exc}"
        ) from exc

    if proc.returncode not in (0, None):
        raise CredentialScanError(
            f"BetterLeaks exited with code {proc.returncode}"
        )

    if not stdout or not stdout.strip():
        return []

    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CredentialScanError(
            "BetterLeaks returned malformed JSON"
        ) from exc

    if not isinstance(parsed, list):
        raise CredentialScanError(
            "BetterLeaks report was not a JSON array"
        )

    findings: list[dict] = []
    for item in parsed:
        if not isinstance(item, dict) or "RuleID" not in item:
            raise CredentialScanError(
                "BetterLeaks finding was missing RuleID"
            )
        findings.append(item)
    return findings


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
                return DetectionResult(
                    detector=self.name, matches=[], escalate=False
                )

            matches = [
                _to_detection_match(finding, self.name) for finding in findings
            ]
            return DetectionResult(
                detector=self.name, matches=matches, escalate=False
            )
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(
                detector=self.name,
                matches=[],
                escalate=True,
                error=str(exc),
            )
