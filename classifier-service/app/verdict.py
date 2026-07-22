"""
VerdictClassifier — Helios Analysis verdict engine running on Bedrock Kimi K2.5.

This mirrors the Helios `_get_helios_verdict()` function from the main backend's
auto_triage_service.py, but uses Bedrock Kimi instead of Anthropic Opus. It
takes a full threat dossier (sender, VT results, graph history, sandbox audit,
etc.) and returns a structured verdict JSON.

Output contract is identical to the legacy backend path so nothing downstream
breaks:
    {
      "verdict": "QUARANTINE|MARK_AS_SPAM|ESCALATE|DISMISS",
      "threat_type": "PHISHING|BEC|MALWARE|SPAM|SAFE|UNKNOWN",
      "confidence": 0.0–1.0,
      "reasoning": "...",
      "key_evidence": [...],
      "notify_recipient": bool,
      "notify_admin": bool,
      "model_used": "moonshotai.kimi-k2.5",
      "input_tokens": int,
      "output_tokens": int,
      "cost_usd": float,
      "latency_ms": float,
    }
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime
from typing import Any

from config.aws import (
    CLASSIFICATION_MODEL,
    LLM_MAX_TOKENS,
    LLM_TEMPERATURE,
    LLM_TIMEOUT_SECONDS,
    bedrock_runtime,
)

logger = logging.getLogger(__name__)

# Same Bedrock Kimi K2.5 pricing as the classifier
LLM_INPUT_COST_PER_1M = 0.60
LLM_OUTPUT_COST_PER_1M = 2.50

VALID_VERDICTS = {"QUARANTINE", "MARK_AS_SPAM", "ESCALATE", "DISMISS"}
VALID_THREAT_TYPES = {"PHISHING", "BEC", "MALWARE", "SPAM", "SAFE", "UNKNOWN"}


def _build_helios_system_prompt() -> str:
    """Match _build_helios_system_prompt() in backend/services/auto_triage_service.py."""
    today = datetime.utcnow().strftime("%B %d, %Y")
    year = datetime.utcnow().year
    return (
        f"You are Helios Analysis, an autonomous email security engine for enterprise organizations "
        f"in the Gulf region.\n\n"
        f"CURRENT DATE: {today}. This is the real current date - use it when reasoning about dates "
        f"in email content, filenames, or deadlines. Do not treat dates in {year} as future or unusual.\n\n"
        "You are given a full threat dossier for a suspicious email. Your job is to make a definitive, "
        "justified verdict.\n\n"
        "VERDICT OPTIONS:\n"
        "- QUARANTINE: High-confidence threat. Move to quarantine folder immediately. Notify recipient and admin.\n"
        "- MARK_AS_SPAM: Clear spam with no malicious payload. Move to junk. No admin alert needed.\n"
        "- ESCALATE: Uncertain or sophisticated threat requiring human review. Flag as high-risk, alert admin.\n"
        "- DISMISS: Low-risk or likely false positive. Mark as resolved, no action.\n\n"
        "ANALYSIS FRAMEWORK:\n"
        "1. Sender reputation: Is the domain newly registered? Does it appear on threat feeds? Graph history?\n"
        "2. Content analysis: AI classification confidence, threat type, urgency signals, impersonation markers\n"
        "3. URL analysis: Are URLs on malware/phishing feeds? VirusTotal results?\n"
        "4. Attachment analysis: Is the file type dangerous? What does the name suggest?\n"
        "5. Context: Is this sender known? Have they sent legitimate mail before?\n\n"
        "USER-REPORTED EMAILS: If user_reported=true, the email was flagged by an employee as suspicious.\n"
        "Weight this signal: employees rarely report legitimate emails. Lean toward ESCALATE or QUARANTINE\n"
        "unless there is very strong evidence it is clean (e.g., known internal sender, domain in allow list).\n\n"
        'RESPONSE FORMAT (JSON only, no markdown, no explanation outside JSON):\n'
        '{\n'
        '  "verdict": "QUARANTINE|MARK_AS_SPAM|ESCALATE|DISMISS",\n'
        '  "threat_type": "PHISHING|BEC|MALWARE|SPAM|SAFE",\n'
        '  "confidence": 0.0,\n'
        '  "reasoning": "2-3 sentence explanation of why",\n'
        '  "key_evidence": ["evidence point 1", "evidence point 2"],\n'
        '  "notify_recipient": true,\n'
        '  "notify_admin": true\n'
        '}\n\n'
        "THREAT TYPE DEFINITIONS:\n"
        "- PHISHING: Credential theft, fake login pages, deceptive links impersonating trusted brands\n"
        "- BEC: Business Email Compromise - impersonating executives/finance to request wire transfers or data\n"
        "- MALWARE: Malicious attachments, macro-enabled docs, drive-by downloads\n"
        "- SPAM: Unsolicited bulk email without malicious payload\n"
        "- SAFE: Legitimate email, no threat detected"
    )


def _normalize_verdict(raw: dict, dossier: dict) -> dict:
    """Validate + normalize verdict JSON to the public contract."""
    verdict = raw.get("verdict", "ESCALATE")
    if verdict not in VALID_VERDICTS:
        verdict = "ESCALATE"

    threat_type = raw.get("threat_type", "UNKNOWN")
    if threat_type not in VALID_THREAT_TYPES:
        threat_type = "UNKNOWN"

    try:
        confidence = float(raw.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    confidence = max(0.0, min(1.0, confidence))

    return {
        "verdict": verdict,
        "threat_type": threat_type,
        "confidence": confidence,
        "reasoning": str(raw.get("reasoning", "")),
        "key_evidence": list(raw.get("key_evidence", []) or []),
        "notify_recipient": bool(raw.get("notify_recipient", False)),
        "notify_admin": bool(raw.get("notify_admin", verdict in ("QUARANTINE", "ESCALATE"))),
    }


def _heuristic_fallback(dossier: dict) -> dict:
    """When LLM is unreachable, fall back to risk-score-based verdict (same as legacy)."""
    risk = dossier.get("risk_score", 0) or 0
    if risk >= 75:
        verdict = "QUARANTINE"
    elif risk >= 50:
        verdict = "ESCALATE"
    else:
        verdict = "DISMISS"
    return {
        "verdict": verdict,
        "threat_type": "UNKNOWN",
        "confidence": 0.5,
        "reasoning": f"Helios Analysis fallback — verdict based on risk score ({risk}).",
        "key_evidence": [f"risk_score:{risk}"],
        "notify_recipient": False,
        "notify_admin": verdict in ("QUARANTINE", "ESCALATE"),
    }


class VerdictClassifier:
    """Bedrock-backed Helios Analysis verdict engine."""

    def __init__(
        self,
        model_id: str = CLASSIFICATION_MODEL,
        timeout_seconds: float = LLM_TIMEOUT_SECONDS,
    ) -> None:
        self.model_id = model_id
        self.timeout = timeout_seconds

    async def _call_llm(self, dossier: dict) -> tuple[str, int, int]:
        """Single Bedrock converse call returning (text, in_tok, out_tok)."""
        user_message = (
            "Please analyse the following threat dossier and return your verdict as JSON:\n\n"
            + json.dumps(dossier, indent=2, default=str)
        )

        response = await asyncio.wait_for(
            asyncio.to_thread(
                bedrock_runtime.converse,
                modelId=self.model_id,
                system=[{"text": _build_helios_system_prompt()}],
                messages=[{"role": "user", "content": [{"text": user_message}]}],
                inferenceConfig={
                    "temperature": LLM_TEMPERATURE,
                    "maxTokens": LLM_MAX_TOKENS,
                },
            ),
            timeout=self.timeout,
        )

        output = response.get("output", {}).get("message", {})
        content_blocks = output.get("content", [])
        text = content_blocks[0].get("text", "") if content_blocks else ""

        usage = response.get("usage", {})
        return text, usage.get("inputTokens", 0), usage.get("outputTokens", 0)

    def _compute_cost(self, in_tok: int, out_tok: int) -> float:
        return (in_tok * LLM_INPUT_COST_PER_1M + out_tok * LLM_OUTPUT_COST_PER_1M) / 1_000_000

    async def verdict(self, dossier: dict) -> dict:
        """Run verdict with one retry. On total failure, return heuristic fallback."""
        t0 = time.time()
        last_err: str | None = None

        for attempt in (1, 2):
            try:
                raw_text, in_tok, out_tok = await self._call_llm(dossier)

                # Extract JSON (handle markdown fences)
                json_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
                if not json_match:
                    raise ValueError("No JSON found in verdict response")

                parsed = json.loads(json_match.group())
                normalized = _normalize_verdict(parsed, dossier)
                normalized.update({
                    "model_used": self.model_id,
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                    "cost_usd": self._compute_cost(in_tok, out_tok),
                    "latency_ms": (time.time() - t0) * 1000,
                })
                if attempt > 1:
                    logger.info(f"verdict succeeded on retry attempt {attempt}")
                return normalized

            except asyncio.TimeoutError:
                last_err = f"timeout after {self.timeout}s"
                logger.warning(f"verdict attempt {attempt}: {last_err}")
            except (ValueError, json.JSONDecodeError) as e:
                last_err = f"parse error: {e}"
                logger.warning(f"verdict attempt {attempt}: {last_err}")
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                logger.warning(f"verdict attempt {attempt}: {last_err}")

            if attempt == 1:
                await asyncio.sleep(0.5)

        # Both attempts failed → heuristic fallback
        logger.error(f"verdict: all attempts failed ({last_err}), returning heuristic")
        fallback = _heuristic_fallback(dossier)
        fallback.update({
            "model_used": f"{self.model_id}-failed-heuristic",
            "input_tokens": 0,
            "output_tokens": 0,
            "cost_usd": 0.0,
            "latency_ms": (time.time() - t0) * 1000,
        })
        return fallback
