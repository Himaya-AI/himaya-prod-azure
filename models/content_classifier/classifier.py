"""
Himaya Helios - MODEL-002: LLM Content Classifier
Async classification using Claude (primary) with GPT-4o fallback.
Includes cost tracking, timeout handling, and Pydantic v2 validation.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import anthropic
import openai
from pydantic import ValidationError

from models.content_classifier.prompts import (
    SYSTEM_PROMPT,
    get_messages_for_classification,
)
from models.shared.config import (
    CLAUDE_MODEL,
    OPENAI_MODEL,
    LLM_TIMEOUT_SECONDS,
    LLM_TEMPERATURE,
    LLM_MAX_TOKENS,
)
from models.shared.schemas import (
    ContentClassificationResult,
    ContentSignal,
    ThreatClassification,
    EmailLanguage,
)

logger = logging.getLogger(__name__)

# Cost per 1M tokens (USD) - approximate as of early 2025
CLAUDE_INPUT_COST_PER_1M = 15.00  # claude-opus-4-5
CLAUDE_OUTPUT_COST_PER_1M = 15.00
GPT4O_INPUT_COST_PER_1M = 2.50
GPT4O_OUTPUT_COST_PER_1M = 10.00

# UNCERTAIN fallback result
UNCERTAIN_RESULT_DICT: dict[str, Any] = {
    "threat_indicators": [],
    "urgency_score": 0,
    "impersonation_detected": False,
    "impersonation_target": None,
    "language": "en",
    "classification": "UNCERTAIN",
    "confidence": 0.0,
    "explanation_ar": "لم يتمكن نظام الذكاء الاصطناعي من إجراء تحليل كامل. يُنصح بمراجعة هذا البريد يدوياً.",
    "explanation_en": "AI analysis was inconclusive for this email — heuristic scoring was used. Manual review is recommended.",
    "signals": [],
}


def _parse_llm_response(raw: str, model_name: str) -> ContentClassificationResult:
    """
    Parse and validate LLM JSON response into ContentClassificationResult.

    Args:
        raw: Raw string response from LLM
        model_name: Model name for tracking

    Returns:
        Validated ContentClassificationResult

    Raises:
        ValueError: If parsing or validation fails
    """
    # Extract JSON block if wrapped in markdown
    text = raw.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON decode error: {e}. Raw: {text[:200]}")

    # Normalize signals
    signals = []
    for sig in data.get("signals", []):
        signals.append(ContentSignal(
            name=sig.get("name", ""),
            value=str(sig.get("value", "")),
            weight=float(sig.get("weight", 0.0)),
        ))

    # Normalize language
    lang_raw = data.get("language", "en").lower()
    try:
        language = EmailLanguage(lang_raw)
    except ValueError:
        language = EmailLanguage.EN

    # Normalize classification
    cls_raw = data.get("classification", "UNCERTAIN").upper()
    try:
        classification = ThreatClassification(cls_raw)
    except ValueError:
        classification = ThreatClassification.UNCERTAIN

    return ContentClassificationResult(
        threat_indicators=data.get("threat_indicators", []),
        urgency_score=int(data.get("urgency_score", 0)),
        impersonation_detected=bool(data.get("impersonation_detected", False)),
        impersonation_target=data.get("impersonation_target"),
        language=language,
        classification=classification,
        confidence=float(data.get("confidence", 0.0)),
        explanation_ar=data.get("explanation_ar", ""),
        explanation_en=data.get("explanation_en", ""),
        signals=signals,
        model_used=model_name,
    )


def _make_uncertain_result(model_name: str, input_tokens: int = 0) -> ContentClassificationResult:
    """Return an UNCERTAIN fallback result."""
    return ContentClassificationResult(
        **{**UNCERTAIN_RESULT_DICT, "model_used": model_name, "input_tokens": input_tokens}
    )


class ContentClassifier:
    """
    LLM-based email content classifier for Gulf cybersecurity threats.

    Primary model: Claude (claude-opus-4-5-20251101)
    Fallback model: GPT-4o

    Features:
    - Async API calls with 3-second timeout
    - Graceful fallback to GPT-4o on Claude timeout/error
    - Final UNCERTAIN result if both models fail
    - Per-call cost tracking
    - Pydantic v2 response validation
    """

    def __init__(
        self,
        anthropic_api_key: str | None = None,
        openai_api_key: str | None = None,
        timeout_seconds: float = LLM_TIMEOUT_SECONDS,
        include_few_shot: bool = True,
    ) -> None:
        """
        Initialize classifier with API clients.

        Args:
            anthropic_api_key: Anthropic API key (reads ANTHROPIC_API_KEY env if None)
            openai_api_key: OpenAI API key (reads OPENAI_API_KEY env if None)
            timeout_seconds: Request timeout in seconds
            include_few_shot: Whether to include few-shot examples in prompts
        """
        self.timeout = timeout_seconds
        self.include_few_shot = include_few_shot

        self.claude_client = anthropic.AsyncAnthropic(api_key=anthropic_api_key)
        self.openai_client = openai.AsyncOpenAI(api_key=openai_api_key)

    async def _call_claude(
        self,
        messages: list[dict[str, str]],
    ) -> tuple[str, int, int]:
        """
        Call Claude API.

        Returns:
            (response_text, input_tokens, output_tokens)
        """
        response = await asyncio.wait_for(
            self.claude_client.messages.create(
                model=CLAUDE_MODEL,
                max_tokens=LLM_MAX_TOKENS,
                temperature=LLM_TEMPERATURE,
                system=SYSTEM_PROMPT,
                messages=messages,
            ),
            timeout=self.timeout,
        )

        content = response.content[0].text if response.content else ""
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        return content, input_tokens, output_tokens

    async def _call_openai(
        self,
        messages: list[dict[str, str]],
    ) -> tuple[str, int, int]:
        """
        Call OpenAI GPT-4o API.

        Returns:
            (response_text, input_tokens, output_tokens)
        """
        full_messages = [{"role": "system", "content": SYSTEM_PROMPT}] + messages

        response = await asyncio.wait_for(
            self.openai_client.chat.completions.create(
                model=OPENAI_MODEL,
                max_tokens=LLM_MAX_TOKENS,
                temperature=LLM_TEMPERATURE,
                messages=full_messages,
                response_format={"type": "json_object"},
            ),
            timeout=self.timeout,
        )

        content = response.choices[0].message.content or ""
        input_tokens = response.usage.prompt_tokens if response.usage else 0
        output_tokens = response.usage.completion_tokens if response.usage else 0
        return content, input_tokens, output_tokens

    def _compute_cost(
        self,
        input_tokens: int,
        output_tokens: int,
        model: str,
    ) -> float:
        """Compute cost in USD for a call."""
        if "claude" in model.lower():
            return (input_tokens * CLAUDE_INPUT_COST_PER_1M + output_tokens * CLAUDE_OUTPUT_COST_PER_1M) / 1_000_000
        elif "gpt" in model.lower():
            return (input_tokens * GPT4O_INPUT_COST_PER_1M + output_tokens * GPT4O_OUTPUT_COST_PER_1M) / 1_000_000
        return 0.0

    async def classify(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        attachments: list[str] | None = None,
        headers: dict[str, str] | None = None,
        email_verify: dict[str, Any] | None = None,
    ) -> ContentClassificationResult:
        """
        Classify an email for threats. Uses Claude with GPT-4o fallback.

        Args:
            sender: Sender email address
            recipient: Recipient email address
            subject: Email subject
            body: Email body text
            attachments: List of attachment filenames
            headers: Email header analysis results (SPF, DKIM, DMARC)

        Returns:
            ContentClassificationResult with classification and confidence
        """
        t0 = time.time()

        messages = get_messages_for_classification(
            sender=sender,
            recipient=recipient,
            subject=subject,
            body=body,
            attachments=attachments,
            headers=headers,
            email_verify=email_verify,
            include_few_shot=self.include_few_shot,
        )

        # --- Primary: Claude ---
        claude_error: str | None = None
        try:
            raw, in_tok, out_tok = await self._call_claude(messages)
            result = _parse_llm_response(raw, CLAUDE_MODEL)
            result.input_tokens = in_tok
            result.output_tokens = out_tok
            result.cost_usd = self._compute_cost(in_tok, out_tok, CLAUDE_MODEL)
            result.latency_ms = (time.time() - t0) * 1000
            logger.debug(f"Claude classification: {result.classification} ({result.confidence:.2f}) in {result.latency_ms:.0f}ms")
            return result

        except asyncio.TimeoutError:
            claude_error = "timeout"
            logger.warning(f"Claude timed out after {self.timeout}s, falling back to GPT-4o")
        except (ValueError, ValidationError) as e:
            claude_error = str(e)
            logger.warning(f"Claude parse error: {e}, falling back to GPT-4o")
        except Exception as e:
            claude_error = str(e)
            logger.warning(f"Claude API error: {e}, falling back to GPT-4o")

        # --- Claude failed: retry once with shorter timeout before giving up ---
        # GPT-4o fallback removed — OpenAI quota is unreliable, Claude is the sole classifier.
        # On Claude failure, retry once after a brief delay.
        logger.warning(f"Claude failed ({claude_error}), retrying once...")
        await asyncio.sleep(1)
        try:
            raw, in_tok, out_tok = await self._call_claude(messages)
            result = _parse_llm_response(raw, CLAUDE_MODEL)
            result.input_tokens = in_tok
            result.output_tokens = out_tok
            result.cost_usd = self._compute_cost(in_tok, out_tok, CLAUDE_MODEL)
            result.latency_ms = (time.time() - t0) * 1000
            logger.info(f"Claude retry classification: {result.classification} ({result.confidence:.2f})")
            return result
        except asyncio.TimeoutError:
            logger.error("Claude retry timed out. Returning UNCERTAIN.")
        except (ValueError, ValidationError) as e:
            logger.error(f"Claude retry parse error: {e}. Returning UNCERTAIN.")
        except Exception as e:
            logger.error(f"Claude retry API error: {e}. Returning UNCERTAIN.")

        # --- Both Claude attempts failed ---
        uncertain = _make_uncertain_result(model_name="claude-retry-failed")
        uncertain.latency_ms = (time.time() - t0) * 1000
        return uncertain

    async def classify_batch(
        self,
        emails: list[dict[str, Any]],
        concurrency: int = 5,
    ) -> list[ContentClassificationResult]:
        """
        Classify multiple emails concurrently.

        Args:
            emails: List of dicts with keys: sender, recipient, subject, body, attachments, headers
            concurrency: Max concurrent API calls

        Returns:
            List of ContentClassificationResult in same order
        """
        semaphore = asyncio.Semaphore(concurrency)

        async def classify_with_sem(email: dict[str, Any]) -> ContentClassificationResult:
            async with semaphore:
                return await self.classify(
                    sender=email["sender"],
                    recipient=email["recipient"],
                    subject=email["subject"],
                    body=email["body"],
                    attachments=email.get("attachments"),
                    headers=email.get("headers"),
                )

        return await asyncio.gather(*[classify_with_sem(e) for e in emails])
