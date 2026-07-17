from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from pydantic import ValidationError

from utils.schema import (
    ContentClassificationResult,
    ContentSignal,
    EmailLanguage,
    ThreatClassification,
)
from config.aws import (
    CLASSIFICATION_MODEL,
    LLM_MAX_TOKENS,
    LLM_TEMPERATURE,
    LLM_TIMEOUT_SECONDS,
    bedrock_runtime,
)

from utils.prompt_loader import get_system_prompt, get_messages_for_classification

logger = logging.getLogger(__name__)

# AWS Bedrock on-demand pricing for moonshotai.kimi-k2.5 (us-east-1, verified 2026-06-15)
#   Input:  $0.60 per 1M tokens
#   Output: $2.50 per 1M tokens
# Source: https://aws.amazon.com/bedrock/pricing/
#
# These constants were previously $15/$15 (copy-pasted from Claude Opus) which
# caused cost_usd to be over-reported by ~22× on every classification.
LLM_INPUT_COST_PER_1M = 0.60
LLM_OUTPUT_COST_PER_1M = 2.50

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
    text = raw.strip()
    if "```json" in text:
        text = text.split("```json")[1].split("```")[0].strip()
    elif "```" in text:
        text = text.split("```")[1].split("```")[0].strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON decode error: {e}. Raw: {text[:200]}")

    signals = [
        ContentSignal(
            name=sig.get("name", ""),
            value=str(sig.get("value", "")),
            weight=float(sig.get("weight", 0.0)),
        )
        for sig in data.get("signals", [])
    ]

    lang_raw = data.get("language", "en").lower()
    try:
        language = EmailLanguage(lang_raw)
    except ValueError:
        language = EmailLanguage.EN

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
    return ContentClassificationResult(
        **{**UNCERTAIN_RESULT_DICT, "model_used": model_name, "input_tokens": input_tokens}
    )


class ContentClassifier:
    def __init__(
        self,
        model_id: str = CLASSIFICATION_MODEL,
        timeout_seconds: float = LLM_TIMEOUT_SECONDS,
        include_few_shot: bool = True,
    ) -> None:
        self.model_id = model_id
        self.timeout = timeout_seconds
        self.include_few_shot = include_few_shot

    async def _call_llm(self, messages: list[dict[str, str]]) -> tuple[str, int, int]:
        bedrock_messages = [
            {"role": m["role"], "content": [{"text": m["content"]}]}
            for m in messages
        ]

        response = await asyncio.wait_for(
            asyncio.to_thread(
                bedrock_runtime.converse,
                modelId=self.model_id,
                system=[{"text": get_system_prompt()}],
                messages=bedrock_messages,
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
        input_tokens = usage.get("inputTokens", 0)
        output_tokens = usage.get("outputTokens", 0)

        return text, input_tokens, output_tokens

    def _compute_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens * LLM_INPUT_COST_PER_1M
            + output_tokens * LLM_OUTPUT_COST_PER_1M
        ) / 1_000_000

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

        try:
            raw, in_tok, out_tok = await self._call_llm(messages)
            result = _parse_llm_response(raw, self.model_id)
            result.input_tokens = in_tok
            result.output_tokens = out_tok
            result.cost_usd = self._compute_cost(in_tok, out_tok)
            result.latency_ms = (time.time() - t0) * 1000
            logger.debug(
                f"LLM classification: {result.classification} "
                f"({result.confidence:.2f}) in {result.latency_ms:.0f}ms"
            )
            return result

        except asyncio.TimeoutError:
            logger.warning(f"LLM timed out after {self.timeout}s, retrying once...")
        except (ValueError, ValidationError) as e:
            logger.warning(f"LLM parse error: {e}, retrying once...")
        except Exception as e:
            logger.warning(f"LLM API error: {e}, retrying once...")

        await asyncio.sleep(1)
        try:
            raw, in_tok, out_tok = await self._call_llm(messages)
            result = _parse_llm_response(raw, self.model_id)
            result.input_tokens = in_tok
            result.output_tokens = out_tok
            result.cost_usd = self._compute_cost(in_tok, out_tok)
            result.latency_ms = (time.time() - t0) * 1000
            logger.info(
                f"LLM retry classification: {result.classification} ({result.confidence:.2f})"
            )
            return result

        except asyncio.TimeoutError:
            logger.error("LLM retry timed out. Returning UNCERTAIN.")
        except (ValueError, ValidationError) as e:
            logger.error(f"LLM retry parse error: {e}. Returning UNCERTAIN.")
        except Exception as e:
            logger.error(f"LLM retry API error: {e}. Returning UNCERTAIN.")

        uncertain = _make_uncertain_result(model_name="llm-retry-failed")
        uncertain.latency_ms = (time.time() - t0) * 1000
        return uncertain

    async def classify_batch(
        self,
        emails: list[dict[str, Any]],
        concurrency: int = 5,
    ) -> list[ContentClassificationResult]:
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
                    email_verify=email.get("email_verify"),
                )

        return await asyncio.gather(*[classify_with_sem(e) for e in emails])
