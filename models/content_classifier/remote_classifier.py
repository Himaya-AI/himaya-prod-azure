"""
RemoteContentClassifier — HTTP client for the standalone Helios classifier service
(Kimi K2.5 via AWS Bedrock, hosted at the ELB in `feature/benchmark`).

Behavior:
- Primary path: POST /classify on the remote classifier-service.
- Fallback path (TIMEOUT ONLY): local Claude Haiku via Anthropic API.
- Any other failure (HTTP 5xx, parse error, etc.) raises so the caller can decide
  what to do — we deliberately do NOT silently fall back on non-timeout errors so
  upstream observability stays clear.

Output shape matches `models.content_classifier.classifier._parse_llm_response()`
and `models.shared.schemas.ContentClassificationResult` so the rest of the
pipeline doesn't need to know whether Kimi or Haiku produced the verdict.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any

import httpx

from models.shared.schemas import ContentClassificationResult

logger = logging.getLogger(__name__)


# Default endpoint — the production classifier-service ELB
DEFAULT_CLASSIFIER_URL = "http://classify-lb-556047835.us-east-1.elb.amazonaws.com"

# Wider timeout to account for Kimi's 7–14s end-to-end latency observed in prod
DEFAULT_PRIMARY_TIMEOUT_SECONDS = 45.0

# Haiku fallback uses its own (shorter) timeout because we only enter that
# path after the primary has already burned its full timeout
DEFAULT_FALLBACK_TIMEOUT_SECONDS = 25.0


class RemoteClassifierTimeout(Exception):
    """Raised when the remote classifier service does not respond in time."""


class RemoteClassifierError(Exception):
    """Raised for any non-timeout failure of the remote classifier service."""


class RemoteContentClassifier:
    """
    Drop-in replacement for ``models.content_classifier.classifier.ContentClassifier``
    that calls the remote classifier microservice.

    Adds a Haiku fallback that ONLY triggers on timeout. All other failures
    (HTTP error, JSON parse error, schema validation error) propagate so the
    caller's outer except block can record them.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout_seconds: float | None = None,
        fallback_enabled: bool = True,
        fallback_timeout_seconds: float | None = None,
        anthropic_api_key: str | None = None,
    ) -> None:
        url = (base_url or os.getenv("CLASSIFIER_SERVICE_URL", DEFAULT_CLASSIFIER_URL)).rstrip("/")
        primary_timeout = float(
            timeout_seconds
            if timeout_seconds is not None
            else os.getenv("CLASSIFIER_SERVICE_TIMEOUT", DEFAULT_PRIMARY_TIMEOUT_SECONDS)
        )
        self._url = url
        self._primary_timeout = primary_timeout
        self._client = httpx.AsyncClient(
            base_url=url,
            timeout=httpx.Timeout(primary_timeout),
        )
        self._fallback_enabled = fallback_enabled and bool(
            anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        )
        self._fallback_timeout = float(
            fallback_timeout_seconds
            if fallback_timeout_seconds is not None
            else os.getenv("CLASSIFIER_FALLBACK_TIMEOUT", DEFAULT_FALLBACK_TIMEOUT_SECONDS)
        )
        self._anthropic_api_key = anthropic_api_key or os.getenv("ANTHROPIC_API_KEY")
        self._fallback_classifier = None  # lazy-built ContentClassifier(Haiku) on first need
        logger.info(
            "RemoteContentClassifier initialised | url=%s primary_timeout=%.1fs "
            "fallback=%s fallback_timeout=%.1fs",
            url,
            primary_timeout,
            "haiku" if self._fallback_enabled else "off",
            self._fallback_timeout,
        )

    async def aclose(self) -> None:
        try:
            await self._client.aclose()
        except Exception:
            pass

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
        payload: dict[str, Any] = {
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "attachments": attachments,
            "headers": headers,
            "email_verify": email_verify,
        }

        # ── Primary path: remote Kimi service ────────────────────────────
        t0 = time.perf_counter()
        try:
            response = await self._client.post("/classify", json=payload)
            response.raise_for_status()
            result = ContentClassificationResult.model_validate(response.json())
            # Service supplies latency_ms from its side; preserve it but also
            # report wall-clock from our side for observability if missing.
            if not getattr(result, "latency_ms", None):
                result.latency_ms = (time.perf_counter() - t0) * 1000
            logger.info(
                "remote_classifier: model=%s class=%s conf=%.2f cost=$%.5f latency=%.0fms",
                result.model_used,
                result.classification,
                result.confidence,
                result.cost_usd or 0.0,
                result.latency_ms or 0.0,
            )
            return result

        except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.WriteTimeout,
                httpx.PoolTimeout, asyncio.TimeoutError) as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            logger.warning(
                "remote_classifier: TIMEOUT after %.0fms (%s) — falling back to Haiku",
                elapsed, type(exc).__name__,
            )
            if self._fallback_enabled:
                return await self._haiku_fallback(
                    sender=sender, recipient=recipient, subject=subject,
                    body=body, attachments=attachments, headers=headers,
                    email_verify=email_verify,
                )
            raise RemoteClassifierTimeout(
                f"Remote classifier timed out after {self._primary_timeout}s "
                "and no Haiku fallback is configured."
            ) from exc

        except httpx.HTTPStatusError as exc:
            # Non-timeout error: log + re-raise so caller can fall through to its
            # own outer except (heuristic, etc). Do NOT silently fall back.
            logger.error(
                "remote_classifier: HTTP %s from %s — body=%s",
                exc.response.status_code, self._url, exc.response.text[:200],
            )
            raise RemoteClassifierError(
                f"Remote classifier returned HTTP {exc.response.status_code}"
            ) from exc

        except Exception as exc:
            logger.error("remote_classifier: unexpected error: %s", exc, exc_info=True)
            raise RemoteClassifierError(f"Remote classifier error: {exc}") from exc

    # ── Haiku fallback (timeout-only) ───────────────────────────────────────

    async def _haiku_fallback(
        self,
        sender: str,
        recipient: str,
        subject: str,
        body: str,
        attachments: list[str] | None,
        headers: dict[str, str] | None,
        email_verify: dict[str, Any] | None,
    ) -> ContentClassificationResult:
        """
        Fall back to Claude Haiku via the local ContentClassifier when the
        remote service times out. Uses the exact same prompt + few-shot pack +
        output schema, just swapping the model id.
        """
        if self._fallback_classifier is None:
            # Lazy build to avoid importing anthropic at module load time
            self._fallback_classifier = _build_haiku_classifier(
                anthropic_api_key=self._anthropic_api_key,
                timeout_seconds=self._fallback_timeout,
            )
            if self._fallback_classifier is None:
                logger.error(
                    "remote_classifier: Haiku fallback requested but ContentClassifier "
                    "could not be initialised. Re-raising timeout."
                )
                raise RemoteClassifierTimeout(
                    "Remote classifier timed out and Haiku fallback is unavailable."
                )

        try:
            result = await self._fallback_classifier.classify(
                sender=sender, recipient=recipient,
                subject=subject, body=body,
                attachments=attachments, headers=headers,
                email_verify=email_verify,
            )
            # Tag the model so downstream telemetry can distinguish fallback runs
            if result.model_used and "fallback" not in result.model_used:
                result.model_used = f"{result.model_used}-fallback"
            logger.info(
                "remote_classifier: HAIKU FALLBACK ok | class=%s conf=%.2f cost=$%.5f",
                result.classification, result.confidence, result.cost_usd or 0.0,
            )
            return result
        except Exception as exc:
            logger.error("remote_classifier: Haiku fallback also failed: %s", exc)
            raise RemoteClassifierError(
                f"Both remote classifier and Haiku fallback failed: {exc}"
            ) from exc


HAIKU_MODEL_ID = "claude-haiku-4-5"


def _build_haiku_classifier(
    anthropic_api_key: str | None,
    timeout_seconds: float,
):
    """
    Build a local ContentClassifier pinned to claude-haiku-4-5.

    We can't use the regular ContentClassifier constructor because it requires
    both Anthropic + OpenAI keys (it eagerly instantiates `openai.AsyncOpenAI`).
    The Haiku-only fallback doesn't need OpenAI, so we build a subclass that:
      1. Skips parent __init__ (no OpenAI client needed)
      2. Overrides _call_claude to use Haiku's model id directly (not the
         imported CLAUDE_MODEL constant, which is bound at import time)
      3. Overrides classify() to use HAIKU_MODEL_ID for model_used + cost calc
    Reuses prompt + few-shot pack + response parsing from the parent so the
    output shape is identical.
    """
    if not anthropic_api_key:
        logger.error("remote_classifier: no Anthropic API key available for Haiku fallback")
        return None
    try:
        import asyncio as _asyncio
        import time as _time
        import anthropic  # type: ignore
        from pydantic import ValidationError
        from models.content_classifier.classifier import ContentClassifier, _parse_llm_response, _make_uncertain_result
        from models.shared.config import LLM_MAX_TOKENS, LLM_TEMPERATURE
        from models.content_classifier.prompts import SYSTEM_PROMPT, get_messages_for_classification

        # Haiku pricing (per 1M tokens) — https://www.anthropic.com/pricing
        HAIKU_INPUT_PER_1M = 1.00
        HAIKU_OUTPUT_PER_1M = 5.00

        class _HaikuOnlyClassifier(ContentClassifier):
            """
            ContentClassifier pinned to claude-haiku-4-5 — fully self-contained,
            bypasses parent constructor (no OpenAI requirement) and parent
            classify() so we tag the model correctly and price using Haiku rates.
            """

            def __init__(self, api_key: str, timeout: float) -> None:  # noqa: D401
                self.timeout = timeout
                self.include_few_shot = True
                self.claude_client = anthropic.AsyncAnthropic(api_key=api_key)
                self.openai_client = None

            async def _call_haiku(self, messages):
                response = await _asyncio.wait_for(
                    self.claude_client.messages.create(
                        model=HAIKU_MODEL_ID,
                        max_tokens=LLM_MAX_TOKENS,
                        temperature=LLM_TEMPERATURE,
                        system=SYSTEM_PROMPT,
                        messages=messages,
                    ),
                    timeout=self.timeout,
                )
                content = response.content[0].text if response.content else ""
                return content, response.usage.input_tokens, response.usage.output_tokens

            @staticmethod
            def _haiku_cost(in_tok: int, out_tok: int) -> float:
                return (in_tok * HAIKU_INPUT_PER_1M + out_tok * HAIKU_OUTPUT_PER_1M) / 1_000_000

            async def classify(  # type: ignore[override]
                self,
                sender: str,
                recipient: str,
                subject: str,
                body: str,
                attachments: list[str] | None = None,
                headers: dict[str, str] | None = None,
            ):
                t0 = _time.perf_counter()
                messages = get_messages_for_classification(
                    sender=sender, recipient=recipient, subject=subject,
                    body=body, attachments=attachments, headers=headers,
                    include_few_shot=self.include_few_shot,
                )
                try:
                    raw, in_tok, out_tok = await self._call_haiku(messages)
                    result = _parse_llm_response(raw, HAIKU_MODEL_ID)
                    result.input_tokens = in_tok
                    result.output_tokens = out_tok
                    result.cost_usd = self._haiku_cost(in_tok, out_tok)
                    result.latency_ms = (_time.perf_counter() - t0) * 1000
                    return result
                except (_asyncio.TimeoutError, ValueError, ValidationError, Exception) as exc:
                    logger.error("haiku fallback inner call failed: %s", exc)
                    result = _make_uncertain_result(model_name=f"{HAIKU_MODEL_ID}-failed")
                    result.latency_ms = (_time.perf_counter() - t0) * 1000
                    return result

        return _HaikuOnlyClassifier(api_key=anthropic_api_key, timeout=timeout_seconds)
    except Exception as exc:
        logger.error("remote_classifier: could not build Haiku fallback: %s", exc, exc_info=True)
        return None
