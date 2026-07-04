"""
Unit tests for the RemoteContentClassifier (Kimi K2.5 primary, Haiku timeout fallback).

These tests use mocked httpx + anthropic to avoid real network calls.
"""
from __future__ import annotations

import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Provide a placeholder Anthropic key so the fallback builder doesn't bail at import time
os.environ.setdefault("ANTHROPIC_API_KEY", "sk-ant-test-placeholder")

from models.content_classifier.remote_classifier import (  # noqa: E402
    DEFAULT_CLASSIFIER_URL,
    RemoteClassifierError,
    RemoteClassifierTimeout,
    RemoteContentClassifier,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _mock_remote_response_json(classification: str = "BEC", cost: float = 0.20):
    return {
        "threat_indicators": ["test indicator"],
        "urgency_score": 80,
        "impersonation_detected": True,
        "impersonation_target": "CEO",
        "language": "en",
        "classification": classification,
        "confidence": 0.95,
        "explanation_ar": "اختبار",
        "explanation_en": "Test classification",
        "signals": [{"name": "test", "value": "1", "weight": 0.9}],
        "model_used": "moonshotai.kimi-k2.5",
        "input_tokens": 12000,
        "output_tokens": 400,
        "cost_usd": cost,
        "latency_ms": 7000.0,
    }


# ── Happy path: remote service returns OK ────────────────────────────────────


@pytest.mark.asyncio
async def test_remote_classifier_happy_path(monkeypatch):
    """Remote service responds normally — no fallback invoked."""

    async def fake_post(self, url, json=None, **kwargs):
        req = httpx.Request("POST", url)
        return httpx.Response(200, json=_mock_remote_response_json(), request=req)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    c = RemoteContentClassifier(base_url="http://test-lb", timeout_seconds=45)
    result = await c.classify(
        sender="x@y", recipient="a@b", subject="s", body="b",
        attachments=None, headers={"SPF": "fail"},
    )
    assert result.classification.value == "BEC"
    assert result.model_used == "moonshotai.kimi-k2.5"
    assert "fallback" not in result.model_used
    await c.aclose()


# ── Timeout path: triggers Haiku fallback ────────────────────────────────────


@pytest.mark.asyncio
async def test_remote_classifier_timeout_triggers_fallback(monkeypatch):
    """A primary timeout should invoke the Haiku fallback, not propagate the timeout."""
    # Force httpx.AsyncClient.post to raise a timeout
    async def timeout_post(self, url, json=None, **kwargs):
        raise httpx.ReadTimeout("simulated timeout")

    monkeypatch.setattr(httpx.AsyncClient, "post", timeout_post)

    # Mock the Haiku fallback's anthropic call by replacing the inner
    # `_HaikuOnlyClassifier._call_haiku` method via class swap on `_build_haiku_classifier`.
    from models.content_classifier import remote_classifier as rc_module
    from models.shared.schemas import ContentClassificationResult, ThreatClassification, EmailLanguage

    class _FakeHaiku:
        async def classify(self, **kwargs):
            return ContentClassificationResult(
                threat_indicators=["fallback indicator"],
                urgency_score=70,
                impersonation_detected=False,
                impersonation_target=None,
                language=EmailLanguage.EN,
                classification=ThreatClassification.PHISHING,
                confidence=0.88,
                explanation_ar="اختبار",
                explanation_en="Fallback result",
                signals=[],
                model_used="claude-haiku-4-5",
                input_tokens=11000,
                output_tokens=350,
                cost_usd=0.018,
                latency_ms=4500.0,
            )

    monkeypatch.setattr(rc_module, "_build_haiku_classifier", lambda **k: _FakeHaiku())

    c = RemoteContentClassifier(
        base_url="http://test-lb",
        timeout_seconds=1.0,
        fallback_timeout_seconds=10.0,
    )
    result = await c.classify(
        sender="x@y", recipient="a@b", subject="s", body="b",
        attachments=None, headers={"SPF": "fail"},
    )
    assert result.classification.value == "PHISHING"
    assert "haiku" in result.model_used.lower()
    assert "fallback" in result.model_used.lower(), f"Expected fallback tag, got: {result.model_used}"
    await c.aclose()


# ── Non-timeout HTTP error: should NOT silently fall back ────────────────────


@pytest.mark.asyncio
async def test_remote_classifier_http_error_does_not_fall_back(monkeypatch):
    """A 5xx from the remote service should raise, not silently fall back."""
    async def fake_post(self, url, json=None, **kwargs):
        req = httpx.Request("POST", url)
        return httpx.Response(503, text="Service Unavailable", request=req)

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    c = RemoteContentClassifier(base_url="http://test-lb", timeout_seconds=10)
    with pytest.raises(RemoteClassifierError):
        await c.classify(
            sender="x@y", recipient="a@b", subject="s", body="b",
            attachments=None, headers=None,
        )
    await c.aclose()


# ── No fallback configured: timeout propagates as RemoteClassifierTimeout ────


@pytest.mark.asyncio
async def test_remote_classifier_timeout_no_fallback(monkeypatch):
    async def timeout_post(self, url, json=None, **kwargs):
        raise httpx.ConnectTimeout("simulated timeout")

    monkeypatch.setattr(httpx.AsyncClient, "post", timeout_post)

    c = RemoteContentClassifier(
        base_url="http://test-lb",
        timeout_seconds=1.0,
        fallback_enabled=False,
    )
    with pytest.raises(RemoteClassifierTimeout):
        await c.classify(
            sender="x@y", recipient="a@b", subject="s", body="b",
            attachments=None, headers=None,
        )
    await c.aclose()


# ── env-var defaults ──────────────────────────────────────────────────────────


def test_default_url_constant():
    """Default URL should point at the prod ELB unless overridden by env var."""
    assert DEFAULT_CLASSIFIER_URL.startswith("http://classify-lb-")
    assert "elb.amazonaws.com" in DEFAULT_CLASSIFIER_URL


def test_use_remote_classifier_default_true(monkeypatch):
    """USE_REMOTE_CLASSIFIER defaults to true so the new path is on by default."""
    monkeypatch.delenv("USE_REMOTE_CLASSIFIER", raising=False)
    # Re-evaluate the email_processor module variable
    import importlib
    import backend.services.email_processor as ep
    importlib.reload(ep)
    assert ep._USE_REMOTE is True
