"""
Tests for Content Classifier (MODEL-002)
Tests prompt construction, JSON parsing, timeout fallback, and Arabic BEC examples.

Note: Requires anthropic and openai packages. Tests skip if not installed.
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

# Check if required dependencies are available
try:
    import anthropic
    import openai
    HAS_LLM_DEPS = True
except ImportError:
    HAS_LLM_DEPS = False

skip_without_llm = pytest.mark.skipif(
    not HAS_LLM_DEPS,
    reason="anthropic/openai packages not installed"
)


# ---------------------------------------------------------------------------
# Prompt Construction Tests
# ---------------------------------------------------------------------------

class TestPromptConstruction:
    """Test that prompts are correctly built for classification."""

    @skip_without_llm
    def test_prompt_non_empty(self):
        """build_classification_prompt should return a non-empty string."""
        from models.content_classifier.prompts import build_classification_prompt

        prompt = build_classification_prompt(
            sender="ceo@evil.com",
            recipient="finance@company.com",
            subject="Urgent wire transfer",
            body="Please transfer funds urgently. CEO",
        )
        assert isinstance(prompt, str)
        assert len(prompt) > 50

    @skip_without_llm
    def test_prompt_contains_sender(self):
        from models.content_classifier.prompts import build_classification_prompt

        prompt = build_classification_prompt(
            sender="attacker@phish.xyz",
            recipient="victim@org.com",
            subject="Action required",
            body="Wire transfer required.",
        )
        assert "phish.xyz" in prompt or "attacker@phish.xyz" in prompt

    @skip_without_llm
    def test_prompt_contains_classification_labels(self):
        """Prompt should mention the expected classification options."""
        from models.content_classifier.prompts import build_classification_prompt

        prompt = build_classification_prompt(
            sender="a@b.com",
            recipient="c@d.com",
            subject="Test",
            body="Click here now!",
        )
        # At least one classification type should be present in the prompt
        assert any(
            label in prompt
            for label in ["BEC", "PHISHING", "MALWARE", "BENIGN", "UNCERTAIN"]
        )

    def test_arabic_bec_example_in_prompts_source(self):
        """The prompts module source should contain Arabic BEC content."""
        # Read the prompts.py file directly to check for Arabic content
        prompts_path = os.path.join(
            os.path.dirname(__file__), "..", "models", "content_classifier", "prompts.py"
        )
        if os.path.exists(prompts_path):
            with open(prompts_path, "r", encoding="utf-8") as f:
                source = f.read()
            
            assert "BEC" in source, "No BEC label found in prompts"
            assert any(
                term in source
                for term in ["Arabic", "arabic", "Gulf", "تحويل", "عاجل"]
            ), "No Arabic or Gulf BEC content found in prompts"
        else:
            pytest.skip("prompts.py not found")


# ---------------------------------------------------------------------------
# JSON Output Parsing Tests
# ---------------------------------------------------------------------------

class TestJsonOutputParsing:
    """Test parsing of LLM JSON responses into structured objects."""

    def _get_valid_mock_response(self) -> str:
        return '''```json
{
  "threat_indicators": ["urgency", "wire_transfer", "ceo_impersonation"],
  "urgency_score": 92,
  "impersonation_detected": true,
  "impersonation_target": "CEO",
  "language": "en",
  "classification": "BEC",
  "confidence": 0.95,
  "explanation_ar": "هذا هجوم اختراق بريد إلكتروني تجاري",
  "explanation_en": "This is a BEC attack impersonating the CEO",
  "signals": []
}
```'''

    @skip_without_llm
    def test_parse_valid_json_response(self):
        """Should correctly parse a valid JSON response from the LLM."""
        from models.content_classifier.classifier import _parse_llm_response

        result = _parse_llm_response(self._get_valid_mock_response(), "claude-3-5-sonnet")

        assert result is not None
        assert result.classification.value == "BEC"
        assert result.urgency_score == 92
        assert result.impersonation_detected is True
        assert result.confidence == 0.95

    @skip_without_llm
    def test_parse_json_without_code_fence(self):
        """Should handle JSON without markdown code fences."""
        from models.content_classifier.classifier import _parse_llm_response

        raw_json = '''{
  "threat_indicators": ["phishing_link"],
  "urgency_score": 75,
  "impersonation_detected": false,
  "impersonation_target": null,
  "language": "en",
  "classification": "PHISHING",
  "confidence": 0.80,
  "explanation_ar": "رابط تصيد احتيالي",
  "explanation_en": "Contains phishing link",
  "signals": []
}'''
        result = _parse_llm_response(raw_json, "gpt-4o")
        assert result is not None
        assert result.classification.value == "PHISHING"

    @skip_without_llm
    def test_parse_invalid_json_raises_value_error(self):
        """Invalid JSON should raise ValueError."""
        from models.content_classifier.classifier import _parse_llm_response

        with pytest.raises((ValueError, Exception)):
            _parse_llm_response("This is not valid JSON at all!!!", "claude")

    @skip_without_llm
    def test_parsed_result_has_required_fields(self):
        from models.content_classifier.classifier import _parse_llm_response

        result = _parse_llm_response(self._get_valid_mock_response(), "claude-test")
        assert result is not None
        assert hasattr(result, "threat_indicators")
        assert hasattr(result, "urgency_score")
        assert hasattr(result, "language")
        assert hasattr(result, "explanation_ar")
        assert hasattr(result, "explanation_en")


# ---------------------------------------------------------------------------
# Timeout Fallback Tests (require LLM deps)
# ---------------------------------------------------------------------------

@skip_without_llm
class TestTimeoutFallback:
    """Test that the classifier gracefully handles LLM timeouts."""

    @pytest.mark.asyncio
    async def test_timeout_returns_uncertain(self):
        """On Claude timeout + OpenAI timeout, classifier should return UNCERTAIN."""
        import asyncio
        from unittest.mock import patch, AsyncMock
        from models.content_classifier.classifier import ContentClassifier
        from models.shared.schemas import ThreatClassification

        classifier = ContentClassifier()

        timeout_exc = asyncio.TimeoutError("Simulated timeout")

        with (
            patch.object(classifier, "_call_claude", new_callable=AsyncMock, side_effect=timeout_exc),
            patch.object(classifier, "_call_openai", new_callable=AsyncMock, side_effect=timeout_exc),
        ):
            result = await classifier.classify(
                sender="test@example.com",
                recipient="user@company.com",
                subject="Test email",
                body="Test email body",
            )

        assert result.classification == ThreatClassification.UNCERTAIN

    @pytest.mark.asyncio
    async def test_api_error_falls_back_to_uncertain(self):
        """On both API errors, should return UNCERTAIN classification, not raise."""
        import asyncio
        from unittest.mock import patch, AsyncMock
        from models.content_classifier.classifier import ContentClassifier
        from models.shared.schemas import ThreatClassification

        classifier = ContentClassifier()

        error = Exception("API key invalid")

        with (
            patch.object(classifier, "_call_claude", new_callable=AsyncMock, side_effect=error),
            patch.object(classifier, "_call_openai", new_callable=AsyncMock, side_effect=error),
        ):
            result = await classifier.classify(
                sender="test@example.com",
                recipient="user@company.com",
                subject="Test",
                body="Test body",
            )

        assert result.classification == ThreatClassification.UNCERTAIN
        assert result.confidence < 0.5
