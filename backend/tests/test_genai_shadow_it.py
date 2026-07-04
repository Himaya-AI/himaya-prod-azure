"""Unit tests for backend.services.genai_shadow_it pure helpers."""
from __future__ import annotations

from backend.services.genai_shadow_it import (
    KNOWN_VENDORS,
    vendor_for_app_name,
    vendor_for_host,
)


def test_chatgpt_host_matches_openai_vendor():
    v = vendor_for_host("chat.openai.com")
    assert v and v["id"] == "openai-chatgpt"


def test_claude_host_matches_anthropic_vendor():
    v = vendor_for_host("claude.ai")
    assert v and v["id"] == "anthropic-claude"


def test_gemini_host_matches_google():
    v = vendor_for_host("gemini.google.com")
    assert v and v["id"] == "google-gemini"


def test_perplexity_host_matches():
    assert vendor_for_host("www.perplexity.ai")["id"] == "perplexity"


def test_unknown_host_returns_none():
    assert vendor_for_host("example.com") is None
    assert vendor_for_host("") is None
    assert vendor_for_host(None) is None


def test_chatgpt_app_name_matches():
    v = vendor_for_app_name("ChatGPT for Microsoft Teams")
    assert v and v["id"] == "openai-chatgpt"


def test_gpt_word_boundary_does_not_match_gptzero():
    # gptzero != ChatGPT; we don't want to flag plagiarism detectors.
    v = vendor_for_app_name("gptzero")
    # gptzero may or may not match "gpt-4" / "gpt-5" — those need a number
    # after gpt. With re word boundaries 'gptzero' is one token so it won't
    # match 'gpt-4'. But it WILL match 'chatgpt' if that keyword is there.
    # KNOWN_VENDORS has 'chatgpt' but no 'gpt' standalone. So None.
    assert v is None


def test_copilot_app_name_matches():
    v = vendor_for_app_name("Microsoft 365 Copilot")
    assert v and v["id"] == "microsoft-copilot"


def test_cursor_keyword_matches():
    v = vendor_for_app_name("cursor ai editor")
    assert v and v["id"] == "cursor"


def test_codeium_and_windsurf_both_match():
    assert vendor_for_app_name("codeium")["id"] == "codeium"
    assert vendor_for_app_name("windsurf")["id"] == "codeium"


def test_every_vendor_has_required_fields():
    for v in KNOWN_VENDORS:
        for k in ("id", "name", "category", "hosts", "app_keywords", "risk"):
            assert k in v, f"vendor {v.get('id')} missing {k}"
        assert v["risk"] in ("low", "medium", "high")
        assert v["category"] in (
            "chat", "coding", "image", "voice", "agent", "productivity", "analytics"
        )
        assert isinstance(v["hosts"], list) and len(v["hosts"]) > 0
        assert isinstance(v["app_keywords"], list) and len(v["app_keywords"]) > 0


def test_vendor_ids_are_unique():
    ids = [v["id"] for v in KNOWN_VENDORS]
    assert len(ids) == len(set(ids)), "duplicate vendor ids"
