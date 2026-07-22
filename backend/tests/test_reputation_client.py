import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from backend.services import reputation_client as rc


def test_build_entities_sender_url_ip_file():
    email_data = {
        "sender": "user@evil.com",
        "body": "Click https://evil.com/a and https://evil.com/b",
        "attachments": [
            {"filename": "invoice.xlsm", "sha256": "a" * 64},
        ],
    }
    auth = {"spf": "fail", "dkim": "none", "dmarc": "fail", "sender_ip": "203.0.113.5"}

    entities = rc.build_entities(email_data, auth)

    types = [e["type"] for e in entities]
    assert types[0] == "sender"
    assert "ip" in types
    assert "url" in types
    assert "file" in types
    assert entities[0]["context"]["auth_results"]["spf"] == "fail"


def test_build_entities_respects_batch_limit():
    urls = [f"https://example{i}.com" for i in range(30)]
    body = " ".join(urls)
    email_data = {"sender": "a@b.com", "body": body}
    entities = rc.build_entities(email_data, {"spf": "pass", "dkim": "pass", "dmarc": "pass"})
    assert len(entities) <= rc.MAX_ENTITIES_PER_REQUEST


def test_map_sender_result_from_service():
    results = [
        {
            "type": "sender",
            "score": 40,
            "indicators": ["spf_fail", "dmarc_fail"],
            "email-verify": {"domain": "evil.com", "has_mx_records": True},
        }
    ]
    auth = {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    mapped = rc.map_sender_result(results, auth)
    assert mapped["reputation_score"] == 40
    assert "spf_fail" in mapped["indicators"]
    assert mapped["spf_pass"] is False
    assert mapped["email_verify"]["domain"] == "evil.com"


def test_map_sender_result_fallback_auth_only():
    auth = {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    mapped = rc.map_sender_result([], auth)
    assert mapped["reputation_score"] == 40
    assert mapped["spf_pass"] is False
    assert mapped["email_verify"] is None


def test_map_link_result_malicious_url_and_ioc():
    results = [
        {
            "type": "url",
            "value": "https://evil.com",
            "verdict": "malicious",
            "indicators": ["ioc_feed_url_match:ioc_urlhaus"],
        },
        {
            "type": "ip",
            "value": "203.0.113.5",
            "verdict": "malicious",
            "indicators": ["ioc_feed_ip_match:ioc_feodo"],
        },
    ]
    mapped = rc.map_link_result(results, urls=["https://evil.com"], att_filenames=[], file_entities=[])
    assert mapped["link_score"] == 100  # 60 + 20 + 30, capped
    assert mapped["malicious_urls"] == ["https://evil.com"]


def test_map_link_result_local_extension_fallback():
    mapped = rc.map_link_result(
        [],
        urls=[],
        att_filenames=["invoice.xlsm"],
        file_entities=[],
    )
    assert mapped["link_score"] == 20
    assert "invoice.xlsm" in mapped["suspicious_attachments"]


def test_lookup_reputation_skips_when_unconfigured(monkeypatch):
    monkeypatch.setattr(rc, "REPUTATION_SERVICE_URL", "")
    out = asyncio.run(rc.lookup_reputation([{"type": "url", "value": "https://x.com"}]))
    assert out == []


def test_lookup_reputation_posts_batch(monkeypatch):
    monkeypatch.setattr(rc, "REPUTATION_SERVICE_URL", "http://reputation:8080")

    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {"results": [{"type": "sender", "score": 10}]}

    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post = AsyncMock(return_value=response)

    with patch("backend.services.reputation_client.httpx.AsyncClient", return_value=client):
        results = asyncio.run(
            rc.lookup_reputation([{"type": "sender", "value": "a@b.com"}])
        )

    assert results[0]["score"] == 10
    client.post.assert_called_once()
    call_url = client.post.call_args[0][0]
    assert call_url.endswith("/api/v1/reputation/lookup")


def test_analyze_email_reputation_integration(monkeypatch):
    monkeypatch.setattr(rc, "REPUTATION_SERVICE_URL", "http://reputation:8080")

    async def fake_lookup(entities):
        return [
            {"type": "sender", "score": 25, "indicators": ["spf_fail"], "verdict": "suspicious"},
            {"type": "url", "value": "https://evil.com", "verdict": "suspicious", "indicators": []},
        ]

    monkeypatch.setattr(rc, "lookup_reputation", fake_lookup)

    email_data = {
        "sender": "a@evil.com",
        "body": "see https://evil.com",
        "attachments": [],
    }
    auth = {"spf": "fail", "dkim": "pass", "dmarc": "pass"}

    link_result, reputation_result = asyncio.run(
        rc.analyze_email_reputation(email_data, auth)
    )

    assert reputation_result["reputation_score"] == 25
    assert link_result["link_score"] == 10
    assert link_result["suspicious_urls"] == ["https://evil.com"]
