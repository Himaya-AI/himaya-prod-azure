"""Manual quarantine / mark-as-spam action wiring.

Covers the two failure modes that made manual actions look broken in prod:

1. A provider move rewrites the message id (and hard-capture deletes the
   original), so the id stored at ingestion goes stale and a re-action 404s.
   The action must re-resolve the live id via the immutable RFC822 message id
   and retry.
2. When the message has already been pulled out of the mailbox there is
   nothing left to move, so the API must report that end state instead of a
   misleading failure/502.
"""

import asyncio
import types

import pytest

from backend.services import quarantine_service as qs


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers: dict = {}
        self.text = ""

    def json(self):
        return self._payload


class _FakeClient:
    """Records calls and replays queued responses."""

    def __init__(self, request_responses, get_responses):
        self._request_responses = list(request_responses)
        self._get_responses = list(get_responses)
        self.request_urls: list[str] = []
        self.get_calls: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def request(self, method, url, **kwargs):
        self.request_urls.append(url)
        return self._request_responses.pop(0)

    async def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs.get("params") or {}))
        return self._get_responses.pop(0)


def _install_client(monkeypatch, client):
    monkeypatch.setattr(qs.httpx, "AsyncClient", lambda *a, **k: client)


# ── Gmail ────────────────────────────────────────────────────────────────────

def test_gmail_spam_reresolves_stale_id_and_retries(monkeypatch):
    """404 on the stored id -> re-resolve via rfc822msgid -> retry -> success."""
    client = _FakeClient(
        request_responses=[_FakeResponse(404), _FakeResponse(200)],
        get_responses=[_FakeResponse(200, {"messages": [{"id": "LIVE_ID"}]})],
    )
    _install_client(monkeypatch, client)

    async def _fake_headers(_user):
        return {"Authorization": "Bearer x"}

    monkeypatch.setattr(qs, "_get_sa_headers_async", _fake_headers)

    ok = asyncio.run(
        qs.mark_as_spam_gmail(
            "user@corp.com", "STALE_ID", internet_message_id="<abc@mail>",
        )
    )

    assert ok is True
    # Second attempt must target the re-resolved id, not the stale one.
    assert "STALE_ID" in client.request_urls[0]
    assert "LIVE_ID" in client.request_urls[1]
    # Angle brackets are stripped for Gmail's rfc822msgid search operator.
    assert client.get_calls[0][1]["q"] == "rfc822msgid:abc@mail"


def test_gmail_spam_without_rfc822_id_does_not_retry(monkeypatch):
    """No stored RFC822 id (pre-fix records) -> single attempt, honest failure."""
    client = _FakeClient(request_responses=[_FakeResponse(404)], get_responses=[])
    _install_client(monkeypatch, client)

    async def _fake_headers(_user):
        return {"Authorization": "Bearer x"}

    monkeypatch.setattr(qs, "_get_sa_headers_async", _fake_headers)

    ok = asyncio.run(qs.mark_as_spam_gmail("user@corp.com", "STALE_ID"))

    assert ok is False
    assert len(client.request_urls) == 1
    assert client.get_calls == []


def test_gmail_spam_missing_auth_is_reported_not_silent(monkeypatch, caplog):
    """The old silent `return False` surfaced as an unexplained 502."""
    async def _no_headers(_user):
        return None

    monkeypatch.setattr(qs, "_get_sa_headers_async", _no_headers)

    with caplog.at_level("WARNING"):
        ok = asyncio.run(qs.mark_as_spam_gmail("user@corp.com", "ID"))

    assert ok is False
    assert any("no auth" in r.message for r in caplog.records)


def test_gmail_quarantine_reresolves_stale_id(monkeypatch):
    client = _FakeClient(
        request_responses=[_FakeResponse(404), _FakeResponse(200)],
        get_responses=[_FakeResponse(200, {"messages": [{"id": "LIVE_ID"}]})],
    )
    _install_client(monkeypatch, client)

    async def _fake_headers(_user):
        return {"Authorization": "Bearer x"}

    monkeypatch.setattr(qs, "_get_sa_headers_async", _fake_headers)
    # Force the Trash fallback rather than the hard-capture path.
    monkeypatch.setitem(
        __import__("sys").modules,
        "backend.services.mailbox_capture_service",
        types.SimpleNamespace(
            hard_capture_enabled=lambda: False,
            capture_gmail=None,
        ),
    )

    ok = asyncio.run(
        qs.quarantine_gmail_message(
            "user@corp.com", "STALE_ID", internet_message_id="<abc@mail>",
        )
    )

    assert ok is True
    assert "LIVE_ID" in client.request_urls[1]


# ── M365 ─────────────────────────────────────────────────────────────────────

def test_m365_spam_reresolves_stale_id_and_retries(monkeypatch):
    """This is the exact prod failure: quarantined message -> stale id -> 404."""
    client = _FakeClient(
        request_responses=[_FakeResponse(404), _FakeResponse(200)],
        get_responses=[_FakeResponse(200, {"value": [{"id": "LIVE_M365_ID"}]})],
    )
    _install_client(monkeypatch, client)

    ok = asyncio.run(
        qs.mark_as_spam_m365(
            "user@corp.com", "STALE_ID",
            access_token="tok", internet_message_id="<abc@mail>",
        )
    )

    assert ok is True
    assert "STALE_ID" in client.request_urls[0]
    assert "LIVE_M365_ID" in client.request_urls[1]
    # Graph filters on the full RFC822 value, brackets included.
    assert client.get_calls[0][1]["$filter"] == "internetMessageId eq '<abc@mail>'"


def test_m365_resolver_escapes_single_quotes(monkeypatch):
    """A quote in the message id must not break the OData filter."""
    client = _FakeClient(
        request_responses=[],
        get_responses=[_FakeResponse(200, {"value": [{"id": "X"}]})],
    )
    asyncio.run(qs._resolve_m365_id(client, {}, "user@corp.com", "<o'brien@mail>"))
    assert client.get_calls[0][1]["$filter"] == "internetMessageId eq '<o''brien@mail>'"


# ── Router-level containment logic ───────────────────────────────────────────

@pytest.mark.parametrize(
    "action,status,expected",
    [
        ("QUARANTINED", "resolved", True),
        ("MARKED_SPAM", "resolved", True),
        ("BLOCK_DELETE", "resolved", True),
        (None, "quarantined", True),
        ("CLEAN", "open", False),
        (None, "open", False),
    ],
)
def test_already_contained(action, status, expected):
    from backend.routers.quarantine import _already_contained

    threat = types.SimpleNamespace(action_taken=action, status=status)
    assert _already_contained(threat) is expected
