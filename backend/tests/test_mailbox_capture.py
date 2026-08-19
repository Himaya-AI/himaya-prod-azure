"""
Unit tests for the mailbox capture service (pull-out-of-mailbox quarantine).

No network/DB: httpx.AsyncClient is replaced with a fake, and the DB-backed
store/delete helpers are monkeypatched. Verifies:
  - encrypt/decrypt roundtrip (with and without ENCRYPTION_KEY)
  - capture_gmail: success, store-failure, and delete-failure rollback paths
  - the safety rule: never delete unless the copy stored first
"""
from __future__ import annotations

import asyncio
import base64
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import backend.services.mailbox_capture_service as mcs  # noqa: E402


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Fake httpx ────────────────────────────────────────────────────────────────
class _Resp:
    def __init__(self, status_code=200, json_data=None, content=b"", text=""):
        self.status_code = status_code
        self._json = json_data or {}
        self.content = content
        self.text = text

    def json(self):
        return self._json


class _Client:
    def __init__(self, handler):
        self._handler = handler

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **k):
        return self._handler("GET", url, k)

    async def post(self, url, **k):
        return self._handler("POST", url, k)

    async def delete(self, url, **k):
        return self._handler("DELETE", url, k)


def _install_client(monkeypatch, handler):
    monkeypatch.setattr(mcs.httpx, "AsyncClient", lambda *a, **k: _Client(handler))


# ── Encryption roundtrip ──────────────────────────────────────────────────────
def test_encrypt_roundtrip_with_key(monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("ENCRYPTION_KEY", Fernet.generate_key().decode())
    raw = b"From: a@b.com\r\nSubject: hi\r\n\r\nbody" * 100
    enc = mcs._encrypt_blob(raw)
    assert isinstance(enc, str) and enc != base64.b64encode(raw).decode()
    assert mcs._decrypt_blob(enc) == raw


def test_encrypt_roundtrip_without_key(monkeypatch):
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    raw = b"plain mime bytes"
    assert mcs._decrypt_blob(mcs._encrypt_blob(raw)) == raw


def test_hard_capture_toggle(monkeypatch):
    monkeypatch.setenv("QUARANTINE_HARD_CAPTURE", "false")
    assert mcs.hard_capture_enabled() is False
    monkeypatch.setenv("QUARANTINE_HARD_CAPTURE", "true")
    assert mcs.hard_capture_enabled() is True


# ── capture_gmail orchestration ───────────────────────────────────────────────
def _gmail_raw_json():
    return {
        "raw": base64.urlsafe_b64encode(b"RAW-MIME").decode(),
        "payload": {"headers": [{"name": "Message-Id", "value": "<abc@x>"}]},
    }


def test_capture_gmail_requires_org():
    assert _run(mcs.capture_gmail(user_email="u@x.com", msg_id="m1", headers={}, org_id=None)) is False


def test_capture_gmail_success(monkeypatch):
    calls = {"deleted": False, "rolled_back": False}

    def handler(method, url, k):
        if method == "GET":
            return _Resp(200, _gmail_raw_json())
        if method == "DELETE":
            calls["deleted"] = True
            return _Resp(204)
        return _Resp(400)

    _install_client(monkeypatch, handler)

    async def _store(**kw):
        assert kw["raw"] == b"RAW-MIME"
        assert kw["internet_message_id"] == "<abc@x>"
        return "cap-1"

    async def _del(cid):
        calls["rolled_back"] = True

    monkeypatch.setattr(mcs, "store_capture", _store)
    monkeypatch.setattr(mcs, "delete_capture", _del)

    ok = _run(mcs.capture_gmail(user_email="u@x.com", msg_id="m1", headers={"Authorization": "Bearer t"}, org_id="org-1"))
    assert ok is True
    assert calls["deleted"] is True
    assert calls["rolled_back"] is False


def test_capture_gmail_store_failure_no_delete(monkeypatch):
    calls = {"deleted": False}

    def handler(method, url, k):
        if method == "GET":
            return _Resp(200, _gmail_raw_json())
        if method == "DELETE":
            calls["deleted"] = True
            return _Resp(204)
        return _Resp(400)

    _install_client(monkeypatch, handler)

    async def _store(**kw):
        return None  # storage failed

    monkeypatch.setattr(mcs, "store_capture", _store)

    ok = _run(mcs.capture_gmail(user_email="u@x.com", msg_id="m1", headers={}, org_id="org-1"))
    assert ok is False
    # Safety rule: must NOT have attempted deletion when the copy wasn't stored.
    assert calls["deleted"] is False


def test_capture_gmail_delete_failure_rolls_back(monkeypatch):
    calls = {"rolled_back_id": None}

    def handler(method, url, k):
        if method == "GET":
            return _Resp(200, _gmail_raw_json())
        if method == "DELETE":
            return _Resp(403, text="insufficient scope")
        return _Resp(400)

    _install_client(monkeypatch, handler)

    async def _store(**kw):
        return "cap-99"

    async def _del(cid):
        calls["rolled_back_id"] = cid

    monkeypatch.setattr(mcs, "store_capture", _store)
    monkeypatch.setattr(mcs, "delete_capture", _del)

    ok = _run(mcs.capture_gmail(user_email="u@x.com", msg_id="m1", headers={}, org_id="org-1"))
    assert ok is False
    # The stored copy must be rolled back so the caller can fall back cleanly.
    assert calls["rolled_back_id"] == "cap-99"


def test_capture_gmail_fetch_failure(monkeypatch):
    def handler(method, url, k):
        return _Resp(404, text="not found")

    _install_client(monkeypatch, handler)
    ok = _run(mcs.capture_gmail(user_email="u@x.com", msg_id="m1", headers={}, org_id="org-1"))
    assert ok is False


# ── reinject_gmail ────────────────────────────────────────────────────────────
def test_reinject_gmail_success(monkeypatch):
    async def _headers(_email):
        return {"Authorization": "Bearer t"}

    monkeypatch.setattr(mcs, "httpx", mcs.httpx)  # keep ref
    # Patch the SA-header lookup imported inside reinject_gmail.
    import backend.services.quarantine_service as qs
    monkeypatch.setattr(qs, "_get_sa_headers_async", _headers)

    def handler(method, url, k):
        if method == "POST" and url.endswith("/messages/insert"):
            return _Resp(200, {"id": "new-123"})
        return _Resp(400)

    _install_client(monkeypatch, handler)
    new_id = _run(mcs.reinject_gmail("u@x.com", b"RAW-MIME"))
    assert new_id == "new-123"
