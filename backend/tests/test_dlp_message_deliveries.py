from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from fastapi import HTTPException

import backend.dlp.api.messages as messages_module
from backend.dlp.api.message_views import (
    DELIVERY_MAX_TEXT_CHARS,
    sanitize_delivery_attempts,
)
from backend.dlp.api.messages import _tenant_message, get_message


def _event_row(payload: dict, occurred_at: datetime) -> SimpleNamespace:
    return SimpleNamespace(payload=payload, occurred_at=occurred_at)


def test_sanitize_delivery_attempts_bounds_and_strips_fields() -> None:
    now = datetime.now(timezone.utc)
    event = _event_row(
        {
            "outcome": "deferred",
            "resulting_state": "deferred",
            "attempt_number": 1,
            "smtp_stage": "rcpt_to",
            "smtp_code": 450,
            "smtp_message": "mailbox busy",
            "detail": "x" * (DELIVERY_MAX_TEXT_CHARS + 500),
            "remote_host": "mx.example.test",
            "accepted_recipients": [],
            "refused_recipients": ["rcpt@example.test"],
            "certificate_thumbprint": "ABCD1234",
            "trigger_command_id": str(uuid4()),
            "attempt_started_at": now.isoformat(),
            "attempt_finished_at": now.isoformat(),
        },
        now,
    )

    attempts = sanitize_delivery_attempts([event])

    assert len(attempts) == 1
    attempt = attempts[0]
    assert set(attempt) == {
        "outcome",
        "resulting_state",
        "attempt_number",
        "smtp_stage",
        "smtp_code",
        "smtp_message",
        "detail",
        "remote_host",
        "accepted_recipients",
        "refused_recipients",
        "attempt_started_at",
        "attempt_finished_at",
        "occurred_at",
    }
    assert attempt["outcome"] == "deferred"
    assert attempt["smtp_code"] == 450
    assert len(attempt["detail"]) == DELIVERY_MAX_TEXT_CHARS
    assert attempt["refused_recipients"] == ["rcpt@example.test"]
    assert attempt["attempt_started_at"] == now
    assert "thumbprint" not in json.dumps(attempt, default=str)


def test_sanitize_delivery_attempts_tolerates_malformed_payload() -> None:
    now = datetime.now(timezone.utc)
    events = [
        _event_row(None, now),
        _event_row(
            {
                "attempt_number": "not-a-number",
                "smtp_code": "not-a-code",
                "accepted_recipients": "not-a-list",
                "attempt_started_at": "not-a-date",
            },
            now,
        ),
    ]

    attempts = sanitize_delivery_attempts(events)

    assert [item["outcome"] for item in attempts] == [
        "uncertain",
        "uncertain",
    ]
    assert attempts[1]["attempt_number"] == 0
    assert attempts[1]["smtp_code"] is None
    assert attempts[1]["accepted_recipients"] == []
    assert attempts[1]["attempt_started_at"] is None


class _Result:
    def __init__(self, rows=(), one=None) -> None:
        self._rows = list(rows)
        self._one = one

    def scalars(self) -> "_Result":
        return self

    def all(self) -> list:
        return self._rows

    def one_or_none(self):
        return self._one


class _FakeSession:
    """Returns queued results for each session.execute call."""

    def __init__(self, results: list[_Result]) -> None:
        self._results = list(results)

    async def execute(self, _statement) -> _Result:
        return self._results.pop(0)


def _message(org_id, message_id) -> SimpleNamespace:
    return SimpleNamespace(
        id=message_id,
        org_id=org_id,
        envelope_from="sender@example.test",
        envelope_to=["rcpt@example.test"],
        state="provider_accepted",
        received_at=datetime.now(timezone.utc),
    )


def _patch_detail_dependencies(monkeypatch, message) -> None:
    monkeypatch.setattr(
        messages_module,
        "_tenant_message",
        AsyncMock(return_value=(message, None)),
    )
    monkeypatch.setattr(
        messages_module,
        "_latest_classification",
        AsyncMock(return_value=None),
    )
    monkeypatch.setattr(
        messages_module,
        "_safe_preview",
        AsyncMock(return_value=(None, None, False)),
    )
    monkeypatch.setattr(
        messages_module.CommandOutboxRepository,
        "list_for_message",
        AsyncMock(return_value=[]),
    )


@pytest.mark.asyncio
async def test_message_detail_returns_deliveries_in_order(
    monkeypatch,
) -> None:
    org_id = uuid4()
    message_id = uuid4()
    message = _message(org_id, message_id)
    now = datetime.now(timezone.utc)
    events = [
        _event_row(
            {
                "outcome": "deferred",
                "resulting_state": "deferred",
                "attempt_number": 1,
                "smtp_stage": "rcpt_to",
                "smtp_code": 450,
                "refused_recipients": ["rcpt@example.test"],
            },
            now,
        ),
        _event_row(
            {
                "outcome": "accepted",
                "resulting_state": "provider_accepted",
                "attempt_number": 2,
                "smtp_code": 250,
                "accepted_recipients": ["rcpt@example.test"],
            },
            now,
        ),
    ]
    session = _FakeSession(
        [
            _Result(),  # parts
            _Result(),  # review history
            _Result(events),  # delivery events
            _Result(),  # command ack events
        ]
    )
    _patch_detail_dependencies(monkeypatch, message)

    detail = await get_message(
        message_id=message_id,
        current_user=SimpleNamespace(org_id=org_id),
        session=session,
    )

    assert [item.attempt_number for item in detail.deliveries] == [1, 2]
    first, second = detail.deliveries
    assert first.outcome == "deferred"
    assert first.smtp_stage == "rcpt_to"
    assert first.refused_recipients == ["rcpt@example.test"]
    assert second.outcome == "accepted"
    assert second.resulting_state == "provider_accepted"
    assert second.accepted_recipients == ["rcpt@example.test"]
    assert detail.model_dump()["deliveries"][0]["occurred_at"]


@pytest.mark.asyncio
async def test_message_detail_with_no_deliveries_returns_empty_list(
    monkeypatch,
) -> None:
    org_id = uuid4()
    message_id = uuid4()
    message = _message(org_id, message_id)
    session = _FakeSession([_Result(), _Result(), _Result(), _Result()])
    _patch_detail_dependencies(monkeypatch, message)

    detail = await get_message(
        message_id=message_id,
        current_user=SimpleNamespace(org_id=org_id),
        session=session,
    )

    assert detail.deliveries == []


@pytest.mark.asyncio
async def test_tenant_message_raises_404_for_other_org() -> None:
    session = _FakeSession([_Result(one=None)])

    with pytest.raises(HTTPException) as exc:
        await _tenant_message(session, uuid4(), uuid4())

    assert exc.value.status_code == 404
