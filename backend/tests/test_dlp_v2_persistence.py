from __future__ import annotations

from uuid import uuid4

import pytest

from backend.dlp.contracts import CommandType, GatewayCommand
from backend.dlp.persistence.models import (
    DlpClassificationResult,
    DlpCommandOutbox,
    DlpDecision,
    DlpMessage,
    DlpMessageEvent,
    DlpMessagePart,
)
from backend.dlp.persistence.repositories import CommandOutboxRepository


def test_v2_models_use_only_new_table_names() -> None:
    tables = {
        DlpMessage.__tablename__,
        DlpMessagePart.__tablename__,
        DlpClassificationResult.__tablename__,
        DlpDecision.__tablename__,
        DlpMessageEvent.__tablename__,
        DlpCommandOutbox.__tablename__,
    }

    assert tables == {
        "dlp_messages",
        "dlp_message_parts",
        "dlp_classification_results",
        "dlp_decisions",
        "dlp_message_events",
        "dlp_command_outbox",
    }
    assert tables.isdisjoint({"dlp_policies", "dlp_events", "dlp_queue"})


def test_capture_and_decision_constraints_are_versioned() -> None:
    message_uniques = {
        tuple(column.name for column in constraint.columns)
        for constraint in DlpMessage.__table__.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    decision_uniques = {
        tuple(column.name for column in constraint.columns)
        for constraint in DlpDecision.__table__.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }

    assert ("deduplication_key",) in message_uniques
    assert ("message_id", "evaluation_version") in decision_uniques


class _FakeSession:
    def __init__(self) -> None:
        self.existing = None
        self.added = []
        self.flush_count = 0

    async def get(self, model, identity):
        del model, identity
        return self.existing

    def add(self, value) -> None:
        self.added.append(value)

    async def flush(self) -> None:
        self.flush_count += 1


@pytest.mark.asyncio
async def test_outbox_reuses_gateway_command_id() -> None:
    session = _FakeSession()
    repository = CommandOutboxRepository(session)  # type: ignore[arg-type]
    command = GatewayCommand(
        command_type=CommandType.ALLOW,
        message_id=uuid4(),
        org_id=str(uuid4()),
    )

    row = await repository.enqueue(command)

    assert row.id == command.command_id
    assert row.payload["command_id"] == str(command.command_id)
    assert row.status == "pending"
    assert session.added == [row]
    assert session.flush_count == 1


@pytest.mark.asyncio
async def test_outbox_enqueue_is_idempotent() -> None:
    session = _FakeSession()
    existing = DlpCommandOutbox(
        id=uuid4(),
        message_id=uuid4(),
        org_id=uuid4(),
        command_type="stop",
        payload={},
        status="pending",
    )
    session.existing = existing
    repository = CommandOutboxRepository(session)  # type: ignore[arg-type]
    command = GatewayCommand(
        command_id=existing.id,
        command_type=CommandType.STOP,
        message_id=existing.message_id,
        org_id=str(existing.org_id),
    )

    row = await repository.enqueue(command)

    assert row is existing
    assert session.added == []
    assert session.flush_count == 0
