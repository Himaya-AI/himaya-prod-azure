"""Persistence repositories used by DLP v2 application services."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from backend.dlp.contracts import CaptureEvent, GatewayCommand
from backend.dlp.persistence.models import (
    DlpClassificationResult,
    DlpCommandOutbox,
    DlpDecision,
    DlpMessage,
    DlpMessageEvent,
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MessageRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, message_id: UUID) -> DlpMessage | None:
        return await self._session.get(DlpMessage, message_id)

    async def create_from_capture(
        self, event: CaptureEvent
    ) -> tuple[DlpMessage, bool]:
        statement = (
            insert(DlpMessage)
            .values(
                id=event.message_id,
                deduplication_key=event.deduplication_key,
                org_id=UUID(event.org_id),
                provider=event.provider,
                provider_deployment_id=event.provider_deployment_id,
                envelope_from=event.envelope_from,
                envelope_to=event.envelope_to,
                blob_uri=event.blob_uri,
                mime_sha256=event.mime_sha256,
                mime_size=event.mime_size,
                state="received",
                received_at=event.received_at,
                gateway_occurred_at=event.occurred_at,
            )
            .on_conflict_do_nothing(index_elements=["deduplication_key"])
            .returning(DlpMessage.id)
        )
        inserted_id = (await self._session.execute(statement)).scalar_one_or_none()
        message = await self.get(event.message_id)
        if message is None:
            raise RuntimeError(
                "Capture deduplication key conflicts with a different message"
            )
        return message, inserted_id is not None

    async def set_state(self, message: DlpMessage, state: str) -> None:
        message.state = state
        message.updated_at = _utcnow()
        await self._session.flush()


class MessageEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_capture(self, event: CaptureEvent) -> bool:
        statement = (
            insert(DlpMessageEvent)
            .values(
                message_id=event.message_id,
                event_key=event.deduplication_key,
                event_type=event.event_type,
                payload=event.model_dump(mode="json"),
                occurred_at=event.occurred_at,
            )
            .on_conflict_do_nothing(index_elements=["event_key"])
            .returning(DlpMessageEvent.id)
        )
        return (
            await self._session.execute(statement)
        ).scalar_one_or_none() is not None


class ClassificationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_run(
        self, message_id: UUID, run_key: str
    ) -> DlpClassificationResult | None:
        result = await self._session.execute(
            select(DlpClassificationResult).where(
                DlpClassificationResult.message_id == message_id,
                DlpClassificationResult.run_key == run_key,
            )
        )
        return result.scalar_one_or_none()

    async def add(self, result: DlpClassificationResult) -> None:
        self._session.add(result)
        await self._session.flush()


class DecisionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(
        self, message_id: UUID, evaluation_version: int
    ) -> DlpDecision | None:
        result = await self._session.execute(
            select(DlpDecision).where(
                DlpDecision.message_id == message_id,
                DlpDecision.evaluation_version == evaluation_version,
            )
        )
        return result.scalar_one_or_none()

    async def add(self, decision: DlpDecision) -> None:
        self._session.add(decision)
        await self._session.flush()


class CommandOutboxRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def enqueue(self, command: GatewayCommand) -> DlpCommandOutbox:
        existing = await self._session.get(
            DlpCommandOutbox, command.command_id
        )
        if existing is not None:
            return existing
        row = DlpCommandOutbox(
            id=command.command_id,
            message_id=command.message_id,
            org_id=UUID(command.org_id),
            command_type=command.command_type.value,
            payload=command.model_dump(mode="json"),
            status="pending",
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def claim_pending(
        self, limit: int = 20
    ) -> list[DlpCommandOutbox]:
        result = await self._session.execute(
            select(DlpCommandOutbox)
            .where(
                DlpCommandOutbox.status == "pending",
                DlpCommandOutbox.available_at <= _utcnow(),
            )
            .order_by(DlpCommandOutbox.created_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return list(result.scalars())

    async def mark_published(self, row: DlpCommandOutbox) -> None:
        row.status = "published"
        row.published_at = _utcnow()
        row.updated_at = _utcnow()
        await self._session.flush()

    async def mark_failed(
        self, row: DlpCommandOutbox, error: str
    ) -> None:
        row.attempts += 1
        row.last_error = error[:4000]
        row.updated_at = _utcnow()
        await self._session.flush()
