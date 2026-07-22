"""Transactional-outbox publisher for gateway commands."""

from __future__ import annotations

import asyncio
import logging

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.dlp.contracts import GatewayCommand
from backend.dlp.messaging.ports import DlpMessageBus
from backend.dlp.persistence.repositories import (
    CommandOutboxRepository,
)

log = logging.getLogger(__name__)


class OutboxPublisher:
    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        bus: DlpMessageBus,
        batch_size: int = 20,
        max_attempts: int = 20,
        idle_seconds: float = 0.5,
    ) -> None:
        self._sessions = session_factory
        self.bus = bus
        self.batch_size = batch_size
        self.max_attempts = max_attempts
        self.idle_seconds = idle_seconds

    async def run_once(self) -> int:
        async with self._sessions() as session:
            async with session.begin():
                repository = CommandOutboxRepository(session)
                rows = await repository.claim_pending(
                    self.batch_size
                )
                for row in rows:
                    try:
                        command = GatewayCommand.model_validate(
                            row.payload
                        )
                        await self.bus.publish_command(command)
                        await repository.mark_published(row)
                    except asyncio.CancelledError:
                        raise
                    except ValidationError as exc:
                        await repository.mark_failed(
                            row,
                            f"Invalid outbox payload: {exc}",
                            terminal=True,
                        )
                        log.exception(
                            "dlp_outbox_payload_invalid",
                            extra={
                                "command_id": str(row.id),
                                "message_id": str(row.message_id),
                            },
                        )
                    except Exception as exc:
                        terminal = (
                            row.attempts + 1 >= self.max_attempts
                        )
                        await repository.mark_failed(
                            row,
                            str(exc),
                            retry_delay_seconds=min(
                                2 ** min(row.attempts, 8), 300
                            ),
                            terminal=terminal,
                        )
                        log.exception(
                            "dlp_outbox_publish_failed",
                            extra={
                                "command_id": str(row.id),
                                "message_id": str(row.message_id),
                                "terminal": terminal,
                            },
                        )
                return len(rows)

    async def run_forever(self) -> None:
        while True:
            count = await self.run_once()
            if count == 0:
                await asyncio.sleep(self.idle_seconds)
