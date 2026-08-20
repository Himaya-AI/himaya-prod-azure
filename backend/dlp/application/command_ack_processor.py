"""Persist command acknowledgements and map STOP to a terminal state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from backend.dlp.contracts import CommandAckEvent, CommandType
from backend.dlp.persistence.repositories import (
    MessageEventRepository,
    MessageRepository,
)


class CommandAckMessageNotReady(LookupError):
    """Capture persistence has not completed yet; abandon for redelivery."""


class CommandAckRejected(ValueError):
    """Permanent tenant mismatch."""


@dataclass(frozen=True)
class CommandAckProcessingResult:
    inserted: bool
    stopped: bool


class CommandAckProcessor:
    def __init__(self, session_factory: Any) -> None:
        self.session_factory = session_factory

    async def process(
        self, event: CommandAckEvent
    ) -> CommandAckProcessingResult:
        async with self.session_factory() as session:
            messages = MessageRepository(session)
            events = MessageEventRepository(session)

            message = await messages.get(event.message_id)
            if message is None:
                raise CommandAckMessageNotReady(str(event.message_id))
            try:
                event_org_id = UUID(event.org_id)
            except ValueError as exc:
                raise CommandAckRejected("Invalid event org_id") from exc
            if message.org_id != event_org_id:
                raise CommandAckRejected(
                    "Command ack tenant does not own message"
                )

            inserted = await events.record_command_ack(event)
            stopped = False
            if event.command_type == CommandType.STOP:
                await messages.set_state(message, "stopped")
                stopped = True

            await session.commit()
            return CommandAckProcessingResult(
                inserted=inserted,
                stopped=stopped,
            )
