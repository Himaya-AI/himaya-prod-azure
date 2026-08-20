from __future__ import annotations

from enum import Enum

from app.domain.models import (
    CommandAckEvent,
    CommandAckStatus,
    CommandType,
    GatewayCommand,
    MessageState,
    command_ack_event_id,
)
from app.logging_setup import get_logger
from app.relay.dispatcher import RelayDispatcher
from app.spool.mta_spool import FilesystemSpoolStore

log = get_logger(__name__)


class CommandProcessingStatus(str, Enum):
    APPLIED = "applied"
    DUPLICATE = "duplicate"
    NOOP = "noop"


class CommandRejectedError(ValueError):
    """Permanent command rejection; caller should dead-letter it."""


class UnknownMessageError(LookupError):
    """Message is not available yet; caller may retry later."""


class CommandNotReadyError(UnknownMessageError):
    """Message exists but has not reached the expected state yet."""


class CommandProcessor:
    def __init__(
        self,
        spool: FilesystemSpoolStore,
        relay: RelayDispatcher,
        *,
        max_relay_attempts: int = 4,
    ) -> None:
        self.spool = spool
        self.relay = relay
        self.max_relay_attempts = max_relay_attempts

    def process(self, command: GatewayCommand) -> CommandProcessingStatus:
        mid = str(command.message_id)
        record = self.spool.get(mid)
        if record is None:
            raise UnknownMessageError(mid)

        if command.command_id in record.processed_command_ids:
            log.info(
                "command.duplicate",
                command_id=str(command.command_id),
                message_id=mid,
            )
            return self._complete(command, CommandProcessingStatus.DUPLICATE)

        if command.org_id != record.org_id:
            raise CommandRejectedError("Command tenant does not own message")

        if (
            command.expected_state is not None
            and record.state != command.expected_state
        ):
            if (
                record.state == MessageState.ACCEPTED_IN_SPOOL
                and command.expected_state == MessageState.CAPTURED
            ):
                raise CommandNotReadyError(
                    "Capture event is committed but spool transition "
                    "is still in progress"
                )
            raise CommandRejectedError(
                f"Expected {command.expected_state.value}, "
                f"found {record.state.value}"
            )

        if record.state == MessageState.PROVIDER_ACCEPTED:
            raise CommandRejectedError("Message was already provider-accepted")

        if record.state == MessageState.STOPPED:
            if command.command_type == CommandType.STOP:
                self.spool.record_command_processed(
                    mid, str(command.command_id)
                )
                return self._complete(command, CommandProcessingStatus.NOOP)
            raise CommandRejectedError("Stopped message is terminal")

        relay_states = {
            CommandType.ALLOW: {MessageState.CAPTURED},
            CommandType.RELEASE: {
                MessageState.CAPTURED,
                MessageState.HELD,
            },
            CommandType.RETRY: {
                MessageState.DEFERRED,
                MessageState.FAILED,
            },
        }
        if command.command_type in relay_states:
            if record.state not in relay_states[command.command_type]:
                raise CommandRejectedError(
                    f"{command.command_type.value} is invalid from "
                    f"{record.state.value}"
                )
            if command.command_type == CommandType.RETRY:
                if record.relay_attempt_count >= self.max_relay_attempts:
                    raise CommandRejectedError(
                        "Maximum provider relay attempts reached"
                    )
                if (
                    record.state == MessageState.FAILED
                    and command.metadata.get("manual_override") is not True
                ):
                    raise CommandRejectedError(
                        "Failed delivery requires manual_override retry"
                    )
            self.relay.relay_message(mid, str(command.command_id))
            return self._complete(command, CommandProcessingStatus.APPLIED)

        if command.command_type == CommandType.STOP:
            self.spool.update_state(
                mid,
                MessageState.STOPPED.value,
                stop_reason=command.reason,
            )
            self.spool.record_command_processed(mid, str(command.command_id))
            log.info("command.stopped", message_id=mid)
            return self._complete(command, CommandProcessingStatus.APPLIED)

        raise CommandRejectedError(
            f"Unsupported command: {command.command_type.value}"
        )

    def _complete(
        self,
        command: GatewayCommand,
        status: CommandProcessingStatus,
    ) -> CommandProcessingStatus:
        self._enqueue_command_ack(command, status)
        return status

    def _enqueue_command_ack(
        self,
        command: GatewayCommand,
        status: CommandProcessingStatus,
    ) -> None:
        record = self.spool.get(str(command.message_id))
        if record is None:
            return
        event = CommandAckEvent(
            event_id=command_ack_event_id(command.command_id),
            command_id=command.command_id,
            message_id=command.message_id,
            org_id=command.org_id,
            command_type=command.command_type,
            status=CommandAckStatus(status.value),
            resulting_state=record.state,
            reason=command.reason,
        )
        self.spool.record_command_ack(event)
