from __future__ import annotations

from app.domain.models import CommandType, GatewayCommand, MessageState
from app.logging_setup import get_logger
from app.relay.dispatcher import RelayDispatcher
from app.spool.mta_spool import FilesystemSpoolStore

log = get_logger(__name__)


class CommandProcessor:
    def __init__(self, spool: FilesystemSpoolStore, relay: RelayDispatcher) -> None:
        self.spool = spool
        self.relay = relay

    def process(self, command: GatewayCommand) -> None:
        mid = str(command.message_id)
        record = self.spool.get(mid)
        if record is None:
            log.error("command.unknown_message", message_id=mid)
            return

        if command.command_type in (CommandType.ALLOW, CommandType.RELEASE, CommandType.RETRY):
            self.spool.update_state(mid, MessageState.ALLOW_PENDING.value)
            self.relay.relay_message(mid)
            return

        if command.command_type == CommandType.STOP:
            self.spool.update_state(
                mid,
                MessageState.STOPPED.value,
                stop_reason=command.reason,
            )
            log.info("command.stopped", message_id=mid)
            return

        log.warning("command.unsupported", command_type=command.command_type.value)
