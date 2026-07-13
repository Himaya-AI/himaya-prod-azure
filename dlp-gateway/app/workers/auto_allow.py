from __future__ import annotations

from app.domain.models import CommandType, GatewayCommand
from app.events.bus import FilesystemEventBus
from app.logging_setup import get_logger

log = get_logger(__name__)


class AutoAllowWorker:
    """Local-only stub: capture event → allow command.

    Replace with backend/dlp classification + policy workers in production.
    """

    def __init__(self, bus: FilesystemEventBus, enabled: bool = True) -> None:
        self.bus = bus
        self.enabled = enabled

    def run_once(self) -> int:
        if not self.enabled:
            return 0
        events = self.bus.consume_captures()
        for event in events:
            command = GatewayCommand(
                command_type=CommandType.ALLOW,
                message_id=event.message_id,
                org_id=event.org_id,
                reason="local FORCE_ALLOW auto-allow",
            )
            self.bus.publish_command(command)
            self.bus.ack_capture(event)
            log.info("auto_allow.issued", message_id=str(event.message_id))
        return len(events)
