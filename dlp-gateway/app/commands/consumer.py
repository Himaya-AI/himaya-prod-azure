from __future__ import annotations

from app.commands.processor import CommandProcessor
from app.events.bus import FilesystemEventBus
from app.logging_setup import get_logger

log = get_logger(__name__)


class CommandConsumer:
    def __init__(self, bus: FilesystemEventBus, processor: CommandProcessor) -> None:
        self.bus = bus
        self.processor = processor

    def run_once(self) -> int:
        commands = self.bus.consume_commands()
        for command in commands:
            try:
                self.processor.process(command)
                self.bus.ack_command(command)
            except Exception:
                log.exception(
                    "command.failed",
                    command_id=str(command.command_id),
                    message_id=str(command.message_id),
                )
        return len(commands)
