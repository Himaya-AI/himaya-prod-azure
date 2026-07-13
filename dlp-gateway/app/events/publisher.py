from __future__ import annotations

from app.domain.models import CaptureEvent, GatewayCommand
from app.events.bus import FilesystemEventBus


class EventPublisher:
    def __init__(self, bus: FilesystemEventBus) -> None:
        self.bus = bus

    def publish_capture(self, event: CaptureEvent) -> None:
        self.bus.publish_capture(event)

    def publish_command(self, command: GatewayCommand) -> None:
        self.bus.publish_command(command)
