from __future__ import annotations

from app.domain.models import (
    CaptureEvent,
    CommandAckEvent,
    DeliveryEvent,
    GatewayCommand,
)
from app.domain.ports import EventBus


class EventPublisher:
    def __init__(self, bus: EventBus) -> None:
        self.bus = bus

    def publish_capture(self, event: CaptureEvent) -> None:
        self.bus.publish_capture(event)

    def publish_command(self, command: GatewayCommand) -> None:
        self.bus.publish_command(command)

    def publish_delivery(self, event: DeliveryEvent) -> None:
        self.bus.publish_delivery(event)

    def publish_command_ack(self, event: CommandAckEvent) -> None:
        self.bus.publish_command_ack(event)
