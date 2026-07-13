from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

from app.domain.models import CaptureEvent, GatewayCommand
from app.logging_setup import get_logger

log = get_logger(__name__)


class FilesystemEventBus:
    """Simple durable local queue for Docker. Replace with Service Bus later."""

    def __init__(self, root: Path) -> None:
        self.root = root
        for name in (
            "captures/ready",
            "captures/processing",
            "captures/done",
            "commands/ready",
            "commands/processing",
            "commands/done",
        ):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def publish_capture(self, event: CaptureEvent) -> None:
        self._enqueue("captures", event.model_dump(mode="json"))

    def consume_captures(self, max_items: int = 10) -> list[CaptureEvent]:
        return [
            CaptureEvent.model_validate(item)
            for item in self._dequeue("captures", max_items)
        ]

    def ack_capture(self, event: CaptureEvent) -> None:
        self._ack("captures", str(event.message_id))

    def publish_command(self, command: GatewayCommand) -> None:
        self._enqueue("commands", command.model_dump(mode="json"))

    def consume_commands(self, max_items: int = 10) -> list[GatewayCommand]:
        return [
            GatewayCommand.model_validate(item)
            for item in self._dequeue("commands", max_items)
        ]

    def ack_command(self, command: GatewayCommand) -> None:
        self._ack("commands", str(command.command_id))

    def _enqueue(self, kind: str, payload: dict) -> None:
        name = f"{int(time.time() * 1000)}_{uuid.uuid4().hex}.json"
        tmp = self.root / kind / "ready" / f".{name}"
        final = self.root / kind / "ready" / name
        data = json.dumps(payload, indent=2, default=str).encode("utf-8")
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, final)
        log.info("bus.enqueued", kind=kind, file=name)

    def _dequeue(self, kind: str, max_items: int) -> list[dict]:
        ready = self.root / kind / "ready"
        processing = self.root / kind / "processing"
        items: list[dict] = []
        for path in sorted(ready.glob("*.json"))[:max_items]:
            dest = processing / path.name
            try:
                os.replace(path, dest)
            except FileNotFoundError:
                continue
            items.append(json.loads(dest.read_text(encoding="utf-8")))
        return items

    def _ack(self, kind: str, token: str) -> None:
        processing = self.root / kind / "processing"
        done = self.root / kind / "done"
        for path in processing.glob("*.json"):
            text = path.read_text(encoding="utf-8")
            if token in text:
                os.replace(path, done / path.name)
                return
