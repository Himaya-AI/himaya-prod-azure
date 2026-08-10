from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path

from app.domain.models import CaptureEvent, DeliveryEvent, GatewayCommand
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
            "captures/dead",
            "commands/ready",
            "commands/processing",
            "commands/done",
            "commands/dead",
            "deliveries/ready",
            "deliveries/processing",
            "deliveries/done",
            "deliveries/dead",
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

    def publish_delivery(self, event: DeliveryEvent) -> None:
        self._enqueue("deliveries", event.model_dump(mode="json"))

    def consume_deliveries(
        self, max_items: int = 10
    ) -> list[DeliveryEvent]:
        return [
            DeliveryEvent.model_validate(item)
            for item in self._dequeue("deliveries", max_items)
        ]

    def ack_delivery(self, event: DeliveryEvent) -> None:
        self._ack("deliveries", str(event.event_id))

    def consume_commands(self, max_items: int = 10) -> list[GatewayCommand]:
        return [
            GatewayCommand.model_validate(item)
            for item in self._dequeue("commands", max_items)
        ]

    def ack_command(self, command: GatewayCommand) -> None:
        self._ack("commands", str(command.command_id))

    def retry_command(self, command: GatewayCommand) -> None:
        self._settle(
            "commands",
            str(command.command_id),
            destination="ready",
        )

    def dead_letter_command(
        self, command: GatewayCommand, reason: str
    ) -> None:
        self._settle(
            "commands",
            str(command.command_id),
            destination="dead",
            reason=reason,
        )

    def recover_stale(
        self, kind: str, stale_after_seconds: int
    ) -> int:
        if kind not in {"captures", "commands", "deliveries"}:
            raise ValueError(f"Unsupported queue kind: {kind}")
        now = time.time()
        recovered = 0
        processing = self.root / kind / "processing"
        ready = self.root / kind / "ready"
        for path in processing.glob("*.json"):
            if now - path.stat().st_mtime < stale_after_seconds:
                continue
            os.replace(path, ready / path.name)
            recovered += 1
        if recovered:
            log.warning("bus.recovered_stale", kind=kind, count=recovered)
        return recovered

    def close(self) -> None:
        return None

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
        self._fsync_dir(final.parent)
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
        self._settle(kind, token, destination="done")

    def _settle(
        self,
        kind: str,
        token: str,
        destination: str,
        reason: str | None = None,
    ) -> None:
        processing = self.root / kind / "processing"
        target = self.root / kind / destination
        for path in processing.glob("*.json"):
            text = path.read_text(encoding="utf-8")
            if token in text:
                if reason is not None:
                    payload = json.loads(text)
                    payload["_dead_letter_reason"] = reason
                    self._write_fsynced(
                        path,
                        json.dumps(
                            payload, indent=2, default=str
                        ).encode("utf-8"),
                    )
                os.replace(path, target / path.name)
                return

    @staticmethod
    def _write_fsynced(path: Path, data: bytes) -> None:
        with open(path, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
