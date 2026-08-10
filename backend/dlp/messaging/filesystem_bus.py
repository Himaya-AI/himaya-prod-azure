"""Durable local adapter compatible with the gateway filesystem queue."""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from pathlib import Path

from backend.dlp.contracts import (
    CaptureEvent,
    DeliveryEvent,
    GatewayCommand,
)
from backend.dlp.messaging.ports import ReceivedCapture, ReceivedDelivery


class FilesystemDlpMessageBus:
    def __init__(
        self, root: Path, reclaim_after_seconds: int = 300
    ) -> None:
        self.root = root
        self.reclaim_after_seconds = reclaim_after_seconds
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
            (root / name).mkdir(parents=True, exist_ok=True)

    async def receive_captures(
        self, max_messages: int = 10, wait_seconds: int = 5
    ) -> list[ReceivedCapture]:
        deadline = time.monotonic() + max(wait_seconds, 0)
        while True:
            received = await asyncio.to_thread(
                self._dequeue_captures, max_messages
            )
            if received or time.monotonic() >= deadline:
                return received
            await asyncio.sleep(0.1)

    async def complete_capture(self, receipt: str) -> None:
        await asyncio.to_thread(
            self._move_receipt, "captures", receipt, "done"
        )

    async def abandon_capture(self, receipt: str) -> None:
        await asyncio.to_thread(
            self._move_receipt, "captures", receipt, "ready"
        )

    async def dead_letter_capture(
        self, receipt: str, reason: str
    ) -> None:
        await asyncio.to_thread(
            self._dead_letter, "captures", receipt, reason
        )

    async def receive_deliveries(
        self, max_messages: int = 10, wait_seconds: int = 5
    ) -> list[ReceivedDelivery]:
        deadline = time.monotonic() + max(wait_seconds, 0)
        while True:
            received = await asyncio.to_thread(
                self._dequeue_deliveries, max_messages
            )
            if received or time.monotonic() >= deadline:
                return received
            await asyncio.sleep(0.1)

    async def complete_delivery(self, receipt: str) -> None:
        await asyncio.to_thread(
            self._move_receipt, "deliveries", receipt, "done"
        )

    async def abandon_delivery(self, receipt: str) -> None:
        await asyncio.to_thread(
            self._move_receipt, "deliveries", receipt, "ready"
        )

    async def dead_letter_delivery(
        self, receipt: str, reason: str
    ) -> None:
        await asyncio.to_thread(
            self._dead_letter, "deliveries", receipt, reason
        )

    async def publish_command(self, command: GatewayCommand) -> None:
        await asyncio.to_thread(
            self._enqueue,
            "commands",
            command.model_dump(mode="json"),
        )

    async def recover_stale(self) -> int:
        return await asyncio.to_thread(self._recover_stale)

    async def close(self) -> None:
        return None

    def _dequeue_captures(
        self, max_messages: int
    ) -> list[ReceivedCapture]:
        ready = self.root / "captures" / "ready"
        processing = self.root / "captures" / "processing"
        received: list[ReceivedCapture] = []
        for path in sorted(ready.glob("*.json"))[:max_messages]:
            destination = processing / path.name
            try:
                os.replace(path, destination)
            except FileNotFoundError:
                continue
            try:
                event = CaptureEvent.model_validate_json(
                    destination.read_text(encoding="utf-8")
                )
            except Exception as exc:
                self._dead_letter(
                    "captures",
                    destination.name,
                    f"invalid capture event: {exc}",
                )
                continue
            received.append(
                ReceivedCapture(event=event, receipt=destination.name)
            )
        return received

    def _dequeue_deliveries(
        self, max_messages: int
    ) -> list[ReceivedDelivery]:
        ready = self.root / "deliveries" / "ready"
        processing = self.root / "deliveries" / "processing"
        received: list[ReceivedDelivery] = []
        for path in sorted(ready.glob("*.json"))[:max_messages]:
            destination = processing / path.name
            try:
                os.replace(path, destination)
            except FileNotFoundError:
                continue
            try:
                event = DeliveryEvent.model_validate_json(
                    destination.read_text(encoding="utf-8")
                )
            except Exception as exc:
                self._dead_letter(
                    "deliveries",
                    destination.name,
                    f"invalid delivery event: {exc}",
                )
                continue
            received.append(
                ReceivedDelivery(
                    event=event,
                    receipt=destination.name,
                )
            )
        return received

    def _enqueue(self, kind: str, payload: dict) -> None:
        name = f"{int(time.time() * 1000)}_{uuid.uuid4().hex}.json"
        ready = self.root / kind / "ready"
        temporary = ready / f".{name}"
        final = ready / name
        self._write_fsynced(
            temporary,
            json.dumps(payload, indent=2, default=str).encode("utf-8"),
        )
        os.replace(temporary, final)
        self._fsync_dir(ready)

    def _move_receipt(
        self, kind: str, receipt: str, destination: str
    ) -> None:
        source = self._safe_receipt_path(kind, "processing", receipt)
        target_dir = self.root / kind / destination
        os.replace(source, target_dir / source.name)
        self._fsync_dir(target_dir)

    def _dead_letter(
        self, kind: str, receipt: str, reason: str
    ) -> None:
        source = self._safe_receipt_path(kind, "processing", receipt)
        raw = source.read_bytes()
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {
                "_raw_payload": raw.decode("utf-8", errors="replace")
            }
        payload["_dead_letter_reason"] = reason[:4000]
        self._write_fsynced(
            source,
            json.dumps(payload, indent=2, default=str).encode("utf-8"),
        )
        target_dir = self.root / kind / "dead"
        os.replace(source, target_dir / source.name)
        self._fsync_dir(target_dir)

    def _recover_stale(self) -> int:
        now = time.time()
        recovered = 0
        for kind in ("captures", "deliveries"):
            processing = self.root / kind / "processing"
            ready = self.root / kind / "ready"
            kind_recovered = 0
            for path in processing.glob("*.json"):
                if (
                    now - path.stat().st_mtime
                    < self.reclaim_after_seconds
                ):
                    continue
                os.replace(path, ready / path.name)
                recovered += 1
                kind_recovered += 1
            if kind_recovered:
                self._fsync_dir(ready)
        return recovered

    def _safe_receipt_path(
        self, kind: str, state: str, receipt: str
    ) -> Path:
        if Path(receipt).name != receipt or not receipt.endswith(".json"):
            raise ValueError("Invalid filesystem queue receipt")
        path = self.root / kind / state / receipt
        if not path.exists():
            raise FileNotFoundError(receipt)
        return path

    @staticmethod
    def _write_fsynced(path: Path, data: bytes) -> None:
        with open(path, "wb") as file_handle:
            file_handle.write(data)
            file_handle.flush()
            os.fsync(file_handle.fileno())

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
