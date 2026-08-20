from __future__ import annotations

import threading
from dataclasses import dataclass, field

from app.capture.worker import CaptureWorker
from app.commands.consumer import CommandConsumer
from app.events.delivery_worker import DeliveryEventPublisherWorker
from app.logging_setup import get_logger
from app.workers.auto_allow import AutoAllowWorker

log = get_logger(__name__)


@dataclass
class WorkerSupervisor:
    capture: CaptureWorker
    auto_allow: AutoAllowWorker
    commands: CommandConsumer
    delivery_events: DeliveryEventPublisherWorker
    poll_interval_sec: float = 1.0
    reclaim_after_sec: int = 300
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    def start(self) -> None:
        self.auto_allow.bus.recover_stale(
            "captures", self.reclaim_after_sec
        )
        self.commands.bus.recover_stale(
            "commands", self.reclaim_after_sec
        )
        self.delivery_events.recover_stale_submissions()
        self._thread = threading.Thread(target=self._loop, name="dlp-workers", daemon=True)
        self._thread.start()
        log.info("workers.started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self.commands.bus.close()
        log.info("workers.stopped")

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.capture.run_once()
                self.auto_allow.run_once()
                self.commands.run_once()
                self.delivery_events.run_once()
            except Exception:
                log.exception("workers.tick_failed")
            self._stop.wait(self.poll_interval_sec)
