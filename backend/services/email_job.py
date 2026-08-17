"""
One scan job on the himaya-email-events queue.

Producer and worker share this shape:

    {
        "org_id": "...",
        "source": "google" | "m365",
        "email": { ... same dict process_email() already uses ... },
        "enqueued_at": "2026-08-13T17:00:00+00:00"
    }

The live poller (delta_sync) enqueues this job. EmailWorker pulls it
and calls process_email().
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from backend.services.queue_client import queue_client
from backend.utils.helper import make_id

EMAIL_SCAN_QUEUE = os.getenv("EMAIL_QUEUE_NAME", "himaya-email-events")
EmailSource = Literal["google", "m365"]
_VALID_SOURCES = {"google", "m365"}


@dataclass(frozen=True)
class EmailScanJob:
    org_id: str
    source: EmailSource
    email: dict[str, Any]
    enqueued_at: str

    @classmethod
    def create(cls, org_id: str, source: EmailSource, email: dict[str, Any]) -> EmailScanJob:
        return cls(
            org_id=org_id,
            source=source,
            email=email,
            enqueued_at=datetime.now(timezone.utc).isoformat(),
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EmailScanJob:
        org_id = data.get("org_id")
        source = data.get("source")
        email = data.get("email")
        enqueued_at = data.get("enqueued_at") or datetime.now(timezone.utc).isoformat()

        if not org_id or not isinstance(org_id, str):
            raise ValueError("EmailScanJob requires org_id")
        if source not in _VALID_SOURCES:
            raise ValueError(f"EmailScanJob source must be google or m365, got {source!r}")
        if not isinstance(email, dict):
            raise ValueError("EmailScanJob requires email dict")

        return cls(org_id=org_id, source=source, email=email, enqueued_at=str(enqueued_at))

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "source": self.source,
            "email": self.email,
            "enqueued_at": self.enqueued_at,
        }

    def dedup_id(self) -> str:
        recipient = self.email.get("recipient") or self.email.get("recipient_email") or ""
        message_id = self.email.get("message_id") or ""
        return make_id(f"{self.org_id}:{recipient}:{message_id}")


async def enqueue_scan_job(org_id: str, source: EmailSource, email: dict[str, Any]) -> EmailScanJob:
    """Put one scan job on the queue. Does not call process_email()."""
    job = EmailScanJob.create(org_id=org_id, source=source, email=email)
    await queue_client.send_message(
        EMAIL_SCAN_QUEUE,
        job.to_dict(),
        message_id=job.dedup_id(),
    )
    return job
