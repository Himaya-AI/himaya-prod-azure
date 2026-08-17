"""
Pull scan jobs from himaya-email-events and run process_email().

Delta sync only enqueues. This worker is what actually analyzes mail.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time

from backend.database import AsyncSessionLocal
from backend.services.email_job import EMAIL_SCAN_QUEUE, EmailScanJob
from backend.services.email_processor import process_email
from backend.services.queue_client import QueueMessage, queue_client

logger = logging.getLogger(__name__)

_LINK_RE = re.compile(r"https?://\S+")


class EmailWorker:
    def __init__(self, concurrency: int = 4) -> None:
        self._concurrency = max(1, concurrency)
        self._sem = asyncio.Semaphore(self._concurrency)

    async def run(self) -> None:
        logger.info("Email worker started (concurrency=%s)", self._concurrency)
        while True:
            try:
                await self._poll()
            except Exception as exc:
                logger.warning("Email worker poll failed: %s", exc)
                await asyncio.sleep(5)

    async def _poll(self) -> None:
        messages = await queue_client.receive_messages(
            EMAIL_SCAN_QUEUE,
            max_messages=self._concurrency,
            wait_time=20,
        )
        if not messages:
            return
        logger.info("Email worker batch size=%s (cap=%s)", len(messages), self._concurrency)
        await asyncio.gather(
            *(self._run_one(message) for message in messages),
            return_exceptions=True,
        )

    async def _run_one(self, message: QueueMessage) -> None:
        async with self._sem:
            try:
                job = EmailScanJob.from_dict(message.body)
            except ValueError as exc:
                logger.warning("Email worker dropping bad job: %s", exc)
                await message.complete()
                return

            msg_id = job.email.get("message_id")
            started = time.monotonic()
            logger.info("Email worker start msg=%s", msg_id)
            try:
                threat = await process_email(job.email, job.org_id)
            except Exception as exc:
                logger.warning(
                    "Email worker scan failed (will retry) org=%s msg=%s elapsed=%.1fs: %s",
                    job.org_id,
                    msg_id,
                    time.monotonic() - started,
                    exc,
                )
                return
            logger.info(
                "Email worker done msg=%s threat=%s elapsed=%.1fs",
                msg_id,
                getattr(threat, "id", None),
                time.monotonic() - started,
            )

            try:
                await self._after_scan(job, threat)
            except Exception as exc:
                logger.warning("Email worker follow-up failed (non-fatal): %s", exc)

            await message.complete()

    async def _after_scan(self, job: EmailScanJob, threat) -> None:
        """Policy + mailbox actions that used to run in delta_sync after AI."""
        if threat is None:
            return

        email = job.email
        provider = "m365" if job.source == "m365" else "gmail"
        policy = email.get("_matched_policy")
        recipient = email.get("recipient") or email.get("recipient_email") or ""
        message_id = email.get("message_id") or ""
        body = email.get("body") or ""

        if policy:
            from backend.services.policy_engine import apply_policy_action

            async with AsyncSessionLocal() as db:
                await apply_policy_action(
                    policy=policy,
                    threat_id=str(threat.id),
                    email_message_id=message_id,
                    recipient_email=recipient,
                    org_id=job.org_id,
                    db=db,
                    sender_email=email.get("sender"),
                    subject=email.get("subject"),
                    ai_explanation=threat.ai_explanation_en or "",
                    body_preview=body[:300],
                    attachments=email.get("attachments"),
                    link_count=len(_LINK_RE.findall(body)),
                    received_at=email.get("date") or "",
                    provider=provider,
                )
                await db.commit()
            return

        if provider == "m365" and threat.action_taken in ("QUARANTINED", "QUARANTINE"):
            from backend.services.quarantine_service import quarantine_m365_message_with_fallback

            await quarantine_m365_message_with_fallback(
                user_email=recipient,
                m365_message_id=message_id,
                org_id=job.org_id,
            )


async def run_email_worker() -> None:
    concurrency = int(os.getenv("EMAIL_PROCESS_CONCURRENCY", "4"))
    await EmailWorker(concurrency=concurrency).run()
