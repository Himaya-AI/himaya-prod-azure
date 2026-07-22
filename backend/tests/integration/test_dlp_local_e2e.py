from __future__ import annotations

import asyncio
import os
import smtplib
import time
from email.message import EmailMessage
from uuid import uuid4

import asyncpg
import httpx
import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("DLP_E2E") != "1",
    reason="Set DLP_E2E=1 with docker-compose.dlp.yml running",
)

SMTP_HOST = os.getenv("DLP_E2E_SMTP_HOST", "127.0.0.1")
SMTP_PORT = int(os.getenv("DLP_E2E_SMTP_PORT", "2526"))
MAILHOG_URL = os.getenv(
    "DLP_E2E_MAILHOG_URL", "http://127.0.0.1:18025"
)
DATABASE_URL = os.getenv(
    "DLP_E2E_DATABASE_URL",
    "postgresql://himaya:himaya-local@127.0.0.1:55432/himaya",
)


def _send(sender: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = "outside@external.test"
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as client:
        client.send_message(message)


async def _wait_for_decision(sender: str) -> asyncpg.Record:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        connection = await asyncpg.connect(DATABASE_URL)
        try:
            row = await connection.fetchrow(
                """
                SELECT d.intended_action, d.effective_action, m.state
                FROM dlp_decisions d
                JOIN dlp_messages m ON m.id = d.message_id
                WHERE m.envelope_from = $1
                ORDER BY d.created_at DESC
                LIMIT 1
                """,
                sender,
            )
        finally:
            await connection.close()
        if row is not None:
            return row
        await asyncio.sleep(0.5)
    raise AssertionError(f"Timed out waiting for decision: {sender}")


async def _wait_for_mailhog_total(
    client: httpx.AsyncClient, expected: int
) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        response = await client.get("/api/v2/messages")
        response.raise_for_status()
        if response.json()["total"] == expected:
            return
        await asyncio.sleep(0.5)
    raise AssertionError(
        f"MailHog did not reach expected total {expected}"
    )


@pytest.mark.asyncio
async def test_local_allow_and_stop_flow() -> None:
    async with httpx.AsyncClient(
        base_url=MAILHOG_URL, timeout=5
    ) as mailhog:
        response = await mailhog.delete("/api/v1/messages")
        response.raise_for_status()

        clean_sender = f"clean-{uuid4().hex}@example.test"
        await asyncio.to_thread(
            _send,
            clean_sender,
            "Routine update",
            "The routine project update is attached.",
        )
        clean_decision = await _wait_for_decision(clean_sender)
        assert clean_decision["intended_action"] == "allow"
        assert clean_decision["effective_action"] == "allow"
        assert clean_decision["state"] == "decided"
        await _wait_for_mailhog_total(mailhog, 1)

        blocked_sender = f"blocked-{uuid4().hex}@example.test"
        await asyncio.to_thread(
            _send,
            blocked_sender,
            "Payment data",
            "Customer card: 4111 1111 1111 1111.",
        )
        blocked_decision = await _wait_for_decision(blocked_sender)
        assert blocked_decision["intended_action"] == "stop"
        assert blocked_decision["effective_action"] == "stop"
        assert blocked_decision["state"] == "decided"

        await asyncio.sleep(2)
        response = await mailhog.get("/api/v2/messages")
        response.raise_for_status()
        assert response.json()["total"] == 1
