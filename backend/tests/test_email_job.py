import asyncio
from unittest.mock import AsyncMock, patch

from backend.services import email_job as ej
from backend.utils.helper import MAX_QUEUE_BYTES, fit_queue_payload, to_json


def test_fit_queue_payload_leaves_small_jobs_alone():
    data = {
        "org_id": "org-1",
        "source": "m365",
        "email": {"message_id": "m1", "body": "hello", "html_body": "<p>hi</p>"},
        "enqueued_at": "2026-08-17T00:00:00+00:00",
    }
    assert fit_queue_payload(data) is data


def test_fit_queue_payload_drops_html_to_fit_service_bus_limit():
    data = {
        "org_id": "org-1",
        "source": "m365",
        "email": {
            "message_id": "m1",
            "body": "plain",
            "html_body": "x" * MAX_QUEUE_BYTES,
            "attachments": [{"filename": "a.pdf", "inline_data": "y" * 1000}],
        },
        "enqueued_at": "2026-08-17T00:00:00+00:00",
    }
    fitted = fit_queue_payload(data)
    assert "html_body" not in fitted["email"]
    assert "inline_data" not in fitted["email"]["attachments"][0]
    assert len(to_json(fitted).encode("utf-8")) <= MAX_QUEUE_BYTES


def test_enqueue_scan_job_sends_fitted_payload():
    huge = {
        "message_id": "m1",
        "recipient": "user@example.com",
        "html_body": "x" * MAX_QUEUE_BYTES,
        "body": "plain",
    }
    send = AsyncMock()
    with patch.object(ej.queue_client, "send_message", send):
        asyncio.run(ej.enqueue_scan_job("org-1", "google", huge))

    sent_body = send.await_args.args[1]
    assert "html_body" not in sent_body["email"]
    assert len(to_json(sent_body).encode("utf-8")) <= MAX_QUEUE_BYTES
