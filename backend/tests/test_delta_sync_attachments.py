from unittest.mock import AsyncMock, MagicMock

from backend.services import attachment_hashing as ah
from backend.services import reputation_client as rc


def test_sha256_hex_empty_file():
    assert ah.sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_gmail_urlsafe_b64_to_std():
    assert ah.gmail_urlsafe_b64_to_std("YS0t") == "YS0t"


def test_enrich_gmail_inline_attachment_hashes():
    payload = b"malware-sample"
    inline_b64 = __import__("base64").urlsafe_b64encode(payload).decode().rstrip("=")
    attachments = [
        {
            "filename": "invoice.xlsm",
            "mimeType": "application/vnd.ms-excel.sheet.macroEnabled.12",
            "size": len(payload),
            "inline_data": inline_b64,
        }
    ]

    enriched = __import__("asyncio").run(
        ah.enrich_gmail_attachments_with_sha256(
            client=AsyncMock(),
            user_email="user@example.com",
            msg_id="msg-1",
            attachments=attachments,
            headers={},
        )
    )

    assert len(enriched) == 1
    assert enriched[0]["filename"] == "invoice.xlsm"
    assert enriched[0]["sha256"] == ah.sha256_hex(payload)


def test_enrich_gmail_fetches_attachment_by_id():
    payload = b"by-id-content"
    raw_b64 = __import__("base64").urlsafe_b64encode(payload).decode().rstrip("=")
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"data": raw_b64}
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)

    attachments = [
        {
            "filename": "report.pdf",
            "mimeType": "application/pdf",
            "size": len(payload),
            "attachment_id": "att-123",
        }
    ]

    enriched = __import__("asyncio").run(
        ah.enrich_gmail_attachments_with_sha256(
            client=client,
            user_email="user@example.com",
            msg_id="msg-2",
            attachments=attachments,
            headers={"Authorization": "Bearer x"},
        )
    )

    assert enriched[0]["sha256"] == ah.sha256_hex(payload)
    client.get.assert_awaited_once()


def test_enrich_gmail_skips_oversized_attachment():
    attachments = [
        {
            "filename": "huge.zip",
            "mimeType": "application/zip",
            "size": ah.MAX_ATTACHMENT_BYTES + 1,
            "attachment_id": "att-big",
        }
    ]
    client = AsyncMock()

    enriched = __import__("asyncio").run(
        ah.enrich_gmail_attachments_with_sha256(
            client=client,
            user_email="user@example.com",
            msg_id="msg-3",
            attachments=attachments,
            headers={},
        )
    )

    assert "sha256" not in enriched[0]
    client.get.assert_not_awaited()


def test_fetch_m365_inbound_attachments_hashes_file():
    payload = b"m365-payload"
    content_b64 = __import__("base64").b64encode(payload).decode()
    list_response = MagicMock()
    list_response.status_code = 200
    list_response.json.return_value = {
        "value": [
            {
                "id": "att-1",
                "name": "evil.docm",
                "contentType": "application/vnd.ms-word.document.macroEnabled.12",
                "size": len(payload),
                "@odata.type": "#microsoft.graph.fileAttachment",
            }
        ]
    }
    content_response = MagicMock()
    content_response.status_code = 200
    content_response.json.return_value = {"contentBytes": content_b64}
    client = AsyncMock()
    client.get = AsyncMock(side_effect=[list_response, content_response])

    attachments = __import__("asyncio").run(
        ah.fetch_m365_inbound_attachments(
            client=client,
            user_email="user@example.com",
            message_id="msg-4",
            access_token="token",
        )
    )

    assert len(attachments) == 1
    assert attachments[0]["filename"] == "evil.docm"
    assert attachments[0]["sha256"] == ah.sha256_hex(payload)


def test_build_file_entities_picks_up_delta_sync_attachment_shape():
    email_data = {
        "attachments": [
            {
                "filename": "evil.docm",
                "mimeType": "application/vnd.ms-word.document.macroEnabled.12",
                "size": 12,
                "sha256": ah.sha256_hex(b"m365-payload"),
            }
        ]
    }
    entities = rc.build_file_entities(email_data)
    assert len(entities) == 1
    assert entities[0]["type"] == "file"
    assert entities[0]["hash_type"] == "sha256"
