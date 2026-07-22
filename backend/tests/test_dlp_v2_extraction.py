from __future__ import annotations

import io
import zipfile
from email.message import EmailMessage

import pytest

from backend.dlp.extraction import (
    MimeExtractionError,
    MimeExtractionLimits,
    SafeMimeExtractor,
)


@pytest.mark.asyncio
async def test_extracts_headers_plain_text_and_html() -> None:
    message = EmailMessage()
    message["Subject"] = "Quarterly report"
    message["From"] = "alice@example.test"
    message["To"] = "bob@external.test"
    message.set_content("Account number: 1234")
    message.add_alternative(
        "<html><body><b>Confidential</b> forecast</body></html>",
        subtype="html",
    )

    result = await SafeMimeExtractor().extract(message.as_bytes())

    assert result.subject == "Quarterly report"
    assert result.sender == "alice@example.test"
    assert "Account number: 1234" in result.text
    assert "Confidential forecast" in result.text
    assert result.is_complete


@pytest.mark.asyncio
async def test_encrypted_pdf_is_reported_not_treated_as_clean() -> None:
    message = EmailMessage()
    message.set_content("See attachment")
    message.add_attachment(
        b"%PDF-1.7\n/Encrypt 1 0 R\n",
        maintype="application",
        subtype="pdf",
        filename="secret.pdf",
    )

    result = await SafeMimeExtractor().extract(message.as_bytes())

    limitation = next(
        item
        for item in result.limitations
        if item.code == "encrypted_content"
    )
    assert limitation.filename == "secret.pdf"
    assert limitation.fatal is True


@pytest.mark.asyncio
async def test_unsupported_attachment_is_explicit_limitation() -> None:
    message = EmailMessage()
    message.set_content("See attachment")
    message.add_attachment(
        b"\x00\x01\x02",
        maintype="application",
        subtype="x-custom",
        filename="sample.custom",
    )

    result = await SafeMimeExtractor().extract(message.as_bytes())

    assert any(
        item.code == "unsupported_content_type"
        for item in result.limitations
    )


@pytest.mark.asyncio
async def test_classifier_text_limit_is_utf8_safe_and_fatal() -> None:
    message = EmailMessage()
    message.set_content("é" * 100)
    extractor = SafeMimeExtractor(
        MimeExtractionLimits(max_text_bytes=80)
    )

    result = await extractor.extract(message.as_bytes())

    assert len(result.text.encode("utf-8")) <= 80
    assert any(
        item.code == "text_limit_exceeded" and item.fatal
        for item in result.limitations
    )


@pytest.mark.asyncio
async def test_rejects_mime_larger_than_hard_limit() -> None:
    extractor = SafeMimeExtractor(
        MimeExtractionLimits(max_mime_bytes=10)
    )

    with pytest.raises(MimeExtractionError, match="exceeds"):
        await extractor.extract(b"x" * 11)


@pytest.mark.asyncio
async def test_archive_expansion_limit_blocks_attachment() -> None:
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(
        archive_bytes, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        archive.writestr("document.xml", "0" * 100_000)
    message = EmailMessage()
    message.set_content("See attachment")
    message.add_attachment(
        archive_bytes.getvalue(),
        maintype="application",
        subtype=(
            "vnd.openxmlformats-officedocument."
            "wordprocessingml.document"
        ),
        filename="bomb.docx",
    )
    extractor = SafeMimeExtractor(
        MimeExtractionLimits(max_archive_ratio=2)
    )

    result = await extractor.extract(message.as_bytes())

    assert any(
        item.code == "archive_expansion_limit" and item.fatal
        for item in result.limitations
    )
