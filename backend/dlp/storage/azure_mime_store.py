"""Bounded, integrity-checked MIME retrieval from Azure Blob Storage."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

from azure.identity.aio import DefaultAzureCredential
from azure.storage.blob.aio import BlobServiceClient


class MimeStorageError(RuntimeError):
    pass


class MimeObjectTooLargeError(MimeStorageError):
    pass


class MimeIntegrityError(MimeStorageError):
    pass


@dataclass(frozen=True)
class BlobReference:
    container: str
    blob_name: str


class AzureBlobMimeStore:
    def __init__(
        self,
        *,
        container: str,
        connection_string: str = "",
        storage_account: str = "",
    ) -> None:
        if connection_string:
            self._credential: DefaultAzureCredential | None = None
            self._service = BlobServiceClient.from_connection_string(
                connection_string
            )
        elif storage_account:
            self._credential = DefaultAzureCredential()
            self._service = BlobServiceClient(
                account_url=(
                    f"https://{storage_account}.blob.core.windows.net"
                ),
                credential=self._credential,
            )
        else:
            raise ValueError(
                "A storage connection string or account is required"
            )
        self.container = container
        self._expected_host = (
            urlparse(self._service.primary_endpoint).hostname or ""
        ).lower()

    async def download(
        self,
        blob_uri: str,
        *,
        expected_sha256: str,
        max_bytes: int,
    ) -> bytes:
        reference = self._parse_blob_reference(blob_uri)
        client = self._service.get_blob_client(
            container=reference.container,
            blob=reference.blob_name,
        )
        downloader = await client.download_blob(max_concurrency=1)
        content = bytearray()
        async for chunk in downloader.chunks():
            content.extend(chunk)
            if len(content) > max_bytes:
                raise MimeObjectTooLargeError(
                    f"MIME object exceeds {max_bytes} bytes"
                )
        actual_sha256 = hashlib.sha256(content).hexdigest()
        if not hmac.compare_digest(
            actual_sha256.lower(), expected_sha256.lower()
        ):
            raise MimeIntegrityError(
                "MIME SHA-256 does not match the capture event"
            )
        return bytes(content)

    async def close(self) -> None:
        await self._service.close()
        if self._credential is not None:
            await self._credential.close()

    def _parse_blob_reference(self, blob_uri: str) -> BlobReference:
        parsed = urlparse(blob_uri)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"http", "https"}:
            raise MimeStorageError("Blob URI must use HTTP or HTTPS")
        if host != self._expected_host:
            raise MimeStorageError("Blob URI host is not the configured store")

        path_parts = [
            unquote(part)
            for part in parsed.path.split("/")
            if part
        ]
        if path_parts and path_parts[0] == self._service.account_name:
            path_parts = path_parts[1:]
        if len(path_parts) < 2:
            raise MimeStorageError(
                "Blob URI must contain a container and blob name"
            )
        if any(part in {".", ".."} for part in path_parts):
            raise MimeStorageError("Blob URI contains an invalid path segment")
        container, *blob_parts = path_parts
        if container != self.container:
            raise MimeStorageError(
                "Blob URI container is not the configured MIME container"
            )
        return BlobReference(
            container=container,
            blob_name="/".join(blob_parts),
        )
