from __future__ import annotations

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobServiceClient, ContentSettings

from app.logging_setup import get_logger

log = get_logger(__name__)


class AzureBlobMimeStore:
    """Immutable MIME object store (Azurite or Azure Blob)."""

    def __init__(self, connection_string: str, container: str) -> None:
        self.container = container
        self._client = BlobServiceClient.from_connection_string(connection_string)
        self._ensure_container()

    def _ensure_container(self) -> None:
        try:
            self._client.create_container(self.container)
        except ResourceExistsError:
            pass
        except Exception as exc:
            # Azurite may race on startup; retry once at first put.
            log.warning("blob.container_init_deferred", error=str(exc))

    def put_immutable(
        self, org_id: str, message_id: str, mime_bytes: bytes, sha256: str
    ) -> str:
        self._ensure_container()
        blob_name = f"{org_id}/{message_id}/{sha256}.eml"
        blob = self._client.get_blob_client(self.container, blob_name)
        if blob.exists():
            log.info("blob.already_exists", blob=blob_name)
            return blob.url
        blob.upload_blob(
            mime_bytes,
            overwrite=False,
            content_settings=ContentSettings(content_type="message/rfc822"),
            metadata={"sha256": sha256, "org_id": org_id, "message_id": message_id},
        )
        log.info("blob.stored", blob=blob_name, size=len(mime_bytes))
        return blob.url
