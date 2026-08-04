"""
Cloud-agnostic storage abstraction — Azure Blob Storage implementation.

Falls back to S3 if AWS_* env vars are still present for gradual migration,
but defaults to Azure Blob Storage when AZURE_STORAGE_ACCOUNT is set.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


class StorageClient:
    """Upload/download blobs with Azure Blob Storage (or S3 fallback)."""

    def __init__(self) -> None:
        self._azure_client: Optional[object] = None
        self._azure_account: Optional[str] = None
        self._s3_client: Optional[object] = None
        self._provider: str = "none"

    async def _init_azure(self) -> None:
        if self._azure_client is not None:
            return
        try:
            from azure.identity.aio import DefaultAzureCredential
            from azure.storage.blob.aio import BlobServiceClient

            account = os.getenv("AZURE_STORAGE_ACCOUNT")
            if not account:
                raise RuntimeError("AZURE_STORAGE_ACCOUNT not set")

            self._azure_account = account
            credential = DefaultAzureCredential()
            self._azure_client = BlobServiceClient(
                account_url=f"https://{account}.blob.core.windows.net",
                credential=credential,
            )
            self._provider = "azure"
            logger.info(f"Azure Blob Storage client initialized: {account}")
        except Exception as exc:
            logger.warning(f"Azure Blob init failed: {exc}")
            self._azure_client = None

    async def _init_s3(self) -> None:
        if self._s3_client is not None:
            return
        try:
            import boto3

            region = os.getenv("AWS_REGION", "us-east-1")
            self._s3_client = boto3.client("s3", region_name=region)
            self._provider = "s3"
            logger.info(f"S3 fallback client initialized: {region}")
        except Exception as exc:
            logger.warning(f"S3 fallback init failed: {exc}")
            self._s3_client = None

    async def _ensure_client(self) -> None:
        if self._provider == "azure":
            return
        await self._init_azure()
        if self._provider == "azure":
            return
        await self._init_s3()

    async def upload(
        self,
        container: str,
        key: str,
        data: bytes,
        content_type: Optional[str] = None,
    ) -> str:
        """Upload data and return a public/private URL."""
        await self._ensure_client()

        if self._provider == "azure":
            from azure.storage.blob import ContentSettings

            blob_client = self._azure_client.get_blob_client(container=container, blob=key)
            await blob_client.upload_blob(
                data,
                overwrite=True,
                content_settings=ContentSettings(content_type=content_type or "application/octet-stream"),
            )
            return f"https://{self._azure_account}.blob.core.windows.net/{container}/{key}"

        if self._provider == "s3" and self._s3_client:
            import boto3

            extra_args = {}
            if content_type:
                extra_args["ContentType"] = content_type
            self._s3_client.put_object(Bucket=container, Key=key, Body=data, **extra_args)
            region = os.getenv("AWS_REGION", "us-east-1")
            return f"https://{container}.s3.{region}.amazonaws.com/{key}"

        raise RuntimeError("No storage provider available")

    async def download(self, container: str, key: str) -> bytes:
        """Download blob bytes."""
        await self._ensure_client()

        if self._provider == "azure":
            blob_client = self._azure_client.get_blob_client(container=container, blob=key)
            downloader = await blob_client.download_blob()
            return await downloader.readall()

        if self._provider == "s3" and self._s3_client:
            import io

            response = self._s3_client.get_object(Bucket=container, Key=key)
            return response["Body"].read()

        raise RuntimeError("No storage provider available")

    async def generate_download_url(
        self,
        container: str,
        key: str,
        expires_seconds: int = 1800,
        download_filename: Optional[str] = None,
    ) -> str:
        """
        Return a time-limited, read-only download URL for a blob/object.

        Azure: issues a short-lived user-delegation SAS (works with managed
        identity / DefaultAzureCredential — no account key required).
        S3 fallback: issues a presigned GET URL.
        """
        await self._ensure_client()

        if self._provider == "azure":
            from datetime import datetime, timedelta, timezone
            from azure.storage.blob import BlobSasPermissions, generate_blob_sas

            start = datetime.now(timezone.utc) - timedelta(minutes=5)
            expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_seconds)

            # User-delegation key is required for SAS when authenticating via
            # DefaultAzureCredential (no shared account key available).
            udk = await self._azure_client.get_user_delegation_key(start, expiry)

            content_disposition = (
                f'attachment; filename="{download_filename}"' if download_filename else None
            )
            sas = generate_blob_sas(
                account_name=self._azure_account,
                container_name=container,
                blob_name=key,
                user_delegation_key=udk,
                permission=BlobSasPermissions(read=True),
                start=start,
                expiry=expiry,
                content_disposition=content_disposition,
            )
            return f"https://{self._azure_account}.blob.core.windows.net/{container}/{key}?{sas}"

        if self._provider == "s3" and self._s3_client:
            params = {"Bucket": container, "Key": key}
            if download_filename:
                params["ResponseContentDisposition"] = f'attachment; filename="{download_filename}"'
            return self._s3_client.generate_presigned_url(
                "get_object", Params=params, ExpiresIn=expires_seconds
            )

        raise RuntimeError("No storage provider available")

    async def close(self) -> None:
        if self._azure_client:
            await self._azure_client.close()


# Singleton instance
storage_client = StorageClient()
