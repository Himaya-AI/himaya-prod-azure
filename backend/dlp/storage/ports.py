"""Storage ports for immutable captured MIME objects."""

from typing import Protocol


class MimeObjectStore(Protocol):
    async def download(
        self,
        blob_uri: str,
        *,
        expected_sha256: str,
        max_bytes: int,
    ) -> bytes: ...

    async def close(self) -> None: ...
