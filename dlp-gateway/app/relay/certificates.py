from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.logging_setup import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class LoadedRelayCertificate:
    org_id: str
    cert_path: Path
    key_path: Path
    thumbprint: str
    not_after: datetime
    subject: str


class CertificateLoadError(RuntimeError):
    """Certificate material is missing or invalid."""


class FilesystemRelayCertificateProvider:
    """Load PEM client cert/key from disk for AWS staging.

    Production can swap this for Secrets Manager / Key Vault without changing
    the Microsoft adapter.
    """

    def __init__(self) -> None:
        # value: (loaded cert, cert mtime_ns, key mtime_ns)
        self._cache: dict[
            tuple[str, str, str], tuple[LoadedRelayCertificate, int, int]
        ] = {}

    def get_certificate(
        self,
        org_id: str,
        cert_path: str,
        key_path: str,
        expected_thumbprint: str | None = None,
    ) -> LoadedRelayCertificate:
        cache_key = (org_id, cert_path, key_path)
        cert_file = Path(cert_path)
        key_file = Path(key_path)
        if not cert_file.is_file():
            raise CertificateLoadError(f"client cert not found: {cert_file}")
        if not key_file.is_file():
            raise CertificateLoadError(f"client key not found: {key_file}")

        cert_mtime = cert_file.stat().st_mtime_ns
        key_mtime = key_file.stat().st_mtime_ns
        cached = self._cache.get(cache_key)
        if cached is not None:
            loaded, cached_cert_mtime, cached_key_mtime = cached
            if (
                cached_cert_mtime == cert_mtime
                and cached_key_mtime == key_mtime
            ):
                self._validate(loaded, expected_thumbprint)
                return loaded

        cert_bytes = cert_file.read_bytes()
        key_bytes = key_file.read_bytes()
        try:
            certificate = x509.load_pem_x509_certificate(cert_bytes)
            serialization.load_pem_private_key(key_bytes, password=None)
        except Exception as exc:  # noqa: BLE001 - surface as load error
            raise CertificateLoadError(f"invalid PEM material: {exc}") from exc

        thumbprint = hashlib.sha1(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest()
        not_after = getattr(certificate, "not_valid_after_utc", None)
        if not_after is None:
            not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
        loaded = LoadedRelayCertificate(
            org_id=org_id,
            cert_path=cert_file,
            key_path=key_file,
            thumbprint=thumbprint,
            not_after=not_after,
            subject=certificate.subject.rfc4514_string(),
        )
        self._validate(loaded, expected_thumbprint)
        self._cache[cache_key] = (loaded, cert_mtime, key_mtime)
        log.info(
            "relay_cert.loaded",
            org_id=org_id,
            thumbprint=thumbprint,
            not_after=not_after.isoformat(),
        )
        return loaded

    def invalidate(self, org_id: str | None = None) -> None:
        if org_id is None:
            self._cache.clear()
            return
        self._cache = {
            key: value for key, value in self._cache.items() if key[0] != org_id
        }

    @staticmethod
    def _validate(
        loaded: LoadedRelayCertificate, expected_thumbprint: str | None
    ) -> None:
        now = datetime.now(timezone.utc)
        if loaded.not_after <= now:
            raise CertificateLoadError(
                f"client certificate expired at {loaded.not_after.isoformat()}"
            )
        if expected_thumbprint:
            expected = expected_thumbprint.replace(":", "").lower()
            actual = loaded.thumbprint.lower()
            if expected != actual:
                raise CertificateLoadError(
                    "client certificate thumbprint mismatch"
                )
