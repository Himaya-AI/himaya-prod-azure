from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.config_cache.snapshot import FileTenantConfigCache
from app.domain.models import (
    DeliveryOutcome,
    RelayRequest,
    RelayResult,
    SmtpStage,
    SpoolRecord,
)
from app.relay.adapters.microsoft import Microsoft365RelayAdapter
from app.relay.adapters import RelayAdapterRegistry, build_default_registry
from app.relay.adapters.local_sink import SmtpSinkRelayAdapter
from app.relay.certificates import FilesystemRelayCertificateProvider
from app.relay.dispatcher import RelayDispatcher
from app.relay.outcomes import classify_smtp_result, spool_state_for_outcome
from app.relay.smtp_transport import PhaseAwareSmtpTransport
from app.spool.mta_spool import FilesystemSpoolStore, sha256_hex


class _ScriptedSmtp:
    """Minimal SMTP stand-in: scripted RCPT/DATA replies without raising."""

    def __init__(
        self,
        *args: Any,
        rcpt_codes: dict[str, int] | None = None,
        data_code: int = 250,
        **kwargs: Any,
    ) -> None:
        self._rcpt_codes = rcpt_codes or {}
        self._data_code = data_code
        self._default_rcpt = 250

    def has_extn(self, name: str) -> bool:
        return False

    def ehlo(self, hostname: str = "") -> tuple[int, bytes]:
        return 250, b"ok"

    def mail(self, sender: str) -> tuple[int, bytes]:
        return 250, b"ok"

    def rcpt(self, recipient: str) -> tuple[int, bytes]:
        code = self._rcpt_codes.get(recipient, self._default_rcpt)
        return code, b"ok" if code < 400 else b"refused"

    def data(self, msg: bytes) -> tuple[int, bytes]:
        return self._data_code, b"queued" if self._data_code < 400 else b"rejected"

    def quit(self) -> None:
        return None

    def close(self) -> None:
        return None


def _submit_mixed_rcpt(
    monkeypatch: Any,
    *,
    data_code: int,
) -> RelayResult:
    def _factory(*args: Any, **kwargs: Any) -> _ScriptedSmtp:
        return _ScriptedSmtp(
            rcpt_codes={
                "ok@external.test": 250,
                "bad@external.test": 550,
            },
            data_code=data_code,
        )

    monkeypatch.setattr("app.relay.smtp_transport.smtplib.SMTP", _factory)
    return PhaseAwareSmtpTransport().submit(
        host="mx.example.test",
        port=25,
        envelope_from="a@sana085.onmicrosoft.com",
        envelope_to=["ok@external.test", "bad@external.test"],
        mime_bytes=b"From: a\r\n\r\nbody\r\n",
        require_starttls=False,
    )


def _write_self_signed_cert(dir_path: Path) -> tuple[Path, Path, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sana085-test.smtp-relay.himaya.ai")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_path = dir_path / "client.pem"
    key_path = dir_path / "client.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    thumbprint = (
        cert.fingerprint(hashes.SHA1()).hex()
    )
    return cert_path, key_path, thumbprint


def test_classify_uncertain_after_data() -> None:
    assert (
        classify_smtp_result(None, connection_lost_after_data=True)
        == DeliveryOutcome.UNCERTAIN
    )
    assert spool_state_for_outcome(DeliveryOutcome.PARTIAL) == "failed"


def test_tenant_snapshot_parses_microsoft_relay(tmp_path: Path) -> None:
    cfg = tmp_path / "tenant.json"
    cfg.write_text(
        """
{
  "schema_version": 1,
  "org_id": "org-1",
  "provider_deployment_id": "dep-1",
  "provider": "m365",
  "routing_hostname": "test.smtp.dlp.himaya.ai",
  "status": "enabled",
  "accepted_sender_domains": ["sana085.onmicrosoft.com"],
  "relay": {
    "adapter": "microsoft",
    "mx_host": "sana085.mail.protection.outlook.com",
    "port": 25,
    "require_starttls": true,
    "ehlo_hostname": "sana085-test.smtp-relay.himaya.ai",
    "tls_sender_certificate_name": "sana085-test.smtp-relay.himaya.ai",
    "client_cert_path": "/certs/client.pem",
    "client_key_path": "/certs/client.key"
  },
  "config_version": 2
}
""".strip(),
        encoding="utf-8",
    )
    cache = FileTenantConfigCache(cfg)
    snap = cache.resolve_for_sender("test@sana085.onmicrosoft.com")
    assert snap is not None
    assert snap.relay.adapter == "microsoft"
    assert snap.relay.host == "sana085.mail.protection.outlook.com"
    assert snap.relay.port == 25
    assert cache.resolve_by_org_id("org-1") is not None


def test_registry_selects_microsoft_adapter() -> None:
    registry = build_default_registry()
    from app.config_cache.snapshot import TenantRelayConfig

    microsoft = TenantRelayConfig(
        adapter="microsoft",
        host="sana085.mail.protection.outlook.com",
        port=25,
        use_tls=True,
        require_starttls=True,
        ehlo_hostname="x",
        tls_sender_certificate_name="x",
        client_cert_path="/c.pem",
        client_key_path="/k.pem",
        certificate_thumbprint=None,
        connection_timeout_seconds=20,
        command_timeout_seconds=60,
    )
    local = TenantRelayConfig(
        adapter="local",
        host="mailhog",
        port=1025,
        use_tls=False,
        require_starttls=False,
        ehlo_hostname=None,
        tls_sender_certificate_name=None,
        client_cert_path=None,
        client_key_path=None,
        certificate_thumbprint=None,
        connection_timeout_seconds=20,
        command_timeout_seconds=60,
    )
    assert registry.get(microsoft).__class__.__name__ == "Microsoft365RelayAdapter"
    assert registry.get(local).__class__.__name__ == "SmtpSinkRelayAdapter"


def test_cert_provider_reloads_after_pem_mtime_change(tmp_path: Path) -> None:
    cert_path, key_path, thumbprint_a = _write_self_signed_cert(tmp_path)
    provider = FilesystemRelayCertificateProvider()
    first = provider.get_certificate("org-1", str(cert_path), str(key_path))
    assert first.thumbprint == thumbprint_a

    # Overwrite with a new cert; bump mtime so cache invalidates on Windows too.
    alt_dir = tmp_path / "b"
    alt_dir.mkdir()
    cert_path_b, key_path_b, thumbprint_b = _write_self_signed_cert(alt_dir)
    cert_path.write_bytes(cert_path_b.read_bytes())
    key_path.write_bytes(key_path_b.read_bytes())
    import os
    import time

    now = time.time() + 5
    os.utime(cert_path, (now, now))
    os.utime(key_path, (now, now))

    second = provider.get_certificate("org-1", str(cert_path), str(key_path))
    assert second.thumbprint == thumbprint_b
    assert second.thumbprint != thumbprint_a


def test_microsoft_adapter_requires_cert_paths() -> None:
    adapter = Microsoft365RelayAdapter()
    result = adapter.submit(
        RelayRequest(
            message_id=uuid4(),
            org_id="org-1",
            provider="m365",
            provider_deployment_id="dep-1",
            envelope_from="a@sana085.onmicrosoft.com",
            envelope_to=["b@external.test"],
            mime_bytes=b"From: a\r\n\r\nbody\r\n",
            relay_config={
                "host": "sana085.mail.protection.outlook.com",
                "port": 25,
            },
        )
    )
    assert result.outcome == DeliveryOutcome.FAILED
    assert "client_cert_path" in (result.detail or "")


def test_microsoft_adapter_uses_transport(tmp_path: Path) -> None:
    cert_path, key_path, thumbprint = _write_self_signed_cert(tmp_path)

    class _FakeTransport:
        def __init__(self) -> None:
            self.called = False

        def submit(self, **kwargs):
            self.called = True
            assert kwargs["host"] == "sana085.mail.protection.outlook.com"
            assert kwargs["client_certificate"] is not None
            return RelayResult(
                outcome=DeliveryOutcome.ACCEPTED,
                smtp_code=250,
                smtp_stage=SmtpStage.FINAL_RESPONSE,
                remote_host=kwargs["host"],
                certificate_thumbprint=kwargs["client_certificate"].thumbprint,
            )

    transport = _FakeTransport()
    adapter = Microsoft365RelayAdapter(
        certificate_provider=FilesystemRelayCertificateProvider(),
        transport=transport,  # type: ignore[arg-type]
    )
    result = adapter.submit(
        RelayRequest(
            message_id=uuid4(),
            org_id="org-1",
            provider="m365",
            provider_deployment_id="dep-1",
            envelope_from="a@sana085.onmicrosoft.com",
            envelope_to=["b@external.test"],
            mime_bytes=b"From: a\r\n\r\nbody\r\n",
            relay_config={
                "host": "sana085.mail.protection.outlook.com",
                "port": 25,
                "require_starttls": True,
                "ehlo_hostname": "sana085-test.smtp-relay.himaya.ai",
                "client_cert_path": str(cert_path),
                "client_key_path": str(key_path),
                "certificate_thumbprint": thumbprint,
            },
        )
    )
    assert transport.called
    assert result.outcome == DeliveryOutcome.ACCEPTED
    assert result.certificate_thumbprint == thumbprint


def test_mixed_rcpt_data_250_is_partial(monkeypatch: Any) -> None:
    result = _submit_mixed_rcpt(monkeypatch, data_code=250)
    assert result.outcome == DeliveryOutcome.PARTIAL
    assert result.accepted_recipients == ["ok@external.test"]
    assert result.refused_recipients == ["bad@external.test"]
    assert result.smtp_code == 250


def test_mixed_rcpt_data_550_is_failed_not_partial(monkeypatch: Any) -> None:
    result = _submit_mixed_rcpt(monkeypatch, data_code=550)
    assert result.outcome == DeliveryOutcome.FAILED
    assert result.outcome != DeliveryOutcome.PARTIAL
    assert result.smtp_code == 550
    assert result.accepted_recipients == ["ok@external.test"]
    assert result.refused_recipients == ["bad@external.test"]


def test_mixed_rcpt_data_450_is_deferred_not_partial(monkeypatch: Any) -> None:
    result = _submit_mixed_rcpt(monkeypatch, data_code=450)
    assert result.outcome == DeliveryOutcome.DEFERRED
    assert result.outcome != DeliveryOutcome.PARTIAL
    assert result.smtp_code == 450


def test_dispatcher_persists_relay_diagnostic_fields(tmp_path: Path) -> None:
    spool = FilesystemSpoolStore(tmp_path / "spool")
    mime = b"From: a\r\nTo: b\r\n\r\nhello\r\n"
    record = SpoolRecord(
        org_id="org-1",
        provider="m365",
        provider_deployment_id="dep-1",
        session_id="s1",
        envelope_from="a@sana085.onmicrosoft.com",
        envelope_to=["ok@external.test", "bad@external.test"],
        mime_sha256=sha256_hex(mime),
        mime_size=len(mime),
        spool_mime_path="",
        metadata_path="",
    )
    saved = spool.commit(record, mime)
    spool.mark_captured(str(saved.message_id), blob_uri="blob://test")

    cfg = tmp_path / "tenant.json"
    cfg.write_text(
        """
{
  "schema_version": 1,
  "org_id": "org-1",
  "provider_deployment_id": "dep-1",
  "provider": "m365",
  "routing_hostname": "test.smtp.dlp.himaya.ai",
  "status": "enabled",
  "accepted_sender_domains": ["sana085.onmicrosoft.com"],
  "relay": {
    "adapter": "microsoft",
    "mx_host": "sana085.mail.protection.outlook.com",
    "port": 25,
    "require_starttls": true,
    "ehlo_hostname": "sana085-test.smtp-relay.himaya.ai",
    "client_cert_path": "/certs/client.pem",
    "client_key_path": "/certs/client.key"
  },
  "config_version": 1
}
""".strip(),
        encoding="utf-8",
    )
    tenant_cache = FileTenantConfigCache(cfg)

    class _StubAdapter:
        def submit(self, request: RelayRequest) -> RelayResult:
            return RelayResult(
                outcome=DeliveryOutcome.PARTIAL,
                smtp_code=250,
                smtp_message="ok",
                detail="partial",
                smtp_stage=SmtpStage.FINAL_RESPONSE,
                accepted_recipients=["ok@external.test"],
                refused_recipients=["bad@external.test"],
                remote_host="sana085.mail.protection.outlook.com",
                certificate_thumbprint="abc123",
            )

    registry = RelayAdapterRegistry(
        local_adapter=SmtpSinkRelayAdapter(host="mailhog", port=1025),
        microsoft_adapter=_StubAdapter(),  # type: ignore[arg-type]
    )
    dispatcher = RelayDispatcher(spool, registry, tenant_cache)
    result = dispatcher.relay_message(str(saved.message_id))
    assert result.outcome == DeliveryOutcome.PARTIAL

    loaded = spool.get(str(saved.message_id))
    assert loaded is not None
    assert loaded.relay_smtp_code == 250
    assert loaded.relay_detail == "partial"
    assert loaded.relay_smtp_stage == SmtpStage.FINAL_RESPONSE.value
    assert loaded.relay_remote_host == "sana085.mail.protection.outlook.com"
    assert loaded.relay_cert_thumbprint == "abc123"
    assert loaded.relay_accepted_recipients == ["ok@external.test"]
    assert loaded.relay_refused_recipients == ["bad@external.test"]
