from __future__ import annotations

from pathlib import Path

from app.config_cache.snapshot import FileTenantConfigCache
from app.domain.models import SpoolRecord
from app.spool.mta_spool import FilesystemSpoolStore, sha256_hex


def test_tenant_resolves_allowed_domain(tmp_path: Path) -> None:
    cfg = tmp_path / "tenant.json"
    cfg.write_text(
        Path("conf/tenants/local-tenant.json").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    cache = FileTenantConfigCache(cfg)
    assert cache.resolve_for_sender("alice@example.test") is not None
    assert cache.resolve_for_sender("eve@evil.test") is None


def test_spool_commit_fsync_roundtrip(tmp_path: Path) -> None:
    spool = FilesystemSpoolStore(tmp_path / "spool")
    mime = b"From: a\r\nTo: b\r\nSubject: t\r\n\r\nhello\r\n"
    record = SpoolRecord(
        org_id="org",
        provider="local",
        provider_deployment_id="dep",
        session_id="s1",
        envelope_from="alice@example.test",
        envelope_to=["bob@external.test"],
        mime_sha256=sha256_hex(mime),
        mime_size=len(mime),
        spool_mime_path="",
        metadata_path="",
    )
    saved = spool.commit(record, mime)
    loaded = spool.get(str(saved.message_id))
    assert loaded is not None
    assert spool.read_mime(loaded) == mime
    pending = spool.list_pending_capture()
    assert len(pending) == 1
