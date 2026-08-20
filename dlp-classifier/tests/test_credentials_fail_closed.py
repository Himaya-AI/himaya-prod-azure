from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.service.deterministic.credentials import (
    CredentialDetector,
    CredentialScanError,
    _run_betterleaks,
)


class _Proc:
    def __init__(
        self,
        stdout: bytes = b"",
        returncode: int = 0,
        hang: bool = False,
    ) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.hang = hang
        self.killed = False

    async def communicate(self, input=None):
        if self.hang:
            await asyncio.sleep(10)
        return self.stdout, b""

    def kill(self) -> None:
        self.killed = True

    async def wait(self) -> int:
        return self.returncode


@pytest.fixture
def betterleaks_settings(monkeypatch):
    settings = SimpleNamespace(
        BETTERLEAKS_BINARY="/usr/local/bin/betterleaks",
        BETTERLEAKS_TIMEOUT=0.05,
    )
    monkeypatch.setattr(
        "app.service.deterministic.credentials.get_settings",
        lambda: settings,
    )
    return settings


@pytest.mark.asyncio
async def test_betterleaks_timeout_fails_closed(
    monkeypatch, betterleaks_settings
) -> None:
    proc = _Proc(hang=True)
    monkeypatch.setattr(
        "app.service.deterministic.credentials.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc),
    )

    with pytest.raises(CredentialScanError, match="timed out"):
        await _run_betterleaks("secret")
    assert proc.killed is True


@pytest.mark.asyncio
async def test_betterleaks_malformed_json_fails_closed(
    monkeypatch, betterleaks_settings
) -> None:
    monkeypatch.setattr(
        "app.service.deterministic.credentials.asyncio.create_subprocess_exec",
        AsyncMock(return_value=_Proc(stdout=b"not-json")),
    )

    with pytest.raises(CredentialScanError, match="malformed JSON"):
        await _run_betterleaks("secret")


@pytest.mark.asyncio
async def test_betterleaks_crash_fails_closed(
    monkeypatch, betterleaks_settings
) -> None:
    monkeypatch.setattr(
        "app.service.deterministic.credentials.asyncio.create_subprocess_exec",
        AsyncMock(return_value=_Proc(stdout=b"", returncode=1)),
    )

    with pytest.raises(CredentialScanError, match="exited with code 1"):
        await _run_betterleaks("secret")


@pytest.mark.asyncio
async def test_betterleaks_empty_report_is_clean(
    monkeypatch, betterleaks_settings
) -> None:
    monkeypatch.setattr(
        "app.service.deterministic.credentials.asyncio.create_subprocess_exec",
        AsyncMock(return_value=_Proc(stdout=b"")),
    )

    assert await _run_betterleaks("hello") == []


@pytest.mark.asyncio
async def test_credential_analyze_maps_scan_error(
    monkeypatch, betterleaks_settings
) -> None:
    monkeypatch.setattr(
        "app.service.deterministic.credentials._run_betterleaks",
        AsyncMock(side_effect=CredentialScanError("BetterLeaks timed out")),
    )
    monkeypatch.setattr(
        "app.service.deterministic.credentials.Path.is_file",
        lambda self: True,
    )
    monkeypatch.setattr(
        "app.service.deterministic.credentials.os.access",
        lambda *args, **kwargs: True,
    )

    result = await CredentialDetector().analyze("token", {})

    assert result.matches == []
    assert result.escalate is True
    assert result.error == "BetterLeaks timed out"
