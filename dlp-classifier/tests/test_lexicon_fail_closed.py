from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("ahocorasick")

from app.service.deterministic.lexicon import (
    LexiconDetector,
    clear_automaton_cache,
)


@pytest.mark.asyncio
async def test_lexicon_redis_miss_is_empty() -> None:
    clear_automaton_cache()
    redis_client = SimpleNamespace(get=AsyncMock(return_value=None))
    result = await LexiconDetector(redis_client).analyze(
        "CONFIDENTIAL payload",
        {"tenant_id": "t1", "lexicon_version": "v1"},
    )
    assert result.error is None
    assert result.matches == []


@pytest.mark.asyncio
async def test_lexicon_redis_failure_fails_closed() -> None:
    clear_automaton_cache()
    redis_client = SimpleNamespace(
        get=AsyncMock(side_effect=ConnectionError("redis down"))
    )
    result = await LexiconDetector(redis_client).analyze(
        "CONFIDENTIAL payload",
        {"tenant_id": "t1", "lexicon_version": "v1"},
    )
    assert result.matches == []
    assert result.error is not None
    assert result.escalate is True
    assert "unavailable" in result.error.lower()


@pytest.mark.asyncio
async def test_lexicon_corrupt_payload_fails_closed() -> None:
    clear_automaton_cache()
    redis_client = SimpleNamespace(
        get=AsyncMock(return_value=b"not-json")
    )
    result = await LexiconDetector(redis_client).analyze(
        "CONFIDENTIAL payload",
        {"tenant_id": "t1", "lexicon_version": "v1"},
    )
    assert result.error is not None
    assert result.escalate is True


@pytest.mark.asyncio
async def test_lexicon_terms_still_match() -> None:
    clear_automaton_cache()
    redis_client = SimpleNamespace(
        get=AsyncMock(return_value=json.dumps(["CONFIDENTIAL"]))
    )
    result = await LexiconDetector(redis_client).analyze(
        "this is CONFIDENTIAL data",
        {"tenant_id": "t1", "lexicon_version": "v1"},
    )
    assert result.error is None
    assert len(result.matches) == 1
    assert result.matches[0].entity_type == "CLASSIFICATION_BANNER"
