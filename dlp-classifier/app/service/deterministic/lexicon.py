from __future__ import annotations

import json
from typing import Any

import ahocorasick
import redis.asyncio as redis

from app.service.base import BaseDetector, DetectionMatch, DetectionResult
from app.utils.automaton import build_automaton

ENTITY_CLASSIFICATION_BANNER = "CLASSIFICATION_BANNER"
ENTITY_TENANT_CODENAME = "TENANT_CODENAME"
ENTITY_BUSINESS_TERM = "BUSINESS_TERM"

# in-process automaton cache: tenant_id -> (lexicon_version, automaton)
_automaton_cache: dict[str, tuple[str, ahocorasick.Automaton]] = {}


def _make_redis_key(tenant_id: str) -> str:
    return f"dlp:lexicon:{tenant_id}"


def _infer_entity_type(term: str) -> str:
    if term.isupper():
        return ENTITY_CLASSIFICATION_BANNER
    if "-" in term or "_" in term:
        return ENTITY_TENANT_CODENAME
    return ENTITY_BUSINESS_TERM


async def _get_automaton(
    redis_client: redis.Redis, tenant_id: str, lexicon_version: str
) -> ahocorasick.Automaton | None:
    """Returns the tenant's automaton, from the in-process cache if the
    version matches, otherwise rebuilt from the tenant's Redis-stored terms.
    Never raises — any failure (Redis miss, bad JSON, connection error)
    results in None so the caller can treat it as "no lexicon"."""
    try:
        cached = _automaton_cache.get(tenant_id)
        if cached is not None and cached[0] == lexicon_version:
            return cached[1]

        raw_terms = await redis_client.get(_make_redis_key(tenant_id))
        if raw_terms is None:
            return None

        terms = json.loads(raw_terms)
        automaton = build_automaton(terms)
        _automaton_cache[tenant_id] = (lexicon_version, automaton)
        return automaton
    except Exception:  # noqa: BLE001
        return None


class LexiconDetector(BaseDetector):
    def __init__(self, redis_client: redis.Redis) -> None:
        self._redis = redis_client

    @property
    def name(self) -> str:
        return "lexicon"

    async def analyze(self, text: str, metadata: dict[str, Any]) -> DetectionResult:
        try:
            tenant_id = metadata.get("tenant_id", "default")
            lexicon_version = metadata.get("lexicon_version", "v1")

            automaton = await _get_automaton(self._redis, tenant_id, lexicon_version)
            if automaton is None or len(automaton) == 0:
                return DetectionResult(detector=self.name, matches=[], escalate=False)

            matches = []
            for end_idx, (_term_idx, term) in automaton.iter(text):
                start = end_idx - len(term) + 1
                end = end_idx + 1
                matches.append(
                    DetectionMatch(
                        detector=self.name,
                        entity_type=_infer_entity_type(term),
                        score=1.0,
                        start=start,
                        end=end,
                        metadata={"term": term, "exact_match": True},
                    )
                )

            return DetectionResult(detector=self.name, matches=matches, escalate=False)
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(
                detector=self.name, matches=[], escalate=False, error=str(exc)
            )
