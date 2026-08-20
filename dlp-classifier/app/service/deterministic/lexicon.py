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


class LexiconUnavailableError(Exception):
    """Tenant lexicon could not be loaded from Redis."""


def _make_redis_key(tenant_id: str) -> str:
    return f"dlp:lexicon:{tenant_id}"


def _infer_entity_type(term: str) -> str:
    if term.isupper():
        return ENTITY_CLASSIFICATION_BANNER
    if "-" in term or "_" in term:
        return ENTITY_TENANT_CODENAME
    return ENTITY_BUSINESS_TERM


def clear_automaton_cache() -> None:
    _automaton_cache.clear()


async def _get_automaton(
    redis_client: redis.Redis, tenant_id: str, lexicon_version: str
) -> ahocorasick.Automaton | None:
    """Returns the tenant's automaton, from the in-process cache if the
    version matches, otherwise rebuilt from the tenant's Redis-stored terms.

    A missing Redis key means no lexicon is configured. Redis, JSON, or
    automaton failures raise LexiconUnavailableError so callers can fail
    closed instead of treating the miss as "no terms".
    """
    cached = _automaton_cache.get(tenant_id)
    if cached is not None and cached[0] == lexicon_version:
        return cached[1]

    try:
        raw_terms = await redis_client.get(_make_redis_key(tenant_id))
    except Exception as exc:  # noqa: BLE001
        raise LexiconUnavailableError(
            f"Lexicon store unavailable: {exc}"
        ) from exc

    if raw_terms is None:
        return None

    try:
        terms = json.loads(raw_terms)
        if not isinstance(terms, list):
            raise LexiconUnavailableError("Lexicon payload is not a list")
        automaton = build_automaton(terms)
    except LexiconUnavailableError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise LexiconUnavailableError(
            f"Lexicon payload is invalid: {exc}"
        ) from exc

    _automaton_cache[tenant_id] = (lexicon_version, automaton)
    return automaton


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

            automaton = await _get_automaton(
                self._redis, tenant_id, lexicon_version
            )
            if automaton is None or len(automaton) == 0:
                return DetectionResult(
                    detector=self.name, matches=[], escalate=False
                )

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

            return DetectionResult(
                detector=self.name, matches=matches, escalate=False
            )
        except Exception as exc:  # noqa: BLE001
            return DetectionResult(
                detector=self.name,
                matches=[],
                escalate=True,
                error=str(exc),
            )
