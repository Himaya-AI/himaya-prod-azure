"""
DSPM sensitive-data detector.

Runs a catalogue of regex patterns over arbitrary text content, applies
optional validators (e.g. Luhn for credit cards), and emits PatternMatch
records with a redacted sample + context window for analyst review.

Designed to be fast and stateless — the engine can fan out across many
sampled objects concurrently.
"""
from __future__ import annotations

import logging
from typing import Iterable, Optional

from .patterns import DEFAULT_PATTERNS, VALIDATORS
from .types import DataPattern, PatternMatch

logger = logging.getLogger(__name__)


# Hard cap on how much text we'll scan per object. 2 MB is the same cap the
# AWS S3 sampler uses, but the detector enforces its own ceiling defensively.
MAX_SCAN_BYTES = 2 * 1024 * 1024

# Context window around each match (chars on each side).
CONTEXT_CHARS = 40

# Per-pattern max matches we'll emit per object. Avoid pathological matches
# (e.g. an email dump producing 100k records) flooding the sink.
MAX_MATCHES_PER_PATTERN = 50


class SensitiveDataDetector:
    """
    Apply a pattern catalogue to text content.

    Patterns can override the catalogue via the constructor. The default
    catalogue is the global DSPM DEFAULT_PATTERNS list.
    """

    def __init__(self, patterns: Optional[list[DataPattern]] = None):
        self.patterns = [p for p in (patterns or DEFAULT_PATTERNS) if p.enabled]

    def scan_text(
        self,
        text: str,
        *,
        location: Optional[dict] = None,
        max_matches_per_pattern: int = MAX_MATCHES_PER_PATTERN,
    ) -> list[PatternMatch]:
        """
        Run every enabled pattern over ``text``. Returns a flat list of
        PatternMatch records. Location is a free-form dict (bucket/object/etc)
        attached to every match so downstream consumers can correlate.
        """
        if not text:
            return []

        # Defensive truncation — never scan more than MAX_SCAN_BYTES.
        if len(text) > MAX_SCAN_BYTES:
            text = text[:MAX_SCAN_BYTES]

        loc = location or {}
        out: list[PatternMatch] = []

        for pat in self.patterns:
            compiled = pat._compiled
            if compiled is None:
                continue

            validator = VALIDATORS.get(pat.validation) if pat.validation else None
            count_for_pattern = 0

            try:
                for m in compiled.finditer(text):
                    matched = m.group(0)
                    if not matched:
                        continue

                    # Optional validation step (Luhn etc).
                    if validator is not None:
                        try:
                            if not validator(matched):
                                continue
                        except Exception as exc:
                            logger.debug(
                                "validator %s raised on match for %s: %s",
                                pat.validation, pat.name, exc,
                            )
                            continue

                    start = max(0, m.start() - CONTEXT_CHARS)
                    end = min(len(text), m.end() + CONTEXT_CHARS)
                    context = text[start:end].replace("\n", " ").strip()

                    out.append(
                        PatternMatch(
                            pattern_name=pat.name,
                            category=pat.category,
                            matched_text=matched,
                            location=dict(loc),
                            confidence=pat.confidence,
                            context=context,
                        )
                    )

                    count_for_pattern += 1
                    if count_for_pattern >= max_matches_per_pattern:
                        break
            except Exception as exc:
                logger.warning("DSPM pattern %s failed: %s", pat.name, exc)
                continue

        return out

    def scan_chunks(
        self,
        chunks: Iterable[str],
        *,
        location: Optional[dict] = None,
    ) -> list[PatternMatch]:
        """Convenience: scan an iterable of text chunks (e.g. streaming reads)."""
        all_matches: list[PatternMatch] = []
        for chunk in chunks:
            all_matches.extend(self.scan_text(chunk, location=location))
        return all_matches
