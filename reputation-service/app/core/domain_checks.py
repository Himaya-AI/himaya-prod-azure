from __future__ import annotations

import importlib.util
import urllib.parse
from dataclasses import dataclass
from typing import Any

if importlib.util.find_spec("confusable_homoglyphs") is not None:
    from confusable_homoglyphs import confusables
else:
    confusables = None

from app.config.settings import load_settings, load_tranco_rank_index
from app.core.tld import TldService


_TLD_SERVICE = TldService()


@dataclass(frozen=True)
class DomainCheckResult:
    check: str
    matched: bool
    indicators: list[str]
    details: dict[str, Any]


def run_domain_checks(
    value: str,
    *,
    rank_index: dict[str, int] | None = None,
    tld_service: TldService | None = None,
) -> dict[str, DomainCheckResult]:
    return {
        "punycode": detect_punycode_domain(value),
        "homoglyph": detect_homoglyph_domain(value),
        "tranco_rank": detect_tranco_rank(
            value,
            rank_index=rank_index,
            tld_service=tld_service,
        ),
    }


def summarize_domain_checks(checks: dict[str, DomainCheckResult]) -> dict[str, Any]:
    punycode = checks.get("punycode")
    homoglyph = checks.get("homoglyph")
    tranco = checks.get("tranco_rank")
    tranco_details = tranco.details if tranco else {}
    return {
        "punycode_detected": bool(punycode and punycode.matched),
        "homoglyph_detected": bool(homoglyph and homoglyph.matched),
        "tranco_rank": tranco_details.get("rank"),
        "tranco_rank_source": tranco_details.get("rank_source"),
        "tranco_matched_domain": tranco_details.get("matched_domain"),
    }


def detect_punycode_domain(value: str) -> DomainCheckResult:
    """
    Detect whether a domain contains one or more punycode labels.

    A label is considered punycode when it begins with the ASCII ACE prefix
    "xn--". This function accepts raw domains, sender-like values, and URLs.
    """
    host = _extract_host(value)
    if not host:
        return _empty_result(
            check="punycode_domain",
            input_value=value,
            details={
                "host": None,
                "punycode_labels": [],
                "unicode_domain": None,
            },
        )

    labels = [label for label in host.split(".") if label]
    punycode_labels = [label for label in labels if label.startswith("xn--")]
    matched = bool(punycode_labels)
    indicators = ["punycode_domain"] if matched else []

    return DomainCheckResult(
        check="punycode_domain",
        matched=matched,
        indicators=indicators,
        details={
            "input": value,
            "host": host,
            "punycode_labels": punycode_labels,
            "unicode_domain": _decode_idna(host) if matched else None,
        },
    )


def detect_homoglyph_domain(value: str) -> DomainCheckResult:
    """
    Detect likely homoglyph abuse in a domain using confusable_homoglyphs.

    Signals include mixed-script labels and Unicode confusable characters.
    """
    host = _extract_host(value)
    if not host:
        return _empty_result(
            check="homoglyph_domain",
            input_value=value,
            details={
                "host": None,
                "unicode_domain": None,
                "mixed_script": False,
                "dangerous_script": False,
                "confusable_count": 0,
            },
        )

    if confusables is None:
        return _empty_result(
            check="homoglyph_domain",
            input_value=value,
            details={
                "host": host,
                "unicode_domain": _decode_idna(host),
                "mixed_script": False,
                "dangerous_script": False,
                "confusable_count": 0,
                "dependency_missing": "confusable_homoglyphs",
            },
        )

    unicode_host = _decode_idna(host)
    has_non_ascii = any(ord(ch) > 127 for ch in unicode_host)
    mixed_script = bool(confusables.is_mixed_script(unicode_host))
    dangerous_script = bool(confusables.is_dangerous(unicode_host))
    confusable_matches = confusables.is_confusable(unicode_host)
    confusable_count = len(confusable_matches) if confusable_matches else 0

    if not has_non_ascii:
        return DomainCheckResult(
            check="homoglyph_domain",
            matched=False,
            indicators=[],
            details={
                "input": value,
                "host": host,
                "unicode_domain": unicode_host,
                "has_non_ascii": False,
                "mixed_script": False,
                "dangerous_script": False,
                "confusable_count": confusable_count,
            },
        )

    indicators: list[str] = []
    if mixed_script:
        indicators.append("homoglyph_mixed_script")
    if dangerous_script:
        indicators.append("homoglyph_dangerous_script")
    # confusable_homoglyphs can report confusables for plain ASCII labels;
    # treat this as suspicious only when Unicode characters are present.
    if has_non_ascii and confusable_count:
        indicators.append("homoglyph_confusable_chars")

    return DomainCheckResult(
        check="homoglyph_domain",
        matched=bool(indicators),
        indicators=indicators,
        details={
            "input": value,
            "host": host,
            "unicode_domain": unicode_host,
            "has_non_ascii": has_non_ascii,
            "mixed_script": mixed_script,
            "dangerous_script": dangerous_script,
            "confusable_count": confusable_count,
        },
    )


def detect_tranco_rank(
    value: str,
    *,
    rank_index: dict[str, int] | None = None,
    tld_service: TldService | None = None,
) -> DomainCheckResult:
    """
    Return Tranco rank for a domain.

    Lookup order:
    1) exact host/domain
    2) eTLD+1 (root domain) fallback
    """
    host = _extract_host(value)
    if not host:
        return _empty_result(
            check="tranco_rank",
            input_value=value,
            details={
                "host": None,
                "matched_domain": None,
                "rank": None,
                "rank_source": None,
                "etld_plus_one": None,
            },
        )

    ranks = rank_index or _load_rank_index()
    etld_plus_one = _root_domain_for(host, tld_service=tld_service)

    rank = ranks.get(host)
    if rank is not None:
        return DomainCheckResult(
            check="tranco_rank",
            matched=True,
            indicators=[f"tranco_rank:{rank}"],
            details={
                "input": value,
                "host": host,
                "matched_domain": host,
                "rank": rank,
                "rank_source": "exact_domain",
                "etld_plus_one": etld_plus_one,
            },
        )

    fallback_rank = ranks.get(etld_plus_one) if etld_plus_one else None
    if fallback_rank is not None:
        return DomainCheckResult(
            check="tranco_rank",
            matched=True,
            indicators=[f"tranco_rank:{fallback_rank}", "tranco_rank_etld_fallback"],
            details={
                "input": value,
                "host": host,
                "matched_domain": etld_plus_one,
                "rank": fallback_rank,
                "rank_source": "etld_plus_one",
                "etld_plus_one": etld_plus_one,
            },
        )

    return DomainCheckResult(
        check="tranco_rank",
        matched=False,
        indicators=[],
        details={
            "input": value,
            "host": host,
            "matched_domain": None,
            "rank": None,
            "rank_source": None,
            "etld_plus_one": etld_plus_one,
        },
    )


def _extract_host(value: str) -> str | None:
    raw = value.strip().lower().rstrip(".")
    if not raw:
        return None

    if "@" in raw:
        raw = raw.rsplit("@", 1)[-1]

    if "://" in raw:
        parsed = urllib.parse.urlparse(raw)
        raw = parsed.hostname or ""

    if not raw:
        return None

    return raw


def _decode_idna(host: str) -> str:
    try:
        return host.encode("ascii").decode("idna")
    except UnicodeError:
        return host


def _root_domain_for(host: str, *, tld_service: TldService | None = None) -> str | None:
    service = tld_service or _TLD_SERVICE
    result = service.analyze(host)
    return result.root_domain


def _empty_result(
    *,
    check: str,
    input_value: str,
    details: dict[str, Any],
) -> DomainCheckResult:
    payload = {"input": input_value}
    payload.update(details)
    return DomainCheckResult(
        check=check,
        matched=False,
        indicators=[],
        details=payload,
    )


def _load_rank_index() -> dict[str, int]:
    settings = load_settings()
    return load_tranco_rank_index(str(settings.tranco_top1m_path))