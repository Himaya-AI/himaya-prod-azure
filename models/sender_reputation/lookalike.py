"""
Himaya Helios - MODEL-003: Domain Lookalike Detection
Detects lookalike/typosquatting domains targeting Gulf financial and government organizations.
Uses Levenshtein distance + homoglyph normalization.
"""

from __future__ import annotations

import unicodedata
import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protected Gulf domains — high-value targets for typosquatting
# ---------------------------------------------------------------------------

PROTECTED_DOMAINS: list[str] = [
    # Saudi Banks
    "alrajhibank.com.sa",
    "riyadbank.com",
    "albilad-bank.com",
    "bsf.com.sa",
    "anb.com.sa",
    # UAE Banks
    "adcb.com",
    "emiratesnbd.com",
    "adib.ae",
    "mashreq.com",
    "fab.ae",
    # Saudi Government
    "zatca.gov.sa",
    "gosi.gov.sa",
    "mof.gov.sa",
    "mol.gov.sa",
    "spa.gov.sa",
    # UAE Government
    "government.ae",
    "mohre.gov.ae",
    "dha.gov.ae",
    # Regional Corporations
    "aramco.com",
    "sabic.com",
    "qatargas.com",
    "adnoc.ae",
]

# Homoglyph map: common confusable Unicode characters → ASCII equivalents
HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "а": "a",  # Cyrillic а
    "е": "e",  # Cyrillic е
    "о": "o",  # Cyrillic о
    "р": "p",  # Cyrillic р
    "с": "c",  # Cyrillic с
    "у": "y",  # Cyrillic у
    "х": "x",  # Cyrillic х
    "і": "i",  # Cyrillic і
    # Common ASCII confusables
    "0": "o",
    "1": "l",
    "l": "l",
    "I": "i",
    "rn": "m",  # Two chars → one (handled separately)
    # Greek
    "α": "a",
    "ο": "o",
    "ρ": "p",
    "ν": "v",
}

# Distance threshold for lookalike flagging
LOOKALIKE_THRESHOLD = 2


def _normalize_homoglyphs(domain: str) -> str:
    """
    Normalize a domain by replacing known homoglyph characters with ASCII equivalents.
    Also performs Unicode NFKC normalization.

    Args:
        domain: Raw domain string

    Returns:
        Normalized domain string
    """
    # NFKC normalization first
    domain = unicodedata.normalize("NFKC", domain)

    # Apply per-character homoglyph substitution
    result = []
    for ch in domain:
        result.append(HOMOGLYPH_MAP.get(ch, ch))

    normalized = "".join(result)

    # Replace "rn" → "m" (visual lookalike: "rn" looks like "m")
    normalized = normalized.replace("rn", "m")

    return normalized.lower()


def _extract_sld(domain: str) -> str:
    """
    Extract the second-level domain + TLD for comparison.
    e.g. "mail.alrajhibank.com.sa" → "alrajhibank.com.sa"
    For simple domains like "alrajhibank.com.sa" → "alrajhibank.com.sa"
    """
    parts = domain.lower().split(".")
    if len(parts) <= 2:
        return domain.lower()
    # Handle compound TLDs like .com.sa, .gov.sa, .gov.ae
    if parts[-2] in ("com", "gov", "net", "org", "co") and len(parts) >= 3:
        # Return last 3 parts
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _levenshtein_distance(s1: str, s2: str) -> int:
    """
    Compute Levenshtein edit distance between two strings.

    Args:
        s1: First string
        s2: Second string

    Returns:
        Edit distance as integer
    """
    # Try fast path via python-Levenshtein if available
    try:
        import Levenshtein
        return Levenshtein.distance(s1, s2)
    except ImportError:
        pass

    # Pure Python fallback (DP)
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    m, n = len(s1), len(s2)
    dp = list(range(n + 1))

    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if s1[i - 1] == s2[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = temp

    return dp[n]


def _domain_without_tld(domain: str) -> str:
    """
    Strip the TLD(s) and return the registrable SLD label only.
    e.g. "alrajhibank.com.sa" → "alrajhibank"
    """
    parts = domain.lower().split(".")
    if len(parts) == 1:
        return domain
    # Compound TLD handling
    if len(parts) >= 3 and parts[-2] in ("com", "gov", "net", "org", "co"):
        return parts[-3]
    return parts[-2] if len(parts) >= 2 else parts[0]


def detect_lookalike(
    domain: str,
    protected_domains: list[str] | None = None,
    threshold: int = LOOKALIKE_THRESHOLD,
) -> tuple[bool, str | None, int]:
    """
    Detect if a domain is a lookalike/typosquat of a protected domain.

    Strategy:
    1. Normalize both domains (homoglyph substitution + unicode normalization)
    2. Compare using Levenshtein distance at the SLD level
    3. Also compare full normalized domain strings

    Args:
        domain: Domain to test
        protected_domains: List of domains to protect. Defaults to PROTECTED_DOMAINS.
        threshold: Maximum edit distance to flag as lookalike (default 2)

    Returns:
        Tuple of (is_lookalike, matched_domain, distance)
        - is_lookalike: True if distance ≤ threshold
        - matched_domain: The protected domain it most resembles (or None)
        - distance: Best (minimum) Levenshtein distance found
    """
    if protected_domains is None:
        protected_domains = PROTECTED_DOMAINS

    domain_clean = domain.lower().strip()

    # Exact match → not a lookalike, it IS the real domain
    if domain_clean in protected_domains:
        return False, None, 0

    # Normalize the incoming domain
    domain_normalized = _normalize_homoglyphs(domain_clean)
    domain_sld = _domain_without_tld(domain_clean)
    domain_sld_normalized = _normalize_homoglyphs(domain_sld)

    best_distance = 999
    best_match: str | None = None
    homoglyph_detected = False

    for protected in protected_domains:
        protected_normalized = _normalize_homoglyphs(protected)
        protected_sld = _domain_without_tld(protected)
        protected_sld_normalized = _normalize_homoglyphs(protected_sld)

        # Skip exact match on normalized (already IS the domain after normalization)
        if domain_normalized == protected_normalized:
            # Only flag if original domain differs (homoglyph attack)
            if domain_clean != protected:
                if 0 < best_distance:
                    best_distance = 0
                    best_match = protected
                    homoglyph_detected = True
            continue

        # Compare SLDs (ignore TLD differences)
        sld_dist = _levenshtein_distance(domain_sld_normalized, protected_sld_normalized)

        # Also compare full domain strings (catches TLD swaps like .com vs .com.sa)
        full_dist = _levenshtein_distance(domain_normalized, protected_normalized)

        # Take the minimum of SLD and full domain comparisons
        dist = min(sld_dist, full_dist)

        if dist < best_distance:
            best_distance = dist
            best_match = protected

    # Check if normalization changed the domain (homoglyph detection)
    if domain_normalized != domain_clean and best_distance <= threshold:
        homoglyph_detected = True

    is_lookalike = 0 < best_distance <= threshold

    if is_lookalike:
        logger.info(
            f"Lookalike detected: {domain!r} → {best_match!r} "
            f"(distance={best_distance}, homoglyph={homoglyph_detected})"
        )
    elif best_distance == 0 and best_match:
        # Homoglyph exact match
        is_lookalike = True

    return is_lookalike, best_match if is_lookalike else None, best_distance
