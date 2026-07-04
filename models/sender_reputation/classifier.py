"""
Himaya Helios - MODEL-003: Sender Reputation Classifier
XGBoost-based reputation scorer with rule-based fallback.
"""

from __future__ import annotations

import logging
import math
import pickle
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TLD Risk Scores — lower = more trustworthy
# ---------------------------------------------------------------------------

TLD_RISK_SCORES: dict[str, float] = {
    ".com": 0.1,
    ".net": 0.2,
    ".org": 0.2,
    ".info": 0.7,
    ".xyz": 0.8,
    ".top": 0.9,
    ".gov.sa": 0.0,
    ".gov.ae": 0.0,
    ".com.sa": 0.1,
    ".ae": 0.15,
    ".io": 0.3,
    ".co": 0.3,
    ".biz": 0.6,
    ".click": 0.8,
    ".online": 0.7,
    ".site": 0.7,
    ".tk": 0.95,
    ".ml": 0.95,
    ".ga": 0.95,
}

# Feature column order — must match training
FEATURE_COLUMNS = [
    "domain_age_days",
    "has_dmarc",
    "has_spf",
    "has_dkim",
    "is_breached",
    "is_lookalike",
    "lookalike_distance",
    "is_new_to_org",
    "tld_risk_score",
    "mx_valid",
    "domain_entropy",
]


def get_tld_risk_score(domain: str) -> float:
    """
    Return the TLD risk score for a domain.

    Checks compound TLDs first (.gov.sa, .com.sa) then simple TLDs.

    Args:
        domain: Full domain string

    Returns:
        Risk score between 0.0 (safe) and 1.0 (risky). Default 0.5 for unknown TLDs.
    """
    domain = domain.lower().strip()

    # Check compound TLDs first (longer matches take priority)
    for tld in sorted(TLD_RISK_SCORES.keys(), key=len, reverse=True):
        if domain.endswith(tld):
            return TLD_RISK_SCORES[tld]

    return 0.5  # Unknown TLD → moderate risk


def compute_domain_entropy(domain: str) -> float:
    """
    Compute Shannon entropy of the second-level domain (SLD) label.

    High entropy (>3.5) suggests randomly generated domain names
    typical of DGA (Domain Generation Algorithm) malware.

    Args:
        domain: Full domain string

    Returns:
        Shannon entropy value (bits)
    """
    # Extract SLD (registrable label)
    parts = domain.lower().strip().split(".")
    if len(parts) >= 3 and parts[-2] in ("com", "gov", "net", "org", "co"):
        sld = parts[-3]
    elif len(parts) >= 2:
        sld = parts[-2]
    else:
        sld = domain

    if not sld:
        return 0.0

    # Compute character frequency distribution
    freq: dict[str, int] = {}
    for ch in sld:
        freq[ch] = freq.get(ch, 0) + 1

    total = len(sld)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)

    return round(entropy, 4)


def _extract_features(signals: dict[str, Any]) -> np.ndarray:
    """
    Extract feature vector from raw signals dictionary.

    Args:
        signals: Dict from collect_all_signals() or equivalent

    Returns:
        numpy array of shape (1, 11) matching FEATURE_COLUMNS
    """
    domain = signals.get("domain", "")

    # Unpack nested dicts
    dmarc = signals.get("dmarc", {}) or {}
    spf = signals.get("spf", {}) or {}
    dkim = signals.get("dkim", {}) or {}
    lookalike = signals.get("lookalike", {}) or {}

    has_dmarc = int(dmarc.get("has_dmarc", signals.get("has_dmarc", False)))
    has_spf = int(spf.get("has_spf", signals.get("has_spf", False)))
    has_dkim = int(dkim.get("has_dkim", signals.get("has_dkim", False)))
    is_lookalike = int(lookalike.get("is_lookalike", signals.get("is_lookalike", False)))
    lookalike_distance = int(lookalike.get("distance", signals.get("lookalike_distance", 999)))
    # Clip distance to reasonable range
    if lookalike_distance == 999:
        lookalike_distance = 10  # Unknown → use high value

    tld_risk = signals.get("tld_risk_score")
    if tld_risk is None:
        tld_risk = get_tld_risk_score(domain)

    domain_entropy = signals.get("domain_entropy")
    if domain_entropy is None:
        domain_entropy = compute_domain_entropy(domain)

    features = [
        float(signals.get("domain_age_days", -1)),
        float(has_dmarc),
        float(has_spf),
        float(has_dkim),
        float(int(signals.get("is_breached", False))),
        float(is_lookalike),
        float(lookalike_distance),
        float(int(signals.get("is_new_to_org", False))),
        float(tld_risk),
        float(int(signals.get("mx_valid", False))),
        float(domain_entropy),
    ]

    return np.array(features, dtype=np.float32).reshape(1, -1)


def _rule_based_score(signals: dict[str, Any]) -> float:
    """
    Rule-based fallback scorer when no ML model is available.

    Scoring logic:
    - Start at 0 (clean)
    - Add penalties for suspicious signals
    - Subtract bonuses for good hygiene

    Returns:
        Float score 0-100 (higher = more suspicious/malicious)
    """
    score = 20.0  # Baseline

    domain = signals.get("domain", "")
    domain_age = signals.get("domain_age_days", -1)
    dmarc = signals.get("dmarc", {}) or {}
    spf = signals.get("spf", {}) or {}
    dkim = signals.get("dkim", {}) or {}
    lookalike = signals.get("lookalike", {}) or {}

    has_dmarc = dmarc.get("has_dmarc", signals.get("has_dmarc", False))
    has_spf = spf.get("has_spf", signals.get("has_spf", False))
    has_dkim = dkim.get("has_dkim", signals.get("has_dkim", False))
    is_breached = signals.get("is_breached", False)
    mx_valid = signals.get("mx_valid", False)
    is_lookalike = lookalike.get("is_lookalike", signals.get("is_lookalike", False))
    lookalike_distance = lookalike.get("distance", signals.get("lookalike_distance", 999))
    is_new_to_org = signals.get("is_new_to_org", False)

    # Domain age penalties
    if domain_age == -1:
        score += 20  # Unknown age is suspicious
    elif domain_age < 30:
        score += 35  # Very new domain
    elif domain_age < 90:
        score += 20
    elif domain_age < 365:
        score += 10
    elif domain_age > 1825:  # 5+ years
        score -= 10

    # Email authentication bonuses/penalties
    if not has_dmarc:
        score += 10
    else:
        dmarc_policy = dmarc.get("policy", "")
        if dmarc_policy == "reject":
            score -= 10
        elif dmarc_policy == "quarantine":
            score -= 5

    if not has_spf:
        score += 8
    else:
        spf_qualifier = spf.get("qualifier", "~")
        if spf_qualifier == "-":
            score -= 8  # Hard fail is good
        elif spf_qualifier == "+":
            score += 5  # +all is actually bad

    if not has_dkim:
        score += 8
    else:
        score -= 5

    # MX record validation
    if not mx_valid:
        score += 15  # No valid MX is highly suspicious

    # Breach database
    if is_breached:
        score += 20

    # Lookalike domain detection
    if is_lookalike:
        score += 40
        if lookalike_distance == 1:
            score += 10  # Very close match
    elif lookalike_distance <= 2:
        score += 20

    # New sender penalty
    if is_new_to_org:
        score += 10

    # TLD risk score
    tld_risk = signals.get("tld_risk_score", get_tld_risk_score(domain))
    score += tld_risk * 30  # Scale TLD risk contribution

    # Domain entropy (DGA detection)
    domain_entropy = signals.get("domain_entropy", compute_domain_entropy(domain))
    if domain_entropy > 3.8:
        score += 20  # High entropy → likely DGA
    elif domain_entropy > 3.2:
        score += 10

    return max(0.0, min(100.0, score))


def score_sender(
    signals: dict[str, Any],
    model: Any | None = None,
    model_path: str | None = None,
) -> float:
    """
    Score a sender's domain reputation using XGBoost or rule-based fallback.

    Args:
        signals: Dict from collect_all_signals() containing domain signals
        model: Pre-loaded XGBoost model (optional)
        model_path: Path to pickled model file (optional, loaded if model=None)

    Returns:
        Reputation score 0-100 where:
        - 0-30: Trusted/legitimate sender
        - 31-60: Neutral/unknown
        - 61-100: Suspicious/malicious
    """
    # Try to load model from disk if not provided
    if model is None and model_path:
        try:
            with open(model_path, "rb") as f:
                model = pickle.load(f)
        except Exception as e:
            logger.warning(f"Could not load model from {model_path}: {e}")

    # Try default model path
    if model is None:
        default_path = Path(__file__).parent / "model.pkl"
        if default_path.exists():
            try:
                with open(default_path, "rb") as f:
                    model = pickle.load(f)
                logger.debug(f"Loaded sender reputation model from {default_path}")
            except Exception as e:
                logger.warning(f"Could not load default model: {e}")

    if model is not None:
        try:
            features = _extract_features(signals)
            # XGBoost returns probability of class 1 (malicious)
            prob_malicious = model.predict_proba(features)[0][1]
            score = float(prob_malicious * 100)
            return max(0.0, min(100.0, score))
        except Exception as e:
            logger.warning(f"Model inference failed, using rule-based fallback: {e}")

    # Fallback to rule-based scoring
    return _rule_based_score(signals)
