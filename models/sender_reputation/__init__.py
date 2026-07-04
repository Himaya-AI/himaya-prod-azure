"""
Himaya Helios - Sender Reputation Engine (MODEL-003)
XGBoost-based domain reputation scoring with async signal collection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from models.shared.schemas import SenderReputationResult, LookalikResult

from .classifier import score_sender, get_tld_risk_score, compute_domain_entropy
from .lookalike import detect_lookalike, PROTECTED_DOMAINS
from .signals import collect_all_signals

logger = logging.getLogger(__name__)

__all__ = [
    "SenderReputationEngine",
    "score_sender",
    "get_tld_risk_score",
    "compute_domain_entropy",
    "detect_lookalike",
    "PROTECTED_DOMAINS",
    "collect_all_signals",
]


class SenderReputationEngine:
    """
    Main entry point for the Sender Reputation Engine.

    Orchestrates async signal collection, lookalike detection,
    and XGBoost scoring into a single SenderReputationResult.

    Usage:
        engine = SenderReputationEngine()
        result = await engine.analyze(domain="example.com", email="user@example.com")
        print(result.final_score)
    """

    def __init__(
        self,
        model: Any | None = None,
        hibp_api_key: str | None = None,
        protected_domains: list[str] | None = None,
    ) -> None:
        """
        Initialize the engine.

        Args:
            model: Pre-loaded XGBoost model (optional, loaded from disk if available)
            hibp_api_key: Have I Been Pwned API key
            protected_domains: Custom list of protected domains (defaults to Gulf domains)
        """
        self.model = model
        self.hibp_api_key = hibp_api_key
        self.protected_domains = protected_domains or PROTECTED_DOMAINS

    async def analyze(
        self,
        domain: str,
        email: str,
        is_new_to_org: bool = False,
        context: dict[str, Any] | None = None,
    ) -> SenderReputationResult:
        """
        Perform full sender reputation analysis.

        Args:
            domain: Sender domain
            email: Full sender email address
            is_new_to_org: Whether this sender is new to the organization
            context: Additional context dict (unused, reserved for future use)

        Returns:
            SenderReputationResult with all signals and final score
        """
        t0 = time.time()

        # Collect signals in parallel
        signals = await collect_all_signals(
            domain=domain,
            email=email,
            hibp_api_key=self.hibp_api_key,
        )

        # Lookalike detection
        is_lookalike, matched_domain, distance = detect_lookalike(
            domain, self.protected_domains
        )

        lookalike_result = LookalikResult(
            is_lookalike=is_lookalike,
            matched_domain=matched_domain,
            distance=distance,
            confidence="high" if distance <= 1 else "medium" if distance <= 2 else "none",
            homoglyph_detected=False,
        )

        # Enrich signals dict for scoring
        tld_risk = get_tld_risk_score(domain)
        domain_entropy = compute_domain_entropy(domain)

        signals["is_new_to_org"] = is_new_to_org
        signals["is_lookalike"] = is_lookalike
        signals["lookalike_distance"] = distance
        signals["tld_risk_score"] = tld_risk
        signals["domain_entropy"] = domain_entropy

        # Score
        final_score = score_sender(signals, model=self.model)
        malicious_prob = final_score / 100.0

        # Extract nested values
        dmarc_data = signals.get("dmarc", {}) or {}
        spf_data = signals.get("spf", {}) or {}
        dkim_data = signals.get("dkim", {}) or {}

        latency_ms = (time.time() - t0) * 1000

        return SenderReputationResult(
            domain=domain,
            email=email,
            domain_age_days=signals.get("domain_age_days", -1),
            has_dmarc=dmarc_data.get("has_dmarc", False),
            dmarc=None,
            has_spf=spf_data.get("has_spf", False),
            spf=None,
            has_dkim=dkim_data.get("has_dkim", False),
            dkim=None,
            is_breached=signals.get("is_breached", False),
            mx_valid=signals.get("mx_valid", False),
            lookalike=lookalike_result,
            is_new_to_org=is_new_to_org,
            tld_risk_score=tld_risk,
            domain_entropy=domain_entropy,
            final_score=final_score,
            malicious_probability=malicious_prob,
            signals_breakdown=signals,
            latency_ms=round(latency_ms, 2),
            cached=False,
        )

    def analyze_sync(
        self,
        domain: str,
        email: str,
        is_new_to_org: bool = False,
    ) -> SenderReputationResult:
        """Synchronous wrapper for analyze()."""
        return asyncio.run(self.analyze(domain, email, is_new_to_org))
