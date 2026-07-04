from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_MEDIUM_THREAT_TYPES = {"PHISHING", "SPOOFING"}


class TrustScorer:
    def __init__(self) -> None:
        pass

    # ── Public ────────────────────────────────────────────────────────────────

    def evaluate(self, graph_data: dict) -> dict:
        sender  = graph_data.get("sender", {})
        domain  = graph_data.get("domain", {})
        rel     = graph_data.get("relationship", {})
        intel   = graph_data.get("intel", {})

        email_count            = int(sender.get("email_count", 0))
        threat_count           = int(sender.get("threat_count", 0))
        historical_threat_types: list[str] = sender.get("historical_threat_types", [])

        domain_total_emails   = int(domain.get("total_emails", 0))
        domain_flagged_emails = int(domain.get("flagged_emails", 0))
        domain_spread         = int(domain.get("total_senders", 0))
        orgs_targeted         = int(domain.get("orgs_targeted", 0))

        prior_emails         = int(rel.get("prior_emails_to_recipient", 0))
 
        reported_by_other_orgs = int(intel.get("reported_by_other_orgs", 0))
        similar_threat_senders = intel.get("similar_threat_senders", [])

        indicators = _build_indicators(graph_data)

        logger.debug(
            "trust_scorer.evaluate | sender_emails=%d threats=%d domain_spread=%d orgs_targeted=%d prior=%d",
            email_count, threat_count, domain_spread, orgs_targeted, prior_emails,
        )

        # ── Hard disqualifiers — block immediately, no score ──────────────────
        if reported_by_other_orgs > 0:
            logger.info("trust_scorer | block: reported_by_other_orgs=%d", reported_by_other_orgs)
            return self._verdict(0, "block", f"Reported by {reported_by_other_orgs} other org(s)", domain_spread, indicators)

        # ── Similar-threat penalty — scaled, not a hard block ─────────────────
        # Penalty: -25 for one match, +5 per additional, capped at -40.
        similar_penalty = 0
        if similar_threat_senders:
            similar_penalty = min(25 + (len(similar_threat_senders) - 1) * 5, 40)

        # Hoist flagged_rate — needed for domain-aware insufficient_history below
        flagged_rate = domain_flagged_emails / domain_total_emails if domain_total_emails > 0 else None

        # ── Insufficient history — can't score yet ────────────────────────────
        if email_count < 5:
            logger.debug("trust_scorer | insufficient_history email_count=%d", email_count)
            domain_trusted = (
                flagged_rate is not None
                and flagged_rate == 0
                and domain_spread <= 2
                and orgs_targeted <= 1
            )
            neutral = 55 if domain_trusted else 45
            adjusted = max(0, neutral - similar_penalty)
            reason = (
                f"Only {email_count} email(s) observed — "
                + ("domain appears clean" if domain_trusted else "not enough history")
                + (f", similar threat profile (-{similar_penalty})" if similar_penalty else "")
            )
            return self._verdict(adjusted, "insufficient_history", reason, domain_spread, indicators)

        # ── Score ─────────────────────────────────────────────────────────────
        score = 0

        # Sender volume
        if email_count > 50:
            score += 20
        elif email_count >= 10:
            score += 10

        # Sender threat rate
        threat_rate = threat_count / email_count
        if threat_rate == 0:
            score += 15
        elif threat_rate <= 0.10:
            score -= 15

        # Threat type severity
        if any(t in _MEDIUM_THREAT_TYPES for t in historical_threat_types):
            score -= 25

        # Similar-threat profile penalty (applied after positives so partial recovery is visible)
        if similar_penalty:
            score -= similar_penalty

        # Relationship with this recipient
        if prior_emails > 5:
            score += 15
        elif prior_emails >= 1:
            score += 8

        # Domain flagged rate
        effective_flagged_rate = flagged_rate if flagged_rate is not None else 0
        if effective_flagged_rate == 0:
            score += 20
        elif effective_flagged_rate < 0.001:
            score += 15
        elif effective_flagged_rate < 0.01:
            score += 5
        else:
            score -= 20

        # Domain spread — many senders or orgs targeted signals a shared/abused domain
        if domain_spread > 10 or orgs_targeted > 5:
            score -= 20
        elif domain_spread > 5 or orgs_targeted > 2:
            score -= 10

        score = max(0, min(100, score))

        reason = f"Score {score}/100"
        if similar_penalty:
            reason += f", similar threat profile (-{similar_penalty})"

        return self._verdict(score, "deterministic", reason, domain_spread, indicators)

    # ── Private ───────────────────────────────────────────────────────────────

    @staticmethod
    def _verdict(score: int, method: str, reasoning: str, domain_spread: int, indicators: list) -> dict:
        return {
            "trust_score":   score,
            "trust_method":  method,
            "reasoning":     reasoning,
            "domain_spread": domain_spread,
            "indicators":    indicators,
        }


# ── Indicator builder ─────────────────────────────────────────────────────────

def _build_indicators(graph_data: dict) -> list[str]:
    sender  = graph_data.get("sender", {})
    domain  = graph_data.get("domain", {})
    intel   = graph_data.get("intel", {})

    email_count    = int(sender.get("email_count", 0))
    threat_types   = sender.get("historical_threat_types", [])
    total_senders  = int(domain.get("total_senders", 0))
    indicators: list[str] = []

    # Sender history
    if email_count == 0:
        indicators.append("first_time_sender")
    elif email_count < 3:
        indicators.append("infrequent_sender")

    # Known threat types on this sender
    for t in threat_types[:3]:
        indicators.append(f"known_threat_type:{t}")

    orgs_targeted = int(domain.get("orgs_targeted", 0))

    # Domain spread
    if total_senders > 10 or orgs_targeted > 5:
        indicators.append(f"domain_wide_campaign:{total_senders}_senders_{orgs_targeted}_orgs")
    elif total_senders > 5 or orgs_targeted > 2:
        indicators.append(f"domain_multi_sender:{total_senders}_senders_{orgs_targeted}_orgs")

    # Cross-org intel
    reported = int(intel.get("reported_by_other_orgs", 0))
    if reported > 0:
        indicators.append(f"reported_by_other_orgs:{reported}")

    similar = intel.get("similar_threat_senders", [])
    if similar:
        indicators.append(f"similar_threat_senders:{len(similar)}")

    return indicators
