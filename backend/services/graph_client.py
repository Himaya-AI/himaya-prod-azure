"""
HTTP client for the Helios graph-service microservice.
Drop-in replacement for graph_service.py — same method signatures,
calls the graph microservice instead of Neo4j directly.
"""
from __future__ import annotations

import logging
import os

import httpx

logger = logging.getLogger(__name__)

_GRAPH_SERVICE_URL     = os.getenv("GRAPH_SERVICE_URL", "http://graph-service:8000")
_GRAPH_SERVICE_TIMEOUT = float(os.getenv("GRAPH_SERVICE_TIMEOUT", "10"))


class GraphClient:

    # ── Health ────────────────────────────────────────────────────────────────

    async def health(self) -> dict:
        """
        Call GET /health on the graph microservice.
        Returns the raw response dict, or {"status": "unreachable"} on failure.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{_GRAPH_SERVICE_URL}/graph/health")
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.warning("graph-service /health failed (%s: %s)", type(exc).__name__, exc)
            return {"status": "unreachable", "error": str(exc)}

    # ── Evaluate (replaces analyze_sender_relationship) ───────────────────────

    async def evaluate(
        self,
        sender: str,
        recipient: str,
        org_id: str,
        reputation_hint: dict | None = None,
    ) -> dict:
        """
        Call POST /evaluate on the graph microservice.
        Returns the full response: sender, domain, relationship, intel, trust sections.
        Falls back to safe defaults if the service is unreachable.
        """
        try:
            payload: dict = {"sender": sender, "recipient": recipient, "org_id": org_id}
            if reputation_hint:
                payload["reputation_hint"] = reputation_hint
            async with httpx.AsyncClient(timeout=_GRAPH_SERVICE_TIMEOUT) as client:
                resp = await client.post(f"{_GRAPH_SERVICE_URL}/graph/evaluate", json=payload)
                resp.raise_for_status()
                return resp.json()
        except Exception as exc:
            logger.warning("graph-service /evaluate failed (%s: %s) — returning defaults", type(exc).__name__, exc)
            return _evaluate_defaults()

    # ── Write (replaces record_communication) ─────────────────────────────────

    async def write(self, data: dict) -> None:
        """
        Call POST /write on the graph microservice (fire-and-forget, 202).
        Non-fatal — logs on failure but never raises.
        """
        try:
            async with httpx.AsyncClient(timeout=_GRAPH_SERVICE_TIMEOUT) as client:
                resp = await client.post(
                    f"{_GRAPH_SERVICE_URL}/graph/write",
                    json=data,
                )
                resp.raise_for_status()
        except Exception as exc:
            logger.debug("graph-service /write failed (non-fatal): %s: %s", type(exc).__name__, exc)

    # ── Retract (replaces retract_threat) ─────────────────────────────────────

    async def retract(
        self,
        sender: str,
        threat_type: str | None = None,
    ) -> None:
        """
        Call DELETE /retract on the graph microservice.
        Removes FLAGGED_AS edges — called on false positive reports.
        """
        try:
            async with httpx.AsyncClient(timeout=_GRAPH_SERVICE_TIMEOUT) as client:
                resp = await client.request(
                    "DELETE",
                    f"{_GRAPH_SERVICE_URL}/graph/retract",
                    json={"sender": sender, "threat_type": threat_type},
                )
                resp.raise_for_status()
        except Exception as exc:
            logger.debug("graph-service /retract failed (non-fatal): %s: %s", type(exc).__name__, exc)

    # ── Report signal (replaces record_report_signal) ─────────────────────────

    async def record_report_signal(
        self,
        org_id: str,
        sender: str,
        reporter: str,
        label: str,
        threat_id: str,
    ) -> None:
        """Stub — report signal endpoint not yet implemented in graph-service."""
        logger.debug("record_report_signal: not yet routed to graph-service (skipped)")


# ── Defaults ──────────────────────────────────────────────────────────────────

def _evaluate_defaults() -> dict:
    """Safe fallback when graph-service is unreachable."""
    return {
        "sender": {
            "email_count":             0,
            "threat_count":            0,
            "reputation_score":        0,
            "first_seen":              None,
            "historical_threat_types": [],
        },
        "domain": {
            "total_emails":            0,
            "flagged_emails":          0,
            "flagged_email_rate":      0.0,
            "total_senders":           0,
            "flagged_senders":         0,
            "orgs_targeted":           0,
            "threat_score":            0,
            "first_seen":              None,
            "last_seen":               None,
            "associated_threat_types": [],
        },
        "relationship": {
            "prior_emails_to_recipient": 0,
            "last_contact":              None,
        },
        "intel": {
            "reported_by_other_orgs": 0,
            "similar_threat_senders": [],
        },
        "trust": {
            "trust_score":   0,
            "trust_method":  "fallback",
            "reasoning":     "graph-service unreachable",
            "domain_spread": 0,
        },
    }


graph_client = GraphClient()
