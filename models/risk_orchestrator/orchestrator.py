"""
Himaya Helios - MODEL-004: Risk Orchestrator
Weighted ensemble combining graph, content, and reputation scores into a final risk decision.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from models.shared.schemas import (
    RiskAction,
    RiskOrchestratorResult,
    ThreatClassification,
    ComplianceControl,
    GraphAnalysisResult,
    ContentClassificationResult,
    SenderReputationResult,
    EmailMetadata,
)

logger = logging.getLogger(__name__)


class RiskOrchestrator:
    """
    Weighted ensemble risk orchestrator for Himaya Helios.

    Combines scores from three AI models:
    - Communication Graph Analyzer (GraphSAGE GNN): 30%
    - Content Classifier (Claude/GPT-4o): 40%
    - Sender Reputation Engine (XGBoost): 30%

    Applies contextual multipliers and maps to action decisions.
    """

    # Model weight configuration
    WEIGHTS: dict[str, float] = {
        "graph_score": 0.30,
        "content_score": 0.40,
        "reputation_score": 0.30,
    }

    # Contextual score multipliers
    MULTIPLIERS: dict[str, float] = {
        "vip_recipient": 1.5,        # Executive / board member
        "finance_dept": 1.3,          # Finance / treasury team
        "whitelisted_sender": 0.0,    # Fully trusted sender → always deliver
        "new_sender": 1.2,            # First-time sender to org
        "exec_impersonation": 1.4,    # Detected executive impersonation
    }

    # Action thresholds
    ACTION_THRESHOLDS = [
        (0, 30, RiskAction.DELIVER),
        (31, 50, RiskAction.DELIVER_WITH_BANNER),
        (51, 70, RiskAction.HOLD_FOR_REVIEW),
        (71, 89, RiskAction.QUARANTINE),
        (90, 100, RiskAction.BLOCK_DELETE),
    ]

    def calculate_score(
        self,
        graph_score: float,
        content_score: float,
        reputation_score: float,
        context: dict[str, Any],
    ) -> float:
        """
        Compute the final risk score using weighted average + contextual multipliers.

        Args:
            graph_score: Score from Graph Analyzer (0-100)
            content_score: Score from Content Classifier (0-100)
            reputation_score: Score from Sender Reputation Engine (0-100)
            context: Dict of contextual flags (see MULTIPLIERS)

        Returns:
            Final risk score clamped to [0, 100]
        """
        # Weighted average
        weighted = (
            graph_score * self.WEIGHTS["graph_score"]
            + content_score * self.WEIGHTS["content_score"]
            + reputation_score * self.WEIGHTS["reputation_score"]
        )

        # Whitelisted sender: bypass all scoring
        if context.get("whitelisted_sender"):
            return 0.0

        # Apply all active multipliers (multiplicative)
        multiplier = 1.0
        for flag, factor in self.MULTIPLIERS.items():
            if flag == "whitelisted_sender":
                continue
            if context.get(flag):
                multiplier *= factor

        score = weighted * multiplier
        return max(0.0, min(100.0, score))

    def get_action(self, score: float) -> RiskAction:
        """
        Map a risk score to an action decision.

        Thresholds:
        - 0-30:   DELIVER
        - 31-50:  DELIVER_WITH_BANNER
        - 51-70:  HOLD_FOR_REVIEW
        - 71-89:  QUARANTINE
        - 90-100: BLOCK_DELETE

        Args:
            score: Final risk score (0-100)

        Returns:
            RiskAction enum value
        """
        for low, high, action in self.ACTION_THRESHOLDS:
            if low <= score <= high:
                return action
        # Fallback (shouldn't happen if score is clamped)
        return RiskAction.BLOCK_DELETE

    def _get_compliance_controls(
        self, classification: ThreatClassification
    ) -> list[ComplianceControl]:
        """
        Map threat classification to SAMA/NCA regulatory control references.

        Args:
            classification: Detected threat type

        Returns:
            List of ComplianceControl objects
        """
        CONTROL_MAP: dict[ThreatClassification, tuple[str, str, str, str]] = {
            ThreatClassification.BEC: (
                "SAMA CSF 3.3.3",
                "NCA ECC 2-7-3",
                "Business Email Compromise Controls",
                "Controls for detecting and preventing BEC/wire fraud attacks",
            ),
            ThreatClassification.PHISHING: (
                "SAMA CSF 3.3.5",
                "NCA ECC 2-7-1",
                "Anti-Phishing Controls",
                "Email phishing detection and user awareness controls",
            ),
            ThreatClassification.GOV_IMPERSONATION: (
                "SAMA CSF 3.3.5",
                "NCA ECC 2-7-4",
                "Government Entity Impersonation",
                "Controls preventing impersonation of government authorities",
            ),
            ThreatClassification.MALWARE: (
                "SAMA CSF 3.3.3",
                "NCA ECC 2-7-5",
                "Malware Prevention Controls",
                "Email-borne malware detection and prevention",
            ),
            ThreatClassification.LOOKALIKE_DOMAIN: (
                "SAMA CSF 3.3.5",
                "NCA ECC 2-7-2",
                "Domain Spoofing Controls",
                "Detection of lookalike/typosquatting domains",
            ),
            ThreatClassification.ACCOUNT_TAKEOVER: (
                "SAMA CSF 3.4.1",
                "NCA ECC 2-7-3",
                "Account Takeover Prevention",
                "Controls for detecting compromised account activity",
            ),
            ThreatClassification.SUPPLY_CHAIN: (
                "SAMA CSF 3.3.3",
                "NCA ECC 2-7-5",
                "Supply Chain Security",
                "Third-party and vendor email fraud controls",
            ),
        }

        if classification not in CONTROL_MAP:
            return []

        sama_id, nca_id, name, desc = CONTROL_MAP[classification]
        return [
            ComplianceControl(
                framework="SAMA",
                control_id=sama_id,
                control_name=name,
                description=desc,
            ),
            ComplianceControl(
                framework="NCA",
                control_id=nca_id,
                control_name=name,
                description=desc,
            ),
        ]

    def _determine_classification(
        self,
        content_result: ContentClassificationResult | None,
        reputation_score: float,
        context: dict[str, Any],
    ) -> ThreatClassification:
        """Determine final threat classification from agent results."""
        if content_result and content_result.classification not in (
            ThreatClassification.BENIGN,
            ThreatClassification.UNCERTAIN,
        ):
            return content_result.classification

        if reputation_score > 70:
            if context.get("exec_impersonation"):
                return ThreatClassification.BEC
            return ThreatClassification.PHISHING

        if content_result:
            return content_result.classification

        return ThreatClassification.UNCERTAIN

    async def orchestrate(
        self,
        email_metadata: EmailMetadata,
        graph_result: GraphAnalysisResult,
        content_result: ContentClassificationResult,
        reputation_result: SenderReputationResult,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Full orchestration: combine model outputs into a complete risk decision.

        Args:
            email_metadata: Raw email metadata
            graph_result: Output from Graph Analyzer
            content_result: Output from Content Classifier
            reputation_result: Output from Sender Reputation Engine
            context: Contextual flags dict (vip_recipient, finance_dept, etc.)

        Returns:
            Complete result dict with score, action, compliance controls, and all sub-results
        """
        t0 = time.time()

        graph_score = float(graph_result.anomaly_score)
        content_score = float(content_result.urgency_score)
        reputation_score = float(reputation_result.final_score)

        # Handle exec impersonation signal from content classifier
        if content_result.impersonation_detected:
            context = {**context, "exec_impersonation": True}

        final_score = self.calculate_score(
            graph_score, content_score, reputation_score, context
        )
        action = self.get_action(final_score)

        # Determine threat classification
        classification = self._determine_classification(
            content_result, reputation_score, context
        )

        # Get compliance controls
        controls = self._get_compliance_controls(classification)

        # Track applied multipliers
        applied_multipliers = {}
        if context.get("whitelisted_sender"):
            applied_multipliers["whitelisted_sender"] = self.MULTIPLIERS["whitelisted_sender"]
        else:
            for flag, factor in self.MULTIPLIERS.items():
                if flag != "whitelisted_sender" and context.get(flag):
                    applied_multipliers[flag] = factor

        processing_ms = (time.time() - t0) * 1000

        evidence_id = str(uuid.uuid4())

        orchestrator_result = RiskOrchestratorResult(
            final_score=final_score,
            action=action,
            multipliers_applied=applied_multipliers,
            agent_scores={
                "graph_score": graph_score,
                "content_score": content_score,
                "reputation_score": reputation_score,
            },
            weighted_scores={
                "graph_weighted": graph_score * self.WEIGHTS["graph_score"],
                "content_weighted": content_score * self.WEIGHTS["content_score"],
                "reputation_weighted": reputation_score * self.WEIGHTS["reputation_score"],
            },
            compliance_controls=controls,
            evidence_id=evidence_id,
            threat_classification=classification,
            processing_time_ms=round(processing_ms, 2),
        )

        return {
            "evidence_id": evidence_id,
            "final_score": final_score,
            "action": action.value,
            "threat_classification": classification.value,
            "confidence": float(content_result.confidence),
            "compliance_controls": [c.model_dump() for c in controls],
            "agent_scores": {
                "graph_score": graph_score,
                "content_score": content_score,
                "reputation_score": reputation_score,
            },
            "weighted_scores": orchestrator_result.weighted_scores,
            "multipliers_applied": applied_multipliers,
            "email_metadata": email_metadata.model_dump(),
            "content_result": content_result.model_dump(),
            "reputation_result": reputation_result.model_dump(),
            "graph_result": graph_result.model_dump(),
            "orchestrator_result": orchestrator_result.model_dump(),
            "processing_time_ms": round(processing_ms, 2),
        }
