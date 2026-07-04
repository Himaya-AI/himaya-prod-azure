"""
Tests for Risk Orchestrator (MODEL-004)
Tests scoring, multipliers, action thresholds, compliance mappings, and full orchestration.
"""

from __future__ import annotations

import sys
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from models.shared.schemas import (
    ThreatClassification,
    RiskAction,
    EmailMetadata,
    EmailDirection,
    GraphAnalysisResult,
    ContentClassificationResult,
    SenderReputationResult,
    LookalikResult,
    EmailLanguage,
)


# ---------------------------------------------------------------------------
# Weighted Average Tests
# ---------------------------------------------------------------------------

class TestWeightedAverage:
    """Test the core weighted average calculation."""

    def _make_orchestrator(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator
        return RiskOrchestrator()

    def test_basic_weighted_average(self):
        """graph=50, content=80, reputation=60 → 50*0.3 + 80*0.4 + 60*0.3 = 15+32+18 = 65"""
        orch = self._make_orchestrator()
        score = orch.calculate_score(50, 80, 60, {})
        assert abs(score - 65.0) < 0.01, f"Expected ~65, got {score}"

    def test_all_zero_scores(self):
        orch = self._make_orchestrator()
        score = orch.calculate_score(0, 0, 0, {})
        assert score == 0.0

    def test_all_hundred_scores(self):
        orch = self._make_orchestrator()
        score = orch.calculate_score(100, 100, 100, {})
        assert score == 100.0

    def test_score_clamped_to_100(self):
        """With VIP multiplier on high scores, result should be clamped to 100."""
        orch = self._make_orchestrator()
        score = orch.calculate_score(90, 95, 90, {"vip_recipient": True})
        assert score == 100.0

    def test_score_clamped_to_zero(self):
        orch = self._make_orchestrator()
        score = orch.calculate_score(0, 0, 0, {})
        assert score == 0.0


# ---------------------------------------------------------------------------
# Multiplier Tests
# ---------------------------------------------------------------------------

class TestMultipliers:
    def _make_orchestrator(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator
        return RiskOrchestrator()

    def test_vip_multiplier_raises_score(self):
        orch = self._make_orchestrator()
        base = orch.calculate_score(50, 50, 50, {})
        vip = orch.calculate_score(50, 50, 50, {"vip_recipient": True})
        assert vip > base

    def test_vip_multiplier_value(self):
        """VIP multiplier = 1.5, so 50 * 1.5 = 75"""
        orch = self._make_orchestrator()
        score = orch.calculate_score(50, 50, 50, {"vip_recipient": True})
        assert abs(score - 75.0) < 0.1, f"Expected ~75, got {score}"

    def test_whitelist_bypass_returns_zero(self):
        """Whitelisted sender should always return score=0."""
        orch = self._make_orchestrator()
        score = orch.calculate_score(100, 100, 100, {"whitelisted_sender": True})
        assert score == 0.0

    def test_finance_dept_multiplier(self):
        orch = self._make_orchestrator()
        base = orch.calculate_score(60, 60, 60, {})
        finance = orch.calculate_score(60, 60, 60, {"finance_dept": True})
        assert finance > base

    def test_combined_multipliers(self):
        """Multiple active multipliers multiply together."""
        orch = self._make_orchestrator()
        # vip (1.5) * finance (1.3) = 1.95
        score = orch.calculate_score(40, 40, 40, {"vip_recipient": True, "finance_dept": True})
        base = orch.calculate_score(40, 40, 40, {})
        assert score > base * 1.8  # ~1.95x increase


# ---------------------------------------------------------------------------
# Action Threshold Tests
# ---------------------------------------------------------------------------

class TestActionThresholds:
    def _make_orchestrator(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator
        return RiskOrchestrator()

    def test_score_0_delivers(self):
        orch = self._make_orchestrator()
        assert orch.get_action(0) == RiskAction.DELIVER

    def test_score_30_delivers(self):
        orch = self._make_orchestrator()
        assert orch.get_action(30) == RiskAction.DELIVER

    def test_score_31_banner(self):
        orch = self._make_orchestrator()
        assert orch.get_action(31) == RiskAction.DELIVER_WITH_BANNER

    def test_score_50_banner(self):
        orch = self._make_orchestrator()
        assert orch.get_action(50) == RiskAction.DELIVER_WITH_BANNER

    def test_score_51_hold(self):
        orch = self._make_orchestrator()
        assert orch.get_action(51) == RiskAction.HOLD_FOR_REVIEW

    def test_score_70_hold(self):
        orch = self._make_orchestrator()
        assert orch.get_action(70) == RiskAction.HOLD_FOR_REVIEW

    def test_score_71_quarantine(self):
        orch = self._make_orchestrator()
        assert orch.get_action(71) == RiskAction.QUARANTINE

    def test_score_89_quarantine(self):
        orch = self._make_orchestrator()
        assert orch.get_action(89) == RiskAction.QUARANTINE

    def test_score_90_block(self):
        orch = self._make_orchestrator()
        assert orch.get_action(90) == RiskAction.BLOCK_DELETE

    def test_score_100_block(self):
        orch = self._make_orchestrator()
        assert orch.get_action(100) == RiskAction.BLOCK_DELETE

    def test_whitelist_action_is_deliver(self):
        """Whitelisted sender score=0 → DELIVER"""
        orch = self._make_orchestrator()
        score = orch.calculate_score(100, 100, 100, {"whitelisted_sender": True})
        action = orch.get_action(score)
        assert action == RiskAction.DELIVER


# ---------------------------------------------------------------------------
# Compliance Control Mapping Tests
# ---------------------------------------------------------------------------

class TestComplianceMappings:
    def _make_orchestrator(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator
        return RiskOrchestrator()

    def _get_control_ids(self, classification):
        from models.risk_orchestrator.action_engine import COMPLIANCE_CONTROLS
        mapping = COMPLIANCE_CONTROLS.get(classification, {})
        return mapping.get("sama_id"), mapping.get("nca_id")

    def test_bec_controls(self):
        sama, nca = self._get_control_ids(ThreatClassification.BEC)
        assert sama == "SAMA CSF 3.3.3"
        assert nca == "NCA ECC 2-7-3"

    def test_phishing_controls(self):
        sama, nca = self._get_control_ids(ThreatClassification.PHISHING)
        assert sama == "SAMA CSF 3.3.5"
        assert nca == "NCA ECC 2-7-1"

    def test_gov_impersonation_controls(self):
        sama, nca = self._get_control_ids(ThreatClassification.GOV_IMPERSONATION)
        assert sama == "SAMA CSF 3.3.5"
        assert nca == "NCA ECC 2-7-4"

    def test_malware_controls(self):
        sama, nca = self._get_control_ids(ThreatClassification.MALWARE)
        assert sama == "SAMA CSF 3.3.3"
        assert nca == "NCA ECC 2-7-5"

    def test_lookalike_controls(self):
        sama, nca = self._get_control_ids(ThreatClassification.LOOKALIKE_DOMAIN)
        assert sama == "SAMA CSF 3.3.5"
        assert nca == "NCA ECC 2-7-2"

    def test_account_takeover_controls(self):
        sama, nca = self._get_control_ids(ThreatClassification.ACCOUNT_TAKEOVER)
        assert sama == "SAMA CSF 3.4.1"
        assert nca == "NCA ECC 2-7-3"

    def test_supply_chain_controls(self):
        sama, nca = self._get_control_ids(ThreatClassification.SUPPLY_CHAIN)
        assert sama == "SAMA CSF 3.3.3"
        assert nca == "NCA ECC 2-7-5"

    def test_all_7_threat_types_have_mappings(self):
        from models.risk_orchestrator.action_engine import COMPLIANCE_CONTROLS
        threat_types = [
            ThreatClassification.BEC,
            ThreatClassification.PHISHING,
            ThreatClassification.GOV_IMPERSONATION,
            ThreatClassification.MALWARE,
            ThreatClassification.LOOKALIKE_DOMAIN,
            ThreatClassification.ACCOUNT_TAKEOVER,
            ThreatClassification.SUPPLY_CHAIN,
        ]
        for tt in threat_types:
            assert tt in COMPLIANCE_CONTROLS, f"Missing compliance mapping for {tt}"


# ---------------------------------------------------------------------------
# Full Orchestration Test
# ---------------------------------------------------------------------------

def _make_email_metadata() -> EmailMetadata:
    return EmailMetadata(
        message_id="test-msg-001",
        sender="ceo@evil-corp.xyz",
        recipient="finance@company.com",
        timestamp=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        subject_hash="abc123",
        direction=EmailDirection.INBOUND,
        org_id="org-001",
    )


def _make_graph_result(score: float = 75.0) -> GraphAnalysisResult:
    return GraphAnalysisResult(
        anomaly_score=score,
        edge_embedding=[0.1] * 64,
        is_anomalous=score >= 70,
        mahalanobis_distance=3.5,
        latency_ms=45.0,
    )


def _make_content_result(
    score: int = 85,
    classification: ThreatClassification = ThreatClassification.BEC,
) -> ContentClassificationResult:
    return ContentClassificationResult(
        threat_indicators=["urgency", "wire_transfer"],
        urgency_score=score,
        impersonation_detected=True,
        impersonation_target="CEO",
        language=EmailLanguage.EN,
        classification=classification,
        confidence=0.92,
        explanation_ar="هذا بريد إلكتروني احتيالي",
        explanation_en="This is a BEC attack",
    )


def _make_reputation_result(score: float = 70.0) -> SenderReputationResult:
    return SenderReputationResult(
        domain="evil-corp.xyz",
        email="ceo@evil-corp.xyz",
        domain_age_days=15,
        has_dmarc=False,
        has_spf=False,
        has_dkim=False,
        is_breached=True,
        mx_valid=False,
        lookalike=LookalikResult(is_lookalike=True, matched_domain="aramco.com", distance=2),
        is_new_to_org=True,
        tld_risk_score=0.8,
        domain_entropy=3.7,
        final_score=score,
        malicious_probability=score / 100.0,
    )


class TestFullOrchestration:

    @pytest.mark.asyncio
    async def test_full_orchestrate_returns_dict(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator

        orch = RiskOrchestrator()
        result = await orch.orchestrate(
            email_metadata=_make_email_metadata(),
            graph_result=_make_graph_result(75),
            content_result=_make_content_result(85),
            reputation_result=_make_reputation_result(70),
            context={"finance_dept": True},
        )

        assert isinstance(result, dict)
        assert "final_score" in result
        assert "action" in result
        assert "threat_classification" in result
        assert "compliance_controls" in result
        assert 0.0 <= result["final_score"] <= 100.0

    @pytest.mark.asyncio
    async def test_orchestrate_high_risk_leads_to_quarantine_or_block(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator

        orch = RiskOrchestrator()
        result = await orch.orchestrate(
            email_metadata=_make_email_metadata(),
            graph_result=_make_graph_result(90),
            content_result=_make_content_result(95),
            reputation_result=_make_reputation_result(85),
            context={},
        )
        assert result["action"] in (RiskAction.QUARANTINE.value, RiskAction.BLOCK_DELETE.value)

    @pytest.mark.asyncio
    async def test_orchestrate_low_risk_delivers(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator

        orch = RiskOrchestrator()
        # Clean email from trusted sender
        content = _make_content_result(5, ThreatClassification.BENIGN)
        content.impersonation_detected = False
        result = await orch.orchestrate(
            email_metadata=_make_email_metadata(),
            graph_result=_make_graph_result(10),
            content_result=content,
            reputation_result=_make_reputation_result(5),
            context={},
        )
        assert result["action"] == RiskAction.DELIVER.value

    @pytest.mark.asyncio
    async def test_whitelist_context_always_delivers(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator

        orch = RiskOrchestrator()
        result = await orch.orchestrate(
            email_metadata=_make_email_metadata(),
            graph_result=_make_graph_result(99),
            content_result=_make_content_result(99),
            reputation_result=_make_reputation_result(99),
            context={"whitelisted_sender": True},
        )
        assert result["action"] == RiskAction.DELIVER.value
        assert result["final_score"] == 0.0


# ---------------------------------------------------------------------------
# Action Record Tests
# ---------------------------------------------------------------------------

class TestActionRecord:

    def test_generate_action_record_keys(self):
        from models.risk_orchestrator.orchestrator import RiskOrchestrator
        from models.risk_orchestrator.action_engine import generate_action_record
        import asyncio

        orch = RiskOrchestrator()
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            orch.orchestrate(
                email_metadata=_make_email_metadata(),
                graph_result=_make_graph_result(80),
                content_result=_make_content_result(85),
                reputation_result=_make_reputation_result(75),
                context={},
            )
        )
        loop.close()

        record = generate_action_record(result, _make_email_metadata(), "org-001")

        required_keys = [
            "record_id", "evidence_id", "org_id", "message_id",
            "sender", "recipient", "final_score", "action",
            "threat_classification", "sama_controls", "nca_controls",
        ]
        for key in required_keys:
            assert key in record, f"Missing key: {key}"

    def test_generate_action_record_compliance_bec(self):
        from models.risk_orchestrator.action_engine import generate_action_record

        mock_result = {
            "evidence_id": "ev-001",
            "final_score": 85.0,
            "action": "QUARANTINE",
            "threat_classification": "BEC",
            "confidence": 0.9,
            "agent_scores": {"graph_score": 80, "content_score": 90, "reputation_score": 75},
            "weighted_scores": {},
            "multipliers_applied": {},
            "processing_time_ms": 120.0,
        }

        record = generate_action_record(mock_result, _make_email_metadata(), "org-001")
        assert "SAMA CSF 3.3.3" in record["sama_controls"]
        assert "NCA ECC 2-7-3" in record["nca_controls"]
