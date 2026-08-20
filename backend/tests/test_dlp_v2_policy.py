from __future__ import annotations

from backend.dlp.domain import (
    ClassificationOutcome,
    Finding,
    TenantMode,
)
from backend.dlp.extraction import ExtractionLimitation
from backend.dlp.policy import (
    MessageContext,
    PolicyAction,
    PolicyEvaluator,
    PolicyRule,
    PolicySet,
    RuleConditions,
    build_default_policy,
)


def _classification(
    findings: tuple[Finding, ...] = (),
    *,
    llm: str = "NOT_SENSITIVE",
    detector_errors: tuple[str, ...] = (),
) -> ClassificationOutcome:
    return ClassificationOutcome(
        findings=findings,
        llm_classification=llm,
        llm_confidence=0.9,
        llm_categories=(),
        llm_reasoning="test",
        detector_errors=detector_errors,
    )


def _context(*recipients: str) -> MessageContext:
    return MessageContext(
        sender="alice@example.test",
        recipients=recipients,
        tenant_domains=frozenset({"example.test"}),
    )


def _credit_card() -> Finding:
    return Finding(
        detector="pii",
        entity_type="CREDIT_CARD",
        confidence=0.97,
        start=10,
        end=29,
        metadata={"masked": "xxxxxxxxxxxx1111"},
    )


def test_high_confidence_credit_card_to_external_recipient_stops() -> None:
    decision = PolicyEvaluator().evaluate(
        policy=build_default_policy(),
        classification=_classification((_credit_card(),)),
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.intended_action == PolicyAction.STOP
    assert decision.effective_action == PolicyAction.STOP
    assert (
        decision.matched_rule_ids[0]
        == "builtin.financial-identity.external"
    )
    assert decision.finding_references[0].entity_type == "CREDIT_CARD"
    assert "1111" not in decision.explanation


def test_same_finding_to_internal_recipient_uses_default_allow() -> None:
    decision = PolicyEvaluator().evaluate(
        policy=build_default_policy(),
        classification=_classification((_credit_card(),)),
        limitations=(),
        context=_context("bob@example.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.intended_action == PolicyAction.ALLOW
    assert decision.matched_rule_ids == ()


def test_monitor_mode_records_intended_stop_but_allows() -> None:
    decision = PolicyEvaluator().evaluate(
        policy=build_default_policy(),
        classification=_classification((_credit_card(),)),
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.MONITOR,
    )

    assert decision.intended_action == PolicyAction.STOP
    assert decision.effective_action == PolicyAction.ALLOW
    assert "Monitor mode" in decision.explanation


def test_fatal_extraction_limitation_holds() -> None:
    decision = PolicyEvaluator().evaluate(
        policy=build_default_policy(),
        classification=_classification(),
        limitations=(
            ExtractionLimitation(
                code="encrypted_content",
                detail="encrypted",
                fatal=True,
            ),
        ),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.effective_action == PolicyAction.HOLD
    assert (
        "system.extraction_incomplete"
        in decision.matched_rule_ids
    )


def test_high_risk_uninspected_attachment_holds() -> None:
    decision = PolicyEvaluator().evaluate(
        policy=build_default_policy(),
        classification=_classification(),
        limitations=(
            ExtractionLimitation(
                code="unsupported_content_type",
                detail="No extractor for application/x-custom",
                filename="sample.custom",
                fatal=True,
            ),
        ),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.effective_action == PolicyAction.HOLD
    assert "system.extraction_incomplete" in decision.matched_rule_ids


def test_detector_error_is_not_treated_as_clean() -> None:
    decision = PolicyEvaluator().evaluate(
        policy=build_default_policy(),
        classification=_classification(
            detector_errors=("credential: timeout",)
        ),
        limitations=(),
        context=_context("bob@example.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.effective_action == PolicyAction.HOLD
    assert "system.detector_error" in decision.matched_rule_ids


def test_highest_severity_wins_before_priority() -> None:
    policy = PolicySet(
        version="test-v1",
        rules=(
            PolicyRule(
                rule_id="hold-first",
                name="Hold",
                action=PolicyAction.HOLD,
                priority=1,
                conditions=RuleConditions(
                    entity_types=frozenset({"credit_card"})
                ),
            ),
            PolicyRule(
                rule_id="stop-later",
                name="Stop",
                action=PolicyAction.STOP,
                priority=999,
                conditions=RuleConditions(
                    entity_types=frozenset({"credit_card"})
                ),
            ),
        ),
    )

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        classification=_classification((_credit_card(),)),
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.intended_action == PolicyAction.STOP
    assert decision.matched_rule_ids == ("stop-later", "hold-first")


def test_disabled_tenant_never_enforces() -> None:
    decision = PolicyEvaluator().evaluate(
        policy=build_default_policy(),
        classification=_classification((_credit_card(),)),
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
        enabled=False,
    )

    assert decision.intended_action == PolicyAction.STOP
    assert decision.effective_action == PolicyAction.ALLOW


def test_enabled_blank_external_only_rule_matches_without_findings() -> None:
    policy = PolicySet(
        version="test-blank",
        rules=(
            PolicyRule(
                rule_id="blank.external",
                name="Blank external hold",
                action=PolicyAction.HOLD,
                priority=100,
                conditions=RuleConditions(external_recipients_only=True),
            ),
        ),
    )

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        classification=_classification(),
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.effective_action == PolicyAction.HOLD
    assert decision.matched_rule_ids == ("blank.external",)


def test_disabled_blank_external_only_rule_does_not_match() -> None:
    policy = PolicySet(
        version="test-blank-disabled",
        rules=(
            PolicyRule(
                rule_id="blank.external",
                name="Blank external hold",
                action=PolicyAction.HOLD,
                priority=100,
                enabled=False,
                conditions=RuleConditions(external_recipients_only=True),
            ),
        ),
    )

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        classification=_classification(),
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.matched_rule_ids == ()
    assert decision.effective_action == PolicyAction.ALLOW


def test_match_all_rule_matches_without_findings() -> None:
    policy = PolicySet(
        version="test-match-all",
        rules=(
            PolicyRule(
                rule_id="catch.all",
                name="Catch all hold",
                action=PolicyAction.HOLD,
                priority=100,
                conditions=RuleConditions(
                    match_all=True,
                    external_recipients_only=True,
                ),
            ),
        ),
    )

    decision = PolicyEvaluator().evaluate(
        policy=policy,
        classification=_classification(),
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )

    assert decision.effective_action == PolicyAction.HOLD
    assert decision.matched_rule_ids == ("catch.all",)


def test_min_llm_confidence_filters_low_confidence_llm_match() -> None:
    policy = PolicySet(
        version="test-llm-confidence",
        rules=(
            PolicyRule(
                rule_id="llm.sensitive",
                name="Sensitive",
                action=PolicyAction.HOLD,
                conditions=RuleConditions(
                    llm_classifications=frozenset({"SENSITIVE"}),
                    min_llm_confidence=0.8,
                    external_recipients_only=True,
                ),
            ),
        ),
    )
    low = ClassificationOutcome(
        findings=(),
        llm_classification="SENSITIVE",
        llm_confidence=0.4,
        llm_categories=(),
        llm_reasoning="test",
    )
    high = ClassificationOutcome(
        findings=(),
        llm_classification="SENSITIVE",
        llm_confidence=0.9,
        llm_categories=(),
        llm_reasoning="test",
    )

    missed = PolicyEvaluator().evaluate(
        policy=policy,
        classification=low,
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )
    matched = PolicyEvaluator().evaluate(
        policy=policy,
        classification=high,
        limitations=(),
        context=_context("bob@external.test"),
        mode=TenantMode.ENFORCE,
    )

    assert missed.matched_rule_ids == ()
    assert matched.matched_rule_ids == ("llm.sensitive",)
