"""Deterministic, explainable DLP policy evaluation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum

from backend.dlp.domain import ClassificationOutcome, Finding, TenantMode
from backend.dlp.extraction import ExtractionLimitation


class PolicyAction(str, Enum):
    ALLOW = "allow"
    HOLD = "hold"
    STOP = "stop"


_ACTION_SEVERITY = {
    PolicyAction.ALLOW: 0,
    PolicyAction.HOLD: 1,
    PolicyAction.STOP: 2,
}


@dataclass(frozen=True)
class RuleConditions:
    entity_types: frozenset[str] = field(default_factory=frozenset)
    detectors: frozenset[str] = field(default_factory=frozenset)
    min_confidence: float = 0.0
    min_match_count: int = 1
    llm_classifications: frozenset[str] = field(
        default_factory=frozenset
    )
    llm_categories: frozenset[str] = field(default_factory=frozenset)
    external_recipients_only: bool = False
    recipient_domains: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not 0.0 <= self.min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1")
        if self.min_match_count < 1:
            raise ValueError("min_match_count must be at least 1")
        object.__setattr__(
            self,
            "entity_types",
            frozenset(value.upper() for value in self.entity_types),
        )
        object.__setattr__(
            self,
            "detectors",
            frozenset(value.lower() for value in self.detectors),
        )
        object.__setattr__(
            self,
            "llm_classifications",
            frozenset(
                value.upper() for value in self.llm_classifications
            ),
        )
        object.__setattr__(
            self,
            "llm_categories",
            frozenset(
                value.lower() for value in self.llm_categories
            ),
        )
        object.__setattr__(
            self,
            "recipient_domains",
            frozenset(
                value.lower().rstrip(".")
                for value in self.recipient_domains
            ),
        )


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    name: str
    action: PolicyAction
    conditions: RuleConditions
    priority: int = 100
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.rule_id:
            raise ValueError("rule_id is required")


@dataclass(frozen=True)
class PolicySet:
    version: str
    rules: tuple[PolicyRule, ...]
    default_action: PolicyAction = PolicyAction.ALLOW

    def __post_init__(self) -> None:
        if not self.version:
            raise ValueError("Policy version is required")
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Policy rule IDs must be unique")


@dataclass(frozen=True)
class MessageContext:
    sender: str
    recipients: tuple[str, ...]
    tenant_domains: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "tenant_domains",
            frozenset(
                domain.lower().rstrip(".")
                for domain in self.tenant_domains
            ),
        )

    @property
    def recipient_domains(self) -> frozenset[str]:
        return frozenset(
            _email_domain(recipient)
            for recipient in self.recipients
            if _email_domain(recipient)
        )

    @property
    def has_external_recipient(self) -> bool:
        return bool(self.recipient_domains - self.tenant_domains)


@dataclass(frozen=True)
class FindingReference:
    detector: str
    entity_type: str
    confidence: float
    start: int
    end: int


@dataclass(frozen=True)
class PolicyDecision:
    policy_version: str
    intended_action: PolicyAction
    effective_action: PolicyAction
    matched_rule_ids: tuple[str, ...]
    finding_references: tuple[FindingReference, ...]
    explanation: str
    evaluation_latency_ms: int


@dataclass(frozen=True)
class _RuleMatch:
    rule_id: str
    name: str
    action: PolicyAction
    priority: int
    findings: tuple[Finding, ...]


class PolicyEvaluator:
    def evaluate(
        self,
        *,
        policy: PolicySet,
        classification: ClassificationOutcome,
        limitations: tuple[ExtractionLimitation, ...],
        context: MessageContext,
        mode: TenantMode,
        enabled: bool = True,
    ) -> PolicyDecision:
        started = time.perf_counter()
        matches: list[_RuleMatch] = []

        fatal_limitations = tuple(
            item for item in limitations if item.fatal
        )
        if fatal_limitations:
            matches.append(
                _RuleMatch(
                    rule_id="system.extraction_incomplete",
                    name="Incomplete content inspection",
                    action=PolicyAction.HOLD,
                    priority=0,
                    findings=(),
                )
            )
        if classification.detector_errors:
            matches.append(
                _RuleMatch(
                    rule_id="system.detector_error",
                    name="Classifier detector failure",
                    action=PolicyAction.HOLD,
                    priority=0,
                    findings=(),
                )
            )

        for rule in policy.rules:
            if not rule.enabled:
                continue
            matched_findings = self._match_rule(
                rule, classification, context
            )
            if matched_findings is not None:
                matches.append(
                    _RuleMatch(
                        rule_id=rule.rule_id,
                        name=rule.name,
                        action=rule.action,
                        priority=rule.priority,
                        findings=matched_findings,
                    )
                )

        matches.sort(
            key=lambda match: (
                -_ACTION_SEVERITY[match.action],
                match.priority,
                match.rule_id,
            )
        )
        if matches:
            winner = matches[0]
            intended_action = winner.action
            explanation = (
                f"{winner.action.value.upper()} selected by "
                f"{winner.rule_id} ({winner.name}); "
                f"{len(matches)} rule(s) matched."
            )
        else:
            intended_action = policy.default_action
            explanation = (
                f"No rule matched; policy default is "
                f"{policy.default_action.value.upper()}."
            )

        effective_action = intended_action
        if not enabled:
            effective_action = PolicyAction.ALLOW
            explanation += " DLP is disabled, so effective action is ALLOW."
        elif mode == TenantMode.MONITOR:
            effective_action = PolicyAction.ALLOW
            explanation += (
                " Monitor mode preserves the intended action but "
                "delivers the message."
            )

        references = _deduplicate_references(
            finding
            for match in matches
            for finding in match.findings
        )
        latency_ms = max(
            0, round((time.perf_counter() - started) * 1000)
        )
        return PolicyDecision(
            policy_version=policy.version,
            intended_action=intended_action,
            effective_action=effective_action,
            matched_rule_ids=tuple(
                match.rule_id for match in matches
            ),
            finding_references=references,
            explanation=explanation,
            evaluation_latency_ms=latency_ms,
        )

    def _match_rule(
        self,
        rule: PolicyRule,
        classification: ClassificationOutcome,
        context: MessageContext,
    ) -> tuple[Finding, ...] | None:
        conditions = rule.conditions
        if (
            conditions.external_recipients_only
            and not context.has_external_recipient
        ):
            return None
        if (
            conditions.recipient_domains
            and not (
                conditions.recipient_domains
                & context.recipient_domains
            )
        ):
            return None
        if (
            conditions.llm_classifications
            and classification.llm_classification.upper()
            not in conditions.llm_classifications
        ):
            return None
        if (
            conditions.llm_categories
            and not (
                conditions.llm_categories
                & frozenset(classification.llm_categories)
            )
        ):
            return None

        has_finding_conditions = bool(
            conditions.entity_types or conditions.detectors
        )
        matched_findings = tuple(
            finding
            for finding in classification.findings
            if (
                not conditions.entity_types
                or finding.entity_type.upper()
                in conditions.entity_types
            )
            and (
                not conditions.detectors
                or finding.detector.lower() in conditions.detectors
            )
            and finding.confidence >= conditions.min_confidence
        )
        if not has_finding_conditions:
            return ()
        if (
            len(matched_findings) < conditions.min_match_count
        ):
            return None
        return matched_findings


def _email_domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].strip().lower().rstrip(".")


def _deduplicate_references(
    findings,
) -> tuple[FindingReference, ...]:
    references: list[FindingReference] = []
    seen: set[tuple] = set()
    for finding in findings:
        key = (
            finding.detector,
            finding.entity_type,
            finding.start,
            finding.end,
        )
        if key in seen:
            continue
        seen.add(key)
        references.append(
            FindingReference(
                detector=finding.detector,
                entity_type=finding.entity_type,
                confidence=finding.confidence,
                start=finding.start,
                end=finding.end,
            )
        )
    return tuple(references)
