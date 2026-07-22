"""Validated JSON representation for persisted tenant policies."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.dlp.policy.evaluator import (
    PolicyAction,
    PolicyRule,
    PolicySet,
    RuleConditions,
)


class RuleConditionsDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity_types: list[str] = Field(default_factory=list)
    detectors: list[str] = Field(default_factory=list)
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    min_match_count: int = Field(default=1, ge=1)
    llm_classifications: list[str] = Field(default_factory=list)
    llm_categories: list[str] = Field(default_factory=list)
    external_recipients_only: bool = False
    recipient_domains: list[str] = Field(default_factory=list)


class PolicyRuleDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    action: PolicyAction
    conditions: RuleConditionsDocument
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = True


class PolicyDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_action: PolicyAction = PolicyAction.ALLOW
    rules: list[PolicyRuleDocument] = Field(
        default_factory=list, max_length=500
    )

    @model_validator(mode="after")
    def validate_unique_rule_ids(self) -> "PolicyDocument":
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Policy rule IDs must be unique")
        return self


def policy_from_document(
    document: PolicyDocument | dict, version: str
) -> PolicySet:
    validated = (
        document
        if isinstance(document, PolicyDocument)
        else PolicyDocument.model_validate(document)
    )
    return PolicySet(
        version=version,
        default_action=validated.default_action,
        rules=tuple(
            PolicyRule(
                rule_id=rule.rule_id,
                name=rule.name,
                action=rule.action,
                conditions=RuleConditions(
                    entity_types=frozenset(
                        rule.conditions.entity_types
                    ),
                    detectors=frozenset(rule.conditions.detectors),
                    min_confidence=(
                        rule.conditions.min_confidence
                    ),
                    min_match_count=(
                        rule.conditions.min_match_count
                    ),
                    llm_classifications=frozenset(
                        rule.conditions.llm_classifications
                    ),
                    llm_categories=frozenset(
                        rule.conditions.llm_categories
                    ),
                    external_recipients_only=(
                        rule.conditions.external_recipients_only
                    ),
                    recipient_domains=frozenset(
                        rule.conditions.recipient_domains
                    ),
                ),
                priority=rule.priority,
                enabled=rule.enabled,
            )
            for rule in validated.rules
        ),
    )


def policy_to_document(policy: PolicySet) -> PolicyDocument:
    return PolicyDocument(
        default_action=policy.default_action,
        rules=[
            PolicyRuleDocument(
                rule_id=rule.rule_id,
                name=rule.name,
                action=rule.action,
                priority=rule.priority,
                enabled=rule.enabled,
                conditions=RuleConditionsDocument(
                    entity_types=sorted(
                        rule.conditions.entity_types
                    ),
                    detectors=sorted(rule.conditions.detectors),
                    min_confidence=(
                        rule.conditions.min_confidence
                    ),
                    min_match_count=(
                        rule.conditions.min_match_count
                    ),
                    llm_classifications=sorted(
                        rule.conditions.llm_classifications
                    ),
                    llm_categories=sorted(
                        rule.conditions.llm_categories
                    ),
                    external_recipients_only=(
                        rule.conditions.external_recipients_only
                    ),
                    recipient_domains=sorted(
                        rule.conditions.recipient_domains
                    ),
                ),
            )
            for rule in policy.rules
        ],
    )
