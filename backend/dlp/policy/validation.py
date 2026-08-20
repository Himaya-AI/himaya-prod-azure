"""Write-path validation for tenant policy documents."""

from __future__ import annotations

import re
from dataclasses import dataclass

from backend.dlp.policy.capabilities import (
    RESERVED_RULE_ID_PREFIXES,
    known_detectors,
    known_entity_types,
    known_llm_classifications,
)
from backend.dlp.policy.evaluator import PolicyAction, ordered_rules
from backend.dlp.policy.serialization import (
    PolicyDocument,
    PolicyRuleDocument,
)

_CREDENTIAL_ENTITY = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


class PolicyWriteError(ValueError):
    """Tenant policy is structurally valid but not writable."""


@dataclass(frozen=True)
class PolicyIssue:
    message: str
    rule_id: str | None = None


def has_content_filters(rule: PolicyRuleDocument) -> bool:
    conditions = rule.conditions
    return bool(
        conditions.entity_types
        or conditions.detectors
        or conditions.llm_classifications
        or conditions.llm_categories
    )


def collect_policy_issues(
    document: PolicyDocument,
) -> tuple[list[PolicyIssue], list[PolicyIssue]]:
    detectors = known_detectors()
    entities = known_entity_types()
    classifications = known_llm_classifications()
    errors: list[PolicyIssue] = []
    warnings: list[PolicyIssue] = []

    for rule in document.rules:
        lowered_id = rule.rule_id.strip().lower()
        if any(
            lowered_id.startswith(prefix)
            for prefix in RESERVED_RULE_ID_PREFIXES
        ):
            errors.append(
                PolicyIssue(
                    f"Rule ID '{rule.rule_id}' is reserved.",
                    rule.rule_id,
                )
            )
        for detector in rule.conditions.detectors:
            if detector not in detectors:
                errors.append(
                    PolicyIssue(
                        f"Unknown detector '{detector}' in rule "
                        f"'{rule.rule_id}'.",
                        rule.rule_id,
                    )
                )
        for entity_type in rule.conditions.entity_types:
            if entity_type in entities:
                continue
            if (
                "credential" in rule.conditions.detectors
                and _CREDENTIAL_ENTITY.fullmatch(entity_type)
            ):
                continue
            errors.append(
                PolicyIssue(
                    f"Unknown entity type '{entity_type}' in rule "
                    f"'{rule.rule_id}'.",
                    rule.rule_id,
                )
            )
        for classification in rule.conditions.llm_classifications:
            if classification not in classifications:
                errors.append(
                    PolicyIssue(
                        f"Unknown LLM classification '{classification}' "
                        f"in rule '{rule.rule_id}'.",
                        rule.rule_id,
                    )
                )
        for domain in rule.conditions.recipient_domains:
            if not _valid_domain(domain):
                errors.append(
                    PolicyIssue(
                        f"Invalid recipient domain '{domain}' in rule "
                        f"'{rule.rule_id}'.",
                        rule.rule_id,
                    )
                )
        if rule.conditions.match_all and has_content_filters(rule):
            errors.append(
                PolicyIssue(
                    f"Rule '{rule.rule_id}' sets match_all and also has "
                    "detectors, entity types, or LLM conditions.",
                    rule.rule_id,
                )
            )
        if (
            rule.enabled
            and rule.action in {PolicyAction.HOLD, PolicyAction.STOP}
            and not rule.conditions.match_all
            and not has_content_filters(rule)
        ):
            errors.append(
                PolicyIssue(
                    f"Rule '{rule.rule_id}' would match every remaining "
                    "message. Set match_all to acknowledge a catch-all, "
                    "or add content conditions.",
                    rule.rule_id,
                )
            )
        elif (
            not rule.enabled
            and rule.action in {PolicyAction.HOLD, PolicyAction.STOP}
            and not rule.conditions.match_all
            and not has_content_filters(rule)
        ):
            warnings.append(
                PolicyIssue(
                    f"Rule '{rule.rule_id}' has no content conditions. "
                    "Enabling it would require match_all or content filters.",
                    rule.rule_id,
                )
            )
        if (
            rule.enabled
            and rule.action == PolicyAction.ALLOW
            and not rule.conditions.match_all
            and not has_content_filters(rule)
        ):
            warnings.append(
                PolicyIssue(
                    f"Rule '{rule.rule_id}' is an Allow with no content "
                    "filters and matches remaining messages that pass "
                    "recipient filters.",
                    rule.rule_id,
                )
            )
        if (
            rule.conditions.min_confidence > 0
            and not rule.conditions.detectors
            and not rule.conditions.entity_types
            and not rule.conditions.match_all
        ):
            warnings.append(
                PolicyIssue(
                    f"Rule '{rule.rule_id}' sets min confidence with no "
                    "detectors or entity types.",
                    rule.rule_id,
                )
            )
        if (
            rule.conditions.min_llm_confidence > 0
            and not rule.conditions.llm_classifications
            and not rule.conditions.llm_categories
        ):
            warnings.append(
                PolicyIssue(
                    f"Rule '{rule.rule_id}' sets min LLM confidence with no "
                    "LLM classifications or categories.",
                    rule.rule_id,
                )
            )

    return errors, warnings


def validate_policy_write(document: PolicyDocument) -> None:
    errors, _warnings = collect_policy_issues(document)
    if errors:
        raise PolicyWriteError(errors[0].message)


def evaluation_order(document: PolicyDocument) -> list[str]:
    return [rule.rule_id for rule in ordered_rules(document.rules)]


def _valid_domain(domain: str) -> bool:
    return not (
        not domain
        or len(domain) > 253
        or "@" in domain
        or "/" in domain
        or any(not label for label in domain.split("."))
        or any(
            not label.replace("-", "").isalnum()
            for label in domain.split(".")
        )
    )


def _require_domain(domain: str, rule_id: str) -> None:
    if not _valid_domain(domain):
        raise PolicyWriteError(
            f"Invalid recipient domain '{domain}' in rule '{rule_id}'."
        )
