"""Write-path validation for tenant policy documents."""

from __future__ import annotations

import re

from backend.dlp.policy.capabilities import (
    RESERVED_RULE_ID_PREFIXES,
    known_detectors,
    known_entity_types,
    known_llm_classifications,
)
from backend.dlp.policy.evaluator import PolicyAction
from backend.dlp.policy.serialization import (
    PolicyDocument,
    PolicyRuleDocument,
)

_CREDENTIAL_ENTITY = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


class PolicyWriteError(ValueError):
    """Tenant policy is structurally valid but not writable."""


def has_content_filters(rule: PolicyRuleDocument) -> bool:
    conditions = rule.conditions
    return bool(
        conditions.entity_types
        or conditions.detectors
        or conditions.llm_classifications
        or conditions.llm_categories
    )


def validate_policy_write(document: PolicyDocument) -> None:
    detectors = known_detectors()
    entities = known_entity_types()
    classifications = known_llm_classifications()

    for rule in document.rules:
        lowered_id = rule.rule_id.strip().lower()
        if any(
            lowered_id.startswith(prefix)
            for prefix in RESERVED_RULE_ID_PREFIXES
        ):
            raise PolicyWriteError(
                f"Rule ID '{rule.rule_id}' is reserved."
            )
        for detector in rule.conditions.detectors:
            if detector not in detectors:
                raise PolicyWriteError(
                    f"Unknown detector '{detector}' in rule '{rule.rule_id}'."
                )
        for entity_type in rule.conditions.entity_types:
            if entity_type in entities:
                continue
            if (
                "credential" in rule.conditions.detectors
                and _CREDENTIAL_ENTITY.fullmatch(entity_type)
            ):
                continue
            raise PolicyWriteError(
                f"Unknown entity type '{entity_type}' in rule "
                f"'{rule.rule_id}'."
            )
        for classification in rule.conditions.llm_classifications:
            if classification not in classifications:
                raise PolicyWriteError(
                    f"Unknown LLM classification '{classification}' "
                    f"in rule '{rule.rule_id}'."
                )
        for domain in rule.conditions.recipient_domains:
            _require_domain(domain, rule.rule_id)
        if rule.conditions.match_all and has_content_filters(rule):
            raise PolicyWriteError(
                f"Rule '{rule.rule_id}' sets match_all and also has "
                "detectors, entity types, or LLM conditions."
            )
        if (
            rule.enabled
            and rule.action in {PolicyAction.HOLD, PolicyAction.STOP}
            and not rule.conditions.match_all
            and not has_content_filters(rule)
        ):
            raise PolicyWriteError(
                f"Rule '{rule.rule_id}' would match every remaining "
                "message. Set match_all to acknowledge a catch-all, "
                "or add content conditions."
            )


def _require_domain(domain: str, rule_id: str) -> None:
    if (
        not domain
        or len(domain) > 253
        or "@" in domain
        or "/" in domain
        or any(not label for label in domain.split("."))
        or any(
            not label.replace("-", "").isalnum()
            for label in domain.split(".")
        )
    ):
        raise PolicyWriteError(
            f"Invalid recipient domain '{domain}' in rule '{rule_id}'."
        )
