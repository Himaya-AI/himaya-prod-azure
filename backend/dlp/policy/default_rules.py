"""Conservative built-in policy used until a tenant publishes one."""

from backend.dlp.policy.evaluator import (
    PolicyAction,
    PolicyRule,
    PolicySet,
    RuleConditions,
)


def build_default_policy() -> PolicySet:
    return PolicySet(
        version="builtin-v1",
        rules=(
            PolicyRule(
                rule_id="builtin.credentials.external",
                name="Credentials sent externally",
                action=PolicyAction.STOP,
                priority=10,
                conditions=RuleConditions(
                    detectors=frozenset({"credential"}),
                    min_confidence=0.8,
                    external_recipients_only=True,
                ),
            ),
            PolicyRule(
                rule_id="builtin.financial-identity.external",
                name="High-confidence financial or identity data",
                action=PolicyAction.STOP,
                priority=20,
                conditions=RuleConditions(
                    entity_types=frozenset(
                        {
                            "CREDIT_CARD",
                            "IBAN_CODE",
                            "US_BANK_NUMBER",
                            "US_SSN",
                            "US_PASSPORT",
                            "US_DRIVER_LICENSE",
                            "UK_NHS",
                            "UK_NINO",
                            "IN_AADHAAR",
                            "IN_PAN",
                        }
                    ),
                    min_confidence=0.9,
                    external_recipients_only=True,
                ),
            ),
            PolicyRule(
                rule_id="builtin.tenant-lexicon.external",
                name="Tenant confidential terms sent externally",
                action=PolicyAction.HOLD,
                priority=30,
                conditions=RuleConditions(
                    detectors=frozenset({"lexicon"}),
                    min_confidence=0.75,
                    external_recipients_only=True,
                ),
            ),
            PolicyRule(
                rule_id="builtin.llm-sensitive.external",
                name="Semantically sensitive external message",
                action=PolicyAction.HOLD,
                priority=40,
                conditions=RuleConditions(
                    llm_classifications=frozenset({"SENSITIVE"}),
                    external_recipients_only=True,
                ),
            ),
            PolicyRule(
                rule_id="builtin.llm-uncertain",
                name="Classifier requested manual review",
                action=PolicyAction.HOLD,
                priority=50,
                conditions=RuleConditions(
                    llm_classifications=frozenset({"UNCERTAIN"})
                ),
            ),
        ),
    )
