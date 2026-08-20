"""Classifier-aligned policy capabilities advertised to the control plane."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

CURRENT_POLICY_SCHEMA_VERSION = 1
RESERVED_RULE_ID_PREFIXES = ("system.",)

DETECTORS: tuple[dict[str, str | bool], ...] = (
    {
        "value": "credential",
        "label": "Credentials",
        "open_entity_types": True,
    },
    {"value": "pii", "label": "PII", "open_entity_types": False},
    {"value": "ner", "label": "Names and places", "open_entity_types": False},
    {
        "value": "lexicon",
        "label": "Confidential terms",
        "open_entity_types": False,
    },
)

_PII_ENTITIES = (
    ("CREDIT_CARD", "Credit card", "pii"),
    ("IBAN_CODE", "IBAN", "pii"),
    ("US_BANK_NUMBER", "US bank number", "pii"),
    ("CRYPTO", "Cryptocurrency address", "pii"),
    ("EMAIL_ADDRESS", "Email address", "pii"),
    ("PHONE_NUMBER", "Phone number", "pii"),
    ("IP_ADDRESS", "IP address", "pii"),
    ("URL", "URL", "pii"),
    ("US_SSN", "US SSN", "pii"),
    ("US_PASSPORT", "US passport", "pii"),
    ("US_DRIVER_LICENSE", "US driver license", "pii"),
    ("US_ITIN", "US ITIN", "pii"),
    ("UK_NHS", "UK NHS number", "pii"),
    ("UK_NINO", "UK National Insurance", "pii"),
    ("UK_PASSPORT", "UK passport", "pii"),
    ("IN_AADHAAR", "India Aadhaar", "pii"),
    ("IN_PAN", "India PAN", "pii"),
    ("IN_PASSPORT", "India passport", "pii"),
)
_NER_ENTITIES = (
    ("PERSON", "Person", "ner"),
    ("LOCATION", "Location", "ner"),
    ("NRP", "Nationality / religion / politics", "ner"),
    ("ORGANIZATION", "Organization", "ner"),
)
_LEXICON_ENTITIES = (
    ("CLASSIFICATION_BANNER", "Classification banner", "lexicon"),
    ("TENANT_CODENAME", "Tenant codename", "lexicon"),
    ("BUSINESS_TERM", "Business term", "lexicon"),
)

LLM_CLASSIFICATIONS = ("SENSITIVE", "UNCERTAIN", "NOT_SENSITIVE")


class PolicyDetectorCapability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str
    label: str
    open_entity_types: bool = False


class PolicyEntityCapability(BaseModel):
    model_config = ConfigDict(extra="forbid")

    value: str
    label: str
    detector: str


class PolicyCapabilitiesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = CURRENT_POLICY_SCHEMA_VERSION
    detectors: list[PolicyDetectorCapability]
    entity_types: list[PolicyEntityCapability]
    llm_classifications: list[str]
    domain_matching: Literal["exact"] = "exact"
    detector_entity_logic: Literal["and"] = "and"
    reserved_rule_id_prefixes: list[str] = Field(
        default_factory=lambda: list(RESERVED_RULE_ID_PREFIXES)
    )


def known_detectors() -> frozenset[str]:
    return frozenset(str(item["value"]) for item in DETECTORS)


def known_entity_types() -> frozenset[str]:
    return frozenset(
        value for value, _label, _detector in (
            *_PII_ENTITIES, *_NER_ENTITIES, *_LEXICON_ENTITIES
        )
    )


def known_llm_classifications() -> frozenset[str]:
    return frozenset(LLM_CLASSIFICATIONS)


def build_policy_capabilities() -> PolicyCapabilitiesResponse:
    entities = [
        PolicyEntityCapability(
            value=value, label=label, detector=detector
        )
        for value, label, detector in (
            *_PII_ENTITIES, *_NER_ENTITIES, *_LEXICON_ENTITIES
        )
    ]
    return PolicyCapabilitiesResponse(
        schema_version=CURRENT_POLICY_SCHEMA_VERSION,
        detectors=[
            PolicyDetectorCapability(
                value=str(item["value"]),
                label=str(item["label"]),
                open_entity_types=bool(item["open_entity_types"]),
            )
            for item in DETECTORS
        ],
        entity_types=entities,
        llm_classifications=list(LLM_CLASSIFICATIONS),
    )
