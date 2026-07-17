from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class EntityType(str, Enum):
    sender = "sender"
    domain = "domain"
    url = "url"
    file = "file"
    ip = "ip"


class Verdict(str, Enum):
    benign = "benign"
    suspicious = "suspicious"
    malicious = "malicious"
    unknown = "unknown"


class AgreementLevel(str, Enum):
    strong = "strong"
    partial = "partial"
    conflict = "conflict"
    none = "none"


class AuthResults(BaseModel):
    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    sender_ip: str | None = None


class EntityContext(BaseModel):
    auth_results: AuthResults | None = None
    filename: str | None = None
    extension: str | None = None
    tenant_id: str | None = None
    labels: list[str] = Field(default_factory=list)


HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


class ReputationEntity(BaseModel):
    type: EntityType
    value: str = Field(..., min_length=1)
    hash_type: Literal["md5", "sha1", "sha256"] | None = None
    context: EntityContext | None = None

    @field_validator("hash_type")
    @classmethod
    def file_hash_type_required(
        cls,
        value: Literal["md5", "sha1", "sha256"] | None,
        info,
    ) -> Literal["md5", "sha1", "sha256"] | None:
        entity_type = info.data.get("type")
        if entity_type == EntityType.file and value is None:
            return "sha256"
        return value

    @model_validator(mode="after")
    def validate_entity_value(self) -> "ReputationEntity":
        if self.type == EntityType.file:
            digest = self.value.strip().replace(" ", "").lower()
            if not all(char in "0123456789abcdef" for char in digest):
                raise ValueError("File hash must be hexadecimal")
            expected = HASH_LENGTHS[self.hash_type or "sha256"]
            if len(digest) != expected:
                raise ValueError(
                    f"File hash length must match hash_type {self.hash_type or 'sha256'}"
                )
            self.value = digest
        elif self.type == EntityType.domain:
            if not self.value.strip().strip("."):
                raise ValueError("Domain value cannot be empty")
        elif self.type == EntityType.sender:
            if "@" not in self.value:
                raise ValueError("Sender value must be a valid email address")
        elif self.type == EntityType.ip:
            import ipaddress

            try:
                parsed = ipaddress.ip_address(self.value.strip())
            except ValueError as exc:
                raise ValueError("IP value must be a valid IPv4 or IPv6 address") from exc
            self.value = str(parsed)
        return self


class LookupOptions(BaseModel):
    force_refresh: bool = False
    include_raw_signals: bool = False
    max_sources: int | None = Field(default=None, ge=1)


class ReputationLookupRequest(BaseModel):
    entities: list[ReputationEntity] = Field(..., min_length=1, max_length=25)
    options: LookupOptions = Field(default_factory=LookupOptions)


class SignalEvidence(BaseModel):
    source: str
    indicator: str
    impact: int = 0
    detail: str | None = None


class EmailVerifyContext(BaseModel):
    valid_format: bool = False
    domain: str | None = None
    root_domain: str | None = None
    subdomain: str | None = None
    tld: str | None = None
    valid_tld: bool = False
    public_domain: bool = False
    has_a_records: bool = False
    has_mx_records: bool = False
    has_txt_records: bool = False
    has_spf_records: bool = False
    spf_qualifier: str | None = None
    spf_strict: bool = False
    dmarc_configured: bool = False
    mx_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ReputationResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type: EntityType
    value: str
    normalized_value: str
    entity_key: str
    verdict: Verdict
    score: int = Field(..., ge=0, le=100)
    confidence: float = Field(..., ge=0.0, le=1.0)
    cache_hit: bool = False
    sources: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    evidence: list[SignalEvidence] = Field(default_factory=list)
    agreement_level: AgreementLevel = AgreementLevel.none
    summary: str
    email_verify: EmailVerifyContext | None = Field(default=None, alias="email-verify")
    raw_signals: list[dict[str, Any]] | None = None
    cached_at: datetime | None = None
    expires_at: datetime | None = None


class ReputationLookupResponse(BaseModel):
    results: list[ReputationResult]
    request_id: str
    latency_ms: float


class CacheEntry(BaseModel):
    source_signals: list[dict[str, Any]] = Field(default_factory=list)
    result: ReputationResult | None = None
    lookup_type: EntityType | None = None
    lookup_value: str | None = None
    cached_at: datetime
    expires_at: datetime


class CacheOverrideRequest(BaseModel):
    verdict: Verdict
    score: int = Field(..., ge=0, le=100)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str = Field(..., min_length=3)
    expires_at: datetime | None = None


class CacheOverrideResponse(BaseModel):
    key: str
    status: str
    expires_at: datetime | None = None


class SourceStatus(BaseModel):
    name: str
    enabled: bool
    configured: bool
    priority: int
    supported_entities: list[str]
    status: str
    detail: str | None = None


class HealthResponse(BaseModel):
    service: str
    environment: str
    status: str
    redis: str
    sources: list[SourceStatus]
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SourceListResponse(BaseModel):
    sources: list[SourceStatus]


class CacheDeleteResponse(BaseModel):
    key: str
    deleted: bool
