"""
Himaya Data Sovereignty Router — enterprise tier only.

Data Residency answers *where* data physically sits. Data Sovereignty is the
enforcement layer on top: *which nation's laws govern the data, whether that
placement is permitted, and provable compliance*.

Four building blocks:
  1. Jurisdiction packs   — borders (allowed regions) + transfer rules + legal citations
  2. Location oracle       — where each asset physically lives, from REAL connector data
  3. Sovereignty policies  — data-class + jurisdiction -> allowed regions + action
  4. Evaluation engine     — joins the above into verdicts (violations) + alerts

The location oracle reads the same connector tables the Data Residency endpoint
uses (aws_resources, azure_resources, gcp_resources, oracle_connections,
databricks_connections, sap_connections, saas_data_items) — no dummy data.

DB tables created at startup (raw SQL, no Alembic):
  - sovereignty_policies
  - sovereignty_violations
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.db_models import Organization as _Org
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/sovereignty", tags=["data-sovereignty"])


# ── Enterprise gate (same pattern as dlp.py / posture.py) ─────────────────────

async def _require_enterprise(current_user, db: AsyncSession):
    """Raise 403 if org is not on Enterprise tier."""
    _org = (await db.execute(
        select(_Org).where(_Org.id == current_user.org_id)
    )).scalar_one_or_none()
    _tier = (getattr(_org, "tier", None) or "Launch").strip().lower()
    if _tier not in ("enterprise", "enterprise trial"):
        raise HTTPException(
            status_code=403,
            detail="Data Sovereignty requires an Enterprise plan. Upgrade to access this feature.",
        )


# ── Region -> jurisdiction (country) resolution ───────────────────────────────
# Maps cloud region codes to the ISO country code of the physical datacentre.
# Used to decide which nation's laws govern data stored there.

AWS_REGION_COUNTRY = {
    "us-east-1": "US", "us-east-2": "US", "us-west-1": "US", "us-west-2": "US",
    "ca-central-1": "CA",
    "eu-west-1": "IE", "eu-west-2": "GB", "eu-west-3": "FR", "eu-central-1": "DE",
    "eu-central-2": "CH", "eu-north-1": "SE", "eu-south-1": "IT", "eu-south-2": "ES",
    "me-south-1": "BH", "me-central-1": "AE",
    "ap-northeast-1": "JP", "ap-northeast-2": "KR", "ap-northeast-3": "JP",
    "ap-southeast-1": "SG", "ap-southeast-2": "AU", "ap-southeast-3": "ID",
    "ap-south-1": "IN", "ap-east-1": "HK",
    "sa-east-1": "BR", "af-south-1": "ZA",
}

AZURE_REGION_COUNTRY = {
    "eastus": "US", "eastus2": "US", "westus": "US", "westus2": "US", "westus3": "US",
    "centralus": "US", "northcentralus": "US", "southcentralus": "US", "westcentralus": "US",
    "canadacentral": "CA", "canadaeast": "CA",
    "northeurope": "IE", "westeurope": "NL", "uksouth": "GB", "ukwest": "GB",
    "francecentral": "FR", "germanywestcentral": "DE", "switzerlandnorth": "CH",
    "norwayeast": "NO", "swedencentral": "SE", "italynorth": "IT", "spaincentral": "ES",
    "polandcentral": "PL",
    "uaenorth": "AE", "uaecentral": "AE", "qatarcentral": "QA", "israelcentral": "IL",
    "southafricanorth": "ZA",
    "southeastasia": "SG", "eastasia": "HK", "japaneast": "JP", "japanwest": "JP",
    "koreacentral": "KR", "centralindia": "IN", "southindia": "IN", "westindia": "IN",
    "australiaeast": "AU", "australiasoutheast": "AU",
    "brazilsouth": "BR",
}

GCP_REGION_COUNTRY = {
    "us-central1": "US", "us-east1": "US", "us-east4": "US", "us-east5": "US",
    "us-west1": "US", "us-west2": "US", "us-west3": "US", "us-west4": "US", "us-south1": "US",
    "northamerica-northeast1": "CA", "northamerica-northeast2": "CA",
    "southamerica-east1": "BR",
    "europe-west1": "BE", "europe-west2": "GB", "europe-west3": "DE", "europe-west4": "NL",
    "europe-west6": "CH", "europe-west8": "IT", "europe-west9": "FR", "europe-west10": "DE",
    "europe-west12": "IT", "europe-north1": "FI", "europe-central2": "PL",
    "europe-southwest1": "ES",
    "me-central1": "QA", "me-central2": "SA", "me-west1": "IL",
    "asia-east1": "TW", "asia-east2": "HK", "asia-northeast1": "JP", "asia-northeast2": "JP",
    "asia-northeast3": "KR", "asia-south1": "IN", "asia-south2": "IN",
    "asia-southeast1": "SG", "asia-southeast2": "ID", "australia-southeast1": "AU",
    "australia-southeast2": "AU",
}

OCI_REGION_COUNTRY = {
    "us-ashburn-1": "US", "us-phoenix-1": "US", "us-sanjose-1": "US",
    "ca-toronto-1": "CA", "ca-montreal-1": "CA",
    "uk-london-1": "GB", "uk-cardiff-1": "GB", "eu-frankfurt-1": "DE",
    "eu-amsterdam-1": "NL", "eu-zurich-1": "CH", "eu-madrid-1": "ES", "eu-milan-1": "IT",
    "eu-paris-1": "FR", "eu-stockholm-1": "SE",
    "me-jeddah-1": "SA", "me-riyadh-1": "SA", "me-dubai-1": "AE", "me-abudhabi-1": "AE",
    "il-jerusalem-1": "IL",
    "ap-tokyo-1": "JP", "ap-osaka-1": "JP", "ap-seoul-1": "KR", "ap-mumbai-1": "IN",
    "ap-hyderabad-1": "IN", "ap-singapore-1": "SG", "ap-sydney-1": "AU",
    "sa-saopaulo-1": "BR", "af-johannesburg-1": "ZA",
}

# Country -> geographic region grouping + friendly name (for UI + policy defaults)
COUNTRY_META = {
    "US": {"region": "North America", "name": "United States"},
    "CA": {"region": "North America", "name": "Canada"},
    "MX": {"region": "North America", "name": "Mexico"},
    "GB": {"region": "Europe", "name": "United Kingdom"},
    "IE": {"region": "Europe", "name": "Ireland"}, "DE": {"region": "Europe", "name": "Germany"},
    "FR": {"region": "Europe", "name": "France"}, "NL": {"region": "Europe", "name": "Netherlands"},
    "SE": {"region": "Europe", "name": "Sweden"}, "NO": {"region": "Europe", "name": "Norway"},
    "FI": {"region": "Europe", "name": "Finland"}, "CH": {"region": "Europe", "name": "Switzerland"},
    "IT": {"region": "Europe", "name": "Italy"}, "ES": {"region": "Europe", "name": "Spain"},
    "PL": {"region": "Europe", "name": "Poland"}, "BE": {"region": "Europe", "name": "Belgium"},
    "SA": {"region": "Middle East", "name": "Saudi Arabia"}, "AE": {"region": "Middle East", "name": "UAE"},
    "QA": {"region": "Middle East", "name": "Qatar"}, "BH": {"region": "Middle East", "name": "Bahrain"},
    "KW": {"region": "Middle East", "name": "Kuwait"}, "OM": {"region": "Middle East", "name": "Oman"},
    "IL": {"region": "Middle East", "name": "Israel"},
    "JP": {"region": "Asia Pacific", "name": "Japan"}, "KR": {"region": "Asia Pacific", "name": "South Korea"},
    "SG": {"region": "Asia Pacific", "name": "Singapore"}, "IN": {"region": "Asia Pacific", "name": "India"},
    "AU": {"region": "Asia Pacific", "name": "Australia"}, "HK": {"region": "Asia Pacific", "name": "Hong Kong"},
    "ID": {"region": "Asia Pacific", "name": "Indonesia"}, "TW": {"region": "Asia Pacific", "name": "Taiwan"},
    "BR": {"region": "South America", "name": "Brazil"}, "ZA": {"region": "Africa", "name": "South Africa"},
}


# ── Jurisdiction packs (borders + transfer rules + legal citations) ───────────
# Prebuilt, shipped reference data. Customers toggle which apply; they don't
# author law. allowed_regions accepts BOTH country codes and cloud region codes.

JURISDICTION_PACKS = {
    "KSA_PDPL": {
        "name": "Saudi Arabia — PDPL / NCA Data Localization",
        "jurisdiction": "KSA",
        "regulator": "SDAIA / NCA",
        "legal_basis": "PDPL Art. 29 (cross-border transfer); NCA data-localization guidance",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["SA", "me-central2", "me-jeddah-1", "me-riyadh-1"],
        "action": "WARN",
        "transfer_rule": "prohibited_unless_adequacy_or_consent",
    },
    "UAE_PDPL": {
        "name": "UAE — Federal PDPL",
        "jurisdiction": "UAE",
        "regulator": "UAE Data Office",
        "legal_basis": "UAE Federal Decree-Law No. 45 of 2021 (PDPL) Art. 22–23",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["AE", "uaenorth", "uaecentral", "me-central-1", "me-dubai-1", "me-abudhabi-1"],
        "action": "WARN",
        "transfer_rule": "allowed_with_adequate_protection",
    },
    "EU_GDPR": {
        "name": "European Union — GDPR (Chapter V transfers)",
        "jurisdiction": "EU",
        "regulator": "EDPB",
        "legal_basis": "GDPR Art. 44–46 (transfers require adequacy decision or SCCs)",
        "data_classes": ["pii", "phi", "confidential", "highly_confidential"],
        "allowed_regions": [
            "IE", "DE", "FR", "NL", "SE", "FI", "IT", "ES", "PL", "BE", "NO",
            "eu-west-1", "eu-west-3", "eu-central-1", "eu-north-1", "eu-south-1",
            "northeurope", "westeurope", "francecentral", "germanywestcentral",
            "swedencentral", "europe-west1", "europe-west3", "europe-west4",
            "europe-west9", "europe-north1",
        ],
        "action": "WARN",
        "transfer_rule": "allowed_with_SCC_or_adequacy",
    },
    "US": {
        "name": "United States — SOC 2 / HIPAA residency",
        "jurisdiction": "US",
        "regulator": "AICPA / HHS",
        "legal_basis": "SOC 2 CC / HIPAA §164.308 data-residency commitments",
        "data_classes": ["phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": [
            "US", "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eastus", "eastus2", "westus", "westus2", "westus3", "centralus",
            "us-central1", "us-east1", "us-east4", "us-west1", "us-west2",
        ],
        "action": "WARN",
        "transfer_rule": "no_restriction",
    },
    "UK_GDPR": {
        "name": "United Kingdom — UK GDPR / DPA 2018",
        "jurisdiction": "UK",
        "regulator": "ICO",
        "legal_basis": "UK GDPR Art. 44–46; Data Protection Act 2018",
        "data_classes": ["pii", "phi", "confidential", "highly_confidential"],
        "allowed_regions": ["GB", "eu-west-2", "uksouth", "ukwest", "europe-west2"],
        "action": "WARN",
        "transfer_rule": "allowed_with_SCC_or_adequacy",
    },
    "QATAR_PDPPL": {
        "name": "Qatar — PDPPL (Law No. 13 of 2016)",
        "jurisdiction": "QATAR",
        "regulator": "NPGC / CRA",
        "legal_basis": "Qatar Law No. 13 of 2016 on Personal Data Privacy Protection, Art. 3 & 15",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["QA", "qatarcentral", "me-central1"],
        "action": "WARN",
        "transfer_rule": "prohibited_unless_adequate_protection",
    },
    "BAHRAIN_PDPL": {
        "name": "Bahrain — PDPL (Law No. 30 of 2018)",
        "jurisdiction": "BAHRAIN",
        "regulator": "PDPA",
        "legal_basis": "Bahrain Law No. 30 of 2018 (PDPL), Art. 12 (cross-border transfer)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["BH", "me-south-1"],
        "action": "WARN",
        "transfer_rule": "allowed_to_adequate_countries_or_authorization",
    },
    "INDIA_DPDP": {
        "name": "India — DPDP Act 2023",
        "jurisdiction": "INDIA",
        "regulator": "Data Protection Board of India",
        "legal_basis": "Digital Personal Data Protection Act, 2023, Sec. 16 (cross-border)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": [
            "IN", "ap-south-1", "ap-south-2", "centralindia", "southindia",
            "westindia", "asia-south1", "asia-south2",
        ],
        "action": "WARN",
        "transfer_rule": "allowed_except_blacklisted_countries",
    },
    "CHINA_PIPL": {
        "name": "China — PIPL / CSL Data Localization",
        "jurisdiction": "CHINA",
        "regulator": "CAC",
        "legal_basis": "PIPL Art. 38–40; Cybersecurity Law Art. 37 (in-country storage)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": [
            "CN", "cn-north-1", "cn-northwest-1", "chinaeast", "chinaeast2",
            "chinaeast3", "chinanorth", "chinanorth2", "chinanorth3",
        ],
        "action": "BLOCK",
        "transfer_rule": "localization_required_security_assessment_for_export",
    },
    "BRAZIL_LGPD": {
        "name": "Brazil — LGPD (Lei 13.709/2018)",
        "jurisdiction": "BRAZIL",
        "regulator": "ANPD",
        "legal_basis": "LGPD Art. 33 (international data transfer)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["BR", "sa-east-1", "brazilsouth", "brazilsoutheast", "southamerica-east1"],
        "action": "WARN",
        "transfer_rule": "allowed_with_adequacy_or_safeguards",
    },
    "CANADA_PIPEDA": {
        "name": "Canada — PIPEDA",
        "jurisdiction": "CANADA",
        "regulator": "OPC",
        "legal_basis": "PIPEDA Principle 4.1.3; provincial (Quebec Law 25) residency expectations",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": [
            "CA", "ca-central-1", "ca-west-1", "canadacentral", "canadaeast",
            "northamerica-northeast1", "northamerica-northeast2",
        ],
        "action": "WARN",
        "transfer_rule": "allowed_with_comparable_protection",
    },
    "AUSTRALIA_PRIVACY": {
        "name": "Australia — Privacy Act 1988 / APPs",
        "jurisdiction": "AUSTRALIA",
        "regulator": "OAIC",
        "legal_basis": "Privacy Act 1988, APP 8 (cross-border disclosure)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": [
            "AU", "ap-southeast-2", "ap-southeast-4", "australiaeast",
            "australiasoutheast", "australiacentral", "australiacentral2",
            "australia-southeast1", "australia-southeast2",
        ],
        "action": "WARN",
        "transfer_rule": "allowed_with_accountability",
    },
    "SINGAPORE_PDPA": {
        "name": "Singapore — PDPA 2012",
        "jurisdiction": "SINGAPORE",
        "regulator": "PDPC",
        "legal_basis": "PDPA 2012, Sec. 26 (transfer limitation)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["SG", "ap-southeast-1", "southeastasia", "asia-southeast1"],
        "action": "WARN",
        "transfer_rule": "allowed_with_comparable_protection",
    },
    "JAPAN_APPI": {
        "name": "Japan — APPI",
        "jurisdiction": "JAPAN",
        "regulator": "PPC",
        "legal_basis": "Act on Protection of Personal Information, Art. 28 (foreign transfer)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": [
            "JP", "ap-northeast-1", "ap-northeast-3", "japaneast", "japanwest",
            "asia-northeast1", "asia-northeast2",
        ],
        "action": "WARN",
        "transfer_rule": "allowed_to_adequate_countries_or_consent",
    },
    "SOUTH_KOREA_PIPA": {
        "name": "South Korea — PIPA",
        "jurisdiction": "SOUTH_KOREA",
        "regulator": "PIPC",
        "legal_basis": "Personal Information Protection Act, Art. 28-8 (overseas transfer)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["KR", "ap-northeast-2", "koreacentral", "koreasouth", "asia-northeast3"],
        "action": "WARN",
        "transfer_rule": "allowed_with_consent_or_certification",
    },
    "SWITZERLAND_FADP": {
        "name": "Switzerland — revFADP",
        "jurisdiction": "SWITZERLAND",
        "regulator": "FDPIC",
        "legal_basis": "Revised Federal Act on Data Protection (nFADP), Art. 16–17",
        "data_classes": ["pii", "phi", "confidential", "highly_confidential"],
        "allowed_regions": ["CH", "eu-central-2", "switzerlandnorth", "switzerlandwest", "europe-west6"],
        "action": "WARN",
        "transfer_rule": "allowed_with_adequacy_or_safeguards",
    },
    "SOUTH_AFRICA_POPIA": {
        "name": "South Africa — POPIA",
        "jurisdiction": "SOUTH_AFRICA",
        "regulator": "Information Regulator",
        "legal_basis": "Protection of Personal Information Act, Sec. 72 (transborder flows)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["ZA", "af-south-1", "southafricanorth", "southafricawest", "africa-south1"],
        "action": "WARN",
        "transfer_rule": "allowed_with_comparable_protection",
    },
    "ISRAEL_PPL": {
        "name": "Israel — Protection of Privacy Law",
        "jurisdiction": "ISRAEL",
        "regulator": "PPA",
        "legal_basis": "Protection of Privacy Law 5741-1981; Privacy Protection (Transfer of Data) Regulations 2001",
        "data_classes": ["pii", "phi", "confidential", "highly_confidential"],
        "allowed_regions": ["IL", "il-central-1", "israelcentral", "me-west1"],
        "action": "WARN",
        "transfer_rule": "allowed_to_adequate_countries",
    },
    "INDONESIA_PDP": {
        "name": "Indonesia — PDP Law (No. 27 of 2022)",
        "jurisdiction": "INDONESIA",
        "regulator": "Kominfo",
        "legal_basis": "Law No. 27 of 2022 on Personal Data Protection, Art. 56 (cross-border)",
        "data_classes": ["pii", "phi", "financial", "confidential", "highly_confidential"],
        "allowed_regions": ["ID", "ap-southeast-3", "asia-southeast2"],
        "action": "WARN",
        "transfer_rule": "allowed_with_adequate_protection",
    },
}

# Data classes we recognise on assets. Anything a policy targets is matched
# against the asset's derived data_class (see _asset_data_class).
KNOWN_DATA_CLASSES = ["pii", "phi", "pci", "financial", "confidential", "highly_confidential"]
VALID_ACTIONS = ("WARN", "BLOCK", "QUARANTINE", "NOTIFY")
ACTION_SEVERITY = {"NOTIFY": "low", "WARN": "medium", "QUARANTINE": "high", "BLOCK": "critical"}


def _region_to_country(provider: str, region: Optional[str]) -> Optional[str]:
    """Resolve a provider region code to an ISO country code."""
    if not region:
        return None
    r = region.strip().lower()
    p = (provider or "").lower()
    if p == "aws":
        return AWS_REGION_COUNTRY.get(r)
    if p == "azure":
        return AZURE_REGION_COUNTRY.get(r)
    if p == "gcp":
        return GCP_REGION_COUNTRY.get(r)
    if p == "oracle":
        return OCI_REGION_COUNTRY.get(r)
    return None


def _snowflake_region_country(account: str) -> tuple:
    """Parse a Snowflake account identifier into (country, region).

    Snowflake account identifiers embed the deployment region, e.g.
    "xy12345.eu-central-1.aws", "ab001.uaenorth.azure", or legacy
    "xy12345.eu-west-1". We scan the dot-separated segments against the
    AWS/Azure/GCP region maps. Returns (None, None) if unrecognised.
    """
    if not account:
        return None, None
    segments = account.lower().replace("_", "-").split(".")
    for seg in segments:
        for prov in ("aws", "azure", "gcp"):
            c = _region_to_country(prov, seg)
            if c:
                return c, seg
    return None, None


# ── Table creation (idempotent, called at import time via lifespan) ───────────

async def ensure_sovereignty_tables(db: AsyncSession):
    """Create Data Sovereignty tables if they don't exist (idempotent)."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS sovereignty_policies (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            name TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            jurisdiction TEXT NOT NULL,
            pack_key TEXT,
            data_classes JSONB NOT NULL DEFAULT '[]'::jsonb,
            allowed_regions JSONB NOT NULL DEFAULT '[]'::jsonb,
            action TEXT NOT NULL DEFAULT 'WARN',
            legal_basis TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS sovereignty_violations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            policy_id UUID,
            policy_name TEXT,
            jurisdiction TEXT,
            provider TEXT NOT NULL,
            resource_ref TEXT NOT NULL,
            resource_name TEXT,
            data_class TEXT,
            actual_region TEXT,
            actual_country TEXT,
            allowed_regions JSONB DEFAULT '[]'::jsonb,
            legal_basis TEXT,
            verdict TEXT NOT NULL DEFAULT 'violation',
            action TEXT NOT NULL DEFAULT 'WARN',
            confidence TEXT NOT NULL DEFAULT 'confirmed',
            status TEXT NOT NULL DEFAULT 'open',
            detected_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS sovereignty_actions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            violation_id UUID,
            action TEXT NOT NULL,
            provider TEXT,
            resource_ref TEXT,
            executed BOOLEAN NOT NULL DEFAULT FALSE,
            manual_required BOOLEAN NOT NULL DEFAULT FALSE,
            result_message TEXT,
            actor_email TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_sovereignty_policies_org ON sovereignty_policies(org_id)"
    ))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_sovereignty_actions_org ON sovereignty_actions(org_id)"
    ))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_sovereignty_violations_org ON sovereignty_violations(org_id)"
    ))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS idx_sovereignty_violations_org_status "
        "ON sovereignty_violations(org_id, status)"
    ))
    await db.commit()
    logger.info("Data Sovereignty tables ensured")


# ── Location oracle — where each asset physically lives (REAL connector data) ─

async def _resolve_m365_country(org_id, current_user, db: AsyncSession) -> Optional[str]:
    """Best-effort M365 tenant country via Graph /organization (same pattern as
    the Data Residency endpoint). Returns an ISO country code or None."""
    try:
        from backend.routers.saas_security import _get_valid_token, _decrypt
        from backend.models.db_models import OrgIntegration
        from backend.models.db_models import SaasIntegration

        access_token = None
        integ = (await db.execute(
            select(SaasIntegration).where(
                SaasIntegration.org_id == current_user.org_id,
                SaasIntegration.provider.in_(["teams", "sharepoint", "microsoft", "m365"]),
                SaasIntegration.status == "active",
            ).limit(1)
        )).scalar_one_or_none()
        if integ:
            access_token = await _get_valid_token(integ, db)
        if not access_token:
            m365 = (await db.execute(
                select(OrgIntegration).where(
                    OrgIntegration.org_id == current_user.org_id,
                    OrgIntegration.provider == "m365",
                    OrgIntegration.status == "active",
                ).limit(1)
            )).scalar_one_or_none()
            if m365 and m365.access_token_enc:
                access_token = _decrypt(m365.access_token_enc)
        if not access_token:
            return None
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(
                "https://graph.microsoft.com/v1.0/organization",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if r.status_code == 200:
                orgs = r.json().get("value", [])
                if orgs:
                    return orgs[0].get("countryLetterCode") or orgs[0].get("preferredDataLocation")
    except Exception as exc:
        logger.debug(f"sovereignty: m365 country lookup failed: {exc}")
    return None


def _classify_from_saas_row(label: Optional[str], categories) -> Optional[str]:
    """Derive a normalized data_class from a saas_data_items classification."""
    cats = set()
    if categories:
        for c in (categories if isinstance(categories, (list, tuple)) else []):
            cats.add(str(c).lower())
    lbl = (label or "").lower()
    joined = " ".join(cats) + " " + lbl
    if any(k in joined for k in ("phi", "health", "medical")):
        return "phi"
    if any(k in joined for k in ("pci", "card", "payment")):
        return "pci"
    if any(k in joined for k in ("financial", "bank", "iban")):
        return "financial"
    if "pii" in joined or "personal" in joined:
        return "pii"
    if lbl in ("highly_confidential", "highly confidential"):
        return "highly_confidential"
    if lbl == "confidential":
        return "confidential"
    return None


def _classify_from_dspm(category: Optional[str], metadata) -> Optional[str]:
    """Derive a normalized sovereignty data_class from a dspm_findings row.

    dspm_findings is the unified cross-cloud classification store written by the
    cross-cloud DLP engine and the DSPM sink for GCP / Snowflake / Oracle / SAP /
    Databricks / Salesforce / GitHub. It carries a single `category` plus a
    `metadata.categories` list using the heuristic vocabulary (pii, pci, phi,
    financial, credentials, source_code, …). We map only the classes that carry
    a residency obligation; infra-only categories (logs, config, network) return
    None so they stay out of hard violations.
    """
    cats: set[str] = set()
    if category:
        cats.add(str(category).lower())
    if metadata:
        md = metadata if isinstance(metadata, dict) else {}
        for c in (md.get("categories") or []):
            cats.add(str(c).lower())
    joined = " ".join(cats)
    if any(k in joined for k in ("phi", "health", "medical", "hipaa", "patient")):
        return "phi"
    if any(k in joined for k in ("pci", "card", "payment")):
        return "pci"
    if any(k in joined for k in ("financial", "bank", "iban", "ledger")):
        return "financial"
    if any(k in joined for k in ("pii", "personal", "customer", "employee", "kyc")):
        return "pii"
    if "credentials" in joined or "secret" in joined:
        return "highly_confidential"
    return None


async def resolve_asset_locations(org_id: str, current_user, db: AsyncSession) -> list[dict]:
    """Return a normalized list of data assets with physical region, jurisdiction,
    data class and confidence — built entirely from real connector tables.

    Each asset: {provider, resource_ref, resource_name, item_type,
                 physical_region, country, data_class, confidence}
    """
    assets: list[dict] = []

    def _add(provider, ref, name, item_type, region, country, data_class, confidence):
        assets.append({
            "provider": provider,
            "resource_ref": ref,
            "resource_name": name,
            "item_type": item_type,
            "physical_region": region,
            "country": country,
            "data_class": data_class,
            "confidence": confidence,
        })

    # 1. AWS storage resources (confirmed regions)
    try:
        rows = await db.execute(text("""
            SELECT COALESCE(name, resource_id) AS rname, resource_id, resource_type, region
            FROM aws_resources
            WHERE org_id = :oid AND region IS NOT NULL
              AND resource_type IN ('s3_bucket','rds_instance','efs_filesystem','ebs_volume','dynamodb_table','redshift_cluster')
            LIMIT 2000
        """), {"oid": org_id})
        for r in rows.mappings():
            country = _region_to_country("aws", r["region"])
            _add("aws", r["resource_id"] or r["rname"], r["rname"], r["resource_type"],
                 r["region"], country, "unclassified", "confirmed")
    except Exception as e:
        logger.debug(f"sovereignty: aws_resources scan skipped: {e}")

    # 2. Azure resources (confirmed regions). Azure schema uses `location`.
    try:
        rows = await db.execute(text("""
            SELECT COALESCE(name, resource_id) AS rname, resource_id, resource_type, location
            FROM azure_resources
            WHERE org_id = :oid AND location IS NOT NULL
            LIMIT 2000
        """), {"oid": org_id})
        for r in rows.mappings():
            country = _region_to_country("azure", r["location"])
            _add("azure", r["resource_id"] or r["rname"], r["rname"],
                 r["resource_type"] or "resource", r["location"], country,
                 "unclassified", "confirmed")
    except Exception as e:
        logger.debug(f"sovereignty: azure_resources scan skipped: {e}")

    # 3. GCP resources (confirmed regions)
    try:
        rows = await db.execute(text("""
            SELECT COALESCE(name, resource_id) AS rname, resource_id, resource_type, location
            FROM gcp_resources
            WHERE org_id = :oid AND location IS NOT NULL
            LIMIT 2000
        """), {"oid": org_id})
        for r in rows.mappings():
            country = _region_to_country("gcp", r["location"])
            _add("gcp", r["resource_id"] or r["rname"], r["rname"],
                 r["resource_type"] or "resource", r["location"], country,
                 "unclassified", "confirmed")
    except Exception as e:
        logger.debug(f"sovereignty: gcp_resources scan skipped: {e}")

    # 4. Oracle Cloud connections (confirmed regions)
    try:
        rows = await db.execute(text("""
            SELECT name, region FROM oracle_connections
            WHERE org_id = :oid AND status = 'active' AND region IS NOT NULL
        """), {"oid": org_id})
        for r in rows.mappings():
            country = _region_to_country("oracle", r["region"])
            _add("oracle", r["name"] or r["region"], r["name"], "oci_tenancy",
                 r["region"], country, "unclassified", "confirmed")
    except Exception as e:
        logger.debug(f"sovereignty: oracle_connections scan skipped: {e}")

    # 5. Databricks workspaces (region INFERRED from workspace URL)
    try:
        rows = await db.execute(text("""
            SELECT workspace_url FROM databricks_connections
            WHERE org_id = :oid AND status = 'active'
        """), {"oid": org_id})
        for r in rows.mappings():
            ws = (r["workspace_url"] or "").lower()
            if "eu-" in ws or "europe" in ws or ".eu." in ws:
                region, country = "eu-west", "IE"
            elif "ap-" in ws or "asia" in ws or ".sg." in ws:
                region, country = "ap-southeast", "SG"
            elif "au-" in ws or "australia" in ws:
                region, country = "ap-southeast-2", "AU"
            else:
                region, country = "us-east", "US"
            _add("databricks", ws or "workspace", ws, "workspace",
                 region, country, "unclassified", "inferred")
    except Exception as e:
        logger.debug(f"sovereignty: databricks scan skipped: {e}")

    # 6. SAP hosts (region INFERRED from hostname)
    try:
        rows = await db.execute(text("""
            SELECT name, system_id, host FROM sap_connections
            WHERE org_id = :oid AND status = 'active'
        """), {"oid": org_id})
        for r in rows.mappings():
            host = (r["host"] or "").lower()
            if ".eu" in host or ".de" in host or "europe" in host:
                region, country = "eu-central", "DE"
            elif ".us" in host or "-us-" in host:
                region, country = "us", "US"
            elif ".ap" in host or ".sg" in host or ".jp" in host:
                region, country = "ap-southeast", "SG"
            else:
                region, country = "eu-central", "DE"
            _add("sap", r["system_id"] or r["name"] or host, r["name"], "erp_system",
                 region, country, "unclassified", "inferred")
    except Exception as e:
        logger.debug(f"sovereignty: sap scan skipped: {e}")

    # 6b. Snowflake accounts — region parsed from the account identifier
    #     (e.g. "xy12345.eu-central-1.aws", "ab001.uaenorth.azure", legacy
    #     "xy12345.eu-west-1"). Snowflake data warehouses hold structured data
    #     so they are in scope for residency even without per-column scans.
    try:
        rows = await db.execute(text("""
            SELECT name, account FROM snowflake_connections
            WHERE org_id = :oid AND status = 'active'
        """), {"oid": org_id})
        for r in rows.mappings():
            acct = (r["account"] or "").lower()
            country, region = _snowflake_region_country(acct)
            _add("snowflake", acct or (r["name"] or "account"), r["name"], "warehouse",
                 region or acct, country, "unclassified", "confirmed" if country else "inferred")
    except Exception as e:
        logger.debug(f"sovereignty: snowflake scan skipped: {e}")

    # 7. M365 SharePoint/OneDrive/Teams data items (region = tenant country)
    #    Only include items that carry a real classification so verdicts are meaningful.
    m365_country = await _resolve_m365_country(org_id, current_user, db)
    try:
        rows = await db.execute(text("""
            SELECT provider, item_id, item_name, item_type,
                   classification_label, classification_categories
            FROM saas_data_items
            WHERE org_id = :oid
              AND provider IN ('sharepoint','onedrive','teams','microsoft','m365')
              AND (classification_label IS NOT NULL OR classification_categories IS NOT NULL)
            LIMIT 5000
        """), {"oid": org_id})
        for r in rows.mappings():
            data_class = _classify_from_saas_row(
                r["classification_label"], r["classification_categories"]
            )
            if not data_class:
                continue  # skip unclassified M365 items — no meaningful sovereignty verdict
            country = m365_country
            confidence = "confirmed" if country else "inferred"
            _add(r["provider"], r["item_id"], r["item_name"], r["item_type"] or "file",
                 country or "unknown", country, data_class, confidence)
    except Exception as e:
        logger.debug(f"sovereignty: saas_data_items scan skipped: {e}")

    # 8. Cloud storage items that were classified by DSPM (upgrade data_class on
    #    matching cloud resources so cloud PII is caught, not just M365).
    try:
        rows = await db.execute(text("""
            SELECT provider, item_id, classification_label, classification_categories
            FROM saas_data_items
            WHERE org_id = :oid
              AND provider IN ('aws','azure','gcp','oracle')
              AND (classification_label IS NOT NULL OR classification_categories IS NOT NULL)
            LIMIT 5000
        """), {"oid": org_id})
        by_ref = {(a["provider"], a["resource_ref"]): a for a in assets}
        for r in rows.mappings():
            dc = _classify_from_saas_row(r["classification_label"], r["classification_categories"])
            if not dc:
                continue
            key = (r["provider"], r["item_id"])
            if key in by_ref:
                by_ref[key]["data_class"] = dc
    except Exception as e:
        logger.debug(f"sovereignty: cloud classification join skipped: {e}")

    # 9. dspm_findings — the unified cross-cloud classification store. This is
    #    the DB-level coverage path for GCP / Snowflake / Oracle / SAP /
    #    Databricks / Salesforce, where structured data is classified per
    #    object (table/column/bucket) rather than at the connection level.
    #    For each sensitive finding we either UPGRADE the data_class of the
    #    matching infra asset, or ADD a new asset so the sensitive object is
    #    evaluated for residency even when the connection-level row is
    #    unclassified. Region is taken from the finding when present, else
    #    inherited from the provider's connector-level asset.
    try:
        # Cloud string in dspm_findings maps 1:1 to our provider names.
        provider_region = {}
        for a in assets:
            provider_region.setdefault(
                a["provider"], (a.get("physical_region"), a.get("country"), a.get("confidence"))
            )
        by_ref = {(a["provider"], str(a["resource_ref"])): a for a in assets}
        added_keys = set()
        rows = await db.execute(text("""
            SELECT cloud, resource_type, resource_id, object_key, category,
                   region, metadata
            FROM dspm_findings
            WHERE org_id = :oid AND resolved_at IS NULL
            LIMIT 5000
        """), {"oid": org_id})
        for r in rows.mappings():
            provider = (r["cloud"] or "").lower()
            if not provider:
                continue
            dc = _classify_from_dspm(r["category"], r["metadata"])
            if not dc:
                continue
            ref = str(r["resource_id"] or r["object_key"] or "").strip()
            if not ref:
                continue
            key = (provider, ref)
            # Upgrade an existing infra asset in place (keeps its confirmed region).
            if key in by_ref:
                if by_ref[key].get("data_class") in (None, "unclassified"):
                    by_ref[key]["data_class"] = dc
                continue
            # Resolve region: prefer the finding's own region, else inherit
            # the provider's connector-level region.
            fregion = (r["region"] or "").strip() or None
            fcountry = None
            confidence = "inferred"
            if fregion:
                for prov in (provider, "aws", "azure", "gcp"):
                    fcountry = _region_to_country(prov, fregion)
                    if fcountry:
                        break
                confidence = "confirmed" if fcountry else "inferred"
            if not fcountry:
                inherited = provider_region.get(provider)
                if inherited:
                    fregion = fregion or inherited[0]
                    fcountry = inherited[1]
                    confidence = inherited[2] or "inferred"
            dedup = (provider, ref, dc)
            if dedup in added_keys:
                continue
            added_keys.add(dedup)
            _add(provider, ref, r["object_key"] or ref,
                 r["resource_type"] or "data_object", fregion, fcountry, dc, confidence)
    except Exception as e:
        logger.debug(f"sovereignty: dspm_findings classification join skipped: {e}")

    return assets


# ── Evaluation engine ─────────────────────────────────────────────────────────

def _asset_matches_policy(asset: dict, policy: dict) -> bool:
    """True if the policy's data classes cover this asset."""
    dcs = policy.get("data_classes") or []
    if not dcs or "all" in dcs:
        return asset.get("data_class") not in (None, "unclassified") or True
    return asset.get("data_class") in dcs


def _asset_in_allowed(asset: dict, allowed: list[str]) -> bool:
    """True if the asset physically resides within an allowed region/country."""
    allowed_set = {str(a).strip().lower() for a in (allowed or [])}
    region = (asset.get("physical_region") or "").lower()
    country = (asset.get("country") or "").lower()
    if region and region in allowed_set:
        return True
    if country and country in allowed_set:
        return True
    return False


async def run_sovereignty_scan(org_id: str, current_user, db: AsyncSession) -> dict:
    """Evaluate all assets against all enabled policies. Idempotent: clears prior
    violations + open sovereignty alerts for the org, then regenerates."""
    # Load enabled policies
    prows = (await db.execute(text("""
        SELECT id, name, jurisdiction, data_classes, allowed_regions, action, legal_basis
        FROM sovereignty_policies WHERE org_id = :oid AND enabled = TRUE
    """), {"oid": org_id})).mappings().all()
    policies = []
    for p in prows:
        policies.append({
            "id": str(p["id"]),
            "name": p["name"],
            "jurisdiction": p["jurisdiction"],
            "data_classes": p["data_classes"] if isinstance(p["data_classes"], list) else (json.loads(p["data_classes"]) if p["data_classes"] else []),
            "allowed_regions": p["allowed_regions"] if isinstance(p["allowed_regions"], list) else (json.loads(p["allowed_regions"]) if p["allowed_regions"] else []),
            "action": p["action"],
            "legal_basis": p["legal_basis"],
        })

    assets = await resolve_asset_locations(org_id, current_user, db)

    # Clear prior state (idempotent re-scan)
    await db.execute(text("DELETE FROM sovereignty_violations WHERE org_id = :oid"), {"oid": org_id})
    await db.execute(text(
        "DELETE FROM saas_alerts WHERE org_id = :oid AND provider = 'sovereignty' AND status = 'open'"
    ), {"oid": org_id})

    violations = 0
    assets_evaluated = 0
    for asset in assets:
        # Only evaluate assets that carry a data class (unclassified cloud infra
        # is reported in posture but not flagged as a hard violation).
        if asset.get("data_class") in (None, "unclassified"):
            continue
        assets_evaluated += 1
        for policy in policies:
            if not _asset_matches_policy(asset, policy):
                continue
            if _asset_in_allowed(asset, policy["allowed_regions"]):
                continue
            # Violation
            violations += 1
            action = policy["action"] if policy["action"] in VALID_ACTIONS else "WARN"
            severity = ACTION_SEVERITY.get(action, "medium")
            vid = str(uuid.uuid4())
            await db.execute(text("""
                INSERT INTO sovereignty_violations
                (id, org_id, policy_id, policy_name, jurisdiction, provider, resource_ref,
                 resource_name, data_class, actual_region, actual_country, allowed_regions,
                 legal_basis, verdict, action, confidence, status)
                VALUES (:id, :oid, :pid, :pname, :juris, :provider, :ref, :rname, :dc,
                        :region, :country, :allowed, :legal, 'violation', :action, :conf, 'open')
            """), {
                "id": vid, "oid": org_id, "pid": policy["id"], "pname": policy["name"],
                "juris": policy["jurisdiction"], "provider": asset["provider"],
                "ref": str(asset["resource_ref"])[:500], "rname": asset.get("resource_name"),
                "dc": asset["data_class"], "region": asset.get("physical_region"),
                "country": asset.get("country"),
                "allowed": json.dumps(policy["allowed_regions"]),
                "legal": policy["legal_basis"], "action": action,
                "conf": asset.get("confidence", "confirmed"),
            })
            # Mirror into the unified alerts pipeline
            title = f"Sovereignty violation: {asset.get('resource_name') or asset['resource_ref']} in {asset.get('country') or asset.get('physical_region')}"
            desc = (
                f"{policy['jurisdiction']} policy '{policy['name']}' requires {asset['data_class']} "
                f"data to reside within {', '.join(policy['allowed_regions'][:6])}"
                f"{'…' if len(policy['allowed_regions']) > 6 else ''}. This {asset['provider'].upper()} "
                f"asset resides in {asset.get('physical_region')} ({asset.get('country') or 'unknown'}). "
                f"Legal basis: {policy['legal_basis']}."
            )
            await db.execute(text("""
                INSERT INTO saas_alerts
                (id, org_id, provider, alert_type, severity, title, description,
                 resource_id, resource_name, classification_result, status)
                VALUES (:id, :oid, 'sovereignty', 'sovereignty_violation', :sev, :title, :desc,
                        :rid, :rname, :cls, 'open')
            """), {
                "id": str(uuid.uuid4()), "oid": org_id, "sev": severity,
                "title": title[:500], "desc": desc,
                "rid": str(asset["resource_ref"])[:500], "rname": asset.get("resource_name"),
                "cls": json.dumps({
                    "jurisdiction": policy["jurisdiction"],
                    "data_class": asset["data_class"],
                    "actual_region": asset.get("physical_region"),
                    "actual_country": asset.get("country"),
                    "allowed_regions": policy["allowed_regions"],
                    "legal_basis": policy["legal_basis"],
                    "action": action,
                    "confidence": asset.get("confidence"),
                }),
            })

    await db.commit()
    return {
        "assets_total": len(assets),
        "assets_evaluated": assets_evaluated,
        "policies_evaluated": len(policies),
        "violations": violations,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Pydantic models ────────────────────────────────────────────────────────────

class SovereigntyPolicyCreate(BaseModel):
    name: str
    jurisdiction: str
    data_classes: list[str] = []
    allowed_regions: list[str] = []
    action: str = "WARN"
    legal_basis: Optional[str] = None
    enabled: bool = True
    pack_key: Optional[str] = None


class SovereigntyPolicyUpdate(BaseModel):
    name: Optional[str] = None
    jurisdiction: Optional[str] = None
    data_classes: Optional[list[str]] = None
    allowed_regions: Optional[list[str]] = None
    action: Optional[str] = None
    legal_basis: Optional[str] = None
    enabled: Optional[bool] = None


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.get("/jurisdictions")
async def list_jurisdiction_packs(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the prebuilt jurisdiction packs (borders + transfer rules + citations)."""
    await _require_enterprise(current_user, db)
    return {
        "packs": [
            {"key": k, **v} for k, v in JURISDICTION_PACKS.items()
        ],
        "data_classes": KNOWN_DATA_CLASSES,
        "actions": list(VALID_ACTIONS),
    }


@router.get("/policies")
async def list_policies(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List sovereignty policies for the org."""
    await _require_enterprise(current_user, db)
    rows = (await db.execute(text("""
        SELECT id, name, enabled, jurisdiction, pack_key, data_classes, allowed_regions,
               action, legal_basis, created_at, updated_at
        FROM sovereignty_policies WHERE org_id = :oid ORDER BY created_at DESC
    """), {"oid": str(current_user.org_id)})).mappings().all()
    out = []
    for r in rows:
        out.append({
            "id": str(r["id"]),
            "name": r["name"],
            "enabled": r["enabled"],
            "jurisdiction": r["jurisdiction"],
            "pack_key": r["pack_key"],
            "data_classes": r["data_classes"] if isinstance(r["data_classes"], list) else json.loads(r["data_classes"] or "[]"),
            "allowed_regions": r["allowed_regions"] if isinstance(r["allowed_regions"], list) else json.loads(r["allowed_regions"] or "[]"),
            "action": r["action"],
            "legal_basis": r["legal_basis"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        })
    return {"policies": out, "total": len(out)}


@router.post("/policies", status_code=201)
async def create_policy(
    body: SovereigntyPolicyCreate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a sovereignty policy."""
    await _require_enterprise(current_user, db)
    if body.action not in VALID_ACTIONS:
        raise HTTPException(status_code=422, detail=f"action must be one of {VALID_ACTIONS}")
    pid = str(uuid.uuid4())
    await db.execute(text("""
        INSERT INTO sovereignty_policies
        (id, org_id, name, enabled, jurisdiction, pack_key, data_classes, allowed_regions, action, legal_basis)
        VALUES (:id, :oid, :name, :enabled, :juris, :pack, :dcs, :regions, :action, :legal)
    """), {
        "id": pid, "oid": str(current_user.org_id), "name": body.name,
        "enabled": body.enabled, "juris": body.jurisdiction, "pack": body.pack_key,
        "dcs": json.dumps(body.data_classes), "regions": json.dumps(body.allowed_regions),
        "action": body.action, "legal": body.legal_basis,
    })
    await db.commit()
    return {"id": pid, "ok": True}


@router.post("/policies/seed-defaults", status_code=201)
async def seed_default_policies(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Seed policies from all jurisdiction packs (skips packs already seeded)."""
    await _require_enterprise(current_user, db)
    existing = {r[0] for r in (await db.execute(text(
        "SELECT pack_key FROM sovereignty_policies WHERE org_id = :oid AND pack_key IS NOT NULL"
    ), {"oid": str(current_user.org_id)})).fetchall()}
    created = []
    for key, pack in JURISDICTION_PACKS.items():
        if key in existing:
            continue
        pid = str(uuid.uuid4())
        await db.execute(text("""
            INSERT INTO sovereignty_policies
            (id, org_id, name, enabled, jurisdiction, pack_key, data_classes, allowed_regions, action, legal_basis)
            VALUES (:id, :oid, :name, TRUE, :juris, :pack, :dcs, :regions, :action, :legal)
        """), {
            "id": pid, "oid": str(current_user.org_id), "name": pack["name"],
            "juris": pack["jurisdiction"], "pack": key,
            "dcs": json.dumps(pack["data_classes"]),
            "regions": json.dumps(pack["allowed_regions"]),
            "action": pack["action"], "legal": pack["legal_basis"],
        })
        created.append(key)
    await db.commit()
    return {"created": created, "skipped": sorted(existing)}


@router.patch("/policies/{policy_id}")
async def update_policy(
    policy_id: str,
    body: SovereigntyPolicyUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a sovereignty policy."""
    await _require_enterprise(current_user, db)
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=422, detail="No fields to update")
    if "action" in updates and updates["action"] not in VALID_ACTIONS:
        raise HTTPException(status_code=422, detail=f"action must be one of {VALID_ACTIONS}")
    if "data_classes" in updates:
        updates["data_classes"] = json.dumps(updates["data_classes"])
    if "allowed_regions" in updates:
        updates["allowed_regions"] = json.dumps(updates["allowed_regions"])
    updates["updated_at"] = datetime.now(timezone.utc)
    set_clause = ", ".join(f"{k}=:{k}" for k in updates)
    params = {**updates, "id": policy_id, "oid": str(current_user.org_id)}
    result = await db.execute(
        text(f"UPDATE sovereignty_policies SET {set_clause} WHERE id=:id AND org_id=:oid"),
        params,
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"ok": True}


@router.delete("/policies/{policy_id}")
async def delete_policy(
    policy_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a sovereignty policy."""
    await _require_enterprise(current_user, db)
    result = await db.execute(
        text("DELETE FROM sovereignty_policies WHERE id=:id AND org_id=:oid"),
        {"id": policy_id, "oid": str(current_user.org_id)},
    )
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"ok": True}


@router.get("/violations")
async def list_violations(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List detected sovereignty violations for the org."""
    await _require_enterprise(current_user, db)
    rows = (await db.execute(text("""
        SELECT id, policy_name, jurisdiction, provider, resource_ref, resource_name,
               data_class, actual_region, actual_country, allowed_regions, legal_basis,
               verdict, action, confidence, status, detected_at
        FROM sovereignty_violations WHERE org_id = :oid
        ORDER BY detected_at DESC LIMIT 500
    """), {"oid": str(current_user.org_id)})).mappings().all()
    out = []
    for r in rows:
        out.append({
            "id": str(r["id"]),
            "policy_name": r["policy_name"],
            "jurisdiction": r["jurisdiction"],
            "provider": r["provider"],
            "resource_ref": r["resource_ref"],
            "resource_name": r["resource_name"],
            "data_class": r["data_class"],
            "actual_region": r["actual_region"],
            "actual_country": r["actual_country"],
            "allowed_regions": r["allowed_regions"] if isinstance(r["allowed_regions"], list) else json.loads(r["allowed_regions"] or "[]"),
            "legal_basis": r["legal_basis"],
            "verdict": r["verdict"],
            "action": r["action"],
            "confidence": r["confidence"],
            "status": r["status"],
            "detected_at": r["detected_at"].isoformat() if r["detected_at"] else None,
        })
    return {"violations": out, "total": len(out)}


@router.post("/scan")
async def trigger_scan(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Run a sovereignty evaluation now (posture batch)."""
    await _require_enterprise(current_user, db)
    result = await run_sovereignty_scan(str(current_user.org_id), current_user, db)
    return {"ok": True, **result}


# ── Enforcement ───────────────────────────────────────────────────────────────
# Data residency cannot be "moved" via API — you can't relocate a bucket to a
# new country with one call. So sovereignty enforcement takes REAL exposure-
# reduction actions where possible (e.g. AWS S3 Block Public Access) and returns
# precise manual remediation steps where an API action can't fix residency.
# Every attempt is recorded in sovereignty_actions for auditor evidence.

async def _load_aws_service_for_org(org_id: str, db: AsyncSession):
    """Build a real AWSSecurityService from the org's stored AWS credentials."""
    row = (await db.execute(text("""
        SELECT access_key_id_enc, secret_access_key_enc, default_region
        FROM aws_connections WHERE org_id = :oid AND status = 'active' LIMIT 1
    """), {"oid": org_id})).mappings().first()
    if not row:
        return None
    from backend.routers.aws_connector import _decrypt as _aws_decrypt
    from backend.services.aws_security_service import AWSSecurityService
    return AWSSecurityService(
        access_key_id=_aws_decrypt(row["access_key_id_enc"]),
        secret_access_key=_aws_decrypt(row["secret_access_key_enc"]),
        region=row["default_region"] or "us-east-1",
    )


async def _revoke_m365_external_sharing(org_id: str, resource_ref: str, db: AsyncSession) -> dict:
    """Revoke external / anyone-link sharing on an M365 (SharePoint/OneDrive/Teams)
    item to cut cross-border exposure immediately. Returns {ok, revoked, message}.

    The driveItem + its permissions are resolved from the item's webUrl via the
    Graph /shares endpoint (which returns parentReference.driveId + item id), then
    every external/anonymous permission is DELETEd. Residency itself is unchanged —
    this is an exposure-reduction action, mirrored on the AWS S3 BPA path.
    """
    import base64 as _b64
    from backend.routers.saas_security import _get_valid_token, _decrypt
    from backend.models.db_models import SaasIntegration, OrgIntegration

    # Resolve a Graph access token from the org's M365 integration.
    integ = (await db.execute(
        select(SaasIntegration).where(
            SaasIntegration.org_id == uuid.UUID(org_id),
            SaasIntegration.provider.in_(["teams", "sharepoint", "onedrive", "microsoft", "m365"]),
            SaasIntegration.status == "active",
        ).limit(1)
    )).scalar_one_or_none()
    token = await _get_valid_token(integ, db) if integ else None
    if not token:
        m365 = (await db.execute(
            select(OrgIntegration).where(
                OrgIntegration.org_id == uuid.UUID(org_id),
                OrgIntegration.provider == "m365",
                OrgIntegration.status == "active",
            ).limit(1)
        )).scalar_one_or_none()
        if m365 and m365.access_token_enc:
            token = _decrypt(m365.access_token_enc)
    if not token:
        return {"ok": False, "revoked": 0, "message": "No active M365 connection/token to revoke sharing."}

    # We need the item's webUrl to resolve it via the shares API. It lives in
    # saas_data_items (populated by the SaaS scanner).
    row = (await db.execute(text("""
        SELECT item_url, provider FROM saas_data_items
        WHERE org_id = :oid AND item_id = :ref LIMIT 1
    """), {"oid": org_id, "ref": resource_ref})).mappings().first()
    web_url = (row or {}).get("item_url")
    if not web_url:
        return {"ok": False, "revoked": 0,
                "message": "Item webUrl not found in inventory — re-run an M365 scan, then retry."}

    # Graph share id encoding: "u!" + base64url(webUrl) with padding stripped.
    share_id = "u!" + _b64.urlsafe_b64encode(web_url.encode()).decode().rstrip("=")
    headers = {"Authorization": f"Bearer {token}"}
    revoked = 0
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            di = await c.get(
                f"https://graph.microsoft.com/v1.0/shares/{share_id}/driveItem?$expand=permissions",
                headers=headers,
            )
            if di.status_code != 200:
                return {"ok": False, "revoked": 0,
                        "message": f"Graph could not resolve the item ({di.status_code})."}
            item = di.json()
            drive_id = (item.get("parentReference") or {}).get("driveId")
            item_id = item.get("id")
            if not drive_id or not item_id:
                return {"ok": False, "revoked": 0, "message": "Item drive/id unresolved from Graph."}
            for p in item.get("permissions", []) or []:
                link = p.get("link") or {}
                is_anon = link.get("scope") == "anonymous"
                is_external = False
                grantees = list(p.get("grantedToIdentitiesV2") or [])
                for g in (p.get("grantedToV2"), p.get("grantedTo")):
                    if g:
                        grantees.append(g)
                for g in grantees:
                    email = ((g or {}).get("user") or {}).get("email", "").lower()
                    if email and "#ext#" in email:
                        is_external = True
                if not (is_anon or is_external):
                    continue
                pid = p.get("id")
                if not pid:
                    continue
                dr = await c.delete(
                    f"https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{item_id}/permissions/{pid}",
                    headers=headers,
                )
                if dr.status_code in (200, 204):
                    revoked += 1
    except Exception as exc:
        logger.warning(f"sovereignty: m365 revoke failed for {resource_ref}: {exc}")
        return {"ok": False, "revoked": revoked, "message": f"Revoke error: {exc}"}

    # Reflect the reduced exposure in the inventory so the UI/next scan agree.
    if revoked:
        try:
            await db.execute(text("""
                UPDATE saas_data_items SET sharing_scope = 'private'
                WHERE org_id = :oid AND item_id = :ref
            """), {"oid": org_id, "ref": resource_ref})
        except Exception:
            pass
    msg = (f"Revoked {revoked} external/anyone-link share(s)."
           if revoked else "No external shares were present — exposure already contained.")
    return {"ok": True, "revoked": revoked, "message": msg}


async def _execute_enforcement(v: dict, org_id: str, db: AsyncSession) -> dict:
    """Execute the enforcement action for a violation. Returns
    {executed, manual_required, message}."""
    provider = (v.get("provider") or "").lower()
    action = (v.get("action") or "WARN").upper()
    resource = v.get("resource_name") or v.get("resource_ref")
    region = v.get("actual_region")
    allowed = ", ".join(v.get("allowed_regions") or [])

    # NOTIFY — record an owner/DPO notification (no data mutation).
    if action == "NOTIFY":
        return {"executed": True, "manual_required": False,
                "message": f"Notification recorded for {provider.upper()} resource '{resource}'."}

    # AWS S3 — REAL action: enforce Block Public Access to cut exposure while the
    # bucket sits in a disallowed jurisdiction.
    if provider == "aws" and action in ("BLOCK", "QUARANTINE"):
        svc = await _load_aws_service_for_org(org_id, db)
        if not svc:
            return {"executed": False, "manual_required": True,
                    "message": "No active AWS connection found to execute enforcement."}
        res = await svc.block_s3_public_access(str(v.get("resource_ref") or resource), region)
        if res.get("ok"):
            return {"executed": True, "manual_required": False,
                    "message": f"{res['message']} Note: residency is unchanged — migrate to {allowed} to fully comply."}
        return {"executed": False, "manual_required": True, "message": res.get("message", "enforcement failed")}

    # M365 SharePoint/OneDrive/Teams — REAL action: revoke external / anyone-link
    # sharing to cut cross-border exposure immediately (residency needs a Multi-Geo
    # move, which stays a manual step, but exposure is contained now).
    if provider in ("sharepoint", "onedrive", "teams") and action in ("BLOCK", "QUARANTINE"):
        res = await _revoke_m365_external_sharing(org_id, str(v.get("resource_ref") or resource), db)
        if res.get("ok"):
            return {"executed": True, "manual_required": False,
                    "message": f"{res['message']} Residency unchanged — move to a Multi-Geo location in {allowed} to fully comply."}
        return {"executed": False, "manual_required": True, "message": res.get("message", "enforcement failed")}

    # All other providers — residency correction requires data migration, which
    # is not an API action. Return precise manual steps (honest, no fake success).
    steps = {
        "azure": "Azure portal → move the resource/storage account to a region within the allowed set, or enable customer-managed geo constraints.",
        "gcp": "GCP console → recreate the bucket/dataset in an allowed region (GCS/BigQuery location is immutable) and migrate data.",
        "oracle": "OCI console → provision the resource in an allowed region and migrate; OCI region is fixed per resource.",
        "snowflake": "Snowflake → data lives in the account's cloud region; replicate to an account in an allowed region or use a data-clean-room boundary.",
        "sap": "Coordinate with SAP Basis to host the system in an allowed region / datacentre.",
        "databricks": "Databricks → workspace region is fixed; create a workspace in an allowed region and migrate jobs/data.",
        "sharepoint": "M365 Admin → use a Multi-Geo satellite location in an allowed region and move the site/mailbox; also revoke external sharing to reduce exposure now.",
        "onedrive": "M365 Admin → move the user's OneDrive to an allowed Multi-Geo location; revoke external sharing to reduce exposure now.",
        "teams": "M365 Admin → apply the allowed Multi-Geo location for the team's data; revoke guest access to reduce exposure now.",
    }
    step = steps.get(provider, "Migrate the resource to a region within the allowed set, or approve the placement by updating the policy.")
    return {"executed": False, "manual_required": True,
            "message": f"Residency violation cannot be auto-corrected via API. {step} Allowed regions: {allowed}."}


@router.post("/violations/{violation_id}/enforce")
async def enforce_violation(
    violation_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute the policy's enforcement action for a single violation."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    row = (await db.execute(text("""
        SELECT id, policy_name, jurisdiction, provider, resource_ref, resource_name,
               data_class, actual_region, actual_country, allowed_regions, action, status
        FROM sovereignty_violations WHERE id = :id AND org_id = :oid
    """), {"id": violation_id, "oid": org_id})).mappings().first()
    if not row:
        raise HTTPException(status_code=404, detail="Violation not found")

    v = dict(row)
    v["allowed_regions"] = v["allowed_regions"] if isinstance(v["allowed_regions"], list) else json.loads(v["allowed_regions"] or "[]")
    result = await _execute_enforcement(v, org_id, db)

    # Audit trail
    await db.execute(text("""
        INSERT INTO sovereignty_actions
        (id, org_id, violation_id, action, provider, resource_ref, executed,
         manual_required, result_message, actor_email)
        VALUES (:id, :oid, :vid, :action, :provider, :ref, :executed, :manual, :msg, :actor)
    """), {
        "id": str(uuid.uuid4()), "oid": org_id, "vid": violation_id,
        "action": v.get("action"), "provider": v.get("provider"),
        "ref": str(v.get("resource_ref"))[:500], "executed": result["executed"],
        "manual": result["manual_required"], "msg": result["message"],
        "actor": getattr(current_user, "email", None),
    })
    # Update violation status
    new_status = "enforced" if result["executed"] else "manual_required"
    await db.execute(text(
        "UPDATE sovereignty_violations SET status = :s WHERE id = :id AND org_id = :oid"
    ), {"s": new_status, "id": violation_id, "oid": org_id})
    # Resolve the mirrored alert if fully enforced
    if result["executed"]:
        await db.execute(text("""
            UPDATE saas_alerts SET status = 'resolved', resolved_at = NOW()
            WHERE org_id = :oid AND provider = 'sovereignty' AND resource_id = :ref AND status = 'open'
        """), {"oid": org_id, "ref": str(v.get("resource_ref"))[:500]})
    await db.commit()
    return {"ok": True, "violation_id": violation_id, "status": new_status, **result}


@router.get("/actions")
async def list_actions(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List the sovereignty enforcement audit trail."""
    await _require_enterprise(current_user, db)
    rows = (await db.execute(text("""
        SELECT id, violation_id, action, provider, resource_ref, executed,
               manual_required, result_message, actor_email, created_at
        FROM sovereignty_actions WHERE org_id = :oid
        ORDER BY created_at DESC LIMIT 500
    """), {"oid": str(current_user.org_id)})).mappings().all()
    return {"actions": [
        {
            "id": str(r["id"]),
            "violation_id": str(r["violation_id"]) if r["violation_id"] else None,
            "action": r["action"],
            "provider": r["provider"],
            "resource_ref": r["resource_ref"],
            "executed": r["executed"],
            "manual_required": r["manual_required"],
            "result_message": r["result_message"],
            "actor_email": r["actor_email"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        } for r in rows
    ], "total": len(rows)}


@router.get("/overview")
async def get_overview(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sovereignty scorecard: per-jurisdiction posture, violation counts, coverage."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    # Policy count
    pol_rows = (await db.execute(text("""
        SELECT jurisdiction, COUNT(*) AS n, SUM(CASE WHEN enabled THEN 1 ELSE 0 END) AS enabled_n
        FROM sovereignty_policies WHERE org_id = :oid GROUP BY jurisdiction
    """), {"oid": org_id})).mappings().all()
    total_policies = sum(r["n"] for r in pol_rows)

    # Violation aggregates
    v_rows = (await db.execute(text("""
        SELECT jurisdiction, action, confidence, COUNT(*) AS n
        FROM sovereignty_violations WHERE org_id = :oid AND status = 'open'
        GROUP BY jurisdiction, action, confidence
    """), {"oid": org_id})).mappings().all()
    total_violations = sum(r["n"] for r in v_rows)

    by_jurisdiction: dict[str, dict] = {}
    for r in pol_rows:
        by_jurisdiction.setdefault(r["jurisdiction"], {
            "jurisdiction": r["jurisdiction"], "policies": 0, "violations": 0,
            "critical": 0, "inferred": 0,
        })
        by_jurisdiction[r["jurisdiction"]]["policies"] = r["n"]
    for r in v_rows:
        j = by_jurisdiction.setdefault(r["jurisdiction"], {
            "jurisdiction": r["jurisdiction"], "policies": 0, "violations": 0,
            "critical": 0, "inferred": 0,
        })
        j["violations"] += r["n"]
        if r["action"] == "BLOCK":
            j["critical"] += r["n"]
        if r["confidence"] == "inferred":
            j["inferred"] += r["n"]

    # Provider breakdown of violations
    prov_rows = (await db.execute(text("""
        SELECT provider, COUNT(*) AS n FROM sovereignty_violations
        WHERE org_id = :oid AND status = 'open' GROUP BY provider
    """), {"oid": org_id})).mappings().all()

    # Data-class breakdown
    dc_rows = (await db.execute(text("""
        SELECT data_class, COUNT(*) AS n FROM sovereignty_violations
        WHERE org_id = :oid AND status = 'open' GROUP BY data_class
    """), {"oid": org_id})).mappings().all()

    return {
        "total_policies": total_policies,
        "total_violations": total_violations,
        "by_jurisdiction": sorted(by_jurisdiction.values(), key=lambda x: -x["violations"]),
        "by_provider": [{"provider": r["provider"], "count": r["n"]} for r in prov_rows],
        "by_data_class": [{"data_class": r["data_class"], "count": r["n"]} for r in dc_rows],
        "packs_available": len(JURISDICTION_PACKS),
    }
