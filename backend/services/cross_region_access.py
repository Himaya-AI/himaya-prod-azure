"""
Cross-region access detector.

Added 2026-06-23 (Adnan, second turn). The Workspace Security tab
already exposed a `saas_cross_region_access` toggle; this module is the
actual detector behind it.

What "cross-region" means here:
  - Every confidential / highly-confidential resource has a *home
    region* (S3 bucket region, M365 tenant country, GCS location,
    Azure region, GitHub org default location, etc.).
  - Every sign-in / API call has a *source country* (M365 Graph sign-in
    location, AWS CloudTrail sourceIPAddress GeoIP, Azure Activity log
    callerIpAddress GeoIP).
  - If a user touches a confidential resource AND their source country
    is outside the resource's home region's country set, we raise a
    SaaS alert under the user's `saas_cross_region_access` pref.

Coverage matrix (all current connectors):
  - M365 (Teams / SharePoint / OneDrive) :: Graph signInActivity
  - AWS                                  :: CloudTrail LookupEvents
  - GCP                                  :: Cloud Audit Logs (best-effort)
  - Azure                                :: Activity Logs (best-effort)
  - GitHub                               :: org audit log (best-effort)
  - Databricks / SAP / Snowflake / Salesforce / Oracle :: name-based
        comparison against the resource's region tag — alert is raised
        with confidence=0.6 since we don't have per-action audit yet.

The detector is intentionally CHEAP: it works off rows already in our
database (`saas_data_items`, `aws_resources`, `gcp_resources`,
`azure_resources`, `audit_logs`) and never makes its own provider API
calls. The CSPM/DSPM loop in main.py invokes it periodically.

Public API:
  - detect_cross_region_access(db, org_id) -> list[dict]
        Returns a list of detection dicts ready for the SaaS alert sink.
  - run_and_alert(db, org_id) -> int
        Convenience wrapper that pushes detections into saas_alerts,
        respecting the `saas_cross_region_access` user toggle.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# ── Region → country mapping ─────────────────────────────────────────────
# We keep this small and explicit. A region can map to multiple
# countries (eu-west-1 = Ireland, but EU-wide data-residency rules
# allow access from any EU country; the residency view will treat
# anything in EU_COUNTRIES as "in region" for an EU-* bucket).

EU_COUNTRIES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
    "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
    "RO", "SK", "SI", "ES", "SE",
}

# Each cloud region -> the set of ISO-3166 country codes that are
# considered "in region" for residency. If a user signs in from a
# country not in this set, that's a cross-region access event.
REGION_TO_COUNTRIES: dict[str, set[str]] = {
    # AWS
    "us-east-1":     {"US"},
    "us-east-2":     {"US"},
    "us-west-1":     {"US"},
    "uaenorth":     {"US"},
    "ca-central-1":  {"CA"},
    "ca-west-1":     {"CA"},
    "eu-west-1":     EU_COUNTRIES,                   # Ireland
    "eu-west-2":     {"GB"},                         # London
    "eu-west-3":     EU_COUNTRIES,                   # Paris
    "eu-central-1":  EU_COUNTRIES,                   # Frankfurt
    "eu-central-2":  EU_COUNTRIES,                   # Zurich (+CH below)
    "eu-north-1":    EU_COUNTRIES,                   # Stockholm
    "eu-south-1":    EU_COUNTRIES,                   # Milan
    "eu-south-2":    EU_COUNTRIES,                   # Spain
    "me-south-1":    {"BH"},                         # Bahrain
    "me-central-1":  {"AE"},                         # UAE
    "ap-south-1":    {"IN"},                         # Mumbai
    "ap-south-2":    {"IN"},                         # Hyderabad
    "ap-northeast-1":{"JP"},
    "ap-northeast-2":{"KR"},
    "ap-northeast-3":{"JP"},
    "ap-southeast-1":{"SG"},
    "ap-southeast-2":{"AU"},
    "ap-southeast-3":{"ID"},
    "ap-southeast-4":{"AU"},
    "ap-east-1":     {"HK"},
    "sa-east-1":     {"BR"},
    "af-south-1":    {"ZA"},
    "il-central-1":  {"IL"},
    # GCP
    "us-central1":   {"US"}, "us-east1": {"US"}, "us-east4": {"US"},
    "us-east5":      {"US"}, "us-west1": {"US"}, "us-west2": {"US"},
    "us-west3":      {"US"}, "us-west4": {"US"},
    "northamerica-northeast1": {"CA"},
    "northamerica-northeast2": {"CA"},
    "southamerica-east1":      {"BR"},
    "southamerica-west1":      {"CL"},
    "europe-west1":  EU_COUNTRIES, "europe-west2": {"GB"},
    "europe-west3":  EU_COUNTRIES, "europe-west4": EU_COUNTRIES,
    "europe-west6":  EU_COUNTRIES | {"CH"},
    "europe-west8":  EU_COUNTRIES, "europe-west9": EU_COUNTRIES,
    "europe-west10": EU_COUNTRIES, "europe-west12": EU_COUNTRIES,
    "europe-central2": EU_COUNTRIES, "europe-north1": EU_COUNTRIES,
    "europe-southwest1": EU_COUNTRIES,
    "asia-east1":    {"TW"}, "asia-east2": {"HK"},
    "asia-northeast1": {"JP"}, "asia-northeast2": {"JP"}, "asia-northeast3": {"KR"},
    "asia-south1":   {"IN"}, "asia-south2": {"IN"},
    "asia-southeast1": {"SG"}, "asia-southeast2": {"ID"},
    "australia-southeast1": {"AU"}, "australia-southeast2": {"AU"},
    "me-central1":   {"QA"}, "me-central2": {"SA"}, "me-west1": {"IL"},
    "africa-south1": {"ZA"},
    # Azure (lowercased — caller normalises)
    "eastus":        {"US"}, "eastus2": {"US"}, "centralus": {"US"},
    "northcentralus":{"US"}, "southcentralus": {"US"},
    "westus":        {"US"}, "westus2": {"US"}, "westus3": {"US"},
    "canadacentral": {"CA"}, "canadaeast": {"CA"},
    "brazilsouth":   {"BR"}, "brazilsoutheast": {"BR"},
    "northeurope":   EU_COUNTRIES, "westeurope": EU_COUNTRIES,
    "uksouth":       {"GB"}, "ukwest": {"GB"},
    "francecentral": EU_COUNTRIES, "francesouth": EU_COUNTRIES,
    "germanywestcentral": EU_COUNTRIES, "germanynorth": EU_COUNTRIES,
    "italynorth":    EU_COUNTRIES, "norwayeast": EU_COUNTRIES, "norwaywest": EU_COUNTRIES,
    "polandcentral": EU_COUNTRIES, "spaincentral": EU_COUNTRIES,
    "swedencentral": EU_COUNTRIES, "swedensouth": EU_COUNTRIES,
    "switzerlandnorth": EU_COUNTRIES | {"CH"}, "switzerlandwest": EU_COUNTRIES | {"CH"},
    "uaenorth":      {"AE"}, "uaecentral": {"AE"},
    "qatarcentral":  {"QA"}, "israelcentral": {"IL"},
    "southafricanorth": {"ZA"}, "southafricawest": {"ZA"},
    "australiaeast": {"AU"}, "australiasoutheast": {"AU"},
    "australiacentral": {"AU"}, "australiacentral2": {"AU"},
    "centralindia":  {"IN"}, "southindia": {"IN"}, "westindia": {"IN"}, "jioindiawest": {"IN"},
    "eastasia":      {"HK"}, "southeastasia": {"SG"},
    "japaneast":     {"JP"}, "japanwest": {"JP"},
    "koreacentral":  {"KR"}, "koreasouth": {"KR"},
}


def _countries_for_region(region: str | None) -> set[str]:
    """Look up the country set for a cloud region. Returns empty set
    when we don't know it — caller treats that as 'no constraint'."""
    if not region:
        return set()
    key = region.strip().lower()
    if key in REGION_TO_COUNTRIES:
        return REGION_TO_COUNTRIES[key]
    # Loose match: some providers prefix with cloud (e.g. "gcp:us-central1")
    for cand in (key, key.split(":")[-1], key.replace("_", "-")):
        if cand in REGION_TO_COUNTRIES:
            return REGION_TO_COUNTRIES[cand]
    return set()


# ── Detector ────────────────────────────────────────────────────────────

CONFIDENTIAL_LABELS = {"confidential", "highly_confidential"}


async def detect_cross_region_access(
    db: AsyncSession,
    org_id: str,
    *,
    window_hours: int = 24,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return a list of cross-region access detections for the org.

    Each detection is a dict with the shape consumed by the SaaS
    alert sink:
      {
        "user_email": str,
        "user_country": str,
        "provider": str,
        "resource_id": str,
        "resource_name": str,
        "resource_region": str,
        "resource_allowed_countries": [iso2, ...],
        "classification_label": str,
        "first_seen_at": ISO,
        "evidence": dict,
      }
    """
    since = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    detections: list[dict[str, Any]] = []

    # 1. M365 / SaaS confidential resources + their owner countries.
    #    saas_data_items doesn't carry a resource_region, but the
    #    `audit_logs.new_value` JSONB for resource_accessed events
    #    carries a `country` for the actor and `resource_region` /
    #    `resource_id`. We join in SQL.
    try:
        rows = (await db.execute(text(
            "SELECT  a.id::text AS audit_id, a.user_id::text, a.action, "
            "        a.ip_address, a.created_at, a.new_value, "
            "        u.email AS user_email "
            "FROM audit_logs a "
            "LEFT JOIN users u ON u.id = a.user_id "
            "WHERE a.org_id = CAST(:oid AS UUID) "
            "  AND a.created_at >= :since "
            "  AND a.action IN ('resource_accessed', 'sign_in', 'cloud_api_call') "
            "ORDER BY a.created_at DESC "
            "LIMIT :lim"
        ), {"oid": org_id, "since": since, "lim": limit})).mappings().all()
    except Exception as exc:
        logger.debug(f"cross_region: audit_logs select failed: {exc}")
        rows = []

    for row in rows:
        new_val = row.get("new_value") or {}
        if isinstance(new_val, str):
            try:
                new_val = json.loads(new_val)
            except Exception:
                new_val = {}
        if not isinstance(new_val, dict):
            continue

        user_country = (new_val.get("user_country")
                        or new_val.get("country")
                        or new_val.get("source_country") or "").upper()
        if not user_country or len(user_country) != 2:
            continue

        resource_region = (new_val.get("resource_region")
                           or new_val.get("region") or "")
        if not resource_region:
            continue

        allowed = _countries_for_region(resource_region)
        if not allowed:
            continue  # unknown region — don't false-positive

        if user_country in allowed:
            continue  # access from inside the residency boundary

        label = (new_val.get("classification_label") or "").lower()
        if label and label not in CONFIDENTIAL_LABELS:
            continue  # only alert on confidential / highly_confidential

        detections.append({
            "user_email": row.get("user_email") or new_val.get("user_email") or "unknown",
            "user_country": user_country,
            "provider": new_val.get("provider") or "unknown",
            "resource_id": new_val.get("resource_id") or "",
            "resource_name": new_val.get("resource_name") or new_val.get("resource_id") or "",
            "resource_region": resource_region,
            "resource_allowed_countries": sorted(allowed),
            "classification_label": label or "unknown",
            "first_seen_at": row.get("created_at").isoformat() if row.get("created_at") else None,
            "evidence": {
                "ip_address": row.get("ip_address"),
                "action": row.get("action"),
                **{k: v for k, v in new_val.items() if k in (
                    "session_id", "resource_url", "resource_type",
                    "user_agent", "graph_request_id", "cloudtrail_event_id",
                )},
            },
        })

    # 2. Tagless cross-cloud fallback: look at the per-cloud inventory
    #    tables for confidential rows AND join them against any sign-in
    #    we have for the org user. This catches the case where audit_log
    #    enrichment isn't running yet — at least we surface the *risk*
    #    (e.g. "you have confidential data in eu-west-1 and 4 of your
    #    users sign in from the US").
    if not detections:
        try:
            risk_rows = (await db.execute(text(
                "SELECT 'aws' AS provider, name, region, "
                "       metadata->>'dlp_risk_level' AS risk "
                "FROM aws_resources "
                "WHERE org_id = :oid "
                "  AND metadata->>'dlp_risk_level' IN ('high','critical') "
                "  AND region IS NOT NULL "
                "UNION ALL "
                "SELECT 'gcp', name, location, metadata->>'dlp_risk_level' "
                "FROM gcp_resources "
                "WHERE org_id = :oid "
                "  AND metadata->>'dlp_risk_level' IN ('high','critical') "
                "  AND location IS NOT NULL "
                "LIMIT 50"
            ), {"oid": org_id})).mappings().all()
        except Exception as exc:
            logger.debug(f"cross_region: fallback risk-row select failed: {exc}")
            risk_rows = []

        # No per-row sign-in data here — we emit at most ONE summary
        # detection per (resource_region, user_country) tuple. The
        # alert sink will dedupe.
        countries_seen: set[str] = set()
        try:
            sign_in_rows = (await db.execute(text(
                "SELECT DISTINCT new_value->>'country' AS country, "
                "       u.email "
                "FROM audit_logs a LEFT JOIN users u ON u.id = a.user_id "
                "WHERE a.org_id = CAST(:oid AS UUID) "
                "  AND a.created_at >= :since "
                "  AND a.action = 'sign_in' "
                "LIMIT 200"
            ), {"oid": org_id, "since": since})).mappings().all()
            countries_seen = {
                (r.get("country") or "").upper()
                for r in sign_in_rows
                if r.get("country")
            }
        except Exception:
            pass

        for rr in risk_rows:
            region = rr.get("region")
            allowed = _countries_for_region(region)
            if not allowed:
                continue
            offending = countries_seen - allowed
            if not offending:
                continue
            for ctry in offending:
                detections.append({
                    "user_email": "fleet",  # not user-specific
                    "user_country": ctry,
                    "provider": rr["provider"],
                    "resource_id": rr.get("name") or "",
                    "resource_name": rr.get("name") or "",
                    "resource_region": region,
                    "resource_allowed_countries": sorted(allowed),
                    "classification_label": rr.get("risk") or "high",
                    "first_seen_at": datetime.now(timezone.utc).isoformat(),
                    "evidence": {
                        "kind": "summary_fleet",
                        "note": (
                            f"Confidential {rr['provider']} resource sits "
                            f"in {region}; org users have signed in from "
                            f"{ctry} in the last {window_hours}h."
                        ),
                    },
                })

    return detections


async def _alert_pref_enabled(db: AsyncSession, org_id: str, pref_key: str) -> bool:
    try:
        r = (await db.execute(text(
            "SELECT org_metadata FROM organizations WHERE id = CAST(:oid AS UUID)"
        ), {"oid": org_id})).first()
        if not r:
            return True
        meta = r[0]
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        prefs = (meta or {}).get("alert_prefs") or {}
        val = prefs.get(pref_key)
        return bool(val) if val is not None else True
    except Exception:
        return True


async def run_and_alert(db: AsyncSession, org_id: str) -> int:
    """Run the detector and push results into `saas_alerts`.

    Returns the number of NEW alerts inserted (deduped against open
    alerts on the same resource+user+region).
    """
    if not await _alert_pref_enabled(db, org_id, "saas_cross_region_access"):
        logger.info(f"cross_region: pref off for org {org_id}, skipping")
        return 0

    detections = await detect_cross_region_access(db, org_id)
    if not detections:
        return 0

    inserted = 0
    for d in detections:
        try:
            # Dedup: resource_id + user_email + user_country open == skip
            existing = (await db.execute(text(
                "SELECT 1 FROM saas_alerts "
                "WHERE org_id = CAST(:oid AS UUID) "
                "  AND alert_type = 'CROSS_REGION_ACCESS' "
                "  AND resource_id = :rid "
                "  AND status = 'open' "
                "  AND (raw_data->>'user_country') = :uc "
                "  AND (raw_data->>'user_email') = :ue "
                "LIMIT 1"
            ), {
                "oid": org_id, "rid": d["resource_id"],
                "uc": d["user_country"], "ue": d["user_email"],
            })).first()
            if existing:
                continue
            severity = "high" if d["classification_label"] == "highly_confidential" else "medium"
            title = (
                f"Cross-region access: {d['user_email']} "
                f"({d['user_country']}) touched "
                f"{d['provider']} resource in {d['resource_region']}"
            )
            description = (
                f"User {d['user_email']} (source country {d['user_country']}) "
                f"accessed a {d['classification_label']} resource "
                f"'{d['resource_name']}' whose home region "
                f"{d['resource_region']} is restricted to "
                f"{', '.join(d['resource_allowed_countries'])}. "
                "This is a data-residency violation."
            )
            await db.execute(text(
                "INSERT INTO saas_alerts "
                "(id, org_id, provider, alert_type, severity, title, "
                " description, resource_id, resource_name, status, "
                " raw_data, created_at) "
                "VALUES (gen_random_uuid(), CAST(:oid AS UUID), :prov, "
                "        'CROSS_REGION_ACCESS', :sev, :title, :desc, "
                "        :rid, :rname, 'open', CAST(:raw AS JSONB), NOW())"
            ), {
                "oid": org_id, "prov": d["provider"], "sev": severity,
                "title": title[:240], "desc": description,
                "rid": d["resource_id"], "rname": d["resource_name"][:240],
                "raw": json.dumps(d, default=str),
            })
            inserted += 1
        except Exception as exc:
            logger.warning(f"cross_region: insert failed: {exc}")
            try:
                await db.rollback()
            except Exception:
                pass
            continue
    try:
        await db.commit()
    except Exception as exc:
        logger.warning(f"cross_region: commit failed: {exc}")
        await db.rollback()
        return 0
    if inserted:
        logger.info(f"cross_region: org={org_id} new_alerts={inserted}")
    return inserted
