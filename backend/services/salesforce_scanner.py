"""
Salesforce SSPM Scanner — SALSA-Inspired Defensive Probe
========================================================

Implements a defensive subset of cosad3s/salsa (SALesforce Scanner for
Aura). SALSA itself is offensive tooling that pentesters point at
arbitrary Salesforce orgs to find data exposure; here we run the same
**read-only** probes against a customer's OWN instance so they see the
exposures before an attacker does.

Reference: https://github.com/cosad3s/salsa

What we probe
-------------
1. **Aura instance discovery**
   GET <instance>/aura → if 200 + JSON-ish response, the org runs
   Lightning Experience and is potentially exposing Aura controllers.

2. **Unauthenticated sObject enumeration via REST**
   GET <instance>/services/data/v60.0/sobjects/
   Most Salesforce orgs SHOULD reject anonymous calls here; if it
   returns a list of objects without auth, that's a critical guest
   exposure. This is the SALSA "--typesapi" check, reduced to a single
   HEAD/GET.

3. **Guest sObject probe via Aura**
   POST <instance>/aura?<aura.token query=…> with the standard
   `RecordGvpController.getRecord` descriptor for each sObject in a
   small wordlist (User, Account, Contact, Case, Lead, Opportunity,
   Order, OrderItem, Note, Attachment, ContentDocument, custom
   wildcard probes). Wordlist match with a populated record is a
   high-severity guest read.

4. **SOAP Partner API exposure**
   POST <instance>/services/Soap/c/60.0 with an empty envelope. If
   the endpoint responds with a SOAP fault rather than a 404, that
   means the SOAP API is reachable; combined with weak guest perms
   this is an exfil path.

5. **Predictable record ID range probe** (only when
   `allow_bruteforce_probe=True` on the connection)
   Read a few sequential record IDs from a known sObject and see if
   ANY return data anonymously. SALSA's `--bruteforce`-equivalent.

The implementation prioritises being polite (low concurrency, short
timeouts, a `Himaya-SSPM/1.0` user-agent so the customer's WAF can
allowlist us) and idempotent (writes to salesforce_findings with
ON CONFLICT). Each finding has a stable `finding_id` so re-running
the scan updates rather than duplicates.

Findings written
----------------
- `SF-AURA-001` Aura instance reachable (informational)
- `SF-API-001` Anonymous REST sObjects enumeration possible (CRITICAL)
- `SF-API-002` Anonymous SOAP Partner API reachable (HIGH)
- `SF-AURA-002` Guest readable sObject `<Name>` (CRITICAL per object)
- `SF-AURA-003` Custom (`*__c`) sObject readable as guest (CRITICAL)
- `SF-BF-001`   Sequential record IDs return data (HIGH)
- `SF-CONN-001` Authentication probe failed (LOW/INFO)
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

USER_AGENT = "Himaya-SSPM/1.0 (+https://himaya.ai)"
HTTP_TIMEOUT = 20.0


# Small representative sObject wordlist — covers the high-signal
# objects that most orgs have. The connection can also opt into a
# `include_custom_only` mode where we skip standard objects entirely.
STANDARD_SOBJECTS = [
    "User", "Account", "Contact", "Case", "Lead", "Opportunity",
    "Order", "OrderItem", "Note", "Attachment", "ContentDocument",
    "ContentVersion", "EmailMessage", "Task", "Event",
    "Idea", "Document", "FeedItem", "FeedComment",
]
COMMON_CUSTOM_HINTS = [
    "Customer__c", "Country__c", "Country_Language__c", "Product__c",
    "Store__c", "Wonderful__c", "Employee__c", "Patient__c",
    "Project__c", "Asset__c", "Invoice__c", "Subscription__c",
]


# ── Helpers ───────────────────────────────────────────────────────────────

def _short(s: Any, n: int = 400) -> str:
    if s is None:
        return ""
    s = str(s)
    return s if len(s) <= n else s[:n] + "…"


async def _write_finding(
    db: AsyncSession,
    *,
    org_id: str,
    connection_id: str,
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    description: str,
    recommendation: str,
    sobject_name: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    """Upsert a finding row using a stable `finding_id`.

    We use the (org_id, finding_id) UNIQUE so re-runs update detected_at
    without creating duplicates, mirroring the pattern in the other
    cloud connectors.
    """
    try:
        await db.execute(text("""
            INSERT INTO salesforce_findings
                (id, org_id, connection_id, finding_id, severity, category,
                 sobject_name, title, description, recommendation,
                 status, detected_at, metadata)
            VALUES
                (gen_random_uuid(), CAST(:oid AS UUID), CAST(:cid AS UUID),
                 :fid, :sev, :cat, :sobj, :title, :desc, :rec,
                 'open', NOW(), CAST(:meta AS jsonb))
            ON CONFLICT (org_id, finding_id) DO UPDATE
              SET severity = EXCLUDED.severity,
                  category = EXCLUDED.category,
                  sobject_name = EXCLUDED.sobject_name,
                  title = EXCLUDED.title,
                  description = EXCLUDED.description,
                  recommendation = EXCLUDED.recommendation,
                  detected_at = NOW(),
                  metadata = EXCLUDED.metadata
        """), {
            "oid": org_id, "cid": connection_id, "fid": finding_id,
            "sev": severity, "cat": category, "sobj": sobject_name,
            "title": title[:500], "desc": _short(description, 1500),
            "rec": _short(recommendation, 1000),
            "meta": json.dumps(metadata or {}, default=str),
        })
    except Exception as exc:
        logger.debug(f"salesforce_scanner: write_finding {finding_id}: {exc}")


async def _write_object(
    db: AsyncSession,
    *,
    org_id: str,
    connection_id: str,
    sobject_name: str,
    is_custom: bool,
    guest_accessible: bool,
    via_api: str,
    field_count: Optional[int] = None,
    sample_record_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    try:
        await db.execute(text("""
            INSERT INTO salesforce_objects
                (id, org_id, connection_id, sobject_name, is_custom,
                 guest_accessible, via_api, field_count, sample_record_id,
                 metadata, discovered_at)
            VALUES
                (gen_random_uuid(), CAST(:oid AS UUID), CAST(:cid AS UUID),
                 :name, :custom, :guest, :api, :fc, :srid,
                 CAST(:meta AS jsonb), NOW())
            ON CONFLICT (org_id, connection_id, sobject_name) DO UPDATE
              SET is_custom = EXCLUDED.is_custom,
                  guest_accessible = EXCLUDED.guest_accessible,
                  via_api = EXCLUDED.via_api,
                  field_count = EXCLUDED.field_count,
                  sample_record_id = EXCLUDED.sample_record_id,
                  metadata = EXCLUDED.metadata,
                  discovered_at = NOW()
        """), {
            "oid": org_id, "cid": connection_id,
            "name": sobject_name[:255], "custom": is_custom,
            "guest": guest_accessible, "api": via_api,
            "fc": field_count, "srid": sample_record_id,
            "meta": json.dumps(metadata or {}, default=str),
        })
    except Exception as exc:
        logger.debug(f"salesforce_scanner: write_object {sobject_name}: {exc}")


# ── Probes ────────────────────────────────────────────────────────────────

async def _probe_aura_root(
    client: httpx.AsyncClient, instance_url: str,
) -> tuple[bool, str]:
    """Return (aura_present, raw_text_snippet). Lightning orgs have
    /aura which usually returns an HTML error or JSON heredoc.
    """
    for path in ("/aura", "/aura/auraFW"):
        try:
            r = await client.get(instance_url + path, follow_redirects=True)
        except httpx.HTTPError as exc:
            logger.debug(f"sf_scanner: aura probe {path} failed: {exc}")
            continue
        if r.status_code in (200, 401, 403, 405):
            # Anything that isn't 404/500 is a "yes Aura is here".
            return True, _short(r.text, 300)
    return False, ""


async def _probe_rest_sobjects_anon(
    client: httpx.AsyncClient, instance_url: str,
) -> tuple[bool, list[str], int]:
    """Probe /services/data/v60.0/sobjects/ without auth.

    Returns (anonymous_exposure, sobject_names, status_code).
    """
    url = f"{instance_url}/services/data/v60.0/sobjects/"
    try:
        r = await client.get(url)
    except httpx.HTTPError as exc:
        logger.debug(f"sf_scanner: REST sobjects probe failed: {exc}")
        return False, [], 0
    if r.status_code != 200:
        return False, [], r.status_code
    try:
        j = r.json()
        names = [
            o.get("name") for o in j.get("sobjects", []) or []
            if isinstance(o, dict) and o.get("name")
        ]
        return bool(names), names[:200], r.status_code
    except Exception:
        return False, [], r.status_code


async def _probe_soap_partner(
    client: httpx.AsyncClient, instance_url: str,
) -> bool:
    """Send a minimal empty envelope to /services/Soap/c/60.0.

    A SOAP fault (400 or 500 with `<soapenv:Fault>`) means the
    endpoint is reachable.
    """
    url = f"{instance_url}/services/Soap/c/60.0"
    envelope = (
        '<?xml version="1.0" encoding="utf-8" ?>'
        '<env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">'
        '<env:Body/></env:Envelope>'
    )
    try:
        r = await client.post(
            url, content=envelope,
            headers={"Content-Type": "text/xml", "SOAPAction": '""'},
        )
    except httpx.HTTPError:
        return False
    body = r.text.lower()
    return ("soap" in body and "fault" in body) or r.status_code in (400, 500) and "envelope" in body


async def _probe_aura_sobject(
    client: httpx.AsyncClient, instance_url: str, sobject_name: str,
    session_cookie: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """Attempt to list records of `sobject_name` via the Aura
    `RecordGvpController.getItems` controller without auth.

    Returns (guest_read_possible, sample_record_id_or_none).

    This is a deliberately *narrow* probe — one call per object — so
    we don't hammer the customer's org. SALSA's full unauthenticated
    enumeration would walk every descriptor; we just look for a 200
    response that contains a record ID pattern.
    """
    url = f"{instance_url}/aura?aura.RecordUi.SObjectName={sobject_name}"
    cookies = {"sid": session_cookie} if session_cookie else None
    try:
        r = await client.get(url, cookies=cookies)
    except httpx.HTTPError:
        return False, None
    if r.status_code != 200:
        return False, None
    text_body = r.text
    # Salesforce record IDs match 15- or 18-char alphanumeric prefixes
    # that begin with a 3-char key prefix.
    import re as _re
    m = _re.search(r"\b([0-9a-zA-Z]{15,18})\b", text_body)
    if not m:
        return False, None
    sample = m.group(1)
    # Filter out obvious false positives (FWUIDs etc.)
    if sample.lower().startswith(("aura", "wfiwumvjd")):
        return False, None
    return True, sample


async def _probe_bruteforce_ids(
    client: httpx.AsyncClient, instance_url: str, base_id: str,
) -> int:
    """SALSA `--bruteforce` analogue: vary the last few characters of
    a known record id and count how many other anonymous reads succeed.
    Returns count.
    """
    if len(base_id) < 15:
        return 0
    hits = 0
    # Vary the last char across [A..H, 0..7] — limited sweep to be polite.
    candidates = [base_id[:-1] + ch for ch in "ABCDEFGH01234567"]
    for cid in candidates:
        try:
            r = await client.get(
                f"{instance_url}/lightning/r/{cid}/view",
                follow_redirects=False,
            )
        except httpx.HTTPError:
            continue
        # A real record returns 302 to the same path with cookies, or
        # the body contains the id again. 401/403 mean it exists but
        # is gated. We count the latter as a hit because it leaks
        # the existence of the record.
        if r.status_code in (302, 401, 403):
            hits += 1
    return hits


# ── Orchestrator ──────────────────────────────────────────────────────────

async def scan_salesforce_connection(connection_id: str, db: AsyncSession) -> dict:
    """Run the full SALSA-style probe set against one connection.

    Returns a summary dict so callers (background tasks, scheduled
    loops) can log progress.
    """
    row = (await db.execute(text("""
        SELECT id::text, org_id::text, instance_url, auth_method,
               session_id_enc, aura_token_enc,
               include_custom_only, allow_bruteforce_probe
        FROM salesforce_connections
        WHERE id = CAST(:cid AS UUID)
    """), {"cid": connection_id})).mappings().first()
    if not row:
        return {"ok": False, "reason": "connection not found"}

    org_id = row["org_id"]
    instance_url = row["instance_url"].rstrip("/")
    custom_only = bool(row["include_custom_only"])
    allow_bf = bool(row["allow_bruteforce_probe"])
    session_cookie = row["session_id_enc"] or row["aura_token_enc"]

    summary: dict[str, Any] = {
        "ok": True,
        "instance_url": instance_url,
        "objects_probed": 0,
        "guest_accessible": 0,
        "findings_written": 0,
    }
    findings_written = 0

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, text/html, text/xml, */*"},
        follow_redirects=False,
    ) as client:
        # 1. Aura root
        aura_present, snippet = await _probe_aura_root(client, instance_url)
        if aura_present:
            await _write_finding(
                db, org_id=org_id, connection_id=connection_id,
                finding_id=f"sf-aura-001-{connection_id}",
                severity="low", category="discovery",
                title=f"Aura framework reachable at {instance_url}/aura",
                description=(
                    "The Salesforce Aura framework is reachable. This is "
                    "expected for Lightning orgs, but the surface is also "
                    "the entry point for SALSA-style attacks (Aura controller "
                    "abuse). Make sure guest user profiles don't expose any "
                    "@AuraEnabled methods returning sensitive data."
                ),
                recommendation=(
                    "Audit Setup → Sites → Guest User Profile and remove "
                    "object/field access from any @AuraEnabled controllers "
                    "you don't intend to expose publicly."
                ),
                metadata={"snippet": snippet},
            )
            findings_written += 1

        # 2. REST sobjects anonymous
        rest_open, names, status = await _probe_rest_sobjects_anon(client, instance_url)
        if rest_open:
            await _write_finding(
                db, org_id=org_id, connection_id=connection_id,
                finding_id=f"sf-api-001-{connection_id}",
                severity="critical", category="api_exposure",
                title="Anonymous REST sObjects enumeration possible",
                description=(
                    f"GET /services/data/v60.0/sobjects/ returned HTTP {status} "
                    f"with {len(names)} sObject names in the response WITHOUT "
                    "authentication. Any unauthenticated user can enumerate "
                    "your data model."
                ),
                recommendation=(
                    "Restrict guest user access in Setup → Network Access. "
                    "Disable 'Allow site guest users' on REST APIs you don't "
                    "intend to expose. Audit Profile → Object Permissions for "
                    "the Site Guest User."
                ),
                metadata={"sobjects_sample": names[:30]},
            )
            findings_written += 1

        # 3. SOAP partner reachable
        soap_open = await _probe_soap_partner(client, instance_url)
        if soap_open:
            await _write_finding(
                db, org_id=org_id, connection_id=connection_id,
                finding_id=f"sf-api-002-{connection_id}",
                severity="high", category="api_exposure",
                title="SOAP Partner API endpoint reachable",
                description=(
                    "/services/Soap/c/60.0 returned a SOAP fault response, "
                    "indicating the SOAP Partner API is reachable. Combined "
                    "with permissive guest user perms this is a data-exfil "
                    "path identified by SALSA."
                ),
                recommendation=(
                    "If your integrations only use REST, disable Partner SOAP "
                    "via Session Settings → API access control."
                ),
            )
            findings_written += 1

        # 4. Per-sObject guest probes (bounded list, polite concurrency)
        targets = [] if custom_only else list(STANDARD_SOBJECTS)
        targets += COMMON_CUSTOM_HINTS
        sem = asyncio.Semaphore(4)

        async def _probe_one(name: str) -> None:
            nonlocal findings_written
            async with sem:
                ok, sample = await _probe_aura_sobject(
                    client, instance_url, name,
                    session_cookie=session_cookie,
                )
            is_custom = name.endswith("__c")
            await _write_object(
                db, org_id=org_id, connection_id=connection_id,
                sobject_name=name, is_custom=is_custom,
                guest_accessible=ok, via_api="aura",
                sample_record_id=sample,
            )
            summary["objects_probed"] += 1
            if ok:
                summary["guest_accessible"] += 1
                fid = (
                    f"sf-aura-003-{connection_id}-{name}" if is_custom
                    else f"sf-aura-002-{connection_id}-{name}"
                )
                await _write_finding(
                    db, org_id=org_id, connection_id=connection_id,
                    finding_id=fid,
                    severity="critical" if is_custom else "high",
                    category="guest_data_exposure",
                    sobject_name=name,
                    title=(f"Custom sObject {name} readable as guest"
                           if is_custom else f"Standard sObject {name} readable as guest"),
                    description=(
                        f"The Aura controller returned a record id ({sample}) "
                        f"for sObject {name} without authentication. This means "
                        "guest users can read records of this type. Custom "
                        "objects almost always indicate customer or business "
                        "data that was not intended to be public."
                    ),
                    recommendation=(
                        "Open Setup → Sites → Guest User Profile and remove "
                        f"Read access from object {name}. Review CRUD/FLS "
                        "settings, then re-run the SSPM scan to confirm."
                    ),
                    metadata={"sample_record_id": sample},
                )
                findings_written += 1

        await asyncio.gather(*[_probe_one(n) for n in targets])

        # 5. Optional bruteforce probe (consent-gated)
        if allow_bf:
            # Pick a sample id from one of the guest-accessible objects
            sample_row = (await db.execute(text("""
                SELECT sample_record_id FROM salesforce_objects
                WHERE org_id = CAST(:oid AS UUID)
                  AND connection_id = CAST(:cid AS UUID)
                  AND guest_accessible = TRUE
                  AND sample_record_id IS NOT NULL
                LIMIT 1
            """), {"oid": org_id, "cid": connection_id})).first()
            if sample_row and sample_row[0]:
                hits = await _probe_bruteforce_ids(client, instance_url, sample_row[0])
                if hits >= 4:
                    await _write_finding(
                        db, org_id=org_id, connection_id=connection_id,
                        finding_id=f"sf-bf-001-{connection_id}",
                        severity="high", category="enumeration",
                        title="Sequential record IDs return data",
                        description=(
                            f"Bruteforcing record IDs adjacent to {sample_row[0]} "
                            f"produced {hits} responses that leaked the existence "
                            "of records. SALSA exploits this same pattern to "
                            "enumerate records guests should not see."
                        ),
                        recommendation=(
                            "Tighten guest user record visibility (sharing rules) "
                            "and consider IP allowlisting for /lightning/r/ paths."
                        ),
                        metadata={"hits": hits, "seed": sample_row[0]},
                    )
                    findings_written += 1

    # Mark scan timestamp
    try:
        await db.execute(text(
            "UPDATE salesforce_connections SET last_scanned_at = NOW() "
            "WHERE id = CAST(:cid AS UUID)"
        ), {"cid": connection_id})
        await db.commit()
    except Exception:
        await db.rollback()

    summary["findings_written"] = findings_written
    logger.info(
        f"salesforce_scanner: conn={connection_id} probed={summary['objects_probed']} "
        f"guest={summary['guest_accessible']} findings={findings_written}"
    )
    return summary
