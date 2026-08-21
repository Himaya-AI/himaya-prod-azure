"""
Exfil Monitor — continuous auto-forwarding & delegate exfiltration detection.

Attackers who compromise a mailbox almost always establish persistence by
setting up **auto-forwarding** (to an external/personal address) or adding a
**delegate** so they keep receiving mail even after a password reset. This
service continuously scans connected M365 and Google Workspace mailboxes for
those persistence mechanisms, records them in ``posture_exfil_events`` (with
first/last-seen history), raises an alert the first time a high-risk/external
one appears, and exposes one-click remediation.

Detection surface:
  - Google: forwardingAddresses, auto-forwarding (updateAutoForwarding), delegates
  - M365:   inbox-rule forward/redirect actions, mailbox forwardingSmtpAddress

Remediation (see ``remediate_event``):
  - Google forward:  disable auto-forwarding + delete the forwarding address
  - Google delegate: delete the delegate
  - M365 rule:       delete the offending inbox rule
  - M365 mailbox fwd: flagged for manual action (not settable via Graph)

Scans run every EXFIL_SCAN_INTERVAL seconds for every org with an active
mailbox integration. The read path uses existing DWD scopes; remediation
additionally requests ``gmail.settings.sharing`` (returns a clear message if
that scope hasn't been granted in the customer's Admin console).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy import select, text

logger = logging.getLogger(__name__)

GRAPH = "https://graph.microsoft.com/v1.0"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1"

# Read path works with the default posture SA scopes. Remediation needs sharing.
_REMEDIATION_SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.settings.basic",
    "https://www.googleapis.com/auth/gmail.settings.sharing",  # forwarding + delegate write
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
]

EXFIL_SCAN_INTERVAL = int(os.getenv("EXFIL_SCAN_INTERVAL", str(20 * 60)))  # 20 min
_MAX_MAILBOXES = int(os.getenv("EXFIL_MAX_MAILBOXES", "100"))


# ── Fingerprint / scoring ─────────────────────────────────────────────────────

def _fingerprint(kind: str, mailbox: str, target: str) -> str:
    raw = f"{kind}|{(mailbox or '').lower()}|{(target or '').lower()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _is_external(mailbox: str, target: str) -> bool:
    mb_dom = mailbox.split("@")[-1].lower() if "@" in mailbox else ""
    tg_dom = target.split("@")[-1].lower() if "@" in target else ""
    return bool(tg_dom) and tg_dom != mb_dom


def _score_delegate(mailbox: str, delegate: str) -> tuple[str, list[str]]:
    reasons = [f"{delegate} has delegate access to {mailbox}"]
    if _is_external(mailbox, delegate):
        reasons.append("Delegate is an EXTERNAL account — classic post-compromise persistence")
        return "high", reasons
    reasons.append("Internal delegate — verify this access is authorised")
    return "medium", reasons


# ── Table ──────────────────────────────────────────────────────────────────────

async def ensure_exfil_table(db) -> None:
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS posture_exfil_events (
            id UUID PRIMARY KEY,
            org_id UUID NOT NULL,
            fingerprint TEXT NOT NULL,
            kind TEXT NOT NULL,              -- 'forward' | 'delegate'
            provider TEXT NOT NULL,          -- 'm365' | 'google'
            mailbox TEXT NOT NULL,
            target TEXT NOT NULL,            -- forward destination or delegate email
            is_external BOOLEAN DEFAULT FALSE,
            risk TEXT NOT NULL DEFAULT 'low',
            risk_reasons JSONB,
            detail JSONB,                    -- {rule_id, forwarding_email, mechanism, ...}
            status TEXT NOT NULL DEFAULT 'active',  -- active | remediated | dismissed | auto_cleared
            first_seen TIMESTAMPTZ DEFAULT NOW(),
            last_seen TIMESTAMPTZ DEFAULT NOW(),
            remediated_at TIMESTAMPTZ,
            note TEXT,
            UNIQUE (org_id, fingerprint)
        )
    """))
    await db.commit()


# ── Collection ───────────────────────────────────────────────────────────────

async def _collect_m365(org_id: str, db) -> list[dict]:
    """Collect M365 forwarding findings (inbox-rule forwards + mailbox forward)."""
    from backend.routers.posture import (
        _get_active_integration, _get_m365_users, _m365_rule_actions, _score_forwarding,
    )
    import re as _re

    integ = await _get_active_integration(db, org_id, "m365")
    if not integ:
        return []

    findings: list[dict] = []
    delegated = {"Authorization": f"Bearer {integ['access_token']}"}

    # App-only mailbox token (covers all mailboxes, not just the connecting user)
    tid = os.getenv("M365_TENANT_ID", "")
    cid = os.getenv("M365_CLIENT_ID", "")
    sec = os.getenv("M365_CLIENT_SECRET", "")
    mb_headers = delegated
    if all([tid, cid, sec]):
        try:
            async with httpx.AsyncClient(timeout=10) as tc:
                tr = await tc.post(
                    f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token",
                    data={"client_id": cid, "client_secret": sec,
                          "scope": "https://graph.microsoft.com/.default",
                          "grant_type": "client_credentials"},
                )
                if tr.status_code == 200:
                    mb_headers = {"Authorization": f"Bearer {tr.json().get('access_token', '')}"}
        except Exception as e:
            logger.debug(f"exfil: M365 app token failed: {e}")

    async with httpx.AsyncClient(timeout=20) as client:
        users = await _get_m365_users(client, mb_headers)
        for email in users[:_MAX_MAILBOXES]:
            # Inbox-rule forwards
            try:
                rr = await client.get(
                    f"{GRAPH}/users/{email}/mailFolders/inbox/messageRules?$top=50",
                    headers=mb_headers,
                )
                if rr.status_code == 200:
                    for rule in rr.json().get("value", []):
                        acts = _m365_rule_actions(rule.get("actions", {}))
                        low = acts.lower()
                        if "forward to:" not in low and "redirect to:" not in low:
                            continue
                        for addr in _re.findall(r'(?:forward|redirect) to: ([\w.@+%-]+)', low):
                            risk, reasons = _score_forwarding(email, addr)
                            findings.append({
                                "kind": "forward", "provider": "m365", "mailbox": email,
                                "target": addr, "is_external": _is_external(email, addr),
                                "risk": risk, "risk_reasons": reasons,
                                "detail": {"mechanism": "inbox_rule",
                                           "rule_id": rule.get("id"),
                                           "rule_name": rule.get("displayName")},
                            })
            except Exception as e:
                logger.debug(f"exfil: M365 rules {email} failed: {e}")

            # Mailbox-level forwarding
            try:
                mr = await client.get(f"{GRAPH}/users/{email}/mailboxSettings", headers=mb_headers)
                if mr.status_code == 200:
                    addr = mr.json().get("forwardingSmtpAddress") or mr.json().get("forwardingAddress")
                    if addr:
                        addr = addr.replace("smtp:", "")
                        risk, reasons = _score_forwarding(email, addr)
                        findings.append({
                            "kind": "forward", "provider": "m365", "mailbox": email,
                            "target": addr, "is_external": _is_external(email, addr),
                            "risk": risk, "risk_reasons": reasons,
                            "detail": {"mechanism": "mailbox_forward"},
                        })
            except Exception as e:
                logger.debug(f"exfil: M365 mailbox fwd {email} failed: {e}")

    return findings


async def _collect_google(org_id: str, db) -> list[dict]:
    """Collect Google forwarding + delegate findings."""
    from backend.routers.posture import _get_active_integration, _get_google_users, _score_forwarding
    from backend.services.baseline_ingestion import _get_sa_headers_async

    integ = await _get_active_integration(db, org_id, "google")
    if not integ:
        return []

    findings: list[dict] = []
    async with httpx.AsyncClient(timeout=20) as client:
        from backend.services.gmail_quota import gmail_user_cooling_down
        users = await _get_google_users(db, org_id)
        for email in users[:_MAX_MAILBOXES]:
            # Don't add settings-API load to a mailbox that's already 429'd —
            # its quota is needed for interactive quarantine/spam actions.
            if await gmail_user_cooling_down(email):
                continue
            hdrs = await _get_sa_headers_async(subject_email=email)
            if not hdrs:
                break

            # Forwarding addresses
            try:
                fr = await client.get(f"{GMAIL_API}/users/{email}/settings/forwardingAddresses", headers=hdrs)
                if fr.status_code == 200:
                    for fwd in fr.json().get("forwardingAddresses", []):
                        if fwd.get("verificationStatus") not in ("accepted", "pending"):
                            continue
                        addr = fwd.get("forwardingEmail", "")
                        if not addr:
                            continue
                        risk, reasons = _score_forwarding(email, addr)
                        findings.append({
                            "kind": "forward", "provider": "google", "mailbox": email,
                            "target": addr, "is_external": _is_external(email, addr),
                            "risk": risk, "risk_reasons": reasons,
                            "detail": {"mechanism": "forwarding_address", "forwarding_email": addr},
                        })
            except Exception as e:
                logger.debug(f"exfil: Gmail forwards {email} failed: {e}")

            # Delegates
            try:
                dr = await client.get(f"{GMAIL_API}/users/{email}/settings/delegates", headers=hdrs)
                if dr.status_code == 200:
                    for d in dr.json().get("delegates", []):
                        deleg = d.get("delegateEmail", "")
                        if not deleg:
                            continue
                        risk, reasons = _score_delegate(email, deleg)
                        findings.append({
                            "kind": "delegate", "provider": "google", "mailbox": email,
                            "target": deleg, "is_external": _is_external(email, deleg),
                            "risk": risk, "risk_reasons": reasons,
                            "detail": {"mechanism": "delegate", "delegate_email": deleg},
                        })
            except Exception as e:
                logger.debug(f"exfil: Gmail delegates {email} failed: {e}")

    return findings


# ── Scan + diff + alert ────────────────────────────────────────────────────────

async def scan_org_exfil(org_id: str) -> dict:
    """Run one focused exfil scan for an org, diffing against stored events."""
    from backend.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        await ensure_exfil_table(db)

        findings: list[dict] = []
        try:
            findings += await _collect_google(org_id, db)
        except Exception as e:
            logger.warning(f"exfil: google collect failed for {org_id}: {e}")
        try:
            findings += await _collect_m365(org_id, db)
        except Exception as e:
            logger.warning(f"exfil: m365 collect failed for {org_id}: {e}")

        # Load existing active fingerprints
        existing = {}
        rows = (await db.execute(text(
            "SELECT fingerprint, status FROM posture_exfil_events WHERE org_id=:oid"
        ), {"oid": org_id})).fetchall()
        for fp, status in rows:
            existing[fp] = status

        seen_fps: set[str] = set()
        new_alerts = 0
        now = datetime.now(timezone.utc)

        for f in findings:
            fp = _fingerprint(f["kind"], f["mailbox"], f["target"])
            seen_fps.add(fp)
            prior = existing.get(fp)

            if prior in ("dismissed",):
                # Respect analyst dismissal — refresh last_seen only
                await db.execute(text(
                    "UPDATE posture_exfil_events SET last_seen=:now WHERE org_id=:oid AND fingerprint=:fp"
                ), {"now": now, "oid": org_id, "fp": fp})
                continue

            if prior is None:
                await db.execute(text(
                    "INSERT INTO posture_exfil_events "
                    "(id, org_id, fingerprint, kind, provider, mailbox, target, is_external, risk, "
                    " risk_reasons, detail, status, first_seen, last_seen) VALUES "
                    "(:id, :oid, :fp, :kind, :provider, :mailbox, :target, :is_external, :risk, "
                    " :risk_reasons, :detail, 'active', :now, :now)"
                ), {
                    "id": str(uuid.uuid4()), "oid": org_id, "fp": fp, "kind": f["kind"],
                    "provider": f["provider"], "mailbox": f["mailbox"], "target": f["target"],
                    "is_external": f["is_external"], "risk": f["risk"],
                    "risk_reasons": json.dumps(f["risk_reasons"]),
                    "detail": json.dumps(f.get("detail") or {}), "now": now,
                })
                # Alert only on genuinely risky new findings
                if f["risk"] == "high" or f["is_external"]:
                    await _raise_alert(db, org_id, f)
                    new_alerts += 1
            else:
                # Re-appeared or still present — reactivate + refresh
                await db.execute(text(
                    "UPDATE posture_exfil_events SET status='active', last_seen=:now, "
                    "risk=:risk, is_external=:is_external, risk_reasons=:rr, detail=:detail "
                    "WHERE org_id=:oid AND fingerprint=:fp"
                ), {
                    "now": now, "risk": f["risk"], "is_external": f["is_external"],
                    "rr": json.dumps(f["risk_reasons"]), "detail": json.dumps(f.get("detail") or {}),
                    "oid": org_id, "fp": fp,
                })

        # Persist inserts/updates first so a later query error can't lose them.
        await db.commit()

        # Anything active but no longer present = auto-cleared (removed at source).
        # Done in a separate transaction so an array-bind issue can't roll back the scan.
        try:
            await db.execute(text(
                "UPDATE posture_exfil_events SET status='auto_cleared' "
                "WHERE org_id=:oid AND status='active' AND NOT (fingerprint = ANY(:seen))"
            ), {"oid": org_id, "seen": list(seen_fps) or [""]})
            await db.commit()
        except Exception as e:
            logger.warning(f"exfil: auto_clear pass failed for {org_id}: {e}")
            await db.rollback()

        logger.info(f"exfil: org {org_id} scanned — {len(findings)} findings, {new_alerts} new alerts")
        return {"findings": len(findings), "new_alerts": new_alerts}


async def _raise_alert(db, org_id: str, f: dict) -> None:
    """Create a SaasAlert for a newly-detected exfil persistence mechanism."""
    from backend.models.db_models import SaasAlert
    kind_label = "auto-forwarding" if f["kind"] == "forward" else "mailbox delegate"
    sev = "critical" if (f["risk"] == "high" and f["is_external"]) else ("high" if f["risk"] == "high" else "medium")
    db.add(SaasAlert(
        org_id=uuid.UUID(org_id),
        provider="email",
        alert_type=f"exfil_{f['kind']}",
        severity=sev,
        title=f"New {kind_label}: {f['mailbox']} → {f['target']}",
        description=(
            f"{f['mailbox']} has a newly-detected {kind_label} to "
            f"{'external ' if f['is_external'] else ''}address {f['target']}. "
            + "; ".join(f.get("risk_reasons") or [])
        ),
        resource_id=f"{f['provider']}:{f['mailbox']}",
        resource_name=f["mailbox"],
        status="open",
        raw_data={"kind": f["kind"], "target": f["target"], "is_external": f["is_external"],
                  "risk": f["risk"], "detail": f.get("detail") or {}},
    ))

    # Best-effort admin email notification. Never let a delivery failure break
    # the scan/commit — email is a side channel on top of the in-app SaasAlert.
    try:
        await _notify_admins_exfil(db, org_id, f, sev, kind_label)
    except Exception as e:
        logger.warning(f"exfil: admin email notification failed for org {org_id}: {e}")


async def _notify_admins_exfil(db, org_id: str, f: dict, sev: str, kind_label: str) -> None:
    """Email the org's active admins about a newly-detected exfil mechanism.

    Reuses the shared transactional path (Azure Communication Email → SES
    fallback) via email_service.send_threat_alert, matching how the mail
    pipeline notifies admins of quarantined threats.
    """
    from backend.models.db_models import Organization, User
    from backend.services.email_service import send_threat_alert

    org_uuid = uuid.UUID(org_id) if isinstance(org_id, str) else org_id

    org = (await db.execute(
        select(Organization).where(Organization.id == org_uuid)
    )).scalar_one_or_none()
    org_name = org.name if org else "Your Organization"

    admins = (await db.execute(
        select(User).where(
            User.org_id == org_uuid,
            User.role == "admin",
            User.is_active.is_(True),
        )
    )).scalars().all()

    admin_emails = [a.email for a in admins if a.email]
    if not admin_emails:
        logger.info(f"exfil: no active admin email for org {org_id}; skipping email (SaasAlert still raised)")
        return

    # Map exfil severity → risk_score bucket the threat-alert template renders.
    risk_score = {"critical": 95, "high": 82}.get(sev, 65)
    threat_type = f"Email Exfiltration ({kind_label}) → {f['target']}"
    detection_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    for email in admin_emails:
        try:
            await asyncio.to_thread(
                send_threat_alert,
                to_email=email,
                org_name=org_name,
                threat_type=threat_type,
                risk_score=risk_score,
                recipient=f["mailbox"],
                action="DETECTED — review & remediate in Posture → Exfil Monitor",
                detection_time=detection_time,
            )
            logger.info(f"exfil: admin alert emailed to {email} for org {org_id} ({threat_type})")
        except Exception as e:
            logger.warning(f"exfil: failed emailing admin {email} for org {org_id}: {e}")


# ── Remediation ──────────────────────────────────────────────────────────────

async def remediate_event(event: dict) -> dict:
    """Actually remove the forward/delegate at the provider. Returns a status dict."""
    from backend.services.baseline_ingestion import _get_sa_headers_async
    from backend.routers.posture import _get_active_integration

    provider = event["provider"]
    mailbox = event["mailbox"]
    kind = event["kind"]
    detail = event.get("detail") or {}

    if provider == "google":
        hdrs = await _get_sa_headers_async(subject_email=mailbox, scopes=_REMEDIATION_SCOPES)
        if not hdrs:
            return {"ok": False, "manual": True,
                    "message": "Google service account unavailable for remediation."}
        async with httpx.AsyncClient(timeout=20) as client:
            if kind == "delegate":
                r = await client.delete(
                    f"{GMAIL_API}/users/{mailbox}/settings/delegates/{event['target']}", headers=hdrs)
                if r.status_code in (200, 204, 404):
                    return {"ok": True, "message": f"Removed delegate {event['target']}"}
                return _google_err(r, "delegate removal")
            # forward: disable auto-forwarding, then delete the forwarding address
            await client.put(
                f"{GMAIL_API}/users/{mailbox}/settings/autoForwarding",
                headers={**hdrs, "Content-Type": "application/json"},
                json={"enabled": False},
            )
            fwd_email = detail.get("forwarding_email") or event["target"]
            r = await client.delete(
                f"{GMAIL_API}/users/{mailbox}/settings/forwardingAddresses/{fwd_email}", headers=hdrs)
            if r.status_code in (200, 204, 404):
                return {"ok": True, "message": f"Disabled forwarding and removed {fwd_email}"}
            return _google_err(r, "forwarding removal")

    # M365
    if kind == "forward" and detail.get("mechanism") == "inbox_rule" and detail.get("rule_id"):
        from backend.database import AsyncSessionLocal  # noqa: F401 (kept for parity)
        # reuse a fresh integration token
        return await _remediate_m365_rule(mailbox, detail["rule_id"], event.get("org_id"))

    return {"ok": False, "manual": True,
            "message": ("This M365 mailbox-level forward must be removed in the Exchange admin "
                        "center (Set-Mailbox -ForwardingSmtpAddress $null); it is not settable via Graph.")}


async def _remediate_m365_rule(mailbox: str, rule_id: str, org_id: str | None) -> dict:
    from backend.database import AsyncSessionLocal
    from backend.routers.posture import _get_active_integration
    async with AsyncSessionLocal() as db:
        integ = await _get_active_integration(db, org_id, "m365") if org_id else None
    # Prefer app-only mailbox token (works across all mailboxes)
    tid = os.getenv("M365_TENANT_ID", ""); cid = os.getenv("M365_CLIENT_ID", ""); sec = os.getenv("M365_CLIENT_SECRET", "")
    headers = None
    if all([tid, cid, sec]):
        try:
            async with httpx.AsyncClient(timeout=10) as tc:
                tr = await tc.post(
                    f"https://login.microsoftonline.com/{tid}/oauth2/v2.0/token",
                    data={"client_id": cid, "client_secret": sec,
                          "scope": "https://graph.microsoft.com/.default",
                          "grant_type": "client_credentials"},
                )
                if tr.status_code == 200:
                    headers = {"Authorization": f"Bearer {tr.json().get('access_token','')}"}
        except Exception:
            pass
    if not headers and integ:
        headers = {"Authorization": f"Bearer {integ['access_token']}"}
    if not headers:
        return {"ok": False, "manual": True, "message": "No M365 token available for remediation."}
    async with httpx.AsyncClient(timeout=15) as client:
        r = await client.delete(
            f"{GRAPH}/users/{mailbox}/mailFolders/inbox/messageRules/{rule_id}", headers=headers)
        if r.status_code in (200, 204, 404):
            return {"ok": True, "message": "Deleted forwarding inbox rule"}
        return {"ok": False, "message": f"Graph delete rule failed: {r.status_code} {r.text[:150]}"}


def _google_err(r: httpx.Response, action: str) -> dict:
    if r.status_code == 403:
        return {"ok": False, "manual": True,
                "message": (f"{action} requires the gmail.settings.sharing DWD scope. Add it in Google "
                            "Admin console → Security → API controls → Domain-wide delegation for the "
                            "Himaya service account, then retry.")}
    return {"ok": False, "message": f"{action} failed: {r.status_code} {r.text[:150]}"}


# ── Background loop ──────────────────────────────────────────────────────────

async def run_exfil_monitor_loop() -> None:
    """Continuously scan every org with an active mailbox integration."""
    from backend.database import AsyncSessionLocal
    await asyncio.sleep(30)  # let startup settle
    logger.info(f"Exfil monitor loop started (interval {EXFIL_SCAN_INTERVAL}s)")
    from backend.services.gmail_quota import acquire_loop_leader
    while True:
        try:
            # Only one replica runs this — avoids N× Gmail settings API calls
            # (delegates/forwardingAddresses) that otherwise exhaust per-user quota.
            if not await acquire_loop_leader("exfil_monitor", ttl=EXFIL_SCAN_INTERVAL * 2):
                await asyncio.sleep(EXFIL_SCAN_INTERVAL)
                continue
            async with AsyncSessionLocal() as db:
                await ensure_exfil_table(db)
                rows = (await db.execute(text(
                    "SELECT DISTINCT org_id FROM org_integrations "
                    "WHERE status='active' AND provider IN ('m365','google')"
                ))).fetchall()
                org_ids = [str(r[0]) for r in rows]
            for oid in org_ids:
                try:
                    await scan_org_exfil(oid)
                except Exception as e:
                    logger.warning(f"exfil: scan failed for org {oid}: {e}")
        except Exception as e:
            logger.error(f"exfil monitor loop error: {e}")
        await asyncio.sleep(EXFIL_SCAN_INTERVAL)
