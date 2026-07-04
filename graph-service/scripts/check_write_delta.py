"""
Write-delta checker — snapshots Neo4j state before and after a /write call,
then prints a structured diff so you can verify exactly what changed.

Usage:
    python scripts/check_write_delta.py [--sender SENDER] [--threat-type THREAT_TYPE]

Env vars (or .env):
    NEO4J_URL           bolt://localhost:7687
    NEO4J_USER          neo4j
    NEO4J_PASSWORD      graph_dev_password
    GRAPH_SERVICE_URL   http://localhost:8001
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import uuid
from pathlib import Path

import httpx
from neo4j import AsyncGraphDatabase, NotificationMinimumSeverity

sys.path.insert(0, str(Path(__file__).parent.parent))

# Suppress Neo4j driver INFO/WARNING noise
logging.getLogger("neo4j").setLevel(logging.ERROR)

NEO4J_URL         = os.getenv("NEO4J_URL",         "bolt://localhost:7687")
NEO4J_USER        = os.getenv("NEO4J_USER",        "neo4j")
NEO4J_PASSWORD    = os.getenv("NEO4J_PASSWORD",    "graph_dev_password")
GRAPH_SERVICE_URL = os.getenv("GRAPH_SERVICE_URL", "http://localhost:8001")
WRITE_SETTLE_SECS = float(os.getenv("WRITE_SETTLE_SECS", "0.5"))

W = 60  # column width


# ── Snapshot queries ──────────────────────────────────────────────────────────

_SENDER_Q = """
MATCH (s:Sender {email: $sender})
OPTIONAL MATCH (s)-[:BELONGS_TO]->(d:Domain)
OPTIONAL MATCH (s)-[:FLAGGED_AS]->(t:ThreatType)
OPTIONAL MATCH (s)-[:SENT]->(e:Email)
OPTIONAL MATCH (s)-[:REPORTED_BY]->(rep:Reporter)
WITH s, d,
     collect(DISTINCT t.type)       AS threat_types,
     collect(DISTINCT e.message_id) AS email_ids,
     count(DISTINCT rep)            AS reporters
RETURN {
    email_count:      s.email_count,
    threat_count:     s.threat_count,
    reputation_score: s.reputation_score,
    last_seen:        s.last_seen,
    threat_types:     threat_types,
    total_emails_sent: size(email_ids),
    reporters:        reporters
} AS snap
"""

_DOMAIN_Q = """
MATCH (d:Domain {name: $domain})
OPTIONAL MATCH (d)<-[:BELONGS_TO]-(s:Sender)
WITH d, count(DISTINCT s) AS total_senders
RETURN {
    last_seen:     d.last_seen,
    threat_score:  d.threat_score,
    total_senders: total_senders
} AS snap
"""

_EMAIL_Q = """
MATCH (e:Email {message_id: $message_id})
OPTIONAL MATCH (e)-[:DELIVERED_TO]->(r:Recipient)
OPTIONAL MATCH (e)-[:CONTAINS_URL]->(u:URL)
OPTIONAL MATCH (e)-[:HAS_ATTACHMENT]->(a:Attachment)
WITH e,
     collect(DISTINCT r.email)  AS recipients,
     collect(DISTINCT u.url)    AS urls,
     collect(DISTINCT a.sha256) AS attachments
RETURN {
    risk_score:  e.risk_score,
    llm_verdict: e.llm_verdict,
    received_at: e.received_at,
    recipients:  recipients,
    urls:        urls,
    attachments: attachments
} AS snap
"""


async def _snap(session, query: str, **params) -> dict | None:
    result = await session.run(query, **params)
    record = await result.single()
    return dict(record["snap"]) if record else None


# ── Output helpers ────────────────────────────────────────────────────────────

def _hr(char="━"): print(char * W)
def _section(title: str): print(f"\n{'═' * W}\n  {title}\n{'═' * W}")


def _diff(label: str, before: dict | None, after: dict | None) -> list[str]:
    """Print diff, return list of human-readable change descriptions."""
    _hr()
    print(f"  {label}")
    _hr()
    changes = []

    if before is None and after is None:
        print("  (not in graph)")
        return changes

    if before is None:
        print("  CREATED")
        for k, v in (after or {}).items():
            print(f"    + {k}: {v}")
        changes.append(f"{label}: created")
        return changes

    if after is None:
        print("  DELETED (unexpected)")
        return changes

    any_change = False
    for k in sorted(set(before) | set(after)):
        b, a = before.get(k), after.get(k)
        if b != a:
            any_change = True
            print(f"  {k}")
            if isinstance(b, list) and isinstance(a, list):
                added   = [x for x in a if x not in b]
                removed = [x for x in b if x not in a]
                if added:
                    print(f"    + {added}")
                    changes.append(f"{label}.{k} +{len(added)}")
                if removed:
                    print(f"    - {removed}")
            else:
                print(f"    {b}  →  {a}")
                changes.append(f"{label}.{k}: {b} → {a}")

    if not any_change:
        print("  (no changes)")

    return changes


# ── Payload builder ───────────────────────────────────────────────────────────

def build_payload(sender: str, recipient: str, org_id: str, threat_type: str | None) -> dict:
    return {
        "sender":       sender,
        "recipient":    recipient,
        "org_id":       org_id,
        "message_id":   f"delta-{uuid.uuid4().hex[:8]}",
        "subject_hash": "delta-check",
        "received_at":  "2026-07-01T12:00:00",
        "llm_verdict":  "THREAT" if threat_type else "CLEAN",
        "risk_score":   85.0 if threat_type else 10.0,
        "threat_type":  threat_type,
        "urls":         ["https://example-ioc.com/payload"] if threat_type else [],
        "attachments":  [],
    }


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(args: argparse.Namespace) -> None:
    sender      = args.sender
    recipient   = args.recipient
    org_id      = args.org_id
    threat_type = args.threat_type or None
    domain      = sender.split("@")[-1]

    payload    = build_payload(sender, recipient, org_id, threat_type)
    message_id = payload["message_id"]

    # Header
    _hr("═")
    print(f"  WRITE DELTA CHECK")
    _hr("═")
    print(f"  sender:       {sender}  →  {domain}")
    print(f"  recipient:    {recipient}  ({org_id})")
    print(f"  threat_type:  {threat_type or '(none — clean email)'}")
    print(f"  message_id:   {message_id}")
    print(f"  graph svc:    {GRAPH_SERVICE_URL}")

    driver = AsyncGraphDatabase.driver(
        NEO4J_URL,
        auth=(NEO4J_USER, NEO4J_PASSWORD),
        notifications_min_severity=NotificationMinimumSeverity.OFF,
    )
    try:
        await driver.verify_connectivity()
    except Exception as exc:
        print(f"\n  ERROR: cannot connect to Neo4j — {exc}")
        await driver.close()
        sys.exit(1)

    # ── BEFORE ───────────────────────────────────────────────────────────────
    async with driver.session() as s:
        before_sender = await _snap(s, _SENDER_Q, sender=sender)
        before_domain = await _snap(s, _DOMAIN_Q, domain=domain)
        before_email  = await _snap(s, _EMAIL_Q,  message_id=message_id)

    _section("BEFORE")
    print(f"  sender exists:  {before_sender is not None}")
    if before_sender:
        print(f"    email_count={before_sender['email_count']}  "
              f"threat_count={before_sender['threat_count']}  "
              f"threat_types={before_sender['threat_types']}")
    print(f"  domain exists:  {before_domain is not None}")
    print(f"  email exists:   {before_email is not None}  (expected: False)")

    # ── WRITE ─────────────────────────────────────────────────────────────────
    print(f"\n  POST /write ...")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(f"{GRAPH_SERVICE_URL}/write", json=payload)
            resp.raise_for_status()
            print(f"  HTTP {resp.status_code} — background task queued")
    except Exception as exc:
        print(f"  ERROR: {exc}")
        await driver.close()
        sys.exit(1)

    print(f"  settling ({WRITE_SETTLE_SECS}s)...")
    await asyncio.sleep(WRITE_SETTLE_SECS)

    # ── AFTER ────────────────────────────────────────────────────────────────
    async with driver.session() as s:
        after_sender = await _snap(s, _SENDER_Q, sender=sender)
        after_domain = await _snap(s, _DOMAIN_Q, domain=domain)
        after_email  = await _snap(s, _EMAIL_Q,  message_id=message_id)

    # ── DELTA ────────────────────────────────────────────────────────────────
    _section("DELTA")
    all_changes: list[str] = []
    all_changes += _diff(f"Sender  ({sender})",    before_sender, after_sender)
    all_changes += _diff(f"Domain  ({domain})",    before_domain, after_domain)
    all_changes += _diff(f"Email   ({message_id})", before_email,  after_email)

    # ── SUMMARY ──────────────────────────────────────────────────────────────
    _section("SUMMARY")
    email_created  = before_email is None and after_email is not None
    threat_flagged = (
        before_sender is not None and after_sender is not None
        and threat_type in (after_sender.get("threat_types") or [])
        and threat_type not in (before_sender.get("threat_types") or [])
    )
    urls_written   = after_email is not None and bool(after_email.get("urls"))

    print(f"  email node created:   {'✓' if email_created  else '✗'}")
    print(f"  email_count +1:       {'✓' if any('email_count' in c for c in all_changes) else '✗'}")
    print(f"  threat_count +1:      {'✓' if any('threat_count' in c for c in all_changes) else '✗  (clean email)'}")
    print(f"  FLAGGED_AS created:   {'✓  ' + threat_type if threat_flagged else '✗  (no new threat type)'}")
    print(f"  URL nodes written:    {'✓  ' + str(after_email.get('urls')) if urls_written else '✗  (no urls)'}")
    _hr()
    print()

    await driver.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Neo4j delta after a /write call")
    parser.add_argument("--sender",      default="newguy@startup.io", help="Sender email")
    parser.add_argument("--recipient",   default="analyst@himaya.ai", help="Recipient email")
    parser.add_argument("--org-id",      default="test-org-001",      help="Org ID")
    parser.add_argument("--threat-type", default=None,                 help="e.g. PHISHING (omit for clean)")
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
