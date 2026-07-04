"""
Seed script — populates Neo4j with test data covering all trust scoring paths.

Usage:
    python scripts/seed.py

Env vars (or set in .env):
    NEO4J_URL       bolt://<host>:7687
    NEO4J_USER      neo4j
    NEO4J_PASSWORD  <password>
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from neo4j import AsyncGraphDatabase

NEO4J_URL      = os.getenv("NEO4J_URL",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "graph_dev_password")

TEST_ORG_ID    = os.getenv("TEST_ORG_ID",    "test-org-001")
TEST_RECIPIENT = os.getenv("TEST_RECIPIENT", "analyst@himaya.ai")


# ── Scenarios ─────────────────────────────────────────────────────────────────

SCENARIOS = [

    # 1. Trusted sender — high volume, 0 threats, clean domain, prior relationship
    #    Expected: deterministic → score ~70 → skip_classification=True
    {
        "name": "trusted_sender",
        "sender_email":   "alice@trusted-corp.com",
        "sender_domain":  "trusted-corp.com",
        "email_count":    120,
        "threat_count":   0,
        "reputation_score": 0,
        "first_seen":     "2023-01-15",
        "last_seen":      "2025-06-19",
        "prior_emails":   18,
        "threat_types":   [],
        "domain_total":   500,
        "domain_flagged": 0,
        "campaign":       None,
        "reported_by":    0,
        "similar":        [],
    },

    # 2. Insufficient history — brand new sender, < 5 emails
    #    Expected: insufficient_history → trusted=False
    {
        "name": "new_sender",
        "sender_email":   "newguy@startup.io",
        "sender_domain":  "startup.io",
        "email_count":    2,
        "threat_count":   0,
        "reputation_score": 0,
        "first_seen":     "2025-06-18",
        "last_seen":      "2025-06-19",
        "prior_emails":   0,
        "threat_types":   [],
        "domain_total":   2,
        "domain_flagged": 0,
        "campaign":       None,
        "reported_by":    0,
        "similar":        [],
    },

    # 3. Campaign-linked sender — hard block
    #    Expected: block → trusted=False
    {
        "name": "campaign_sender",
        "sender_email":   "attacker@phish-wave.com",
        "sender_domain":  "phish-wave.com",
        "email_count":    80,
        "threat_count":   60,
        "reputation_score": 75,
        "first_seen":     "2025-05-01",
        "last_seen":      "2025-06-19",
        "prior_emails":   0,
        "threat_types":   ["PHISHING"],
        "domain_total":   300,
        "domain_flagged": 240,
        "campaign":       {
            "campaign_id": "camp-001",
            "name":        "Gulf Phishing Wave Q2",
            "confidence":  0.95,
            "first_seen":  "2025-05-01",
            "last_seen":   "2025-06-19",
        },
        "reported_by":    5,
        "similar":        ["mirror@phish-wave.com", "alert@phish-wave.net"],
    },

    # 4. Cross-org reported sender — hard block
    #    Expected: block → trusted=False
    {
        "name": "reported_sender",
        "sender_email":   "scammer@evil-domain.net",
        "sender_domain":  "evil-domain.net",
        "email_count":    30,
        "threat_count":   10,
        "reputation_score": 33,
        "first_seen":     "2025-03-10",
        "last_seen":      "2025-06-15",
        "prior_emails":   1,
        "threat_types":   ["BEC"],
        "domain_total":   40,
        "domain_flagged": 12,
        "campaign":       None,
        "reported_by":    3,   # 3 other orgs reported this sender
        "similar":        [],
    },

    # 5. PHISHING history sender — deterministic, low score
    #    Expected: deterministic → score low → skip_classification=False
    {
        "name": "phishing_history_sender",
        "sender_email":   "risky@dodgy-corp.com",
        "sender_domain":  "dodgy-corp.com",
        "email_count":    25,
        "threat_count":   8,
        "reputation_score": 32,
        "first_seen":     "2024-11-01",
        "last_seen":      "2025-06-10",
        "prior_emails":   2,
        "threat_types":   ["PHISHING", "SPOOFING"],
        "domain_total":   60,
        "domain_flagged": 20,
        "campaign":       None,
        "reported_by":    0,
        "similar":        [],
    },

    # 6. Similar threat senders — hard block
    #    Expected: block → trusted=False
    {
        "name": "similar_threat_sender",
        "sender_email":   "lookalike@trusted-c0rp.com",
        "sender_domain":  "trusted-c0rp.com",
        "email_count":    15,
        "threat_count":   5,
        "reputation_score": 33,
        "first_seen":     "2025-04-01",
        "last_seen":      "2025-06-18",
        "prior_emails":   0,
        "threat_types":   ["IMPERSONATION"],
        "domain_total":   20,
        "domain_flagged": 6,
        "campaign":       None,
        "reported_by":    0,
        "similar":        ["attacker@phish-wave.com", "scammer@evil-domain.net"],
    },

    # 7. Borderline sender — ambiguous, just below threshold
    #    Expected: deterministic → score ~55-60 → skip_classification=False
    {
        "name": "borderline_sender",
        "sender_email":   "vendor@mid-range.com",
        "sender_domain":  "mid-range.com",
        "email_count":    20,
        "threat_count":   0,
        "reputation_score": 0,
        "first_seen":     "2024-06-01",
        "last_seen":      "2025-06-19",
        "prior_emails":   3,
        "threat_types":   [],
        "domain_total":   80,
        "domain_flagged": 4,   # flagged_rate = 5% → -20 pts
        "campaign":       None,
        "reported_by":    0,
        "similar":        [],
    },
]


# ── Seed logic ────────────────────────────────────────────────────────────────

async def seed(driver) -> None:
    async with driver.session() as s:
        print("Clearing previous test data...")
        # Delete Email nodes reachable from seed senders first (they have no email/org_id property)
        await s.run(
            "MATCH (sender:Sender)-[:SENT]->(e:Email) "
            "WHERE sender.email ENDS WITH '@trusted-corp.com' "
            "OR sender.email ENDS WITH '@startup.io' OR sender.email ENDS WITH '@phish-wave.com' "
            "OR sender.email ENDS WITH '@evil-domain.net' OR sender.email ENDS WITH '@dodgy-corp.com' "
            "OR sender.email ENDS WITH '@trusted-c0rp.com' OR sender.email ENDS WITH '@mid-range.com' "
            "DETACH DELETE e"
        )
        await s.run(
            "MATCH (n) WHERE n.org_id = $org_id OR n.email ENDS WITH '@trusted-corp.com' "
            "OR n.email ENDS WITH '@startup.io' OR n.email ENDS WITH '@phish-wave.com' "
            "OR n.email ENDS WITH '@evil-domain.net' OR n.email ENDS WITH '@dodgy-corp.com' "
            "OR n.email ENDS WITH '@trusted-c0rp.com' OR n.email ENDS WITH '@mid-range.com' "
            "DETACH DELETE n",
            org_id=TEST_ORG_ID,
        )

    for scenario in SCENARIOS:
        print(f"Seeding: {scenario['name']} ({scenario['sender_email']})...")
        await _seed_scenario(driver, scenario)

    print("\nDone. Test with:")
    for s in SCENARIOS:
        print(f"  POST /evaluate  sender={s['sender_email']}  recipient={TEST_RECIPIENT}  org_id={TEST_ORG_ID}")


async def _seed_scenario(driver, s: dict) -> None:
    async with driver.session() as session:
        # Sender + Domain
        await session.run("""
            MERGE (sender:Sender {email: $email})
            SET sender.domain          = $domain,
                sender.first_seen      = $first_seen,
                sender.last_seen       = $last_seen,
                sender.email_count     = $email_count,
                sender.threat_count    = $threat_count,
                sender.reputation_score = $reputation_score
            MERGE (d:Domain {name: $domain})
            SET d.first_seen  = $first_seen,
                d.last_seen   = $last_seen,
                d.threat_score = $domain_threat_score
            MERGE (sender)-[:BELONGS_TO]->(d)
        """,
            email=s["sender_email"],
            domain=s["sender_domain"],
            first_seen=s["first_seen"],
            last_seen=s["last_seen"],
            email_count=s["email_count"],
            threat_count=s["threat_count"],
            reputation_score=s["reputation_score"],
            domain_threat_score=int(s["domain_flagged"] / max(s["domain_total"], 1) * 100),
        )

        # Recipient + prior email edges
        await session.run("""
            MERGE (r:Recipient {email: $recipient, org_id: $org_id})
        """, recipient=TEST_RECIPIENT, org_id=TEST_ORG_ID)

        for i in range(s["prior_emails"]):
            await session.run("""
                MATCH (sender:Sender {email: $email})
                MATCH (r:Recipient {email: $recipient, org_id: $org_id})
                MERGE (e:Email {message_id: $msg_id})
                SET e.subject_hash = 'seed',
                    e.received_at  = '2025-06-01',
                    e.llm_verdict  = 'CLEAN',
                    e.risk_score   = 0
                MERGE (sender)-[:SENT]->(e)
                MERGE (e)-[:DELIVERED_TO]->(r)
            """,
                email=s["sender_email"],
                recipient=TEST_RECIPIENT,
                org_id=TEST_ORG_ID,
                msg_id=f"seed-{s['name']}-{i}",
            )

        # Threat types
        for t in s["threat_types"]:
            await session.run("""
                MATCH (sender:Sender {email: $email})
                MERGE (tt:ThreatType {type: $threat_type})
                MERGE (sender)-[:FLAGGED_AS]->(tt)
            """, email=s["sender_email"], threat_type=t)

        # Domain email volume (extra senders on domain)
        if s["domain_total"] > 0:
            await session.run("""
                MATCH (d:Domain {name: $domain})
                SET d.total_emails   = $total,
                    d.flagged_emails = $flagged
            """,
                domain=s["sender_domain"],
                total=s["domain_total"],
                flagged=s["domain_flagged"],
            )

        # Campaign
        if s["campaign"]:
            c = s["campaign"]
            await session.run("""
                MATCH (sender:Sender {email: $email})
                MERGE (cam:Campaign {campaign_id: $campaign_id})
                SET cam.name       = $name,
                    cam.confidence = $confidence,
                    cam.first_seen = $first_seen,
                    cam.last_seen  = $last_seen
                WITH sender, cam
                MATCH (sender)-[:SENT]->(e:Email)
                MERGE (e)-[:PART_OF]->(cam)
            """,
                email=s["sender_email"],
                campaign_id=c["campaign_id"],
                name=c["name"],
                confidence=c["confidence"],
                first_seen=c["first_seen"],
                last_seen=c["last_seen"],
            )

        # Cross-org reporters
        for i in range(s["reported_by"]):
            await session.run("""
                MATCH (sender:Sender {email: $email})
                MERGE (rep:Reporter {email: $reporter_email, org_id: $reporter_org})
                MERGE (sender)-[:REPORTED_BY]->(rep)
            """,
                email=s["sender_email"],
                reporter_email=f"reporter{i}@other-org-{i}.com",
                reporter_org=f"other-org-{i:03d}",
            )

        # Similar threat senders (shared ThreatType edges)
        for sim_email in s["similar"]:
            sim_domain = sim_email.split("@")[-1]
            for threat_type in (s["threat_types"] or ["PHISHING"]):
                await session.run("""
                    MERGE (sim:Sender {email: $sim_email})
                    SET sim.domain = $sim_domain
                    MERGE (tt:ThreatType {type: $threat_type})
                    MERGE (sim)-[:FLAGGED_AS]->(tt)
                """, sim_email=sim_email, sim_domain=sim_domain, threat_type=threat_type)


# ── Entry point ───────────────────────────────────────────────────────────────

async def main() -> None:
    print(f"Connecting to Neo4j at {NEO4J_URL}...")
    driver = AsyncGraphDatabase.driver(NEO4J_URL, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        await driver.verify_connectivity()
        print("Connected.\n")
        await seed(driver)
    finally:
        await driver.close()


if __name__ == "__main__":
    asyncio.run(main())
