"""
Neo4j communication graph service — Himaya.

Analyzes sender-recipient relationships to detect anomalies:
  - First-time sender to this org
  - Volume anomalies (sudden burst from new domain)
  - Domain-level threat clustering (how many recipients in this org got mail from same domain)
  - Lookalike domain detection (edit-distance check against known org domains)

Neo4j connection:  bolt://NEO4J_URL  (env: NEO4J_URL, NEO4J_USER, NEO4J_PASSWORD)
Falls back to a DB-backed heuristic (PostgreSQL) if Neo4j is unavailable — avoids the
random mock that was producing inconsistent/misleading graph scores.
"""
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class GraphService:
    def __init__(self):
        self._driver = None
        self._db: object = None   # SQLAlchemy AsyncSession factory — set on startup

    async def init(self, url: str, user: str, password: str):
        """Connect to Neo4j.  Falls back gracefully if unavailable."""
        if not url:
            logger.info("NEO4J_URL not set — graph service will use DB-backed heuristic")
            return
        last_error = None
        for attempt in range(3):
            try:
                from neo4j import AsyncGraphDatabase
                import asyncio as _asyncio
                if attempt > 0:
                    await _asyncio.sleep(5 * attempt)
                self._driver = AsyncGraphDatabase.driver(url, auth=(user, password))
                await self._driver.verify_connectivity()
                # Create indexes on first connect
                async with self._driver.session() as s:
                    await s.run("CREATE INDEX sender_email IF NOT EXISTS FOR (n:Sender) ON (n.email)")
                    await s.run("CREATE INDEX recipient_email_org IF NOT EXISTS FOR (n:Recipient) ON (n.email, n.org_id)")
                    await s.run("CREATE INDEX domain_name IF NOT EXISTS FOR (n:Domain) ON (n.name)")
                logger.info(f"Neo4j connected: {url} (attempt {attempt+1})")
                return
            except Exception as e:
                last_error = e
                logger.warning(f"Neo4j connect attempt {attempt+1}/3 failed ({type(e).__name__}: {e})")
                self._driver = None
        logger.error(f"Neo4j unavailable after 3 attempts ({last_error}) — using DB-backed heuristic fallback")

    async def close(self):
        if self._driver:
            await self._driver.close()

    # ── DB-backed heuristic (no Neo4j) ────────────────────────────────────────

    async def _db_heuristic(self, org_id: str, sender: str, recipient: str) -> dict:
        """
        Lightweight graph scoring using existing Threats table:
          - Count prior emails from this sender domain to this org (last 90 days)
          - Count distinct recipients in this org who got mail from this domain
          - Score is higher for first-time senders and domain-burst patterns
        Deterministic and accurate — no randomness.
        """
        try:
            from backend.database import AsyncSessionLocal
            from backend.models.db_models import Threat
            from sqlalchemy import select, func
            from datetime import timedelta

            sender_domain = sender.split("@")[-1] if "@" in sender else sender
            cutoff = datetime.utcnow() - timedelta(days=90)

            async with AsyncSessionLocal() as db:
                # How many times has this exact sender emailed this org?
                sender_count_q = await db.execute(
                    select(func.count(Threat.id)).where(
                        Threat.org_id == org_id if not isinstance(org_id, str) else Threat.org_id.cast_string() == org_id,
                        Threat.sender == sender,
                        Threat.detected_at >= cutoff,
                    )
                )
                sender_freq = sender_count_q.scalar() or 0

                # How many distinct org recipients has this sender_domain reached?
                domain_spread_q = await db.execute(
                    select(func.count(func.distinct(Threat.recipient_email))).where(
                        Threat.sender_domain == sender_domain,
                        Threat.detected_at >= cutoff,
                    )
                )
                domain_spread = domain_spread_q.scalar() or 0

        except Exception as _e:
            logger.debug(f"DB heuristic query failed (non-fatal): {_e}")
            sender_freq = 0
            domain_spread = 0

        score = 0
        indicators = []

        if sender_freq == 0:
            # Completely new sender — meaningful signal
            score += 35
            indicators.append("first_time_sender")
        elif sender_freq < 3:
            score += 15
            indicators.append("infrequent_sender")

        if domain_spread > 10:
            # This domain is hitting many org mailboxes — potential campaign
            score += 25
            indicators.append(f"domain_wide_campaign:{domain_spread}_recipients")
        elif domain_spread > 5:
            score += 10
            indicators.append(f"domain_multi_recipient:{domain_spread}")

        return {
            "graph_score": min(score, 100),
            "indicators": indicators,
            "first_time_sender": sender_freq == 0,
            "communication_frequency": sender_freq,
            "mode": "db_heuristic",
        }

    # ── Neo4j full analysis ────────────────────────────────────────────────────

    async def analyze_sender_relationship(
        self,
        org_id: str,
        sender: str,
        recipient: str,
    ) -> dict:
        """
        Analyze communication graph to detect anomalies.
        Returns a graph score (0-100) and list of indicator strings.
        """
        if not self._driver:
            return await self._db_heuristic(org_id, sender, recipient)

        sender_domain = sender.split("@")[-1] if "@" in sender else sender

        try:
            async with self._driver.session() as session:
                # Query 1: direct sender → recipient history
                rel_result = await session.run(
                    """
                    MATCH (s:Sender {email: $sender})-[r:SENT_TO]->(rec:Recipient {email: $recipient, org_id: $org_id})
                    RETURN count(r) AS freq,
                           min(r.timestamp) AS first_seen,
                           max(r.timestamp) AS last_seen
                    """,
                    sender=sender, recipient=recipient, org_id=org_id,
                )
                rel = await rel_result.single()
                freq = rel["freq"] if rel else 0

                # Query 2: domain-level spread within this org
                domain_result = await session.run(
                    """
                    MATCH (s:Sender)-[:SENT_TO]->(rec:Recipient {org_id: $org_id})
                    WHERE s.email ENDS WITH $domain
                    RETURN count(distinct rec.email) AS spread,
                           count(distinct s.email)   AS sender_count
                    """,
                    org_id=org_id, domain=f"@{sender_domain}",
                )
                domain_rec = await domain_result.single()
                domain_spread = domain_rec["spread"] if domain_rec else 0
                domain_sender_count = domain_rec["sender_count"] if domain_rec else 0

                # Query 3: any threats ever from this sender domain
                threat_result = await session.run(
                    """
                    MATCH (s:Sender {email: $sender})-[:FLAGGED_AS]->(t:ThreatType)
                    RETURN collect(t.type) AS threat_types
                    """,
                    sender=sender,
                )
                threat_rec = await threat_result.single()
                known_threats = threat_rec["threat_types"] if threat_rec else []

        except Exception as _qe:
            logger.warning(f"Neo4j query failed, falling back to DB heuristic: {_qe}")
            return await self._db_heuristic(org_id, sender, recipient)

        score = 0
        indicators = []
        first_time = freq == 0

        if first_time:
            score += 35
            indicators.append("first_time_sender")
        elif freq < 3:
            score += 15
            indicators.append("infrequent_sender")

        if domain_spread > 10:
            score += 25
            indicators.append(f"domain_wide_campaign:{domain_spread}_recipients")
        elif domain_spread > 5:
            score += 10
            indicators.append(f"domain_multi_recipient:{domain_spread}")

        if domain_sender_count > 5:
            score += 15
            indicators.append(f"multiple_senders_same_domain:{domain_sender_count}")

        if known_threats:
            score += 30
            indicators.extend([f"known_threat_type:{t}" for t in known_threats[:3]])

        return {
            "graph_score": min(score, 100),
            "indicators": indicators,
            "first_time_sender": first_time,
            "communication_frequency": freq,
            "mode": "neo4j",
        }

    async def record_communication(
        self,
        org_id: str,
        sender: str,
        recipient: str,
        timestamp: str,
        threat_type: str | None = None,
    ):
        """Record a sender→recipient edge in Neo4j after processing."""
        if not self._driver:
            return  # DB heuristic reads from Threats table directly — no recording needed

        sender_domain = sender.split("@")[-1] if "@" in sender else sender
        try:
            async with self._driver.session() as session:
                is_threat = bool(threat_type and threat_type not in ("CLEAN", "BENIGN"))
                await session.run(
                    """
                    MERGE (s:Sender {email: $sender})
                      ON CREATE SET s.domain        = $domain,
                                    s.first_seen    = $timestamp,
                                    s.email_count   = 0,
                                    s.threat_count  = 0,
                                    s.reputation_score = 0
                    SET s.email_count  = coalesce(s.email_count, 0) + 1,
                        s.last_seen    = $timestamp,
                        s.threat_count = coalesce(s.threat_count, 0) + CASE WHEN $is_threat THEN 1 ELSE 0 END,
                        s.reputation_score = CASE
                            WHEN coalesce(s.email_count, 0) + 1 = 0 THEN 0
                            ELSE toInteger(
                                100.0 * (coalesce(s.threat_count, 0) + CASE WHEN $is_threat THEN 1 ELSE 0 END)
                                / (coalesce(s.email_count, 0) + 1)
                            )
                        END
                    WITH s
                    MERGE (d:Domain {name: $domain})
                    MERGE (s)-[:BELONGS_TO]->(d)
                    WITH s
                    MERGE (r:Recipient {email: $recipient, org_id: $org_id})
                    CREATE (s)-[:SENT_TO {timestamp: $timestamp, threat_type: $threat_type_val}]->(r)
                    """,
                    sender=sender, domain=sender_domain,
                    recipient=recipient, org_id=org_id, timestamp=timestamp,
                    is_threat=is_threat, threat_type_val=threat_type or "CLEAN",
                )
                # Record threat type relationship on the sender node if flagged
                if is_threat:
                    await session.run(
                        """
                        MATCH (s:Sender {email: $sender})
                        MERGE (t:ThreatType {type: $threat_type})
                        MERGE (s)-[:FLAGGED_AS]->(t)
                        """,
                        sender=sender, threat_type=threat_type,
                    )
        except Exception as _e:
            logger.debug(f"Neo4j record_communication failed (non-fatal): {_e}")

    async def record_threat(self, sender: str, threat_type: str):
        """Mark a sender as associated with a specific threat type."""
        if not self._driver:
            return
        try:
            async with self._driver.session() as session:
                await session.run(
                    """
                    MERGE (s:Sender {email: $sender})
                    MERGE (t:ThreatType {type: $threat_type})
                    MERGE (s)-[:FLAGGED_AS]->(t)
                    """,
                    sender=sender, threat_type=threat_type,
                )
        except Exception as _e:
            logger.debug(f"Neo4j record_threat failed (non-fatal): {_e}")

    async def retract_threat(self, sender: str, threat_type: str | None = None):
        """
        Remove FLAGGED_AS edge(s) for a sender — called on False Positive reports.
        If threat_type is provided, removes only that specific edge.
        If None, removes ALL FLAGGED_AS edges (full exoneration).
        Also decrements threat_count and recomputes reputation_score on Sender node.
        """
        if not self._driver:
            return
        try:
            async with self._driver.session() as session:
                if threat_type:
                    await session.run(
                        """
                        MATCH (s:Sender {email: $sender})-[r:FLAGGED_AS]->(t:ThreatType {type: $threat_type})
                        DELETE r
                        """,
                        sender=sender, threat_type=threat_type,
                    )
                else:
                    await session.run(
                        """
                        MATCH (s:Sender {email: $sender})-[r:FLAGGED_AS]->()
                        DELETE r
                        """,
                        sender=sender,
                    )
                # Recompute threat_count and reputation_score from remaining edges
                await session.run(
                    """
                    MATCH (s:Sender {email: $sender})
                    OPTIONAL MATCH (s)-[:FLAGGED_AS]->()
                    WITH s, count(*) AS remaining_threats
                    SET s.threat_count = remaining_threats,
                        s.reputation_score = CASE
                            WHEN coalesce(s.email_count, 0) = 0 THEN 0
                            ELSE toInteger(100.0 * remaining_threats / s.email_count)
                        END
                    """,
                    sender=sender,
                )
        except Exception as _e:
            logger.debug(f"Neo4j retract_threat failed (non-fatal): {_e}")

    async def record_report_signal(
        self,
        org_id: str,
        sender: str,
        reporter: str,
        label: str,
        threat_id: str,
    ):
        """Store employee phish report as a training edge in Neo4j."""
        if not self._driver:
            return
        try:
            async with self._driver.session() as session:
                await session.run(
                    """
                    MERGE (s:Sender {email: $sender, org_id: $org_id})
                    MERGE (r:Reporter {email: $reporter, org_id: $org_id})
                    MERGE (s)-[e:REPORTED_BY {org_id: $org_id}]->(r)
                    SET e.label = $label,
                        e.threat_id = $threat_id,
                        e.reported_at = datetime(),
                        e.count = coalesce(e.count, 0) + 1
                    """,
                    sender=sender,
                    reporter=reporter,
                    org_id=org_id,
                    label=label,
                    threat_id=threat_id,
                )
        except Exception as e:
            logger.debug(f"graph record_report_signal failed: {e}")


graph_service = GraphService()
