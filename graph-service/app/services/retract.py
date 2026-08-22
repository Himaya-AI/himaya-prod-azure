from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Remove one specific threat type edge, or all FLAGGED_AS edges if threat_type is None
_RETRACT_ONE = """
MATCH (s:Sender {email: $sender})-[r:FLAGGED_AS]->(t:ThreatType {type: $threat_type})
DELETE r
RETURN count(r) AS removed
"""

_RETRACT_ALL = """
MATCH (s:Sender {email: $sender})-[r:FLAGGED_AS]->(:ThreatType)
DELETE r
RETURN count(r) AS removed
"""

# Retraction must also undo the trust damage. FLAGGED_AS edges feed the
# known_threat_type / similar_threat_senders penalties, but threat_count and
# reputation_score on the Sender node feed the threat-rate penalty — leaving
# them behind keeps the sender permanently distrusted after exoneration.
_RECOMPUTE = """
MATCH (s:Sender {email: $sender})
OPTIONAL MATCH (s)-[f:FLAGGED_AS]->(:ThreatType)
WITH s, count(f) AS remaining
SET s.threat_count = remaining,
    s.reputation_score = CASE
        WHEN coalesce(s.email_count, 0) = 0 THEN 0
        ELSE toInteger(100.0 * remaining / s.email_count)
    END
"""


async def retract_threat(
    neo4j_service,
    sender: str,
    threat_type: str | None,
) -> int:
    """
    Remove FLAGGED_AS edge(s) for a sender on a false-positive report.
    Returns the number of edges removed.
    """
    query  = _RETRACT_ONE if threat_type else _RETRACT_ALL
    params = {"sender": sender, **({"threat_type": threat_type} if threat_type else {})}

    async with neo4j_service.session() as session:
        result = await session.run(query, **params)
        record = await result.single()
        await session.run(_RECOMPUTE, sender=sender)

    removed = record["removed"] if record else 0
    logger.info(
        "retract | sender=%s threat_type=%s removed=%d edge(s)",
        sender, threat_type or "*", removed,
    )
    return removed
