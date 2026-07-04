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

    removed = record["removed"] if record else 0
    logger.info(
        "retract | sender=%s threat_type=%s removed=%d edge(s)",
        sender, threat_type or "*", removed,
    )
    return removed
