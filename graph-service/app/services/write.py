from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ── Cypher ────────────────────────────────────────────────────────────────────

_CORE = """
MERGE (s:Sender {email: $sender})
ON CREATE SET s.domain          = $domain,
              s.first_seen      = $received_at,
              s.email_count     = 0,
              s.threat_count    = 0,
              s.reputation_score = 0
SET s.last_seen      = $received_at,
    s.email_count    = coalesce(s.email_count, 0) + 1,
    s.threat_count   = coalesce(s.threat_count, 0) + CASE WHEN $is_threat THEN 1 ELSE 0 END,
    s.reputation_score = CASE
        WHEN (coalesce(s.email_count, 0) + 1) = 0 THEN 0
        ELSE toInteger(
            100.0
            * (coalesce(s.threat_count, 0) + CASE WHEN $is_threat THEN 1 ELSE 0 END)
            / (coalesce(s.email_count, 0) + 1)
        )
    END
WITH s
MERGE (d:Domain {name: $domain})
ON CREATE SET d.first_seen   = $received_at,
              d.threat_score  = 0
SET d.last_seen = $received_at
MERGE (s)-[:BELONGS_TO]->(d)
WITH s
MERGE (r:Recipient {email: $recipient, org_id: $org_id})
WITH s, r
CREATE (e:Email {
    message_id:   $message_id,
    subject_hash: $subject_hash,
    received_at:  $received_at,
    llm_verdict:  $llm_verdict,
    risk_score:   $risk_score
})
CREATE (s)-[:SENT]->(e)
CREATE (e)-[:DELIVERED_TO]->(r)
"""

_THREAT = """
MATCH (s:Sender {email: $sender})
MERGE (t:ThreatType {type: $threat_type})
MERGE (s)-[:FLAGGED_AS]->(t)
"""

_URL = """
MATCH (e:Email {message_id: $message_id})
MERGE (u:URL {url: $url})
ON CREATE SET u.domain          = $url_domain,
              u.first_seen      = $received_at,
              u.reputation_score = 0
SET u.last_seen = $received_at
MERGE (e)-[:CONTAINS_URL]->(u)
WITH u
MERGE (d:Domain {name: $url_domain})
MERGE (u)-[:HOSTED_ON]->(d)
"""

_ATTACHMENT = """
MATCH (e:Email {message_id: $message_id})
MERGE (a:Attachment {sha256: $sha256})
ON CREATE SET a.filename         = $filename,
              a.extension        = $extension,
              a.reputation_score = 0
MERGE (e)-[:HAS_ATTACHMENT]->(a)
"""

# ── Public ────────────────────────────────────────────────────────────────────

async def record_communication(neo4j_service, data: dict) -> None:
    """
    Write a processed email into the graph.
    Called fire-and-forget from the /write route background task.
    """
    try:
        await _record_communication(neo4j_service, data)
    except Exception as exc:
        logger.error("write.record_communication failed (message_id=%s): %s: %s",
                     data.get("message_id"), type(exc).__name__, exc)


async def _record_communication(neo4j_service, data: dict) -> None:
    sender      = data["sender"]
    recipient   = data["recipient"]
    org_id      = data["org_id"]
    domain      = sender.split("@")[-1] if "@" in sender else sender
    threat_type = data.get("threat_type")
    is_threat   = bool(threat_type)

    await _write_core(neo4j_service, {
        "sender":       sender,
        "recipient":    recipient,
        "org_id":       org_id,
        "domain":       domain,
        "message_id":   data.get("message_id", ""),
        "subject_hash": data.get("subject_hash", ""),
        "received_at":  data.get("received_at", ""),
        "llm_verdict":  data.get("llm_verdict"),
        "risk_score":   data.get("risk_score", 0),
        "is_threat":    is_threat,
    })

    if is_threat:
        await _write_threat(neo4j_service, sender, threat_type)

    for url in data.get("urls", []):
        await _write_url(neo4j_service, data.get("message_id", ""), url, data.get("received_at", ""))

    for attachment in data.get("attachments", []):
        await _write_attachment(neo4j_service, data.get("message_id", ""), attachment)


# ── Private ───────────────────────────────────────────────────────────────────

async def _write_core(neo4j_service, params: dict) -> None:
    async with neo4j_service.session() as session:
        await session.run(_CORE, **params)


async def _write_threat(neo4j_service, sender: str, threat_type: str) -> None:
    async with neo4j_service.session() as session:
        await session.run(_THREAT, sender=sender, threat_type=threat_type)


async def _write_url(neo4j_service, message_id: str, url: str, received_at: str) -> None:
    url_domain = url.split("/")[2] if url.startswith("http") else url
    async with neo4j_service.session() as session:
        await session.run(
            _URL,
            message_id=message_id,
            url=url,
            url_domain=url_domain,
            received_at=received_at,
        )


async def _write_attachment(neo4j_service, message_id: str, attachment: dict) -> None:
    async with neo4j_service.session() as session:
        await session.run(
            _ATTACHMENT,
            message_id=message_id,
            sha256=attachment.get("sha256", ""),
            filename=attachment.get("filename", ""),
            extension=attachment.get("extension", ""),
        )
