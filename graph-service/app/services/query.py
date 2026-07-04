from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ── Cypher ────────────────────────────────────────────────────────────────────

GRAPH_QUERY = """
MATCH (s:Sender {email: $sender})
OPTIONAL MATCH (s)-[:BELONGS_TO]->(d:Domain)
OPTIONAL MATCH (s)-[:FLAGGED_AS]->(t:ThreatType)
WITH s, d, collect(DISTINCT t.type) AS sender_threat_types

CALL {
    WITH s
    OPTIONAL MATCH (s)-[e:SENT]->(email:Email)-[:DELIVERED_TO]->(rec:Recipient {email: $recipient, org_id: $org_id})
    RETURN count(email)           AS prior_emails,
           max(email.received_at) AS last_contact
}

CALL {
    WITH d
    OPTIONAL MATCH (d)<-[:BELONGS_TO]-(ds:Sender)
    RETURN
        count(DISTINCT ds)                                                                           AS total_senders,
        sum(coalesce(ds.email_count, 0))                                                             AS domain_total_emails,
        sum(coalesce(ds.threat_count, 0))                                                            AS domain_flagged_emails,
        count(DISTINCT CASE WHEN coalesce(ds.threat_count, 0) > 0 THEN ds.email ELSE null END)      AS flagged_senders
}

CALL {
    WITH d
    OPTIONAL MATCH (d)<-[:BELONGS_TO]-(:Sender)-[:SENT]->(:Email)-[:DELIVERED_TO]->(r:Recipient)
    RETURN count(DISTINCT r.org_id) AS orgs_targeted
}

CALL {
    WITH d
    OPTIONAL MATCH (d)<-[:BELONGS_TO]-(:Sender)-[:FLAGGED_AS]->(dt:ThreatType)
    RETURN collect(DISTINCT dt.type) AS domain_threat_types
}

CALL {
    WITH s
    OPTIONAL MATCH (s)-[:REPORTED_BY]->(rep:Reporter)
    WHERE rep.org_id <> $org_id
    RETURN count(DISTINCT rep.org_id) AS reported_by_other_orgs
}

CALL {
    WITH s
    OPTIONAL MATCH (s)-[:FLAGGED_AS]->(:ThreatType)<-[:FLAGGED_AS]-(sim:Sender)
    WHERE sim.email <> s.email
    RETURN collect(DISTINCT sim.email)[0..5] AS similar_threat_senders
}


RETURN {
    sender: {
        email_count:             coalesce(s.email_count, 0),
        threat_count:            coalesce(s.threat_count, 0),
        reputation_score:        coalesce(s.reputation_score, 0),
        first_seen:              s.first_seen,
        historical_threat_types: sender_threat_types
    },
    domain: {
        total_emails:            coalesce(domain_total_emails, 0),
        flagged_emails:          coalesce(domain_flagged_emails, 0),
        flagged_email_rate:      CASE
                                     WHEN coalesce(domain_total_emails, 0) > 0
                                     THEN round(
                                              toFloat(coalesce(domain_flagged_emails, 0))
                                              / domain_total_emails * 100000
                                          ) / 100000
                                     ELSE 0.0
                                 END,
        total_senders:           coalesce(total_senders, 0),
        flagged_senders:         coalesce(flagged_senders, 0),
        orgs_targeted:           coalesce(orgs_targeted, 0),
        threat_score:            coalesce(d.threat_score, 0),
        first_seen:              coalesce(d.first_seen, s.first_seen),
        last_seen:               coalesce(d.last_seen, s.last_seen),
        associated_threat_types: domain_threat_types
    },
    relationship: {
        prior_emails_to_recipient: coalesce(prior_emails, 0),
        last_contact:              last_contact
    },
    intel: {
        reported_by_other_orgs:  coalesce(reported_by_other_orgs, 0),
        similar_threat_senders:  similar_threat_senders
    }
} AS result
"""

# ── Query ─────────────────────────────────────────────────────────────────────

async def execute_query(
    neo4j_service,
    sender: str,
    recipient: str,
    org_id: str,
) -> dict:
    async with neo4j_service.session() as session:
        result = await session.run(
            GRAPH_QUERY,
            sender=sender,
            recipient=recipient,
            org_id=org_id,
        )
        record = await result.single()

    if record is None:
        logger.info("Sender %s not found in graph — returning new sender defaults", sender)
        return _new_sender_defaults()

    return dict(record["result"])


# ── Defaults ──────────────────────────────────────────────────────────────────

def _new_sender_defaults() -> dict:
    return {
        "sender": {
            "email_count":             0,
            "threat_count":            0,
            "reputation_score":        0,
            "first_seen":              None,
            "historical_threat_types": [],
        },
        "domain": {
            "total_emails":            0,
            "flagged_emails":          0,
            "flagged_email_rate":      0.0,
            "total_senders":           0,
            "flagged_senders":         0,
            "orgs_targeted":           0,
            "threat_score":            0,
            "first_seen":              None,
            "last_seen":               None,
            "associated_threat_types": [],
        },
        "relationship": {
            "prior_emails_to_recipient": 0,
            "last_contact":              None,
        },
        "intel": {
            "reported_by_other_orgs":  0,
            "similar_threat_senders":  [],
        },
    }
