"""
Himaya Helios - MODEL-004: Action Engine
Generates structured ThreatActionRecord with compliance mappings and Redis publishing.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any

from models.shared.schemas import (
    ThreatActionRecord,
    ThreatClassification,
    RiskAction,
    ComplianceControl,
    EmailMetadata,
    EmailDirection,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SAMA / NCA Compliance Control Mappings
# ---------------------------------------------------------------------------

COMPLIANCE_CONTROLS: dict[ThreatClassification, dict[str, str]] = {
    ThreatClassification.BEC: {
        "sama_id": "SAMA CSF 3.3.3",
        "nca_id": "NCA ECC 2-7-3",
        "name": "Business Email Compromise Prevention",
        "sama_desc": (
            "Controls for detecting Business Email Compromise (BEC) attacks, "
            "including wire fraud, payroll diversion, and CEO/CFO fraud patterns."
        ),
        "nca_desc": (
            "Detection and prevention of email-based financial fraud targeting "
            "employees with financial authority."
        ),
    },
    ThreatClassification.PHISHING: {
        "sama_id": "SAMA CSF 3.3.5",
        "nca_id": "NCA ECC 2-7-1",
        "name": "Anti-Phishing Controls",
        "sama_desc": (
            "Email phishing detection, URL analysis, and anti-spoofing controls "
            "to protect against credential harvesting attacks."
        ),
        "nca_desc": (
            "Technical and procedural controls to detect, block, and respond to "
            "phishing attempts via email channels."
        ),
    },
    ThreatClassification.GOV_IMPERSONATION: {
        "sama_id": "SAMA CSF 3.3.5",
        "nca_id": "NCA ECC 2-7-4",
        "name": "Government Entity Impersonation Detection",
        "sama_desc": (
            "Controls preventing fraudulent impersonation of SAMA, ZATCA, GOSI, "
            "MOF, and other Saudi/GCC government authorities via email."
        ),
        "nca_desc": (
            "Detection of emails impersonating government entities to manipulate "
            "recipients into disclosing information or transferring funds."
        ),
    },
    ThreatClassification.MALWARE: {
        "sama_id": "SAMA CSF 3.3.3",
        "nca_id": "NCA ECC 2-7-5",
        "name": "Email-Borne Malware Prevention",
        "sama_desc": (
            "Email security controls for detecting and blocking malicious "
            "attachments, macro-enabled documents, and exploit delivery via email."
        ),
        "nca_desc": (
            "Anti-malware email gateway controls to prevent delivery of malicious "
            "payloads, ransomware, and trojan attachments."
        ),
    },
    ThreatClassification.LOOKALIKE_DOMAIN: {
        "sama_id": "SAMA CSF 3.3.5",
        "nca_id": "NCA ECC 2-7-2",
        "name": "Domain Spoofing and Lookalike Detection",
        "sama_desc": (
            "Technical controls for detecting typosquatting, homoglyph attacks, "
            "and lookalike domains impersonating financial institutions."
        ),
        "nca_desc": (
            "Detection of domains resembling legitimate organizations through "
            "Levenshtein distance analysis and homoglyph substitution."
        ),
    },
    ThreatClassification.ACCOUNT_TAKEOVER: {
        "sama_id": "SAMA CSF 3.4.1",
        "nca_id": "NCA ECC 2-7-3",
        "name": "Account Takeover Prevention",
        "sama_desc": (
            "Controls for detecting compromised email accounts used to conduct "
            "internal BEC attacks or data exfiltration via legitimate credentials."
        ),
        "nca_desc": (
            "Behavioral anomaly detection to identify account compromise and "
            "unauthorized use of valid employee credentials for malicious purposes."
        ),
    },
    ThreatClassification.SUPPLY_CHAIN: {
        "sama_id": "SAMA CSF 3.3.3",
        "nca_id": "NCA ECC 2-7-5",
        "name": "Supply Chain Email Security",
        "sama_desc": (
            "Third-party and vendor email fraud controls to detect VEC "
            "(Vendor Email Compromise) and supply chain impersonation."
        ),
        "nca_desc": (
            "Controls for verifying third-party email authenticity and detecting "
            "fraudulent communications from compromised or spoofed vendor accounts."
        ),
    },
}


def _build_compliance_controls(
    classification: ThreatClassification,
) -> tuple[list[ComplianceControl], list[str], list[str]]:
    """
    Build compliance control objects and ID lists for a threat classification.

    Returns:
        Tuple of (controls list, sama_ids list, nca_ids list)
    """
    mapping = COMPLIANCE_CONTROLS.get(classification)
    if not mapping:
        return [], [], []

    sama_control = ComplianceControl(
        framework="SAMA",
        control_id=mapping["sama_id"],
        control_name=mapping["name"],
        description=mapping["sama_desc"],
    )
    nca_control = ComplianceControl(
        framework="NCA",
        control_id=mapping["nca_id"],
        control_name=mapping["name"],
        description=mapping["nca_desc"],
    )

    return (
        [sama_control, nca_control],
        [mapping["sama_id"]],
        [mapping["nca_id"]],
    )


def generate_action_record(
    orchestrator_result: dict[str, Any],
    email_metadata: EmailMetadata,
    org_id: str,
) -> dict[str, Any]:
    """
    Generate a complete ThreatActionRecord from orchestrator output.

    Includes:
    - All model scores and results
    - SAMA/NCA compliance control mappings
    - Audit metadata (timestamps, evidence IDs)
    - Redis publish-ready structure

    Args:
        orchestrator_result: Dict returned by RiskOrchestrator.orchestrate()
        email_metadata: Original email metadata
        org_id: Organization ID for multi-tenancy and Redis channel routing

    Returns:
        Fully structured dict ready for database insert and Redis publishing
    """
    classification = ThreatClassification(
        orchestrator_result.get("threat_classification", ThreatClassification.UNCERTAIN)
    )
    action = RiskAction(orchestrator_result.get("action", RiskAction.HOLD_FOR_REVIEW))

    controls, sama_ids, nca_ids = _build_compliance_controls(classification)

    # Extract scores
    agent_scores = orchestrator_result.get("agent_scores", {})
    graph_score = float(agent_scores.get("graph_score", 0.0))
    content_score = float(agent_scores.get("content_score", 0.0))
    reputation_score = float(agent_scores.get("reputation_score", 0.0))
    final_score = float(orchestrator_result.get("final_score", 0.0))
    confidence = float(orchestrator_result.get("confidence", 0.0))

    evidence_id = orchestrator_result.get("evidence_id", str(uuid.uuid4()))
    record_id = str(uuid.uuid4())
    now = datetime.utcnow()

    # Build full record
    record = ThreatActionRecord(
        record_id=record_id,
        evidence_id=evidence_id,
        org_id=org_id,
        message_id=email_metadata.message_id,
        sender=email_metadata.sender,
        recipient=email_metadata.recipient,
        timestamp=email_metadata.timestamp,
        direction=email_metadata.direction,
        final_score=final_score,
        graph_score=graph_score,
        content_score=content_score,
        reputation_score=reputation_score,
        action=action,
        threat_classification=classification,
        confidence=confidence,
        compliance_controls=controls,
        sama_controls=sama_ids,
        nca_controls=nca_ids,
        created_at=now,
        processed_by="himaya-v1",
        redis_published=False,
        redis_channel=f"threats:{org_id}",
    )

    record_dict = record.model_dump()

    # Add enriched metadata for DB storage
    record_dict["_meta"] = {
        "weighted_scores": orchestrator_result.get("weighted_scores", {}),
        "multipliers_applied": orchestrator_result.get("multipliers_applied", {}),
        "processing_time_ms": orchestrator_result.get("processing_time_ms", 0.0),
        "compliance_summary": {
            "sama_controls": sama_ids,
            "nca_controls": nca_ids,
            "framework_count": len(controls),
        },
        "agent_scores": agent_scores,
    }

    # Serialize datetime objects for JSON compatibility
    record_dict["timestamp"] = record_dict["timestamp"].isoformat()
    record_dict["created_at"] = record_dict["created_at"].isoformat()

    return record_dict


async def publish_to_redis(
    record: dict[str, Any],
    redis_client: Any,
) -> bool:
    """
    Publish a threat action record to the Redis pub/sub channel.

    Channel format: threats:{org_id}

    Args:
        record: Dict from generate_action_record()
        redis_client: Async Redis client (redis.asyncio)

    Returns:
        True if published successfully, False on error
    """
    org_id = record.get("org_id", "unknown")
    channel = f"threats:{org_id}"

    try:
        payload = json.dumps(record, default=str)
        await redis_client.publish(channel, payload)
        logger.info(
            f"Published threat record {record.get('record_id')} to {channel} "
            f"(score={record.get('final_score')}, action={record.get('action')})"
        )
        return True

    except Exception as e:
        logger.error(f"Failed to publish threat record to Redis channel {channel}: {e}")
        return False


def publish_to_redis_sync(
    record: dict[str, Any],
    redis_client: Any,
) -> bool:
    """
    Synchronous Redis publish (for non-async contexts).

    Args:
        record: Dict from generate_action_record()
        redis_client: Synchronous Redis client

    Returns:
        True if published successfully, False on error
    """
    org_id = record.get("org_id", "unknown")
    channel = f"threats:{org_id}"

    try:
        payload = json.dumps(record, default=str)
        redis_client.publish(channel, payload)
        logger.info(f"Published threat record to {channel}")
        return True
    except Exception as e:
        logger.error(f"Failed to publish to Redis: {e}")
        return False
