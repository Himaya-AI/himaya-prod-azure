from datetime import datetime
from typing import Optional, Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
import uuid

from backend.database import get_db
from backend.models.db_models import Threat, ComplianceEvidence
from backend.routers.auth import get_current_user
from backend.schemas.api_schemas import BulkActionRequest
from backend.services.feedback_trainer import record_analyst_feedback


class FeedbackRequest(BaseModel):
    label: Literal["confirmed_malicious", "false_positive", "confirmed_benign"]
    notes: Optional[str] = None

router = APIRouter(prefix="/api/threats", tags=["threats"])


def _risk_to_severity(score) -> str:
    if not score: return "low"
    if score >= 80: return "critical"
    if score >= 60: return "high"
    if score >= 35: return "medium"
    return "low"

def threat_to_dict(t: Threat) -> dict:
    sb = t.score_breakdown or {}
    return {
        "id": str(t.id),
        "org_id": str(t.org_id),
        "email_message_id": t.email_message_id,
        "sender": t.sender,
        "sender_domain": t.sender_domain,
        "recipient_email": t.recipient_email,
        "recipient_user_id": str(t.recipient_user_id) if t.recipient_user_id else None,
        "subject": getattr(t, "subject", None),
        "threat_type": t.threat_type,
        "risk_score": t.risk_score,
        "score_breakdown": sb,
        "graph_score": t.graph_score,
        "content_score": t.content_score,
        "reputation_score": t.reputation_score,
        "status": t.status,
        "action_taken": t.action_taken,
        "ai_explanation_en": t.ai_explanation_en,
        "ai_explanation_ar": t.ai_explanation_ar,
        "threat_indicators": t.threat_indicators,
        "sama_controls": t.sama_controls,
        "nca_controls": t.nca_controls,
        "false_positive": t.false_positive,
        "detected_at": t.detected_at.isoformat() if t.detected_at else None,
        "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        # Extracted artifacts — surfaced directly for the detail view
        "suspicious_urls": sb.get("suspicious_urls", []),
        "malicious_urls": sb.get("malicious_urls", []),
        "suspicious_attachments": sb.get("suspicious_attachments", []),
        # AI / LLM fields
        "llm_classification": getattr(t, "llm_classification", None),
        "llm_confidence": getattr(t, "llm_confidence", None),
        "llm_model": getattr(t, "llm_model", None),
        "llm_cost_usd": getattr(t, "llm_cost_usd", None),
        # Threat signal fields
        "urgency_score": getattr(t, "urgency_score", None),
        "impersonation_detected": getattr(t, "impersonation_detected", None),
        "impersonation_target": getattr(t, "impersonation_target", None),
        "auth_results": getattr(t, "auth_results", None),
        "analyst_verdict": getattr(t, "analyst_verdict", None),
        "analyst_notes": getattr(t, "analyst_notes", None),
        "reviewed_at": t.reviewed_at.isoformat() if getattr(t, "reviewed_at", None) else None,
        # email_body_preview: read via __dict__ to avoid ORM column error before migration
        "email_body_preview": t.__dict__.get("email_body_preview"),
        # Frontend-expected field aliases (ThreatTable / legacy compat)
        "type": (t.threat_type or "unknown").lower(),
        "severity": _risk_to_severity(t.risk_score),
        "recipient": t.recipient_email,
        "received_at": t.detected_at.isoformat() if t.detected_at else None,
        "overall_score": t.risk_score,
    }


@router.get("")
async def list_threats(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None, description="low|medium|high|critical"),
    threat_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    include_clean: bool = Query(False, description="Include clean/benign emails (default excluded)"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import or_
    # By default only return suspicious / flagged / quarantined emails — not clean ones
    # Include threats with NULL action_taken (older records) but exclude explicit "CLEAN"
    filters = [
        Threat.org_id == current_user.org_id,
    ]
    if not include_clean:
        filters.append(
            or_(Threat.action_taken.is_(None), Threat.action_taken != "CLEAN")
        )

    if severity:
        score_ranges = {
            "critical": (80, 100),
            "high": (60, 79),
            "medium": (40, 59),
            "low": (0, 39),
        }
        if severity in score_ranges:
            lo, hi = score_ranges[severity]
            filters.append(and_(Threat.risk_score >= lo, Threat.risk_score <= hi))

    if threat_type:
        # Support comma-separated multi-type filter from the frontend pill multi-select
        if ',' in threat_type:
            types = [t.strip().upper() for t in threat_type.split(',') if t.strip()]
            filters.append(Threat.threat_type.in_(types))
        else:
            filters.append(Threat.threat_type == threat_type)
    if status:
        filters.append(Threat.status == status)
    if date_from:
        filters.append(Threat.detected_at >= datetime.fromisoformat(date_from))
    if date_to:
        filters.append(Threat.detected_at <= datetime.fromisoformat(date_to))

    total_result = await db.execute(
        select(func.count()).select_from(Threat).where(and_(*filters))
    )
    total = total_result.scalar() or 0

    result = await db.execute(
        select(Threat)
        .where(and_(*filters))
        .order_by(Threat.detected_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    threats = result.scalars().all()

    return {
        "items": [threat_to_dict(t) for t in threats],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
    }


@router.get("/{threat_id}")
async def get_threat(
    threat_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    return threat_to_dict(threat)


@router.post("/{threat_id}/quarantine")
async def quarantine_threat(
    threat_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    threat.status = "quarantined"
    threat.action_taken = "QUARANTINE"
    threat.resolved_at = datetime.utcnow()
    await db.flush()

    # Actually move the email out of inbox via Gmail/M365 API
    moved = False
    if threat.email_message_id and threat.recipient_email:
        try:
            from backend.services.quarantine_service import quarantine_gmail_message
            from backend.models.db_models import OrgIntegration
            from backend.services.baseline_ingestion import _decrypt

            # Get org access token as fallback
            int_res = await db.execute(
                select(OrgIntegration).where(
                    OrgIntegration.org_id == current_user.org_id,
                    OrgIntegration.provider == "google",
                    OrgIntegration.status == "active",
                )
            )
            integ = int_res.scalar_one_or_none()
            fallback_token = None
            if integ and integ.access_token_enc:
                try:
                    fallback_token = _decrypt(integ.access_token_enc)
                except Exception:
                    pass

            moved = await quarantine_gmail_message(
                user_email=threat.recipient_email,
                gmail_message_id=threat.email_message_id,
                access_token=fallback_token,
            )
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Quarantine move failed (non-fatal): {e}")

    return {"message": "Threat quarantined", "threat_id": threat_id, "email_moved": moved}


@router.post("/{threat_id}/false-positive")
async def mark_false_positive(
    threat_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    threat.false_positive = True
    threat.status = "false_positive"
    threat.resolved_at = datetime.utcnow()
    await db.flush()
    return {"message": "Marked as false positive", "threat_id": threat_id}


@router.post("/bulk")
async def bulk_action(
    req: BulkActionRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    updated = 0
    for tid in req.threat_ids:
        result = await db.execute(
            select(Threat).where(
                Threat.id == uuid.UUID(tid),
                Threat.org_id == current_user.org_id,
            )
        )
        threat = result.scalar_one_or_none()
        if threat:
            if req.action == "quarantine":
                threat.status = "quarantined"
                threat.action_taken = "QUARANTINE"
            elif req.action == "false_positive":
                threat.false_positive = True
                threat.status = "false_positive"
            elif req.action == "resolve":
                threat.status = "resolved"
            threat.resolved_at = datetime.utcnow()
            updated += 1

    await db.flush()
    return {"message": f"Updated {updated} threats", "action": req.action}


@router.post("/{threat_id}/feedback")
async def submit_analyst_feedback(
    threat_id: str,
    req: FeedbackRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Analyst confirms/dismisses a threat. Feeds the active learning loop.
    label options:
      confirmed_malicious  → True Positive (model was correct, or FN being escalated)
      false_positive       → Model was wrong, email was benign
      confirmed_benign     → Email was clean (low-risk confirm)
    """
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    threat_snapshot = {
        "threat_type": threat.threat_type,
        "risk_score": threat.risk_score,
        "score_breakdown": threat.score_breakdown,
        "sender_domain": threat.sender_domain,
        "subject_hash": threat.subject_hash,
        "content_score": threat.content_score,
        "graph_score": threat.graph_score,
        "reputation_score": threat.reputation_score,
        "threat_indicators": threat.threat_indicators,
        "ai_explanation_en": threat.ai_explanation_en,
    }

    feedback_result = await record_analyst_feedback(
        threat_id=threat_id,
        org_id=str(current_user.org_id),
        analyst_email=current_user.email,
        label=req.label,
        notes=req.notes,
        threat_snapshot=threat_snapshot,
        db=db,
    )

    return {
        "threat_id": threat_id,
        "feedback_id": feedback_result["feedback_id"],
        "label": req.label,
        "retrain_triggered": feedback_result["retrain_triggered"],
        "message": feedback_result["message"],
    }


@router.get("/feedback/stats")
async def feedback_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return analyst feedback stats for this org — precision/recall estimates."""
    from sqlalchemy import text
    try:
        result = await db.execute(
            text("SELECT feedback_tp, feedback_fp, feedback_tn FROM org_metrics WHERE org_id = :org_id"),
            {"org_id": str(current_user.org_id)},
        )
        row = result.fetchone()
        if row:
            tp, fp, tn = row.feedback_tp or 0, row.feedback_fp or 0, row.feedback_tn or 0
            total = tp + fp + tn
            precision = round(tp / (tp + fp), 3) if (tp + fp) > 0 else None
            recall_estimate = None  # Need FN data for true recall
            return {
                "true_positives": tp,
                "false_positives": fp,
                "confirmed_benign": tn,
                "total_reviewed": total,
                "precision": precision,
                "recall_estimate": recall_estimate,
                "note": "Based on analyst-reviewed samples only",
            }
    except Exception:
        pass
    return {"total_reviewed": 0, "precision": None, "note": "No feedback data yet"}


class StatusUpdateRequest(BaseModel):
    status: Literal["new", "investigating", "resolved", "closed"]


@router.patch("/{threat_id}/status")
async def update_threat_status(
    threat_id: str,
    req: StatusUpdateRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update threat investigation status."""
    result = await db.execute(
        select(Threat).where(
            Threat.id == uuid.UUID(threat_id),
            Threat.org_id == current_user.org_id,
        )
    )
    threat = result.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")
    threat.status = req.status
    await db.flush()
    return {"id": threat_id, "status": req.status}


@router.get("/stats/investigating")
async def get_investigating_count(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Count of threats currently in investigating status — feeds dashboard Active tile."""
    count = (await db.execute(
        select(func.count(Threat.id)).where(
            Threat.org_id == current_user.org_id,
            Threat.status.in_(["new", "investigating"]),
            Threat.threat_type != "CLEAN",
        )
    )).scalar() or 0
    return {"investigating": count}


@router.post("/auto-triage")
async def auto_triage(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(default=5, ge=1, le=50),
):
    """
    One-shot auto-triage: runs full investigation pipeline on up to `limit` pending threats (default 5, max 50).
    Delegates to the auto_triage_service investigation pipeline (VT + feeds + Helios Analysis verdict).
    """
    import asyncio as _asyncio
    import logging as _logging
    _log = _logging.getLogger(__name__)

    org_id = str(current_user.org_id)
    try:
        from backend.services.auto_triage_service import _find_pending_threats, investigate_threat
        pending_ids = await _find_pending_threats(org_id, limit=limit)
    except Exception as _e:
        _log.warning(f"auto_triage: could not find pending threats: {_e}")
        pending_ids = []

    results = []
    for tid in pending_ids:
        try:
            inv = await investigate_threat(str(tid), org_id)
            results.append({"threat_id": str(tid), "verdict": inv.get("verdict"), "applied": inv.get("applied")})
        except Exception as _e:
            _log.warning(f"auto_triage: investigation failed for {tid}: {_e}")
            results.append({"threat_id": str(tid), "error": str(_e)})

    verdicts = [r.get("verdict") for r in results if r.get("verdict")]
    quarantined = sum(1 for v in verdicts if v == "QUARANTINE")
    escalated = sum(1 for v in verdicts if v == "ESCALATE")
    dismissed = sum(1 for v in verdicts if v == "DISMISS")
    return {
        "total_processed": len(results),
        "quarantined": quarantined,
        "escalated": escalated,
        "dismissed": dismissed,
        "results": results,
        "message": f"Auto-triage complete: {quarantined} quarantined, {escalated} escalated, {dismissed} dismissed",
    }


@router.post("/auto-triage/toggle")
async def toggle_auto_triage(
    body: dict,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Toggle the autonomous auto-triage agent on/off for the current org.
    POST body: {"enabled": true|false}
    When enabled, starts a background loop that investigates threats every 2 minutes.
    Enabled state is persisted in Postgres (org_metadata) so it survives Redis flushes
    and ECS restarts indefinitely — not just for 24h.
    """
    import asyncio as _asyncio
    import redis as _redis_sync
    import logging as _log
    from backend.config import settings as _cfg
    from backend.models.db_models import Organization as _Org
    from sqlalchemy import select as _sel

    enabled = bool(body.get("enabled", False))
    org_id = str(current_user.org_id)
    _logger = _log.getLogger(__name__)

    # ── 1. Persist to Postgres (survives Redis flush + indefinite restarts) ──
    try:
        _org = await db.execute(_sel(_Org).where(_Org.id == current_user.org_id))
        _org_row = _org.scalar_one_or_none()
        if _org_row:
            meta = dict(_org_row.org_metadata or {})
            meta["auto_triage_enabled"] = enabled
            _org_row.org_metadata = meta
            await db.commit()
    except Exception as _dbe:
        _logger.warning(f"auto_triage toggle: DB persist failed (non-fatal): {_dbe}")

    # ── 2. Sync Redis (loop reads this every cycle) ──────────────────────────
    r = _redis_sync.from_url(_cfg.REDIS_URL, decode_responses=True)
    try:
        if enabled:
            # No TTL — Redis key persists until explicitly disabled
            r.set(f"auto_triage:enabled:{org_id}", "1")
            # Start the per-org loop as a background asyncio task (with auto-restart wrapper)
            try:
                import builtins
                if hasattr(builtins, '_helios_spawn_triage_loop'):
                    # Use watchdog-wrapped spawn function from main.py
                    _asyncio.create_task(builtins._helios_spawn_triage_loop(org_id))
                    _logger.info(f"auto_triage: loop task created (with watchdog) for org={org_id}")
                else:
                    # Fallback to direct spawn (no auto-restart on crash)
                    from backend.services.auto_triage_service import run_auto_triage_loop
                    _asyncio.create_task(run_auto_triage_loop(org_id))
                    _logger.info(f"auto_triage: loop task created (no watchdog) for org={org_id}")
            except Exception as _te:
                _logger.warning(f"auto_triage: failed to create loop task: {_te}")
        else:
            r.delete(f"auto_triage:enabled:{org_id}")
            r.delete(f"auto_triage:status:{org_id}")
    finally:
        r.close()

    return {"enabled": enabled, "org_id": org_id}


@router.get("/auto-triage/status")
async def auto_triage_status(
    current_user=Depends(get_current_user),
):
    """
    Get current auto-triage agent state for this org.
    Returns: enabled, last_run timestamp, last_processed count.
    """
    import redis as _redis_sync
    import json as _json
    from backend.config import settings as _cfg

    org_id = str(current_user.org_id)
    r = _redis_sync.from_url(_cfg.REDIS_URL, decode_responses=True)
    try:
        enabled_raw = r.get(f"auto_triage:enabled:{org_id}")
        status_raw = r.get(f"auto_triage:status:{org_id}")
    finally:
        r.close()

    enabled = bool(enabled_raw)
    status = {}
    if status_raw:
        try:
            status = _json.loads(status_raw)
        except Exception:
            pass

    return {
        "enabled": enabled,
        "org_id": org_id,
        "last_run": status.get("last_run"),
        "last_processed": status.get("last_processed", 0),
        "running": status.get("running", False),
    }


@router.get("/auto-triage/audit")
async def auto_triage_audit(
    limit: int = 50,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the auto-triage audit trail — the last N threats that were investigated
    by the auto-triage agent, with their verdict, confidence, reasoning, and evidence.
    """
    from sqlalchemy import select, text as _sql
    from backend.models.db_models import Threat

    # Find threats where auto_triage verdict was applied (stored in threat_indicators JSONB)
    result = await db.execute(
        select(
            Threat.id,
            Threat.sender,
            Threat.sender_domain,
            Threat.recipient_email,
            Threat.subject,
            Threat.threat_type,
            Threat.risk_score,
            Threat.action_taken,
            Threat.detected_at,
            Threat.threat_indicators,
        )
        .where(
            Threat.org_id == current_user.org_id,
            Threat.threat_indicators["auto_triaged"].as_boolean() == True,
        )
        .order_by(Threat.detected_at.desc())
        .limit(limit)
    )
    rows = result.all()

    audit = []
    for r in rows:
        ti = r.threat_indicators or {}
        audit.append({
            "threat_id": str(r.id),
            "sender": r.sender,
            "sender_domain": r.sender_domain,
            "recipient": r.recipient_email,
            "subject": r.subject,
            "threat_type": r.threat_type,
            "original_risk_score": r.risk_score,
            "action_taken": r.action_taken,
            "detected_at": r.detected_at.isoformat() if r.detected_at else None,
            # Auto-triage specific fields
            "verdict": ti.get("auto_triage_verdict"),
            "confidence": ti.get("auto_triage_confidence"),
            "reasoning": ti.get("auto_triage_reasoning"),
            "key_evidence": ti.get("auto_triage_evidence", []),
            "triaged_at": ti.get("auto_triage_at"),
            "vt_domain_malicious": ti.get("vt_domain_malicious", 0),
            "vt_url_malicious": ti.get("vt_url_malicious", 0),
            "feed_matches": ti.get("feed_matches", []),
            "graph_prior_emails": ti.get("graph_prior_emails", 0),
            "attachment_risk": ti.get("attachment_risk"),
            # Sandbox audit trail — permanently stored in DB (not Redis)
            "sandbox_verdict": ti.get("ec2_sandbox_verdict"),
            "sandbox_url_results": ti.get("ec2_sandbox_url_results", []),
            "sandbox_attachment_results": ti.get("ec2_sandbox_attachment_results", []),
            "sandbox_ran_at": ti.get("ec2_sandbox_ran_at"),
        })

    return {"items": audit, "total": len(audit)}


# ── System Health Endpoint ────────────────────────────────────────────────

@router.get("/system-health")
async def threat_system_health(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return threat detection system health metrics."""
    import redis as _redis_sync
    import httpx as _httpx
    from backend.config import settings as _cfg
    from sqlalchemy import text as _text

    org_id = str(current_user.org_id)

    # 1. Auto-triage status
    auto_triage_enabled = False
    try:
        r = _redis_sync.from_url(_cfg.REDIS_URL, decode_responses=True)
        auto_triage_enabled = bool(r.get(f"auto_triage:enabled:{org_id}"))
        r.close()
    except Exception:
        pass

    # 2. Recent threat count (last 24h)
    recent_threats = 0
    try:
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(hours=24)
        ct = (await db.execute(
            select(func.count(Threat.id)).where(
                Threat.org_id == current_user.org_id,
                Threat.detected_at >= cutoff,
            )
        )).scalar() or 0
        recent_threats = ct
    except Exception:
        pass

    # 3. DeepSeek reachability
    deepseek_ok = False
    try:
        import os
        _ds_url = os.getenv("DEEPSEEK_ENDPOINT", "http://10.0.1.113:8001")
        async with _httpx.AsyncClient(timeout=3) as _c:
            _r = await _c.get(f"{_ds_url}/health")
            deepseek_ok = _r.status_code == 200
    except Exception:
        pass

    # 4. DLP operational (any events in last 7 days)
    dlp_active = False
    try:
        from datetime import timedelta
        cutoff7 = datetime.utcnow() - timedelta(days=7)
        dlp_ct = (await db.execute(
            _text("SELECT COUNT(*) FROM dlp_events WHERE org_id=:oid AND created_at >= :cutoff"),
            {"oid": org_id, "cutoff": cutoff7}
        )).scalar() or 0
        dlp_active = dlp_ct > 0
    except Exception:
        pass

    return {
        "auto_triage_enabled": auto_triage_enabled,
        "recent_threats_24h": recent_threats,
        "deepseek_reachable": deepseek_ok,
        "dlp_active": dlp_active,
        "status": "operational",
    }
