"""
Celery worker definitions for Himaya.
Broker: Redis
"""
import asyncio
import logging
from celery import Celery
from backend.config import settings

logger = logging.getLogger(__name__)

def _celery_redis_url(url: str) -> str:
    """Celery requires ssl_cert_reqs on rediss:// URLs (Azure Cache for Redis)."""
    if url.startswith("rediss://") and "ssl_cert_reqs" not in url:
        sep = "&" if "?" in url else "?"
        return f"{url}{sep}ssl_cert_reqs=CERT_REQUIRED"
    return url


celery_app = Celery(
    "sentinel_mail",
    broker=_celery_redis_url(settings.REDIS_URL),
    backend=_celery_redis_url(settings.REDIS_URL),
    include=["backend.workers.celery_app"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)


def run_async(coro):
    """Run async coroutine in celery (sync) context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(name="process_email_task", bind=True, max_retries=3)
def process_email_task(self, email_data: dict, org_id: str):
    """Process an email through the full threat detection pipeline."""
    from backend.database import AsyncSessionLocal
    from backend.services.email_processor import process_email

    async def _run():
        async with AsyncSessionLocal() as db:
            threat = await process_email(email_data, org_id, db)
            await db.commit()
            return str(threat.id) if threat else None

    try:
        threat_id = run_async(_run())
        logger.info(f"Email processed: threat_id={threat_id}")
        return {"status": "success", "threat_id": threat_id}
    except Exception as exc:
        logger.error(f"Email processing failed: {exc}")
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="calculate_risk_score_task")
def calculate_risk_score_task(org_id: str):
    """Recalculate org-level risk score from recent threats."""
    from backend.database import AsyncSessionLocal
    from backend.models.db_models import Threat, Organization
    from sqlalchemy import select, func
    from datetime import datetime, timedelta

    async def _run():
        async with AsyncSessionLocal() as db:
            since = datetime.utcnow() - timedelta(days=30)
            result = await db.execute(
                select(func.avg(Threat.risk_score).label("avg_risk"))
                .where(Threat.org_id == org_id)
                .where(Threat.detected_at >= since)
            )
            avg = result.scalar() or 0

            org_result = await db.execute(
                select(Organization).where(Organization.id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if org:
                org.risk_score = int(avg)
                await db.commit()
                logger.info(f"Updated risk score for org {org_id}: {int(avg)}")

    run_async(_run())
    return {"status": "done", "org_id": org_id}


@celery_app.task(name="sync_m365_users_task")
def sync_m365_users_task(org_id: str):
    """
    Placeholder: Sync users from Microsoft 365.
    In production, this will use Graph API to pull user list.
    """
    logger.info(f"[MOCK] M365 user sync for org {org_id} — skipped in dev mode")
    return {"status": "skipped", "reason": "mock_mode", "org_id": org_id}


@celery_app.task(name="rollup_monthly_usage")
def rollup_monthly_usage():
    """
    Aggregate usage_events into monthly_usage table.
    Run daily via Celery beat schedule.
    """
    from datetime import datetime

    async def _run():
        from backend.database import AsyncSessionLocal
        from sqlalchemy import text
        async with AsyncSessionLocal() as db:
            now = datetime.utcnow()
            year, month = now.year, now.month
            result = await db.execute(
                text("""
                    INSERT INTO monthly_usage (org_id, year, month, emails_scanned, threats_detected)
                    SELECT
                        org_id,
                        :yr,
                        :mo,
                        SUM(CASE WHEN event_type = 'email_scanned' THEN count ELSE 0 END),
                        SUM(CASE WHEN event_type = 'threat_detected' THEN count ELSE 0 END)
                    FROM usage_events
                    WHERE EXTRACT(YEAR FROM recorded_at) = :yr
                      AND EXTRACT(MONTH FROM recorded_at) = :mo
                    GROUP BY org_id
                    ON CONFLICT (org_id, year, month) DO UPDATE SET
                        emails_scanned = EXCLUDED.emails_scanned,
                        threats_detected = EXCLUDED.threats_detected,
                        computed_at = NOW()
                """),
                {"yr": year, "mo": month},
            )
            await db.commit()
            logger.info(f"Monthly usage rollup complete for {year}-{month:02d}")

    run_async(_run())
    return {"status": "done"}


# Celery beat schedule — run rollup daily at 2 AM UTC
celery_app.conf.beat_schedule = {
    "rollup-monthly-usage-daily": {
        "task": "rollup_monthly_usage",
        "schedule": 86400,  # every 24 hours
    },
}
