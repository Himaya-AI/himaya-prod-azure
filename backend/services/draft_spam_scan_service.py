"""Background auto-scan loops for Draft Analysis and Spam Center."""
import asyncio
import logging

logger = logging.getLogger(__name__)

SCAN_INTERVAL_SECONDS = 90

# Serialize draft + spam writes to the same DB rows to prevent deadlocks
_db_write_lock = asyncio.Lock()


async def _get_active_org_ids() -> list[str]:
    """Fetch all active org IDs using a fresh session."""
    from sqlalchemy import select
    from backend.database import AsyncSessionLocal
    from backend.models.db_models import Organization
    async with AsyncSessionLocal() as db:
        orgs = (await db.execute(
            select(Organization.id).where(Organization.status == "active")
        )).scalars().all()
        return [str(oid) for oid in orgs]


async def _scan_all_orgs_drafts():
    """Scan drafts for each active org using a fresh DB session per org."""
    from backend.database import AsyncSessionLocal
    from backend.routers.drafts import _scan_org_drafts

    try:
        org_ids = await _get_active_org_ids()
    except Exception as e:
        logger.warning(f"Draft auto-scan: failed to fetch orgs: {e}")
        return

    for org_id in org_ids:
        # Serialize with spam loop to prevent deadlocks on shared tables
        async with _db_write_lock:
            async with AsyncSessionLocal() as db:
                try:
                    result = await _scan_org_drafts(org_id, db)
                    await db.commit()
                    logger.info(f"Draft auto-scan org={org_id}: {result}")
                except Exception as e:
                    logger.warning(f"Draft auto-scan failed org={org_id}: {e}")
                    try:
                        await db.rollback()
                    except Exception:
                        pass


async def _scan_all_orgs_spam():
    """Sync spam for each active org using a fresh DB session per org."""
    from backend.database import AsyncSessionLocal
    from backend.routers.spam import _sync_org_spam

    try:
        org_ids = await _get_active_org_ids()
    except Exception as e:
        logger.warning(f"Spam auto-sync: failed to fetch orgs: {e}")
        return

    for org_id in org_ids:
        # Serialize with draft loop to prevent deadlocks on shared tables
        async with _db_write_lock:
            async with AsyncSessionLocal() as db:
                try:
                    result = await _sync_org_spam(org_id, db)
                    await db.commit()
                    logger.info(f"Spam auto-sync org={org_id}: {result}")
                except Exception as e:
                    logger.warning(f"Spam auto-sync failed org={org_id}: {e}")
                    try:
                        await db.rollback()
                    except Exception:
                        pass


async def run_draft_scan_loop():
    logger.info("Draft auto-scan loop starting...")
    await asyncio.sleep(30)  # let DB/connections stabilize at startup
    while True:
        try:
            await _scan_all_orgs_drafts()
        except Exception as e:
            logger.error(f"Draft scan loop crash: {e}")
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)


async def run_spam_sync_loop():
    logger.info("Spam auto-sync loop starting...")
    await asyncio.sleep(75)  # offset further from draft loop (was 45)
    while True:
        try:
            await _scan_all_orgs_spam()
        except Exception as e:
            logger.error(f"Spam sync loop crash: {e}")
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)
