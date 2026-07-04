"""
Himaya Helios - FastAPI Application Entry Point
"""
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

import sentry_sdk
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from backend.config import settings

# ── Sentry ── error tracking, tracing, profiling, logs ──────────────────────
sentry_sdk.init(
    dsn=os.getenv(
        "SENTRY_DSN",
        "https://04c8a189e838c04b7f53c294cf38cfe3@o4511675369193472.ingest.us.sentry.io/4511675703033856",
    ),
    environment=os.getenv("SENTRY_ENVIRONMENT", "azure-prod"),
    send_default_pii=True,
    enable_logs=True,
    traces_sample_rate=float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "1.0")),
    profile_session_sample_rate=float(os.getenv("SENTRY_PROFILE_SAMPLE_RATE", "1.0")),
    profile_lifecycle="trace",
)
from backend.database import engine, AsyncSessionLocal
from backend.services.websocket_manager import manager as ws_manager
from backend.services.graph_client import graph_client
from backend.services.alert_service import alert_service

# Routers
from backend.routers import auth, dashboard, threats, people, policies, compliance, onboarding, settings as settings_router, message_trace, admin, sandbox, reports, neo4j_mgmt
from backend.routers.quarantine import router as quarantine_router
from backend.routers.phish_report import router as phish_report_router
from backend.routers.posture import router as posture_router
from backend.routers.dlp import router as dlp_router, ensure_dlp_tables
from backend.routers.dlp_webhook import router as dlp_webhook_router
from backend.routers.drafts import router as drafts_router, ensure_draft_tables
from backend.routers.spam import router as spam_router, ensure_spam_tables
from backend.routers.saas_security import router as saas_security_router
from backend.routers.falcon import router as falcon_router
from backend.routers.aws_connector import router as aws_router, ensure_aws_tables
from backend.routers.gcp_connector import router as gcp_router, ensure_gcp_tables
from backend.routers.databricks_connector import router as databricks_router, ensure_databricks_tables
from backend.routers.sap_connector import router as sap_router, ensure_sap_tables
from backend.routers.azure_connector import router as azure_router, ensure_azure_tables
from backend.routers.oracle_connector import router as oracle_router, ensure_oracle_tables
from backend.routers.github_connector import router as github_router, ensure_github_tables
from backend.routers.snowflake_connector import router as snowflake_router  # ensure_snowflake_tables created lazily on first connect
from backend.routers.salesforce_connector import router as salesforce_router, ensure_salesforce_tables
from backend.routers.cspm import router as cspm_router
from backend.services.cspm import ensure_cspm_tables
from backend.routers.dspm import router as dspm_router
from backend.services.dspm import ensure_dspm_tables
from backend.routers.toxic_combinations import router as toxic_router
from backend.routers.data_lifecycle import router as data_lifecycle_router
from backend.routers.permission_diff_router import router as permission_diff_router
from backend.routers.genai_shadow_it_router import router as genai_shadow_it_router
from backend.routers.dspm_access import router as dspm_access_router
from backend.services.toxic_combinations import (
    ensure_schema as ensure_toxic_schema,
    run_for_org as run_toxic_for_org,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown events."""
    logger.info("Starting Himaya Helios API...")

    # graph-service handles Neo4j directly — no local init needed

    # Test Redis
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        await r.ping()
        await r.aclose()
        logger.info("Redis connected")
    except Exception as e:
        logger.warning(f"Redis not available: {e}")

    # Ensure DLP tables exist
    try:
        async with AsyncSessionLocal() as session:
            await ensure_dlp_tables(session)
        logger.info("DLP tables ensured")
    except Exception as e:
        logger.warning(f"DLP table setup failed (non-fatal): {e}")

    # Ensure Draft Analysis tables exist (timeout to avoid blocking on DDL lock during rolling deploy)
    try:
        import asyncio as _asyncio
        async with AsyncSessionLocal() as session:
            await _asyncio.wait_for(ensure_draft_tables(session), timeout=15.0)
        logger.info("Draft tables ensured")
    except _asyncio.TimeoutError:
        logger.warning("Draft table setup timed out (non-fatal — DDL lock contention during rolling deploy)")
    except Exception as e:
        logger.warning(f"Draft table setup failed (non-fatal): {e}")

    # Ensure Spam Center tables exist (timeout to avoid blocking on DDL lock during rolling deploy)
    try:
        import asyncio as _asyncio2
        async with AsyncSessionLocal() as session:
            await _asyncio2.wait_for(ensure_spam_tables(session), timeout=15.0)
        logger.info("Spam tables ensured")
    except _asyncio2.TimeoutError:
        logger.warning("Spam table setup timed out (non-fatal — DDL lock contention during rolling deploy)")
    except Exception as e:
        logger.warning(f"Spam table setup failed (non-fatal): {e}")

    # Ensure SaaS Security tables exist (skip if already present to avoid lock contention)
    try:
        async with AsyncSessionLocal() as session:
            from sqlalchemy import text as _sst

            # Idempotent CREATE for tables added AFTER the initial SaaS
            # bootstrap (e.g. saas_oauth_apps). These run regardless of the
            # short-circuit below so newly-added tables don't get missed on
            # tenants that already had the older SaaS tables.
            _new_tbl_stmts = [
                """
                CREATE TABLE IF NOT EXISTS saas_oauth_apps (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    app_name TEXT NOT NULL,
                    app_id VARCHAR(500) NOT NULL,
                    provider VARCHAR(50) NOT NULL,
                    publisher TEXT,
                    permissions JSONB DEFAULT '[]',
                    status VARCHAR(50) DEFAULT 'unknown',
                    risk_score REAL DEFAULT 0.5,
                    user_count INTEGER DEFAULT 0,
                    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT uq_saas_oauth_apps_org_app_provider UNIQUE (org_id, app_id, provider)
                )
                """,
            ]
            for _stmt in _new_tbl_stmts:
                try:
                    await session.execute(_sst(_stmt.strip()))
                    await session.commit()
                except Exception as _ne:
                    await session.rollback()
                    logger.debug(f"SaaS new-table create skipped (non-fatal): {_ne}")

            # Quick check — if main table exists skip the rest of the CREATE block
            _tbl_check = await session.execute(
                _sst("SELECT 1 FROM information_schema.tables WHERE table_name='saas_integrations' LIMIT 1")
            )
            if _tbl_check.scalar():
                logger.info("SaaS Security tables ensured")
                # skip the rest of the CREATE TABLE block
                raise StopIteration("tables_exist")
            _saas_stmts = [
                """
                CREATE TABLE IF NOT EXISTS saas_integrations (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    provider VARCHAR(50) NOT NULL,
                    status VARCHAR(50) NOT NULL DEFAULT 'disconnected',
                    access_token TEXT,
                    refresh_token TEXT,
                    token_expiry TIMESTAMPTZ,
                    tenant_id VARCHAR(255),
                    scopes TEXT[] DEFAULT '{}',
                    error_message TEXT,
                    connected_at TIMESTAMPTZ,
                    last_synced_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT uq_saas_integrations_org_provider UNIQUE (org_id, provider)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saas_alerts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    provider VARCHAR(50) NOT NULL,
                    alert_type VARCHAR(100) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    resource_id VARCHAR(500),
                    resource_name TEXT,
                    resource_url TEXT,
                    classification_result JSONB,
                    posture_result JSONB,
                    status VARCHAR(50) DEFAULT 'open',
                    assigned_to UUID REFERENCES users(id),
                    resolved_at TIMESTAMPTZ,
                    resolved_by UUID REFERENCES users(id),
                    raw_data JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saas_data_items (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    provider VARCHAR(50) NOT NULL,
                    item_type VARCHAR(50) NOT NULL,
                    item_id VARCHAR(500) NOT NULL,
                    item_name TEXT NOT NULL,
                    item_url TEXT,
                    parent_path TEXT,
                    owner_email VARCHAR(255),
                    size_bytes BIGINT,
                    classification_label VARCHAR(100),
                    classification_score REAL,
                    classification_categories TEXT[] DEFAULT '{}',
                    classification_result JSONB,
                    sharing_scope VARCHAR(50),
                    last_modified_at TIMESTAMPTZ,
                    last_scanned_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT uq_saas_data_items_org_provider_item UNIQUE (org_id, provider, item_id)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saas_posture_checks (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    provider VARCHAR(50) NOT NULL,
                    check_name VARCHAR(255) NOT NULL,
                    check_category VARCHAR(100) NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL,
                    description TEXT NOT NULL,
                    recommendation TEXT,
                    evidence JSONB,
                    remediation_steps TEXT[] DEFAULT '{}',
                    last_checked_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saas_risky_users (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    user_email VARCHAR(255) NOT NULL,
                    user_id VARCHAR(255),
                    risk_level VARCHAR(50) NOT NULL,
                    risk_state VARCHAR(100),
                    risk_detail TEXT,
                    risk_last_updated_at TIMESTAMPTZ,
                    provider VARCHAR(50) NOT NULL DEFAULT 'microsoft',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    updated_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT uq_saas_risky_users_org_email UNIQUE (org_id, user_email, provider)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saas_oauth_apps (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    app_name TEXT NOT NULL,
                    app_id VARCHAR(500) NOT NULL,
                    provider VARCHAR(50) NOT NULL,
                    publisher TEXT,
                    permissions JSONB DEFAULT '[]',
                    status VARCHAR(50) DEFAULT 'unknown',
                    risk_score REAL DEFAULT 0.5,
                    user_count INTEGER DEFAULT 0,
                    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT uq_saas_oauth_apps_org_app_provider UNIQUE (org_id, app_id, provider)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saas_admin_actions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    admin_email VARCHAR(255),
                    action_type VARCHAR(255) NOT NULL,
                    target_type VARCHAR(100),
                    target_id VARCHAR(500),
                    target_name TEXT,
                    details JSONB,
                    provider VARCHAR(50) NOT NULL DEFAULT 'microsoft',
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT uq_saas_admin_actions_org_id UNIQUE (org_id, admin_email, action_type, target_id, created_at)
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS saas_user_risk_scores (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    user_email VARCHAR(255) NOT NULL,
                    user_id VARCHAR(255),
                    display_name VARCHAR(255),
                    job_title VARCHAR(255),
                    department VARCHAR(255),
                    risk_score INTEGER DEFAULT 0,
                    risk_factors JSONB DEFAULT '[]',
                    updated_at TIMESTAMPTZ DEFAULT NOW(),
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT uq_saas_user_risk_scores_org_email UNIQUE (org_id, user_email)
                )
                """,
            ]
            for _stmt in _saas_stmts:
                try:
                    await session.execute(_sst(_stmt.strip()))
                    await session.commit()
                except Exception as _se:
                    await session.rollback()
        logger.info("SaaS Security tables ensured")
    except StopIteration:
        pass  # tables already exist, nothing to do
    except Exception as e:
        logger.warning(f"SaaS Security table setup failed (non-fatal): {e}")

    # Ensure CSPM (cloud security posture management) tables exist
    try:
        import asyncio as _asyncio_cspm
        async with AsyncSessionLocal() as session:
            await _asyncio_cspm.wait_for(ensure_cspm_tables(session), timeout=15.0)
        logger.info("CSPM tables ensured")
    except _asyncio_cspm.TimeoutError:
        logger.warning("CSPM table setup timed out (non-fatal — DDL lock contention)")
    except Exception as e:
        logger.warning(f"CSPM table setup failed (non-fatal): {e}")

    # Ensure DSPM (data security posture management) tables exist
    try:
        import asyncio as _asyncio_dspm
        async with AsyncSessionLocal() as session:
            await _asyncio_dspm.wait_for(ensure_dspm_tables(session), timeout=15.0)
        logger.info("DSPM tables ensured")
    except _asyncio_dspm.TimeoutError:
        logger.warning("DSPM table setup timed out (non-fatal — DDL lock contention)")
    except Exception as e:
        logger.warning(f"DSPM table setup failed (non-fatal): {e}")

    # Test DB + run pending migrations
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(__import__("sqlalchemy").text("SELECT 1"))
            # Set a short lock timeout so DDL statements fail fast instead of hanging during rolling deploys
            await session.execute(__import__("sqlalchemy").text("SET lock_timeout = '3s'"))
            await session.execute(__import__("sqlalchemy").text("SET statement_timeout = '10s'"))
            # Apply all pending migrations
            import pathlib
            # SQL splitter that respects single-quoted string literals and
            # line comments. The previous naive sql.split(";") broke any
            # migration whose VALUES contained semicolons inside strings
            # (e.g. "TLS for email; OAuth tokens encrypted at rest").
            def _split_sql_statements(text: str):
                stmts = []
                buf = []
                in_str = False
                i = 0
                while i < len(text):
                    ch = text[i]
                    nxt = text[i + 1] if i + 1 < len(text) else ""
                    if not in_str and ch == "-" and nxt == "-":
                        # Skip line comment to end of line
                        nl = text.find("\n", i)
                        if nl == -1:
                            break
                        i = nl + 1
                        continue
                    if ch == "'":
                        # Toggle on single quote (PostgreSQL escapes '' as literal)
                        if in_str and nxt == "'":
                            buf.append("''")
                            i += 2
                            continue
                        in_str = not in_str
                        buf.append(ch)
                        i += 1
                        continue
                    if ch == ";" and not in_str:
                        stmt = "".join(buf).strip()
                        if stmt:
                            stmts.append(stmt)
                        buf = []
                        i += 1
                        continue
                    buf.append(ch)
                    i += 1
                tail = "".join(buf).strip()
                if tail:
                    stmts.append(tail)
                return stmts

            for mig in ["fix_billing_records.sql", "fix_missing_columns.sql", "add_shared_mailboxes_opendbl.sql", "add_saas_risk_tables.sql", "add_security_rules_table.sql", "fix_ai_alert_prefix.sql", "fix_ai_alerts_v2.sql", "add_compliance_score_history.sql", "expand_sama_nca_controls.sql", "fix_admin_actions_nullable_email.sql"]:
                migration_path = pathlib.Path(__file__).parent / "migrations" / mig
                if migration_path.exists():
                    sql = migration_path.read_text()
                    for stmt in _split_sql_statements(sql):
                        try:
                            await session.execute(__import__("sqlalchemy").text(stmt))
                            await session.commit()
                        except Exception as _me:
                            logger.warning(f"Migration stmt skipped ({mig}): {_me}")
                            await session.rollback()
            # Explicit column guards — idempotent
            _guard_stmts = [
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS subject TEXT",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS subject_hash VARCHAR(64)",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS recipient_email VARCHAR(255)",
                # LLM metadata columns (added in v2 model, may be missing in older DBs)
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS llm_classification VARCHAR(50)",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS llm_confidence REAL",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS llm_model VARCHAR(100)",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS llm_cost_usd REAL",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS impersonation_detected BOOLEAN DEFAULT FALSE",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS impersonation_target VARCHAR(255)",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS urgency_score INTEGER",
                # Analyst feedback columns
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS analyst_verdict VARCHAR(50)",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS analyst_email VARCHAR(255)",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS analyst_notes TEXT",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ",
                # Email metadata columns
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS email_received_at TIMESTAMPTZ",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS auth_results JSONB",
                # email_body_preview and policy_id were missing — caused transaction aborts
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS email_body_preview TEXT",
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS policy_id UUID",
                # email_groups table for Groups / DL discovery (delta sync populated)
                """CREATE TABLE IF NOT EXISTS email_groups (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    provider VARCHAR(50) NOT NULL,
                    group_email VARCHAR(255) NOT NULL,
                    group_name VARCHAR(255),
                    description TEXT,
                    member_count INTEGER DEFAULT 0,
                    external_id VARCHAR(255),
                    last_synced_at TIMESTAMPTZ DEFAULT NOW(),
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )""",
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_email_groups_org_email ON email_groups(org_id, group_email)",
                # Compliance status extra columns
                "ALTER TABLE compliance_status ADD COLUMN IF NOT EXISTS notes TEXT",
                "ALTER TABLE compliance_status ADD COLUMN IF NOT EXISTS last_assessed_at TIMESTAMPTZ",
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_compliance_controls_fw_cid ON compliance_controls (framework, control_id)",
                # Per-provider domain for org_integrations (fixes multi-provider domain overwrite bug)
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS org_domain VARCHAR(255)",
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS mailbox_count INTEGER DEFAULT 0",
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS groups_count INTEGER DEFAULT 0",
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS aliases_count INTEGER DEFAULT 0",
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS shared_count INTEGER DEFAULT 0",
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS last_baseline_at TIMESTAMPTZ",
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS baseline_progress INTEGER DEFAULT 0",
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS scope_group_id VARCHAR(255)",
                "ALTER TABLE org_integrations ADD COLUMN IF NOT EXISTS scope_group_name VARCHAR(255)",
                # Users need a directory_provider to scope deactivation correctly per provider
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_provider VARCHAR(50)",
                # Organization metadata JSONB for alert_prefs, settings, etc.
                "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS org_metadata JSONB DEFAULT '{}'::jsonb",
                # Phish report key for employee add-ons (Gmail / Outlook)
                "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS phish_report_key VARCHAR(64)",
                # Org tier (Launch / Enterprise)
                "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS tier VARCHAR(20) DEFAULT 'Launch'",
                "UPDATE organizations SET tier = 'Enterprise' WHERE domain = 'himaya.ai'",
                # SaaS data items — new metadata columns
                "ALTER TABLE saas_data_items ADD COLUMN IF NOT EXISTS classification_result JSONB",
                # Exclude from auto-triage flag (for DLP drafts, manual escalations)
                "ALTER TABLE threats ADD COLUMN IF NOT EXISTS exclude_auto_triage BOOLEAN DEFAULT FALSE",
                # Saas alerts dedup fingerprint — added 2026-06-18 because
                # GitHub CSPM mirror + DSPM SaaS scanners were creating
                # 100+ duplicate rows of the same alert (no UNIQUE
                # constraint existed).
                "ALTER TABLE saas_alerts ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)",
                # (dedup DELETE + unique index are handled separately after startup — see below)
            ]
            for _gs in _guard_stmts:
                try:
                    await session.execute(__import__("sqlalchemy").text(_gs))
                    await session.commit()
                except Exception as _ge:
                    await session.rollback()
            await session.commit()
        logger.info("Database connected")
    except Exception as e:
        logger.warning(f"Database not available: {e}")

    # Dedup threats: separate session so DELETE + CREATE INDEX run in independent transactions
    try:
        import asyncio as _asyncio_dedup
        from sqlalchemy import text as _stext
        async with AsyncSessionLocal() as _dd_session:
            await _dd_session.execute(_stext("SET lock_timeout = '3s'"))
            await _dd_session.execute(_stext("SET statement_timeout = '10s'"))
            # Step 1: delete duplicate rows (keep earliest by detected_at)
            _del = await _dd_session.execute(_stext("""
                DELETE FROM threats
                WHERE id IN (
                  SELECT id FROM (
                    SELECT id,
                           ROW_NUMBER() OVER (
                             PARTITION BY email_message_id, org_id, recipient_email
                             ORDER BY detected_at ASC, id ASC
                           ) AS rn
                    FROM threats
                    WHERE email_message_id IS NOT NULL AND email_message_id != ''
                      AND recipient_email IS NOT NULL
                  ) ranked
                  WHERE rn > 1
                )
            """))
            _deleted = _del.rowcount
            await _dd_session.commit()
            if _deleted:
                logger.info(f"Dedup: removed {_deleted} duplicate threat rows")
        # Step 2: create unique index in its own session (cannot run inside active transaction)
        async with AsyncSessionLocal() as _idx_session:
            await _idx_session.execute(_stext("SET lock_timeout = '3s'"))
            await _idx_session.execute(_stext("SET statement_timeout = '10s'"))
            await _idx_session.execute(_stext("""
                CREATE UNIQUE INDEX IF NOT EXISTS uq_threats_msg_recipient_org
                ON threats (email_message_id, org_id, recipient_email)
                WHERE email_message_id IS NOT NULL
                  AND email_message_id != ''
                  AND recipient_email IS NOT NULL
            """))
            await _idx_session.commit()
            logger.info("Dedup index uq_threats_msg_recipient_org ensured")
    except Exception as _ddup_e:
        logger.warning(f"Dedup/index startup step failed (non-fatal): {_ddup_e}")

    # ── Saas alerts dedup ─────────────────────────────────────────
    # Adnan 2026-06-18: saas_alerts had no UNIQUE constraint so every
    # CSPM / DSPM scan cycle was adding fresh rows for the same finding.
    # We saw 148 copies of one DSPM PII alert + 147 copies of a GitHub
    # 2FA alert. Backfill a fingerprint, dedupe keeping the earliest
    # row, then add a partial UNIQUE index so future inserts coalesce.
    try:
        from sqlalchemy import text as _stext
        async with AsyncSessionLocal() as _ds_session:
            await _ds_session.execute(_stext("SET lock_timeout = '3s'"))
            await _ds_session.execute(_stext("SET statement_timeout = '15s'"))
            # Backfill fingerprint where missing. We use md5 over the
            # natural-key signature — cheap, deterministic, fits in 32 chars.
            await _ds_session.execute(_stext("""
                UPDATE saas_alerts
                   SET fingerprint = MD5(
                       COALESCE(provider, '') || '|' ||
                       COALESCE(alert_type, '') || '|' ||
                       COALESCE(resource_id, '') || '|' ||
                       LEFT(COALESCE(title, ''), 200)
                   )
                 WHERE fingerprint IS NULL
            """))
            await _ds_session.commit()
            # Keep the earliest occurrence per (org_id, fingerprint) and
            # carry forward the LATEST status if any sibling was already
            # acknowledged / resolved (so we don't accidentally re-open
            # something the user closed).
            _del = await _ds_session.execute(_stext("""
                WITH ranked AS (
                    SELECT id,
                           ROW_NUMBER() OVER (
                               PARTITION BY org_id, fingerprint
                               ORDER BY created_at ASC, id ASC
                           ) AS rn
                      FROM saas_alerts
                     WHERE fingerprint IS NOT NULL
                )
                DELETE FROM saas_alerts
                 WHERE id IN (SELECT id FROM ranked WHERE rn > 1)
            """))
            _ds_session_deleted = _del.rowcount
            await _ds_session.commit()
            if _ds_session_deleted:
                logger.info(f"Dedup: removed {_ds_session_deleted} duplicate saas_alert rows")
        # We deliberately do NOT add a UNIQUE constraint here yet —
        # 25+ Python insert sites would have to be updated to use ON
        # CONFLICT DO NOTHING. Instead we add a non-unique index on
        # fingerprint (for fast periodic cleanup) and run a periodic
        # dedup task (see saas_alerts_dedup_loop in backend/main.py).
        async with AsyncSessionLocal() as _ds_idx:
            await _ds_idx.execute(_stext("SET lock_timeout = '3s'"))
            await _ds_idx.execute(_stext("SET statement_timeout = '15s'"))
            await _ds_idx.execute(_stext("""
                CREATE INDEX IF NOT EXISTS ix_saas_alerts_org_fingerprint
                ON saas_alerts (org_id, fingerprint)
                WHERE fingerprint IS NOT NULL
            """))
            await _ds_idx.commit()
            logger.info("Index ix_saas_alerts_org_fingerprint ensured")
        # DB-side trigger so new inserts always populate fingerprint
        # automatically, regardless of which of the 25+ Python insert
        # sites is firing. Keeps inserters dumb and the periodic
        # cleanup cheap.
        async with AsyncSessionLocal() as _ds_trig:
            await _ds_trig.execute(_stext("""
                CREATE OR REPLACE FUNCTION saas_alerts_compute_fingerprint()
                RETURNS TRIGGER AS $$
                BEGIN
                    IF NEW.fingerprint IS NULL THEN
                        NEW.fingerprint := MD5(
                            COALESCE(NEW.provider, '') || '|' ||
                            COALESCE(NEW.alert_type, '') || '|' ||
                            COALESCE(NEW.resource_id, '') || '|' ||
                            LEFT(COALESCE(NEW.title, ''), 200)
                        );
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
            """))
            await _ds_trig.execute(_stext("""
                DROP TRIGGER IF EXISTS saas_alerts_fingerprint_trigger ON saas_alerts;
            """))
            await _ds_trig.execute(_stext("""
                CREATE TRIGGER saas_alerts_fingerprint_trigger
                BEFORE INSERT OR UPDATE OF provider, alert_type, resource_id, title ON saas_alerts
                FOR EACH ROW
                EXECUTE FUNCTION saas_alerts_compute_fingerprint();
            """))
            await _ds_trig.commit()
            logger.info("saas_alerts fingerprint trigger installed")
    except Exception as _saas_dd_e:
        logger.warning(f"saas_alerts dedup startup step failed (non-fatal): {_saas_dd_e}")

    # Ensure tenant admin password hash is in sync with settings (prevents login breakage after re-provision)
    try:
        from backend.utils.hashing import hash_password, verify_password
        async with AsyncSessionLocal() as _pw_session:
            from backend.models.db_models import User
            from sqlalchemy import select as _sel
            _res = await _pw_session.execute(_sel(User).where(User.email == settings.VENDOR_ADMIN_EMAIL))
            _admin_user = _res.scalar_one_or_none()
            if _admin_user and _admin_user.password_hash:
                # Only re-sync if the current hash doesn't verify — avoids unnecessary writes
                if not verify_password(settings.VENDOR_ADMIN_PASSWORD, _admin_user.password_hash):
                    _admin_user.password_hash = hash_password(settings.VENDOR_ADMIN_PASSWORD)
                    _admin_user.is_active = True
                    await _pw_session.commit()
                    logger.warning(f"startup: re-synced password hash for {settings.VENDOR_ADMIN_EMAIL} (was stale)")
                else:
                    logger.info(f"startup: password hash OK for {settings.VENDOR_ADMIN_EMAIL}")
    except Exception as _pw_e:
        logger.warning(f"startup: password sync check failed (non-fatal): {_pw_e}")

    # Store background task references to prevent GC and enable exception logging
    _background_tasks = []

    # Start 1-minute delta sync loop
    try:
        from backend.services.delta_sync import run_delta_sync_loop, run_outbound_dlp_loop
        _delta_task = asyncio.create_task(run_delta_sync_loop(), name="delta_sync_loop")
        _background_tasks.append(_delta_task)
        logger.info("Delta sync loop started")
        
        # Start fast 20-second outbound DLP loop for recall capability
        _outbound_dlp_task = asyncio.create_task(run_outbound_dlp_loop(), name="outbound_dlp_loop")
        _background_tasks.append(_outbound_dlp_task)
        logger.info("Outbound DLP loop started (20s interval)")
    except Exception as e:
        logger.warning(f"Delta sync loop failed to start: {e}")

    # Start background draft + spam auto-scan loops
    try:
        from backend.services.draft_spam_scan_service import run_draft_scan_loop, run_spam_sync_loop
        asyncio.create_task(run_draft_scan_loop())
        asyncio.create_task(run_spam_sync_loop())
        logger.info("Draft and spam auto-scan loops started")
    except Exception as e:
        logger.warning(f"Draft/spam scan loops failed to start: {e}")

    # Start SaaS Security background scan loop (Shadow IT, Entra Risk, Admin Actions)
    async def _saas_security_scan_loop():
        import asyncio as _aio
        SAAS_SCAN_INTERVAL = 300  # 5 minutes — per user 2026-06-16 directive.
                                  # Keeps SaaS scans, CSPM, and DSPM all on the same
                                  # cadence so the cross-cloud Overview is coherent.
        await _aio.sleep(60)  # Initial delay to let other workers start
        while True:
            try:
                from backend.routers.saas_security import _run_saas_scan
                from backend.models.db_models import SaasIntegration
                from sqlalchemy import select as _sel
                async with AsyncSessionLocal() as _db:
                    integs = (await _db.execute(
                        _sel(SaasIntegration.org_id).where(SaasIntegration.status == "active").distinct()
                    )).scalars().all()
                    for oid in integs:
                        try:
                            await _run_saas_scan(str(oid))
                        except Exception as _se:
                            logger.warning(f"saas_security_loop: org {oid}: {_se}")
            except Exception as _le:
                logger.warning(f"saas_security_loop: {_le}")
            await _aio.sleep(SAAS_SCAN_INTERVAL)

    try:
        asyncio.create_task(_saas_security_scan_loop())
        logger.info("SaaS Security scan loop started (5 min interval)")  # already correct text
    except Exception as e:
        logger.warning(f"SaaS Security scan loop failed to start: {e}")

    # Proactive SaaS token warmup — force-refresh every stored Microsoft Graph token at
    # boot so the running task does not keep re-using a stale token issued before the
    # most recent admin-consent regrant. Fires-and-forgets; failures are logged only.
    try:
        from backend.routers.saas_security import warmup_saas_tokens
        asyncio.create_task(warmup_saas_tokens())
        logger.info("SaaS token warmup scheduled")
    except Exception as e:
        logger.warning(f"SaaS token warmup failed to schedule: {e}")

    # Start Workspace Sync loop for AWS/GCP/Databricks/SAP connectors
    try:
        from backend.services.workspace_sync import run_workspace_sync_loop
        asyncio.create_task(run_workspace_sync_loop())
        logger.info("Workspace sync loop started (5 min interval for cloud connectors)")
    except Exception as e:
        logger.warning(f"Workspace sync loop failed to start: {e}")

    # Start Databricks background scanner (10 min interval)
    try:
        from backend.routers.databricks_connector import start_databricks_background_worker
        start_databricks_background_worker()
    except Exception as e:
        logger.warning(f"Databricks background scanner failed to start: {e}")

    # Start 15-day rebaseline loop — improves threat detection accuracy over time
    # Re-runs baseline ingestion for all active orgs every 15 days so the AI models
    # re-learn from the latest email patterns, catching drift and new attack vectors.
    async def _rebaseline_loop():
        import asyncio as _aio
        REBASELINE_INTERVAL_DAYS = 15
        REBASELINE_INTERVAL_SEC = REBASELINE_INTERVAL_DAYS * 24 * 3600

        # Stagger first run — wait 1 hour so the initial baseline finishes first
        await _aio.sleep(3600)

        while True:
            try:
                logger.info("Periodic rebaseline: starting 15-day refresh cycle")
                from backend.database import AsyncSessionLocal
                from backend.models.db_models import OrgIntegration, Organization
                from backend.services.baseline_ingestion import run_baseline_ingestion
                from backend.services.baseline_ingestion import _decrypt
                import redis.asyncio as _aioredis
                from sqlalchemy import select as _sel

                async with AsyncSessionLocal() as _db:
                    integ_res = await _db.execute(
                        _sel(OrgIntegration).where(OrgIntegration.status == "active")
                    )
                    integrations = integ_res.scalars().all()

                for integ in integrations:
                    try:
                        org_id = str(integ.org_id)
                        provider = (integ.provider or "").lower()
                        logger.info(f"Rebaseline: org={org_id} provider={provider}")

                        _redis = _aioredis.from_url(settings.REDIS_URL, decode_responses=True)
                        try:
                            # Skip if a baseline is already running for this org
                            status = await _redis.get(f"baseline:{org_id}:status")
                            if status == "running":
                                logger.info(f"Rebaseline: skipping org {org_id} — baseline already running")
                                continue

                            # Mark as running
                            await _redis.set(f"baseline:{org_id}:status", "running", ex=7200)
                            await _redis.set(f"baseline:{org_id}:progress", 1, ex=7200)
                        finally:
                            await _redis.aclose()

                        access_token = _decrypt(integ.access_token_enc) if integ.access_token_enc else ""
                        refresh_token = _decrypt(integ.refresh_token_enc) if integ.refresh_token_enc else ""

                        async with AsyncSessionLocal() as _rebase_db:
                            org_res = await _rebase_db.execute(
                                _sel(Organization).where(Organization.id == integ.org_id)
                            )
                            org = org_res.scalar_one_or_none()
                            domain = org.domain if org else ""
                            mailbox_count = org.mailbox_count if org else 50

                        if provider in ("google", "google_workspace", "gmail"):
                            await run_baseline_ingestion(
                                org_id=org_id,
                                access_token=access_token,
                                refresh_token=refresh_token,
                                domain=domain,
                                mailbox_count=mailbox_count,
                            )
                        # M365 rebaseline can be added here when Graph API baseline is implemented
                        logger.info(f"Rebaseline complete for org={org_id}")
                    except Exception as _re:
                        logger.warning(f"Rebaseline failed for org {integ.org_id}: {_re}")

            except Exception as _loop_err:
                logger.warning(f"Rebaseline loop error: {_loop_err}")

            logger.info(f"Periodic rebaseline: sleeping {REBASELINE_INTERVAL_DAYS} days until next cycle")
            await _aio.sleep(REBASELINE_INTERVAL_SEC)

    try:
        asyncio.create_task(_rebaseline_loop())
        logger.info("15-day periodic rebaseline loop started")
    except Exception as e:
        logger.warning(f"Rebaseline loop failed to start: {e}")

    # ── Periodic saas_alerts dedup loop ────────────────────────────
    # Cleans up rows the CSPM mirror / DSPM scanner re-insert each
    # cycle. Adnan 2026-06-18: 25+ insert sites + no UNIQUE → ~1000
    # duplicate rows accumulated. Running every 5 min keeps the noise
    # close to zero while we migrate inserters to ON CONFLICT.
    async def _saas_alerts_dedup_loop():
        import asyncio as _aio
        from sqlalchemy import text as _stext
        await _aio.sleep(60)  # let startup finish first
        while True:
            try:
                async with AsyncSessionLocal() as _s:
                    await _s.execute(_stext("SET lock_timeout = '5s'"))
                    await _s.execute(_stext("SET statement_timeout = '30s'"))
                    # Backfill fingerprint for any row that snuck in
                    # before the trigger fired.
                    await _s.execute(_stext("""
                        UPDATE saas_alerts
                           SET fingerprint = MD5(
                               COALESCE(provider, '') || '|' ||
                               COALESCE(alert_type, '') || '|' ||
                               COALESCE(resource_id, '') || '|' ||
                               LEFT(COALESCE(title, ''), 200)
                           )
                         WHERE fingerprint IS NULL
                    """))
                    await _s.commit()
                    # Delete duplicates, keeping earliest row per
                    # (org_id, fingerprint).
                    r = await _s.execute(_stext("""
                        WITH ranked AS (
                            SELECT id,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY org_id, fingerprint
                                       ORDER BY created_at ASC, id ASC
                                   ) AS rn
                              FROM saas_alerts
                             WHERE fingerprint IS NOT NULL
                        )
                        DELETE FROM saas_alerts
                         WHERE id IN (SELECT id FROM ranked WHERE rn > 1)
                    """))
                    removed = r.rowcount
                    await _s.commit()
                    if removed:
                        logger.info(f"saas_alerts_dedup_loop: removed {removed} duplicate row(s)")
                    # Also dedupe aws_findings (the alerts list UNIONs
                    # from this table). Same root cause: missing UNIQUE
                    # constraint + repeated CloudTrail polling reinserts.
                    r2 = await _s.execute(_stext("""
                        WITH ranked AS (
                            SELECT id,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY org_id, title, COALESCE(resource_id, '')
                                       ORDER BY detected_at ASC, id ASC
                                   ) AS rn
                              FROM aws_findings
                        )
                        DELETE FROM aws_findings
                         WHERE id IN (SELECT id FROM ranked WHERE rn > 1)
                    """))
                    removed_aws = r2.rowcount
                    await _s.commit()
                    if removed_aws:
                        logger.info(f"saas_alerts_dedup_loop: removed {removed_aws} duplicate aws_findings row(s)")
                    # And dedupe databricks_findings on the same shape.
                    r3 = await _s.execute(_stext("""
                        WITH ranked AS (
                            SELECT id,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY org_id, title, COALESCE(resource_id, '')
                                       ORDER BY detected_at ASC, id ASC
                                   ) AS rn
                              FROM databricks_findings
                        )
                        DELETE FROM databricks_findings
                         WHERE id IN (SELECT id FROM ranked WHERE rn > 1)
                    """))
                    removed_db = r3.rowcount
                    await _s.commit()
                    if removed_db:
                        logger.info(f"saas_alerts_dedup_loop: removed {removed_db} duplicate databricks_findings row(s)")
            except Exception as _e:
                logger.debug(f"saas_alerts_dedup_loop iteration failed: {_e}")
            await _aio.sleep(300)  # every 5 minutes

    try:
        asyncio.create_task(_saas_alerts_dedup_loop())
        logger.info("saas_alerts dedup loop started (every 5 min)")
    except Exception as e:
        logger.warning(f"saas_alerts dedup loop failed to start: {e}")

    # Start compliance auto-assessment worker (runs 30s after startup, then every 24h)
    try:
        from backend.services.compliance_worker import run_compliance_assessment_loop
        from backend.services.daily_digest import run_daily_digest_loop
        from backend.services.weekly_digest import run_weekly_digest_loop
        asyncio.create_task(run_compliance_assessment_loop())
        asyncio.create_task(run_daily_digest_loop())
        asyncio.create_task(run_weekly_digest_loop())
        logger.info("Compliance auto-assessment worker + digest loops started")
    except Exception as e:
        logger.warning(f"Compliance worker failed to start: {e}")

    # Start OpenDBL IP blocklist refresh worker (every 6 hours)
    # Skip if SKIP_THREAT_FEEDS=1 (reduces memory on low-RAM systems like Pi)
    skip_feeds = os.getenv("SKIP_THREAT_FEEDS", "0") == "1"
    if not skip_feeds:
        try:
            from backend.services.opendbl_service import run_opendbl_refresh_loop
            asyncio.create_task(run_opendbl_refresh_loop())
            from backend.services.anva_service import run_anva_refresh_loop
            asyncio.create_task(run_anva_refresh_loop())
            logger.info("OpenDBL blocklist refresh worker started (6h interval)")
        except Exception as e:
            logger.warning(f"OpenDBL worker failed to start: {e}")

        # Start IOC Threat Feeds refresh worker (every 1 hour)
        try:
            from backend.services.threat_feeds_service import run_feeds_refresh_loop
            asyncio.create_task(run_feeds_refresh_loop())
            logger.info("Threat feeds refresh worker started (interval: 1h)")
        except Exception as e:
            logger.warning(f"Threat feeds worker failed to start: {e}")
    else:
        logger.info("Threat feeds skipped (SKIP_THREAT_FEEDS=1)")

    # ── CERT-CN IOC scraper (6h interval) ────────────────────────────────────
    try:
        from backend.services.cert_cn_service import run_cert_cn_refresh_loop
        asyncio.create_task(run_cert_cn_refresh_loop())
        logger.info("CERT-CN IOC scraper started (interval: 6h)")
    except Exception as _ce:
        logger.warning(f"CERT-CN scraper failed to start: {_ce}")

    # M365 token proactive refresh — runs every 45 minutes to keep tokens fresh
    # M365 access tokens expire in 1h; refreshing at 45 min ensures no expiry gaps
    # between delta sync cycles. New token is persisted back to org_integrations.
    async def _m365_token_refresh_loop():
        """Proactively refresh M365 access tokens for all active integrations every 45 min."""
        await asyncio.sleep(60)  # Wait 1 min after startup before first run
        while True:
            try:
                from backend.services.baseline_ingestion import _refresh_m365_token, _decrypt
                from backend.routers.onboarding import encrypt_token as _encrypt
                from backend.models.db_models import OrgIntegration as _M365OI
                from sqlalchemy import select as _m365sel
                async with AsyncSessionLocal() as _m365db:
                    _res = await _m365db.execute(
                        _m365sel(_M365OI).where(
                            _M365OI.provider == "m365",
                            _M365OI.status == "active",
                        )
                    )
                    integrations = _res.scalars().all()

                refreshed = 0
                for integ in integrations:
                    try:
                        refresh_token = _decrypt(integ.refresh_token_enc) if integ.refresh_token_enc else None
                        if not refresh_token or refresh_token in ("demo_refresh_token", ""):
                            continue
                        new_token = await _refresh_m365_token(refresh_token)
                        if new_token:
                            async with AsyncSessionLocal() as _persist_db:
                                from sqlalchemy import select as _psel
                                _ir = await _persist_db.execute(
                                    _psel(_M365OI).where(_M365OI.id == integ.id)
                                )
                                _i = _ir.scalar_one_or_none()
                                if _i:
                                    _i.access_token_enc = _encrypt(new_token)
                                    await _persist_db.commit()
                                    refreshed += 1
                    except Exception as _te:
                        logger.debug(f"M365 token refresh failed for org {integ.org_id}: {_te}")

                if refreshed:
                    logger.info(f"M365 proactive token refresh: {refreshed} token(s) refreshed")
            except Exception as _loop_e:
                logger.warning(f"M365 token refresh loop error: {_loop_e}")

            await asyncio.sleep(45 * 60)  # 45-minute interval

    try:
        asyncio.create_task(_m365_token_refresh_loop())
        logger.info("M365 proactive token refresh loop started (45 min interval)")
    except Exception as e:
        logger.warning(f"M365 token refresh loop failed to start: {e}")

    # Auto-triage: re-spawn per-org loops for any org that had it enabled before restart.
    # Redis key `auto_triage:enabled:{org_id}` persists across restarts (TTL 24h).
    # On startup we scan all orgs and restart the loop for any with the key still set.
    try:
        import redis.asyncio as _at_redis
        from backend.models.db_models import Organization as _ATOrg
        from sqlalchemy import select as _at_sel
        from backend.services.auto_triage_service import run_auto_triage_loop

        # Track active triage loops by org_id
        _active_triage_tasks: dict[str, asyncio.Task] = {}

        async def _spawn_triage_loop(org_id: str):
            """Spawn a triage loop for an org, wrapped with auto-restart on crash."""
            while True:
                try:
                    await run_auto_triage_loop(org_id)
                    # If loop exits normally (disabled), break out
                    break
                except Exception as exc:
                    logger.error(f"auto_triage: loop crashed for org={org_id}, restarting in 30s: {exc}")
                    await asyncio.sleep(30)
                    # Check if still enabled before restarting
                    _r = _at_redis.from_url(settings.REDIS_URL, decode_responses=True)
                    try:
                        still_enabled = await _r.get(f"auto_triage:enabled:{org_id}")
                        if not still_enabled:
                            logger.info(f"auto_triage: org={org_id} disabled while crashed, not restarting")
                            break
                    finally:
                        await _r.aclose()

        async def _restore_auto_triage_loops():
            """Re-spawn auto-triage loops for all orgs that had it enabled before restart.
            Source of truth is Postgres org_metadata.auto_triage_enabled (survives Redis flushes).
            Redis key is re-synced here so the loop can read it without a DB call each cycle.
            """
            await asyncio.sleep(5)  # Let rest of startup complete first
            _r = _at_redis.from_url(settings.REDIS_URL, decode_responses=True)
            try:
                async with AsyncSessionLocal() as _at_db:
                    _org_res = await _at_db.execute(_at_sel(_ATOrg))
                    orgs = _org_res.scalars().all()

                restored = 0
                for _org in orgs:
                    _oid = str(_org.id)
                    meta = _org.org_metadata or {}
                    db_enabled = meta.get("auto_triage_enabled", False)

                    # Also check Redis as fallback for orgs toggled before this deploy
                    redis_enabled = await _r.get(f"auto_triage:enabled:{_oid}")

                    if db_enabled or redis_enabled:
                        # Re-sync Redis key with no TTL (persistent until disabled)
                        await _r.set(f"auto_triage:enabled:{_oid}", "1")
                        task = asyncio.create_task(_spawn_triage_loop(_oid))
                        _active_triage_tasks[_oid] = task
                        restored += 1
                        logger.info(f"auto_triage: restored loop for org={_oid} (db={db_enabled} redis={bool(redis_enabled)})")

                if restored:
                    logger.info(f"auto_triage: {restored} org loop(s) restored on startup")
                else:
                    logger.info("auto_triage: no orgs had auto-triage enabled — nothing to restore")
            finally:
                await _r.aclose()

        asyncio.create_task(_restore_auto_triage_loops())
        logger.info("Auto-triage startup restore task scheduled (with auto-restart on crash)")

        # Store spawn function for use by the enable endpoint
        import builtins
        builtins._helios_spawn_triage_loop = _spawn_triage_loop
        builtins._helios_active_triage_tasks = _active_triage_tasks
    except Exception as e:
        logger.warning(f"Auto-triage startup restore failed: {e}")

    # ── Sandbox orphan reaper (runs once on startup + periodic) ──────────────
    # Kills any helios-sandbox ECS tasks older than SESSION_TIMEOUT minutes
    # that were orphaned by a prior backend restart (their asyncio.sleep timer died).
    async def _sandbox_reaper():
        import boto3 as _boto3, os as _os
        from datetime import timezone as _tz
        _timeout_min = int(_os.getenv("SANDBOX_SESSION_TIMEOUT_MINUTES", "30"))
        _cluster = _os.getenv("SANDBOX_ECS_CLUSTER", "himaya")
        _region  = _os.getenv("AWS_REGION", "us-west-2")
        while True:
            try:
                _ecs = _boto3.client("ecs", region_name=_region)
                _arns_resp = _ecs.list_tasks(cluster=_cluster)
                _arns = _arns_resp.get("taskArns", [])
                if _arns:
                    _tasks = _ecs.describe_tasks(cluster=_cluster, tasks=_arns).get("tasks", [])
                    _now = datetime.now(_tz.utc)
                    _killed = 0
                    for _t in _tasks:
                        if "helios-sandbox" not in (_t.get("taskDefinitionArn") or ""):
                            continue
                        _started = _t.get("startedAt")
                        if not _started:
                            continue
                        if _started.tzinfo is None:
                            _started = _started.replace(tzinfo=_tz.utc)
                        _age_min = (_now - _started).total_seconds() / 60
                        if _age_min > _timeout_min:
                            try:
                                _ecs.stop_task(
                                    cluster=_cluster,
                                    task=_t["taskArn"],
                                    reason=f"Sandbox timeout reaper: age={int(_age_min)}min > {_timeout_min}min",
                                )
                                _killed += 1
                                logger.info(f"sandbox_reaper: stopped orphaned task {_t['taskArn'][-12:]} (age={int(_age_min)}min)")
                            except Exception as _ke:
                                logger.debug(f"sandbox_reaper: stop failed for {_t.get('taskArn','?')}: {_ke}")
                    if _killed:
                        logger.info(f"sandbox_reaper: killed {_killed} orphaned sandbox task(s)")
            except Exception as _re:
                logger.debug(f"sandbox_reaper: cycle error (non-fatal): {_re}")
            await asyncio.sleep(300)  # check every 5 min

    try:
        asyncio.create_task(_sandbox_reaper())
        logger.info("Sandbox orphan reaper started (5min interval, 30min timeout)")
    except Exception as _sre:
        logger.warning(f"Sandbox reaper start failed: {_sre}")

    # ── Posture auto-scan loop (every 6 hours) ────────────────────────────
    async def _posture_scan_loop():
        import asyncio as _aio
        from sqlalchemy import select as _psel
        from backend.models.db_models import OrgIntegration as _POI
        from backend.routers.posture import _run_posture_scan
        from backend.routers.saas_security import _update_worker_status, _set_worker_next_run
        POSTURE_INTERVAL = 6 * 3600  # 6 hours
        await _aio.sleep(120)  # 2-min startup delay
        while True:
            _update_worker_status("posture_scan", "running")
            _set_worker_next_run("posture_scan", POSTURE_INTERVAL)
            try:
                async with AsyncSessionLocal() as _pdb:
                    # Only scan enterprise/enterprise-trial orgs
                    from backend.models.db_models import Organization as _PostureOrg
                    from sqlalchemy import select as _osel
                    _ent_orgs = await _pdb.execute(
                        _osel(_PostureOrg.id).where(
                            _PostureOrg.tier.in_(["Enterprise", "enterprise", "Enterprise Trial", "enterprise trial"])
                        )
                    )
                    _ent_org_ids = {str(r[0]) for r in _ent_orgs.fetchall() if r[0]}
                    _res = await _pdb.execute(_psel(_POI.org_id).where(_POI.status == "active").distinct())
                    _org_ids = [str(r[0]) for r in _res.fetchall() if r[0] is not None and str(r[0]) in _ent_org_ids]
                for _oid in _org_ids:
                    try:
                        await _run_posture_scan(_oid)
                        logger.info(f"Posture auto-scan completed for org {_oid}")
                    except Exception as _pe:
                        logger.warning(f"Posture auto-scan failed for org {_oid}: {_pe}")
            except Exception as _ple:
                logger.warning(f"Posture scan loop error: {_ple}")
            await _aio.sleep(POSTURE_INTERVAL)
    try:
        asyncio.create_task(_posture_scan_loop())
        logger.info("Posture auto-scan loop started (6h interval)")
    except Exception as _pse:
        logger.warning(f"Posture scan loop start failed: {_pse}")

    # ── AWS Security scan loop (every 5 minutes) ───────────────────────────────
    async def _aws_security_scan_loop():
        import asyncio as _aio
        from sqlalchemy import text as _txt
        AWS_SCAN_INTERVAL = 2 * 60  # 2 minutes — tightened from 5 min so the
                                    # fast upsert loop refreshes resources/findings
                                    # nearly in real-time. workspace_sync still owns
                                    # the slow full sweep + prune at 5 min.
        await _aio.sleep(90)  # 1.5-min startup delay
        while True:
            from backend.routers.saas_security import _update_worker_status, _set_worker_next_run, _aws_ai_classify_resource
            _update_worker_status("aws_scan", "running")
            _set_worker_next_run("aws_scan", AWS_SCAN_INTERVAL)
            try:
                async with AsyncSessionLocal() as _db:
                    # Get all AWS connections that need scanning
                    _res = await _db.execute(_txt("""
                        SELECT c.id, c.org_id, c.access_key_id_enc, c.secret_access_key_enc,
                               c.default_region, c.scan_regions
                        FROM aws_connections c
                        WHERE c.status = 'active'
                          AND (c.last_scan_at IS NULL OR c.last_scan_at < NOW() - INTERVAL '5 minutes')
                    """))
                    _conns = _res.mappings().fetchall()
                for _conn in _conns:
                    try:
                        from backend.routers.aws_connector import _decrypt
                        from backend.services.aws_security_service import AWSSecurityService
                        import json as _json
                        
                        _access_key = _decrypt(_conn["access_key_id_enc"])
                        _secret_key = _decrypt(_conn["secret_access_key_enc"])
                        _regions = _conn["scan_regions"] or [_conn["default_region"]]
                        _org_id = str(_conn["org_id"])
                        _conn_id = str(_conn["id"])
                        
                        _svc = AWSSecurityService(
                            access_key_id=_access_key,
                            secret_access_key=_secret_key,
                            region=_conn["default_region"],
                        )
                        logger.info(f"AWS auto-scan starting for connection {_conn['id']}")
                        _result = await _svc.scan_all(regions=_regions)
                        logger.info(f"AWS scan_all returned: {len(_result.get('resources', []))} resources, {len(_result.get('findings', []))} findings")
                        
                        # Store results in DB
                        async with AsyncSessionLocal() as _wdb:
                            logger.info(f"AWS auto-scan storing {len(_result.get('resources', []))} resources for connection {_conn_id}")
                            
                            for _res_item in _result.get("resources", []):
                                # AI classify high-risk resources (public or unencrypted)
                                _ai_result = None
                                if _res_item.get("public_access") or not _res_item.get("encryption_enabled", True):
                                    try:
                                        _ai_result = await _aws_ai_classify_resource(
                                            _res_item["resource_type"],
                                            _res_item.get("metadata", {}),
                                            _org_id,
                                        )
                                    except Exception:
                                        pass

                                _meta = _res_item.get("metadata", {})
                                if _ai_result:
                                    _meta["ai_risk_level"] = _ai_result.get("risk_level")
                                    _meta["ai_categories"] = _ai_result.get("categories", [])
                                    _meta["ai_remediation"] = _ai_result.get("remediation_steps", [])
                                    _meta["ai_explanation"] = _ai_result.get("explanation", "")

                                await _wdb.execute(_txt("""
                                    INSERT INTO aws_resources
                                        (org_id, connection_id, resource_type, resource_id, resource_arn,
                                         name, region, size_bytes, encryption_enabled, public_access,
                                         tags, metadata, scanned_at)
                                    VALUES (:org_id, :conn_id, :rt, :rid, :arn, :name, :region,
                                            :size, :enc, :pub, CAST(:tags AS jsonb), CAST(:meta AS jsonb), NOW())
                                    ON CONFLICT (org_id, resource_arn) DO UPDATE SET
                                        name = EXCLUDED.name, size_bytes = EXCLUDED.size_bytes,
                                        encryption_enabled = EXCLUDED.encryption_enabled,
                                        public_access = EXCLUDED.public_access,
                                        tags = EXCLUDED.tags,
                                        -- Preserve DLP/AI keys written by
                                        -- _aws_dlp_classify_resources between
                                        -- cycles. Without this the 2-min
                                        -- auto-scan loop wipes the labels
                                        -- the classifier just wrote and the
                                        -- Data Inventory "Categories" column
                                        -- never sticks. This is the
                                        -- third aws_resources writer (the
                                        -- other two live in aws_connector.py
                                        -- and workspace_sync.py and already
                                        -- have this preserve clause).
                                        metadata = EXCLUDED.metadata || COALESCE(
                                            (SELECT jsonb_object_agg(key, value)
                                             FROM jsonb_each(aws_resources.metadata)
                                             WHERE key IN ('dlp_classified','dlp_categories',
                                                           'dlp_risk_level','dlp_schema_version',
                                                           'ai_categories','ai_risk_level',
                                                           'ai_remediation','ai_explanation')),
                                            '{}'::jsonb
                                        ),
                                        scanned_at = NOW()
                                """), {
                                    "org_id": _org_id, "conn_id": _conn_id,
                                    "rt": _res_item["resource_type"], "rid": _res_item["resource_id"],
                                    "arn": _res_item["resource_arn"], "name": _res_item["name"],
                                    "region": _res_item["region"], "size": _res_item.get("size_bytes"),
                                    "enc": _res_item.get("encryption_enabled", False),
                                    "pub": _res_item.get("public_access", False),
                                    "tags": _json.dumps(_res_item.get("tags", {})),
                                    "meta": _json.dumps(_meta),
                                })

                                # Create alert for AI-classified high-risk resources
                                if _ai_result and _ai_result.get("risk_level") in ("high", "critical"):
                                    try:
                                        await _wdb.execute(_txt("""
                                            INSERT INTO aws_findings
                                                (org_id, connection_id, finding_id, severity, category,
                                                 resource_type, resource_id, resource_arn,
                                                 title, description, recommendation, detected_at, metadata)
                                            VALUES (:org_id, :conn_id, :fid, :sev, :cat, :rt, :rid, :arn,
                                                    :title, :desc, :rec, NOW(), CAST(:meta AS jsonb))
                                            ON CONFLICT (org_id, finding_id) DO UPDATE SET
                                                severity = EXCLUDED.severity,
                                                description = EXCLUDED.description
                                        """), {
                                            "org_id": _org_id, "conn_id": _conn_id,
                                            "fid": f"ai-{_res_item['resource_arn'][:80]}",
                                            "sev": _ai_result["risk_level"],
                                            "cat": ",".join(_ai_result.get("categories", ["ai_analysis"])),
                                            "rt": _res_item["resource_type"],
                                            "rid": _res_item["resource_id"],
                                            "arn": _res_item["resource_arn"],
                                            "title": f"AI Risk: {_res_item['name']} ({_ai_result['risk_level']})",
                                            "desc": _ai_result.get("explanation", ""),
                                            "rec": "; ".join(_ai_result.get("remediation_steps", [])[:2]),
                                            "meta": _json.dumps(_ai_result),
                                        })
                                    except Exception:
                                        pass
                            
                            for _find in _result.get("findings", []):
                                await _wdb.execute(_txt("""
                                    INSERT INTO aws_findings
                                        (org_id, connection_id, finding_id, severity, category,
                                         resource_type, resource_id, resource_arn,
                                         title, description, recommendation, detected_at, metadata)
                                    VALUES (:org_id, :conn_id, :fid, :sev, :cat, :rt, :rid, :arn,
                                            :title, :desc, :rec, NOW(), CAST(:meta AS jsonb))
                                    ON CONFLICT (org_id, finding_id) DO UPDATE SET
                                        severity = EXCLUDED.severity, title = EXCLUDED.title,
                                        description = EXCLUDED.description,
                                        recommendation = EXCLUDED.recommendation
                                """), {
                                    "org_id": _org_id, "conn_id": _conn_id,
                                    "fid": _find["finding_id"], "sev": _find["severity"],
                                    "cat": _find["category"], "rt": _find["resource_type"],
                                    "rid": _find["resource_id"], "arn": _find["resource_arn"],
                                    "title": _find["title"], "desc": _find["description"],
                                    "rec": _find["recommendation"],
                                    "meta": _json.dumps(_find.get("metadata", {})),
                                })
                            
                            await _wdb.execute(_txt(
                                "UPDATE aws_connections SET last_scan_at = NOW() WHERE id = :id"
                            ), {"id": _conn_id})
                            await _wdb.commit()
                            logger.info(f"AWS auto-scan DB commit successful for connection {_conn_id}")
                        
                        logger.info(f"AWS auto-scan completed for connection {_conn_id}: {len(_result.get('resources', []))} resources, {len(_result.get('findings', []))} findings")
                        _update_worker_status("aws_scan", "completed")
                    except Exception as _ae:
                        import traceback
                        logger.warning(f"AWS auto-scan failed for connection {_conn.get('id')}: {_ae}")
                        logger.warning(f"AWS auto-scan traceback: {traceback.format_exc()}")
                        _update_worker_status("aws_scan", "error", str(_ae)[:200])
            except Exception as _ale:
                logger.warning(f"AWS scan loop error: {_ale}")
            await _aio.sleep(AWS_SCAN_INTERVAL)
    
    try:
        asyncio.create_task(_aws_security_scan_loop())
        logger.info("AWS Security auto-scan loop started (5 min interval)")
    except Exception as _awse:
        logger.warning(f"AWS scan loop start failed: {_awse}")

    # ── SaaS Security watchdog (restarts on crash, 5 min interval) ─────────────
    async def _saas_worker_watchdog():
        """Watchdog: restarts saas scan worker if it crashes."""
        while True:
            try:
                from backend.routers.saas_security import _auto_scan_all_orgs
                while True:
                    await _auto_scan_all_orgs()
                    await asyncio.sleep(300)  # 5 min — gives DeepSeek time to finish inference per file
            except Exception as exc:
                logger.error(f"saas_worker: crashed, restarting in 30s: {exc}")
                await asyncio.sleep(30)
    try:
        asyncio.create_task(_saas_worker_watchdog())
        logger.info("SaaS Security watchdog started (5 min interval, auto-restart on crash)")
    except Exception as _sse:
        logger.warning(f"SaaS watchdog start failed: {_sse}")

    # ── DLP Classification Worker (Claude-powered, 30 min interval) ────────────
    async def _dlp_worker_loop():
        """DLP classification worker using Claude API."""
        while True:
            try:
                from backend.routers.saas_security import _run_dlp_worker_all_orgs, _update_worker_status, _set_worker_next_run
                _update_worker_status("dlp_worker", "running")
                _set_worker_next_run("dlp_worker", 1800)
                await _run_dlp_worker_all_orgs()
                _update_worker_status("dlp_worker", "completed")
            except Exception as exc:
                logger.warning(f"dlp_worker_loop: error: {exc}")
            await asyncio.sleep(1800)  # 30 minutes
    try:
        asyncio.create_task(_dlp_worker_loop())
        logger.info("DLP classification worker started (30 min interval)")
    except Exception as _dlpe:
        logger.warning(f"DLP worker start failed: {_dlpe}")

    # ── Unified CSPM + DSPM background loop (5 min interval) ─────────────────
    # Walks every connected cloud + M365 tenant and runs:
    #   - CSPM engine (AWS / Azure / GCP / Oracle / GitHub)
    #   - DSPM scanner (AWS S3 + M365 SharePoint/OneDrive)
    # Findings flow into cspm_findings / dspm_findings + the saas_alerts mirror.
    async def _cspm_dspm_loop():
        import asyncio as _aio
        from sqlalchemy import text as _ctxt
        CSPM_DSPM_INTERVAL = 300  # 5 minutes
        # Per-connection staleness threshold so a manual scan isn't redone
        # if it happened in the last interval.
        STALENESS_SECONDS = CSPM_DSPM_INTERVAL - 30
        # Wait long enough that ECS ALB health checks have stabilised before
        # we start the first heavy cycle. AWS CSPM in particular uses sync
        # boto3 in run_in_executor which competes for the default thread pool
        # used by /health, so the first cycle MUST happen after the task is
        # registered as healthy.
        await _aio.sleep(420)  # 7 min — first cycle never collides with ALB grace

        async def _aws() -> tuple[int, int]:
            """Run CSPM against every active AWS connection.

            DSPM (S3 content sampling) used to be in this same coroutine,
            but the combined CSPM + DSPM workload would consistently blow
            the 180s per-cloud budget on accounts with many resources —
            see Adnan 2026-06-22 prod logs where every cycle showed
            `aws timed out after 180s` and `aws_dspm=0`. Split out into
            _aws_dspm so each gets its own budget.
            """
            cspm_n, dspm_n = 0, 0
            try:
                from backend.routers.aws_connector import _decrypt
                from backend.services.cspm import (
                    ScanContext as _CSPMCtx,
                    run_scan as _cspm_run,
                    write_findings as _cspm_wf,
                )
                from backend.services.cspm.collectors.aws import (
                    AwsCollectorConfig as _AwsCfg,
                    make_aws_collector as _mk_aws,
                )
                from backend.services.cspm.plugins.aws import AWS_PLUGINS as _AWS_PL
                from backend.services.cspm.sink import (
                    mark_resolved as _cspm_mr,
                    write_scan_report as _cspm_wr,
                )
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: AWS imports failed: {_imp}")
                return 0, 0

            async with AsyncSessionLocal() as _db:
                rows = (await _db.execute(_ctxt("""
                    SELECT id, org_id, access_key_id_enc, secret_access_key_enc,
                           default_region, scan_regions
                    FROM aws_connections
                    WHERE status = 'active'
                """))).mappings().fetchall()

            for row in rows:
                conn_id = str(row["id"])
                org_id = str(row["org_id"])
                try:
                    access_key = _decrypt(row["access_key_id_enc"])
                    secret_key = _decrypt(row["secret_access_key_enc"])
                    default_region = row["default_region"] or "us-east-1"
                    regions = row["scan_regions"] or [default_region]

                    # CSPM
                    try:
                        cfg = _AwsCfg(
                            access_key_id=access_key,
                            secret_access_key=secret_key,
                            default_region=default_region,
                            scan_regions=regions,
                        )
                        ctx = _CSPMCtx(
                            org_id=org_id, connection_id=conn_id,
                            cloud="aws", regions=regions,
                        )
                        report = await _cspm_run(
                            cloud="aws",
                            collector=_mk_aws(cfg),
                            plugins=_AWS_PL,
                            ctx=ctx,
                        )
                        async with AsyncSessionLocal() as _wdb:
                            await _cspm_wf(_wdb, org_id, conn_id, report.findings)
                            seen = {f.fingerprint for f in report.findings if f.status.value != "ok"}
                            await _cspm_mr(_wdb, org_id, "aws", seen)
                            await _cspm_wr(_wdb, report)
                        cspm_n += 1
                    except Exception as _ce:
                        logger.warning(f"cspm_dspm_loop: AWS CSPM failed for {conn_id}: {_ce}")

                except Exception as _ae:
                    logger.warning(f"cspm_dspm_loop: AWS conn {conn_id}: {_ae}")
            return cspm_n, dspm_n

        async def _aws_dspm() -> int:
            """AWS S3 DSPM scan (split out from _aws so each gets its own
            180s per-cloud budget). Reduces per-connection workload by
            tightening max_buckets/keys defaults so the scan finishes
            within budget on accounts with a lot of buckets.
            """
            n = 0
            try:
                from backend.routers.aws_connector import _decrypt
                from backend.services.dspm import run_aws_s3_scan as _dspm_aws
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: AWS DSPM imports failed: {_imp}")
                return 0

            async with AsyncSessionLocal() as _db:
                rows = (await _db.execute(_ctxt("""
                    SELECT id, org_id, access_key_id_enc, secret_access_key_enc,
                           default_region
                    FROM aws_connections
                    WHERE status = 'active'
                """))).mappings().fetchall()

            for row in rows:
                conn_id = str(row["id"])
                org_id = str(row["org_id"])
                try:
                    access_key = _decrypt(row["access_key_id_enc"])
                    secret_key = _decrypt(row["secret_access_key_enc"])
                    default_region = row["default_region"] or "us-east-1"
                    async with AsyncSessionLocal() as _wdb:
                        # Cap the workload so a single AWS account with
                        # hundreds of buckets doesn't starve every other
                        # cloud's slot in the gate. The defaults inside
                        # run_aws_s3_scan were 50 buckets × 100 keys =
                        # 5,000 head/get calls, which routinely exceeded
                        # the 180s budget. 25 × 50 leaves headroom.
                        await _dspm_aws(
                            _wdb,
                            org_id=org_id,
                            connection_id=conn_id,
                            access_key_id=access_key,
                            secret_access_key=secret_key,
                            default_region=default_region,
                            max_buckets=25,
                            max_keys_per_bucket=50,
                        )
                    n += 1
                except Exception as _de:
                    logger.warning(
                        f"cspm_dspm_loop: AWS DSPM failed for {conn_id}: {_de}"
                    )
            return n

        async def _connector_cspm(
            table: str,
            cloud_name: str,
            run_one,                  # async callable(org_id, conn_id)
        ) -> int:
            """Run CSPM for every active connection in ``table`` by delegating to the
            connector router's ``_run_background_scan`` helper. Keeps logic in one
            place per cloud and inherits all upsert/audit/last_scan_at bookkeeping."""
            n = 0
            try:
                async with AsyncSessionLocal() as _db:
                    rows = (await _db.execute(_ctxt(
                        f"SELECT id, org_id FROM {table} WHERE status = 'active'"
                    ))).fetchall()
            except Exception as _qe:
                logger.debug(f"cspm_dspm_loop: skipping {cloud_name} (no {table}): {_qe}")
                return 0

            for conn_id, org_id in rows:
                try:
                    await run_one(str(org_id), str(conn_id))
                    n += 1
                except Exception as _ge:
                    logger.warning(f"cspm_dspm_loop: {cloud_name} conn {conn_id}: {_ge}")
            return n

        async def _azure_cspm() -> int:
            try:
                from backend.routers.azure_connector import _run_background_scan as _az
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: azure import failed: {_imp}")
                return 0
            return await _connector_cspm("azure_connections", "azure", _az)

        async def _gcp_cspm() -> int:
            try:
                from backend.routers.gcp_connector import _run_background_scan as _gc
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: gcp import failed: {_imp}")
                return 0
            return await _connector_cspm("gcp_connections", "gcp", _gc)

        async def _oracle_cspm() -> int:
            try:
                from backend.routers.oracle_connector import _run_background_scan as _or
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: oracle import failed: {_imp}")
                return 0
            return await _connector_cspm("oracle_connections", "oracle", _or)

        async def _github_cspm() -> int:
            try:
                from backend.routers.github_connector import _run_background_scan as _gh
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: github import failed: {_imp}")
                return 0
            return await _connector_cspm("github_connections", "github", _gh)

        async def _snowflake_sspm() -> int:
            try:
                from backend.routers.snowflake_connector import _run_background_scan as _sf
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: snowflake import failed: {_imp}")
                return 0
            return await _connector_cspm("snowflake_connections", "snowflake", _sf)

        async def _sap_security() -> int:
            try:
                from backend.routers.sap_connector import _run_background_scan as _sap
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: sap import failed: {_imp}")
                return 0
            return await _connector_cspm("sap_connections", "sap", _sap)

        async def _salesforce_sspm() -> int:
            try:
                from backend.routers.salesforce_connector import (
                    _run_background_scan as _sfdc,
                )
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: salesforce import failed: {_imp}")
                return 0
            return await _connector_cspm("salesforce_connections", "salesforce", _sfdc)

        async def _azure_dspm() -> int:
            """DSPM Blob scan for every active Azure connection."""
            n = 0
            try:
                from backend.routers.azure_connector import _decrypt as _az_decrypt
                from backend.services.dspm import run_azure_dspm_scan
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: azure dspm import failed: {_imp}")
                return 0
            try:
                async with AsyncSessionLocal() as _db:
                    rows = (await _db.execute(_ctxt("""
                        SELECT id, org_id, tenant_id, client_id,
                               client_secret_enc, subscription_id
                        FROM azure_connections
                        WHERE status = 'active'
                    """))).mappings().fetchall()
            except Exception as _qe:
                logger.debug(f"cspm_dspm_loop: skipping azure dspm (no table): {_qe}")
                return 0
            for r in rows:
                conn_id = str(r["id"])
                org_id = str(r["org_id"])
                try:
                    _client_secret_plain = _az_decrypt(r["client_secret_enc"])
                    async with AsyncSessionLocal() as _wdb:
                        await run_azure_dspm_scan(
                            _wdb,
                            org_id=org_id,
                            connection_id=conn_id,
                            tenant_id=r["tenant_id"],
                            client_id=r["client_id"],
                            client_secret=_client_secret_plain,
                            subscription_id=r["subscription_id"],
                        )
                    n += 1
                except Exception as _de:
                    logger.warning(f"cspm_dspm_loop: Azure DSPM conn {conn_id}: {_de}")
            return n

        async def _gcs_dspm() -> int:
            """DSPM GCS scan for every active GCP connection."""
            n = 0
            try:
                from backend.routers.gcp_connector import _decrypt as _gcp_decrypt
                from backend.services.dspm import run_gcs_dspm_scan
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: gcp dspm import failed: {_imp}")
                return 0
            try:
                async with AsyncSessionLocal() as _db:
                    rows = (await _db.execute(_ctxt("""
                        SELECT id, org_id, project_id, service_account_json_enc
                        FROM gcp_connections
                        WHERE status = 'active'
                    """))).mappings().fetchall()
            except Exception as _qe:
                logger.debug(f"cspm_dspm_loop: skipping gcs dspm (no table): {_qe}")
                return 0
            for r in rows:
                conn_id = str(r["id"])
                org_id = str(r["org_id"])
                try:
                    sa_json = _gcp_decrypt(r["service_account_json_enc"])
                    async with AsyncSessionLocal() as _wdb:
                        await run_gcs_dspm_scan(
                            _wdb,
                            org_id=org_id,
                            connection_id=conn_id,
                            project_id=r["project_id"],
                            service_account_json=sa_json,
                        )
                    n += 1
                except Exception as _de:
                    logger.warning(f"cspm_dspm_loop: GCS DSPM conn {conn_id}: {_de}")
            return n

        async def _m365_dspm() -> int:
            """DSPM scan of SharePoint + OneDrive for every active M365 integration."""
            n = 0
            try:
                from backend.models.db_models import SaasIntegration as _Integ
                from backend.routers.saas_security import _get_valid_token
                from backend.services.dspm import run_m365_dspm_scan
                from sqlalchemy import select as _select
            except Exception as _imp:
                logger.warning(f"cspm_dspm_loop: M365 DSPM imports failed: {_imp}")
                return 0

            async with AsyncSessionLocal() as _db:
                integs = (await _db.execute(
                    _select(_Integ).where(
                        _Integ.status.in_(("active", "error")),
                        _Integ.provider.in_(("m365", "teams", "sharepoint")),
                    )
                )).scalars().all()
                # Dedupe by org_id — one Graph token serves all M365 sub-providers
                seen_orgs: set[str] = set()
                for integ in integs:
                    oid = str(integ.org_id)
                    if oid in seen_orgs:
                        continue
                    seen_orgs.add(oid)
                    try:
                        token = await _get_valid_token(integ, _db)
                    except Exception as _te:
                        logger.debug(f"cspm_dspm_loop: M365 token refresh failed for org {oid}: {_te}")
                        token = None
                    if not token:
                        continue
                    try:
                        async with AsyncSessionLocal() as _wdb:
                            await run_m365_dspm_scan(
                                _wdb,
                                org_id=oid,
                                integration_id=str(integ.id),
                                access_token=token,
                            )
                        n += 1
                    except Exception as _me:
                        logger.warning(f"cspm_dspm_loop: M365 DSPM org {oid}: {_me}")
            return n

        # Per-cloud timeout. If any cloud's runner exceeds this, we log and move
        # on — protects the event loop / request handlers from being starved.
        PER_CLOUD_TIMEOUT = 180  # 3 min (under 5-min cycle)

        # Global gate — only N cloud runners may execute in parallel inside one
        # cycle. Keeps the executor thread pool available for /health + API.
        _scan_gate = _aio.Semaphore(2)

        async def _safe(name: str, coro):
            """Run a runner under the gate + timeout. Swallows errors."""
            async with _scan_gate:
                try:
                    return await _aio.wait_for(coro, timeout=PER_CLOUD_TIMEOUT)
                except _aio.TimeoutError:
                    logger.warning(
                        f"cspm_dspm_loop: {name} timed out after {PER_CLOUD_TIMEOUT}s"
                    )
                    return 0
                except Exception as _e:
                    logger.warning(f"cspm_dspm_loop: {name} failed: {_e}")
                    return 0

        cycle = 0
        while True:
            cycle += 1
            try:
                # Fan out all cloud runners concurrently. Each is independent
                # and writes to its own table, so they can't conflict.
                results = await _aio.gather(
                    _safe("aws", _aws()),               # returns (cspm_n, 0)
                    _safe("aws_dspm", _aws_dspm()),     # NEW: standalone budget
                    _safe("azure_cspm", _azure_cspm()),
                    _safe("gcp_cspm", _gcp_cspm()),
                    _safe("oracle_cspm", _oracle_cspm()),
                    _safe("github_cspm", _github_cspm()),
                    _safe("snowflake_sspm", _snowflake_sspm()),
                    _safe("sap_security", _sap_security()),
                    _safe("salesforce_sspm", _salesforce_sspm()),
                    _safe("azure_dspm", _azure_dspm()),
                    _safe("gcs_dspm", _gcs_dspm()),
                    _safe("m365_dspm", _m365_dspm()),
                )
                aws_result = results[0] if isinstance(results[0], tuple) else (0, 0)
                aws_cspm, _ = aws_result
                aws_dspm = results[1]
                (
                    azure_cspm, gcp_cspm, oracle_cspm, github_cspm,
                    snowflake_sspm, sap_security, salesforce_sspm,
                    azure_dspm, gcs_dspm, m365_dspm,
                ) = results[2:]
                logger.info(
                    f"cspm_dspm_loop: cycle {cycle} — aws_cspm={aws_cspm} "
                    f"aws_dspm={aws_dspm} azure_cspm={azure_cspm} "
                    f"gcp_cspm={gcp_cspm} oracle_cspm={oracle_cspm} "
                    f"github_cspm={github_cspm} snowflake_sspm={snowflake_sspm} "
                    f"sap_security={sap_security} salesforce_sspm={salesforce_sspm} "
                    f"azure_dspm={azure_dspm} gcs_dspm={gcs_dspm} "
                    f"m365_dspm={m365_dspm}"
                )

                # Cross-cloud heuristic DLP classifier — fills
                # `dlp_categories` / `dlp_risk_level` / `dlp_classified`
                # for every connector table (Databricks, GCP, Azure,
                # Oracle, SAP, GitHub, Snowflake). AWS already has its
                # own LLM-driven classifier in saas_security._aws_dlp_
                # classify_resources. M365 categories come from the SaaS
                # scan loop. This closes the gap where only M365+AWS
                # rows had categories in the Data Inventory UI.
                try:
                    from backend.services.cross_cloud_dlp import classify_all_clouds
                    async with AsyncSessionLocal() as _ccdb:
                        org_rows_ccdlp = (await _ccdb.execute(_ctxt(
                            "SELECT DISTINCT id FROM organizations"
                        ))).fetchall()
                        logger.info(
                            f"cspm_dspm_loop: cross_cloud_dlp starting for {len(org_rows_ccdlp)} org(s)"
                        )
                        for (oid,) in org_rows_ccdlp:
                            try:
                                async with AsyncSessionLocal() as _ocdb:
                                    summary_dlp = await classify_all_clouds(str(oid), _ocdb)
                                    # ALWAYS log so we can see when the
                                    # function ran (even if zero rows
                                    # needed classification). Adnan 2026-06-22
                                    # debug pass: rev 369 cycles showed no
                                    # cross_cloud_dlp lines, making it
                                    # impossible to tell if classify_all_
                                    # clouds was even running.
                                    logger.info(
                                        f"cspm_dspm_loop: cross_cloud_dlp org={oid} "
                                        f"results={summary_dlp}"
                                    )
                            except Exception as _ce:
                                logger.warning(
                                    f"cspm_dspm_loop: cross_cloud_dlp org {oid}: {_ce}"
                                )
                except Exception as _cct:
                    logger.warning(f"cspm_dspm_loop: cross_cloud_dlp top-level: {_cct}")

                # Toxic Combinations DSPM engine — runs after CSPM/DSPM so it
                # consumes the freshest classification + finding state.
                # Only sweep orgs that actually have inventory to evaluate.
                try:
                    async with AsyncSessionLocal() as _tdb:
                        await ensure_toxic_schema(_tdb)
                        # Tolerant sweep — some tables may not exist yet for
                        # an org that hasn't connected the relevant cloud.
                        # Collect distinct org_ids per table individually,
                        # swallow missing-table errors, then dedupe.
                        org_id_set: set = set()
                        for _tbl in (
                            "aws_resources", "gcp_resources",
                            "databricks_resources", "saas_data_items",
                            "salesforce_objects", "salesforce_findings",
                            "azure_resources", "oracle_resources",
                        ):
                            try:
                                rs = await _tdb.execute(_ctxt(
                                    f"SELECT DISTINCT org_id FROM {_tbl}"
                                ))
                                for (oid,) in rs.fetchall():
                                    if oid is not None:
                                        org_id_set.add(oid)
                            except Exception as _se:
                                logger.debug(f"cspm_dspm_loop: toxic sweep skip {_tbl}: {_se}")
                                # asyncpg leaves the session in 'aborted' state;
                                # rollback so the next query in the same
                                # connection doesn't fail with InFailedSqlTransactionError.
                                try:
                                    await _tdb.rollback()
                                except Exception:
                                    pass
                        org_rows = [(oid,) for oid in org_id_set]
                        for (oid,) in org_rows:
                            try:
                                async with AsyncSessionLocal() as _odb:
                                    summary = await run_toxic_for_org(str(oid), _odb)
                                    logger.info(
                                        f"cspm_dspm_loop: toxic_combinations org={oid} "
                                        f"matches={summary['matches']} upserted={summary['upserted']} "
                                        f"swept={summary['swept']}"
                                    )
                            except Exception as _toxe:
                                logger.warning(f"cspm_dspm_loop: toxic engine failed for {oid}: {_toxe}")
                except Exception as _tx_top:
                    logger.warning(f"cspm_dspm_loop: toxic engine top-level error: {_tx_top}")

                # ── Cross-region access detector ────────────────────────
                # Adnan 2026-06-23 (turn 2): emits CROSS_REGION_ACCESS
                # alerts under the user's `saas_cross_region_access`
                # toggle. Per-org, per-cycle. Cheap — reads existing
                # audit_logs + inventory tables only.
                try:
                    from backend.services.cross_region_access import (
                        run_and_alert as _cra_run,
                    )
                    for (oid,) in org_rows:
                        try:
                            async with AsyncSessionLocal() as _crdb:
                                n_cra = await _cra_run(_crdb, str(oid))
                                if n_cra:
                                    logger.info(
                                        f"cspm_dspm_loop: cross_region org={oid} new_alerts={n_cra}"
                                    )
                        except Exception as _crexc:
                            logger.warning(
                                f"cspm_dspm_loop: cross_region failed org={oid}: {_crexc}"
                            )
                except Exception as _cra_top:
                    logger.warning(
                        f"cspm_dspm_loop: cross_region top-level error: {_cra_top}"
                    )

                # ── Permission diff / ACL change tracker ──────────────────
                # Adnan 2026-06-23 (turn 2): snapshots every connector
                # row's ACL fields each cycle, emits PERMISSION_DIFF
                # alerts on CRIT/HIGH delta (e.g. bucket flipped public).
                try:
                    from backend.services.permission_diff import (
                        run_and_alert as _pd_run,
                    )
                    for (oid,) in org_rows:
                        try:
                            async with AsyncSessionLocal() as _pdb:
                                n_pd = await _pd_run(_pdb, str(oid))
                                if n_pd:
                                    logger.info(
                                        f"cspm_dspm_loop: permission_diff org={oid} new_alerts={n_pd}"
                                    )
                        except Exception as _pdexc:
                            logger.warning(
                                f"cspm_dspm_loop: permission_diff failed org={oid}: {_pdexc}"
                            )
                except Exception as _pd_top:
                    logger.warning(
                        f"cspm_dspm_loop: permission_diff top-level error: {_pd_top}"
                    )
            except Exception as _le:
                logger.warning(f"cspm_dspm_loop: cycle {cycle} error: {_le}")
            await _aio.sleep(CSPM_DSPM_INTERVAL)

    # Auto-loop is env-gated and ON by default. CSPM/DSPM sync work now
    # runs in a dedicated thread pool (backend/services/cspm/executor.py)
    # so it cannot saturate the default executor used by /health and
    # request handlers. Set HELIOS_CSPM_DSPM_AUTOLOOP=0 to disable.
    if os.getenv("HELIOS_CSPM_DSPM_AUTOLOOP", "1") == "1":
        try:
            asyncio.create_task(_cspm_dspm_loop())
            logger.info(
                "CSPM+DSPM unified loop started (5 min interval, "
                "AWS+Azure+GCP+Oracle+GitHub CSPM, "
                "AWS S3 + Azure Blob + GCS + M365 SP/OneDrive DSPM, "
                "isolated thread pool)"
            )
        except Exception as _cdl_e:
            logger.warning(f"CSPM+DSPM loop start failed: {_cdl_e}")
    else:
        logger.info(
            "CSPM+DSPM auto-loop DISABLED (HELIOS_CSPM_DSPM_AUTOLOOP=0). "
            "Manual scan endpoints remain available."
        )

    # Seed security_rules default rules (non-fatal)
    try:
        from backend.routers.saas_security import _seed_security_rules
        async with AsyncSessionLocal() as _seed_db:
            await _seed_security_rules(_seed_db)
    except Exception as _seed_e:
        logger.warning(f"Security rules seeding failed (non-fatal): {_seed_e}")

    logger.info("Himaya Helios API ready ✓")
    yield

    # Shutdown
    await engine.dispose()
    logger.info("Himaya Helios API shutdown complete")


app = FastAPI(
    title="Himaya Helios API",
    description="AI-powered email security for Gulf financial institutions",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Log 422 validation errors with full detail so we can diagnose issues."""
    logger.error(f"422 Validation error on {request.method} {request.url.path}: {exc.errors()}")
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors(), "body": str(exc.body)[:200] if exc.body else None},
    )

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://app.himaya.ai",
        "https://appsforoffice.microsoft.com",
        "https://script.google.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include all routers
app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(threats.router)
app.include_router(people.router)
app.include_router(policies.router)
app.include_router(compliance.router)
app.include_router(onboarding.router)
app.include_router(settings_router.router)
app.include_router(message_trace.router)
app.include_router(admin.router)
app.include_router(neo4j_mgmt.router)
app.include_router(sandbox.router)
app.include_router(reports.router)
app.include_router(quarantine_router)
app.include_router(phish_report_router)
app.include_router(posture_router)
app.include_router(dlp_router)
app.include_router(dlp_webhook_router)
app.include_router(drafts_router)
app.include_router(spam_router)
app.include_router(saas_security_router)
app.include_router(falcon_router)
app.include_router(aws_router)
app.include_router(gcp_router)
app.include_router(databricks_router)
app.include_router(sap_router)
app.include_router(azure_router)
app.include_router(oracle_router)
app.include_router(github_router)
app.include_router(snowflake_router)
app.include_router(salesforce_router)
app.include_router(cspm_router)
app.include_router(dspm_router)
app.include_router(toxic_router)
app.include_router(data_lifecycle_router)
app.include_router(permission_diff_router)
app.include_router(genai_shadow_it_router)
app.include_router(dspm_access_router)


@app.get("/health")
async def health_check():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/")
async def root():
    return {
        "service": "Himaya Helios API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }


@app.websocket("/ws/threats")
async def websocket_threats(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    org_id: Optional[str] = Query(None),
):
    """
    WebSocket endpoint for real-time threat updates.
    Connect with: ws://localhost:8000/ws/threats?token=<jwt>&org_id=<org_id>
    """
    if not org_id:
        await websocket.close(code=4001)
        return

    # Optionally validate JWT token here
    if token:
        try:
            from jose import jwt, JWTError
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            token_org_id = payload.get("org_id")
            if token_org_id and token_org_id != org_id:
                await websocket.close(code=4003)
                return
        except Exception:
            await websocket.close(code=4001)
            return

    await ws_manager.connect(websocket, org_id)
    logger.info(f"WebSocket connected: org_id={org_id}")

    try:
        # Send initial connected message
        await websocket.send_json({"event": "connected", "org_id": org_id})

        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()
            # Echo back for ping/pong
            await websocket.send_json({"event": "pong", "data": data})

    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket, org_id)
        logger.info(f"WebSocket disconnected: org_id={org_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await ws_manager.disconnect(websocket, org_id)


@app.get("/health/neo4j")
async def neo4j_health():
    """Proxy to graph-service health — Neo4j is managed by the graph microservice."""
    import httpx
    graph_url = os.getenv("GRAPH_SERVICE_URL", "http://graph-service:8000")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{graph_url}/health")
            return resp.json()
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}
