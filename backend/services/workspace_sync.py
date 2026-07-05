"""
Workspace Sync — Background worker for SaaS Security connectors (AWS, GCP, Databricks, SAP).
Runs periodic scans and aggregates data from all connected cloud/SaaS platforms.
"""
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import AsyncSessionLocal

logger = logging.getLogger(__name__)

# Scan intervals
# Cadence tightened 2026-06-13: customers want near-real-time delta
# visibility (≤1 min for cheap reads). AWS/GCP scan_all is expensive
# (multi-region API calls + boto3 paginators) so we keep their slow
# scans at 5 min, but light-weight delta paths run more frequently
# via the parallel auto-scan loop in main.py (2 min interval, tightened
# below) and the SaaS delta_sync loop (already 1 min).
AWS_SCAN_INTERVAL_SECONDS = 300        # full sweep — every 5 min
GCP_SCAN_INTERVAL_SECONDS = 300        # full sweep — every 5 min
DATABRICKS_SCAN_INTERVAL_SECONDS = 300  # tightened from 10 min
SAP_SCAN_INTERVAL_SECONDS = 300         # tightened from 10 min


async def run_workspace_sync_loop():
    """Long-running background task: scan all connected cloud workspaces."""
    logger.info("Workspace sync loop started")
    cycle = 0
    while True:
        cycle += 1
        try:
            if cycle % 12 == 1:  # Log every hour (12 * 5 min)
                logger.info(f"Workspace sync heartbeat: cycle {cycle}")
            await _sync_all_workspaces()
        except asyncio.CancelledError:
            logger.warning("Workspace sync loop cancelled")
            raise
        except Exception as e:
            logger.error(f"Workspace sync error (cycle {cycle}): {e}", exc_info=True)
        try:
            await asyncio.sleep(AWS_SCAN_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logger.warning("Workspace sync loop cancelled during sleep")
            raise


async def _sync_all_workspaces():
    """Scan all connected workspaces across all orgs."""
    async with AsyncSessionLocal() as db:
        # Get all orgs with any cloud connections
        orgs = await _get_orgs_with_connections(db)
        
        for org_id in orgs:
            try:
                await _sync_org_workspaces(db, org_id)
            except Exception as e:
                logger.error(f"Workspace sync failed for org {org_id}: {e}", exc_info=True)


async def _get_orgs_with_connections(db: AsyncSession) -> list[str]:
    """Get all org IDs that have at least one active connection."""
    org_ids = set()
    
    # Check AWS connections
    try:
        result = await db.execute(text(
            "SELECT DISTINCT org_id FROM aws_connections WHERE status = 'active'"
        ))
        for row in result:
            org_ids.add(str(row[0]))
    except Exception:
        pass  # Table may not exist
    
    # Check GCP connections
    try:
        result = await db.execute(text(
            "SELECT DISTINCT org_id FROM gcp_connections WHERE status = 'active'"
        ))
        for row in result:
            org_ids.add(str(row[0]))
    except Exception:
        pass
    
    # Check Databricks connections
    try:
        result = await db.execute(text(
            "SELECT DISTINCT org_id FROM databricks_connections WHERE status = 'active'"
        ))
        for row in result:
            org_ids.add(str(row[0]))
    except Exception:
        pass
    
    # Check SAP connections
    try:
        result = await db.execute(text(
            "SELECT DISTINCT org_id FROM sap_connections WHERE status = 'active'"
        ))
        for row in result:
            org_ids.add(str(row[0]))
    except Exception:
        pass
    
    return list(org_ids)


async def _sync_org_workspaces(db: AsyncSession, org_id: str):
    """Sync all workspaces for a single org."""
    # AWS
    await _sync_aws_connections(db, org_id)
    # GCP
    await _sync_gcp_connections(db, org_id)
    # Databricks
    await _sync_databricks_connections(db, org_id)
    # SAP
    await _sync_sap_connections(db, org_id)


async def _sync_aws_connections(db: AsyncSession, org_id: str):
    """Sync all AWS connections for an org."""
    try:
        from backend.services.aws_security_service import AWSSecurityService
        from backend.routers.aws_connector import _decrypt
        
        result = await db.execute(text("""
            SELECT id, access_key_id_enc, secret_access_key_enc, default_region, scan_regions, last_scan_at
            FROM aws_connections
            WHERE org_id = :org_id AND status = 'active'
        """), {"org_id": org_id})
        
        for row in result.mappings():
            # Skip if scanned recently (within interval)
            last_scan = row["last_scan_at"]
            if last_scan:
                since_scan = (datetime.now(timezone.utc) - last_scan.replace(tzinfo=timezone.utc)).total_seconds()
                if since_scan < AWS_SCAN_INTERVAL_SECONDS:
                    continue
            
            connection_id = str(row["id"])
            logger.info(f"AWS background scan starting for connection {connection_id}")
            
            try:
                access_key = _decrypt(row["access_key_id_enc"])
                secret_key = _decrypt(row["secret_access_key_enc"])
                regions = row["scan_regions"] or [row["default_region"]]
                
                service = AWSSecurityService(
                    access_key_id=access_key,
                    secret_access_key=secret_key,
                    region=row["default_region"],
                )
                
                # Capture scan start so we can prune resources/findings
                # that AWS no longer reports after this scan. Anything
                # whose scanned_at is older than scan_start_ts after the
                # upsert pass is treated as gone in AWS and removed from
                # the dashboard (incl. the data residency map).
                scan_start_ts = datetime.now(timezone.utc)
                scan_result = await service.scan_all(regions=regions)

                # Store resources
                for resource in scan_result.get("resources", []):
                    # JSON-serialize tags and metadata for asyncpg JSONB columns
                    tags_json = json.dumps(resource.get("tags") or {})
                    meta_json = json.dumps(resource.get("metadata") or {})
                    
                    await db.execute(text("""
                        INSERT INTO aws_resources
                            (org_id, connection_id, resource_type, resource_id, resource_arn,
                             name, region, size_bytes, encryption_enabled, encryption_type, 
                             public_access, tags, metadata, scanned_at)
                        VALUES
                            (:org_id, :conn_id, :rtype, :rid, :arn, :name, :region, :size,
                             :enc, :enc_type, :public, CAST(:tags AS jsonb), CAST(:meta AS jsonb), NOW())
                        ON CONFLICT (org_id, resource_arn) DO UPDATE SET
                            name = EXCLUDED.name,
                            size_bytes = EXCLUDED.size_bytes,
                            encryption_enabled = EXCLUDED.encryption_enabled,
                            encryption_type = EXCLUDED.encryption_type,
                            public_access = EXCLUDED.public_access,
                            tags = EXCLUDED.tags,
                            -- Preserve DLP/AI classification keys the DLP
                            -- worker writes between sweeps. Same merge
                            -- pattern as aws_connector.py line ~598
                            -- (rev 361 fix). Without this every workspace
                            -- sync wipes dlp_categories / dlp_risk_level
                            -- and the Data Inventory Categories column
                            -- flashes empty until the classifier catches
                            -- back up (~5–10 min).
                            metadata = EXCLUDED.metadata || COALESCE(
                                (SELECT jsonb_object_agg(key, value)
                                 FROM jsonb_each(aws_resources.metadata)
                                 WHERE key IN ('dlp_classified','dlp_categories',
                                               'dlp_risk_level','dlp_schema_version',
                                               'ai_categories')),
                                '{}'::jsonb
                            ),
                            scanned_at = NOW()
                    """), {
                        "org_id": org_id,
                        "conn_id": connection_id,
                        "rtype": resource.get("resource_type"),
                        "rid": resource.get("resource_id"),
                        "arn": resource.get("resource_arn"),
                        "name": resource.get("name"),
                        "region": resource.get("region"),
                        "size": resource.get("size_bytes"),
                        "enc": resource.get("encryption_enabled", False),
                        "enc_type": resource.get("encryption_type"),
                        "public": resource.get("public_access", False),
                        "tags": tags_json,
                        "meta": meta_json,
                    })
                
                # Store findings
                for finding in scan_result.get("findings", []):
                    # JSON-serialize metadata for asyncpg JSONB column
                    finding_meta_json = json.dumps(finding.get("metadata") or {})
                    
                    await db.execute(text("""
                        INSERT INTO aws_findings
                            (org_id, connection_id, finding_id, severity, category,
                             resource_type, resource_id, resource_arn, title, description,
                             recommendation, status, detected_at, metadata)
                        VALUES
                            (:org_id, :conn_id, :fid, :sev, :cat, :rtype, :rid, :arn,
                             :title, :desc, :rec, 'open', NOW(), CAST(:meta AS jsonb))
                        ON CONFLICT (org_id, finding_id) DO UPDATE SET
                            severity = EXCLUDED.severity,
                            title = EXCLUDED.title,
                            description = EXCLUDED.description,
                            recommendation = EXCLUDED.recommendation,
                            metadata = EXCLUDED.metadata
                    """), {
                        "org_id": org_id,
                        "conn_id": connection_id,
                        "fid": finding.get("finding_id"),
                        "sev": finding.get("severity"),
                        "cat": finding.get("category"),
                        "rtype": finding.get("resource_type"),
                        "rid": finding.get("resource_id"),
                        "arn": finding.get("resource_arn"),
                        "title": finding.get("title"),
                        "desc": finding.get("description"),
                        "rec": finding.get("recommendation"),
                        "meta": finding_meta_json,
                    })
                
                # Prune resources/findings that the scan no longer reports.
                #
                # SAFETY GUARDS (added 2026-06-12 after prod regression where
                # ~55 rows were deleted on every cycle and AWS data inventory
                # disappeared mid-customer-demo):
                #
                # 1. Only prune when this scan actually returned resources.
                #    A 0-resource scan_result almost always means a partial
                #    AWS failure (rate limit, region timeout, IAM perms gap)
                #    — pruning in that case wipes the whole tenant view.
                # 2. Only delete rows older than a generous grace window
                #    (PRUNE_GRACE_HOURS). A parallel scan loop in main.py
                #    upserts the same connection every 5 minutes; using
                #    scan_start_ts as the threshold races with that loop
                #    because workspace_sync's scan_all can take 20+ minutes
                #    sweeping all regions, so its scan_start_ts is far
                #    older than the upsert timestamps from main.py's faster
                #    loop. Anything > grace hours stale is genuinely gone.
                # 3. Tenant isolation preserved: still scoped by
                #    (org_id, connection_id) — never crosses orgs.
                PRUNE_GRACE_HOURS = 6
                resources_seen = len(scan_result.get("resources", []))
                pruned = 0
                if resources_seen > 0:
                    stale_resources = await db.execute(text("""
                        DELETE FROM aws_resources
                         WHERE org_id        = CAST(:org_id AS UUID)
                           AND connection_id = CAST(:cid    AS UUID)
                           AND scanned_at    < (NOW() - (:grace_hours || ' hours')::interval)
                    """), {
                        "org_id": org_id,
                        "cid": connection_id,
                        "grace_hours": str(PRUNE_GRACE_HOURS),
                    })
                    pruned = stale_resources.rowcount if stale_resources.rowcount is not None else 0

                    # Auto-close findings tied to deleted ARNs.
                    try:
                        await db.execute(text("""
                            UPDATE aws_findings
                               SET status = 'resolved'
                             WHERE org_id        = CAST(:org_id AS UUID)
                               AND connection_id = CAST(:cid    AS UUID)
                               AND status        = 'open'
                               AND NOT EXISTS (
                                     SELECT 1 FROM aws_resources r
                                      WHERE r.org_id        = aws_findings.org_id
                                        AND r.resource_arn = aws_findings.resource_arn
                               )
                        """), {"org_id": org_id, "cid": connection_id})
                    except Exception as _fe:
                        logger.debug(f"AWS findings auto-close skipped: {_fe}")
                else:
                    logger.warning(
                        f"AWS prune skipped for {connection_id}: scan returned 0 "
                        f"resources (likely partial failure). Not deleting anything."
                    )

                # Update last_scan_at
                await db.execute(text("""
                    UPDATE aws_connections SET last_scan_at = NOW() WHERE id = :id
                """), {"id": connection_id})

                await db.commit()
                logger.info(
                    f"AWS scan complete for {connection_id}: "
                    f"{len(scan_result.get('resources', []))} resources, "
                    f"{len(scan_result.get('findings', []))} findings, "
                    f"{pruned} stale rows pruned (grace=6h)"
                )
                
            except Exception as e:
                logger.error(f"AWS scan failed for connection {connection_id}: {e}", exc_info=True)
                await db.rollback()
                
    except Exception as e:
        logger.debug(f"AWS sync skipped (table may not exist): {e}")


async def _sync_gcp_connections(db: AsyncSession, org_id: str):
    """Sync all GCP connections for an org."""
    try:
        from backend.services.gcp_security_service import GCPSecurityService
        from backend.routers.gcp_connector import _decrypt
        
        result = await db.execute(text("""
            SELECT id, credentials_enc, project_id, last_scan_at
            FROM gcp_connections
            WHERE org_id = :org_id AND status = 'active'
        """), {"org_id": org_id})
        
        for row in result.mappings():
            last_scan = row["last_scan_at"]
            if last_scan:
                since_scan = (datetime.now(timezone.utc) - last_scan.replace(tzinfo=timezone.utc)).total_seconds()
                if since_scan < GCP_SCAN_INTERVAL_SECONDS:
                    continue
            
            connection_id = str(row["id"])
            logger.info(f"GCP background scan starting for connection {connection_id}")
            
            try:
                import json
                creds_json = json.loads(_decrypt(row["credentials_enc"]))
                
                service = GCPSecurityService(credentials=creds_json, project_id=row["project_id"])
                scan_result = await service.scan_all()
                
                # Store resources
                for resource in scan_result.get("resources", []):
                    await db.execute(text("""
                        INSERT INTO gcp_resources
                            (org_id, connection_id, resource_type, resource_id, name,
                             location, size_bytes, public_access, encryption, labels,
                             metadata, scanned_at)
                        VALUES
                            (:org_id, :conn_id, :rtype, :rid, :name, :loc, :size,
                             :public, :enc, :labels, :meta, NOW())
                        ON CONFLICT (org_id, resource_id) DO UPDATE SET
                            name = EXCLUDED.name,
                            size_bytes = EXCLUDED.size_bytes,
                            public_access = EXCLUDED.public_access,
                            encryption = EXCLUDED.encryption,
                            labels = EXCLUDED.labels,
                            -- Preserve DLP keys written by cross_cloud_dlp
                            -- between sweeps. Without this the GCP
                            -- branch loses its labels on every cycle.
                            metadata = EXCLUDED.metadata || COALESCE(
                                (SELECT jsonb_object_agg(key, value)
                                 FROM jsonb_each(gcp_resources.metadata)
                                 WHERE key IN ('dlp_classified','dlp_categories',
                                               'dlp_risk_level','dlp_schema_version',
                                               'ai_categories')),
                                '{}'::jsonb
                            ),
                            scanned_at = NOW()
                    """), {
                        "org_id": org_id,
                        "conn_id": connection_id,
                        "rtype": resource.get("resource_type"),
                        "rid": resource.get("resource_id"),
                        "name": resource.get("name"),
                        "loc": resource.get("location"),
                        "size": resource.get("size_bytes"),
                        "public": resource.get("public_access", False),
                        "enc": resource.get("encryption"),
                        "labels": resource.get("labels"),
                        "meta": resource.get("metadata"),
                    })
                
                # Store findings
                for finding in scan_result.get("findings", []):
                    await db.execute(text("""
                        INSERT INTO gcp_findings
                            (org_id, connection_id, finding_id, severity, category,
                             resource_type, resource_id, title, description,
                             recommendation, status, detected_at, metadata)
                        VALUES
                            (:org_id, :conn_id, :fid, :sev, :cat, :rtype, :rid,
                             :title, :desc, :rec, 'open', NOW(), :meta)
                        ON CONFLICT (org_id, finding_id) DO UPDATE SET
                            severity = EXCLUDED.severity,
                            title = EXCLUDED.title,
                            description = EXCLUDED.description,
                            metadata = EXCLUDED.metadata
                    """), {
                        "org_id": org_id,
                        "conn_id": connection_id,
                        "fid": finding.get("finding_id"),
                        "sev": finding.get("severity"),
                        "cat": finding.get("category"),
                        "rtype": finding.get("resource_type"),
                        "rid": finding.get("resource_id"),
                        "title": finding.get("title"),
                        "desc": finding.get("description"),
                        "rec": finding.get("recommendation"),
                        "meta": finding.get("metadata"),
                    })
                
                await db.execute(text("""
                    UPDATE gcp_connections SET last_scan_at = NOW() WHERE id = :id
                """), {"id": connection_id})
                
                await db.commit()
                logger.info(f"GCP scan complete for {connection_id}")
                
            except Exception as e:
                logger.error(f"GCP scan failed for connection {connection_id}: {e}", exc_info=True)
                await db.rollback()
                
    except Exception as e:
        logger.debug(f"GCP sync skipped: {e}")


async def _sync_databricks_connections(db: AsyncSession, org_id: str):
    """Sync all Databricks connections for an org."""
    try:
        from backend.services.databricks_security_service import DatabricksSecurityService
        from backend.routers.databricks_connector import _decrypt
        
        result = await db.execute(text("""
            SELECT id, workspace_url, access_token_enc, last_scan_at
            FROM databricks_connections
            WHERE org_id = :org_id AND status = 'active'
        """), {"org_id": org_id})
        
        for row in result.mappings():
            last_scan = row["last_scan_at"]
            if last_scan:
                since_scan = (datetime.now(timezone.utc) - last_scan.replace(tzinfo=timezone.utc)).total_seconds()
                if since_scan < DATABRICKS_SCAN_INTERVAL_SECONDS:
                    continue
            
            connection_id = str(row["id"])
            logger.info(f"Databricks background scan starting for connection {connection_id}")
            
            try:
                token = _decrypt(row["access_token_enc"])
                
                service = DatabricksSecurityService(
                    workspace_url=row["workspace_url"],
                    access_token=token,
                )
                scan_result = await service.scan_all()
                
                # Store resources (notebooks, clusters, secrets)
                for resource in scan_result.get("resources", []):
                    await db.execute(text("""
                        INSERT INTO databricks_resources
                            (org_id, connection_id, resource_type, resource_id, name, path, metadata, scanned_at)
                        VALUES (:org_id, :conn_id, :rtype, :rid, :name, :path, :meta, NOW())
                        ON CONFLICT (connection_id, resource_type, resource_id) DO UPDATE SET
                            name = EXCLUDED.name,
                            path = EXCLUDED.path,
                            -- Preserve DLP keys written by the classifier between scans.
                            metadata = EXCLUDED.metadata || COALESCE(
                                (SELECT jsonb_object_agg(key, value)
                                 FROM jsonb_each(databricks_resources.metadata)
                                 WHERE key IN ('dlp_classified','dlp_categories',
                                               'dlp_risk_level','dlp_schema_version',
                                               'ai_categories')),
                                '{}'::jsonb
                            ),
                            scanned_at = NOW()
                    """), {
                        "org_id": org_id,
                        "conn_id": connection_id,
                        "rtype": resource.get("type", "unknown"),
                        "rid": resource.get("id", ""),
                        "name": resource.get("name", ""),
                        "path": resource.get("path", ""),
                        "meta": json.dumps(resource.get("metadata") or {}),
                    })
                
                # Store findings
                for finding in scan_result.get("findings", []):
                    await db.execute(text("""
                        INSERT INTO databricks_findings
                            (org_id, connection_id, finding_type, severity, title, description, resource_id, metadata, detected_at)
                        VALUES (:org_id, :conn_id, :ftype, :sev, :title, :desc, :rid, :meta, NOW())
                        ON CONFLICT DO NOTHING
                    """), {
                        "org_id": org_id,
                        "conn_id": connection_id,
                        "ftype": finding.get("type", "unknown"),
                        "sev": finding.get("severity", "medium"),
                        "title": finding.get("title", ""),
                        "desc": finding.get("description", ""),
                        "rid": finding.get("resource_id", ""),
                        "meta": json.dumps(finding.get("metadata") or {}),
                    })
                
                await db.execute(text("""
                    UPDATE databricks_connections SET last_scan_at = NOW() WHERE id = :id
                """), {"id": connection_id})
                
                await db.commit()
                logger.info(f"Databricks scan complete for {connection_id}: {len(scan_result.get('resources', []))} resources, {len(scan_result.get('findings', []))} findings")
                
            except Exception as e:
                logger.error(f"Databricks scan failed for connection {connection_id}: {e}", exc_info=True)
                await db.rollback()
                
    except Exception as e:
        logger.debug(f"Databricks sync skipped: {e}")


async def _sync_sap_connections(db: AsyncSession, org_id: str):
    """Sync all SAP connections for an org."""
    try:
        from backend.services.sap_security_service import SAPSecurityService
        from backend.routers.sap_connector import _decrypt
        
        result = await db.execute(text("""
            SELECT id, host, username_enc, password_enc, client, sysnr, last_scan_at
            FROM sap_connections
            WHERE org_id = :org_id AND status = 'active'
        """), {"org_id": org_id})
        
        for row in result.mappings():
            last_scan = row["last_scan_at"]
            if last_scan:
                since_scan = (datetime.now(timezone.utc) - last_scan.replace(tzinfo=timezone.utc)).total_seconds()
                if since_scan < SAP_SCAN_INTERVAL_SECONDS:
                    continue
            
            connection_id = str(row["id"])
            logger.info(f"SAP background scan starting for connection {connection_id}")
            
            try:
                username = _decrypt(row["username_enc"])
                password = _decrypt(row["password_enc"])
                
                service = SAPSecurityService(
                    host=row["host"],
                    username=username,
                    password=password,
                    client=row["client"],
                    sysnr=row["sysnr"],
                )
                scan_result = await service.scan_all()
                
                await db.execute(text("""
                    UPDATE sap_connections SET last_scan_at = NOW() WHERE id = :id
                """), {"id": connection_id})
                
                await db.commit()
                logger.info(f"SAP scan complete for {connection_id}")
                
            except Exception as e:
                logger.error(f"SAP scan failed for connection {connection_id}: {e}", exc_info=True)
                await db.rollback()
                
    except Exception as e:
        logger.debug(f"SAP sync skipped: {e}")


# ── Aggregated Stats Endpoint Support ──────────────────────────────────────────

async def get_workspace_stats(db: AsyncSession, org_id: str) -> dict:
    """Get aggregated stats from all connected cloud/SaaS platforms."""
    stats = {
        "total_resources": 0,
        "total_findings": 0,
        "critical_findings": 0,
        "high_findings": 0,
        "medium_findings": 0,
        "low_findings": 0,
        "by_provider": {},
        "by_resource_type": {},
        "data_regions": [],
        "connections": {
            "aws": 0,
            "gcp": 0,
            "databricks": 0,
            "sap": 0,
            "m365": 0,
            "google": 0,
        },
        "recent_findings": [],
    }
    
    # Per-provider cloud stats.
    # A provider is surfaced in by_provider ONLY when it is actually connected
    # (>=1 active connection) OR has inventoried resources. This prevents a
    # provider the customer never connected (e.g. GCP) from appearing as an
    # empty "0 resources / 0 findings" card, and ensures every connected cloud
    # (AWS/GCP/Azure/Oracle/Databricks) shows up — the previous code only ever
    # queried AWS + GCP and added them unconditionally, so Azure/Oracle/
    # Databricks resources were invisible in the funnel + data inventory.
    #   (provider, conn_table, resource_table, findings_table, region_col)
    _PROVIDER_TABLES = [
        ("aws", "aws_connections", "aws_resources", "aws_findings", "region"),
        ("gcp", "gcp_connections", "gcp_resources", "gcp_findings", "location"),
        ("azure", "azure_connections", "azure_resources", "azure_findings", "region"),
        ("oracle", "oracle_connections", "oracle_resources", "oracle_findings", "region"),
        ("databricks", "databricks_connections", "databricks_resources", "databricks_findings", "region"),
    ]
    for prov, conn_tbl, res_tbl, find_tbl, region_col in _PROVIDER_TABLES:
        try:
            conn_n = (await db.execute(
                text(f"SELECT COUNT(*) FROM {conn_tbl} WHERE org_id = :org_id AND status = 'active'"),
                {"org_id": org_id},
            )).scalar() or 0
            stats["connections"][prov] = conn_n

            res_n = (await db.execute(
                text(f"SELECT COUNT(*) FROM {res_tbl} WHERE org_id = :org_id"),
                {"org_id": org_id},
            )).scalar() or 0

            # Not connected and no data → do not surface this provider at all.
            if conn_n == 0 and res_n == 0:
                continue

            stats["total_resources"] += res_n
            stats["by_provider"][prov] = {"resources": res_n, "findings": 0}

            # Open findings by severity (best-effort — table may not exist for
            # every provider on older deployments).
            try:
                fr = await db.execute(
                    text(f"SELECT severity, COUNT(*) as count FROM {find_tbl} "
                         f"WHERE org_id = :org_id AND status = 'open' GROUP BY severity"),
                    {"org_id": org_id},
                )
                for row in fr.mappings():
                    sev = row["severity"].lower() if row["severity"] else "low"
                    count = row["count"]
                    stats["total_findings"] += count
                    stats["by_provider"][prov]["findings"] += count
                    if sev == "critical":
                        stats["critical_findings"] += count
                    elif sev == "high":
                        stats["high_findings"] += count
                    elif sev == "medium":
                        stats["medium_findings"] += count
                    else:
                        stats["low_findings"] += count
            except Exception as _fe:
                logger.debug(f"{prov} findings query skipped: {_fe}")

            # Data-residency regions (best-effort — column name varies).
            try:
                rr = await db.execute(
                    text(f"SELECT DISTINCT {region_col} FROM {res_tbl} "
                         f"WHERE org_id = :org_id AND {region_col} IS NOT NULL"),
                    {"org_id": org_id},
                )
                for row in rr:
                    if row[0]:
                        stats["data_regions"].append({"provider": prov, "region": row[0]})
            except Exception as _re:
                logger.debug(f"{prov} regions query skipped: {_re}")

        except Exception as e:
            logger.debug(f"{prov} stats error: {e}")
    
    # M365/Google stats from org_integrations
    try:
        result = await db.execute(text("""
            SELECT provider, COUNT(*) as count FROM org_integrations 
            WHERE org_id = :org_id AND status = 'active'
            GROUP BY provider
        """), {"org_id": org_id})
        for row in result.mappings():
            provider = row["provider"]
            if provider == "m365":
                stats["connections"]["m365"] = row["count"]
            elif provider == "google":
                stats["connections"]["google"] = row["count"]
    except Exception as e:
        logger.debug(f"Org integrations stats error: {e}")
    
    # Recent findings (combined)
    try:
        findings = []
        
        # AWS findings
        result = await db.execute(text("""
            SELECT finding_id, severity, title, category, detected_at, 'aws' as provider
            FROM aws_findings
            WHERE org_id = :org_id AND status = 'open'
            ORDER BY detected_at DESC
            LIMIT 10
        """), {"org_id": org_id})
        for row in result.mappings():
            findings.append(dict(row))
        
        # GCP findings
        result = await db.execute(text("""
            SELECT finding_id, severity, title, category, detected_at, 'gcp' as provider
            FROM gcp_findings
            WHERE org_id = :org_id AND status = 'open'
            ORDER BY detected_at DESC
            LIMIT 10
        """), {"org_id": org_id})
        for row in result.mappings():
            findings.append(dict(row))
        
        # Sort by detected_at and take top 10
        findings.sort(key=lambda x: x.get("detected_at") or "", reverse=True)
        stats["recent_findings"] = findings[:10]
        
    except Exception as e:
        logger.debug(f"Recent findings error: {e}")
    
    return stats
