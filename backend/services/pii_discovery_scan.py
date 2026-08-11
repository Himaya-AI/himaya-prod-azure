"""
PII discovery — persistence + per-source scanners.

Builds on `pii_discovery.classify_column` to:
  1. Ensure the `column_classifications` lineage table.
  2. Run REAL per-column sampling against Snowflake (INFORMATION_SCHEMA + sampled
     SELECTs) and classify each column with confidence + redacted evidence.
  3. Classify SAP via the documented data-dictionary catalog (well-known PII/HR
     tables) — honest name/metadata-level classification since the SAP connector
     does not execute row queries.
  4. Mirror every sensitive column into `dspm_findings` so the sovereignty scan
     enforces residency per jurisdiction, and into `column_classifications` for
     DSAR data-mapping.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.pii_discovery import (
    CATEGORY_TO_DATA_CLASS,
    ColumnClassification,
    classify_column,
    column_fingerprint,
)

logger = logging.getLogger(__name__)


# Heuristic → dspm severity by data_class.
_CLASS_SEVERITY = {
    "highly_confidential": "critical",
    "phi": "high",
    "pci": "high",
    "pii": "medium",
    "financial": "high",
}


async def ensure_classification_tables(db: AsyncSession) -> None:
    """Create the column-level classification lineage table (idempotent)."""
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS column_classifications (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            source VARCHAR(32) NOT NULL,          -- snowflake / sap / oracle / ...
            connection_id UUID,
            database_name VARCHAR(255),
            schema_name VARCHAR(255),
            table_name VARCHAR(255),
            column_name VARCHAR(255),
            data_class VARCHAR(32),               -- pii / phi / pci / financial / highly_confidential
            category VARCHAR(64),                 -- pii_email / pci_card / ...
            detector VARCHAR(32),                 -- value+name / value / name_only
            confidence REAL,
            evidence JSONB DEFAULT '{}'::jsonb,   -- {samples, sample_size, match_count, note}
            region VARCHAR(64),
            country VARCHAR(8),
            fingerprint VARCHAR(64) NOT NULL,
            first_seen_at TIMESTAMPTZ DEFAULT NOW(),
            last_seen_at TIMESTAMPTZ DEFAULT NOW(),
            CONSTRAINT column_classifications_unique UNIQUE (org_id, fingerprint)
        )
    """))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_colcls_org_source ON column_classifications(org_id, source)"
    ))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_colcls_org_class ON column_classifications(org_id, data_class)"
    ))
    await db.execute(text(
        "CREATE INDEX IF NOT EXISTS ix_colcls_org_cat ON column_classifications(org_id, category)"
    ))
    await db.commit()


async def _persist_classification(
    db: AsyncSession,
    org_id: str,
    source: str,
    connection_id: Optional[str],
    database_name: str,
    schema_name: str,
    table_name: str,
    cls: ColumnClassification,
    region: Optional[str],
    country: Optional[str],
) -> None:
    """Upsert one column classification + mirror it into dspm_findings."""
    fp = column_fingerprint(source, database_name, schema_name, table_name, cls.column_name)
    evidence = {
        "samples": cls.evidence,
        "sample_size": cls.sample_size,
        "match_count": cls.match_count,
        "detector": cls.detector,
        "reason": (
            f"{cls.match_count}/{cls.sample_size} sampled values matched {cls.category}"
            if cls.detector != "name_only"
            else f"column name matched {cls.category}"
        ),
    }
    await db.execute(text("""
        INSERT INTO column_classifications
            (org_id, source, connection_id, database_name, schema_name, table_name,
             column_name, data_class, category, detector, confidence, evidence,
             region, country, fingerprint, first_seen_at, last_seen_at)
        VALUES
            (CAST(:org AS UUID), :src, :cid, :db, :schema, :tbl,
             :col, :dc, :cat, :det, :conf, CAST(:ev AS JSONB),
             :region, :country, :fp, NOW(), NOW())
        ON CONFLICT (org_id, fingerprint) DO UPDATE SET
            data_class = EXCLUDED.data_class,
            category = EXCLUDED.category,
            detector = EXCLUDED.detector,
            confidence = EXCLUDED.confidence,
            evidence = EXCLUDED.evidence,
            region = EXCLUDED.region,
            country = EXCLUDED.country,
            last_seen_at = NOW()
    """), {
        "org": org_id, "src": source,
        "cid": connection_id if connection_id else None,
        "db": database_name[:255], "schema": schema_name[:255], "tbl": table_name[:255],
        "col": cls.column_name[:255], "dc": cls.data_class, "cat": cls.category,
        "det": cls.detector, "conf": cls.confidence, "ev": json.dumps(evidence),
        "region": (region or "")[:64] or None, "country": (country or "")[:8] or None,
        "fp": fp,
    })

    # Mirror into dspm_findings so the sovereignty scan enforces residency.
    severity = _CLASS_SEVERITY.get(cls.data_class or "", "medium")
    resource_id = f"{database_name}.{schema_name}.{table_name}"
    object_key = f"{resource_id}.{cls.column_name}"
    await db.execute(text("""
        INSERT INTO dspm_findings
            (org_id, cloud, fingerprint, resource_type, resource_id, object_key,
             category, severity, pattern_name, match_count, redacted_sample,
             confidence, region, metadata, first_seen_at, last_seen_at)
        VALUES
            (CAST(:org AS UUID), :cloud, :fp, :rt, :rid, :ok,
             :cat, :sev, :pn, :mc, :rs,
             :conf, :region, CAST(:md AS JSONB), NOW(), NOW())
        ON CONFLICT (org_id, cloud, fingerprint) DO UPDATE SET
            category = EXCLUDED.category,
            severity = EXCLUDED.severity,
            match_count = EXCLUDED.match_count,
            redacted_sample = EXCLUDED.redacted_sample,
            confidence = EXCLUDED.confidence,
            region = EXCLUDED.region,
            metadata = EXCLUDED.metadata,
            last_seen_at = NOW(),
            resolved_at = NULL
    """), {
        "org": org_id, "cloud": source, "fp": fp, "rt": "column",
        "rid": resource_id[:512], "ok": object_key,
        "cat": cls.category, "sev": severity,
        "pn": f"column-classifier:{cls.detector}",
        "mc": cls.match_count,
        "rs": "; ".join(cls.evidence)[:500],
        "conf": cls.confidence, "region": (region or "global")[:64],
        "md": json.dumps({
            "source": "pii_discovery",
            "data_class": cls.data_class,
            "categories": [cls.category] if cls.category else [],
            "confidence": cls.confidence,
            "detector": cls.detector,
            "evidence_samples": cls.evidence,
            "sample_size": cls.sample_size,
            "column": cls.column_name,
            "table": resource_id,
        }),
    })


# ── Snowflake real per-column sampling ──────────────────────────────────────

def _snowflake_sample_sync(client, max_tables: int, sample_rows: int) -> list[dict]:
    """Enumerate columns and sample values from a live Snowflake account.

    Runs in a worker thread (snowflake-connector-python is sync). Returns a list
    of {database, schema, table, column, values[]} dicts. Skips Snowflake's own
    SNOWFLAKE / INFORMATION_SCHEMA metadata databases.
    """
    out: list[dict] = []
    dbs = client.query("SELECT DATABASE_NAME FROM SNOWFLAKE.INFORMATION_SCHEMA.DATABASES")
    db_names = [
        r["DATABASE_NAME"] for r in dbs
        if r.get("DATABASE_NAME") and r["DATABASE_NAME"].upper() not in ("SNOWFLAKE", "SNOWFLAKE_SAMPLE_DATA")
    ]
    tables_scanned = 0
    for db_name in db_names:
        if tables_scanned >= max_tables:
            break
        try:
            cols = client.query(f"""
                SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, DATA_TYPE
                FROM {db_name}.INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA <> 'INFORMATION_SCHEMA'
                ORDER BY TABLE_SCHEMA, TABLE_NAME
            """)
        except Exception as exc:
            logger.debug(f"pii_discovery/snowflake: columns query failed for {db_name}: {exc}")
            continue

        # Group columns by table.
        by_table: dict[tuple, list[dict]] = {}
        for c in cols:
            key = (c["TABLE_SCHEMA"], c["TABLE_NAME"])
            by_table.setdefault(key, []).append(c)

        for (schema, table), tcols in by_table.items():
            if tables_scanned >= max_tables:
                break
            tables_scanned += 1
            # Only sample string-ish columns (where PII lives). Keep others for
            # name-only classification.
            text_cols = [
                c["COLUMN_NAME"] for c in tcols
                if str(c.get("DATA_TYPE", "")).upper() in (
                    "TEXT", "STRING", "VARCHAR", "CHAR", "VARIANT", "NUMBER", "OBJECT"
                )
            ]
            samples: dict[str, list] = {}
            if text_cols:
                col_list = ", ".join(f'"{c}"' for c in text_cols[:50])
                try:
                    rows = client.query(
                        f'SELECT {col_list} FROM "{db_name}"."{schema}"."{table}" '
                        f'SAMPLE ({sample_rows} ROWS)'
                    )
                except Exception:
                    try:
                        rows = client.query(
                            f'SELECT {col_list} FROM "{db_name}"."{schema}"."{table}" '
                            f'LIMIT {sample_rows}'
                        )
                    except Exception as exc:
                        logger.debug(f"pii_discovery/snowflake: sample failed {schema}.{table}: {exc}")
                        rows = []
                for c in text_cols:
                    samples[c] = [r.get(c.upper()) for r in rows]
            for c in tcols:
                cname = c["COLUMN_NAME"]
                out.append({
                    "database": db_name, "schema": schema, "table": table,
                    "column": cname, "values": samples.get(cname, []),
                })
    return out


async def scan_snowflake_columns(
    db: AsyncSession,
    org_id: str,
    connection_id: str,
    *,
    max_tables: int = 40,
    sample_rows: int = 200,
) -> dict:
    """Run a real per-column PII scan for one Snowflake connection."""
    import asyncio
    from backend.routers.snowflake_connector import _decrypt
    from backend.services.snowflake_scanner import SnowflakeClient
    from backend.routers.data_sovereignty import _snowflake_region_country

    await ensure_classification_tables(db)
    row = (await db.execute(text("""
        SELECT account, sf_user, sf_role, warehouse, auth_method,
               password_enc, private_key_enc, private_key_passphrase_enc
        FROM snowflake_connections
        WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)
    """), {"cid": connection_id, "org": org_id})).first()
    if not row:
        return {"ok": False, "error": "connection not found"}
    (acct, usr, role, wh, auth_method, pwd_enc, pk_enc, pkp_enc) = row
    country, region = _snowflake_region_country((acct or "").lower())

    def _run():
        client = SnowflakeClient(
            account=acct, user=usr, role=role, warehouse=wh,
            password=_decrypt(pwd_enc), private_key_pem=_decrypt(pk_enc),
            private_key_passphrase=_decrypt(pkp_enc),
        )
        client.connect()
        try:
            return _snowflake_sample_sync(client, max_tables, sample_rows)
        finally:
            client.close()

    try:
        columns = await asyncio.to_thread(_run)
    except Exception as exc:
        logger.warning(f"pii_discovery/snowflake: scan failed org={org_id}: {exc}")
        return {"ok": False, "error": str(exc)[:300]}

    sensitive = 0
    for col in columns:
        cls = classify_column(col["column"], col["values"])
        if not cls.is_sensitive:
            continue
        sensitive += 1
        await _persist_classification(
            db, org_id, "snowflake", connection_id,
            col["database"], col["schema"], col["table"], cls,
            region or (acct or "").lower(), country,
        )
    await db.commit()
    logger.info(
        f"pii_discovery/snowflake: org={org_id} columns={len(columns)} sensitive={sensitive}"
    )
    return {"ok": True, "columns_scanned": len(columns), "sensitive_columns": sensitive}


# ── SAP documented data-dictionary catalog ──────────────────────────────────
# The SAP connector does not execute row queries, so we classify from SAP's
# well-known data dictionary: these standard tables/columns carry PII/HR/finance
# by definition. Confidence is name/metadata-based (detector='name_only').
_SAP_CATALOG: list[dict] = [
    {"table": "KNA1", "desc": "Customer master (general)", "columns": {
        "NAME1": "pii_name", "STRAS": "pii_address", "PSTLZ": "pii_address",
        "ORT01": "pii_address", "TELF1": "pii_phone", "STCD1": "pii_national_id"}},
    {"table": "LFA1", "desc": "Vendor master (general)", "columns": {
        "NAME1": "pii_name", "STRAS": "pii_address", "TELF1": "pii_phone",
        "STCD1": "pii_national_id"}},
    {"table": "PA0002", "desc": "HR master: personal data", "columns": {
        "VORNA": "pii_name", "NACHN": "pii_name", "GBDAT": "pii_dob",
        "PERID": "pii_national_id", "GESCH": "pii_name"}},
    {"table": "PA0006", "desc": "HR master: addresses", "columns": {
        "STRAS": "pii_address", "ORT01": "pii_address", "PSTLZ": "pii_address",
        "TELNR": "pii_phone"}},
    {"table": "PA0009", "desc": "HR master: bank details", "columns": {
        "BANKN": "financial_account", "BANKL": "financial_account",
        "IBAN": "financial_iban", "SWIFT": "financial_swift"}},
    {"table": "PA0008", "desc": "HR master: basic pay", "columns": {
        "BET01": "financial_account", "ANSAL": "financial_account"}},
    {"table": "BUT000", "desc": "Business partner", "columns": {
        "NAME_FIRST": "pii_name", "NAME_LAST": "pii_name", "PERSNUMBER": "pii_national_id"}},
    {"table": "ADR6", "desc": "Address: e-mail", "columns": {"SMTP_ADDR": "pii_email"}},
    {"table": "ADRC", "desc": "Address master", "columns": {
        "TEL_NUMBER": "pii_phone", "STREET": "pii_address", "CITY1": "pii_address"}},
]


async def classify_sap_catalog(
    db: AsyncSession,
    org_id: str,
    connection_id: str,
) -> dict:
    """Classify the documented SAP data-dictionary PII/finance columns."""
    await ensure_classification_tables(db)
    conn = (await db.execute(text("""
        SELECT host, system_id FROM sap_connections
        WHERE id = CAST(:cid AS UUID) AND org_id = CAST(:org AS UUID)
    """), {"cid": connection_id, "org": org_id})).mappings().first()
    if not conn:
        return {"ok": False, "error": "connection not found"}

    # Region inferred from the SAP host (same heuristic as the sovereignty oracle).
    host = (conn["host"] or "").lower()
    if ".eu" in host or ".de" in host or "europe" in host:
        region, country = "eu-central", "DE"
    elif ".us" in host or "-us-" in host:
        region, country = "us", "US"
    elif ".ap" in host or ".sg" in host or ".jp" in host:
        region, country = "ap-southeast", "SG"
    else:
        region, country = "eu-central", "DE"

    sap_db = conn["system_id"] or "SAP"
    sensitive = 0
    for entry in _SAP_CATALOG:
        for col, category in entry["columns"].items():
            cls = ColumnClassification(
                column_name=col,
                data_class=CATEGORY_TO_DATA_CLASS.get(category),
                category=category,
                detector="name_only",
                confidence=0.6,
                evidence=[f"SAP data dictionary: {entry['table']} ({entry['desc']}) column {col}"],
                sample_size=0,
                match_count=0,
            )
            await _persist_classification(
                db, org_id, "sap", connection_id,
                sap_db, "SAPABAP", entry["table"], cls, region, country,
            )
            sensitive += 1
    await db.commit()
    logger.info(f"pii_discovery/sap: org={org_id} catalog columns classified={sensitive}")
    return {"ok": True, "sensitive_columns": sensitive}
