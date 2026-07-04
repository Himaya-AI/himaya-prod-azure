from __future__ import annotations

import hashlib
import logging
import re
import time
from pathlib import Path

logger = logging.getLogger(__name__)

MIGRATIONS_DIR = Path(__file__).parent.parent.parent / "config" / "migrations"
_FILENAME_RE   = re.compile(r"^(V\d+)__[a-z0-9_]+\.cypher$", re.IGNORECASE)


async def run_migrations(neo4j_service) -> None:
    files = sorted(
        p for p in MIGRATIONS_DIR.glob("*.cypher")
        if _FILENAME_RE.match(p.name)
    )
    if not files:
        logger.info("No migration files found in %s", MIGRATIONS_DIR)
        return

    # Ensure history tracking exists, then fetch applied versions
    async with neo4j_service.session() as session:
        await session.run(
            "CREATE CONSTRAINT migration_version_unique IF NOT EXISTS "
            "FOR (m:__MigrationHistory) REQUIRE m.version IS UNIQUE"
        )
        result  = await session.run("MATCH (m:__MigrationHistory) RETURN m.version AS version")
        applied = {r["version"] for r in await result.data()}

    pending = [p for p in files if p.name.split("__")[0].upper() not in applied]

    if not pending:
        logger.info("Schema up to date — %d migration(s) already applied", len(applied))
        return

    logger.info("%d pending migration(s) to apply", len(pending))
    for path in pending:
        await _apply(neo4j_service, path)


async def _apply(neo4j_service, path: Path) -> None:
    version  = path.name.split("__")[0].upper()
    content  = path.read_text(encoding="utf-8")
    statements = _parse(content)

    logger.info("Applying %s...", path.name)
    start = time.monotonic()

    try:
        async with neo4j_service.session() as session:
            for statement in statements:
                await session.run(statement)
    except Exception as exc:
        logger.error("Migration %s failed — %s: %s", version, type(exc).__name__, exc)
        raise

    elapsed_ms = int((time.monotonic() - start) * 1000)

    async with neo4j_service.session() as session:
        await session.run(
            """
            CREATE (:__MigrationHistory {
                version:           $version,
                filename:          $filename,
                checksum:          $checksum,
                applied_at:        datetime(),
                execution_time_ms: $elapsed_ms
            })
            """,
            version=version,
            filename=path.name,
            checksum=hashlib.md5(content.encode()).hexdigest(),
            elapsed_ms=elapsed_ms,
        )

    logger.info("%s applied in %dms", version, elapsed_ms)


def _parse(content: str) -> list[str]:
    """Strip // comments, join lines, split on semicolons."""
    lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("//")]
    return [s.strip() for s in " ".join(lines).split(";") if s.strip()]
