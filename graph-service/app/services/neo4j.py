from __future__ import annotations

import asyncio
import logging

from config.neo4j import create_driver, RETRY_ATTEMPTS, RETRY_BACKOFF_SECONDS

logger = logging.getLogger(__name__)


class Neo4jService:
    def __init__(self) -> None:
        self._driver = None

    # ── Startup ───────────────────────────────────────────────────────────────

    async def init(self, url: str, user: str, password: str) -> None:
        if not url:
            logger.warning("NEO4J_URL not set — service will be unavailable")
            return

        last_error: Exception | None = None

        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                if attempt > 1:
                    await asyncio.sleep(RETRY_BACKOFF_SECONDS * (attempt - 1))

                driver = create_driver(url, user, password)

                await driver.verify_connectivity()
                self._driver = driver
                logger.info("Neo4j connected: %s (attempt %d/%d)", url, attempt, RETRY_ATTEMPTS)
                return

            except Exception as exc:
                last_error = exc
                logger.warning(
                    "Neo4j connect attempt %d/%d failed — %s: %s",
                    attempt, RETRY_ATTEMPTS, type(exc).__name__, exc,
                )

        logger.error(
            "Neo4j unavailable after %d attempts — last error: %s",
            RETRY_ATTEMPTS, last_error,
        )

    # ── Shutdown ──────────────────────────────────────────────────────────────

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j driver closed.")

    # ── Health ────────────────────────────────────────────────────────────────

    async def is_connected(self) -> bool:
        if not self._driver:
            return False
        try:
            await self._driver.verify_connectivity()
            return True
        except Exception:
            return False

    # ── Session ───────────────────────────────────────────────────────────────

    def session(self):
        if not self._driver:
            raise RuntimeError("Neo4j driver is not initialized")
        return self._driver.session()
