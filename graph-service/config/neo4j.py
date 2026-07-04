import os

from dotenv import load_dotenv
from neo4j import AsyncGraphDatabase

load_dotenv()

# ── Connection ────────────────────────────────────────────────────────────────
NEO4J_URL      = os.getenv("NEO4J_URL", "")
NEO4J_USER     = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")

# ── Connection pool ───────────────────────────────────────────────────────────
_MAX_POOL_SIZE           = int(os.getenv("NEO4J_MAX_POOL_SIZE", "20"))
_MAX_CONNECTION_LIFETIME = int(os.getenv("NEO4J_MAX_CONNECTION_LIFETIME", "1800"))
_ACQUISITION_TIMEOUT     = float(os.getenv("NEO4J_ACQUISITION_TIMEOUT", "10.0"))
# ── Retry ─────────────────────────────────────────────────────────────────────
RETRY_ATTEMPTS        = int(os.getenv("NEO4J_RETRY_ATTEMPTS", "3"))
RETRY_BACKOFF_SECONDS = int(os.getenv("NEO4J_RETRY_BACKOFF_SECONDS", "5"))


def create_driver(url: str, user: str, password: str):
    return AsyncGraphDatabase.driver(
        url,
        auth=(user, password),
        max_connection_pool_size=_MAX_POOL_SIZE,
        max_connection_lifetime=_MAX_CONNECTION_LIFETIME,
        connection_acquisition_timeout=_ACQUISITION_TIMEOUT,
        notifications_disabled_categories={"DEPRECATION"},
    )
