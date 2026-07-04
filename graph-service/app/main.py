from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.services.neo4j import Neo4jService
from app.services.migrations import run_migrations
from app.services.trust_scorer import TrustScorer
from app.routes import router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Neo4j ─────────────────────────────────────────────────────────────────
    logger.info("Initializing Neo4j driver...")
    neo4j_service = Neo4jService()
    await neo4j_service.init(
        url=os.getenv("NEO4J_URL", ""),
        user=os.getenv("NEO4J_USER", "neo4j"),
        password=os.getenv("NEO4J_PASSWORD", ""),
    )
    app.state.neo4j = neo4j_service
    logger.info("Neo4j driver ready.")

    # ── Migrations ────────────────────────────────────────────────────────────
    logger.info("Running schema migrations...")
    await run_migrations(neo4j_service)
    logger.info("Migrations complete.")

    logger.info("Initializing TrustScorer...")
    app.state.trust_scorer = TrustScorer()
    logger.info("TrustScorer ready.")

    yield

    # ── Shutdown ──────────────────────────────────────────────────────────────
    logger.info("Graph service shutting down.")
    await neo4j_service.close()
    logger.info("Neo4j driver closed.")


app = FastAPI(
    title="Helios Graph Service",
    description="Neo4j trust scoring and graph intelligence service",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://app.himaya.ai",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/graph")
