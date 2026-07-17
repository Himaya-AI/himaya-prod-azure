from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

import asyncio

from app.kimi import KimiClassifier
from app.routes import router
from app.verdict import VerdictClassifier
from utils.prompt_loader import reload_prompts

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Pre-warming prompt cache from S3...")
    await asyncio.to_thread(reload_prompts)
    logger.info("Prompt cache ready.")
    logger.info("Initializing ContentClassifier...")
    app.state.classifier = KimiClassifier()
    logger.info("ContentClassifier ready.")
    logger.info("Initializing VerdictClassifier...")
    app.state.verdict_classifier = VerdictClassifier()
    logger.info("VerdictClassifier ready.")
    yield
    logger.info("Classifier service shutting down.")


app = FastAPI(
    title="Helios Mail Classifier",
    description="Email threat classification service",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(router)
