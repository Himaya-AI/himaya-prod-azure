from __future__ import annotations

from fastapi import APIRouter, Request

from utils.schema import ClassifyRequest, ContentClassificationResult, VerdictRequest, VerdictResult
from config.aws import CLASSIFICATION_MODEL
from app.classifier import ContentClassifier
from app.verdict import VerdictClassifier

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "model": CLASSIFICATION_MODEL}


@router.post("/classify", response_model=ContentClassificationResult)
async def classify(req: ClassifyRequest, request: Request) -> ContentClassificationResult:
    return await request.app.state.classifier.classify(
        sender=req.sender,
        recipient=req.recipient,
        subject=req.subject,
        body=req.body,
        attachments=req.attachments,
        headers=req.headers,
        email_verify=req.email_verify.model_dump() if req.email_verify else None,
    )


@router.post("/classify/{id}", response_model=ContentClassificationResult)
async def classify_with_model(
    id: str, req: ClassifyRequest
) -> ContentClassificationResult:
    classifier = ContentClassifier(model_id=id)
    return await classifier.classify(
        sender=req.sender,
        recipient=req.recipient,
        subject=req.subject,
        body=req.body,
        attachments=req.attachments,
        headers=req.headers,
        email_verify=req.email_verify.model_dump() if req.email_verify else None,
    )


@router.post("/classify/batch", response_model=list[ContentClassificationResult])
async def classify_batch(
    reqs: list[ClassifyRequest],
    request: Request,
) -> list[ContentClassificationResult]:
    emails = [r.model_dump() for r in reqs]
    return await request.app.state.classifier.classify_batch(emails)


# ── Verdict / Helios Analysis (auto-triage) ─────────────────────────────────

@router.post("/verdict", response_model=VerdictResult)
async def verdict(req: VerdictRequest, request: Request) -> VerdictResult:
    """
    Helios Analysis verdict for a single threat dossier.

    Replaces the Anthropic Opus call in backend/services/auto_triage_service.py
    with a Bedrock Kimi K2.5 call — same prompt, same JSON contract.
    """
    classifier = request.app.state.verdict_classifier
    dossier = req.model_dump(exclude_none=False)
    result = await classifier.verdict(dossier)
    return VerdictResult(**result)
