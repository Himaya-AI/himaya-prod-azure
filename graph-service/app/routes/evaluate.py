from __future__ import annotations

import logging

from fastapi import APIRouter, Request

from app.services.llm_analyst import analyze_trust, apply_llm, should_invoke
from app.services.query import execute_query
from utils.schemas import EvaluateRequest, EvaluateResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/evaluate", response_model=EvaluateResponse)
async def evaluate(body: EvaluateRequest, req: Request) -> EvaluateResponse:
    logger.info("evaluate | sender=%s recipient=%s org=%s", body.sender, body.recipient, body.org_id)

    graph_data = await execute_query(
        req.app.state.neo4j,
        sender=body.sender,
        recipient=body.recipient,
        org_id=body.org_id,
    )

    trust: dict = req.app.state.trust_scorer.evaluate(graph_data)
    logger.info(
        "trust_scorer | method=%s score=%d domain_spread=%d indicators=%s",
        trust["trust_method"], trust["trust_score"], trust["domain_spread"], trust["indicators"],
    )

    rep_hint = body.reputation_hint.model_dump() if body.reputation_hint else None

    if should_invoke(trust):
        logger.info("llm_analyst | invoking for sender=%s method=%s", body.sender, trust["trust_method"])
        llm = await analyze_trust(
            graph_data, trust,
            content_hint=body.content_hint,
            reputation_hint=rep_hint,
        )
        if llm:
            trust = apply_llm(trust, llm)
            logger.info(
                "llm_analyst | applied adjustment=%+d final_score=%d confidence=%.2f",
                trust["llm_adjustment"], trust["trust_score"], trust["llm_confidence"],
            )
        else:
            logger.warning("llm_analyst | call failed — keeping rule-engine verdict score=%d", trust["trust_score"])
    else:
        logger.debug("llm_analyst | skipped method=%s score=%d", trust["trust_method"], trust["trust_score"])

    return EvaluateResponse(
        sender=graph_data["sender"],
        domain=graph_data["domain"],
        relationship=graph_data["relationship"],
        intel=graph_data["intel"],
        trust=trust,
    )
