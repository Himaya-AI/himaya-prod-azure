from __future__ import annotations

from app.domain.models import DeliveryOutcome, SmtpStage


def classify_smtp_result(
    code: int | None,
    *,
    connection_lost_after_data: bool = False,
    stage: SmtpStage | None = None,
) -> DeliveryOutcome:
    if connection_lost_after_data or stage == SmtpStage.DATA_SENT:
        if code is None:
            return DeliveryOutcome.UNCERTAIN
    if code is None:
        return DeliveryOutcome.FAILED
    if code == 250:
        return DeliveryOutcome.ACCEPTED
    if 400 <= code < 500:
        return DeliveryOutcome.DEFERRED
    return DeliveryOutcome.FAILED


def spool_state_for_outcome(outcome: DeliveryOutcome) -> str:
    return {
        DeliveryOutcome.ACCEPTED: "provider_accepted",
        DeliveryOutcome.DEFERRED: "deferred",
        DeliveryOutcome.FAILED: "failed",
        DeliveryOutcome.PARTIAL: "failed",
        DeliveryOutcome.UNCERTAIN: "outcome_uncertain",
    }[outcome]
