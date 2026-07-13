from app.domain.models import DeliveryOutcome


def classify_smtp_result(code: int | None, connection_lost_after_data: bool) -> DeliveryOutcome:
    if connection_lost_after_data:
        return DeliveryOutcome.UNCERTAIN
    if code is None:
        return DeliveryOutcome.FAILED
    if code == 250:
        return DeliveryOutcome.ACCEPTED
    if 400 <= code < 500:
        return DeliveryOutcome.DEFERRED
    return DeliveryOutcome.FAILED
