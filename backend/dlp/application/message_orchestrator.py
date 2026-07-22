"""Idempotent capture-to-decision application workflow."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.dlp.application.tenant_config import (
    DatabaseTenantConfigProvider,
)
from backend.dlp.classification import ClassifierClient, ClassifierError
from backend.dlp.contracts import (
    CaptureEvent,
    CommandType,
    GatewayCommand,
    GatewayMessageState,
)
from backend.dlp.domain import ClassificationOutcome, Finding
from backend.dlp.domain import TenantMode
from backend.dlp.extraction import (
    ExtractionLimitation,
    MimeExtractionError,
    MimeExtractionResult,
    SafeMimeExtractor,
)
from backend.dlp.persistence.models import (
    DlpClassificationResult,
    DlpDecision,
    DlpMessagePart,
)
from backend.dlp.persistence.repositories import (
    ClassificationRepository,
    CommandOutboxRepository,
    DecisionRepository,
    MessageEventRepository,
    MessageRepository,
)
from backend.dlp.policy import (
    MessageContext,
    PolicyAction,
    PolicyDecision,
    PolicyEvaluator,
)
from backend.dlp.storage.azure_mime_store import (
    MimeIntegrityError,
    MimeObjectTooLargeError,
    MimeStorageError,
)
from backend.dlp.storage.ports import MimeObjectStore


@dataclass(frozen=True)
class MessageProcessingResult:
    message_id: UUID
    intended_action: PolicyAction
    effective_action: PolicyAction
    command_id: UUID | None
    resumed: bool = False


class MessageOrchestrator:
    EVALUATION_VERSION = 1

    def __init__(
        self,
        *,
        session_factory: async_sessionmaker[AsyncSession],
        mime_store: MimeObjectStore,
        extractor: SafeMimeExtractor,
        classifier: ClassifierClient,
        policy_evaluator: PolicyEvaluator,
        tenant_configs: DatabaseTenantConfigProvider,
    ) -> None:
        self._sessions = session_factory
        self._mime_store = mime_store
        self._extractor = extractor
        self._classifier = classifier
        self._policy_evaluator = policy_evaluator
        self._tenant_configs = tenant_configs

    async def process(
        self, event: CaptureEvent
    ) -> MessageProcessingResult:
        await self._ingest(event)
        existing = await self._existing_decision(event.message_id)
        if existing is not None:
            return _processing_result(existing, resumed=True)

        async with self._sessions() as session:
            tenant = await self._tenant_configs.get(
                session, UUID(event.org_id)
            )

        run_key = (
            f"classifier-v1:{tenant.lexicon_version}:"
            f"{event.mime_sha256}"
        )
        classification_row = await self._classification_row(
            event.message_id, run_key
        )
        if classification_row is None:
            extraction, classification, classifier_error = (
                await self._inspect(event, tenant.lexicon_version)
            )
            classification_row = await self._persist_inspection(
                event.message_id,
                run_key,
                extraction,
                classification,
                classifier_error,
            )
        else:
            extraction = _stored_extraction(classification_row)
            classification = _stored_classification(
                classification_row
            )

        decision = self._policy_evaluator.evaluate(
            policy=tenant.policy,
            classification=classification,
            limitations=extraction.limitations,
            context=MessageContext(
                sender=event.envelope_from,
                recipients=tuple(event.envelope_to),
                tenant_domains=tenant.domains,
            ),
            mode=tenant.mode,
            enabled=tenant.enabled,
        )
        return await self._persist_decision(
            event, classification_row.id, decision, tenant.mode
        )

    async def _ingest(self, event: CaptureEvent) -> None:
        async with self._sessions() as session:
            async with session.begin():
                messages = MessageRepository(session)
                message, created = await messages.create_from_capture(
                    event
                )
                await MessageEventRepository(session).record_capture(
                    event
                )
                if created:
                    await messages.set_state(message, "received")

    async def _existing_decision(
        self, message_id: UUID
    ) -> DlpDecision | None:
        async with self._sessions() as session:
            return await DecisionRepository(session).get(
                message_id, self.EVALUATION_VERSION
            )

    async def _classification_row(
        self, message_id: UUID, run_key: str
    ) -> DlpClassificationResult | None:
        async with self._sessions() as session:
            return await ClassificationRepository(session).get_by_run(
                message_id, run_key
            )

    async def _inspect(
        self, event: CaptureEvent, lexicon_version: str
    ) -> tuple[
        MimeExtractionResult,
        ClassificationOutcome,
        str | None,
    ]:
        try:
            raw_mime = await self._mime_store.download(
                event.blob_uri,
                expected_sha256=event.mime_sha256,
                max_bytes=min(
                    event.mime_size,
                    self._extractor.limits.max_mime_bytes,
                ),
            )
            extraction = await self._extractor.extract(raw_mime)
        except (
            MimeIntegrityError,
            MimeObjectTooLargeError,
            MimeStorageError,
            MimeExtractionError,
        ) as exc:
            limitation = ExtractionLimitation(
                code="mime_inspection_failed",
                detail=str(exc)[:1000],
                fatal=True,
            )
            extraction = MimeExtractionResult(
                subject="",
                sender=event.envelope_from,
                recipients=tuple(event.envelope_to),
                text="",
                parts=(),
                limitations=(limitation,),
            )

        if not extraction.text.strip():
            error = "No extractable text was available to classify"
            return extraction, _failed_classification(error), error
        try:
            classification = await self._classifier.classify(
                extraction.text,
                tenant_id=event.org_id,
                message_id=str(event.message_id),
                lexicon_version=lexicon_version,
            )
            return extraction, classification, None
        except ClassifierError as exc:
            error = str(exc)[:1000]
            return extraction, _failed_classification(error), error

    async def _persist_inspection(
        self,
        message_id: UUID,
        run_key: str,
        extraction: MimeExtractionResult,
        classification: ClassificationOutcome,
        classifier_error: str | None,
    ) -> DlpClassificationResult:
        async with self._sessions() as session:
            async with session.begin():
                existing = await ClassificationRepository(
                    session
                ).get_by_run(message_id, run_key)
                if existing is not None:
                    return existing

                await session.execute(
                    delete(DlpMessagePart).where(
                        DlpMessagePart.message_id == message_id
                    )
                )
                for part in extraction.parts:
                    text_digest = (
                        hashlib.sha256(
                            part.text.encode("utf-8")
                        ).hexdigest()
                        if part.text
                        else None
                    )
                    session.add(
                        DlpMessagePart(
                            message_id=message_id,
                            part_index=part.part_index,
                            content_type=part.content_type,
                            disposition=part.disposition,
                            filename=part.filename,
                            size_bytes=part.size_bytes,
                            sha256=part.sha256,
                            extraction_status=(
                                "limited"
                                if part.limitation
                                else "extracted"
                            ),
                            extracted_text_sha256=text_digest,
                            extracted_text_length=(
                                len(part.text) if part.text else None
                            ),
                            limitation_code=(
                                part.limitation.code
                                if part.limitation
                                else None
                            ),
                            limitation_detail=(
                                part.limitation.detail
                                if part.limitation
                                else None
                            ),
                        )
                    )

                row = DlpClassificationResult(
                    message_id=message_id,
                    run_key=run_key,
                    status=(
                        "failed"
                        if classifier_error
                        else "completed"
                    ),
                    findings=[
                        asdict(finding)
                        for finding in classification.findings
                    ],
                    llm_result={
                        "classification": (
                            classification.llm_classification
                        ),
                        "confidence": classification.llm_confidence,
                        "categories": list(
                            classification.llm_categories
                        ),
                        "reasoning": classification.llm_reasoning,
                        "detector_errors": list(
                            classification.detector_errors
                        ),
                        "escalation_requested": (
                            classification.escalation_requested
                        ),
                    },
                    limitations=[
                        asdict(item)
                        for item in extraction.limitations
                    ],
                    error=classifier_error,
                    completed_at=datetime.now(timezone.utc),
                )
                await ClassificationRepository(session).add(row)
                message = await MessageRepository(session).get(message_id)
                if message is None:
                    raise RuntimeError("DLP message disappeared")
                await MessageRepository(session).set_state(
                    message, "classified"
                )
                return row

    async def _persist_decision(
        self,
        event: CaptureEvent,
        classification_result_id: UUID,
        decision: PolicyDecision,
        mode: TenantMode,
    ) -> MessageProcessingResult:
        async with self._sessions() as session:
            async with session.begin():
                decisions = DecisionRepository(session)
                existing = await decisions.get(
                    event.message_id, self.EVALUATION_VERSION
                )
                if existing is not None:
                    return _processing_result(
                        existing, resumed=True
                    )
                row = DlpDecision(
                    message_id=event.message_id,
                    classification_result_id=(
                        classification_result_id
                    ),
                    evaluation_version=self.EVALUATION_VERSION,
                    policy_version=decision.policy_version,
                    mode=mode.value,
                    intended_action=decision.intended_action.value,
                    effective_action=decision.effective_action.value,
                    matched_rule_ids=list(
                        decision.matched_rule_ids
                    ),
                    finding_references=[
                        asdict(reference)
                        for reference in decision.finding_references
                    ],
                    explanation=decision.explanation,
                    evaluation_latency_ms=(
                        decision.evaluation_latency_ms
                    ),
                )
                await decisions.add(row)
                command = _gateway_command(event, decision)
                if command is not None:
                    await CommandOutboxRepository(session).enqueue(
                        command
                    )
                message = await MessageRepository(session).get(
                    event.message_id
                )
                if message is None:
                    raise RuntimeError("DLP message disappeared")
                await MessageRepository(session).set_state(
                    message, "decided"
                )
                return MessageProcessingResult(
                    message_id=event.message_id,
                    intended_action=decision.intended_action,
                    effective_action=decision.effective_action,
                    command_id=(
                        command.command_id if command else None
                    ),
                )


def _failed_classification(error: str) -> ClassificationOutcome:
    return ClassificationOutcome(
        findings=(),
        llm_classification="UNCERTAIN",
        llm_confidence=0.0,
        llm_categories=(),
        llm_reasoning="Classification was unavailable.",
        detector_errors=(f"classifier_service: {error}",),
        escalation_requested=True,
    )


def _stored_extraction(
    row: DlpClassificationResult,
) -> MimeExtractionResult:
    limitations = tuple(
        ExtractionLimitation(**item) for item in row.limitations
    )
    return MimeExtractionResult(
        subject="",
        sender="",
        recipients=(),
        text="",
        parts=(),
        limitations=limitations,
    )


def _stored_classification(
    row: DlpClassificationResult,
) -> ClassificationOutcome:
    llm = row.llm_result or {}
    return ClassificationOutcome(
        findings=tuple(
            Finding(**item) for item in row.findings
        ),
        llm_classification=str(
            llm.get("classification", "UNCERTAIN")
        ),
        llm_confidence=float(llm.get("confidence", 0.0)),
        llm_categories=tuple(llm.get("categories", [])),
        llm_reasoning=str(llm.get("reasoning", "")),
        detector_errors=tuple(llm.get("detector_errors", [])),
        escalation_requested=bool(
            llm.get("escalation_requested", False)
        ),
    )


def _gateway_command(
    event: CaptureEvent, decision: PolicyDecision
) -> GatewayCommand | None:
    command_type = {
        PolicyAction.ALLOW: CommandType.ALLOW,
        PolicyAction.STOP: CommandType.STOP,
    }.get(decision.effective_action)
    if command_type is None:
        return None
    command_id = uuid.uuid5(
        uuid.NAMESPACE_URL,
        (
            f"dlp-v1:{event.message_id}:"
            f"{MessageOrchestrator.EVALUATION_VERSION}:"
            f"{command_type.value}"
        ),
    )
    return GatewayCommand(
        command_id=command_id,
        command_type=command_type,
        message_id=event.message_id,
        org_id=event.org_id,
        expected_state=GatewayMessageState.CAPTURED,
        reason=decision.explanation,
        metadata={
            "policy_version": decision.policy_version,
            "intended_action": decision.intended_action.value,
        },
    )


def _processing_result(
    decision: DlpDecision, *, resumed: bool
) -> MessageProcessingResult:
    effective = PolicyAction(decision.effective_action)
    command_id = (
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            (
                f"dlp-v1:{decision.message_id}:"
                f"{decision.evaluation_version}:"
                f"{effective.value}"
            ),
        )
        if effective in {PolicyAction.ALLOW, PolicyAction.STOP}
        else None
    )
    return MessageProcessingResult(
        message_id=decision.message_id,
        intended_action=PolicyAction(decision.intended_action),
        effective_action=effective,
        command_id=command_id,
        resumed=resumed,
    )
