"""Standalone DLP v2 worker process entry point."""

from __future__ import annotations

import asyncio
import logging

from backend.database import AsyncSessionLocal
from backend.dlp.application.message_orchestrator import (
    MessageOrchestrator,
)
from backend.dlp.application.tenant_config import (
    DatabaseTenantConfigProvider,
)
from backend.dlp.classification import ClassifierClient
from backend.dlp.config import DlpSettings, get_dlp_settings
from backend.dlp.extraction import (
    MimeExtractionLimits,
    SafeMimeExtractor,
)
from backend.dlp.messaging.filesystem_bus import (
    FilesystemDlpMessageBus,
)
from backend.dlp.messaging.ports import DlpMessageBus
from backend.dlp.messaging.service_bus import (
    AzureServiceBusDlpMessageBus,
)
from backend.dlp.policy import PolicyEvaluator
from backend.dlp.storage.azure_mime_store import AzureBlobMimeStore
from backend.dlp.workers.capture_consumer import CaptureConsumer
from backend.dlp.workers.outbox_publisher import OutboxPublisher

log = logging.getLogger(__name__)


async def _build_bus(settings: DlpSettings) -> DlpMessageBus:
    if settings.message_bus == "filesystem":
        return FilesystemDlpMessageBus(
            settings.local_queue_dir,
            reclaim_after_seconds=(
                settings.local_queue_reclaim_seconds
            ),
        )
    bus = AzureServiceBusDlpMessageBus(
        capture_queue_name=settings.capture_queue_name,
        command_queue_name=settings.command_queue_name,
        connection_string=settings.service_bus_connection_string,
        fully_qualified_namespace=(
            settings.service_bus_fully_qualified_namespace
        ),
    )
    await bus.connect()
    return bus


async def run() -> None:
    settings = get_dlp_settings()
    bus = await _build_bus(settings)
    mime_store = AzureBlobMimeStore(
        container=settings.mime_blob_container,
        connection_string=(
            settings.azure_storage_connection_string
        ),
        storage_account=settings.azure_storage_account,
    )
    classifier = ClassifierClient(
        settings.classifier_service_url,
        connect_timeout_seconds=(
            settings.classifier_connect_timeout_seconds
        ),
        read_timeout_seconds=(
            settings.classifier_read_timeout_seconds
        ),
        max_attempts=settings.classifier_max_attempts,
        circuit_failure_threshold=(
            settings.classifier_circuit_failure_threshold
        ),
        circuit_recovery_seconds=(
            settings.classifier_circuit_recovery_seconds
        ),
        max_text_bytes=settings.max_classifier_text_bytes,
    )
    extractor = SafeMimeExtractor(
        MimeExtractionLimits(
            max_mime_bytes=settings.max_mime_bytes,
            max_text_bytes=settings.max_classifier_text_bytes,
        )
    )
    orchestrator = MessageOrchestrator(
        session_factory=AsyncSessionLocal,
        mime_store=mime_store,
        extractor=extractor,
        classifier=classifier,
        policy_evaluator=PolicyEvaluator(),
        tenant_configs=DatabaseTenantConfigProvider(settings),
    )
    capture_consumer = CaptureConsumer(bus, orchestrator)
    outbox_publisher = OutboxPublisher(
        session_factory=AsyncSessionLocal, bus=bus
    )
    try:
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(
                capture_consumer.run_forever(),
                name="dlp-capture-consumer",
            )
            tasks.create_task(
                outbox_publisher.run_forever(),
                name="dlp-outbox-publisher",
            )
    finally:
        await classifier.close()
        await mime_store.close()
        await bus.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        log.info("DLP worker stopped")


if __name__ == "__main__":
    main()
