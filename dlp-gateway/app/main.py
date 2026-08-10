from __future__ import annotations

import signal
import time

from app.capture.mime_store import AzureBlobMimeStore
from app.capture.worker import CaptureWorker
from app.commands.consumer import CommandConsumer
from app.commands.processor import CommandProcessor
from app.config import get_settings
from app.config_cache.snapshot import FileTenantConfigCache
from app.events.bus import FilesystemEventBus
from app.events.delivery_worker import DeliveryEventPublisherWorker
from app.events.publisher import EventPublisher
from app.events.service_bus import AzureServiceBusEventBus
from app.health.server import create_health_server
from app.logging_setup import configure_logging, get_logger
from app.relay.adapters import build_default_registry
from app.relay.dispatcher import RelayDispatcher
from app.smtp.edge import DlpSMTPHandler, SmtpEdge
from app.smtp.tenant_resolver import TenantResolver
from app.smtp.trust import TrustPolicy
from app.spool.mta_spool import FilesystemSpoolStore
from app.workers.auto_allow import AutoAllowWorker
from app.workers.supervisor import WorkerSupervisor

log = get_logger(__name__)


def build_app():
    settings = get_settings()
    configure_logging(settings.log_level)

    settings.spool_dir.mkdir(parents=True, exist_ok=True)
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    settings.queue_dir.mkdir(parents=True, exist_ok=True)

    spool = FilesystemSpoolStore(settings.spool_dir)
    if settings.message_bus == "service_bus":
        if settings.force_allow:
            raise ValueError(
                "FORCE_ALLOW must be false when using Service Bus"
            )
        bus = AzureServiceBusEventBus(
            capture_queue_name=settings.capture_queue_name,
            command_queue_name=settings.command_queue_name,
            delivery_queue_name=settings.delivery_queue_name,
            connection_string=settings.service_bus_connection_string,
            fully_qualified_namespace=(
                settings.service_bus_fully_qualified_namespace
            ),
        )
    else:
        bus = FilesystemEventBus(settings.queue_dir)
    publisher = EventPublisher(bus)
    cache = FileTenantConfigCache(settings.tenant_config_path)
    resolver = TenantResolver(cache)
    trust = TrustPolicy(settings)

    mime_store = AzureBlobMimeStore(
        settings.azure_storage_connection_string,
        settings.blob_container,
    )
    capture = CaptureWorker(spool, mime_store, publisher)
    auto_allow = AutoAllowWorker(bus, enabled=settings.force_allow)
    adapters = build_default_registry(
        default_local_host=settings.relay_host,
        default_local_port=settings.relay_port,
    )
    relay = RelayDispatcher(spool, adapters, cache)
    commands = CommandConsumer(
        bus,
        CommandProcessor(
            spool,
            relay,
            max_relay_attempts=settings.relay_max_attempts,
        ),
    )
    delivery_events = DeliveryEventPublisherWorker(spool, publisher)
    workers = WorkerSupervisor(
        capture,
        auto_allow,
        commands,
        delivery_events,
        reclaim_after_sec=settings.queue_reclaim_seconds,
    )

    handler = DlpSMTPHandler(settings, spool, resolver, trust)
    smtp = SmtpEdge(handler, settings)

    def health_payload() -> dict:
        tenant = cache.resolve_for_sender("user@example.test")
        if tenant is None:
            tenant = cache.resolve_for_sender("test@sana085.onmicrosoft.com")
        tenant_ok = tenant is not None
        relay_adapter = tenant.relay.adapter if tenant else None
        return {
            "ok": tenant_ok and settings.spool_dir.exists(),
            "service": "dlp-gateway",
            "env": settings.dlp_env,
            "force_allow": settings.force_allow,
            "smtp_port": settings.smtp_port,
            "tenant_config_loaded": tenant_ok,
            "relay_adapter": relay_adapter,
            "provider": tenant.provider if tenant else None,
        }

    return settings, smtp, workers, health_payload


def main() -> None:
    settings, smtp, workers, health_payload = build_app()
    health_server, _ = create_health_server(
        settings.health_host, settings.health_port, health_payload
    )

    stopping = False

    def _stop(*_args) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    workers.start()
    smtp.start()
    log.info("gateway.started", env=settings.dlp_env)

    try:
        while not stopping:
            time.sleep(0.5)
    finally:
        log.info("gateway.stopping")
        smtp.stop()
        workers.stop()
        health_server.shutdown()
        log.info("gateway.stopped")


if __name__ == "__main__":
    main()
