"""
CSPM engine — orchestrates collector + plugins, produces a ScanReport.

Mirrors cloudsploit's engine.js but is async-native and stateless. The engine
itself does not know about specific clouds; it loads a registry of plugins
that target a given cloud and executes them against a populated cache.
"""
from __future__ import annotations

import asyncio
import logging
import time
import traceback
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from .types import (
    Finding,
    PluginMeta,
    PluginResult,
    PluginStatus,
    ScanContext,
    ScanReport,
    Severity,
)

logger = logging.getLogger(__name__)


# A plugin is a (meta, run_fn) pair. run_fn may be sync or async.
PluginRun = Callable[[ScanContext], PluginResult] | Callable[[ScanContext], Awaitable[PluginResult]]
Plugin = tuple[PluginMeta, PluginRun]

# A collector populates ctx.cache with raw cloud API responses. Async.
Collector = Callable[[ScanContext], Awaitable[None]]


class CSPMEngine:
    """
    Runs a collector + plugin set against a single cloud connection.

    Usage:
        engine = CSPMEngine(cloud="azure", collector=azure_collector, plugins=AZURE_PLUGINS)
        report = await engine.run(ctx)
    """

    def __init__(
        self,
        cloud: str,
        collector: Collector,
        plugins: list[Plugin],
        max_concurrency: int = 8,
    ):
        self.cloud = cloud
        self.collector = collector
        self.plugins = plugins
        self.max_concurrency = max_concurrency

    async def run(self, ctx: ScanContext) -> ScanReport:
        started_at = datetime.now(timezone.utc)
        errors: list[str] = []

        # ── Collection phase ────────────────────────────────────────────────
        try:
            await self.collector(ctx)
        except Exception as exc:
            tb = traceback.format_exc()
            logger.exception(f"CSPM collector failed for {self.cloud}: {exc}")
            errors.append(f"collector: {exc}")

        # ── Plugin phase ────────────────────────────────────────────────────
        sem = asyncio.Semaphore(self.max_concurrency)

        async def _run_one(plugin: Plugin) -> PluginResult:
            meta, fn = plugin
            async with sem:
                t0 = time.perf_counter()
                try:
                    out = fn(ctx)
                    if asyncio.iscoroutine(out):
                        out = await out  # type: ignore[assignment]
                except Exception as exc:
                    logger.exception(f"CSPM plugin {meta.plugin_id} failed: {exc}")
                    out = PluginResult(
                        plugin_id=meta.plugin_id,
                        findings=[
                            Finding(
                                plugin_id=meta.plugin_id,
                                cloud=self.cloud,
                                severity=Severity.INFO,
                                status=PluginStatus.UNKNOWN,
                                category=meta.category,
                                title=meta.title,
                                message=f"Plugin error: {exc}",
                                recommendation=meta.recommended_action,
                            )
                        ],
                        errors=[str(exc)],
                    )
                out.duration_ms = int((time.perf_counter() - t0) * 1000)
                return out

        results: list[PluginResult] = await asyncio.gather(
            *[_run_one(p) for p in self.plugins], return_exceptions=False
        )

        # ── Aggregate ───────────────────────────────────────────────────────
        all_findings: list[Finding] = []
        ok, fail, unknown = 0, 0, 0
        for r in results:
            all_findings.extend(r.findings)
            statuses = {f.status for f in r.findings}
            if PluginStatus.FAIL in statuses:
                fail += 1
            elif PluginStatus.UNKNOWN in statuses and not (
                PluginStatus.OK in statuses or PluginStatus.WARN in statuses
            ):
                unknown += 1
            else:
                ok += 1
            errors.extend(r.errors)

        finished_at = datetime.now(timezone.utc)
        return ScanReport(
            org_id=ctx.org_id,
            connection_id=ctx.connection_id,
            cloud=self.cloud,
            started_at=started_at,
            finished_at=finished_at,
            plugins_run=len(results),
            plugins_ok=ok,
            plugins_fail=fail,
            plugins_unknown=unknown,
            findings=all_findings,
            errors=errors,
        )


async def run_scan(
    cloud: str,
    collector: Collector,
    plugins: list[Plugin],
    ctx: ScanContext,
    max_concurrency: int = 8,
) -> ScanReport:
    """One-shot helper: build engine and run."""
    engine = CSPMEngine(cloud=cloud, collector=collector, plugins=plugins, max_concurrency=max_concurrency)
    return await engine.run(ctx)


# ── Plugin builder helpers ────────────────────────────────────────────────────

def add_result(
    findings: list[Finding],
    *,
    meta: PluginMeta,
    cloud: str,
    code: int,
    message: str,
    region: str = "global",
    resource: str = "",
    resource_type: str = "",
    severity: Optional[Severity] = None,
    metadata: Optional[dict] = None,
) -> None:
    """
    Mirror of cloudsploit's helpers.addResult().
    code: 0 OK, 1 WARN, 2 FAIL, 3 UNKNOWN
    """
    status = {
        0: PluginStatus.OK,
        1: PluginStatus.WARN,
        2: PluginStatus.FAIL,
        3: PluginStatus.UNKNOWN,
    }.get(code, PluginStatus.UNKNOWN)

    if severity is None:
        if status == PluginStatus.OK:
            severity = Severity.INFO
        elif status == PluginStatus.WARN:
            severity = Severity.LOW
        elif status == PluginStatus.FAIL:
            severity = meta.severity
        else:
            severity = Severity.INFO

    findings.append(
        Finding(
            plugin_id=meta.plugin_id,
            cloud=cloud,
            severity=severity,
            status=status,
            category=meta.category,
            title=meta.title,
            message=message,
            resource=resource,
            resource_type=resource_type or meta.category,
            region=region,
            recommendation=meta.recommended_action,
            compliance=dict(meta.compliance),
            metadata=metadata or {},
        )
    )
