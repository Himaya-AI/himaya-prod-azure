"""Regression tests for AWS security scanner executor isolation."""
from __future__ import annotations

import asyncio
import threading
import time

import pytest

from backend.services.aws_security_service import AWSSecurityService
from backend.services.cspm import executor as cspm_executor


@pytest.fixture(autouse=True)
def _reset_cspm_pool():
    cspm_executor.shutdown(wait=True)
    yield
    cspm_executor.shutdown(wait=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("public_method", "sync_method", "args"),
    [
        ("test_connection", "_test_connection_sync", ()),
        ("scan_s3_buckets", "_scan_s3_buckets_sync", ()),
        ("scan_efs_filesystems", "_scan_efs_filesystems_sync", (["us-east-1"],)),
        ("scan_ebs_volumes", "_scan_ebs_volumes_sync", (["us-east-1"],)),
        ("scan_rds_instances", "_scan_rds_instances_sync", (["us-east-1"],)),
        ("scan_cloudtrail_events", "_scan_cloudtrail_events_sync", (["us-east-1"],)),
        ("scan_iam_users", "_scan_iam_users_sync", ()),
        ("scan_iam_roles", "_scan_iam_roles_sync", ()),
        ("scan_ec2_instances", "_scan_ec2_instances_sync", (["us-east-1"],)),
    ],
)
async def test_aws_sync_work_uses_dedicated_cspm_executor(
    monkeypatch,
    public_method,
    sync_method,
    args,
):
    service = AWSSecurityService("test-access-key", "test-secret")
    monkeypatch.setattr(
        service,
        sync_method,
        lambda *unused_args: threading.current_thread().name,
    )

    worker_name = await getattr(service, public_method)(*args)

    assert worker_name.startswith("cspm-dspm")


@pytest.mark.asyncio
async def test_aws_scan_load_keeps_event_loop_and_default_executor_responsive(
    monkeypatch,
):
    service = AWSSecurityService("test-access-key", "test-secret")
    release_scans = threading.Event()

    def _blocking_scan():
        release_scans.wait(timeout=2)
        return [], []

    monkeypatch.setattr(service, "_scan_s3_buckets_sync", _blocking_scan)

    started_at = time.perf_counter()
    scan_tasks = [
        asyncio.create_task(service.scan_s3_buckets())
        for _ in range(64)
    ]
    release_timer = threading.Timer(0.75, release_scans.set)
    release_timer.start()

    try:
        # A scanner running sync work on the event loop would delay this yield.
        await asyncio.sleep(0.05)
        assert time.perf_counter() - started_at < 0.5

        # Bcrypt uses this same default executor via asyncio.to_thread.
        default_result = await asyncio.wait_for(
            asyncio.to_thread(lambda: "request-responsive"),
            timeout=0.5,
        )
        assert default_result == "request-responsive"
    finally:
        release_scans.set()
        await asyncio.gather(*scan_tasks)
        release_timer.cancel()
