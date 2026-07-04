"""
CSPM engine unit tests — exercise the plugin runner against synthetic cache data.

Run: python -m pytest backend/tests/test_cspm_engine.py -v
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.services.cspm.engine import CSPMEngine, add_result, run_scan
from backend.services.cspm.plugins.azure import AZURE_PLUGINS
from backend.services.cspm.plugins.github import GITHUB_PLUGINS
from backend.services.cspm.plugins.oracle import ORACLE_PLUGINS
from backend.services.cspm.types import (
    Finding,
    PluginMeta,
    PluginResult,
    PluginStatus,
    ScanContext,
    Severity,
)


# ── Severity / fingerprint sanity ────────────────────────────────────────────

def test_severity_from_cloudsploit_codes():
    assert Severity.from_cloudsploit_code(0) == Severity.INFO
    assert Severity.from_cloudsploit_code(1) == Severity.LOW
    assert Severity.from_cloudsploit_code(2) == Severity.HIGH
    assert Severity.from_cloudsploit_code(3) == Severity.INFO


def test_finding_fingerprint_stable():
    f1 = Finding(
        plugin_id="x", cloud="azure", severity=Severity.HIGH, status=PluginStatus.FAIL,
        category="s", title="t", message="m1", resource="r", region="eastus",
    )
    f2 = Finding(
        plugin_id="x", cloud="azure", severity=Severity.HIGH, status=PluginStatus.FAIL,
        category="s", title="t", message="m2-different", resource="r", region="eastus",
    )
    assert f1.fingerprint == f2.fingerprint  # message must NOT affect FP
    f3 = Finding(
        plugin_id="x", cloud="azure", severity=Severity.HIGH, status=PluginStatus.FAIL,
        category="s", title="t", message="m1", resource="r-different", region="eastus",
    )
    assert f1.fingerprint != f3.fingerprint  # resource DOES affect FP


# ── add_result helper ─────────────────────────────────────────────────────────

def test_add_result_codes():
    meta = PluginMeta(
        plugin_id="t", cloud="aws", title="t", category="c", severity=Severity.MEDIUM
    )
    findings: list[Finding] = []
    add_result(findings, meta=meta, cloud="aws", code=0, message="ok")
    add_result(findings, meta=meta, cloud="aws", code=1, message="warn")
    add_result(findings, meta=meta, cloud="aws", code=2, message="fail")
    add_result(findings, meta=meta, cloud="aws", code=3, message="unknown")
    assert findings[0].status == PluginStatus.OK
    assert findings[0].severity == Severity.INFO
    assert findings[1].status == PluginStatus.WARN
    assert findings[1].severity == Severity.LOW
    assert findings[2].status == PluginStatus.FAIL
    assert findings[2].severity == Severity.MEDIUM  # uses plugin meta default
    assert findings[3].status == PluginStatus.UNKNOWN


# ── Engine end-to-end with synthetic Azure cache ─────────────────────────────

@pytest.mark.asyncio
async def test_engine_azure_smoke():
    async def fake_collector(ctx):
        ctx.add_source(["storageAccounts", "list", "global"], {"err": None, "data": [
            {"id": "/sa/bad", "location": "eastus", "properties": {
                "supportsHttpsTrafficOnly": False,
                "allowBlobPublicAccess": True,
                "minimumTlsVersion": "TLS1_0",
                "publicNetworkAccess": "Enabled",
            }},
            {"id": "/sa/good", "location": "westus", "properties": {
                "supportsHttpsTrafficOnly": True,
                "allowBlobPublicAccess": False,
                "minimumTlsVersion": "TLS1_2",
                "publicNetworkAccess": "Disabled",
            }},
        ]})
        ctx.add_source(["vaults", "list", "global"], {"err": None, "data": [
            {"id": "/kv/bad", "location": "eastus", "properties": {
                "enableSoftDelete": False,
                "enablePurgeProtection": False,
            }},
        ]})
        ctx.add_source(["networkSecurityGroups", "list", "global"], {"err": None, "data": [
            {"id": "/nsg/bad", "location": "eastus", "properties": {
                "securityRules": [{"properties": {
                    "direction": "Inbound", "access": "Allow",
                    "sourceAddressPrefix": "*", "destinationPortRange": "22",
                }, "name": "open-ssh"}],
            }},
        ]})

    ctx = ScanContext(org_id="o", connection_id="c", cloud="azure")
    report = await run_scan("azure", fake_collector, AZURE_PLUGINS, ctx)
    assert report.plugins_run == len(AZURE_PLUGINS)
    assert report.findings, "expected at least one finding"

    # Must catch the critical open NSG
    critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
    assert any("open-ssh" in f.message for f in critical), "expected open-ssh NSG to fire critical"

    # Must catch HTTPS-only fail on bad SA
    https_fails = [f for f in report.findings
                   if f.plugin_id == "azure-storage-secure-transfer-required"
                   and f.status == PluginStatus.FAIL]
    assert len(https_fails) == 1
    assert https_fails[0].resource == "/sa/bad"


# ── Engine with GitHub synthetic data ────────────────────────────────────────

@pytest.mark.asyncio
async def test_engine_github_smoke():
    async def fake_collector(ctx):
        org = "testorg"
        ctx.add_source(["orgs", "get", org], {"err": None, "data": {
            "login": org,
            "two_factor_requirement_enabled": False,
        }})
        ctx.add_source(["orgs", "members2faDisabled", org], {"err": None, "data": [
            {"login": "alice"}, {"login": "bob"},
        ]})
        ctx.add_source(["orgs", "outsideCollaborators", org], {"err": None, "data": []})
        ctx.add_source(["orgs", "hooks", org], {"err": None, "data": [
            {"config": {"url": "http://insecure.example.com/hook"}},
            {"config": {"url": "https://secure.example.com/hook"}},
        ]})
        ctx.add_source(["repos", "list", org], {"err": None, "data": [
            {"full_name": f"{org}/repo1", "default_branch": "main", "archived": False, "disabled": False},
        ]})
        ctx.add_source(["repos", "branchProtection", f"{org}/repo1"], {"err": None, "data": {}})
        ctx.add_source(["repos", "vulnerabilityAlerts", f"{org}/repo1"], {"err": "HTTP 404", "data": None})
        ctx.add_source(["repos", "details", f"{org}/repo1"], {"err": None, "data": {
            "security_and_analysis": {"secret_scanning": {"status": "disabled"}},
        }})
        ctx.add_source(["repos", "secretScanningAlerts", f"{org}/repo1"], {"err": None, "data": []})
        ctx.add_source(["repos", "codeScanningAlerts", f"{org}/repo1"], {"err": None, "data": []})
        ctx.add_source(["repos", "collaborators", f"{org}/repo1"], {"err": None, "data": []})

    ctx = ScanContext(org_id="o", connection_id="c", cloud="github", settings={"org": "testorg"})
    report = await run_scan("github", fake_collector, GITHUB_PLUGINS, ctx)

    # 2FA should be marked critical
    two_fa = [f for f in report.findings if f.plugin_id == "github-org-2fa-enforced"]
    assert two_fa and two_fa[0].status == PluginStatus.FAIL
    assert two_fa[0].severity == Severity.CRITICAL

    # Webhook HTTPS should fail (1 non-HTTPS hook)
    hook = [f for f in report.findings if f.plugin_id == "github-org-webhook-https-only"]
    assert hook and hook[0].status == PluginStatus.FAIL


# ── Plugin meta serialization ────────────────────────────────────────────────

def test_plugin_meta_serializes():
    meta = AZURE_PLUGINS[0][0]
    d = meta.as_dict()
    assert "plugin_id" in d
    assert "severity" in d
    assert isinstance(d["severity"], str)


# ── Engine collector exception is handled ────────────────────────────────────

@pytest.mark.asyncio
async def test_engine_handles_collector_failure():
    async def boom(ctx):
        raise RuntimeError("simulated network outage")

    ctx = ScanContext(org_id="o", connection_id="c", cloud="azure")
    report = await run_scan("azure", boom, AZURE_PLUGINS, ctx)
    # collector failure is recorded but plugins still run (and report info findings)
    assert any("simulated network outage" in e for e in report.errors)
    assert report.plugins_run == len(AZURE_PLUGINS)


# ── Engine plugin exception is handled ────────────────────────────────────────

@pytest.mark.asyncio
async def test_engine_handles_plugin_failure():
    bad_meta = PluginMeta(
        plugin_id="bad-plugin", cloud="azure", title="bad", category="x",
        severity=Severity.HIGH,
    )

    def bad_run(ctx):
        raise ValueError("plugin blew up")

    plugins = [(bad_meta, bad_run)]
    ctx = ScanContext(org_id="o", connection_id="c", cloud="azure")
    report = await run_scan("azure", lambda c: asyncio.sleep(0), plugins, ctx)
    assert report.plugins_run == 1
    assert any("plugin blew up" in (f.message or "") for f in report.findings)
