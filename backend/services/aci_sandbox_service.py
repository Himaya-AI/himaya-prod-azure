"""
Azure Container Instances Sandbox Detonation Service — Himaya

Spins an ephemeral, network-isolated-from-prod ACI container group,
detonates URLs / analyzes attachments inside it, reads findings from
container logs, then deletes the container group.

Same result contract as the legacy EC2 sandbox (EC2DetonationResult) so
callers and the triage dossier stay unchanged.
"""
import asyncio
import json
import logging
import re
import uuid

from backend.config import settings
from backend.services.ec2_sandbox_service import EC2DetonationResult, _compute_verdict

logger = logging.getLogger(__name__)

SANDBOX_IMAGE = "python:3.12-slim"
POLL_INTERVAL = 5   # seconds between container state checks
RESULTS_START = "___SANDBOX_RESULTS_START___"
RESULTS_END = "___SANDBOX_RESULTS_END___"


def _build_detonation_script(urls: list, attachment_filenames: list) -> str:
    """Pure-stdlib Python detonation script executed inside the ACI container."""
    return f"""
import json, re, ssl, urllib.request

URLS = {json.dumps(urls)}
ATTACHMENTS = {json.dumps(attachment_filenames)}

url_results = []
attachment_results = []

class RedirectRecorder(urllib.request.HTTPRedirectHandler):
    chain = []
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        RedirectRecorder.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

for url in URLS:
    result = {{
        "url": url, "status_code": None, "redirect_chain": [],
        "final_url": "", "page_snippet": "", "suspicious_indicators": [], "error": "",
    }}
    RedirectRecorder.chain = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(
            RedirectRecorder, urllib.request.HTTPSHandler(context=ctx)
        )
        req = urllib.request.Request(url, headers={{"User-Agent": "Mozilla/5.0"}})
        resp = opener.open(req, timeout=15)
        result["status_code"] = resp.status
        result["final_url"] = resp.geturl()
        result["redirect_chain"] = list(RedirectRecorder.chain)
        body = resp.read(2048).decode("utf-8", errors="ignore")
        result["page_snippet"] = body[:500]

        indicators = []
        body_lower = body.lower()
        if any(kw in body_lower for kw in ["login", "password", "credential", "verify your account"]):
            indicators.append("credential-harvesting-page")
        if any(kw in body_lower for kw in ["download", ".exe", ".zip", "payload"]):
            indicators.append("payload-delivery-page")
        if len(result["redirect_chain"]) > 2:
            indicators.append("redirect-chain-length-" + str(len(result["redirect_chain"])))
        domain = re.search(r"https?://([^/]+)", result["final_url"] or url)
        if domain:
            d = domain.group(1)
            if re.search(r"\\d{{4,}}", d) or len(d) > 40:
                indicators.append("suspicious-domain-pattern")
        result["suspicious_indicators"] = indicators
    except Exception as e:
        result["error"] = str(e)[:300]
    url_results.append(result)

MACRO_EXTS = {{".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}}
HIGH_RISK_EXTS = {{".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".pif"}}

for filename in ATTACHMENTS:
    result = {{
        "filename": filename, "file_type": "", "strings_preview": "",
        "macro_detected": False, "macro_vba_snippet": "", "error": "",
    }}
    ext = ("." + filename.rsplit(".", 1)[-1]).lower() if "." in filename else ""
    result["file_type"] = ext
    if ext in MACRO_EXTS:
        result["macro_detected"] = True
        result["macro_vba_snippet"] = "Macro-enabled Office format detected: " + ext
    elif ext in HIGH_RISK_EXTS:
        result["strings_preview"] = "High-risk executable/script extension: " + ext
    attachment_results.append(result)

print("{RESULTS_START}")
print(json.dumps({{"url_results": url_results, "attachment_results": attachment_results}}))
print("{RESULTS_END}")
"""


async def detonate_in_aci(
    threat_id: str,
    urls: list,
    attachment_names: list,
    attachment_data: dict,
    org_id: str,
    timeout_seconds: int = 120,
) -> EC2DetonationResult:
    """
    Main entry point: launch an ephemeral ACI container group, run URL /
    attachment detonation inside it, parse results from logs, delete the group.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.containerinstance import ContainerInstanceManagementClient
        from azure.mgmt.containerinstance.models import (
            Container,
            ContainerGroup,
            ContainerGroupRestartPolicy,
            EnvironmentVariable,
            OperatingSystemTypes,
            ResourceRequests,
            ResourceRequirements,
        )
    except ImportError:
        logger.warning("aci_sandbox: azure-mgmt-containerinstance not available — skipping detonation")
        return EC2DetonationResult(error="azure-mgmt-containerinstance not available", verdict="UNAVAILABLE")

    if not settings.AZURE_SUBSCRIPTION_ID:
        logger.warning("aci_sandbox: AZURE_SUBSCRIPTION_ID not configured — skipping detonation")
        return EC2DetonationResult(error="AZURE_SUBSCRIPTION_ID not configured", verdict="UNAVAILABLE")

    group_name = f"himaya-sandbox-{uuid.uuid4().hex[:12]}"
    rg = settings.AZURE_RESOURCE_GROUP

    def _make_client():
        cred = DefaultAzureCredential(
            managed_identity_client_id=settings.AZURE_CLIENT_ID or None
        )
        return ContainerInstanceManagementClient(cred, settings.AZURE_SUBSCRIPTION_ID)

    client = None
    try:
        client = await asyncio.to_thread(_make_client)

        script = _build_detonation_script(urls, attachment_names)
        container = Container(
            name="detonator",
            image=SANDBOX_IMAGE,
            command=["python", "-c", script],
            resources=ResourceRequirements(
                requests=ResourceRequests(cpu=0.5, memory_in_gb=0.5)
            ),
            environment_variables=[EnvironmentVariable(name="THREAT_ID", value=threat_id)],
        )
        group = ContainerGroup(
            location=settings.AZURE_REGION,
            containers=[container],
            os_type=OperatingSystemTypes.LINUX,
            restart_policy=ContainerGroupRestartPolicy.NEVER,
        )

        logger.info(f"aci_sandbox: launching {group_name} (urls={len(urls)}, attachments={len(attachment_names)})")
        poller = await asyncio.to_thread(
            client.container_groups.begin_create_or_update, rg, group_name, group
        )
        await asyncio.to_thread(poller.result, 60)

        # Poll until the container terminates or timeout
        raw: dict = {}
        elapsed = 0
        while elapsed < timeout_seconds:
            await asyncio.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            cg = await asyncio.to_thread(client.container_groups.get, rg, group_name)
            states = [
                c.instance_view.current_state.state if c.instance_view and c.instance_view.current_state else ""
                for c in (cg.containers or [])
            ]
            if states and all(s == "Terminated" for s in states):
                break

        logs = await asyncio.to_thread(
            client.containers.list_logs, rg, group_name, "detonator"
        )
        content = logs.content or ""
        match = re.search(
            re.escape(RESULTS_START) + r"\s*(\{.*?\})\s*" + re.escape(RESULTS_END),
            content,
            re.DOTALL,
        )
        if match:
            raw = json.loads(match.group(1))
        else:
            logger.warning(f"aci_sandbox: no results marker in logs for {group_name}")
            return EC2DetonationResult(
                error="sandbox produced no results (timeout or crash)", verdict="UNAVAILABLE"
            )

        verdict = _compute_verdict(raw)
        logger.info(f"aci_sandbox: {group_name} verdict={verdict}")
        return EC2DetonationResult(
            verdict=verdict,
            urls_detonated=urls,
            url_results=raw.get("url_results", []),
            attachment_results=raw.get("attachment_results", []),
            raw_json=raw,
            instance_id=group_name,
        )
    except Exception as e:
        logger.warning(f"aci_sandbox: detonation failed for {threat_id}: {e}")
        return EC2DetonationResult(error=str(e)[:300], verdict="UNAVAILABLE")
    finally:
        if client is not None:
            try:
                await asyncio.to_thread(
                    client.container_groups.begin_delete, rg, group_name
                )
            except Exception as _del_err:
                logger.warning(f"aci_sandbox: cleanup of {group_name} failed: {_del_err}")
