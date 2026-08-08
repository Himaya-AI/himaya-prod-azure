"""
Azure Container Instances Sandbox Detonation Service — Himaya

Spins an ephemeral, network-isolated-from-prod ACI container group,
detonates URLs / analyzes attachments inside it, reads findings from
container logs, then deletes the container group.

Same result contract as the legacy EC2 sandbox (EC2DetonationResult) so
callers and the triage dossier stay unchanged.
"""
import asyncio
import base64
import json
import logging
import os
import re
import uuid

from backend.config import settings
from backend.services.ec2_sandbox_service import EC2DetonationResult, _compute_verdict

logger = logging.getLogger(__name__)

# Custom Himaya detonator image (built from ./sandbox/detonator) preloaded with
# open-source analysis tooling: Playwright/Chromium (real URL detonation),
# ClamAV, YARA, oletools, pdf structural analysis, 7z/exiftool/file/strings.
DETONATOR_IMAGE  = os.getenv("DETONATOR_ACI_IMAGE", "himayaprodacr.azurecr.io/himaya-detonator:latest")
DETONATOR_CPU    = float(os.getenv("DETONATOR_ACI_CPU", "2"))
DETONATOR_MEM_GB = float(os.getenv("DETONATOR_ACI_MEMORY_GB", "4"))

# ACR pull credentials (shared with the interactive sandbox image).
ACR_SERVER   = os.getenv("SANDBOX_ACR_SERVER", "")
ACR_USERNAME = os.getenv("SANDBOX_ACR_USERNAME", "")
ACR_PASSWORD = os.getenv("SANDBOX_ACR_PASSWORD", "")

POLL_INTERVAL = 5   # seconds between container state checks
RESULTS_START = "___SANDBOX_RESULTS_START___"
RESULTS_END = "___SANDBOX_RESULTS_END___"


def _build_job(urls: list, attachments: list) -> str:
    """Base64-encode the detonation job (urls + attachment SAS URLs) for the
    container to read from the DETONATION_JOB env var."""
    job = {
        "urls": [u for u in (urls or []) if isinstance(u, str) and u.startswith("http")],
        "attachments": [
            {"name": a.get("name", "attachment"), "url": a.get("url", "")}
            for a in (attachments or [])
            if isinstance(a, dict) and a.get("url")
        ],
    }
    return base64.b64encode(json.dumps(job).encode()).decode()


async def detonate_in_aci(
    threat_id: str,
    urls: list,
    attachment_names: list,
    attachment_data: dict,
    org_id: str,
    timeout_seconds: int = 180,
    attachments: list = None,
) -> EC2DetonationResult:
    """
    Main entry point: launch an ephemeral ACI container group running the Himaya
    detonator image, which detonates URLs in real Chromium and analyzes
    attachment bytes with ClamAV/YARA/oletools/pdf/7z, parse the results from
    the container logs, then delete the group.

    `attachments` is a list of {"name", "url"} where url is a short-lived SAS the
    container downloads. `attachment_names` remains for metadata-only fallback.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.containerinstance import ContainerInstanceManagementClient
        from azure.mgmt.containerinstance.models import (
            Container,
            ContainerGroup,
            ContainerGroupRestartPolicy,
            EnvironmentVariable,
            ImageRegistryCredential,
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

        job_b64 = _build_job(urls, attachments or [])
        env_vars = [
            EnvironmentVariable(name="THREAT_ID", value=threat_id),
            EnvironmentVariable(name="DETONATION_JOB", secure_value=job_b64),
        ]

        # Private ACR pull credentials for the detonator image.
        image_host = DETONATOR_IMAGE.split("/", 1)[0]
        acr_server = ACR_SERVER or (image_host if ".azurecr.io" in image_host else "")
        registry_creds = []
        if acr_server and ACR_USERNAME and ACR_PASSWORD:
            registry_creds.append(ImageRegistryCredential(
                server=acr_server, username=ACR_USERNAME, password=ACR_PASSWORD,
            ))
        elif ".azurecr.io" in image_host:
            logger.warning(
                "aci_sandbox: detonator image is on private ACR but "
                "SANDBOX_ACR_USERNAME/PASSWORD are unset — image pull will fail."
            )

        container = Container(
            name="detonator",
            image=DETONATOR_IMAGE,
            resources=ResourceRequirements(
                requests=ResourceRequests(cpu=DETONATOR_CPU, memory_in_gb=DETONATOR_MEM_GB)
            ),
            environment_variables=env_vars,
        )
        group = ContainerGroup(
            location=settings.AZURE_REGION,
            containers=[container],
            os_type=OperatingSystemTypes.LINUX,
            restart_policy=ContainerGroupRestartPolicy.NEVER,
            image_registry_credentials=registry_creds or None,
        )

        _n_att = len(attachments or []) or len(attachment_names or [])
        logger.info(f"aci_sandbox: launching {group_name} image={DETONATOR_IMAGE} (urls={len(urls)}, attachments={_n_att})")
        poller = await asyncio.to_thread(
            client.container_groups.begin_create_or_update, rg, group_name, group
        )
        # Detonator image is large (~2 GB) — allow time for the first pull.
        await asyncio.to_thread(poller.result, 300)

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
