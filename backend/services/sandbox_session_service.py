"""
Interactive Sandbox Session Service — Himaya  (Azure ACI Edition)

Launches an ephemeral Azure Container Instances (ACI) container group running a
noVNC desktop so analysts can interact with a suspicious email's links in a
throwaway isolated browser, streamed to the browser over noVNC.

Architecture:
  1. Analyst clicks "Launch Interactive Session"
  2. Backend creates an ACI container group (SANDBOX_ACI_IMAGE) with a public IP
     + DNS label, exposing port 6080 (noVNC).
  3. Backend polls until the group is Running and the FQDN/IP is assigned.
  4. noVNC URL = http://{fqdn}:6080/vnc.html?autoconnect=true&resize=scale
  5. Session auto-terminates after SANDBOX_SESSION_TIMEOUT_MINUTES (default 30),
     deleting the container group.

Isolation:
  - Ephemeral container group with only a public IP + outbound internet; no VNet
    attachment, so no access to prod private resources. Deleted on session end.

Image:
  - SANDBOX_ACI_IMAGE (env) defaults to a public noVNC desktop image so the
    feature works out of the box. A custom image can pre-render the email HTML
    via the EMAIL_HTML_B64 env var.
"""

import asyncio
import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from backend.config import settings

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
# Public noVNC desktop image. A custom image can pre-render the email via the
# EMAIL_HTML_B64 env var; the default public image gives an isolated Firefox
# desktop the analyst drives manually. Override with SANDBOX_ACI_IMAGE.
SANDBOX_ACI_IMAGE  = os.getenv("SANDBOX_ACI_IMAGE", "dorowu/ubuntu-desktop-lxde-vnc:latest")
SANDBOX_NOVNC_PORT = int(os.getenv("SANDBOX_NOVNC_PORT", "6080"))
SESSION_TIMEOUT    = int(os.getenv("SANDBOX_SESSION_TIMEOUT_MINUTES", "30"))
SANDBOX_CPU        = float(os.getenv("SANDBOX_ACI_CPU", "1"))
SANDBOX_MEM_GB     = float(os.getenv("SANDBOX_ACI_MEMORY_GB", "2"))

# Configured when we have an Azure subscription to launch ACI into.
SANDBOX_CONFIGURED = bool(settings.AZURE_SUBSCRIPTION_ID)

REDIS_TTL = SESSION_TIMEOUT * 60 + 300


def _get_redis():
    import redis.asyncio as aioredis
    return aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)


def _make_aci_client():
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.containerinstance import ContainerInstanceManagementClient
    cred = DefaultAzureCredential(managed_identity_client_id=settings.AZURE_CLIENT_ID or None)
    return ContainerInstanceManagementClient(cred, settings.AZURE_SUBSCRIPTION_ID)


async def create_sandbox_session(
    threat_id: str,
    org_id: str,
    email_html: str = "",
    email_subject: str = "Suspicious Email",
) -> dict:
    """
    Launch an Azure ACI noVNC sandbox and return session details.
    Returns immediately with status='launching'; poll get_session() for updates.
    """
    if not SANDBOX_CONFIGURED:
        return {
            "session_id": "",
            "status": "not_configured",
            "message": (
                "Sandbox not configured. Set AZURE_SUBSCRIPTION_ID (and optionally "
                "SANDBOX_ACI_IMAGE) so Himaya can launch the isolated Azure sandbox."
            ),
            "setup_required": True,
        }

    session_id = str(uuid.uuid4())
    vnc_password = base64.b64encode(uuid.uuid4().bytes)[:12].decode()
    email_b64 = (
        base64.b64encode(email_html.encode("utf-8", errors="replace")).decode()[:6000]
        if email_html else ""
    )

    timeout_at = (datetime.now(timezone.utc) + timedelta(minutes=SESSION_TIMEOUT)).isoformat()

    session = {
        "session_id":   session_id,
        "threat_id":    threat_id,
        "org_id":       org_id,
        "status":       "launching",
        "container_group": None,
        "public_ip":    None,
        "streaming_url": None,
        "vnc_password": vnc_password,
        "timeout_at":   timeout_at,
        "launched_at":  datetime.now(timezone.utc).isoformat(),
        "message":      "Allocating isolated Azure sandbox…",
    }

    r = _get_redis()
    try:
        await r.set(f"sandbox_session:{session_id}", json.dumps(session), ex=REDIS_TTL)
    finally:
        await r.aclose()

    # Launch ACI container group in background
    asyncio.create_task(_launch_aci_session(session_id, vnc_password, email_b64, email_subject))

    return {k: v for k, v in session.items() if k != "vnc_password"}


async def _launch_aci_session(session_id: str, vnc_password: str, email_b64: str, email_subject: str):
    """Background: create an ACI noVNC container group and poll until the endpoint is live."""
    r = _get_redis()

    async def _update(patch: dict):
        raw = await r.get(f"sandbox_session:{session_id}")
        if raw:
            s = json.loads(raw)
            s.update(patch)
            await r.set(f"sandbox_session:{session_id}", json.dumps(s), ex=REDIS_TTL)

    group_name = f"himaya-sandbox-{session_id[:8]}"
    rg = settings.AZURE_RESOURCE_GROUP
    dns_label = f"himaya-sbx-{session_id[:8]}"
    client = None
    try:
        from azure.mgmt.containerinstance.models import (
            Container, ContainerGroup, ContainerGroupNetworkProtocol,
            ContainerGroupRestartPolicy, ContainerPort, EnvironmentVariable,
            IpAddress, OperatingSystemTypes, Port, ResourceRequests, ResourceRequirements,
        )

        await _update({"status": "starting", "message": "Launching isolated Azure sandbox…"})
        client = await asyncio.to_thread(_make_aci_client)

        env_vars = [
            EnvironmentVariable(name="VNC_PW", value=vnc_password),
            EnvironmentVariable(name="VNC_PASSWORD", value=vnc_password),
            EnvironmentVariable(name="SESSION_ID", value=session_id),
        ]
        if email_b64:
            env_vars.append(EnvironmentVariable(name="EMAIL_HTML_B64", value=email_b64))

        container = Container(
            name="sandbox",
            image=SANDBOX_ACI_IMAGE,
            resources=ResourceRequirements(
                requests=ResourceRequests(cpu=SANDBOX_CPU, memory_in_gb=SANDBOX_MEM_GB)
            ),
            ports=[ContainerPort(port=SANDBOX_NOVNC_PORT)],
            environment_variables=env_vars,
        )
        group = ContainerGroup(
            location=settings.AZURE_REGION,
            containers=[container],
            os_type=OperatingSystemTypes.LINUX,
            restart_policy=ContainerGroupRestartPolicy.NEVER,
            ip_address=IpAddress(
                type="Public",
                dns_name_label=dns_label,
                ports=[Port(protocol=ContainerGroupNetworkProtocol.TCP, port=SANDBOX_NOVNC_PORT)],
            ),
        )

        await _update({
            "status": "booting",
            "container_group": group_name,
            "message": "Container starting — booting sandbox desktop…",
        })
        logger.info(f"Sandbox {session_id}: creating ACI group {group_name}")
        poller = await asyncio.to_thread(
            client.container_groups.begin_create_or_update, rg, group_name, group
        )
        await asyncio.to_thread(poller.result, 120)

        # Poll until the group has a public IP and the container is Running
        public_ip = None
        fqdn = None
        elapsed = 0
        max_wait = 300
        while elapsed < max_wait:
            await asyncio.sleep(10)
            elapsed += 10
            cg = await asyncio.to_thread(client.container_groups.get, rg, group_name)
            ipaddr = getattr(cg, "ip_address", None)
            if ipaddr and getattr(ipaddr, "ip", None):
                public_ip = ipaddr.ip
                fqdn = getattr(ipaddr, "fqdn", None) or public_ip
            csts = [
                (c.instance_view.current_state.state
                 if c.instance_view and c.instance_view.current_state else "")
                for c in (cg.containers or [])
            ]
            if csts and all(s == "Terminated" for s in csts):
                raise RuntimeError("Sandbox container terminated during startup")
            if public_ip and csts and any(s == "Running" for s in csts):
                break

        if not public_ip:
            raise RuntimeError("Sandbox started but no public IP was assigned")

        host = fqdn or public_ip
        # Give noVNC a few seconds to bind inside the container
        await asyncio.sleep(15)
        streaming_url = (
            f"http://{host}:{SANDBOX_NOVNC_PORT}/vnc.html"
            f"?autoconnect=true&resize=scale&password={vnc_password}"
        )
        await _update({
            "status":        "ready",
            "public_ip":     public_ip,
            "streaming_url": streaming_url,
            "message":       "Session ready",
        })
        logger.info(f"Sandbox {session_id}: ready at {streaming_url}")

        # Auto-terminate after session timeout
        await asyncio.sleep(SESSION_TIMEOUT * 60)
        logger.info(f"Sandbox {session_id}: timeout reached, destroying sandbox")
        await _delete_group(client, rg, group_name, session_id)
        await _update({"status": "terminated", "message": "Session timed out — sandbox destroyed"})

    except Exception as e:
        logger.error(f"Sandbox {session_id}: launch failed: {e}", exc_info=True)
        await _update({
            "status":  "error",
            "message": f"Failed to launch sandbox: {str(e)[:200]}",
        })
        if client is not None:
            await _delete_group(client, rg, group_name, session_id)
    finally:
        await r.aclose()


async def get_session(session_id: str) -> Optional[dict]:
    r = _get_redis()
    try:
        raw = await r.get(f"sandbox_session:{session_id}")
        if not raw:
            return None
        return json.loads(raw)
    finally:
        await r.aclose()


async def terminate_session(session_id: str) -> bool:
    r = _get_redis()
    try:
        raw = await r.get(f"sandbox_session:{session_id}")
        if not raw:
            return False

        session = json.loads(raw)
        group_name = session.get("container_group")

        if group_name and SANDBOX_CONFIGURED:
            try:
                client = await asyncio.to_thread(_make_aci_client)
                await _delete_group(client, settings.AZURE_RESOURCE_GROUP, group_name, session_id)
            except Exception as _e:
                logger.warning(f"Sandbox {session_id}: ACI delete failed (non-fatal): {_e}")

        session["status"] = "terminated"
        session["message"] = "Session terminated by analyst"
        await r.set(f"sandbox_session:{session_id}", json.dumps(session), ex=300)
        return True
    finally:
        await r.aclose()


async def _delete_group(client, rg: str, group_name: str, session_id: str):
    """Delete an ACI container group (ephemeral sandbox teardown)."""
    try:
        await asyncio.to_thread(client.container_groups.begin_delete, rg, group_name)
        logger.info(f"Sandbox {session_id}: ACI group {group_name} deleted")
    except Exception as e:
        logger.warning(f"Sandbox {session_id}: ACI delete failed (non-fatal): {e}")
