"""
Interactive Sandbox Session Service — Himaya Helios  (ECS Fargate Edition)

Instead of launching raw EC2 instances, we now launch pre-baked ECS Fargate tasks.
The sandbox container (helios-sandbox image) has TigerVNC + noVNC + Firefox
pre-installed — no user-data bootstrapping needed, so sessions are ready in ~45s.

Architecture:
  1. Analyst clicks "Launch Interactive Session"
  2. Backend calls ecs.run_task() with the helios-sandbox task definition
  3. ECS launches a Fargate task in the sandbox subnet with a public IP
  4. Backend polls until task is RUNNING and has a public IP
  5. noVNC URL = http://{public_ip}:6080/vnc.html?autoconnect=true&resize=scale
  6. Session auto-terminates after SANDBOX_SESSION_TIMEOUT_MINUTES (default 30)

Security isolation:
  - Tasks run in a dedicated sandbox VPC (no access to prod resources)
  - Security group allows inbound 6080 (noVNC) only
  - IAM task role: only S3 PutObject to sandbox bucket + SSM read
  - Task stops on session end; no persistent state
"""

import asyncio
import base64
import json
import logging
import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

import boto3

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
AWS_REGION          = os.getenv("AWS_DEFAULT_REGION", "uaenorth")
SANDBOX_CLUSTER     = os.getenv("SANDBOX_ECS_CLUSTER", "himaya")   # Use main cluster
SANDBOX_TASK_DEF    = os.getenv("SANDBOX_TASK_DEF", "helios-sandbox")      # ECS task definition family
SANDBOX_SG_ID       = os.getenv("SANDBOX_SG_ID", "")
SANDBOX_SUBNET      = os.getenv("SANDBOX_SUBNET_ID", "")
SANDBOX_BUCKET      = os.getenv("SANDBOX_S3_BUCKET", os.getenv("S3_BUCKET", ""))
SESSION_TIMEOUT     = int(os.getenv("SANDBOX_SESSION_TIMEOUT_MINUTES", "30"))
SANDBOX_TASK_ROLE   = os.getenv("SANDBOX_TASK_EXECUTION_ROLE_ARN", "")

# Configured if all env vars are present
SANDBOX_CONFIGURED  = bool(SANDBOX_SG_ID and SANDBOX_SUBNET)

REDIS_TTL = SESSION_TIMEOUT * 60 + 300


def _get_redis():
    import redis.asyncio as aioredis
    return aioredis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True)


def _ecs_client():
    return boto3.client("ecs", region_name=AWS_REGION)


def _ec2_client():
    return boto3.client("ec2", region_name=AWS_REGION)


async def create_sandbox_session(
    threat_id: str,
    org_id: str,
    email_html: str = "",
    email_subject: str = "Suspicious Email",
) -> dict:
    """
    Launch an ECS Fargate sandbox task and return session details.
    Returns immediately with status='launching'; poll get_session() for updates.
    """
    if not SANDBOX_CONFIGURED:
        return {
            "session_id": "",
            "status": "not_configured",
            "message": (
                "Sandbox infrastructure not configured. "
                "Set SANDBOX_SG_ID, SANDBOX_SUBNET_ID, and ensure the "
                "'helios-sandbox' ECS task definition exists."
            ),
            "setup_required": True,
        }

    session_id = str(uuid.uuid4())
    vnc_password = base64.b64encode(uuid.uuid4().bytes)[:12].decode()

    # Store email HTML in S3 and pass the S3 key — env var overrides are capped at 8192 bytes
    # and large emails (with body + attachments) exceed this limit causing InvalidParameterException
    email_s3_key = ""
    if email_html and SANDBOX_BUCKET:
        try:
            import boto3 as _boto3_s3
            _s3c = _boto3_s3.client("s3", region_name=AWS_REGION)
            email_s3_key = f"sandbox-email/{session_id}/email.html"
            _s3c.put_object(
                Bucket=SANDBOX_BUCKET,
                Key=email_s3_key,
                Body=email_html.encode("utf-8", errors="replace"),
                ContentType="text/html",
            )
            logger.info(f"Sandbox {session_id}: email HTML stored at s3://{SANDBOX_BUCKET}/{email_s3_key}")
        except Exception as _s3e:
            logger.warning(f"Sandbox: S3 email store failed, falling back to b64 truncation: {_s3e}")
            email_s3_key = ""

    # Fallback: b64 truncated to 6000 chars (safe under 8192 override limit)
    email_b64 = ""
    if not email_s3_key:
        email_b64 = base64.b64encode(email_html.encode("utf-8", errors="replace")).decode()[:6000] if email_html else ""

    timeout_at = (datetime.now(timezone.utc) + timedelta(minutes=SESSION_TIMEOUT)).isoformat()

    session = {
        "session_id":   session_id,
        "threat_id":    threat_id,
        "org_id":       org_id,
        "status":       "launching",
        "task_arn":     None,
        "public_ip":    None,
        "streaming_url": None,
        "vnc_password": vnc_password,
        "timeout_at":   timeout_at,
        "launched_at":  datetime.now(timezone.utc).isoformat(),
        "message":      "Allocating isolated Fargate task…",
    }

    r = _get_redis()
    try:
        await r.set(f"sandbox_session:{session_id}", json.dumps(session), ex=REDIS_TTL)
    finally:
        await r.aclose()

    # Launch ECS task in background
    asyncio.create_task(_launch_ecs_task(session_id, vnc_password, email_b64, email_subject, email_s3_key))

    return {k: v for k, v in session.items() if k != "vnc_password"}


async def _launch_ecs_task(session_id: str, vnc_password: str, email_b64: str, email_subject: str, email_s3_key: str = ""):
    """Background: run the ECS Fargate sandbox task and poll until public IP is available."""
    r = _get_redis()

    async def _update(patch: dict):
        raw = await r.get(f"sandbox_session:{session_id}")
        if raw:
            s = json.loads(raw)
            s.update(patch)
            await r.set(f"sandbox_session:{session_id}", json.dumps(s), ex=REDIS_TTL)

    try:
        await _update({"status": "starting", "message": "Launching Fargate task…"})

        ecs = _ecs_client()

        # Environment variables passed into the container at runtime
        # EMAIL_HTML_B64 is only set as fallback; preferred path is EMAIL_S3_KEY
        # (ECS container overrides have an 8192-byte hard limit)
        env_overrides = [
            {"name": "VNC_PASSWORD",   "value": vnc_password},
            {"name": "SESSION_ID",     "value": session_id},
            {"name": "SANDBOX_BUCKET", "value": SANDBOX_BUCKET},
        ]
        if email_s3_key:
            env_overrides.append({"name": "EMAIL_S3_KEY", "value": email_s3_key})
        elif email_b64:
            env_overrides.append({"name": "EMAIL_HTML_B64", "value": email_b64})

        network_config = {
            "awsvpcConfiguration": {
                "subnets":         [SANDBOX_SUBNET],
                "securityGroups":  [SANDBOX_SG_ID],
                "assignPublicIp":  "ENABLED",
            }
        }

        run_kwargs = {
            "cluster":        SANDBOX_CLUSTER,
            "taskDefinition": SANDBOX_TASK_DEF,
            "launchType":     "FARGATE",
            "networkConfiguration": network_config,
            "overrides": {
                "containerOverrides": [{
                    "name":        "sandbox",
                    "environment": env_overrides,
                }],
            },
            "startedBy": f"helios-sandbox-{session_id[:8]}",
            # Note: tags removed — ecs:TagResource permission causes AccessDenied
            # on RunTask when tags are present but ecs:TagResource isn't available.
        }

        loop = asyncio.get_event_loop()
        resp = await loop.run_in_executor(None, lambda: ecs.run_task(**run_kwargs))

        failures = resp.get("failures", [])
        if failures:
            raise RuntimeError(f"ECS task failed to launch: {failures[0].get('reason', 'unknown')}")

        tasks = resp.get("tasks", [])
        if not tasks:
            raise RuntimeError("ECS returned no tasks")

        task_arn = tasks[0]["taskArn"]
        await _update({
            "status":   "booting",
            "task_arn": task_arn,
            "message":  "Container starting — installing desktop environment…",
        })

        logger.info(f"Sandbox {session_id}: ECS task launched {task_arn}")

        # ── Poll for RUNNING state and public IP ──────────────────────────────
        public_ip = await _poll_task_ip(ecs, task_arn, session_id)

        if not public_ip:
            raise RuntimeError("Task started but no public IP assigned — check subnet settings")

        streaming_url = (
            f"http://{public_ip}:6080/vnc.html"
            f"?autoconnect=true&resize=scale&quality=6&path=websockify"
        )

        await _update({
            "status":        "ready",
            "public_ip":     public_ip,
            "streaming_url": streaming_url,
            "message":       "Session ready",
        })
        logger.info(f"Sandbox {session_id}: ready at {streaming_url}")

        # ── Auto-terminate after session timeout ──────────────────────────────
        await asyncio.sleep(SESSION_TIMEOUT * 60)
        logger.info(f"Sandbox {session_id}: timeout reached, terminating task")
        await _terminate_task(ecs, task_arn, session_id)
        await _update({"status": "terminated", "message": "Session timed out — task terminated"})

    except Exception as e:
        logger.error(f"Sandbox {session_id}: launch failed: {e}", exc_info=True)
        await _update({
            "status":  "error",
            "message": f"Failed to launch sandbox: {str(e)[:200]}",
        })
    finally:
        await r.aclose()


async def _poll_task_ip(ecs_client, task_arn: str, session_id: str, max_wait: int = 180) -> Optional[str]:
    """Poll ECS task until RUNNING, then resolve the public IP via ENI."""
    ec2 = _ec2_client()
    loop = asyncio.get_event_loop()
    elapsed = 0

    while elapsed < max_wait:
        await asyncio.sleep(10)
        elapsed += 10

        try:
            cluster = SANDBOX_CLUSTER
            desc = await loop.run_in_executor(
                None,
                lambda: ecs_client.describe_tasks(cluster=cluster, tasks=[task_arn])
            )
            task_list = desc.get("tasks", [])
            if not task_list:
                continue

            task = task_list[0]
            last_status = task.get("lastStatus", "PENDING")

            if last_status == "STOPPED":
                reason = task.get("stoppedReason", "unknown")
                raise RuntimeError(f"Task stopped unexpectedly: {reason}")

            if last_status != "RUNNING":
                logger.debug(f"Sandbox {session_id}: task status={last_status}, waiting…")
                continue

            # Task is RUNNING — find the ENI and its public IP
            attachments = task.get("attachments", [])
            eni_id = None
            for att in attachments:
                if att.get("type") == "ElasticNetworkInterface":
                    for detail in att.get("details", []):
                        if detail.get("name") == "networkInterfaceId":
                            eni_id = detail["value"]
                            break
                if eni_id:
                    break

            if not eni_id:
                logger.debug(f"Sandbox {session_id}: no ENI yet, waiting…")
                continue

            eni_desc = await loop.run_in_executor(
                None,
                lambda: ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])
            )
            ifaces = eni_desc.get("NetworkInterfaces", [])
            if ifaces:
                assoc = ifaces[0].get("Association", {})
                public_ip = assoc.get("PublicIp")
                if public_ip:
                    # Wait a few more seconds for noVNC to initialise inside the container
                    await asyncio.sleep(15)
                    return public_ip

        except RuntimeError:
            raise
        except Exception as e:
            logger.warning(f"Sandbox {session_id}: poll error (continuing): {e}")

    return None


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
        task_arn = session.get("task_arn")

        if task_arn:
            ecs = _ecs_client()
            await _terminate_task(ecs, task_arn, session_id)

        session["status"] = "terminated"
        session["message"] = "Session terminated by analyst"
        await r.set(f"sandbox_session:{session_id}", json.dumps(session), ex=300)
        return True
    finally:
        await r.aclose()


async def _terminate_task(ecs_client, task_arn: str, session_id: str):
    """Stop an ECS task."""
    loop = asyncio.get_event_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: ecs_client.stop_task(
                cluster=SANDBOX_CLUSTER,
                task=task_arn,
                reason=f"Helios sandbox session {session_id} ended",
            )
        )
        logger.info(f"Sandbox {session_id}: ECS task {task_arn} stopped")
    except Exception as e:
        logger.warning(f"Sandbox {session_id}: task stop failed (non-fatal): {e}")
