"""
EC2 Sandbox Detonation Service — Helios

Spins an ephemeral EC2 instance, detonates URLs/attachments inside it,
captures findings, uploads to S3, then terminates the instance.
"""
import asyncio
import json
import logging
import os
import base64
from dataclasses import dataclass, field
from typing import Optional
import time

logger = logging.getLogger(__name__)

REGION = "us-west-2"
S3_BUCKET = "himaya-evidence"
SG_NAME = "helios-sandbox-sg"
INSTANCE_TYPE = "t3.micro"
POLL_INTERVAL = 10  # seconds between state checks
MAX_WAIT = 180  # seconds max to wait for termination


@dataclass
class UrlDetonationResult:
    url: str
    status_code: Optional[int] = None
    redirect_chain: list = field(default_factory=list)
    final_url: str = ""
    page_snippet: str = ""
    suspicious_indicators: list = field(default_factory=list)
    error: str = ""


@dataclass
class AttachmentDetonationResult:
    filename: str
    file_type: str = ""
    strings_preview: str = ""
    macro_detected: bool = False
    macro_vba_snippet: str = ""
    error: str = ""


@dataclass
class EC2DetonationResult:
    verdict: str = "UNAVAILABLE"
    urls_detonated: list = field(default_factory=list)
    url_results: list = field(default_factory=list)
    attachment_results: list = field(default_factory=list)
    raw_json: dict = field(default_factory=dict)
    instance_id: str = ""
    error: str = ""


# ── Internal helpers ──────────────────────────────────────────────────────────

def _get_or_create_sandbox_sg(ec2_client, vpc_id: str = "") -> str:
    """Get or create the helios-sandbox-sg security group (outbound only)."""
    # Try to find existing SG — filter by VPC if known to avoid cross-VPC mismatch
    try:
        filters = [{"Name": "group-name", "Values": [SG_NAME]}]
        if vpc_id:
            filters.append({"Name": "vpc-id", "Values": [vpc_id]})
        resp = ec2_client.describe_security_groups(Filters=filters)
        groups = resp.get("SecurityGroups", [])
        if groups:
            sg_id = groups[0]["GroupId"]
            logger.debug(f"ec2_sandbox: reusing existing SG {sg_id}")
            return sg_id
    except Exception as e:
        logger.debug(f"ec2_sandbox: describe_security_groups failed: {e}")

    # Create new SG — outbound-only (no inbound rules)
    try:
        create_resp = ec2_client.create_security_group(
            GroupName=SG_NAME,
            Description="Helios sandbox - outbound only",
        )
        sg_id = create_resp["GroupId"]

        # Allow all outbound traffic
        ec2_client.authorize_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",  # all protocols
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        logger.info(f"ec2_sandbox: created sandbox SG {sg_id}")
        return sg_id
    except Exception as e:
        logger.warning(f"ec2_sandbox: could not create SG: {e}")
        # Fall back to default SG (still functional, just not isolated)
        try:
            default = ec2_client.describe_security_groups(
                Filters=[{"Name": "group-name", "Values": ["default"]}]
            )
            return default["SecurityGroups"][0]["GroupId"]
        except Exception:
            raise RuntimeError(f"Cannot resolve sandbox security group: {e}")


def _get_latest_al2023_ami(ec2_client) -> str:
    """Resolve latest Amazon Linux 2023 x86_64 AMI ID."""
    try:
        resp = ec2_client.describe_images(
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
            Owners=["amazon"],
        )
        images = resp.get("Images", [])
        if not images:
            raise ValueError("No AL2023 AMIs found")
        # Sort by creation date, newest first
        images.sort(key=lambda x: x.get("CreationDate", ""), reverse=True)
        ami_id = images[0]["ImageId"]
        logger.debug(f"ec2_sandbox: resolved AL2023 AMI {ami_id}")
        return ami_id
    except Exception as e:
        logger.warning(f"ec2_sandbox: AMI lookup failed, using fallback: {e}")
        return "ami-0250adf05ecc45684"  # us-west-2 AL2023 fallback (2023.11.20260413)


def _build_userdata(urls: list, attachment_filenames: list, threat_id: str) -> str:
    """
    Build the bash UserData script for the EC2 instance.
    The script:
      1. Installs python3-pip, curl, wget, oletools
      2. Detonates each URL via curl (captures status code, redirect chain, page snippet)
      3. Runs basic attachment analysis on filenames (extensions, macro hints)
      4. Writes /tmp/sandbox_results.json
      5. Uploads to S3
      6. Shuts down the instance
    Returns a base64-encoded string as required by the EC2 API.
    """
    # Escape URLs for bash injection safety
    safe_urls = [u.replace("'", "'\\''") for u in urls]
    safe_attachments = [a.replace("'", "'\\''") for a in attachment_filenames]

    urls_bash = " ".join(f"'{u}'" for u in safe_urls)
    attachments_bash = " ".join(f"'{a}'" for a in safe_attachments)

    script = f"""#!/bin/bash
set -e
exec > /var/log/helios-sandbox.log 2>&1

# 1. Install dependencies
yum install -y python3-pip curl wget 2>/dev/null || true
pip3 install oletools 2>/dev/null || true

THREAT_ID="{threat_id}"
RESULTS_FILE="/tmp/sandbox_results.json"

# Initialise results structure
python3 - << 'PYEOF'
import json, subprocess, re, os

url_results = []
attachment_results = []

URLS = {json.dumps(urls)}
ATTACHMENTS = {json.dumps(attachment_filenames)}

# ── URL detonation ──────────────────────────────────────────────────────────
for url in URLS:
    result = {{
        "url": url,
        "status_code": None,
        "redirect_chain": [],
        "final_url": "",
        "page_snippet": "",
        "suspicious_indicators": [],
        "error": "",
    }}
    try:
        proc = subprocess.run(
            ["curl", "-Lv", "--max-time", "15", "--user-agent", "Mozilla/5.0",
             "-w", "\\n__STATUS__:%{{http_code}}\\n__FINAL__:%{{url_effective}}\\n",
             "-o", "/tmp/page_body.html", url],
            capture_output=True, text=True, timeout=20
        )
        stderr = proc.stderr or ""
        stdout = proc.stdout or ""

        # Parse status code
        status_match = re.search(r"__STATUS__:(\\d+)", stdout)
        if status_match:
            result["status_code"] = int(status_match.group(1))

        # Parse final URL
        final_match = re.search(r"__FINAL__:(.*)", stdout)
        if final_match:
            result["final_url"] = final_match.group(1).strip()

        # Extract redirect chain from verbose output
        redirect_chain = re.findall(r"Location: (https?://[^\\r\\n]+)", stderr, re.IGNORECASE)
        result["redirect_chain"] = redirect_chain

        # Page snippet (first 500 chars)
        if os.path.exists("/tmp/page_body.html"):
            with open("/tmp/page_body.html", "r", errors="ignore") as f:
                result["page_snippet"] = f.read(500)

        # Suspicious indicators heuristics
        indicators = []
        body_lower = result["page_snippet"].lower()
        if any(kw in body_lower for kw in ["login", "password", "credential", "verify your account"]):
            indicators.append("credential-harvesting-page")
        if any(kw in body_lower for kw in ["download", ".exe", ".zip", "payload"]):
            indicators.append("payload-delivery-page")
        if len(redirect_chain) > 2:
            indicators.append(f"redirect-chain-length-{{len(redirect_chain)}}")
        if result["status_code"] and result["status_code"] in (200, 301, 302):
            domain = re.search(r"https?://([^/]+)", result["final_url"] or url)
            if domain:
                d = domain.group(1)
                if re.search(r"\\d{{4,}}", d) or len(d) > 40:
                    indicators.append("suspicious-domain-pattern")
        result["suspicious_indicators"] = indicators

    except Exception as e:
        result["error"] = str(e)

    url_results.append(result)

# ── Attachment analysis ─────────────────────────────────────────────────────
MACRO_EXTS = {{".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}}
HIGH_RISK_EXTS = {{".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".pif"}}

for filename in ATTACHMENTS:
    result = {{
        "filename": filename,
        "file_type": "",
        "strings_preview": "",
        "macro_detected": False,
        "macro_vba_snippet": "",
        "error": "",
    }}
    try:
        ext = ("." + filename.rsplit(".", 1)[-1]).lower() if "." in filename else ""
        result["file_type"] = ext

        if ext in MACRO_EXTS:
            result["macro_detected"] = True
            result["macro_vba_snippet"] = f"Macro-enabled Office format detected: {{ext}}"
        elif ext in HIGH_RISK_EXTS:
            result["macro_detected"] = False
            result["strings_preview"] = f"High-risk executable/script extension: {{ext}}"
    except Exception as e:
        result["error"] = str(e)

    attachment_results.append(result)

# Write results
with open("/tmp/sandbox_results.json", "w") as f:
    json.dump({{"url_results": url_results, "attachment_results": attachment_results}}, f)

print("Sandbox analysis complete.")
PYEOF

# 5. Upload results to S3
aws s3 cp "$RESULTS_FILE" "s3://{S3_BUCKET}/ec2-sandbox/{threat_id}/results.json" 2>/dev/null || true

# 6. Shut down
shutdown -h now
"""

    encoded = base64.b64encode(script.encode("utf-8")).decode("utf-8")
    return encoded


def _resolve_instance_profile() -> Optional[dict]:
    """Return IamInstanceProfile dict if helios-sandbox-role exists, else None."""
    try:
        import boto3
        iam = boto3.client("iam")
        iam.get_instance_profile(InstanceProfileName="helios-sandbox-role")
        logger.debug("ec2_sandbox: found helios-sandbox-role instance profile")
        return {"Name": "helios-sandbox-role"}
    except Exception as e:
        logger.warning(
            f"ec2_sandbox: helios-sandbox-role instance profile not found "
            f"(EC2 won't have S3 write access without it): {e}"
        )
        return None


def _compute_verdict(raw: dict) -> str:
    """
    Derive a verdict string from the results JSON.
    - MALICIOUS: any URL hit (200/301/302) with suspicious_indicators, OR any macro attachment
    - CLEAN:     results present, nothing suspicious
    - TIMEOUT:   results unavailable / parse failure
    """
    url_results = raw.get("url_results", [])
    attachment_results = raw.get("attachment_results", [])

    for ur in url_results:
        if ur.get("status_code") in (200, 301, 302) and ur.get("suspicious_indicators"):
            return "MALICIOUS"

    for ar in attachment_results:
        if ar.get("macro_detected"):
            return "MALICIOUS"

    if url_results or attachment_results:
        return "CLEAN"

    return "TIMEOUT"


# ── Main entry point ──────────────────────────────────────────────────────────

async def detonate_in_ec2(
    threat_id: str,
    urls: list,
    attachment_names: list,
    attachment_data: dict,
    org_id: str,
    timeout_seconds: int = 120,
) -> EC2DetonationResult:
    """
    Main entry point: launch an ephemeral EC2 instance, run URL/attachment
    detonation inside it, wait for completion, fetch S3 results, return findings.

    All boto3 calls are dispatched via asyncio.to_thread to avoid blocking the
    event loop.
    """
    # 1. Check boto3 availability
    try:
        import boto3
    except ImportError:
        logger.warning("ec2_sandbox: boto3 not available — skipping sandbox detonation")
        return EC2DetonationResult(error="boto3 not available", verdict="UNAVAILABLE")

    instance_id: Optional[str] = None

    try:
        # 2. Get EC2 client
        ec2 = await asyncio.to_thread(boto3.client, "ec2", region_name=REGION)

        # 3. Get/create security group — pass VPC from env or resolve from subnet
        _subnet_id = os.getenv("SANDBOX_SUBNET_ID", "")
        _vpc_id = ""
        if _subnet_id:
            try:
                _sn = await asyncio.to_thread(
                    lambda: boto3.client("ec2", region_name=REGION).describe_subnets(SubnetIds=[_subnet_id])
                )
                _vpc_id = _sn["Subnets"][0]["VpcId"]
            except Exception:
                pass
        sg_id = await asyncio.to_thread(_get_or_create_sandbox_sg, ec2, _vpc_id)

        # 4. Get latest AL2023 AMI
        ami_id = await asyncio.to_thread(_get_latest_al2023_ami, ec2)

        # 5. Resolve instance profile
        instance_profile = await asyncio.to_thread(_resolve_instance_profile)

        # 6. Build UserData
        userdata = _build_userdata(
            urls=list(urls or []),
            attachment_filenames=list(attachment_names or []),
            threat_id=threat_id,
        )

        # 7. Launch instance (On-Demand, no Spot for reliability)
        launch_kwargs: dict = {
            "ImageId": ami_id,
            "InstanceType": INSTANCE_TYPE,
            "MinCount": 1,
            "MaxCount": 1,
            "SecurityGroupIds": [sg_id],
            "UserData": userdata,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": f"helios-sandbox-{threat_id[:8]}"},
                        {"Key": "helios:threat_id", "Value": threat_id},
                        {"Key": "helios:org_id", "Value": org_id},
                        {"Key": "helios:role", "Value": "sandbox-detonation"},
                    ],
                }
            ],
        }
        if instance_profile:
            launch_kwargs["IamInstanceProfile"] = instance_profile
        if _subnet_id:
            launch_kwargs["SubnetId"] = _subnet_id  # pin to correct VPC subnet

        logger.info(
            f"ec2_sandbox: launching {INSTANCE_TYPE} instance for threat={threat_id} "
            f"ami={ami_id} sg={sg_id}"
        )
        run_resp = await asyncio.to_thread(ec2.run_instances, **launch_kwargs)

        instance_id = run_resp["Instances"][0]["InstanceId"]
        logger.info(f"ec2_sandbox: launched instance {instance_id} for threat={threat_id}")

        # 8. Wait loop — poll until terminated/stopped or timeout
        deadline = time.monotonic() + min(timeout_seconds, MAX_WAIT)
        final_state = "unknown"

        while time.monotonic() < deadline:
            await asyncio.sleep(POLL_INTERVAL)
            try:
                desc = await asyncio.to_thread(
                    ec2.describe_instances,
                    InstanceIds=[instance_id],
                )
                state = (
                    desc["Reservations"][0]["Instances"][0]["State"]["Name"]
                )
                logger.debug(f"ec2_sandbox: instance {instance_id} state={state}")
                if state in ("terminated", "stopped"):
                    final_state = state
                    break
            except Exception as poll_err:
                logger.debug(f"ec2_sandbox: poll error (non-fatal): {poll_err}")

        logger.info(
            f"ec2_sandbox: instance {instance_id} finished with state={final_state} "
            f"for threat={threat_id}"
        )

        # 9. Fetch results from S3
        s3 = await asyncio.to_thread(boto3.client, "s3", region_name=REGION)
        s3_key = f"ec2-sandbox/{threat_id}/results.json"

        try:
            s3_resp = await asyncio.to_thread(
                s3.get_object,
                Bucket=S3_BUCKET,
                Key=s3_key,
            )
            raw_body = s3_resp["Body"].read()
            raw_json = json.loads(raw_body)
            logger.info(
                f"ec2_sandbox: fetched results from s3://{S3_BUCKET}/{s3_key} "
                f"for threat={threat_id}"
            )
        except Exception as s3_err:
            logger.warning(
                f"ec2_sandbox: failed to read S3 results for threat={threat_id}: {s3_err}"
            )
            return EC2DetonationResult(
                verdict="TIMEOUT",
                instance_id=instance_id,
                error=f"S3 results unavailable: {s3_err}",
            )

        # 10. Parse results and compute verdict
        url_results = raw_json.get("url_results", [])
        attachment_results = raw_json.get("attachment_results", [])
        verdict = _compute_verdict(raw_json)

        return EC2DetonationResult(
            verdict=verdict,
            urls_detonated=list(urls or []),
            url_results=url_results,
            attachment_results=attachment_results,
            raw_json=raw_json,
            instance_id=instance_id,
            error="",
        )

    except Exception as e:
        logger.error(
            f"ec2_sandbox: detonate_in_ec2 failed for threat={threat_id}: {e}",
            exc_info=True,
        )
        return EC2DetonationResult(
            verdict="UNAVAILABLE",
            instance_id=instance_id or "",
            error=str(e),
        )

    finally:
        # 11. Always terminate the instance (idempotent)
        if instance_id:
            try:
                import boto3 as _b3
                _ec2 = await asyncio.to_thread(_b3.client, "ec2", region_name=REGION)
                await asyncio.to_thread(
                    _ec2.terminate_instances,
                    InstanceIds=[instance_id],
                )
                logger.info(f"ec2_sandbox: terminated instance {instance_id}")
            except Exception as term_err:
                logger.warning(
                    f"ec2_sandbox: terminate_instances failed for {instance_id} "
                    f"(instance may already be gone): {term_err}"
                )
