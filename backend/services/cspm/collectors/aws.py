"""
AWS collector — bridges the existing AWSSecurityService scan output into the
CSPM engine's cache shape so plugins can be ported from cloudsploit format.

Rather than re-implementing boto calls, we reuse AWSSecurityService and
synthesize the cloudsploit-style cache: ctx.cache[<service>][<method>][<region>] = {data, err}.

Threading model: sync boto3 calls run inside a dedicated thread pool
(``_CSPM_EXECUTOR``) instead of the default asyncio executor. This prevents
CSPM scans from starving uvicorn's request handlers (which share the
default pool) and keeps /health responsive even during heavy multi-region
scans. See backend/services/cspm/executor.py for the pool definition.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from ..executor import run_blocking
from ..types import ScanContext

logger = logging.getLogger(__name__)


class AwsCollectorConfig:
    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        default_region: str = "us-east-1",
        scan_regions: Optional[list[str]] = None,
    ):
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.default_region = default_region
        self.scan_regions = scan_regions or [default_region]


async def collect_aws(ctx: ScanContext, config: Optional[AwsCollectorConfig] = None) -> None:
    if config is None:
        s = ctx.settings
        config = AwsCollectorConfig(
            access_key_id=s["access_key_id"],
            secret_access_key=s["secret_access_key"],
            default_region=s.get("default_region", "us-east-1"),
            scan_regions=ctx.regions or s.get("scan_regions"),
        )

    from backend.services.aws_security_service import AWSSecurityService

    service = AWSSecurityService(
        access_key_id=config.access_key_id,
        secret_access_key=config.secret_access_key,
        region=config.default_region,
    )

    # We invoke a curated set of inventory scans, then map their output into the cache.
    loop = asyncio.get_event_loop()

    def _scan_iam():
        try:
            iam = service._get_client("iam")
            users = iam.list_users().get("Users", [])
            # For each user, gather access keys + login profile
            enriched = []
            for u in users[:200]:
                try:
                    keys = iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", [])
                    try:
                        iam.get_login_profile(UserName=u["UserName"])
                        has_pw = True
                    except Exception:
                        has_pw = False
                    mfa = iam.list_mfa_devices(UserName=u["UserName"]).get("MFADevices", [])
                    u["_AccessKeys"] = keys
                    u["_HasConsolePassword"] = has_pw
                    u["_MFADevices"] = mfa
                except Exception:
                    pass
                enriched.append(u)
            pwd_policy = None
            try:
                pwd_policy = iam.get_account_password_policy().get("PasswordPolicy")
            except Exception:
                pass
            return enriched, pwd_policy
        except Exception as exc:
            logger.warning(f"AWS IAM collection failed: {exc}")
            return [], None

    def _scan_s3():
        try:
            s3 = service._get_client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            enriched = []
            for b in buckets[:300]:
                name = b["Name"]
                try:
                    enc = s3.get_bucket_encryption(Bucket=name).get("ServerSideEncryptionConfiguration")
                    b["_Encryption"] = enc
                except Exception:
                    b["_Encryption"] = None
                try:
                    pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration")
                    b["_PublicAccessBlock"] = pab
                except Exception:
                    b["_PublicAccessBlock"] = None
                try:
                    logging_ = s3.get_bucket_logging(Bucket=name)
                    b["_Logging"] = logging_.get("LoggingEnabled") is not None
                except Exception:
                    b["_Logging"] = False
                try:
                    versioning = s3.get_bucket_versioning(Bucket=name).get("Status", "Suspended")
                    b["_Versioning"] = versioning
                except Exception:
                    b["_Versioning"] = "Suspended"
                enriched.append(b)
            return enriched
        except Exception as exc:
            logger.warning(f"AWS S3 collection failed: {exc}")
            return []

    def _scan_ec2(region: str):
        try:
            ec2 = service._get_client("ec2", region=region)
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
            instances = []
            try:
                instances = [
                    i for r in ec2.describe_instances().get("Reservations", []) for i in r.get("Instances", [])
                ]
            except Exception:
                pass
            volumes = []
            try:
                volumes = ec2.describe_volumes().get("Volumes", [])
            except Exception:
                pass
            return sgs, instances, volumes
        except Exception as exc:
            logger.warning(f"AWS EC2 collection failed for {region}: {exc}")
            return [], [], []

    def _scan_cloudtrail():
        try:
            ct = service._get_client("cloudtrail")
            trails = ct.describe_trails().get("trailList", [])
            for t in trails:
                try:
                    status = ct.get_trail_status(Name=t["TrailARN"])
                    t["_Status"] = status
                except Exception:
                    pass
            return trails
        except Exception as exc:
            logger.warning(f"AWS CloudTrail collection failed: {exc}")
            return []

    # Run sync boto3 in the dedicated CSPM thread pool so /health and other
    # request handlers (which use the default asyncio executor) are not
    # affected. The CSPM pool has a fixed, small worker count so even a
    # multi-region scan can't drive up FD/socket pressure.
    iam_users, pwd_policy = await run_blocking(_scan_iam)
    ctx.add_source(["iam", "listUsers", "global"], {"err": None, "data": iam_users})
    ctx.add_source(["iam", "getAccountPasswordPolicy", "global"], {"err": None, "data": pwd_policy})

    buckets = await run_blocking(_scan_s3)
    ctx.add_source(["s3", "listBuckets", "global"], {"err": None, "data": buckets})

    # Run regions concurrently — the pool's worker cap throttles
    # max-in-flight automatically.
    region_results = await asyncio.gather(
        *(run_blocking(_scan_ec2, region) for region in config.scan_regions),
        return_exceptions=True,
    )
    for region, result in zip(config.scan_regions, region_results):
        if isinstance(result, Exception):
            logger.warning(f"AWS EC2 collection failed for {region}: {result}")
            sgs, instances, volumes = [], [], []
        else:
            sgs, instances, volumes = result
        ctx.add_source(["ec2", "describeSecurityGroups", region], {"err": None, "data": sgs})
        ctx.add_source(["ec2", "describeInstances", region], {"err": None, "data": instances})
        ctx.add_source(["ec2", "describeVolumes", region], {"err": None, "data": volumes})

    trails = await run_blocking(_scan_cloudtrail)
    ctx.add_source(["cloudtrail", "describeTrails", "global"], {"err": None, "data": trails})


def make_aws_collector(config: AwsCollectorConfig):
    async def _runner(ctx: ScanContext) -> None:
        await collect_aws(ctx, config)
    return _runner
