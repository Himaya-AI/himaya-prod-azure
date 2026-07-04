"""
AWS CSPM plugins — high-value security checks running on the cache populated by
collectors/aws.py.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

from ..engine import add_result
from ..types import Finding, PluginMeta, PluginResult, ScanContext, Severity

CLOUD = "aws"


def _data(ctx: ScanContext, path: list[str]) -> list | dict | None:
    s = ctx.get_source(path)
    if not s:
        return None
    return s.get("data") if isinstance(s, dict) else s


# ──────────────────────────────────────────────────────────────────────────────
# IAM: root account MFA, access key rotation, password policy
# ──────────────────────────────────────────────────────────────────────────────

_meta_pwd_policy = PluginMeta(
    plugin_id="aws-iam-strong-password-policy",
    cloud=CLOUD,
    title="IAM: Strong Password Policy",
    category="IAM",
    severity=Severity.HIGH,
    description="Ensures account password policy meets CIS recommendations.",
    recommended_action="Require: min length 14, uppercase, lowercase, number, symbol, max age 90d, reuse 24.",
    compliance={"CIS-AWS": "CIS 1.5–1.11 password requirements."},
)


def _run_pwd_policy(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    pp = _data(ctx, ["iam", "getAccountPasswordPolicy", "global"]) or {}
    if not isinstance(pp, dict):
        pp = {}
    weaknesses: list[str] = []
    if not pp:
        add_result(findings, meta=_meta_pwd_policy, cloud=CLOUD, code=2,
                   message="No account password policy set",
                   resource="root", resource_type="Account")
        return PluginResult(plugin_id=_meta_pwd_policy.plugin_id, findings=findings)
    if (pp.get("MinimumPasswordLength") or 0) < 14:
        weaknesses.append(f"min length {pp.get('MinimumPasswordLength')}")
    if not pp.get("RequireUppercaseCharacters"):
        weaknesses.append("no uppercase")
    if not pp.get("RequireLowercaseCharacters"):
        weaknesses.append("no lowercase")
    if not pp.get("RequireNumbers"):
        weaknesses.append("no numbers")
    if not pp.get("RequireSymbols"):
        weaknesses.append("no symbols")
    if (pp.get("MaxPasswordAge") or 0) > 90 or not pp.get("MaxPasswordAge"):
        weaknesses.append("max age >90d")
    if (pp.get("PasswordReusePrevention") or 0) < 24:
        weaknesses.append("reuse <24")
    if weaknesses:
        add_result(findings, meta=_meta_pwd_policy, cloud=CLOUD, code=2,
                   message=f"Weak password policy: {', '.join(weaknesses)}",
                   resource="root", resource_type="Account")
    else:
        add_result(findings, meta=_meta_pwd_policy, cloud=CLOUD, code=0,
                   message="Password policy meets CIS recommendations",
                   resource="root", resource_type="Account")
    return PluginResult(plugin_id=_meta_pwd_policy.plugin_id, findings=findings)


_meta_user_mfa = PluginMeta(
    plugin_id="aws-iam-user-mfa-enabled",
    cloud=CLOUD,
    title="IAM: Console Users Have MFA",
    category="IAM",
    severity=Severity.CRITICAL,
    description="Ensures every IAM user with a console password has MFA enabled.",
    recommended_action="Enable MFA for every console-capable IAM user.",
)


def _run_user_mfa(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    users = _data(ctx, ["iam", "listUsers", "global"]) or []
    for u in users:
        if not isinstance(u, dict):
            continue
        if not u.get("_HasConsolePassword"):
            continue
        if u.get("_MFADevices"):
            add_result(findings, meta=_meta_user_mfa, cloud=CLOUD, code=0,
                       message=f"User {u.get('UserName')} has MFA",
                       resource=u.get("Arn", ""), resource_type="IAMUser")
        else:
            add_result(findings, meta=_meta_user_mfa, cloud=CLOUD, code=2,
                       message=f"User {u.get('UserName')} has console password but no MFA",
                       resource=u.get("Arn", ""), resource_type="IAMUser")
    return PluginResult(plugin_id=_meta_user_mfa.plugin_id, findings=findings)


_meta_key_rotation = PluginMeta(
    plugin_id="aws-iam-access-key-rotation-90d",
    cloud=CLOUD,
    title="IAM: Access Keys Rotated < 90 Days",
    category="IAM",
    severity=Severity.HIGH,
    description="Ensures all active access keys are less than 90 days old.",
    recommended_action="Rotate or disable access keys older than 90 days.",
    compliance={"CIS-AWS": "CIS 1.14 mandates 90-day key rotation."},
)


def _run_key_rotation(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    users = _data(ctx, ["iam", "listUsers", "global"]) or []
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    for u in users:
        if not isinstance(u, dict):
            continue
        for k in u.get("_AccessKeys") or []:
            if k.get("Status") != "Active":
                continue
            created = k.get("CreateDate")
            if not created:
                continue
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created.replace("Z", "+00:00"))
                except Exception:
                    continue
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age_d = (datetime.now(timezone.utc) - created).days
            if created < cutoff:
                add_result(findings, meta=_meta_key_rotation, cloud=CLOUD, code=2,
                           message=f"Access key for {u.get('UserName')} is {age_d}d old",
                           resource=k.get("AccessKeyId", ""), resource_type="AccessKey")
            else:
                add_result(findings, meta=_meta_key_rotation, cloud=CLOUD, code=0,
                           message=f"Access key for {u.get('UserName')} is {age_d}d old",
                           resource=k.get("AccessKeyId", ""), resource_type="AccessKey")
    return PluginResult(plugin_id=_meta_key_rotation.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# S3: encryption, public access block, logging, versioning
# ──────────────────────────────────────────────────────────────────────────────

_meta_s3_enc = PluginMeta(
    plugin_id="aws-s3-bucket-encryption-at-rest",
    cloud=CLOUD,
    title="S3: Bucket Encryption at Rest",
    category="S3",
    severity=Severity.HIGH,
    description="Ensures every S3 bucket has server-side encryption enabled.",
    recommended_action="Enable SSE-S3 or SSE-KMS on every bucket.",
    compliance={"PCI": "PCI requires encryption at rest for cardholder data."},
)


def _run_s3_enc(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    buckets = _data(ctx, ["s3", "listBuckets", "global"]) or []
    for b in buckets:
        name = b.get("Name", "")
        if b.get("_Encryption"):
            add_result(findings, meta=_meta_s3_enc, cloud=CLOUD, code=0,
                       message="Bucket encrypted at rest",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
        else:
            add_result(findings, meta=_meta_s3_enc, cloud=CLOUD, code=2,
                       message="Bucket has no server-side encryption",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
    return PluginResult(plugin_id=_meta_s3_enc.plugin_id, findings=findings)


_meta_s3_public = PluginMeta(
    plugin_id="aws-s3-bucket-public-access-block",
    cloud=CLOUD,
    title="S3: Public Access Block Enabled",
    category="S3",
    severity=Severity.CRITICAL,
    description="Ensures S3 buckets have all 4 public-access-block settings enabled.",
    recommended_action="Block public ACLs + policies + ignore public ACLs + restrict public buckets.",
    compliance={"CIS-AWS": "CIS 2.1.5 mandates S3 public access block."},
)


def _run_s3_public(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    buckets = _data(ctx, ["s3", "listBuckets", "global"]) or []
    for b in buckets:
        name = b.get("Name", "")
        pab = b.get("_PublicAccessBlock") or {}
        flags = (
            pab.get("BlockPublicAcls"),
            pab.get("IgnorePublicAcls"),
            pab.get("BlockPublicPolicy"),
            pab.get("RestrictPublicBuckets"),
        )
        if all(flags):
            add_result(findings, meta=_meta_s3_public, cloud=CLOUD, code=0,
                       message="Public access block fully enabled",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
        elif any(flags):
            add_result(findings, meta=_meta_s3_public, cloud=CLOUD, code=1,
                       message=f"Partial public access block: {flags}",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
        else:
            add_result(findings, meta=_meta_s3_public, cloud=CLOUD, code=2,
                       message="No public access block",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
    return PluginResult(plugin_id=_meta_s3_public.plugin_id, findings=findings)


_meta_s3_logging = PluginMeta(
    plugin_id="aws-s3-bucket-access-logging",
    cloud=CLOUD,
    title="S3: Access Logging Enabled",
    category="S3",
    severity=Severity.MEDIUM,
    description="Ensures S3 buckets have access logging enabled.",
    recommended_action="Configure server access logging to a centralized bucket.",
)


def _run_s3_logging(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    buckets = _data(ctx, ["s3", "listBuckets", "global"]) or []
    for b in buckets:
        name = b.get("Name", "")
        if b.get("_Logging"):
            add_result(findings, meta=_meta_s3_logging, cloud=CLOUD, code=0,
                       message="Bucket access logging enabled",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
        else:
            add_result(findings, meta=_meta_s3_logging, cloud=CLOUD, code=2,
                       message="Bucket access logging disabled",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
    return PluginResult(plugin_id=_meta_s3_logging.plugin_id, findings=findings)


_meta_s3_versioning = PluginMeta(
    plugin_id="aws-s3-bucket-versioning-enabled",
    cloud=CLOUD,
    title="S3: Bucket Versioning Enabled",
    category="S3",
    severity=Severity.MEDIUM,
    description="Ensures S3 buckets have versioning enabled.",
    recommended_action="Enable versioning to protect against accidental deletion and ransomware.",
)


def _run_s3_versioning(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    buckets = _data(ctx, ["s3", "listBuckets", "global"]) or []
    for b in buckets:
        name = b.get("Name", "")
        v = b.get("_Versioning", "Suspended")
        if v == "Enabled":
            add_result(findings, meta=_meta_s3_versioning, cloud=CLOUD, code=0,
                       message="Versioning enabled",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
        else:
            add_result(findings, meta=_meta_s3_versioning, cloud=CLOUD, code=2,
                       message=f"Versioning {v}",
                       resource=f"arn:aws:s3:::{name}", resource_type="S3Bucket")
    return PluginResult(plugin_id=_meta_s3_versioning.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# EC2 SGs: open admin ports
# ──────────────────────────────────────────────────────────────────────────────

_meta_sg_admin = PluginMeta(
    plugin_id="aws-ec2-sg-no-open-admin",
    cloud=CLOUD,
    title="EC2: Security Groups Block SSH/RDP From 0.0.0.0/0",
    category="Networking",
    severity=Severity.CRITICAL,
    description="Ensures no SG allows port 22/3389 inbound from 0.0.0.0/0 or ::/0.",
    recommended_action="Restrict admin ports to known IP ranges.",
    compliance={"PCI": "PCI prohibits unrestricted internet exposure of admin ports."},
)


def _run_sg_admin(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    # Walk every region we collected for
    for region, sgs in (ctx.cache.get("ec2", {}).get("describeSecurityGroups") or {}).items():
        if not isinstance(sgs, dict):
            continue
        for sg in sgs.get("data") or []:
            gid = sg.get("GroupId", "")
            arn = f"arn:aws:ec2:{region}:*:security-group/{gid}"
            bad: list[str] = []
            for perm in sg.get("IpPermissions") or []:
                fp = perm.get("FromPort")
                tp = perm.get("ToPort")
                if fp is None and tp is None:
                    # All ports (-1) — must check ranges
                    ranges = perm.get("IpRanges") or []
                    if any(r.get("CidrIp") in ("0.0.0.0/0",) for r in ranges):
                        bad.append("all-ports/0.0.0.0/0")
                    continue
                ranges = perm.get("IpRanges") or []
                ipv6 = perm.get("Ipv6Ranges") or []
                open_any = any(r.get("CidrIp") == "0.0.0.0/0" for r in ranges) or any(
                    r.get("CidrIpv6") == "::/0" for r in ipv6
                )
                if not open_any:
                    continue
                lo, hi = fp or 0, tp or 65535
                if lo <= 22 <= hi:
                    bad.append(f"22 in {lo}-{hi}")
                if lo <= 3389 <= hi:
                    bad.append(f"3389 in {lo}-{hi}")
            if bad:
                add_result(findings, meta=_meta_sg_admin, cloud=CLOUD, code=2,
                           message=f"SG open admin: {', '.join(bad)}",
                           resource=arn, resource_type="SecurityGroup", region=region)
            else:
                add_result(findings, meta=_meta_sg_admin, cloud=CLOUD, code=0,
                           message="No open admin ports",
                           resource=arn, resource_type="SecurityGroup", region=region)
    return PluginResult(plugin_id=_meta_sg_admin.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# EBS: unencrypted volumes
# ──────────────────────────────────────────────────────────────────────────────

_meta_ebs_enc = PluginMeta(
    plugin_id="aws-ebs-volume-encryption",
    cloud=CLOUD,
    title="EBS: Volume Encryption",
    category="Compute",
    severity=Severity.HIGH,
    description="Ensures all EBS volumes are encrypted.",
    recommended_action="Enable encryption on all EBS volumes; turn on EBS encryption-by-default.",
)


def _run_ebs_enc(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    for region, vols in (ctx.cache.get("ec2", {}).get("describeVolumes") or {}).items():
        if not isinstance(vols, dict):
            continue
        for v in vols.get("data") or []:
            vid = v.get("VolumeId", "")
            arn = f"arn:aws:ec2:{region}:*:volume/{vid}"
            if v.get("Encrypted"):
                add_result(findings, meta=_meta_ebs_enc, cloud=CLOUD, code=0,
                           message="Volume encrypted",
                           resource=arn, resource_type="EBSVolume", region=region)
            else:
                add_result(findings, meta=_meta_ebs_enc, cloud=CLOUD, code=2,
                           message="Volume is unencrypted",
                           resource=arn, resource_type="EBSVolume", region=region)
    return PluginResult(plugin_id=_meta_ebs_enc.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# CloudTrail: enabled + multi-region + log file validation
# ──────────────────────────────────────────────────────────────────────────────

_meta_ct = PluginMeta(
    plugin_id="aws-cloudtrail-enabled-multiregion",
    cloud=CLOUD,
    title="CloudTrail: Multi-Region Trail Logging Enabled",
    category="Logging",
    severity=Severity.HIGH,
    description="Ensures at least one multi-region CloudTrail is enabled with log file validation.",
    recommended_action="Enable a multi-region trail with IsMultiRegionTrail=true and LogFileValidationEnabled=true.",
    compliance={"CIS-AWS": "CIS 3.1 requires CloudTrail enabled in all regions."},
)


def _run_ct(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    trails = _data(ctx, ["cloudtrail", "describeTrails", "global"]) or []
    multi = [t for t in trails if t.get("IsMultiRegionTrail")]
    logging_ = [t for t in multi if (t.get("_Status") or {}).get("IsLogging")]
    validated = [t for t in logging_ if t.get("LogFileValidationEnabled")]
    if validated:
        add_result(findings, meta=_meta_ct, cloud=CLOUD, code=0,
                   message=f"{len(validated)} multi-region trail(s) with log validation",
                   resource="account", resource_type="Account")
    elif logging_:
        add_result(findings, meta=_meta_ct, cloud=CLOUD, code=1,
                   message="Multi-region trail enabled but log file validation off",
                   resource="account", resource_type="Account")
    elif multi:
        add_result(findings, meta=_meta_ct, cloud=CLOUD, code=2,
                   message="Multi-region trail exists but is not logging",
                   resource="account", resource_type="Account")
    else:
        add_result(findings, meta=_meta_ct, cloud=CLOUD, code=2,
                   message="No multi-region CloudTrail",
                   resource="account", resource_type="Account")
    return PluginResult(plugin_id=_meta_ct.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# EC2 instances: public IP
# ──────────────────────────────────────────────────────────────────────────────

_meta_pub_inst = PluginMeta(
    plugin_id="aws-ec2-instance-public-ip",
    cloud=CLOUD,
    title="EC2: Instances Without Public IP",
    category="Compute",
    severity=Severity.MEDIUM,
    description="Flags EC2 instances with public IPs.",
    recommended_action="Use load balancers / NAT gateways instead of direct public IPs.",
)


def _run_pub_inst(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    for region, ins in (ctx.cache.get("ec2", {}).get("describeInstances") or {}).items():
        if not isinstance(ins, dict):
            continue
        for i in ins.get("data") or []:
            iid = i.get("InstanceId", "")
            arn = f"arn:aws:ec2:{region}:*:instance/{iid}"
            if i.get("PublicIpAddress"):
                add_result(findings, meta=_meta_pub_inst, cloud=CLOUD, code=2,
                           message=f"Instance has public IP {i.get('PublicIpAddress')}",
                           resource=arn, resource_type="EC2Instance", region=region)
            else:
                add_result(findings, meta=_meta_pub_inst, cloud=CLOUD, code=0,
                           message="No public IP",
                           resource=arn, resource_type="EC2Instance", region=region)
    return PluginResult(plugin_id=_meta_pub_inst.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Registry
# ──────────────────────────────────────────────────────────────────────────────

AWS_PLUGINS = [
    (_meta_pwd_policy, _run_pwd_policy),
    (_meta_user_mfa, _run_user_mfa),
    (_meta_key_rotation, _run_key_rotation),
    (_meta_s3_enc, _run_s3_enc),
    (_meta_s3_public, _run_s3_public),
    (_meta_s3_logging, _run_s3_logging),
    (_meta_s3_versioning, _run_s3_versioning),
    (_meta_sg_admin, _run_sg_admin),
    (_meta_ebs_enc, _run_ebs_enc),
    (_meta_ct, _run_ct),
    (_meta_pub_inst, _run_pub_inst),
]
