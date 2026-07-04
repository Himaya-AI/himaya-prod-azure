"""
Oracle OCI CSPM plugins.
"""
from __future__ import annotations

from ..engine import add_result
from ..types import Finding, PluginMeta, PluginResult, ScanContext, Severity


CLOUD = "oracle"


def _data(ctx: ScanContext, path: list[str]) -> list | dict | None:
    """Helper to get .data from cached source."""
    src = ctx.get_source(path)
    if not src:
        return None
    return src.get("data") if isinstance(src, dict) else src


def _as_dict(item) -> dict:
    if hasattr(item, "__dict__"):
        return item.__dict__
    return item if isinstance(item, dict) else {}


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: IAM users have MFA enabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_mfa = PluginMeta(
    plugin_id="oci-iam-mfa-for-console-users",
    cloud=CLOUD,
    title="IAM: MFA Enabled for Console Users",
    category="Identity",
    severity=Severity.CRITICAL,
    description="Ensures every console-capable IAM user has at least one MFA TOTP device.",
    recommended_action="Enroll an MFA TOTP device for every console-capable user.",
    compliance={"CIS-OCI": "CIS OCI 1.7 mandates MFA for all users with a console password."},
)


def _run_mfa(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    users = _data(ctx, ["identity", "listUsers", ctx.regions[0] if ctx.regions else "global"]) or []
    if not isinstance(users, list):
        users = [users]
    for u in users:
        ud = _as_dict(u)
        uid = ud.get("id") or ud.get("user_id") or ""
        name = ud.get("name") or uid
        if not uid:
            continue
        mfa_src = _data(ctx, ["identity", "listMfaTotpDevices", uid]) or []
        if not isinstance(mfa_src, list):
            mfa_src = [mfa_src]
        active = [m for m in mfa_src if (_as_dict(m).get("is_activated") or _as_dict(m).get("isActivated"))]
        if active:
            add_result(findings, meta=_meta_mfa, cloud=CLOUD, code=0,
                       message=f"User {name} has MFA enabled",
                       resource=uid, resource_type="User")
        else:
            add_result(findings, meta=_meta_mfa, cloud=CLOUD, code=2,
                       message=f"User {name} does not have MFA enabled",
                       resource=uid, resource_type="User")
    return PluginResult(plugin_id=_meta_mfa.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Object Storage bucket public access
# ──────────────────────────────────────────────────────────────────────────────

_meta_obj_public = PluginMeta(
    plugin_id="oci-objectstore-no-public-buckets",
    cloud=CLOUD,
    title="Object Storage: No Public Buckets",
    category="Storage",
    severity=Severity.HIGH,
    description="Ensures no Object Storage bucket allows public read/list access.",
    recommended_action="Set public_access_type='NoPublicAccess' on every bucket.",
    compliance={"CIS-OCI": "CIS OCI mandates non-public bucket access for sensitive data."},
)


def _run_obj_public(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    region = ctx.regions[0] if ctx.regions else "global"
    buckets = _data(ctx, ["objectstore", "listBuckets", region]) or []
    if not isinstance(buckets, list):
        buckets = [buckets]
    for b in buckets:
        bd = _as_dict(b)
        bid = bd.get("name", "")
        pa = (bd.get("public_access_type") or bd.get("publicAccessType") or "").lower()
        if pa in ("nopublicaccess", "no_public_access", "none", ""):
            add_result(findings, meta=_meta_obj_public, cloud=CLOUD, code=0,
                       message="Bucket is private",
                       resource=bid, resource_type="Bucket", region=region)
        else:
            add_result(findings, meta=_meta_obj_public, cloud=CLOUD, code=2,
                       message=f"Bucket is publicly accessible: {pa}",
                       resource=bid, resource_type="Bucket", region=region)
    return PluginResult(plugin_id=_meta_obj_public.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Block volume backup policy
# ──────────────────────────────────────────────────────────────────────────────

_meta_vol_backup = PluginMeta(
    plugin_id="oci-block-volume-backup-enabled",
    cloud=CLOUD,
    title="Block Volumes: Backup Policy Assigned",
    category="Storage",
    severity=Severity.MEDIUM,
    description="Ensures block volumes have a backup policy assigned for data protection.",
    recommended_action="Assign a backup policy to each block volume.",
)


def _run_vol_backup(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    region = ctx.regions[0] if ctx.regions else "global"
    vols = _data(ctx, ["blockstorage", "listVolumes", region]) or []
    if not isinstance(vols, list):
        vols = [vols]
    for v in vols:
        vd = _as_dict(v)
        vid = vd.get("id", "")
        name = vd.get("display_name") or vd.get("displayName") or vid
        # Volumes have a defined_tags map; backup policy assignment lives elsewhere but
        # vol.is_hydrated / backup_policy_id is the modern field
        bp = vd.get("backup_policy_id") or vd.get("backupPolicyId")
        if bp:
            add_result(findings, meta=_meta_vol_backup, cloud=CLOUD, code=0,
                       message=f"Volume {name} has backup policy",
                       resource=vid, resource_type="BlockVolume", region=region)
        else:
            add_result(findings, meta=_meta_vol_backup, cloud=CLOUD, code=1,
                       message=f"Volume {name} has no backup policy in metadata (verify externally)",
                       resource=vid, resource_type="BlockVolume", region=region)
    return PluginResult(plugin_id=_meta_vol_backup.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Security list — ingress SSH/RDP open
# ──────────────────────────────────────────────────────────────────────────────

_meta_seclist_open = PluginMeta(
    plugin_id="oci-networking-no-open-admin-ports",
    cloud=CLOUD,
    title="Networking: Security Lists Block SSH/RDP From Internet",
    category="Networking",
    severity=Severity.CRITICAL,
    description="Ensures no Security List ingress rule allows port 22/3389 from 0.0.0.0/0.",
    recommended_action="Restrict SSH/RDP ingress to known IP ranges or use a bastion.",
)


def _run_seclist_open(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    region = ctx.regions[0] if ctx.regions else "global"
    sec_lists = _data(ctx, ["networking", "listSecurityLists", region]) or []
    if not isinstance(sec_lists, list):
        sec_lists = [sec_lists]
    for sl in sec_lists:
        sd = _as_dict(sl)
        sid = sd.get("id", "")
        ingress = sd.get("ingress_security_rules") or sd.get("ingressSecurityRules") or []
        bad: list[str] = []
        for r in ingress:
            rd = _as_dict(r)
            src = rd.get("source", "")
            tcp = rd.get("tcp_options") or rd.get("tcpOptions") or {}
            tcp_d = _as_dict(tcp)
            dest = tcp_d.get("destination_port_range") or tcp_d.get("destinationPortRange") or {}
            dd = _as_dict(dest)
            lo = dd.get("min")
            hi = dd.get("max")
            if src in ("0.0.0.0/0", "::/0") and lo and hi:
                if lo <= 22 <= hi or lo <= 3389 <= hi:
                    bad.append(f"{lo}-{hi}")
        if bad:
            add_result(findings, meta=_meta_seclist_open, cloud=CLOUD, code=2,
                       message=f"Security List has open admin ports: {', '.join(bad)}",
                       resource=sid, resource_type="SecurityList", region=region)
        else:
            add_result(findings, meta=_meta_seclist_open, cloud=CLOUD, code=0,
                       message="No open admin ports from internet",
                       resource=sid, resource_type="SecurityList", region=region)
    return PluginResult(plugin_id=_meta_seclist_open.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Audit retention >= 365 days
# ──────────────────────────────────────────────────────────────────────────────

_meta_audit = PluginMeta(
    plugin_id="oci-audit-retention-365d",
    cloud=CLOUD,
    title="Audit: Retention Period >= 365 Days",
    category="Audit",
    severity=Severity.MEDIUM,
    description="Ensures the OCI Audit service retention is at least 365 days.",
    recommended_action="Increase audit retention to 365 days.",
    compliance={"CIS-OCI": "CIS OCI requires 365-day audit retention."},
)


def _run_audit(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    region = ctx.regions[0] if ctx.regions else "global"
    cfg = _data(ctx, ["audit", "getConfiguration", region]) or {}
    cd = _as_dict(cfg)
    days = cd.get("retention_period_days") or cd.get("retentionPeriodDays") or 0
    if days >= 365:
        add_result(findings, meta=_meta_audit, cloud=CLOUD, code=0,
                   message=f"Audit retention {days}d",
                   resource="tenancy", resource_type="AuditConfig", region=region)
    elif days:
        add_result(findings, meta=_meta_audit, cloud=CLOUD, code=2,
                   message=f"Audit retention only {days}d (need 365+)",
                   resource="tenancy", resource_type="AuditConfig", region=region)
    else:
        add_result(findings, meta=_meta_audit, cloud=CLOUD, code=3,
                   message="Could not read audit configuration",
                   resource="tenancy", resource_type="AuditConfig", region=region)
    return PluginResult(plugin_id=_meta_audit.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: KMS vaults exist for managed encryption
# ──────────────────────────────────────────────────────────────────────────────

_meta_kms = PluginMeta(
    plugin_id="oci-kms-vaults-present",
    cloud=CLOUD,
    title="KMS: Customer-Managed Vaults Present",
    category="Key Management",
    severity=Severity.LOW,
    description="Ensures the tenancy has at least one KMS vault for customer-managed key encryption.",
    recommended_action="Create a KMS vault and use customer-managed keys for sensitive data.",
)


def _run_kms(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    region = ctx.regions[0] if ctx.regions else "global"
    vaults = _data(ctx, ["vaults", "listVaults", region]) or []
    if not isinstance(vaults, list):
        vaults = [vaults]
    if vaults:
        add_result(findings, meta=_meta_kms, cloud=CLOUD, code=0,
                   message=f"{len(vaults)} KMS vault(s) present", region=region)
    else:
        add_result(findings, meta=_meta_kms, cloud=CLOUD, code=1,
                   message="No KMS vaults found", region=region)
    return PluginResult(plugin_id=_meta_kms.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Registry
# ──────────────────────────────────────────────────────────────────────────────

ORACLE_PLUGINS = [
    (_meta_mfa, _run_mfa),
    (_meta_obj_public, _run_obj_public),
    (_meta_vol_backup, _run_vol_backup),
    (_meta_seclist_open, _run_seclist_open),
    (_meta_audit, _run_audit),
    (_meta_kms, _run_kms),
]
