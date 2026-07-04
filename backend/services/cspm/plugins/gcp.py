"""GCP CSPM plugins."""
from __future__ import annotations

from ..engine import add_result
from ..types import Finding, PluginMeta, PluginResult, ScanContext, Severity


CLOUD = "gcp"


def _data(ctx: ScanContext, path: list[str]):
    s = ctx.get_source(path)
    if not s:
        return None
    return s.get("data") if isinstance(s, dict) else s


# ── Bucket uniform access ────────────────────────────────────────────────────

_meta_uniform = PluginMeta(
    plugin_id="gcp-storage-uniform-bucket-level-access",
    cloud=CLOUD,
    title="Storage: Uniform Bucket-Level Access Enabled",
    category="Storage",
    severity=Severity.HIGH,
    description="Ensures GCS buckets use uniform bucket-level access (no ACLs).",
    recommended_action="Enable Uniform bucket-level access on all buckets.",
)


def _run_uniform(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    buckets = _data(ctx, ["storage", "listBuckets", "global"]) or []
    for b in buckets:
        name = b.get("name", "")
        if (b.get("iam_configuration") or {}).get("uniform_bucket_level_access_enabled"):
            add_result(findings, meta=_meta_uniform, cloud=CLOUD, code=0,
                       message="Uniform access enabled",
                       resource=f"gs://{name}", resource_type="Bucket")
        else:
            add_result(findings, meta=_meta_uniform, cloud=CLOUD, code=2,
                       message="Uniform bucket-level access disabled",
                       resource=f"gs://{name}", resource_type="Bucket")
    return PluginResult(plugin_id=_meta_uniform.plugin_id, findings=findings)


# ── Bucket public-access-prevention enforced ──────────────────────────────────

_meta_pap = PluginMeta(
    plugin_id="gcp-storage-public-access-prevention",
    cloud=CLOUD,
    title="Storage: Public Access Prevention Enforced",
    category="Storage",
    severity=Severity.CRITICAL,
    description="Ensures GCS buckets enforce public access prevention.",
    recommended_action="Set public_access_prevention='enforced' on every bucket.",
)


def _run_pap(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    buckets = _data(ctx, ["storage", "listBuckets", "global"]) or []
    for b in buckets:
        name = b.get("name", "")
        pap = (b.get("iam_configuration") or {}).get("public_access_prevention", "")
        if pap == "enforced":
            add_result(findings, meta=_meta_pap, cloud=CLOUD, code=0,
                       message="Public access prevention enforced",
                       resource=f"gs://{name}", resource_type="Bucket")
        else:
            add_result(findings, meta=_meta_pap, cloud=CLOUD, code=2,
                       message=f"Public access prevention: {pap or 'inherited'}",
                       resource=f"gs://{name}", resource_type="Bucket")
    return PluginResult(plugin_id=_meta_pap.plugin_id, findings=findings)


# ── Public IAM bindings on buckets ────────────────────────────────────────────

_meta_public_iam = PluginMeta(
    plugin_id="gcp-storage-no-public-iam",
    cloud=CLOUD,
    title="Storage: No Public IAM Bindings",
    category="Storage",
    severity=Severity.CRITICAL,
    description="Ensures no GCS bucket has allUsers or allAuthenticatedUsers in IAM bindings.",
    recommended_action="Remove allUsers / allAuthenticatedUsers from bucket IAM policy.",
)


def _run_public_iam(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    buckets = _data(ctx, ["storage", "listBuckets", "global"]) or []
    for b in buckets:
        name = b.get("name", "")
        bad: list[str] = []
        for binding in b.get("iam_bindings") or []:
            for m in binding.get("members") or []:
                if m in ("allUsers", "allAuthenticatedUsers"):
                    bad.append(f"{binding.get('role')} -> {m}")
        if bad:
            add_result(findings, meta=_meta_public_iam, cloud=CLOUD, code=2,
                       message=f"Public bindings: {', '.join(bad)}",
                       resource=f"gs://{name}", resource_type="Bucket")
        else:
            add_result(findings, meta=_meta_public_iam, cloud=CLOUD, code=0,
                       message="No public bindings",
                       resource=f"gs://{name}", resource_type="Bucket")
    return PluginResult(plugin_id=_meta_public_iam.plugin_id, findings=findings)


# ── Cloud SQL requires SSL ────────────────────────────────────────────────────

_meta_sql_ssl = PluginMeta(
    plugin_id="gcp-sql-require-ssl",
    cloud=CLOUD,
    title="Cloud SQL: Require SSL",
    category="SQL",
    severity=Severity.HIGH,
    description="Ensures Cloud SQL instances require SSL connections.",
    recommended_action="Enable requireSsl=true on all Cloud SQL instances.",
)


def _run_sql_ssl(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    instances = _data(ctx, ["sql", "listInstances", "global"]) or []
    for ins in instances:
        name = ins.get("name", "")
        settings = ins.get("settings") or {}
        ip_cfg = settings.get("ipConfiguration") or {}
        if ip_cfg.get("requireSsl"):
            add_result(findings, meta=_meta_sql_ssl, cloud=CLOUD, code=0,
                       message="SSL required",
                       resource=name, resource_type="SqlInstance")
        else:
            add_result(findings, meta=_meta_sql_ssl, cloud=CLOUD, code=2,
                       message="SSL NOT required",
                       resource=name, resource_type="SqlInstance")
    return PluginResult(plugin_id=_meta_sql_ssl.plugin_id, findings=findings)


# ── Service account user-managed key rotation ────────────────────────────────

_meta_sa_keys = PluginMeta(
    plugin_id="gcp-iam-sa-no-user-managed-keys",
    cloud=CLOUD,
    title="IAM: No User-Managed Service Account Keys",
    category="IAM",
    severity=Severity.HIGH,
    description="Flags service accounts (informational — key inspection requires additional permissions).",
    recommended_action="Prefer workload identity / short-lived tokens; remove user-managed SA keys.",
)


def _run_sa_keys(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    sas = _data(ctx, ["iam", "listServiceAccounts", "global"]) or []
    for sa in sas:
        email = sa.get("email", "")
        if not sa.get("disabled"):
            add_result(findings, meta=_meta_sa_keys, cloud=CLOUD, code=1,
                       message=f"Active service account: {email}",
                       resource=email, resource_type="ServiceAccount")
    return PluginResult(plugin_id=_meta_sa_keys.plugin_id, findings=findings)


# ── Firewall: no open admin ports ─────────────────────────────────────────────

_meta_fw_admin = PluginMeta(
    plugin_id="gcp-firewall-no-open-admin",
    cloud=CLOUD,
    title="Firewall: No Open SSH/RDP From Internet",
    category="Networking",
    severity=Severity.CRITICAL,
    description="Ensures no firewall rule allows port 22/3389 inbound from 0.0.0.0/0.",
    recommended_action="Restrict source IP ranges for admin ports.",
)


def _run_fw_admin(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    fws = _data(ctx, ["compute", "listFirewalls", "global"]) or []
    for fw in fws:
        name = fw.get("name", "")
        if fw.get("direction") != "INGRESS" or fw.get("disabled"):
            continue
        src_ranges = fw.get("sourceRanges") or []
        if "0.0.0.0/0" not in src_ranges:
            continue
        for allow in fw.get("allowed") or []:
            ports = allow.get("ports") or []
            for p in ports:
                if "-" in p:
                    lo, hi = (int(x) for x in p.split("-"))
                else:
                    lo = hi = int(p)
                if lo <= 22 <= hi or lo <= 3389 <= hi:
                    add_result(findings, meta=_meta_fw_admin, cloud=CLOUD, code=2,
                               message=f"Firewall {name} allows admin port {p} from 0.0.0.0/0",
                               resource=name, resource_type="Firewall")
                    break
    return PluginResult(plugin_id=_meta_fw_admin.plugin_id, findings=findings)


# ── Bucket KMS encryption ────────────────────────────────────────────────────

_meta_kms = PluginMeta(
    plugin_id="gcp-storage-cmk-encryption",
    cloud=CLOUD,
    title="Storage: Bucket Encrypted with CMEK",
    category="Storage",
    severity=Severity.MEDIUM,
    description="Ensures buckets use customer-managed encryption keys.",
    recommended_action="Configure default_kms_key_name on sensitive buckets.",
)


def _run_kms(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    buckets = _data(ctx, ["storage", "listBuckets", "global"]) or []
    for b in buckets:
        name = b.get("name", "")
        if b.get("default_kms_key_name"):
            add_result(findings, meta=_meta_kms, cloud=CLOUD, code=0,
                       message="CMEK configured",
                       resource=f"gs://{name}", resource_type="Bucket")
        else:
            add_result(findings, meta=_meta_kms, cloud=CLOUD, code=1,
                       message="Using Google-managed encryption (no CMEK)",
                       resource=f"gs://{name}", resource_type="Bucket")
    return PluginResult(plugin_id=_meta_kms.plugin_id, findings=findings)


GCP_PLUGINS = [
    (_meta_uniform, _run_uniform),
    (_meta_pap, _run_pap),
    (_meta_public_iam, _run_public_iam),
    (_meta_sql_ssl, _run_sql_ssl),
    (_meta_sa_keys, _run_sa_keys),
    (_meta_fw_admin, _run_fw_admin),
    (_meta_kms, _run_kms),
]
