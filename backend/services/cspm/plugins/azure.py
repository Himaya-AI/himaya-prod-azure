"""
Azure CSPM plugins. Ported from cloudsploit's plugins/azure/* with adaptations
for Helios' Python plugin engine.

Each plugin returns a PluginResult. Run signatures are sync (engine awaits if needed).
"""
from __future__ import annotations

from ..engine import add_result
from ..types import (
    Finding,
    PluginMeta,
    PluginResult,
    PluginStatus,
    ScanContext,
    Severity,
)


CLOUD = "azure"

# ──────────────────────────────────────────────────────────────────────────────
# Helper: walk storage accounts
# ──────────────────────────────────────────────────────────────────────────────

def _iter_storage_accounts(ctx: ScanContext):
    src = ctx.get_source(["storageAccounts", "list", "global"]) or {}
    for it in (src.get("data") or []):
        yield it


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Storage account secure transfer required
# ──────────────────────────────────────────────────────────────────────────────

_meta_secure_transfer = PluginMeta(
    plugin_id="azure-storage-secure-transfer-required",
    cloud=CLOUD,
    title="Storage Accounts: Secure Transfer Required",
    category="Storage",
    domain="Storage",
    severity=Severity.HIGH,
    description="Ensures storage accounts enforce HTTPS-only access.",
    recommended_action="Set 'supportsHttpsTrafficOnly' to true on all storage accounts.",
    link="https://learn.microsoft.com/azure/storage/common/storage-require-secure-transfer",
    compliance={"PCI": "PCI requires data in transit to be encrypted.",
                "HIPAA": "HIPAA requires PHI data in transit to be encrypted."},
    apis=["storageAccounts:list"],
)


def _run_secure_transfer(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    found_any = False
    for sa in _iter_storage_accounts(ctx):
        found_any = True
        sid = sa.get("id", "")
        loc = sa.get("location", "global")
        props = sa.get("properties") or {}
        if props.get("supportsHttpsTrafficOnly"):
            add_result(findings, meta=_meta_secure_transfer, cloud=CLOUD, code=0,
                       message="Storage account requires secure transfer",
                       region=loc, resource=sid, resource_type="StorageAccount")
        else:
            add_result(findings, meta=_meta_secure_transfer, cloud=CLOUD, code=2,
                       message="Storage account does not require secure transfer (HTTPS-only)",
                       region=loc, resource=sid, resource_type="StorageAccount")
    if not found_any:
        add_result(findings, meta=_meta_secure_transfer, cloud=CLOUD, code=0,
                   message="No storage accounts found", region="global")
    return PluginResult(plugin_id=_meta_secure_transfer.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Storage account public network access disabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_sa_public = PluginMeta(
    plugin_id="azure-storage-public-network-access-disabled",
    cloud=CLOUD,
    title="Storage Accounts: Public Network Access Disabled",
    category="Storage",
    severity=Severity.HIGH,
    description="Ensures storage accounts do not allow public network access.",
    recommended_action="Set publicNetworkAccess='Disabled' or restrict via firewall.",
    link="https://learn.microsoft.com/azure/storage/common/storage-network-security",
    compliance={"PCI": "PCI restricts public network exposure of sensitive data stores."},
)


def _run_sa_public(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    for sa in _iter_storage_accounts(ctx):
        sid = sa.get("id", "")
        loc = sa.get("location", "global")
        props = sa.get("properties") or {}
        pna = (props.get("publicNetworkAccess") or "Enabled").lower()
        net_rules = props.get("networkAcls") or {}
        default_action = (net_rules.get("defaultAction") or "Allow").lower()
        if pna == "disabled":
            add_result(findings, meta=_meta_sa_public, cloud=CLOUD, code=0,
                       message="Public network access disabled",
                       region=loc, resource=sid, resource_type="StorageAccount")
        elif default_action == "deny":
            add_result(findings, meta=_meta_sa_public, cloud=CLOUD, code=1,
                       message="Public network access enabled but firewall default-deny",
                       region=loc, resource=sid, resource_type="StorageAccount")
        else:
            add_result(findings, meta=_meta_sa_public, cloud=CLOUD, code=2,
                       message="Storage account is open to public networks",
                       region=loc, resource=sid, resource_type="StorageAccount")
    return PluginResult(plugin_id=_meta_sa_public.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Storage account blob service soft-delete enabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_blob_softdelete = PluginMeta(
    plugin_id="azure-storage-blob-soft-delete-enabled",
    cloud=CLOUD,
    title="Storage Accounts: Blob Soft Delete Enabled",
    category="Storage",
    severity=Severity.MEDIUM,
    description="Ensures blob soft-delete is enabled for recovery from accidental deletion.",
    recommended_action="Enable blob soft delete with at least a 7-day retention window.",
)


def _run_blob_softdelete(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    for sa in _iter_storage_accounts(ctx):
        sid = sa.get("id", "")
        loc = sa.get("location", "global")
        blob = ctx.get_source(["storageAccounts", "blobServices", sid]) or {}
        data = blob.get("data") or {}
        props = (data.get("properties") or {}) if isinstance(data, dict) else {}
        dr = props.get("deleteRetentionPolicy") or {}
        if dr.get("enabled") and (dr.get("days") or 0) >= 7:
            add_result(findings, meta=_meta_blob_softdelete, cloud=CLOUD, code=0,
                       message=f"Blob soft delete enabled ({dr.get('days')}d)",
                       region=loc, resource=sid, resource_type="StorageAccount")
        elif dr.get("enabled"):
            add_result(findings, meta=_meta_blob_softdelete, cloud=CLOUD, code=1,
                       message=f"Blob soft delete enabled but retention <7d ({dr.get('days')}d)",
                       region=loc, resource=sid, resource_type="StorageAccount")
        else:
            add_result(findings, meta=_meta_blob_softdelete, cloud=CLOUD, code=2,
                       message="Blob soft delete disabled",
                       region=loc, resource=sid, resource_type="StorageAccount")
    return PluginResult(plugin_id=_meta_blob_softdelete.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Key Vault key expiration enabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_kv_key_exp = PluginMeta(
    plugin_id="azure-keyvault-key-expiration-enabled",
    cloud=CLOUD,
    title="Key Vaults: Key Expiration Enabled",
    category="Key Vaults",
    severity=Severity.MEDIUM,
    description="Ensures all Key Vault keys have an expiration date set.",
    recommended_action="Set an expiration date on every Key Vault key.",
    compliance={"PCI": "Cryptographic keys must be rotated periodically."},
)


def _run_kv_key_exp(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    vaults = (ctx.get_source(["vaults", "list", "global"]) or {}).get("data") or []
    for v in vaults:
        vid = v.get("id", "")
        loc = v.get("location", "global")
        keys = (ctx.get_source(["vaults", "getKeys", vid]) or {}).get("data") or []
        if not keys:
            add_result(findings, meta=_meta_kv_key_exp, cloud=CLOUD, code=0,
                       message="No keys found", region=loc, resource=vid, resource_type="KeyVault")
            continue
        for k in keys:
            kid = k.get("kid", "")
            attrs = k.get("attributes") or {}
            if attrs.get("exp") or attrs.get("expires"):
                add_result(findings, meta=_meta_kv_key_exp, cloud=CLOUD, code=0,
                           message="Expiry set", region=loc, resource=kid, resource_type="KeyVaultKey")
            else:
                add_result(findings, meta=_meta_kv_key_exp, cloud=CLOUD, code=2,
                           message="Key has no expiration date", region=loc,
                           resource=kid, resource_type="KeyVaultKey")
    return PluginResult(plugin_id=_meta_kv_key_exp.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Key Vault soft delete + purge protection
# ──────────────────────────────────────────────────────────────────────────────

_meta_kv_recovery = PluginMeta(
    plugin_id="azure-keyvault-recovery-enabled",
    cloud=CLOUD,
    title="Key Vaults: Soft Delete + Purge Protection Enabled",
    category="Key Vaults",
    severity=Severity.HIGH,
    description="Ensures Key Vaults have soft delete and purge protection enabled.",
    recommended_action="Enable enableSoftDelete and enablePurgeProtection on every Key Vault.",
)


def _run_kv_recovery(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    vaults = (ctx.get_source(["vaults", "list", "global"]) or {}).get("data") or []
    for v in vaults:
        vid = v.get("id", "")
        loc = v.get("location", "global")
        props = v.get("properties") or {}
        sd = props.get("enableSoftDelete")
        pp = props.get("enablePurgeProtection")
        if sd and pp:
            add_result(findings, meta=_meta_kv_recovery, cloud=CLOUD, code=0,
                       message="Soft delete + purge protection enabled",
                       region=loc, resource=vid, resource_type="KeyVault")
        elif sd:
            add_result(findings, meta=_meta_kv_recovery, cloud=CLOUD, code=1,
                       message="Soft delete enabled but purge protection disabled",
                       region=loc, resource=vid, resource_type="KeyVault")
        else:
            add_result(findings, meta=_meta_kv_recovery, cloud=CLOUD, code=2,
                       message="Soft delete and purge protection disabled",
                       region=loc, resource=vid, resource_type="KeyVault")
    return PluginResult(plugin_id=_meta_kv_recovery.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: SQL Server Auditing Enabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_sql_audit = PluginMeta(
    plugin_id="azure-sqlserver-auditing-enabled",
    cloud=CLOUD,
    title="SQL Servers: Auditing Enabled",
    category="SQL",
    severity=Severity.HIGH,
    description="Ensures auditing is enabled on every Azure SQL Server.",
    recommended_action="Enable auditing with state='Enabled' on all SQL servers.",
    compliance={"HIPAA": "HIPAA requires audit logging of access to sensitive data."},
)


def _run_sql_audit(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    servers = (ctx.get_source(["sqlServers", "list", "global"]) or {}).get("data") or []
    for s in servers:
        sid = s.get("id", "")
        loc = s.get("location", "global")
        audit = (ctx.get_source(["sqlServers", "auditingSettings", sid]) or {}).get("data") or {}
        props = (audit.get("properties") or {}) if isinstance(audit, dict) else {}
        state = (props.get("state") or "Disabled").lower()
        if state == "enabled":
            add_result(findings, meta=_meta_sql_audit, cloud=CLOUD, code=0,
                       message="SQL server auditing enabled",
                       region=loc, resource=sid, resource_type="SqlServer")
        else:
            add_result(findings, meta=_meta_sql_audit, cloud=CLOUD, code=2,
                       message="SQL server auditing is not enabled",
                       region=loc, resource=sid, resource_type="SqlServer")
    return PluginResult(plugin_id=_meta_sql_audit.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: SQL Server Azure AD admin configured
# ──────────────────────────────────────────────────────────────────────────────

_meta_sql_aad = PluginMeta(
    plugin_id="azure-sqlserver-aad-admin-configured",
    cloud=CLOUD,
    title="SQL Servers: Azure AD Admin Configured",
    category="SQL",
    severity=Severity.HIGH,
    description="Ensures Azure AD admin is configured on every SQL Server.",
    recommended_action="Configure an Azure AD admin user/group on each SQL Server.",
)


def _run_sql_aad(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    servers = (ctx.get_source(["sqlServers", "list", "global"]) or {}).get("data") or []
    for s in servers:
        sid = s.get("id", "")
        loc = s.get("location", "global")
        admin = (ctx.get_source(["sqlServers", "azureADAdmin", sid]) or {}).get("data") or {}
        if admin and (admin.get("properties") or {}).get("login"):
            add_result(findings, meta=_meta_sql_aad, cloud=CLOUD, code=0,
                       message=f"AAD admin configured: {(admin['properties'] or {}).get('login')}",
                       region=loc, resource=sid, resource_type="SqlServer")
        else:
            add_result(findings, meta=_meta_sql_aad, cloud=CLOUD, code=2,
                       message="No Azure AD admin configured for SQL server",
                       region=loc, resource=sid, resource_type="SqlServer")
    return PluginResult(plugin_id=_meta_sql_aad.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Disk encryption with CMK
# ──────────────────────────────────────────────────────────────────────────────

_meta_disk_cmk = PluginMeta(
    plugin_id="azure-disk-cmk-encryption",
    cloud=CLOUD,
    title="Disks: Customer-Managed Key Encryption",
    category="Compute",
    severity=Severity.MEDIUM,
    description="Ensures managed disks are encrypted with a customer-managed key.",
    recommended_action="Configure CMK on disks containing sensitive data.",
)


def _run_disk_cmk(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    disks = (ctx.get_source(["disks", "list", "global"]) or {}).get("data") or []
    for d in disks:
        did = d.get("id", "")
        loc = d.get("location", "global")
        props = d.get("properties") or {}
        enc = props.get("encryption") or {}
        et = (enc.get("type") or "").lower()
        if "customerkey" in et or "encryptionatresttwithcustomerkey".lower() in et.replace("_", "").lower():
            add_result(findings, meta=_meta_disk_cmk, cloud=CLOUD, code=0,
                       message="Disk encrypted with CMK",
                       region=loc, resource=did, resource_type="Disk")
        elif et:
            add_result(findings, meta=_meta_disk_cmk, cloud=CLOUD, code=1,
                       message=f"Disk encrypted with platform-managed key ({et})",
                       region=loc, resource=did, resource_type="Disk")
        else:
            add_result(findings, meta=_meta_disk_cmk, cloud=CLOUD, code=2,
                       message="Disk encryption status unknown",
                       region=loc, resource=did, resource_type="Disk")
    return PluginResult(plugin_id=_meta_disk_cmk.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: VM has log analytics agent
# ──────────────────────────────────────────────────────────────────────────────

_meta_vm_la = PluginMeta(
    plugin_id="azure-vm-log-analytics-agent",
    cloud=CLOUD,
    title="VMs: Log Analytics / Azure Monitor Agent Installed",
    category="Compute",
    severity=Severity.MEDIUM,
    description="Ensures every VM has Log Analytics or Azure Monitor Agent extension installed.",
    recommended_action="Install AzureMonitorLinuxAgent / AzureMonitorWindowsAgent on all VMs.",
)


def _run_vm_la(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    vms = (ctx.get_source(["virtualMachines", "list", "global"]) or {}).get("data") or []
    for v in vms:
        vid = v.get("id", "")
        loc = v.get("location", "global")
        ext_root = (ctx.get_source(["virtualMachines", "extensions", vid]) or {}).get("data") or {}
        extensions = ext_root.get("value") if isinstance(ext_root, dict) else ext_root
        names = []
        for e in (extensions or []):
            n = (e.get("name") or "").lower()
            t = ((e.get("properties") or {}).get("type") or "").lower()
            names.append(n + ":" + t)
        joined = " ".join(names)
        if any(k in joined for k in ["azuremonitor", "omsagent", "microsoftmonitoring"]):
            add_result(findings, meta=_meta_vm_la, cloud=CLOUD, code=0,
                       message="VM has monitoring agent installed",
                       region=loc, resource=vid, resource_type="VirtualMachine")
        else:
            add_result(findings, meta=_meta_vm_la, cloud=CLOUD, code=2,
                       message="VM is missing the monitoring agent",
                       region=loc, resource=vid, resource_type="VirtualMachine")
    return PluginResult(plugin_id=_meta_vm_la.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: NSG no open RDP / SSH from internet
# ──────────────────────────────────────────────────────────────────────────────

_meta_nsg_open_admin = PluginMeta(
    plugin_id="azure-nsg-open-admin-ports",
    cloud=CLOUD,
    title="NSGs: SSH/RDP Not Open to 0.0.0.0/0",
    category="Networking",
    severity=Severity.CRITICAL,
    description="Ensures no NSG rule allows SSH (22) or RDP (3389) inbound from 0.0.0.0/0 (Any).",
    recommended_action="Restrict source IP ranges for SSH/RDP rules.",
    compliance={"PCI": "PCI prohibits unrestricted admin access from the internet."},
)


def _run_nsg_open_admin(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    nsgs = (ctx.get_source(["networkSecurityGroups", "list", "global"]) or {}).get("data") or []
    for nsg in nsgs:
        nid = nsg.get("id", "")
        loc = nsg.get("location", "global")
        props = nsg.get("properties") or {}
        rules = props.get("securityRules") or []
        bad: list[str] = []
        for r in rules:
            rp = r.get("properties") or {}
            if (rp.get("direction") or "").lower() != "inbound":
                continue
            if (rp.get("access") or "").lower() != "allow":
                continue
            src = rp.get("sourceAddressPrefix") or ""
            srcs = rp.get("sourceAddressPrefixes") or []
            open_to_any = src in ("*", "0.0.0.0/0", "Internet", "Any") or any(
                s in ("*", "0.0.0.0/0", "Internet", "Any") for s in srcs
            )
            if not open_to_any:
                continue
            ports = [rp.get("destinationPortRange") or ""] + (rp.get("destinationPortRanges") or [])
            joined = " ".join(p for p in ports if p)
            if any(tok in joined for tok in ["22", "3389", "*"]):
                bad.append(r.get("name") or "rule")
        if bad:
            add_result(findings, meta=_meta_nsg_open_admin, cloud=CLOUD, code=2,
                       message=f"NSG has open admin ports: {', '.join(bad)}",
                       region=loc, resource=nid, resource_type="NetworkSecurityGroup")
        else:
            add_result(findings, meta=_meta_nsg_open_admin, cloud=CLOUD, code=0,
                       message="No open admin ports",
                       region=loc, resource=nid, resource_type="NetworkSecurityGroup")
    return PluginResult(plugin_id=_meta_nsg_open_admin.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Web App HTTPS only
# ──────────────────────────────────────────────────────────────────────────────

_meta_webapp_https = PluginMeta(
    plugin_id="azure-webapp-https-only",
    cloud=CLOUD,
    title="App Services: HTTPS Only",
    category="App Services",
    severity=Severity.HIGH,
    description="Ensures App Service web apps enforce HTTPS.",
    recommended_action="Set httpsOnly=true on every App Service web app.",
    compliance={"PCI": "Data in transit must be encrypted."},
)


def _run_webapp_https(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    apps = (ctx.get_source(["webApps", "list", "global"]) or {}).get("data") or []
    for a in apps:
        aid = a.get("id", "")
        loc = a.get("location", "global")
        props = a.get("properties") or {}
        if props.get("httpsOnly"):
            add_result(findings, meta=_meta_webapp_https, cloud=CLOUD, code=0,
                       message="HTTPS-only enabled",
                       region=loc, resource=aid, resource_type="WebApp")
        else:
            add_result(findings, meta=_meta_webapp_https, cloud=CLOUD, code=2,
                       message="HTTPS-only NOT enabled",
                       region=loc, resource=aid, resource_type="WebApp")
    return PluginResult(plugin_id=_meta_webapp_https.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Defender for Cloud — Standard plan enabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_defender = PluginMeta(
    plugin_id="azure-defender-standard-plan",
    cloud=CLOUD,
    title="Defender: Standard Plan Enabled",
    category="Defender",
    severity=Severity.HIGH,
    description="Ensures Microsoft Defender for Cloud Standard pricing tier is enabled.",
    recommended_action="Enable Standard tier on key Defender plans (VMs, SQL, KeyVault, Storage).",
)


def _run_defender(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    pricings = (ctx.get_source(["defender", "pricings", "global"]) or {}).get("data") or {}
    items = (pricings.get("value") if isinstance(pricings, dict) else None) or []
    if not items:
        add_result(findings, meta=_meta_defender, cloud=CLOUD, code=3,
                   message="Could not read Defender pricings (permission?)", region="global")
        return PluginResult(plugin_id=_meta_defender.plugin_id, findings=findings)
    for p in items:
        name = p.get("name")
        tier = (p.get("properties") or {}).get("pricingTier") or "Free"
        if tier.lower() in ("standard", "premium"):
            add_result(findings, meta=_meta_defender, cloud=CLOUD, code=0,
                       message=f"Defender for {name}: {tier}", region="global",
                       resource=name, resource_type="DefenderPlan")
        else:
            add_result(findings, meta=_meta_defender, cloud=CLOUD, code=2,
                       message=f"Defender for {name} is on Free tier", region="global",
                       resource=name, resource_type="DefenderPlan")
    return PluginResult(plugin_id=_meta_defender.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Storage account allow blob public access disabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_blob_pub = PluginMeta(
    plugin_id="azure-storage-blob-public-access-disabled",
    cloud=CLOUD,
    title="Storage Accounts: Allow Blob Public Access Disabled",
    category="Storage",
    severity=Severity.HIGH,
    description="Ensures storage accounts have 'allowBlobPublicAccess' set to false.",
    recommended_action="Set allowBlobPublicAccess=false on all storage accounts.",
)


def _run_blob_pub(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    for sa in _iter_storage_accounts(ctx):
        sid = sa.get("id", "")
        loc = sa.get("location", "global")
        props = sa.get("properties") or {}
        if props.get("allowBlobPublicAccess") is False:
            add_result(findings, meta=_meta_blob_pub, cloud=CLOUD, code=0,
                       message="Blob public access disabled",
                       region=loc, resource=sid, resource_type="StorageAccount")
        else:
            add_result(findings, meta=_meta_blob_pub, cloud=CLOUD, code=2,
                       message="Blob public access allowed",
                       region=loc, resource=sid, resource_type="StorageAccount")
    return PluginResult(plugin_id=_meta_blob_pub.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Storage account min TLS version
# ──────────────────────────────────────────────────────────────────────────────

_meta_sa_tls = PluginMeta(
    plugin_id="azure-storage-min-tls-version",
    cloud=CLOUD,
    title="Storage Accounts: Minimum TLS Version 1.2+",
    category="Storage",
    severity=Severity.HIGH,
    description="Ensures storage accounts require TLS 1.2 or higher.",
    recommended_action="Set minimumTlsVersion='TLS1_2' on all storage accounts.",
    compliance={"PCI": "PCI mandates TLS 1.2 or higher.", "HIPAA": "Modern TLS for PHI."},
)


def _run_sa_tls(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    for sa in _iter_storage_accounts(ctx):
        sid = sa.get("id", "")
        loc = sa.get("location", "global")
        props = sa.get("properties") or {}
        tls = (props.get("minimumTlsVersion") or "TLS1_0").upper()
        if tls in ("TLS1_2", "TLS1_3"):
            add_result(findings, meta=_meta_sa_tls, cloud=CLOUD, code=0,
                       message=f"Min TLS {tls}", region=loc, resource=sid, resource_type="StorageAccount")
        else:
            add_result(findings, meta=_meta_sa_tls, cloud=CLOUD, code=2,
                       message=f"Min TLS too low: {tls}", region=loc, resource=sid, resource_type="StorageAccount")
    return PluginResult(plugin_id=_meta_sa_tls.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Subscription role assignments — owner count
# ──────────────────────────────────────────────────────────────────────────────

_meta_owner_count = PluginMeta(
    plugin_id="azure-subscription-owner-count",
    cloud=CLOUD,
    title="Subscription: Owner Count <= 5",
    category="IAM",
    severity=Severity.MEDIUM,
    description="Ensures no more than 5 subscription-level Owner role assignments exist.",
    recommended_action="Reduce subscription-level Owner assignments via PIM / least privilege.",
)


def _run_owner_count(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    ra = (ctx.get_source(["roleAssignments", "list", "global"]) or {}).get("data") or []
    owners: list[str] = []
    for r in ra:
        props = r.get("properties") or {}
        rdid = (props.get("roleDefinitionId") or "").lower()
        if rdid.endswith("/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"):  # Owner
            owners.append(props.get("principalId") or "")
    if not owners:
        add_result(findings, meta=_meta_owner_count, cloud=CLOUD, code=3,
                   message="No role assignments visible", region="global")
    elif len(owners) <= 5:
        add_result(findings, meta=_meta_owner_count, cloud=CLOUD, code=0,
                   message=f"Owner role assignments: {len(owners)}", region="global",
                   resource="subscription", resource_type="Subscription")
    else:
        add_result(findings, meta=_meta_owner_count, cloud=CLOUD, code=2,
                   message=f"Excessive Owner role assignments: {len(owners)}", region="global",
                   resource="subscription", resource_type="Subscription")
    return PluginResult(plugin_id=_meta_owner_count.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin registry
# ──────────────────────────────────────────────────────────────────────────────

AZURE_PLUGINS = [
    (_meta_secure_transfer, _run_secure_transfer),
    (_meta_sa_public, _run_sa_public),
    (_meta_blob_softdelete, _run_blob_softdelete),
    (_meta_blob_pub, _run_blob_pub),
    (_meta_sa_tls, _run_sa_tls),
    (_meta_kv_key_exp, _run_kv_key_exp),
    (_meta_kv_recovery, _run_kv_recovery),
    (_meta_sql_audit, _run_sql_audit),
    (_meta_sql_aad, _run_sql_aad),
    (_meta_disk_cmk, _run_disk_cmk),
    (_meta_vm_la, _run_vm_la),
    (_meta_nsg_open_admin, _run_nsg_open_admin),
    (_meta_webapp_https, _run_webapp_https),
    (_meta_defender, _run_defender),
    (_meta_owner_count, _run_owner_count),
]
