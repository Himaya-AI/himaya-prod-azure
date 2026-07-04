"""
GitHub org-level CSPM plugins.
"""
from __future__ import annotations

from ..engine import add_result
from ..types import Finding, PluginMeta, PluginResult, ScanContext, Severity


CLOUD = "github"


def _src(ctx: ScanContext, path: list[str]) -> dict | list | None:
    s = ctx.get_source(path)
    if not s:
        return None
    return s.get("data") if isinstance(s, dict) else s


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: 2FA required for org members
# ──────────────────────────────────────────────────────────────────────────────

_meta_2fa = PluginMeta(
    plugin_id="github-org-2fa-enforced",
    cloud=CLOUD,
    title="Org: 2FA Required",
    category="Identity",
    severity=Severity.CRITICAL,
    description="Ensures GitHub organization requires 2FA for all members.",
    recommended_action="Enable 'Require two-factor authentication' in org security settings.",
    compliance={"SOC2": "Access controls require MFA for privileged accounts."},
)


def _run_2fa(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    org_info = _src(ctx, ["orgs", "get", ctx.settings.get("org", "org")]) or {}
    members_2fa = _src(ctx, ["orgs", "members2faDisabled", ctx.settings.get("org", "org")]) or []
    org = ctx.settings.get("org", "org")
    enforced = org_info.get("two_factor_requirement_enabled") if isinstance(org_info, dict) else None
    if enforced is True:
        add_result(findings, meta=_meta_2fa, cloud=CLOUD, code=0,
                   message="Org enforces 2FA",
                   resource=org, resource_type="Org")
    elif members_2fa and len(members_2fa) > 0:
        add_result(findings, meta=_meta_2fa, cloud=CLOUD, code=2,
                   message=f"Org does not enforce 2FA; {len(members_2fa)} members have 2FA disabled",
                   resource=org, resource_type="Org",
                   metadata={"members_without_2fa": [m.get("login") for m in members_2fa[:20]]})
    else:
        add_result(findings, meta=_meta_2fa, cloud=CLOUD, code=2,
                   message="Org does not enforce 2FA",
                   resource=org, resource_type="Org")
    return PluginResult(plugin_id=_meta_2fa.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Outside collaborators limited
# ──────────────────────────────────────────────────────────────────────────────

_meta_outside = PluginMeta(
    plugin_id="github-org-outside-collaborators",
    cloud=CLOUD,
    title="Org: Outside Collaborator Count Reviewed",
    category="Identity",
    severity=Severity.MEDIUM,
    description="Flags when org has many outside collaborators (potential supply-chain risk).",
    recommended_action="Audit outside collaborators; remove unnecessary access.",
)


def _run_outside(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    org = ctx.settings.get("org", "org")
    collabs = _src(ctx, ["orgs", "outsideCollaborators", org]) or []
    if not collabs:
        add_result(findings, meta=_meta_outside, cloud=CLOUD, code=0,
                   message="No outside collaborators",
                   resource=org, resource_type="Org")
    elif len(collabs) > 20:
        add_result(findings, meta=_meta_outside, cloud=CLOUD, code=2,
                   message=f"Org has {len(collabs)} outside collaborators (review)",
                   resource=org, resource_type="Org",
                   metadata={"collaborator_count": len(collabs)})
    else:
        add_result(findings, meta=_meta_outside, cloud=CLOUD, code=1,
                   message=f"Org has {len(collabs)} outside collaborators",
                   resource=org, resource_type="Org",
                   metadata={"collaborator_count": len(collabs)})
    return PluginResult(plugin_id=_meta_outside.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Default branch protection
# ──────────────────────────────────────────────────────────────────────────────

_meta_bp = PluginMeta(
    plugin_id="github-repo-default-branch-protection",
    cloud=CLOUD,
    title="Repos: Default Branch Protection Enabled",
    category="Repos",
    severity=Severity.HIGH,
    description="Ensures default branch has protection rules.",
    recommended_action="Enable branch protection: require PR reviews, dismiss stale approvals, restrict pushes.",
)


def _run_bp(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    org = ctx.settings.get("org", "org")
    repos = _src(ctx, ["repos", "list", org]) or []
    for r in repos:
        full = r.get("full_name")
        if not full or r.get("archived") or r.get("disabled"):
            continue
        bp = _src(ctx, ["repos", "branchProtection", full])
        if bp and isinstance(bp, dict) and bp.get("required_pull_request_reviews"):
            add_result(findings, meta=_meta_bp, cloud=CLOUD, code=0,
                       message="Default branch protected with PR review",
                       resource=full, resource_type="Repo")
        elif bp and isinstance(bp, dict) and bp.get("url"):
            add_result(findings, meta=_meta_bp, cloud=CLOUD, code=1,
                       message="Default branch protected but no PR review required",
                       resource=full, resource_type="Repo")
        else:
            add_result(findings, meta=_meta_bp, cloud=CLOUD, code=2,
                       message="Default branch has no protection",
                       resource=full, resource_type="Repo")
    return PluginResult(plugin_id=_meta_bp.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Secret scanning enabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_secret_scan = PluginMeta(
    plugin_id="github-repo-secret-scanning-enabled",
    cloud=CLOUD,
    title="Repos: Secret Scanning Enabled",
    category="Repos",
    severity=Severity.HIGH,
    description="Ensures secret scanning is enabled and no open alerts exist.",
    recommended_action="Enable secret scanning + push protection on every repo.",
)


def _run_secret_scan(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    org = ctx.settings.get("org", "org")
    repos = _src(ctx, ["repos", "list", org]) or []
    for r in repos:
        full = r.get("full_name")
        if not full or r.get("archived"):
            continue
        details = _src(ctx, ["repos", "details", full]) or {}
        ss = ((details.get("security_and_analysis") or {}).get("secret_scanning") or {})
        state = ss.get("status", "")
        alerts = _src(ctx, ["repos", "secretScanningAlerts", full]) or []
        open_alerts = [a for a in alerts if a.get("state") == "open"]
        if state == "enabled" and not open_alerts:
            add_result(findings, meta=_meta_secret_scan, cloud=CLOUD, code=0,
                       message="Secret scanning enabled, no open alerts",
                       resource=full, resource_type="Repo")
        elif state == "enabled" and open_alerts:
            add_result(findings, meta=_meta_secret_scan, cloud=CLOUD, code=2,
                       message=f"Secret scanning has {len(open_alerts)} open alert(s)",
                       resource=full, resource_type="Repo",
                       metadata={"open_alert_count": len(open_alerts)})
        else:
            add_result(findings, meta=_meta_secret_scan, cloud=CLOUD, code=2,
                       message="Secret scanning is not enabled",
                       resource=full, resource_type="Repo")
    return PluginResult(plugin_id=_meta_secret_scan.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Dependabot vulnerability alerts enabled
# ──────────────────────────────────────────────────────────────────────────────

_meta_vuln = PluginMeta(
    plugin_id="github-repo-vulnerability-alerts-enabled",
    cloud=CLOUD,
    title="Repos: Vulnerability Alerts Enabled",
    category="Repos",
    severity=Severity.HIGH,
    description="Ensures Dependabot vulnerability alerts are enabled on every repo.",
    recommended_action="Enable Dependabot alerts under repo Security settings.",
)


def _run_vuln(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    org = ctx.settings.get("org", "org")
    repos = _src(ctx, ["repos", "list", org]) or []
    for r in repos:
        full = r.get("full_name")
        if not full or r.get("archived"):
            continue
        v = ctx.get_source(["repos", "vulnerabilityAlerts", full]) or {}
        # GitHub returns 204 (no content) when enabled. Our wrapper sees this as
        # err=None data={} or err='HTTP 404' if disabled.
        err = v.get("err") if isinstance(v, dict) else None
        if not err:
            add_result(findings, meta=_meta_vuln, cloud=CLOUD, code=0,
                       message="Vulnerability alerts enabled",
                       resource=full, resource_type="Repo")
        elif "404" in (err or ""):
            add_result(findings, meta=_meta_vuln, cloud=CLOUD, code=2,
                       message="Vulnerability alerts NOT enabled",
                       resource=full, resource_type="Repo")
        else:
            add_result(findings, meta=_meta_vuln, cloud=CLOUD, code=3,
                       message=f"Could not check vulnerability alerts: {err}",
                       resource=full, resource_type="Repo")
    return PluginResult(plugin_id=_meta_vuln.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Code scanning open alerts
# ──────────────────────────────────────────────────────────────────────────────

_meta_code_scan = PluginMeta(
    plugin_id="github-repo-code-scanning-open-alerts",
    cloud=CLOUD,
    title="Repos: Code Scanning Open Alerts",
    category="Repos",
    severity=Severity.HIGH,
    description="Flags repos with open code scanning alerts.",
    recommended_action="Resolve open code scanning alerts.",
)


def _run_code_scan(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    org = ctx.settings.get("org", "org")
    repos = _src(ctx, ["repos", "list", org]) or []
    for r in repos:
        full = r.get("full_name")
        if not full or r.get("archived"):
            continue
        alerts = _src(ctx, ["repos", "codeScanningAlerts", full]) or []
        open_a = [a for a in alerts if a.get("state") == "open"]
        if open_a:
            sev_counts = {}
            for a in open_a:
                s = (a.get("rule") or {}).get("severity") or "warning"
                sev_counts[s] = sev_counts.get(s, 0) + 1
            add_result(findings, meta=_meta_code_scan, cloud=CLOUD, code=2,
                       message=f"{len(open_a)} open code scanning alert(s)",
                       resource=full, resource_type="Repo",
                       metadata={"open_alerts_by_severity": sev_counts})
        else:
            # Don't emit OK for every repo without alerts — keeps the result list lean.
            pass
    return PluginResult(plugin_id=_meta_code_scan.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Webhook HTTPS-only
# ──────────────────────────────────────────────────────────────────────────────

_meta_hook_https = PluginMeta(
    plugin_id="github-org-webhook-https-only",
    cloud=CLOUD,
    title="Org: Webhooks Use HTTPS",
    category="Org",
    severity=Severity.MEDIUM,
    description="Ensures org-level webhooks only use HTTPS URLs.",
    recommended_action="Update non-HTTPS webhook URLs.",
)


def _run_hook_https(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    org = ctx.settings.get("org", "org")
    hooks = _src(ctx, ["orgs", "hooks", org]) or []
    bad = []
    for h in hooks:
        url = (h.get("config") or {}).get("url", "")
        if url and not url.startswith("https://"):
            bad.append(url)
    if bad:
        add_result(findings, meta=_meta_hook_https, cloud=CLOUD, code=2,
                   message=f"{len(bad)} webhook(s) use non-HTTPS URLs",
                   resource=org, resource_type="Org",
                   metadata={"non_https_urls": bad[:10]})
    else:
        add_result(findings, meta=_meta_hook_https, cloud=CLOUD, code=0,
                   message="All org webhooks use HTTPS",
                   resource=org, resource_type="Org")
    return PluginResult(plugin_id=_meta_hook_https.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Plugin: Repos with too many admins
# ──────────────────────────────────────────────────────────────────────────────

_meta_admins = PluginMeta(
    plugin_id="github-repo-excessive-admins",
    cloud=CLOUD,
    title="Repos: Excessive Admin Collaborators",
    category="Repos",
    severity=Severity.MEDIUM,
    description="Flags repos with more than 5 admin collaborators.",
    recommended_action="Reduce admin collaborators to the minimum required.",
)


def _run_admins(ctx: ScanContext) -> PluginResult:
    findings: list[Finding] = []
    org = ctx.settings.get("org", "org")
    repos = _src(ctx, ["repos", "list", org]) or []
    for r in repos:
        full = r.get("full_name")
        if not full or r.get("archived"):
            continue
        collabs = _src(ctx, ["repos", "collaborators", full]) or []
        admins = [c for c in collabs if (c.get("permissions") or {}).get("admin")]
        if len(admins) > 5:
            add_result(findings, meta=_meta_admins, cloud=CLOUD, code=2,
                       message=f"{len(admins)} admin collaborators",
                       resource=full, resource_type="Repo",
                       metadata={"admin_logins": [a.get("login") for a in admins[:20]]})
    return PluginResult(plugin_id=_meta_admins.plugin_id, findings=findings)


# ──────────────────────────────────────────────────────────────────────────────
# Registry
# ──────────────────────────────────────────────────────────────────────────────

GITHUB_PLUGINS = [
    (_meta_2fa, _run_2fa),
    (_meta_outside, _run_outside),
    (_meta_bp, _run_bp),
    (_meta_secret_scan, _run_secret_scan),
    (_meta_vuln, _run_vuln),
    (_meta_code_scan, _run_code_scan),
    (_meta_hook_https, _run_hook_https),
    (_meta_admins, _run_admins),
]
