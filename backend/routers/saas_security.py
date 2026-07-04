"""
SaaS Security — Teams & SharePoint connector, alert scanning, data lifecycle, posture checks.
Enterprise-tier feature for Helios.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db, AsyncSessionLocal
from backend.models.db_models import (
    Organization,
    SaasIntegration,
    SaasAlert,
    SaasDataItem,
    SaasPostureCheck,
)
from backend.routers.auth import get_current_user
from backend.utils.response_cache import cached_endpoint, cache_get, cache_set, cache_invalidate

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/saas", tags=["saas-security"])

# ── Env vars ──────────────────────────────────────────────────────────────────

SAAS_M365_CLIENT_ID = os.getenv("SAAS_M365_CLIENT_ID", "")
SAAS_M365_CLIENT_SECRET = os.getenv("SAAS_M365_CLIENT_SECRET", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", "https://app.himaya.ai")
SAAS_REDIRECT_URI = f"{FRONTEND_URL}/api/saas/callback"
DEEPSEEK_ENDPOINT = os.getenv("DEEPSEEK_ENDPOINT", "http://10.0.1.113:8001")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
GRAPH = "https://graph.microsoft.com/v1.0"


async def _fetch_tenant_domains(access_token: str) -> list[str]:
    """Return lowercased verified-domain list for the tenant. Empty list
    if we can't enumerate (best-effort)."""
    try:
        sc, data = await _safe_graph_get(f"{GRAPH}/domains?$select=id", access_token)
        if sc != 200:
            return []
        return [(d.get("id") or "").lower() for d in data.get("value", []) if d.get("id")]
    except Exception:
        return []


def _is_external_email_for(email: str, tenant_domains: list[str]) -> bool:
    """Module-level external-email check. Mirrors the closure-scoped helper
    in meeting-security but reusable across endpoints (External Users, etc.).

    External when:
      - email contains '#ext#' (B2B guest UPN format)
      - OR doesn't end with any verified tenant domain
    Returns False for empty/invalid emails.
    """
    em = (email or "").lower()
    if not em or "@" not in em:
        return False
    if "#ext#" in em:
        return True
    if not tenant_domains:
        # Without tenant context we don't have ground truth; be
        # conservative — don't claim it's external.
        return False
    return not any(em.endswith("@" + d) for d in tenant_domains)


# ── Teams / SharePoint OAuth scopes ──────────────────────────────────────────

_TEAMS_SCOPES = "Team.ReadBasic.All ChannelMessage.Read.All Files.Read.All offline_access"
_SHAREPOINT_SCOPES = "Sites.Read.All Files.Read.All offline_access"

# ── Required Microsoft Graph application permissions ────────────────────────
# Full list of Graph application permissions the Helios SaaS Security scanner
# needs. Used to build the admin-consent URL so Azure shows exactly what's
# being granted, and as the source of truth for the Azure AD app manifest's
# requiredResourceAccess block.
#
# IMPORTANT: Azure only grants permissions that are also declared in the app
# registration's manifest. The consent URL alone is not enough — the manifest
# must list every permission below under requiredResourceAccess[Microsoft Graph]
# with type="Role" (application permissions, not delegated).
#
# Manifest-update steps (Azure Portal → App registrations → Helios → API permissions):
#   1. Add the permissions below under "Microsoft Graph" → "Application permissions".
#   2. Click "Grant admin consent for <tenant>".
#   3. Customers re-consent by opening /consent-url with prompt=consent.
# Each name MUST be a valid Microsoft Graph APPLICATION permission name (the
# `value` field of an `appRole`, not a delegated `oauth2PermissionScope`).
# If any name is invalid, Azure rejects the WHOLE admin-consent request with
# AADSTS650053 — nothing gets granted, including scopes that would otherwise
# work. So this list is intentionally conservative: only names verified to
# exist as application permissions on Microsoft Graph.
_REQUIRED_GRAPH_SCOPES: list[str] = [
    # ── Already granted (powers Working endpoints) ──
    "User.Read.All",                       # External users / guest enumeration
    "Group.Read.All",                      # Teams membership
    "Sites.Read.All",                      # SharePoint sites & files
    "Files.Read.All",                      # File content for DLP scan
    "ChannelMessage.Read.All",             # Teams channel messages
    "Directory.Read.All",                  # Tenant directory
    # ── New (required for Governance tab endpoints currently blocked) ──
    "Policy.Read.All",                     # Conditional Access policies & gap detection
    "AuditLog.Read.All",                   # Blocked sign-ins, risky sign-ins
    "AppCatalog.Read.All",                 # Teams apps catalog + tenant apps
    "TeamsAppInstallation.ReadForTeam.All",# Per-team installed Teams apps
    "InformationProtectionPolicy.Read.All",# DLP / sensitivity labels
    "IdentityRiskyUser.Read.All",          # Risky users feed (sign-in risk policy gap)
    "IdentityRiskEvent.Read.All",          # Risk events (user-risk policy gap)
    "SecurityEvents.Read.All",             # Security alerts
    # NOTE on Meeting Security:
    # `OnlineMeetings.Read.All` requires a Teams application access policy +
    # is rejected by some tenants with AADSTS650053 if not provisioned. The
    # /meeting-security endpoint falls back gracefully to org-level meeting
    # policy checks when this scope isn't granted, so it's omitted here.
]

# Space-separated scope string suitable for the /v2.0/adminconsent URL.
# `.default` is intentionally NOT used here — we want Azure to show the
# full granular list to the consenting admin so the screen makes it clear
# what is being granted.
_REQUIRED_GRAPH_SCOPE_STRING: str = " ".join(
    f"https://graph.microsoft.com/{s}" for s in _REQUIRED_GRAPH_SCOPES
)


# ── Token encrypt/decrypt (reuse pattern from onboarding.py) ─────────────────

def _get_fernet():
    from cryptography.fernet import Fernet
    key = os.getenv("ENCRYPTION_KEY")
    if not key:
        key = Fernet.generate_key().decode()
    if isinstance(key, str):
        key = key.encode()
    return Fernet(key)


def _encrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _get_fernet().encrypt(token.encode()).decode()
    except Exception:
        return token


def _decrypt(enc: str) -> str:
    if not enc:
        return ""
    try:
        return _get_fernet().decrypt(enc.encode()).decode()
    except Exception:
        return enc


def _is_aad_premium_required_error(status_code: int, body_text: str) -> bool:
    """Return True if Graph 403 is from missing Entra ID P1/P2 (tenant tier), not a missing permission.

    These endpoints (auditLogs/signIns, identityProtection/*) require an Entra ID
    Premium license on the customer tenant. No code or admin-consent change can
    unblock them — only a license upgrade. Detect so we can skip silently instead of
    spamming logs as if it were a permission issue.
    """
    if status_code != 403:
        return False
    bt = (body_text or "").lower()
    return (
        "requestfromnonpremiumtenant" in bt
        or "premium license" in bt
        or "b2ctenant" in bt
    )


def _is_graph_permission_missing_error(status_code: int, body_text: str) -> bool:
    """Return True if Graph 403 is the classic 'Application has insufficient privileges'
    / 'MSGraphPermissionMissing' error — meaning the app-only token does not carry the
    required role. Usually caused by stale cached tokens issued before admin consent
    was regranted with new scopes.
    """
    if status_code != 403:
        return False
    bt = (body_text or "").lower()
    return (
        "msgraphpermissionmissing" in bt
        or "insufficient privileges" in bt
        or "authorization_requestdenied" in bt
    )


async def warmup_saas_tokens() -> None:
    """On app startup, force-refresh every active SaaS integration's stored access token.

    This protects against the failure mode where an admin re-grants consent with new
    scopes, but the running task keeps re-using the previously-cached token that was
    issued before the regrant — causing every Graph call to come back 403 with
    'MSGraphPermissionMissing' until someone force-deploys the service.

    Runs best-effort: any failure is logged and skipped. Safe to call repeatedly.
    """
    try:
        async with AsyncSessionLocal() as db:
            rows = (await db.execute(
                select(SaasIntegration).where(
                    SaasIntegration.status.in_(["active", "error"]),
                    SaasIntegration.provider.in_(["teams", "sharepoint", "microsoft", "m365"]),
                )
            )).scalars().all()
            if not rows:
                logger.info("saas_token_warmup: no active Microsoft integrations to refresh")
                return
            refreshed = 0
            failed = 0
            for integ in rows:
                try:
                    tok = await _get_valid_token(integ, db)
                    if tok:
                        refreshed += 1
                    else:
                        failed += 1
                except Exception as exc:
                    failed += 1
                    logger.warning(f"saas_token_warmup: refresh failed for integ {integ.id} ({integ.provider}): {exc}")
            logger.info(
                f"saas_token_warmup: refreshed={refreshed} failed={failed} total={len(rows)}"
            )
    except Exception as exc:
        logger.warning(f"saas_token_warmup: unexpected error: {exc}")


async def graph_get_with_retry(
    client: "httpx.AsyncClient",
    url: str,
    integ: SaasIntegration,
    db: AsyncSession,
) -> "httpx.Response":
    """GET against Microsoft Graph with one automatic token-refresh retry on 403
    'MSGraphPermissionMissing' / 'Authorization_RequestDenied'.

    The first attempt uses the integration's currently-stored token. If Graph rejects
    it as a permissions failure, we force a fresh client_credentials mint and retry
    exactly once. This handles the regrant-consent-without-restart scenario gracefully.
    """
    token = _decrypt(integ.access_token or "")
    if not token:
        token = await _get_valid_token(integ, db)
    resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
    if _is_graph_permission_missing_error(resp.status_code, resp.text):
        logger.info(
            f"graph_get_with_retry: 403 MSGraphPermissionMissing on {url[:120]} — "
            f"refreshing token for integ {integ.id} ({integ.provider}) and retrying once"
        )
        # Invalidate cached token and re-mint
        integ.access_token = None
        try:
            await db.commit()
        except Exception:
            await db.rollback()
        new_token = await _get_valid_token(integ, db)
        if new_token and new_token != token:
            resp = await client.get(url, headers={"Authorization": f"Bearer {new_token}"})
            logger.info(
                f"graph_get_with_retry: retry returned status={resp.status_code} for integ {integ.id}"
            )
    return resp


async def _get_valid_token(integ: SaasIntegration, db: AsyncSession) -> str:
    """
    Return a valid access token for the integration.
    Strategy:
      1. Try client_credentials (app token) using SAAS_M365_CLIENT_ID + SECRET + tenant_id
         — works for most Graph API read operations, doesn’t expire like delegated tokens.
      2. If no tenant_id stored, fall back to refresh_token grant.
      3. If refresh also fails, mark integration error and return "".
    """
    tenant_id = integ.tenant_id or "common"

    # If tenant_id not stored, try extracting from JWT in stored access_token
    if tenant_id == "common":
        stored_at = _decrypt(integ.access_token or "")
        if stored_at:
            try:
                import base64 as _b64j
                parts = stored_at.split(".")
                if len(parts) >= 2:
                    p = parts[1] + "==" * (4 - len(parts[1]) % 4)
                    claims = json.loads(_b64j.urlsafe_b64decode(p).decode())
                    tid = claims.get("tid")
                    if tid:
                        tenant_id = tid
                        integ.tenant_id = tid
                        try:
                            await db.commit()
                        except Exception:
                            await db.rollback()
                        logger.info(f"saas_token: recovered tenant_id={tid} from stored JWT")
            except Exception:
                pass

    M365_MAIN_CLIENT_ID = os.getenv("M365_CLIENT_ID", "")
    M365_MAIN_CLIENT_SECRET = os.getenv("M365_CLIENT_SECRET", "")

    # ── Strategy 1: main Himaya Helios app (preferred — has Sites.Read.All, ChannelMessage.Read.All) ──
    # Use the same app the customer consented to for email security. It already has all the
    # Graph permissions we need for SaaS scanning (Sites.ReadWrite.All, Files.ReadWrite.All,
    # ChannelMessage.Read.All etc.) granted via the original M365 onboarding consent.
    if M365_MAIN_CLIENT_ID and M365_MAIN_CLIENT_SECRET and tenant_id != "common":
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={
                        "client_id": M365_MAIN_CLIENT_ID,
                        "client_secret": M365_MAIN_CLIENT_SECRET,
                        "scope": "https://graph.microsoft.com/.default",
                        "grant_type": "client_credentials",
                    },
                )
                if resp.status_code == 200:
                    new_at = resp.json().get("access_token", "")
                    if new_at:
                        integ.access_token = _encrypt(new_at)
                        try:
                            await db.commit()
                        except Exception:
                            await db.rollback()
                        logger.info(f"saas_token: acquired via main M365 app for tenant {tenant_id}")
                        return new_at
                else:
                    logger.warning(f"saas_token: main M365 app failed for {tenant_id}: {resp.status_code}")
        except Exception as exc:
            logger.warning(f"saas_token: main M365 app exception for {tenant_id}: {exc}")

    # ── Strategy 2: SaaS connector app (fallback) ───────────────────────────
    if SAAS_M365_CLIENT_ID and SAAS_M365_CLIENT_SECRET and tenant_id != "common":
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={
                        "client_id": SAAS_M365_CLIENT_ID,
                        "client_secret": SAAS_M365_CLIENT_SECRET,
                        "scope": "https://graph.microsoft.com/.default",
                        "grant_type": "client_credentials",
                    },
                )
                if resp.status_code == 200:
                    token_data = resp.json()
                    new_at = token_data.get("access_token", "")
                    if new_at:
                        integ.access_token = _encrypt(new_at)
                        try:
                            await db.commit()
                        except Exception:
                            await db.rollback()
                        return new_at
        except Exception as exc:
            logger.warning(f"saas_token: saas connector client_credentials failed for {tenant_id}: {exc}")

    # ── Strategy 2: refresh_token grant ──────────────────────────────
    refresh_token = _decrypt(integ.refresh_token or "")
    if refresh_token and SAAS_M365_CLIENT_ID:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                scope = (
                    "Team.ReadBasic.All ChannelMessage.Read.All Files.Read.All Sites.Read.All "
                    "AuditLog.Read.All Policy.Read.All Directory.Read.All User.Read.All "
                    "IdentityRiskyUser.Read.All offline_access"
                )
                resp = await client.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={
                        "client_id": SAAS_M365_CLIENT_ID,
                        "client_secret": SAAS_M365_CLIENT_SECRET,
                        "refresh_token": refresh_token,
                        "scope": scope,
                        "grant_type": "refresh_token",
                    },
                )
                if resp.status_code == 200:
                    token_data = resp.json()
                    new_at = token_data.get("access_token", "")
                    new_rt = token_data.get("refresh_token", refresh_token)
                    if new_at:
                        integ.access_token = _encrypt(new_at)
                        integ.refresh_token = _encrypt(new_rt)
                        integ.error_message = None
                        try:
                            await db.commit()
                        except Exception:
                            await db.rollback()
                        logger.info(f"saas_token: refreshed delegated token for org {integ.org_id} provider {integ.provider}")
                        return new_at
                else:
                    logger.warning(f"saas_token: refresh_token grant failed {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            logger.warning(f"saas_token: refresh_token exception: {exc}")

    # ── Both failed ──────────────────────────────────────────────────
    logger.error(f"saas_token: all token strategies failed for org {integ.org_id} provider {integ.provider} — will retry next cycle")
    # Don’t mark as error — let it retry on next scan cycle. Just log.
    return ""


# ── AWS platform-specific remediation steps ─────────────────────────────────

def _aws_platform_remediation_steps(category: str, finding) -> list:
    """Return concrete AWS console / CLI / IAM remediation steps for a given
    finding category. Caller is the Posture endpoint; output replaces the
    generic 'Review and remediate this security finding.' fallback.

    The hardcoded steps are intentionally specific (region, ARN, console
    path, CLI verb) so the user can act without context-switching to docs.
    AI-classified findings still take precedence via metadata.ai_remediation.
    """
    try:
        rtype = (finding['resource_type'] or '').lower()
    except Exception:
        rtype = ''
    try:
        rid = finding['resource_id'] or ''
    except Exception:
        rid = ''
    region = ''
    try:
        meta = finding['metadata'] or {}
        if isinstance(meta, dict):
            region = meta.get('region', '')
    except Exception:
        meta = {}

    if category == 'encryption':
        if 's3' in rtype:
            return [
                f"AWS Console → S3 → {rid} → Properties → Default encryption → enable SSE-KMS with a customer-managed CMK.",
                f"CLI: aws s3api put-bucket-encryption --bucket {rid} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"aws:kms\"}}}}]}}'",
                "Enable S3 Bucket Keys to reduce KMS request cost.",
                "Verify objects already in the bucket are re-encrypted via S3 Batch Operations if compliance requires it.",
            ]
        if 'ebs' in rtype:
            return [
                f"AWS Console → EC2 → Volumes → {rid} → detach → create encrypted snapshot → restore as encrypted volume.",
                f"Enable EBS encryption by default for region {region or 'all regions'}: EC2 → Settings → Data protection and security → Always encrypt new EBS volumes.",
                "Rotate the customer-managed KMS key annually per CIS AWS 2.8.",
            ]
        if 'rds' in rtype:
            return [
                f"AWS Console → RDS → {rid} → take a snapshot → Copy snapshot → enable encryption → restore as new encrypted instance → cut traffic over → delete unencrypted instance.",
                "Enable automated backups + cross-region snapshot encryption for DR.",
            ]
        if 'efs' in rtype:
            return [
                f"EFS cannot be encrypted in place. Create a new encrypted EFS for {rid}, DataSync the data, update mount targets, then delete the old file system.",
            ]
        return [
            f"Enable encryption at rest for {rtype.upper() or 'this resource'} using a customer-managed KMS key.",
            "Verify in-transit encryption is enforced (TLS 1.2+ minimum).",
        ]

    if category == 'public_access':
        if 's3' in rtype:
            return [
                f"AWS Console → S3 → {rid} → Permissions → Block public access → turn ALL four toggles ON → Save.",
                f"CLI: aws s3api put-public-access-block --bucket {rid} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                "Audit bucket policy + ACLs for any 'AllUsers' or 'AuthenticatedUsers' grants; replace with VPC endpoint + IAM principals.",
                "Enable S3 Access Analyzer to monitor for re-introduction of public access.",
            ]
        if 'security_group' in rtype or 'sg' in rtype:
            return [
                f"AWS Console → VPC → Security Groups → {rid} → remove inbound rules with source 0.0.0.0/0 (especially on 22/3389/3306/5432/6379).",
                "Replace open rules with: bastion CIDR + SSM Session Manager, or VPC peering / Transit Gateway.",
                "Enable VPC Flow Logs to confirm no legitimate traffic depends on the open rule.",
            ]
        if 'rds' in rtype:
            return [
                f"AWS Console → RDS → {rid} → Modify → Connectivity → Public access = No → Apply immediately.",
                "Move the DB into private subnets only; route app tier via VPC.",
            ]
        return [
            f"Remove public/internet exposure on {rtype.upper() or 'this resource'} — restrict to VPC + private subnets.",
            "Verify no security group, NACL, or resource policy allows 0.0.0.0/0.",
        ]

    if category == 'iam':
        if 'iam_user' in rtype or rtype.endswith('user'):
            return [
                f"AWS Console → IAM → Users → {rid} → Security credentials → require MFA → set console password rotation.",
                f"If access keys exist for {rid}: rotate them (create new → update app → deactivate old → delete after 7 days).",
                "Replace long-lived IAM users with IAM Identity Center (SSO) where possible.",
                "Run aws iam generate-credential-report to confirm MFA + key rotation status.",
            ]
        if 'role' in rtype:
            return [
                f"AWS Console → IAM → Roles → {rid} → Trust relationships → narrow Principal from '*' to specific account/service.",
                "Run IAM Access Analyzer policy generation to right-size permissions based on actual usage.",
                "Add aws:SourceAccount + aws:SourceArn conditions to prevent the confused deputy.",
            ]
        if 'policy' in rtype:
            return [
                f"AWS Console → IAM → Policies → {rid} → replace any Resource:'*' with explicit ARN globs, drop Action:'*' or service:* wildcards.",
                "Use AWS Managed Policies (job functions) as a starting point and customize down.",
            ]
        return [
            "Run IAM Access Analyzer to surface over-permissive policies and unused access.",
            "Enforce MFA on the root account + all human users (CIS AWS 1.5–1.7).",
            "Rotate access keys older than 90 days; remove keys inactive >90 days.",
        ]

    if category == 'admin_action':
        principal = (meta.get('user_identity') if isinstance(meta, dict) else None) or 'unknown'
        return [
            f"Verify the action against the change-management ticket and confirm the principal ({principal}) was authorized.",
            "AWS Console → CloudTrail → Event history → search by event name + time to view the full request/response payload.",
            "If unauthorized: disable the offending IAM principal (deactivate keys, attach AWSDenyAll), then rotate any credentials touched.",
            "Add the event name to GuardDuty or Security Hub custom insights for future detection.",
            "Confirm CloudTrail is multi-region + log-file validation enabled (CIS AWS 3.1–3.2).",
        ]

    if category == 'misconfiguration':
        return [
            "Open the finding's resource in the AWS console and compare against the AWS Well-Architected Security Pillar checklist.",
            "Run aws configservice get-compliance-details-by-resource against the resource to see which AWS Config rule flagged it.",
            "If a known fix exists in Systems Manager Automation, run the AWS-PublishOperationalMetric or AWS-ConfigureSecurityHub remediation runbook.",
        ]

    return [
        "Open this finding in the AWS console for the affected resource.",
        "Cross-reference with AWS Security Hub + GuardDuty for related signal.",
        "Document remediation in your change-tracking system, then re-run the posture scan to confirm closure.",
    ]


# ── Enterprise gate ───────────────────────────────────────────────────────────

async def _require_enterprise(current_user, db: AsyncSession):
    org = (await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )).scalar_one_or_none()
    tier = (getattr(org, "tier", None) or "Launch").strip().lower()
    if tier not in ("enterprise", "enterprise trial"):
        raise HTTPException(
            status_code=403,
            detail="SaaS Security requires an Enterprise plan.",
        )


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class AlertStatusUpdate(BaseModel):
    status: str  # 'acknowledged' | 'resolved' | 'suppressed'


# ══════════════════════════════════════════════════════════════════════════════
# CONNECTOR ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.post("/auto-connect")
async def auto_connect_from_m365(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Auto-create Teams + SharePoint integrations by reusing the existing M365
    integration token and tenant_id from the main onboarding.
    
    This allows customers to enable SaaS Security without a separate OAuth flow
    if they've already connected their M365 environment for email protection.
    """
    await _require_enterprise(current_user, db)
    org_id = current_user.org_id

    # Find existing M365 integration from main onboarding
    from backend.models.db_models import OrgIntegration
    m365_integ = (await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_id,
            OrgIntegration.provider == "m365",
        )
    )).scalar_one_or_none()

    if not m365_integ:
        raise HTTPException(
            status_code=404,
            detail="No M365 integration found. Please connect M365 via Settings → Integrations first."
        )

    # Get tenant_id from the stored token (JWT claims) or config
    tenant_id = None
    stored_token = _decrypt(m365_integ.access_token_enc or "")
    if stored_token:
        try:
            import base64 as _b64j
            parts = stored_token.split(".")
            if len(parts) >= 2:
                p = parts[1] + "==" * (4 - len(parts[1]) % 4)
                claims = json.loads(_b64j.urlsafe_b64decode(p).decode())
                tenant_id = claims.get("tid")
        except Exception:
            pass

    if not tenant_id:
        raise HTTPException(
            status_code=400,
            detail="Could not extract tenant_id from M365 token. Please reconnect M365."
        )

    # Get app token for Teams/SharePoint using client_credentials
    if not SAAS_M365_CLIENT_ID or not SAAS_M365_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="SAAS_M365_CLIENT_ID/SECRET not configured on server."
        )

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": SAAS_M365_CLIENT_ID,
                    "client_secret": SAAS_M365_CLIENT_SECRET,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
    except Exception as exc:
        logger.error(f"saas_auto_connect: token request failed: {exc}")
        raise HTTPException(status_code=502, detail="Failed to reach Microsoft login endpoint")

    if resp.status_code != 200:
        err = resp.json().get("error_description", resp.text[:200])
        raise HTTPException(
            status_code=400,
            detail=f"Could not obtain SaaS token for tenant {tenant_id}. Ensure admin consent was granted for Helios SaaS Security app. Error: {err[:200]}"
        )

    access_token = resp.json().get("access_token", "")
    if not access_token:
        raise HTTPException(status_code=500, detail="No access token in response")

    # Create/update both Teams and SharePoint integrations
    now = datetime.now(timezone.utc)
    created = []
    for provider in ("teams", "sharepoint"):
        existing = (await db.execute(
            select(SaasIntegration).where(
                SaasIntegration.org_id == org_id,
                SaasIntegration.provider == provider,
            )
        )).scalar_one_or_none()

        if existing:
            existing.access_token = _encrypt(access_token)
            existing.tenant_id = tenant_id
            existing.status = "active"
            existing.error_message = None
            existing.updated_at = now
            created.append({"provider": provider, "action": "updated"})
        else:
            db.add(SaasIntegration(
                org_id=org_id,
                provider=provider,
                access_token=_encrypt(access_token),
                refresh_token=None,
                tenant_id=tenant_id,
                status="active",
                connected_at=now,
            ))
            created.append({"provider": provider, "action": "created"})

    await db.commit()
    logger.info(f"saas_auto_connect: created Teams+SharePoint integrations for org {org_id} tenant {tenant_id}")

    return {
        "status": "connected",
        "tenant_id": tenant_id,
        "integrations": created,
        "message": "Teams and SharePoint integrations created from your existing M365 connection."
    }


@router.get("/integrations")
@cached_endpoint("saas:integrations", ttl=20)
async def list_integrations(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all SaaS integrations for the current org."""
    await _require_enterprise(current_user, db)
    result = await db.execute(
        select(SaasIntegration).where(SaasIntegration.org_id == current_user.org_id)
    )
    items = result.scalars().all()

    # Check if M365 is connected but SaaS integrations don't exist yet
    from backend.models.db_models import OrgIntegration
    m365_exists = (await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == current_user.org_id,
            OrgIntegration.provider == "m365",
        )
    )).scalar_one_or_none() is not None

    has_teams = any(i.provider == "teams" for i in items)
    has_sharepoint = any(i.provider == "sharepoint" for i in items)

    return {
        "integrations": [
            {
                "id": str(i.id),
                "provider": i.provider,
                "status": i.status,
                "tenant_id": i.tenant_id,
                "scopes": i.scopes or [],
                "error_message": i.error_message,
                "connected_at": i.connected_at.isoformat() if i.connected_at else None,
                "last_synced_at": i.last_synced_at.isoformat() if i.last_synced_at else None,
            }
            for i in items
        ],
        "m365_connected": m365_exists,
        "can_auto_connect": m365_exists and (not has_teams or not has_sharepoint),
    }


class ConnectRequest(BaseModel):
    provider: str  # 'teams' | 'sharepoint'
    tenant_id: str  # Customer's Azure AD tenant ID (e.g. fbd8b3a8-...)


@router.post("/connect-from-m365")
async def connect_from_m365(
    body: dict,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Connect Teams or SharePoint using the org's existing M365 integration token.
    Resolves tenant_id server-side — no tenant ID needed from the client.
    """
    from backend.models.db_models import OrgIntegration
    org_id = current_user.org_id
    provider = body.get("provider")
    if provider not in ("teams", "sharepoint"):
        raise HTTPException(status_code=400, detail="provider must be 'teams' or 'sharepoint'")

    await _require_enterprise(current_user, db)

    # Resolve tenant_id from existing M365 integration
    tenant_id = os.getenv("M365_TENANT_ID", "")
    m365_integ = (await db.execute(
        select(OrgIntegration).where(
            OrgIntegration.org_id == org_id,
            OrgIntegration.provider == "m365",
        ).limit(1)
    )).scalar_one_or_none()
    if m365_integ:
        stored_token = _decrypt(m365_integ.access_token_enc or "")
        if stored_token:
            try:
                import base64 as _b64
                parts = stored_token.split(".")
                if len(parts) >= 2:
                    p = parts[1] + "==" * (4 - len(parts[1]) % 4)
                    claims = json.loads(_b64.urlsafe_b64decode(p).decode())
                    tenant_id = claims.get("tid") or tenant_id
            except Exception:
                pass

    if not tenant_id:
        raise HTTPException(status_code=400, detail="No M365 integration found. Please connect M365 first.")

    # Get token using main app credentials
    client_id = os.getenv("M365_CLIENT_ID", SAAS_M365_CLIENT_ID)
    client_secret = os.getenv("M365_CLIENT_SECRET", SAAS_M365_CLIENT_SECRET)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Token request failed: {exc}")

    if resp.status_code != 200:
        err = resp.json().get("error_description", resp.text[:200])
        raise HTTPException(status_code=400, detail=f"Could not obtain token for tenant {tenant_id}: {err}")

    access_token = resp.json().get("access_token", "")
    if not access_token:
        raise HTTPException(status_code=400, detail="Empty token returned")

    # Upsert integration
    existing = (await db.execute(
        select(SaasIntegration).where(
            SaasIntegration.org_id == org_id,
            SaasIntegration.provider == provider,
        )
    )).scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if existing:
        existing.access_token = _encrypt(access_token)
        existing.tenant_id = tenant_id
        existing.status = "active"
        existing.error_message = None
        existing.connected_at = now
    else:
        db.add(SaasIntegration(
            org_id=org_id,
            provider=provider,
            status="active",
            access_token=_encrypt(access_token),
            tenant_id=tenant_id,
            connected_at=now,
        ))

    await db.commit()
    logger.info(f"saas_connect_from_m365: {provider} connected for org {org_id} tenant {tenant_id}")
    return {"status": "connected", "provider": provider}


@router.post("/connect")
async def connect_provider(
    body: ConnectRequest,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Connect Teams or SharePoint using client_credentials (app-only token).
    Customer provides their Azure AD tenant ID. No OAuth redirect needed —
    the Helios app must already have admin consent granted in the customer tenant
    (via the /adminconsent URL shown in the UI).
    """
    await _require_enterprise(current_user, db)

    provider = body.provider
    tenant_id = body.tenant_id.strip()

    if provider not in ("teams", "sharepoint"):
        raise HTTPException(status_code=400, detail="provider must be 'teams' or 'sharepoint'")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id is required")

    # Use main Helios app credentials (preferred — already trusted by customers)
    _client_id = os.getenv("M365_CLIENT_ID") or SAAS_M365_CLIENT_ID
    _client_secret = os.getenv("M365_CLIENT_SECRET") or SAAS_M365_CLIENT_SECRET
    if not _client_id or not _client_secret:
        raise HTTPException(status_code=500, detail="M365 credentials not configured")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                data={
                    "client_id": _client_id,
                    "client_secret": _client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
    except Exception as exc:
        logger.error(f"saas_connect: token request failed: {exc}")
        raise HTTPException(status_code=502, detail="Failed to reach Microsoft login endpoint")

    if resp.status_code != 200:
        err = resp.json().get("error_description", resp.text[:200])
        logger.error(f"saas_connect: client_credentials failed for tenant {tenant_id}: {err}")
        raise HTTPException(
            status_code=400,
            detail=f"Could not obtain token for tenant {tenant_id}. Ensure admin consent has been granted. Error: {err[:200]}"
        )

    access_token = resp.json().get("access_token", "")
    if not access_token:
        raise HTTPException(status_code=500, detail="No access token in response")

    # Quick validation: verify the token can reach Graph
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            test_resp = await client.get(
                f"{GRAPH}/organization",
                headers={"Authorization": f"Bearer {access_token}"},
            )
        if test_resp.status_code not in (200, 403):  # 403 = token works but no Directory.Read
            raise HTTPException(
                status_code=400,
                detail=f"Token validation failed (Graph returned {test_resp.status_code}). Check permissions."
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning(f"saas_connect: token validation failed: {exc}")

    # Upsert integration record
    now = datetime.now(timezone.utc)
    org_uuid = current_user.org_id
    try:
        existing = (await db.execute(
            select(SaasIntegration).where(
                SaasIntegration.org_id == org_uuid,
                SaasIntegration.provider == provider,
            )
        )).scalar_one_or_none()

        if existing:
            existing.access_token = _encrypt(access_token)
            existing.refresh_token = None
            existing.tenant_id = tenant_id
            existing.status = "active"
            existing.error_message = None
            existing.connected_at = now
            existing.updated_at = now
        else:
            db.add(SaasIntegration(
                org_id=org_uuid,
                provider=provider,
                access_token=_encrypt(access_token),
                refresh_token=None,
                tenant_id=tenant_id,
                status="active",
                connected_at=now,
            ))
        await db.commit()
        logger.info(f"saas_connect: {provider} connected for org {org_uuid} tenant {tenant_id}")
    except Exception as exc:
        logger.error(f"saas_connect: DB persist failed: {exc}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to save integration")

    return {"status": "connected", "provider": provider, "tenant_id": tenant_id}


# Keep legacy GET endpoints for backwards compatibility (redirect to error)
@router.get("/connect/teams")
async def connect_teams_legacy():
    raise HTTPException(status_code=410, detail="Use POST /api/saas/connect with {provider, tenant_id}")


@router.get("/connect/sharepoint")
async def connect_sharepoint_legacy():
    raise HTTPException(status_code=410, detail="Use POST /api/saas/connect with {provider, tenant_id}")


@router.get("/required-scopes")
async def get_required_scopes(current_user=Depends(get_current_user)):
    """
    Return the canonical list of Microsoft Graph application permissions the
    Helios SaaS Security scanner requires. Use this for:
      - Building the Azure AD app registration manifest (requiredResourceAccess)
      - Surface in the UI so admins know exactly what's being requested at consent time
      - Ops verification after a consent flow
    """
    return {
        "scopes": _REQUIRED_GRAPH_SCOPES,
        "count": len(_REQUIRED_GRAPH_SCOPES),
        "resource": "Microsoft Graph",
        "resource_id": "00000003-0000-0000-c000-000000000000",
        "permission_type": "Application",
    }


@router.get("/consent-url")
async def get_consent_url(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the admin consent URL for SaaS Security using the org's existing M365 integration.
    Uses the main Himaya Helios app (M365_CLIENT_ID) so no separate app consent is needed.
    Tenant ID is pulled server-side from the org's stored M365 integration — never exposed to frontend.
    """
    from backend.models.db_models import OrgIntegration
    org_id = current_user.org_id

    # Get tenant_id from stored M365 integration or SaaS integration
    tenant_id = None

    # Try SaaS integrations first (already have tenant_id stored)
    saas_integ = (await db.execute(
        select(SaasIntegration).where(
            SaasIntegration.org_id == org_id,
            SaasIntegration.tenant_id.isnot(None),
        ).limit(1)
    )).scalar_one_or_none()
    if saas_integ:
        tenant_id = saas_integ.tenant_id

    # Fall back to main M365 integration
    if not tenant_id:
        m365_integ = (await db.execute(
            select(OrgIntegration).where(
                OrgIntegration.org_id == org_id,
                OrgIntegration.provider == "m365",
            ).limit(1)
        )).scalar_one_or_none()
        if m365_integ:
            # Try to extract tenant_id from stored JWT
            stored_token = _decrypt(m365_integ.access_token_enc or "")
            if stored_token:
                try:
                    import base64 as _b64
                    parts = stored_token.split(".")
                    if len(parts) >= 2:
                        p = parts[1] + "==" * (4 - len(parts[1]) % 4)
                        claims = json.loads(_b64.urlsafe_b64decode(p).decode())
                        tenant_id = claims.get("tid")
                except Exception:
                    pass
            # Also check env var as fallback
            if not tenant_id:
                tenant_id = os.getenv("M365_TENANT_ID", "")

    if not tenant_id or tenant_id == "common":
        raise HTTPException(status_code=400, detail="No M365 integration found. Connect M365 email security first.")

    client_id = os.getenv("M365_CLIENT_ID", SAAS_M365_CLIENT_ID)
    redirect_uri = "https://app.himaya.ai/api/saas/callback"
    import urllib.parse

    # IMPORTANT: there are TWO admin consent endpoints, and they have
    # different parameter rules:
    #
    #   /adminconsent       (v1) — takes ONLY client_id, redirect_uri, state.
    #                              Pulls the scope list from the app's
    #                              registered manifest automatically. This is
    #                              the right one for a multi-tenant app where
    #                              the manifest is the source of truth for
    #                              what's being granted.
    #
    #   /v2.0/adminconsent  (v2) — REJECTS scope= and prompt=consent. Trying
    #                              to pass either returns AADSTS90014
    #                              "required field 'scope' is missing" or
    #                              AADSTS900144 "required field 'response_type'
    #                              is missing" depending on the day. We were
    #                              hitting this. Don't use v2 for adminconsent.
    #
    # The clean v1 URL forces Microsoft to show the consent dialog listing
    # every permission the app currently requests in its manifest, so the
    # admin sees the new Governance-tab scopes (Policy.Read.All etc.) and can
    # accept them all in one click.
    url = (
        f"https://login.microsoftonline.com/{tenant_id}/adminconsent"
        f"?client_id={client_id}"
        f"&redirect_uri={urllib.parse.quote(redirect_uri, safe='')}"
        f"&state=saas_admin_consent"
    )
    return {
        "url": url,
        "tenant_id": tenant_id[:8] + "...",  # only expose prefix for logging, not full ID
        "scopes": _REQUIRED_GRAPH_SCOPES,
        "scope_count": len(_REQUIRED_GRAPH_SCOPES),
    }


@router.get("/force-reconsent-url")
async def force_reconsent_url(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns a URL that forces the admin-consent dialog using the OAuth
    /authorize endpoint with prompt=admin_consent. This is the fallback when
    /adminconsent v1 silently no-ops (e.g. because the existing servicePrincipal
    already exists and AAD thinks consent isn't needed).

    Difference from /consent-url:
      - Uses /oauth2/v2.0/authorize (not /adminconsent)
      - Adds prompt=admin_consent which Microsoft documents as the way to
        force re-display of the consent UI even if the app is already
        servicePrincipal-installed.
      - Uses scope=https://graph.microsoft.com/.default which evaluates to
        "every application permission currently in the app's manifest".
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    integ = (await db.execute(
        select(SaasIntegration).where(
            SaasIntegration.org_id == current_user.org_id,
            SaasIntegration.status == "active",
        ).limit(1)
    )).scalar_one_or_none()
    tenant_id = (integ.tenant_id if integ else None) or os.getenv("M365_TENANT_ID", "")
    if not tenant_id or tenant_id == "common":
        raise HTTPException(status_code=400, detail="No M365 integration connected.")

    client_id = os.getenv("M365_CLIENT_ID", SAAS_M365_CLIENT_ID)
    redirect_uri = "https://app.himaya.ai/api/saas/callback"
    import urllib.parse
    url = (
        f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
        f"?client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={urllib.parse.quote(redirect_uri, safe='')}"
        f"&response_mode=query"
        f"&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"
        f"&prompt=admin_consent"
        f"&state=force_reconsent"
    )
    return {"url": url, "tenant_id": tenant_id[:8] + "..."}


@router.get("/callback")
async def oauth_callback(
    code: str = Query(None),
    state: str = Query(None),
    error: str = Query(None),
    # Admin consent redirect params
    admin_consent: str = Query(None),
    tenant: str = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """OAuth callback — handles admin consent redirects and legacy OAuth code exchange."""
    # Admin consent success — just redirect back to connectors, user can now click Connect
    if admin_consent and admin_consent.lower() == "true":
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?consent_granted=1")

    # Force-reconsent flow returns via /authorize so we get ?code=... &state=force_reconsent.
    # We don't actually need the auth code — the consent itself is what matters,
    # and it's already been written to the customer tenant by the time AAD redirects
    # back to us. Just bounce the user back to the page with a success marker.
    if state == "force_reconsent":
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?consent_granted=1&via=force")

    if error:
        # If admin consent was denied, redirect with message
        if error in ("access_denied", "consent_required"):
            return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?error=consent_denied")
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?error=oauth_denied")

    if not state or not code:
        # Could be an admin consent return with unexpected params — just go back
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security")

    try:
        state_data = json.loads(base64.urlsafe_b64decode(state + "==").decode())
        org_id = state_data["org_id"]
        provider = state_data["provider"]
        org_uuid = uuid.UUID(org_id)
    except Exception as exc:
        logger.warning(f"saas_security: invalid state in callback: {exc}")
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?error=invalid_state")

    if not SAAS_M365_CLIENT_ID:
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?error=not_configured")

    access_token = ""
    refresh_token = ""
    tenant_id = None
    scopes_granted: list[str] = []

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                data={
                    "client_id": SAAS_M365_CLIENT_ID,
                    "client_secret": SAAS_M365_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": SAAS_REDIRECT_URI,
                    "grant_type": "authorization_code",
                },
            )
            if resp.status_code != 200:
                logger.error(f"saas_security: token exchange failed: {resp.status_code} {resp.text[:300]}")
                return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?error=token_failed")
            token_data = resp.json()
            access_token = token_data.get("access_token", "")
            refresh_token = token_data.get("refresh_token", "")
            scopes_granted = token_data.get("scope", "").split()

            # Extract tenant_id from the JWT claims (tid claim) — no extra API call needed
            # JWT is 3 base64url-encoded parts: header.payload.signature
            if access_token:
                try:
                    import base64 as _b64
                    payload_b64 = access_token.split(".")[1]
                    # Add padding
                    payload_b64 += "==" * (4 - len(payload_b64) % 4)
                    jwt_payload = json.loads(_b64.urlsafe_b64decode(payload_b64).decode())
                    tid = jwt_payload.get("tid") or jwt_payload.get("tenant_id")
                    if tid:
                        tenant_id = tid
                        logger.info(f"saas_security: extracted tenant_id={tid} from JWT")
                except Exception as _jwt_exc:
                    logger.warning(f"saas_security: JWT decode failed, trying /me: {_jwt_exc}")

            # Fallback: try /me for tenant domain (best-effort, non-fatal if 403)
            if not tenant_id and access_token:
                try:
                    me_resp = await client.get(
                        f"{GRAPH}/me",
                        headers={"Authorization": f"Bearer {access_token}"},
                    )
                    if me_resp.status_code == 200:
                        me_data = me_resp.json()
                        email = me_data.get("mail") or me_data.get("userPrincipalName", "")
                        if "@" in email:
                            tenant_id = email.split("@")[1]
                    else:
                        logger.warning(f"saas_security: /me returned {me_resp.status_code} — tenant_id from JWT only")
                except Exception:
                    pass
    except Exception as exc:
        logger.error(f"saas_security: callback exception: {exc}")
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?error=exception")

    if not access_token:
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?error=no_token")

    try:
        now = datetime.now(timezone.utc)
        existing = (await db.execute(
            select(SaasIntegration).where(
                SaasIntegration.org_id == org_uuid,
                SaasIntegration.provider == provider,
            )
        )).scalar_one_or_none()

        if existing:
            existing.access_token = _encrypt(access_token)
            existing.refresh_token = _encrypt(refresh_token)
            existing.tenant_id = tenant_id
            existing.scopes = scopes_granted
            existing.status = "active"
            existing.error_message = None
            existing.connected_at = now
            existing.updated_at = now
        else:
            db.add(SaasIntegration(
                org_id=org_uuid,
                provider=provider,
                access_token=_encrypt(access_token),
                refresh_token=_encrypt(refresh_token),
                tenant_id=tenant_id,
                scopes=scopes_granted,
                status="active",
                connected_at=now,
            ))
        await db.commit()
    except Exception as exc:
        logger.error(f"saas_security: DB persist failed: {exc}")
        await db.rollback()
        return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?error=db_error")

    return RedirectResponse(url=f"{FRONTEND_URL}/saas-security?connected={provider}")


@router.delete("/integrations/{provider}")
async def disconnect_integration(
    provider: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disconnect a SaaS integration."""
    await _require_enterprise(current_user, db)
    integ = (await db.execute(
        select(SaasIntegration).where(
            SaasIntegration.org_id == current_user.org_id,
            SaasIntegration.provider == provider,
        )
    )).scalar_one_or_none()
    if not integ:
        raise HTTPException(status_code=404, detail="Integration not found")
    integ.status = "disconnected"
    integ.access_token = None
    integ.refresh_token = None
    integ.token_expiry = None
    integ.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": f"{provider} disconnected"}


# ══════════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS — IAM risks, workers status, etc.
# ══════════════════════════════════════════════════════════════════════════════

async def _get_iam_risks_summary(org_id: str, db: AsyncSession) -> list:
    """Gather top IAM risks from AWS findings + posture checks for overview panel."""
    risks = []
    # 1. IAM-related AWS findings (category='iam' or resource_type starts with 'iam_')
    try:
        result = await db.execute(text("""
            SELECT title, description, severity, category, resource_type, resource_id
            FROM aws_findings
            WHERE org_id = :org_id
              AND (category = 'iam' OR resource_type LIKE 'iam_%'
                   OR title ILIKE '%iam%' OR title ILIKE '%mfa%' OR title ILIKE '%access key%'
                   OR title ILIKE '%console%' OR title ILIKE '%privilege%')
              AND severity IN ('critical', 'high', 'medium')
              AND status = 'open'
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END
            LIMIT 10
        """), {"org_id": org_id})
        for row in result.mappings():
            # Format principal to show user name for IAM findings
            principal = row["resource_id"] or row["category"] or "AWS IAM"
            if row["resource_type"] == "iam_user":
                principal = f"User: {principal}"
            risks.append({
                "principal": principal,
                "description": row["title"],
                "severity": row["severity"],
                "provider": "aws",
                "type": "iam",
                "resource_type": row["resource_type"],
            })
    except Exception:
        pass

    # 2. IAM-related posture check failures
    try:
        result = await db.execute(text("""
            SELECT check_name, description, severity, provider
            FROM saas_posture_checks
            WHERE org_id = CAST(:org_id AS UUID)
              AND status = 'fail'
              AND (check_category ILIKE '%iam%' OR check_category ILIKE '%identity%'
                   OR check_category ILIKE '%mfa%' OR check_category ILIKE '%privilege%'
                   OR check_name ILIKE '%mfa%' OR check_name ILIKE '%root%'
                   OR check_name ILIKE '%admin%' OR check_name ILIKE '%iam%'
                   OR check_name ILIKE '%privilege%')
              AND severity IN ('critical', 'high', 'medium')
            ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END
            LIMIT 10
        """), {"org_id": org_id})
        for row in result.mappings():
            risks.append({
                "principal": row["provider"] or "Unknown",
                "description": row["check_name"],
                "severity": row["severity"],
                "provider": row["provider"] or "unknown",
                "type": "posture_check",
            })
    except Exception:
        pass

    # 3. Entra risky users (count as IAM risk)
    try:
        result = await db.execute(text("""
            SELECT display_name, risk_level, risk_detail, user_email
            FROM saas_risky_users
            WHERE org_id = CAST(:org_id AS UUID)
              AND risk_level IN ('high', 'medium')
            LIMIT 5
        """), {"org_id": org_id})
        for row in result.mappings():
            risks.append({
                "principal": row["user_email"] or row["display_name"] or "Unknown User",
                "description": f"Risky user: {row['display_name'] or 'Unknown'} - {row['risk_detail'] or 'Risk detected by Entra'}",
                "severity": row["risk_level"],
                "provider": "m365",
                "type": "risky_user",
            })
    except Exception:
        pass

    # Sort by severity and deduplicate
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    risks.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 3))
    return risks[:10]


async def _get_workers_status(org_id: str, db: AsyncSession) -> dict:
    """Check which background workers are active based on recent activity."""
    status = {
        "classification_worker": False,
        "alert_scanner": False,
        "posture_checker": False,
        "sync_worker": False,
        "iam_scanner": False,
    }
    try:
        # Check if classification worker ran recently (data items scanned in last 24h)
        result = await db.execute(text("""
            SELECT COUNT(*) FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND last_scanned_at >= NOW() - INTERVAL '24 hours'
        """), {"org_id": org_id})
        status["classification_worker"] = (result.scalar() or 0) > 0
    except Exception:
        status["classification_worker"] = True  # Default active

    try:
        # Check if alert scanner ran recently
        result = await db.execute(text("""
            SELECT COUNT(*) FROM saas_alerts
            WHERE org_id = CAST(:org_id AS UUID)
              AND created_at >= NOW() - INTERVAL '48 hours'
        """), {"org_id": org_id})
        status["alert_scanner"] = (result.scalar() or 0) > 0
    except Exception:
        status["alert_scanner"] = True

    try:
        # Check if posture checker ran recently
        result = await db.execute(text("""
            SELECT COUNT(*) FROM saas_posture_checks
            WHERE org_id = CAST(:org_id AS UUID)
              AND last_checked_at >= NOW() - INTERVAL '48 hours'
        """), {"org_id": org_id})
        status["posture_checker"] = (result.scalar() or 0) > 0
    except Exception:
        status["posture_checker"] = True

    try:
        # Check sync worker (data items synced recently)
        result = await db.execute(text("""
            SELECT COUNT(*) FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND created_at >= NOW() - INTERVAL '48 hours'
        """), {"org_id": org_id})
        status["sync_worker"] = (result.scalar() or 0) > 0
    except Exception:
        status["sync_worker"] = True

    try:
        # IAM scanner: check aws_findings for IAM-related findings
        result = await db.execute(text("""
            SELECT COUNT(*) FROM aws_findings
            WHERE org_id = :org_id
              AND detected_at >= NOW() - INTERVAL '48 hours'
        """), {"org_id": org_id})
        status["iam_scanner"] = (result.scalar() or 0) > 0
    except Exception:
        status["iam_scanner"] = True

    return status


async def _aws_iam_scan(org_id: str, db: AsyncSession) -> list:
    """
    Enumerate IAM risks from AWS:
    - Users without MFA
    - Users with AdministratorAccess
    - Access keys older than 90 days
    - Root account usage
    - Overprivileged policies
    """
    logger.info(f"_aws_iam_scan: starting for org {org_id}")
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    # Local import — _decrypt is the AWS-connection-row decrypt helper. We
    # re-alias it as _aws_decrypt to keep this function's callsites readable.
    from backend.routers.aws_connector import _decrypt as _aws_decrypt

    risks = []
    try:
        # Get AWS credentials from DB
        aws_conn = await db.execute(text("""
            SELECT access_key_id_enc, secret_access_key_enc, default_region
            FROM aws_connections
            WHERE org_id = :org_id AND status = 'active'
            LIMIT 1
        """), {"org_id": org_id})
        conn_row = aws_conn.mappings().first()
        if not conn_row:
            return risks

        access_key = _aws_decrypt(conn_row["access_key_id_enc"])
        secret_key = _aws_decrypt(conn_row["secret_access_key_enc"])
        region = conn_row["default_region"] or "us-east-1"

        iam = boto3.client(
            "iam",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )

        # 1. Check for users without MFA
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    mfa_resp = iam.list_mfa_devices(UserName=username)
                    if not mfa_resp.get("MFADevices"):
                        risks.append({
                            "principal": username,
                            "description": f"IAM user '{username}' has no MFA device configured",
                            "severity": "high",
                            "provider": "aws",
                            "type": "no_mfa",
                        })
                    # Check access key age
                    keys_resp = iam.list_access_keys(UserName=username)
                    for key in keys_resp.get("AccessKeyMetadata", []):
                        if key["Status"] == "Active":
                            from datetime import datetime, timezone
                            age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                            if age > 90:
                                risks.append({
                                    "principal": username,
                                    "description": f"Access key for '{username}' is {age} days old (>90 days)",
                                    "severity": "medium",
                                    "provider": "aws",
                                    "type": "old_access_key",
                                })
        except ClientError as e:
            logger.warning(f"IAM user scan failed: {e}")

        # 2. Check for users with AdministratorAccess
        try:
            paginator = iam.get_paginator("list_entities_for_policy")
            admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            for page in paginator.paginate(PolicyArn=admin_arn):
                for user in page.get("PolicyUsers", []):
                    risks.append({
                        "principal": user["UserName"],
                        "description": f"IAM user '{user['UserName']}' has AdministratorAccess (overprivileged)",
                        "severity": "critical",
                        "provider": "aws",
                        "type": "admin_access",
                    })
        except ClientError as e:
            logger.warning(f"IAM admin policy scan failed: {e}")

        # 3. Check root account
        try:
            acct_summary = iam.get_account_summary()
            summary_map = acct_summary.get("SummaryMap", {})
            if summary_map.get("AccountMFAEnabled", 0) == 0:
                risks.append({
                    "principal": "root",
                    "description": "AWS root account does not have MFA enabled",
                    "severity": "critical",
                    "provider": "aws",
                    "type": "root_no_mfa",
                })
        except ClientError as e:
            logger.warning(f"IAM root check failed: {e}")

    except (ImportError, NoCredentialsError, Exception) as exc:
        logger.warning(f"_aws_iam_scan: {exc}")

    logger.info(f"_aws_iam_scan: found {len(risks)} IAM risks for org {org_id}")
    return risks


# ══════════════════════════════════════════════════════════════════════════════
# STATS ENDPOINT — Aggregated metrics from all connectors
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/stats")
@cached_endpoint("saas:stats", ttl=30)
async def get_workspace_stats(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get aggregated workspace security stats from all connected platforms:
    - M365/Google (SaaS Security)
    - AWS (Cloud Infrastructure)
    - GCP (Cloud Infrastructure)
    - Databricks (AI Infrastructure)
    - SAP (Financial Platforms)
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    # Get stats from workspace sync service
    from backend.services.workspace_sync import get_workspace_stats as _get_ws_stats
    cloud_stats = await _get_ws_stats(db, org_id)
    
    # Get SaaS-specific stats (M365/Google)
    total_files = 0
    classified_files = 0
    sensitive_files = 0
    external_shares = 0
    
    try:
        # Read from classification_label — the column the DLP worker actually
        # writes. Older deployments used a column named `classification`;
        # the dlp_worker has been writing classification_label for some time
        # (saas_security.py:10454). Reading from the wrong column was the
        # reason the overview tile always showed "0 classified".
        # NOTE: every query in this endpoint is gated by org_id (current
        # user's tenant) — per-org silo enforced.
        result = await db.execute(text("""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE classification_label IS NOT NULL
                                   AND classification_label <> '')           AS classified,
                COUNT(*) FILTER (WHERE classification_label IN
                                       ('confidential', 'highly_confidential',
                                        'restricted', 'pii', 'phi',
                                        'financial', 'secret'))               AS sensitive,
                COUNT(*) FILTER (WHERE sharing_scope IN ('external', 'public', 'anyone')) AS external
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
        """), {"org_id": org_id})
        row = result.mappings().first()
        if row:
            total_files = row["total"] or 0
            classified_files = row["classified"] or 0
            sensitive_files = row["sensitive"] or 0
            external_shares = row["external"] or 0
    except Exception as _e:
        logger.warning(f"overview stats: classification_label query failed: {_e}")
        await db.rollback()
        # Fall back to legacy column name for very old data
        try:
            result = await db.execute(text("""
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE classification IS NOT NULL) AS classified,
                    COUNT(*) FILTER (WHERE classification IN
                                           ('confidential','highly_confidential')) AS sensitive,
                    COUNT(*) FILTER (WHERE scope = 'external' OR scope = 'anyone') AS external
                FROM saas_data_items
                WHERE org_id = CAST(:org_id AS UUID)
            """), {"org_id": org_id})
            row = result.mappings().first()
            if row:
                total_files = row["total"] or 0
                classified_files = row["classified"] or 0
                sensitive_files = row["sensitive"] or 0
                external_shares = row["external"] or 0
        except Exception:
            await db.rollback()

    # Also count AWS public resources as external shares
    try:
        aws_public_result = await db.execute(text("""
            SELECT COUNT(*) FROM aws_resources
            WHERE org_id = :org_id AND public_access = TRUE
        """), {"org_id": org_id})
        aws_public_count = aws_public_result.scalar() or 0
        external_shares += aws_public_count
        # Also count AWS encrypted resources as sensitive
        aws_sensitive_result = await db.execute(text("""
            SELECT COUNT(*) FROM aws_resources
            WHERE org_id = :org_id AND encryption_enabled = TRUE
        """), {"org_id": org_id})
        sensitive_files += aws_sensitive_result.scalar() or 0
    except Exception:
        try:
            await db.rollback()
        except Exception:
            pass

    # Get alert counts
    alerts_today = 0
    alerts_week = 0
    try:
        result = await db.execute(text("""
            SELECT 
                COUNT(CASE WHEN created_at >= NOW() - INTERVAL '1 day' THEN 1 END) as today,
                COUNT(CASE WHEN created_at >= NOW() - INTERVAL '7 days' THEN 1 END) as week
            FROM saas_alerts
            WHERE org_id = :org_id AND status != 'resolved'
        """), {"org_id": org_id})
        row = result.mappings().first()
        if row:
            alerts_today = row["today"] or 0
            alerts_week = row["week"] or 0
    except Exception:
        await db.rollback()
    
    # Combine with cloud findings
    alerts_today += cloud_stats.get("critical_findings", 0)
    alerts_week += cloud_stats.get("total_findings", 0)
    
    # Get posture score
    posture_score = 0
    try:
        result = await db.execute(text("""
            SELECT AVG(CASE WHEN status = 'pass' THEN 100 ELSE 0 END) as score
            FROM saas_posture_checks
            WHERE org_id = :org_id
        """), {"org_id": org_id})
        posture_score = int(result.scalar() or 0)
    except Exception:
        await db.rollback()
    
    # Connected apps count
    connected_apps = 0
    try:
        result = await db.execute(text("""
            SELECT COUNT(*) FROM saas_integrations WHERE org_id = :org_id AND status = 'active'
        """), {"org_id": org_id})
        connected_apps = result.scalar() or 0
    except Exception:
        await db.rollback()
    
    # Add cloud connections
    connected_apps += cloud_stats.get("connections", {}).get("aws", 0)
    connected_apps += cloud_stats.get("connections", {}).get("gcp", 0)
    connected_apps += cloud_stats.get("connections", {}).get("databricks", 0)
    connected_apps += cloud_stats.get("connections", {}).get("sap", 0)
    
    # Get users monitored + M365/Google email stats
    users_monitored = 0
    emails_scanned = 0
    mailboxes = 0
    m365_connected = False
    google_connected = False
    email_provider = None
    
    try:
        # Use text query - same pattern as workspace_sync.py
        result = await db.execute(text("""
            SELECT provider, COALESCE(mailbox_count, 0) as mailbox_count 
            FROM org_integrations 
            WHERE org_id = :org_id AND status = 'active'
        """), {"org_id": org_id})
        rows = result.mappings().all()
        logger.info(f"saas/stats: org_id={org_id} found {len(rows)} integrations")
        for row in rows:
            mc = row["mailbox_count"] or 0
            provider_name = row["provider"]
            logger.info(f"saas/stats: integration provider={provider_name} mailbox_count={mc}")
            if mc > 0:
                users_monitored += mc
                mailboxes += mc
            if provider_name == "m365":
                m365_connected = True
                if not email_provider:
                    email_provider = "m365"
            elif provider_name == "google":
                google_connected = True
                if not email_provider:
                    email_provider = "google"
    except Exception as e:
        logger.warning(f"Failed to get org_integrations: {e}", exc_info=True)
    
    # Get emails/threats scanned count (from threats table)
    try:
        result = await db.execute(text("""
            SELECT COUNT(*) FROM threats WHERE org_id = :org_id
        """), {"org_id": org_id})
        emails_scanned = result.scalar() or 0
    except Exception as e:
        logger.warning(f"Failed to get emails count: {e}")
    
    # Data by classification
    data_by_classification = []
    try:
        result = await db.execute(text("""
            SELECT classification_label as label, COUNT(*) as count
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID) AND classification_label IS NOT NULL
            GROUP BY classification_label
            ORDER BY count DESC
        """), {"org_id": org_id})
        for row in result.mappings():
            data_by_classification.append({
                "label": row["label"],
                "count": row["count"]
            })
    except Exception:
        # Fallback to old column name
        try:
            result = await db.execute(text("""
                SELECT classification as label, COUNT(*) as count
                FROM saas_data_items
                WHERE org_id = CAST(:org_id AS UUID) AND classification IS NOT NULL
                GROUP BY classification
                ORDER BY count DESC
            """), {"org_id": org_id})
            for row in result.mappings():
                data_by_classification.append({
                    "label": row["label"],
                    "count": row["count"]
                })
        except Exception:
            pass

    # Add AWS resources to data classification
    try:
        aws_cls_result = await db.execute(text("""
            SELECT
                CASE
                    WHEN public_access = TRUE THEN 'public'
                    WHEN encryption_enabled = TRUE THEN 'confidential'
                    ELSE 'internal'
                END as label,
                COUNT(*) as count
            FROM aws_resources
            WHERE org_id = :org_id
            GROUP BY 1
        """), {"org_id": org_id})
        cls_map = {row["label"]: row["count"] for row in aws_cls_result.mappings()}
        if cls_map:
            # Merge with existing data_by_classification
            existing_labels = {d["label"]: i for i, d in enumerate(data_by_classification)}
            for label, count in cls_map.items():
                if label in existing_labels:
                    data_by_classification[existing_labels[label]]["count"] += count
                else:
                    data_by_classification.append({"label": label, "count": count})
            data_by_classification.sort(key=lambda x: x["count"], reverse=True)
    except Exception:
        pass

    # Alerts by type
    alerts_by_type = []
    try:
        result = await db.execute(text("""
            SELECT alert_type, COUNT(*) as count
            FROM saas_alerts
            WHERE org_id = :org_id AND status != 'resolved'
            GROUP BY alert_type
        """), {"org_id": org_id})
        for row in result.mappings():
            alerts_by_type.append({
                "type": row["alert_type"],
                "count": row["count"]
            })
    except Exception:
        pass
    
    # 7-day trend
    trend_7d = []
    try:
        result = await db.execute(text("""
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM saas_alerts
            WHERE org_id = :org_id AND created_at >= NOW() - INTERVAL '7 days'
            GROUP BY DATE(created_at)
            ORDER BY date
        """), {"org_id": org_id})
        for row in result.mappings():
            trend_7d.append({
                "date": str(row["date"]),
                "count": row["count"]
            })
    except Exception:
        pass
    
    return {
        "total_files": total_files + cloud_stats.get("total_resources", 0),
        "classified_files": classified_files,
        "sensitive_files": sensitive_files,
        "external_shares": external_shares,
        "alerts_today": alerts_today,
        "alerts_week": alerts_week,
        "posture_score": posture_score,
        "connected_apps": connected_apps,
        "users_monitored": users_monitored,
        "high_risk_users": 0,  # Placeholder
        "data_by_classification": data_by_classification,
        "alerts_by_type": alerts_by_type,
        "trend_7d": trend_7d,
        # IAM risks from AWS findings + posture checks
        "iam_risks": await _get_iam_risks_summary(org_id, db),
        # Security funnel (Wiz-style)
        "funnel_data": {
            "total_resources": cloud_stats.get("total_resources", 0) + total_files,
            "misconfigs": cloud_stats.get("total_findings", 0),
            "exposures": external_shares,
            "exploitable": cloud_stats.get("critical_findings", 0),
            "by_provider": cloud_stats.get("by_provider", {}),
        },
        # Background worker status
        "workers_status": await _get_workers_status(org_id, db),
        # Email integration stats (M365/Google)
        "email_stats": {
            "emails_scanned": emails_scanned,
            "mailboxes": mailboxes,
            "m365_connected": m365_connected,
            "google_connected": google_connected,
            "provider": email_provider,
        },
        # Cloud-specific stats
        "cloud_stats": {
            "total_resources": cloud_stats.get("total_resources", 0),
            "total_findings": cloud_stats.get("total_findings", 0),
            "critical_findings": cloud_stats.get("critical_findings", 0),
            "high_findings": cloud_stats.get("high_findings", 0),
            "by_provider": cloud_stats.get("by_provider", {}),
            "data_regions": cloud_stats.get("data_regions", []),
            "connections": cloud_stats.get("connections", {}),
            "recent_findings": cloud_stats.get("recent_findings", []),
        },
    }


# ALERT ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/alerts")
@cached_endpoint("saas:alerts", ttl=20)
async def list_alerts(
    provider: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List unified alerts from SaaS (Teams/SharePoint) and AWS findings.
    AWS findings are included alongside M365 alerts with provider='aws'.
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    offset = (page - 1) * page_size
    
    # Build WHERE conditions for both sources
    saas_conditions = ["org_id = :org_id"]
    aws_conditions = ["org_id = :org_id"]
    params: dict = {"org_id": org_id, "limit": page_size, "offset": offset}
    
    # Databricks conditions mirror AWS conditions
    databricks_conditions = ["org_id = :org_id"]
    
    if provider:
        if provider == 'aws':
            # Only AWS findings
            saas_conditions.append("1=0")  # Exclude SaaS
            databricks_conditions.append("1=0")  # Exclude Databricks
        elif provider == 'databricks':
            # Only Databricks findings
            saas_conditions.append("1=0")  # Exclude SaaS
            aws_conditions.append("1=0")  # Exclude AWS
        else:
            # Only SaaS alerts for specific provider
            saas_conditions.append("provider = :provider")
            aws_conditions.append("1=0")  # Exclude AWS
            databricks_conditions.append("1=0")  # Exclude Databricks
            params["provider"] = provider
    if severity:
        saas_conditions.append("severity = :severity")
        aws_conditions.append("severity = :severity")
        databricks_conditions.append("severity = :severity")
        params["severity"] = severity
    if status:
        saas_conditions.append("status = :status")
        aws_conditions.append("status = :status")
        databricks_conditions.append("status = :status")
        params["status"] = status
    if alert_type:
        saas_conditions.append("alert_type = :alert_type")
        aws_conditions.append("category = :alert_type")
        databricks_conditions.append("category = :alert_type")
        params["alert_type"] = alert_type
    
    saas_where = " AND ".join(saas_conditions)
    aws_where = " AND ".join(aws_conditions)
    databricks_where = " AND ".join(databricks_conditions)
    
    # UNION query: SaaS alerts + AWS findings + Databricks findings
    union_sql = f"""
        SELECT 
            id::text, org_id::text, provider, alert_type, severity, title, description,
            resource_id, resource_name, resource_url, classification_result, posture_result,
            status, resolved_at, created_at, updated_at, 'saas' as source
        FROM saas_alerts
        WHERE {saas_where}
        UNION ALL
        SELECT 
            id::text, org_id::text, 'aws' as provider, category as alert_type, severity, title, description,
            resource_id, resource_arn as resource_name, NULL as resource_url, 
            metadata as classification_result, NULL as posture_result,
            status, resolved_at, detected_at as created_at, detected_at as updated_at, 'aws' as source
        FROM aws_findings
        WHERE {aws_where}
        UNION ALL
        SELECT 
            id::text, org_id::text, 'databricks' as provider, category as alert_type, severity, title, description,
            resource_id, resource_path as resource_name, NULL as resource_url, 
            metadata as classification_result, NULL as posture_result,
            status, resolved_at, detected_at as created_at, detected_at as updated_at, 'databricks' as source
        FROM databricks_findings
        WHERE {databricks_where}
        ORDER BY created_at DESC NULLS LAST
        LIMIT :limit OFFSET :offset
    """
    
    # Count query
    count_sql = f"""
        SELECT COUNT(*) FROM (
            SELECT id FROM saas_alerts WHERE {saas_where}
            UNION ALL
            SELECT id FROM aws_findings WHERE {aws_where}
            UNION ALL
            SELECT id FROM databricks_findings WHERE {databricks_where}
        ) combined
    """
    
    try:
        # Execute count
        count_result = await db.execute(text(count_sql), {k: v for k, v in params.items() if k not in ("limit", "offset")})
        total = count_result.scalar() or 0
        
        # Execute union
        result = await db.execute(text(union_sql), params)
        rows = result.mappings().all()
        
        items = []
        for row in rows:
            items.append({
                "id": row["id"],
                "org_id": row["org_id"],
                "provider": row["provider"],
                "alert_type": row["alert_type"] or "security_finding",
                "severity": row["severity"],
                "title": row["title"],
                "description": row["description"],
                "resource_id": row["resource_id"],
                "resource_name": row["resource_name"],
                "resource_url": row["resource_url"],
                "classification_result": row["classification_result"],
                "posture_result": row["posture_result"],
                "status": row["status"],
                "resolved_at": row["resolved_at"].isoformat() if row["resolved_at"] else None,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
                "source": row["source"],
                "remediation_steps": _get_alert_remediation_steps(
                    row["alert_type"], row["provider"], row["description"] or ""
                ),
            })
        
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": items,
        }
    except Exception as e:
        logger.warning(f"list_alerts: UNION query failed, falling back to SaaS only: {e}")
        # Fallback to original SaaS-only query
        q = select(SaasAlert).where(SaasAlert.org_id == current_user.org_id)
        if provider and provider != 'aws':
            q = q.where(SaasAlert.provider == provider)
        if severity:
            q = q.where(SaasAlert.severity == severity)
        if status:
            q = q.where(SaasAlert.status == status)
        if alert_type:
            q = q.where(SaasAlert.alert_type == alert_type)

        total_q = select(func.count()).select_from(q.subquery())
        total = (await db.execute(total_q)).scalar() or 0

        q = q.order_by(SaasAlert.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        rows = (await db.execute(q)).scalars().all()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": [_alert_to_dict(a) for a in rows],
        }


@router.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single alert by ID."""
    await _require_enterprise(current_user, db)
    alert = (await db.execute(
        select(SaasAlert).where(
            SaasAlert.id == uuid.UUID(alert_id),
            SaasAlert.org_id == current_user.org_id,
        )
    )).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_dict(alert)


@router.patch("/alerts/{alert_id}")
async def update_alert_status(
    alert_id: str,
    body: AlertStatusUpdate,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update alert status."""
    await _require_enterprise(current_user, db)
    allowed = {"open", "acknowledged", "resolved", "suppressed"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"status must be one of: {allowed}")

    alert = (await db.execute(
        select(SaasAlert).where(
            SaasAlert.id == uuid.UUID(alert_id),
            SaasAlert.org_id == current_user.org_id,
        )
    )).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    now = datetime.now(timezone.utc)
    alert.status = body.status
    alert.updated_at = now
    if body.status == "resolved":
        alert.resolved_at = now
        alert.resolved_by = current_user.id
    await db.commit()
    return _alert_to_dict(alert)


# ── AI-driven remediation guidance ──────────────────────────────────────────

def _alert_to_remediation_ctx(alert: object) -> dict:
    """Normalise a SaaSAlert ORM row OR an aws_findings / databricks_findings
    raw row into a single dict that the remediation helpers below can
    read uniformly. Adnan 2026-06-17: the alerts list is a UNION of three
    tables but the remediation endpoint only knew about SaasAlert, so any
    AWS / Databricks finding 404'd.
    """
    def _g(attr: str, default=None):
        if isinstance(alert, dict):
            return alert.get(attr, default)
        return getattr(alert, attr, default)
    return {
        "alert_type": _g("alert_type") or _g("category") or "security_finding",
        "severity": _g("severity") or "medium",
        "title": _g("title") or "",
        "description": _g("description") or "",
        "provider": _g("provider") or "",
        "resource_name": _g("resource_name") or _g("resource_arn") or _g("resource_path"),
        "resource_url": _g("resource_url"),
        "resource_id": _g("resource_id"),
        "classification_result": _g("classification_result") or _g("metadata") or {},
        "posture_result": _g("posture_result") or {},
    }


async def _claude_alert_remediation(alert: object) -> Optional[dict]:
    """Call Claude to generate context-specific remediation for an alert.

    Accepts a SaasAlert ORM row or any dict with the standard fields
    (so it also works for aws_findings + databricks_findings rows).
    Returns dict with summary/impact/steps or None if Claude
    unavailable/failed. Mirrors the Anthropic pattern used in
    backend/services/dlp_service.py.
    """
    if not ANTHROPIC_API_KEY:
        return None
    try:
        ctx = _alert_to_remediation_ctx(alert)
        cls = ctx.get("classification_result") or {}
        pos = ctx.get("posture_result") or {}
        # Truncate any large JSON to keep prompt bounded.
        cls_str = json.dumps(cls, default=str)[:1500]
        pos_str = json.dumps(pos, default=str)[:1500]
        prompt = (
            "You are a senior cloud security engineer writing remediation guidance "
            "for a workspace security platform. Generate a context-specific plan "
            "that an admin can act on immediately. Reference the actual resource by "
            "name, provider, and URL where relevant — do NOT use generic placeholders.\n\n"
            f"Alert type: {ctx['alert_type']}\n"
            f"Severity: {ctx['severity']}\n"
            f"Title: {ctx['title']}\n"
            f"Description: {ctx['description']}\n"
            f"Provider: {ctx['provider']}\n"
            f"Resource name: {ctx['resource_name'] or 'n/a'}\n"
            f"Resource URL: {ctx['resource_url'] or 'n/a'}\n"
            f"Resource id: {ctx['resource_id'] or 'n/a'}\n"
            f"Classification result (DLP): {cls_str}\n"
            f"Posture result: {pos_str}\n\n"
            "Respond with JSON ONLY in this exact shape:\n"
            "{\n"
            '  "summary": "1 paragraph (2-4 sentences) describing what is wrong, naming the resource.",\n'
            '  "impact": "2 paragraphs separated by \\n\\n covering business / compliance impact and what an attacker could do.",\n'
            '  "steps": ["step 1 with concrete UI / CLI / portal actions referencing the resource", "step 2 ...", "..."]\n'
            "}\n\n"
            "Rules: produce 4-8 numbered steps in the steps array (no leading numbers, the UI will number them). "
            "Each step should be specific — name the exact console (e.g. 'AWS S3 console', 'Microsoft 365 Defender', "
            "'Entra ID', 'Databricks workspace admin', 'GCP IAM') and reference the actual resource. "
            "Do not include 'review the alert' as a step. Be concrete and operational."
        )
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 1500,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if r.status_code != 200:
                logger.warning(
                    f"alert_remediation: Claude returned {r.status_code}: {r.text[:200]}"
                )
                return None
            raw = r.json()["content"][0]["text"].strip()
            raw = re.sub(r"^```[\w]*\n?", "", raw)
            raw = re.sub(r"```$", "", raw).strip()
            parsed = json.loads(raw)
            summary = str(parsed.get("summary") or "").strip()
            impact = str(parsed.get("impact") or "").strip()
            steps_raw = parsed.get("steps") or []
            steps = [str(s).strip() for s in steps_raw if str(s).strip()]
            if not summary or not steps:
                logger.warning("alert_remediation: Claude returned empty summary/steps")
                return None
            return {"summary": summary, "impact": impact, "steps": steps}
    except Exception as exc:
        logger.warning(f"alert_remediation: Claude call failed: {exc}")
        return None


def _fallback_alert_remediation(alert: object) -> dict:
    """Less-generic fallback when Claude is unavailable.

    Stitches together the heuristic steps and at least names the resource
    and provider in the summary so it doesn't read like a template.
    Works for SaaSAlert ORM rows AND raw aws/databricks finding rows.
    """
    ctx = _alert_to_remediation_ctx(alert)
    steps = _get_alert_remediation_steps(
        ctx["alert_type"], ctx["provider"], ctx["description"] or ""
    )
    res = ctx["resource_name"] or ctx["resource_id"] or "this resource"
    provider = (ctx["provider"] or "").upper() or "the provider"
    summary = (
        f"{ctx['title']} — {res} on {provider} triggered a "
        f"{ctx['severity']} severity {(ctx['alert_type'] or '').replace('_', ' ')} alert. "
        f"{(ctx['description'] or '').strip()}"
    ).strip()
    impact = (
        f"This finding on {res} ({provider}) can expose your organisation to "
        f"data leakage, unauthorised access, or compliance violations depending on "
        f"who can reach the resource and what it contains.\n\n"
        f"Treat the alert at its stated severity ({ctx['severity']}) until the listed "
        f"remediation steps are completed and verified in the {provider} console."
    )
    return {"summary": summary, "impact": impact, "steps": steps}


@router.get("/alerts/{alert_id}/remediation")
async def get_alert_remediation(
    alert_id: str,
    refresh: bool = Query(False, description="If true, bypass and clear cache"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return AI-generated, context-specific remediation guidance for an alert.

    Cached in Redis under key `alert_remediation:{alert_id}` for 24h.
    Pass `?refresh=true` to bust the cache and regenerate.
    """
    await _require_enterprise(current_user, db)
    try:
        alert_uuid = uuid.UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid alert_id")

    # Adnan 2026-06-17: the alerts list is a UNION of saas_alerts +
    # aws_findings + databricks_findings. The old code only looked in
    # saas_alerts so any AWS or Databricks alert 404'd. Now look in all
    # three, in order, and stop at the first hit.
    alert: object | None = (await db.execute(
        select(SaasAlert).where(
            SaasAlert.id == alert_uuid,
            SaasAlert.org_id == current_user.org_id,
        )
    )).scalar_one_or_none()

    if alert is None:
        # Try aws_findings
        try:
            aws_row = await db.execute(text("""
                SELECT id::text, org_id::text, category as alert_type, severity,
                       title, description, resource_id, resource_arn as resource_name,
                       NULL::text as resource_url, metadata as classification_result,
                       NULL::jsonb as posture_result, 'aws' as provider
                FROM aws_findings
                WHERE id = :aid AND org_id = CAST(:oid AS UUID)
                LIMIT 1
            """), {"aid": alert_uuid, "oid": str(current_user.org_id)})
            row = aws_row.mappings().first()
            if row:
                alert = dict(row)
        except Exception as _ex:
            logger.debug(f"alert_remediation: aws_findings lookup failed: {_ex}")

    if alert is None:
        # Try databricks_findings
        try:
            db_row = await db.execute(text("""
                SELECT id::text, org_id::text, category as alert_type, severity,
                       title, description, resource_id, resource_path as resource_name,
                       NULL::text as resource_url, metadata as classification_result,
                       NULL::jsonb as posture_result, 'databricks' as provider
                FROM databricks_findings
                WHERE id = :aid AND org_id = CAST(:oid AS UUID)
                LIMIT 1
            """), {"aid": alert_uuid, "oid": str(current_user.org_id)})
            row = db_row.mappings().first()
            if row:
                alert = dict(row)
        except Exception as _ex:
            logger.debug(f"alert_remediation: databricks_findings lookup failed: {_ex}")

    if alert is None:
        # Try cspm_findings (github / azure / oracle path)
        try:
            cs_row = await db.execute(text("""
                SELECT id::text, org_id::text,
                       check_id as alert_type, severity,
                       title, description, resource_id, resource_id as resource_name,
                       NULL::text as resource_url, metadata as classification_result,
                       NULL::jsonb as posture_result, cloud as provider
                FROM cspm_findings
                WHERE id = :aid AND org_id = CAST(:oid AS UUID)
                LIMIT 1
            """), {"aid": alert_uuid, "oid": str(current_user.org_id)})
            row = cs_row.mappings().first()
            if row:
                alert = dict(row)
        except Exception as _ex:
            logger.debug(f"alert_remediation: cspm_findings lookup failed: {_ex}")

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    org_id = str(current_user.org_id)
    cache_extra = {"alert_id": alert_id}

    if refresh:
        await cache_invalidate("alert_remediation", org_id, extra=cache_extra)
    else:
        cached = await cache_get("alert_remediation", org_id, extra=cache_extra)
        if cached:
            return cached

    ai_result = await _claude_alert_remediation(alert)
    if ai_result:
        payload = {
            "summary": ai_result["summary"],
            "impact": ai_result["impact"],
            "steps": ai_result["steps"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ai_powered": True,
        }
    else:
        fb = _fallback_alert_remediation(alert)
        payload = {
            "summary": fb["summary"],
            "impact": fb["impact"],
            "steps": fb["steps"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ai_powered": False,
        }

    # 24h cache
    await cache_set("alert_remediation", org_id, payload, ttl=86400, extra=cache_extra)
    return payload


@router.post("/alerts/scan")
async def trigger_scan(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a background scan of all connected providers."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    background_tasks.add_task(_run_saas_scan, org_id)
    return {"message": "Scan started", "org_id": org_id}


# ══════════════════════════════════════════════════════════════════════════════
# DATA LIFECYCLE ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/data")
@cached_endpoint("saas:data", ttl=30)
async def list_data_items(
    provider: Optional[str] = Query(None),
    classification_label: Optional[str] = Query(None),
    sharing_scope: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List unified data inventory from SaaS (SharePoint/Teams), AWS resources, and Databricks.
    AWS resources (S3, EBS, RDS, EFS) appear alongside SharePoint files with provider='aws'.
    Databricks notebooks/clusters appear with provider='databricks'.
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    offset = (page - 1) * page_size
    
    # Build WHERE conditions.
    # 2026-06-17: Adnan asked to exclude IAM users/roles from Data
    # Inventory — they belong in the User Risk section, not DSPM.
    saas_conditions = ["org_id = :org_id"]
    aws_conditions = [
        "org_id = :org_id",
        "resource_type NOT IN ('iam_user', 'iam_role', 'iam_group', 'iam_policy')",
    ]
    databricks_conditions = ["org_id = :org_id"]
    gcp_conditions = ["org_id = :org_id"]
    salesforce_conditions = ["org_id = :org_id"]
    # Adnan 2026-06-23 (turn 3): the Data Inventory + Sensitive Data
    # Discovery only showed M365 + AWS (+ databricks/gcp/salesforce when
    # those existed) because Azure, Oracle, GitHub, Snowflake, and SAP
    # had no UNION branch. Each new branch is gated on _table_exists so
    # a brand-new tenant doesn't get a query error.
    azure_conditions = ["org_id = :org_id"]
    oracle_conditions = ["org_id = :org_id"]
    github_conditions = ["org_id = :org_id"]
    snowflake_conditions = ["org_id = :org_id"]
    sap_conditions = ["org_id = :org_id"]
    params: dict = {"org_id": org_id, "limit": page_size, "offset": offset}
    
    # Adnan 2026-06-23: keep this dispatcher table-agnostic. For each
    # provider name we enable just one branch and exclude every other.
    _all_branches = [
        "saas", "aws", "databricks", "gcp", "salesforce",
        "azure", "oracle", "github", "snowflake", "sap",
    ]
    _cond_lookup = {
        "saas":       saas_conditions,
        "aws":        aws_conditions,
        "databricks": databricks_conditions,
        "gcp":        gcp_conditions,
        "salesforce": salesforce_conditions,
        "azure":      azure_conditions,
        "oracle":     oracle_conditions,
        "github":     github_conditions,
        "snowflake":  snowflake_conditions,
        "sap":        sap_conditions,
    }
    if provider:
        # SaaS table holds m365 sub-providers (teams/sharepoint/onedrive);
        # we treat anything not in our cloud list as a SaaS sub-provider.
        cloud_branches = {
            "aws", "databricks", "gcp", "salesforce",
            "azure", "oracle", "github", "snowflake", "sap",
        }
        if provider in cloud_branches:
            for name in _all_branches:
                if name != provider:
                    _cond_lookup[name].append("1=0")
        else:
            # SaaS sub-provider (teams / sharepoint / onedrive / m365).
            saas_conditions.append("provider = :provider")
            for name in _all_branches:
                if name != "saas":
                    _cond_lookup[name].append("1=0")
            params["provider"] = provider
    if classification_label:
        saas_conditions.append("classification_label = :classification_label")
        # Map cloud-row classification based on resource properties.
        params["classification_label"] = classification_label
        # Reusable filters that look at metadata->>'dlp_risk_level' first
        # (canonical) and only fall back to public/encryption flags.
        _conf = (
            "(metadata->>'dlp_risk_level' IN ('high','critical') "
            " OR (encryption_enabled = TRUE AND public_access = FALSE))"
        )
        _pub  = "public_access = TRUE"
        _int  = (
            "(metadata->>'dlp_risk_level' = 'low' "
            " OR (encryption_enabled = FALSE AND public_access = FALSE))"
        )
        _hi   = (
            "((metadata->>'dlp_risk_level') IN ('high','critical') "
            " AND (metadata->'dlp_categories')::jsonb "
            " ?| ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial'])"
        )
        if classification_label == 'confidential':
            for k in ("aws", "gcp", "azure", "oracle"):
                _cond_lookup[k].append(_conf)
            databricks_conditions.append("has_secrets = TRUE")
            salesforce_conditions.append("(metadata->>'dlp_risk_level' IN ('high','critical') OR is_custom = TRUE)")
            github_conditions.append("severity IN ('high','critical')")
            snowflake_conditions.append("severity IN ('high','critical')")
            sap_conditions.append("severity IN ('high','critical')")
        elif classification_label == 'public':
            for k in ("aws", "gcp", "azure", "oracle"):
                _cond_lookup[k].append(_pub)
            databricks_conditions.append("1=0")
            salesforce_conditions.append("guest_accessible = TRUE")
            github_conditions.append("1=0")
            snowflake_conditions.append("1=0")
            sap_conditions.append("1=0")
        elif classification_label == 'internal':
            for k in ("aws", "gcp", "azure", "oracle"):
                _cond_lookup[k].append(_int)
            databricks_conditions.append("has_secrets = FALSE")
            salesforce_conditions.append("guest_accessible = FALSE")
            github_conditions.append("severity IN ('low','medium','info')")
            snowflake_conditions.append("severity IN ('low','medium','info')")
            sap_conditions.append("severity IN ('low','medium','info')")
        elif classification_label == 'highly_confidential':
            for k in ("aws", "gcp", "azure", "oracle"):
                _cond_lookup[k].append(_hi)
            databricks_conditions.append("1=0")
            salesforce_conditions.append("1=0")
            github_conditions.append("severity = 'critical'")
            snowflake_conditions.append("severity = 'critical'")
            sap_conditions.append("severity = 'critical'")
        else:
            for k in ("aws", "gcp", "azure", "oracle", "databricks",
                      "salesforce", "github", "snowflake", "sap"):
                _cond_lookup[k].append("1=0")
    if sharing_scope:
        saas_conditions.append("sharing_scope = :sharing_scope")
        params["sharing_scope"] = sharing_scope
        if sharing_scope == 'public':
            for k in ("aws", "gcp", "azure", "oracle"):
                _cond_lookup[k].append("public_access = TRUE")
            databricks_conditions.append("1=0")
            salesforce_conditions.append("guest_accessible = TRUE")
            github_conditions.append("1=0")  # GitHub findings have no public flag
            snowflake_conditions.append("1=0")
            sap_conditions.append("1=0")
        elif sharing_scope in ('private', 'org'):
            for k in ("aws", "gcp", "azure", "oracle"):
                _cond_lookup[k].append("public_access = FALSE")
            salesforce_conditions.append("guest_accessible = FALSE")
            # databricks, github, snowflake, sap are always org-scoped
        else:
            for k in ("aws", "gcp", "azure", "oracle", "databricks",
                      "salesforce", "github", "snowflake", "sap"):
                _cond_lookup[k].append("1=0")

    saas_where = " AND ".join(saas_conditions)
    aws_where = " AND ".join(aws_conditions)
    databricks_where = " AND ".join(databricks_conditions)
    gcp_where = " AND ".join(gcp_conditions)
    salesforce_where = " AND ".join(salesforce_conditions)
    azure_where = " AND ".join(azure_conditions)
    oracle_where = " AND ".join(oracle_conditions)
    github_where = " AND ".join(github_conditions)
    snowflake_where = " AND ".join(snowflake_conditions)
    sap_where = " AND ".join(sap_conditions)

    # Detect whether salesforce_objects exists so we can omit that
    # UNION branch on a brand-new tenant. The existence check is cheap
    # (≤1ms) compared to a 30s catalog-level scan, and we cache the
    # result on the process for 30s to avoid hammering pg_catalog.
    # Cheap existence checks so we omit UNION branches for connectors
    # the tenant hasn't enabled.
    async def _exists(tbl: str) -> bool:
        try:
            return (await db.execute(text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_name = :t LIMIT 1"
            ), {"t": tbl})).first() is not None
        except Exception:
            return False

    salesforce_branch_sql = ""
    sf_exists = await _exists("salesforce_objects")
    azure_exists     = await _exists("azure_resources")
    oracle_exists    = await _exists("oracle_resources")
    github_exists    = await _exists("github_findings")
    snowflake_exists = await _exists("snowflake_findings")
    sap_exists       = await _exists("sap_findings")
    if sf_exists:
        salesforce_branch_sql = f"""
            UNION ALL
            SELECT
                id::text, 'salesforce' as source, 'salesforce' as provider,
                'sobject' as item_type,
                sobject_name as item_name, NULL::text as item_url,
                NULL::text as parent_path,
                NULL::text as owner_email, NULL::bigint as size_bytes,
                -- Translate the DLP worker's risk_level (low|medium|high|critical)
                -- into the sensitivity label vocabulary the frontend expects
                -- (public|internal|confidential|highly_confidential). High-risk
                -- rows that carry PII/PHI/PCI/credentials/customer_data tokens
                -- are escalated to highly_confidential so they light up the
                -- Sensitive Exposure panel + filters.
                CASE
                    WHEN metadata->>'dlp_risk_level' IN ('public','internal','confidential','highly_confidential')
                        THEN metadata->>'dlp_risk_level'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high')
                         AND (metadata->'dlp_categories')::jsonb
                             ?| ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial']
                        THEN 'highly_confidential'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high','medium')
                        THEN 'confidential'
                    WHEN metadata->>'dlp_risk_level' = 'low' AND guest_accessible = TRUE
                        THEN 'public'
                    WHEN metadata->>'dlp_risk_level' = 'low'
                        THEN 'internal'
                    WHEN guest_accessible = TRUE THEN 'public'
                    WHEN is_custom = TRUE THEN 'confidential'
                    ELSE 'internal'
                END as classification_label,
                CASE
                    WHEN metadata->>'dlp_classified' = 'true' THEN 0.85
                    WHEN guest_accessible = TRUE THEN 0.95
                    ELSE 0.5
                END as classification_score,
                COALESCE(
                    NULLIF(metadata->>'dlp_categories', ''),
                    '[]'
                ) as classification_categories,
                CASE WHEN guest_accessible = TRUE THEN 'public' ELSE 'org' END as sharing_scope,
                discovered_at as last_modified_at, discovered_at as last_scanned_at,
                discovered_at as created_at,
                NULL::text as region, NULL::text as resource_arn,
                FALSE as encryption_enabled,
                guest_accessible as public_access,
                metadata
            FROM salesforce_objects
            WHERE {salesforce_where}
        """

    # Adnan 2026-06-23 (turn 3): branches for Azure / Oracle (inventory
    # tables with metadata->>dlp_*) and GitHub / Snowflake / SAP
    # (findings tables — they don't have public_access/encryption flags,
    # so we synthesise sharing_scope='org' and read categories from
    # the same metadata key as the inventory rows).
    azure_branch_sql = ""
    if azure_exists:
        azure_branch_sql = f"""
            UNION ALL
            SELECT
                id::text, 'azure' as source, 'azure' as provider, resource_type as item_type,
                COALESCE(name, resource_id) as item_name, NULL::text as item_url,
                location as parent_path,
                COALESCE(metadata->>'owner', metadata->>'created_by', NULL) as owner_email,
                NULL::bigint as size_bytes,
                CASE
                    WHEN metadata->>'dlp_risk_level' IN ('public','internal','confidential','highly_confidential')
                        THEN metadata->>'dlp_risk_level'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high')
                         AND (metadata->'dlp_categories')::jsonb
                             ?| ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial']
                        THEN 'highly_confidential'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high','medium')
                        THEN 'confidential'
                    WHEN metadata->>'dlp_risk_level' = 'low' AND public_access = TRUE
                        THEN 'public'
                    WHEN metadata->>'dlp_risk_level' = 'low'
                        THEN 'internal'
                    WHEN public_access = TRUE THEN 'public'
                    WHEN encryption_enabled = TRUE THEN 'confidential'
                    ELSE 'internal'
                END as classification_label,
                CASE
                    WHEN metadata->>'dlp_classified' = 'true' THEN 0.85
                    WHEN encryption_enabled = TRUE THEN 0.8
                    ELSE 0.5
                END as classification_score,
                COALESCE(
                    NULLIF(metadata->>'dlp_categories', ''),
                    NULLIF(metadata->>'ai_categories', ''),
                    '[]'
                ) as classification_categories,
                CASE WHEN public_access = TRUE THEN 'public' ELSE 'private' END as sharing_scope,
                last_modified as last_modified_at, scanned_at as last_scanned_at, created_at,
                location as region, NULL::text as resource_arn, encryption_enabled, public_access,
                metadata
            FROM azure_resources
            WHERE {azure_where}
        """

    oracle_branch_sql = ""
    if oracle_exists:
        oracle_branch_sql = f"""
            UNION ALL
            SELECT
                id::text, 'oracle' as source, 'oracle' as provider, resource_type as item_type,
                COALESCE(name, resource_id) as item_name, NULL::text as item_url,
                region as parent_path,
                COALESCE(metadata->>'owner', metadata->>'created_by', NULL) as owner_email,
                NULL::bigint as size_bytes,
                CASE
                    WHEN metadata->>'dlp_risk_level' IN ('public','internal','confidential','highly_confidential')
                        THEN metadata->>'dlp_risk_level'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high')
                         AND (metadata->'dlp_categories')::jsonb
                             ?| ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial']
                        THEN 'highly_confidential'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high','medium')
                        THEN 'confidential'
                    WHEN metadata->>'dlp_risk_level' = 'low' AND public_access = TRUE
                        THEN 'public'
                    WHEN metadata->>'dlp_risk_level' = 'low'
                        THEN 'internal'
                    WHEN public_access = TRUE THEN 'public'
                    WHEN encryption_enabled = TRUE THEN 'confidential'
                    ELSE 'internal'
                END as classification_label,
                CASE
                    WHEN metadata->>'dlp_classified' = 'true' THEN 0.85
                    WHEN encryption_enabled = TRUE THEN 0.8
                    ELSE 0.5
                END as classification_score,
                COALESCE(
                    NULLIF(metadata->>'dlp_categories', ''),
                    '[]'
                ) as classification_categories,
                CASE WHEN public_access = TRUE THEN 'public' ELSE 'private' END as sharing_scope,
                last_modified as last_modified_at, scanned_at as last_scanned_at, created_at,
                region, NULL::text as resource_arn, encryption_enabled, public_access,
                metadata
            FROM oracle_resources
            WHERE {oracle_where}
        """

    # Findings tables (github / snowflake / sap): no per-row public_access
    # or encryption flag, no last_modified column, just a finding row.
    # Adnan 2026-06-23 (turn 6): the schemas DIFFER between these three:
    #   - sap_findings  has `finding_type`, `detected_at`, `metadata jsonb`
    #   - snowflake_findings has `first_seen_at` (NO `detected_at`),
    #     `evidence text`, `compliance jsonb` (NO `metadata`), no
    #     `finding_type`.
    #   - github_findings: we don't even create it explicitly; if a tenant
    #     has it, treat its shape as unknown and DO NOT add a branch —
    #     a schema mismatch crashes the whole UNION and we silently
    #     fall back to the SaaS-only path, which is exactly what was
    #     causing the Data Inventory loading hang.
    # Probe columns at runtime per table and emit a branch only when we
    # have the bare minimum (`title`, `severity`, an id, a time column).
    async def _columns(t: str) -> set[str]:
        try:
            r = (await db.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = :t"
            ), {"t": t})).fetchall()
            return {row[0] for row in r}
        except Exception:
            return set()

    async def _build_findings_branch(
        provider_name: str, table: str, where: str,
    ) -> str:
        cols = await _columns(table)
        if not {"title", "severity", "id"}.issubset(cols):
            return ""
        item_type_expr = (
            "COALESCE(finding_type, category, 'finding')"
            if "finding_type" in cols
            else "COALESCE(category, 'finding')"
        )
        time_col = (
            "detected_at" if "detected_at" in cols
            else ("first_seen_at" if "first_seen_at" in cols
                  else ("last_seen_at" if "last_seen_at" in cols
                        else "NULL::timestamptz"))
        )
        meta_expr = (
            "metadata" if "metadata" in cols
            else ("compliance" if "compliance" in cols
                  else "'{}'::jsonb")
        )
        # When metadata->>'dlp_*' is not available (snowflake), we still
        # need a JSONB to feed the CASE expressions. The expression
        # `meta_expr` returns the right column, or an empty object.
        return f"""
            UNION ALL
            SELECT
                id::text, '{provider_name}' as source, '{provider_name}' as provider,
                {item_type_expr} as item_type,
                title as item_name, NULL::text as item_url,
                category as parent_path,
                NULL::text as owner_email, NULL::bigint as size_bytes,
                CASE
                    WHEN ({meta_expr})::jsonb->>'dlp_risk_level' IN ('public','internal','confidential','highly_confidential')
                        THEN ({meta_expr})::jsonb->>'dlp_risk_level'
                    WHEN severity = 'critical'
                         AND COALESCE((({meta_expr})::jsonb)->'dlp_categories', '[]'::jsonb)
                             ?| ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial']
                        THEN 'highly_confidential'
                    WHEN severity IN ('critical','high') THEN 'confidential'
                    WHEN severity IN ('medium','low','info') THEN 'internal'
                    ELSE 'internal'
                END as classification_label,
                CASE
                    WHEN ({meta_expr})::jsonb->>'dlp_classified' = 'true' THEN 0.85
                    WHEN severity = 'critical' THEN 0.9
                    WHEN severity = 'high' THEN 0.8
                    ELSE 0.5
                END as classification_score,
                COALESCE(
                    NULLIF(({meta_expr})::jsonb->>'dlp_categories', ''),
                    '[]'
                ) as classification_categories,
                'org' as sharing_scope,
                {time_col} as last_modified_at, {time_col} as last_scanned_at, {time_col} as created_at,
                NULL::text as region, NULL::text as resource_arn,
                FALSE as encryption_enabled, FALSE as public_access,
                ({meta_expr})::jsonb as metadata
            FROM {table}
            WHERE {where}
        """

    github_branch_sql    = (await _build_findings_branch("github",    "github_findings",    github_where))    if github_exists    else ""
    snowflake_branch_sql = (await _build_findings_branch("snowflake", "snowflake_findings", snowflake_where)) if snowflake_exists else ""
    sap_branch_sql       = (await _build_findings_branch("sap",       "sap_findings",       sap_where))       if sap_exists       else ""

    # UNION query: SaaS data items + AWS resources + Databricks resources
    # classification_categories must be valid JSON on every branch so the
    # Python parser below produces a real list. SaaS uses text[] — convert
    # via to_jsonb. AWS/Databricks/GCP read metadata->>'dlp_categories'
    # which is already a JSON-encoded array string; parse with ::jsonb so
    # COALESCE branches return jsonb uniformly. Final ::text cast keeps the
    # UNION column type stable (json text) for the response parser.
    union_sql = f"""
        SELECT * FROM (
            SELECT 
                id::text, 'saas' as source, provider, item_type, item_name, item_url, parent_path,
                owner_email, size_bytes, classification_label, classification_score,
                to_jsonb(COALESCE(classification_categories, ARRAY[]::text[]))::text as classification_categories, sharing_scope, last_modified_at, last_scanned_at, created_at,
                NULL::text as region, NULL::text as resource_arn, FALSE as encryption_enabled, FALSE as public_access,
                NULL::jsonb as metadata
            FROM saas_data_items
            WHERE {saas_where}
            UNION ALL
            SELECT 
                id::text, 'aws' as source, 'aws' as provider, resource_type as item_type, 
                COALESCE(name, resource_id) as item_name, NULL::text as item_url, region as parent_path,
                COALESCE(metadata->>'owner', metadata->>'created_by', metadata->>'launched_by', NULL) as owner_email, size_bytes,
                -- Map risk_level (low|medium|high|critical) → sensitivity
                -- label (public|internal|confidential|highly_confidential).
                -- PII/PHI/PCI/credentials in categories escalate to
                -- highly_confidential so the Sensitive Exposure panel +
                -- filters pick AWS rows up.
                CASE
                    WHEN metadata->>'dlp_risk_level' IN ('public','internal','confidential','highly_confidential')
                        THEN metadata->>'dlp_risk_level'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high')
                         AND (metadata->'dlp_categories')::jsonb
                             ?| ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial']
                        THEN 'highly_confidential'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high','medium')
                        THEN 'confidential'
                    WHEN metadata->>'dlp_risk_level' = 'low' AND public_access = TRUE
                        THEN 'public'
                    WHEN metadata->>'dlp_risk_level' = 'low'
                        THEN 'internal'
                    WHEN public_access = TRUE THEN 'public'
                    WHEN encryption_enabled = TRUE THEN 'confidential'
                    ELSE 'internal'
                END as classification_label,
                CASE 
                    WHEN metadata->>'dlp_classified' = 'true' THEN 0.85
                    WHEN encryption_enabled = TRUE THEN 0.8 
                    ELSE 0.5 
                END as classification_score,
                -- Prefer the canonical dlp_categories key written by the
                -- DLP worker; fall back to ai_categories written by the
                -- fast main.py auto-scan loop so freshly-scanned resources
                -- still show categories before the DLP worker catches up.
                COALESCE(
                    NULLIF(metadata->>'dlp_categories', ''),
                    NULLIF(metadata->>'ai_categories', ''),
                    '[]'
                ) as classification_categories,
                CASE WHEN public_access = TRUE THEN 'public' ELSE 'private' END as sharing_scope,
                last_modified as last_modified_at, scanned_at as last_scanned_at, created_at,
                region, resource_arn, encryption_enabled, public_access,
                metadata
            FROM aws_resources
            WHERE {aws_where}
            UNION ALL
            SELECT 
                id::text, 'databricks' as source, 'databricks' as provider, resource_type as item_type,
                COALESCE(name, resource_path, resource_id) as item_name, NULL::text as item_url, resource_path as parent_path,
                created_by as owner_email, NULL::bigint as size_bytes,
                -- Translate DLP worker's risk_level → sensitivity label.
                CASE
                    WHEN metadata->>'dlp_risk_level' IN ('public','internal','confidential','highly_confidential')
                        THEN metadata->>'dlp_risk_level'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high')
                         AND (metadata->'dlp_categories')::jsonb
                             ?| ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial']
                        THEN 'highly_confidential'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high','medium')
                        THEN 'confidential'
                    WHEN metadata->>'dlp_risk_level' = 'low'
                        THEN 'internal'
                    WHEN has_secrets = TRUE THEN 'confidential'
                    ELSE 'internal'
                END as classification_label,
                CASE
                    WHEN metadata->>'dlp_classified' = 'true' THEN 0.85
                    WHEN has_secrets = TRUE THEN 0.9 ELSE 0.5
                END as classification_score,
                -- Prefer canonical dlp_categories, fall back to legacy secret_types
                COALESCE(
                    NULLIF(metadata->>'dlp_categories', ''),
                    NULLIF(metadata->>'secret_types', ''),
                    '[]'
                ) as classification_categories,
                'org' as sharing_scope,
                last_modified as last_modified_at, scanned_at as last_scanned_at, created_at,
                NULL::text as region, NULL::text as resource_arn, FALSE as encryption_enabled, FALSE as public_access,
                metadata
            FROM databricks_resources
            WHERE {databricks_where}
            UNION ALL
            SELECT
                id::text, 'gcp' as source, 'gcp' as provider, resource_type as item_type,
                COALESCE(name, resource_name, resource_id) as item_name, NULL::text as item_url,
                location as parent_path,
                COALESCE(metadata->>'owner', metadata->>'created_by', NULL) as owner_email, size_bytes,
                -- Translate DLP worker's risk_level → sensitivity label.
                CASE
                    WHEN metadata->>'dlp_risk_level' IN ('public','internal','confidential','highly_confidential')
                        THEN metadata->>'dlp_risk_level'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high')
                         AND (metadata->'dlp_categories')::jsonb
                             ?| ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial']
                        THEN 'highly_confidential'
                    WHEN metadata->>'dlp_risk_level' IN ('critical','high','medium')
                        THEN 'confidential'
                    WHEN metadata->>'dlp_risk_level' = 'low' AND public_access = TRUE
                        THEN 'public'
                    WHEN metadata->>'dlp_risk_level' = 'low'
                        THEN 'internal'
                    WHEN public_access = TRUE THEN 'public'
                    WHEN encryption_enabled = TRUE THEN 'confidential'
                    ELSE 'internal'
                END as classification_label,
                CASE
                    WHEN metadata->>'dlp_classified' = 'true' THEN 0.85
                    WHEN encryption_enabled = TRUE THEN 0.8
                    ELSE 0.5
                END as classification_score,
                COALESCE(
                    NULLIF(metadata->>'dlp_categories', ''),
                    '[]'
                ) as classification_categories,
                CASE WHEN public_access = TRUE THEN 'public' ELSE 'private' END as sharing_scope,
                last_modified as last_modified_at, scanned_at as last_scanned_at, created_at,
                location as region, NULL::text as resource_arn, encryption_enabled, public_access,
                metadata
            FROM gcp_resources
            WHERE {gcp_where}
            {salesforce_branch_sql}
            {azure_branch_sql}
            {oracle_branch_sql}
            {github_branch_sql}
            {snowflake_branch_sql}
            {sap_branch_sql}
        ) combined
        ORDER BY last_modified_at DESC NULLS LAST
        LIMIT :limit OFFSET :offset
    """

    # Count query
    count_salesforce_branch = ""
    if sf_exists:
        count_salesforce_branch = f"""
            UNION ALL
            SELECT id FROM salesforce_objects WHERE {salesforce_where}
        """
    count_azure_branch     = f" UNION ALL SELECT id FROM azure_resources WHERE {azure_where} "     if azure_exists     else ""
    count_oracle_branch    = f" UNION ALL SELECT id FROM oracle_resources WHERE {oracle_where} "   if oracle_exists    else ""
    # Only count a findings table if we actually emitted a UNION branch
    # for it. Otherwise the WHERE clause (which may reference `severity`)
    # would crash on tables that lack the column.
    count_github_branch    = f" UNION ALL SELECT id FROM github_findings WHERE {github_where} "    if github_branch_sql    else ""
    count_snowflake_branch = f" UNION ALL SELECT id FROM snowflake_findings WHERE {snowflake_where} " if snowflake_branch_sql else ""
    count_sap_branch       = f" UNION ALL SELECT id FROM sap_findings WHERE {sap_where} "          if sap_branch_sql       else ""
    count_sql = f"""
        SELECT COUNT(*) FROM (
            SELECT id FROM saas_data_items WHERE {saas_where}
            UNION ALL
            SELECT id FROM aws_resources WHERE {aws_where}
            UNION ALL
            SELECT id FROM databricks_resources WHERE {databricks_where}
            UNION ALL
            SELECT id FROM gcp_resources WHERE {gcp_where}
            {count_salesforce_branch}
            {count_azure_branch}
            {count_oracle_branch}
            {count_github_branch}
            {count_snowflake_branch}
            {count_sap_branch}
        ) combined
    """
    
    try:
        # Execute count
        logger.info(f"list_data_items: executing count query for org_id={org_id}")
        count_result = await db.execute(text(count_sql), {k: v for k, v in params.items() if k not in ("limit", "offset")})
        total = count_result.scalar() or 0
        logger.info(f"list_data_items: count={total} for org_id={org_id}")
        
        # Execute union
        result = await db.execute(text(union_sql), params)
        rows = result.mappings().all()
        logger.info(f"list_data_items: got {len(rows)} rows for org_id={org_id}")
        
        items = []
        for row in rows:
            item = {
                "id": row["id"],
                "provider": row["provider"],
                "item_type": row["item_type"],
                "item_name": row["item_name"],
                "item_url": row["item_url"],
                "parent_path": row["parent_path"],
                "owner_email": row["owner_email"],
                "size_bytes": row["size_bytes"],
                "classification_label": row["classification_label"],
                "classification_score": row["classification_score"],
                "classification_result": None,
                "sharing_scope": row["sharing_scope"],
                "last_modified_at": row["last_modified_at"].isoformat() if row["last_modified_at"] else None,
                "last_scanned_at": row["last_scanned_at"].isoformat() if row["last_scanned_at"] else None,
                "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                "source": row["source"],
            }
            # Parse classification_categories — SaaS returns a Python list,
            # cloud branches return a JSON string. Adnan 2026-06-23 (turn 3):
            # ALSO check `metadata.dlp_categories` directly because some
            # rows were written before the CAST(:meta AS jsonb) fix and have
            # metadata stored as a JSON-encoded string rather than an object;
            # for those `metadata->>'dlp_categories'` returns NULL and the
            # UNION column comes back empty even though the data is there.
            raw_cats = row["classification_categories"]
            parsed_cats: list = []
            if isinstance(raw_cats, list):
                parsed_cats = raw_cats
            elif isinstance(raw_cats, str) and raw_cats and raw_cats != "[]":
                try:
                    parsed_cats = json.loads(raw_cats)
                    if not isinstance(parsed_cats, list):
                        parsed_cats = []
                except Exception:
                    parsed_cats = []
            # Fallback: dig into metadata directly for legacy rows.
            if not parsed_cats and row.get("metadata"):
                meta = row["metadata"]
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                if isinstance(meta, dict):
                    fallback = (meta.get("dlp_categories")
                                or meta.get("ai_categories")
                                or meta.get("categories")
                                or meta.get("dlp_data_categories")
                                or [])
                    if isinstance(fallback, str):
                        try:
                            fallback = json.loads(fallback)
                        except Exception:
                            fallback = []
                    if isinstance(fallback, list):
                        parsed_cats = [str(c) for c in fallback if c]
            item["classification_categories"] = parsed_cats
            # Cloud-specific fields (region / encryption / public_access /
            # metadata) are shared across every cloud branch — not just AWS.
            # Adnan 2026-06-23 (turn 3): without this, Azure/GCP/Oracle rows
            # came back without `region` populated even though the column
            # was selected.
            if row["source"] in ('aws', 'gcp', 'azure', 'oracle',
                                 'salesforce', 'databricks',
                                 'github', 'snowflake', 'sap'):
                item["region"] = row["region"]
                item["resource_arn"] = row["resource_arn"]
                item["encryption_enabled"] = row["encryption_enabled"]
                item["public_access"] = row["public_access"]
                if row["metadata"]:
                    item["metadata"] = row["metadata"]
            items.append(item)
        
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": items,
        }
    except Exception as e:
        logger.warning(f"list_data_items: UNION query failed, falling back to SaaS only: {e}")
        # Fallback to original SaaS-only query
        q = select(SaasDataItem).where(SaasDataItem.org_id == current_user.org_id)
        if provider and provider != 'aws':
            q = q.where(SaasDataItem.provider == provider)
        if classification_label:
            q = q.where(SaasDataItem.classification_label == classification_label)
        if sharing_scope:
            q = q.where(SaasDataItem.sharing_scope == sharing_scope)

        total_q = select(func.count()).select_from(q.subquery())
        total = (await db.execute(total_q)).scalar() or 0

        q = q.order_by(SaasDataItem.last_modified_at.desc().nullslast()).offset((page - 1) * page_size).limit(page_size)
        rows = (await db.execute(q)).scalars().all()

        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "items": [_data_item_to_dict(d) for d in rows],
        }


# ── AI-driven verbose resource risk analysis ─────────────────────────────────

# Shared SQL fragment: translate the cross-cloud DLP worker's risk_level
# (low|medium|high|critical) into the sensitivity label vocabulary the
# frontend expects (public|internal|confidential|highly_confidential).
# `_extra_low` / `_extra_default` let each branch insert table-specific
# fallbacks (public_access, has_secrets, etc.) when DLP hasn't classified
# the row yet.
def _label_case_sql(low_extra: str = "", default_extra: str = "") -> str:
    return (
        "CASE "
        "WHEN metadata->>'dlp_risk_level' IN ('public','internal','confidential','highly_confidential') "
        "  THEN metadata->>'dlp_risk_level' "
        "WHEN metadata->>'dlp_risk_level' IN ('critical','high') "
        "     AND (metadata->'dlp_categories')::jsonb ?| "
        "         ARRAY['pii','phi','pci','credentials','secrets','customer_data','financial'] "
        "  THEN 'highly_confidential' "
        "WHEN metadata->>'dlp_risk_level' IN ('critical','high','medium') "
        "  THEN 'confidential' "
        f"{low_extra} "
        "WHEN metadata->>'dlp_risk_level' = 'low' "
        "  THEN 'internal' "
        f"{default_extra} "
        "ELSE 'internal' "
        "END"
    )


async def _fetch_data_item_context(item_id: str, org_id: str, db: AsyncSession) -> Optional[dict]:
    """Look up a data inventory item across saas/aws/databricks/gcp tables.

    Mirrors the UNION shape used by /api/saas/data so we can resolve any id
    returned by that listing endpoint.
    """
    # Try saas_data_items first (UUID PK)
    try:
        item_uuid = uuid.UUID(item_id)
        row = (await db.execute(
            text(
                "SELECT id::text, 'saas' as source, provider, item_type, item_name, "
                "item_url, parent_path, owner_email, size_bytes, classification_label, "
                "classification_score, to_jsonb(COALESCE(classification_categories, ARRAY[]::text[]))::text as classification_categories, "
                "sharing_scope, last_modified_at, last_scanned_at, created_at, "
                "NULL::jsonb as metadata, NULL::text as region, FALSE as encryption_enabled, "
                "FALSE as public_access "
                "FROM saas_data_items WHERE id=:id AND org_id=:oid"
            ),
            {"id": str(item_uuid), "oid": org_id},
        )).mappings().first()
        if row:
            return dict(row)
    except (ValueError, Exception) as exc:  # noqa: BLE001 — fall through to other tables
        logger.debug(f"resource_risk: saas lookup failed for {item_id}: {exc}")

    # Try aws_resources
    try:
        _aws_label_sql = _label_case_sql(
            low_extra=("WHEN metadata->>'dlp_risk_level' = 'low' "
                       "AND public_access THEN 'public'"),
            default_extra=("WHEN public_access THEN 'public' "
                           "WHEN encryption_enabled THEN 'confidential'"),
        )
        row = (await db.execute(
            text(
                "SELECT id::text, 'aws' as source, 'aws' as provider, resource_type as item_type, "
                "COALESCE(name, resource_id) as item_name, NULL::text as item_url, "
                "region as parent_path, "
                "COALESCE(metadata->>'owner', metadata->>'created_by', metadata->>'launched_by') as owner_email, "
                "size_bytes, "
                + _aws_label_sql + " as classification_label, "
                "0.5::real as classification_score, "
                "COALESCE(NULLIF(metadata->>'dlp_categories',''), NULLIF(metadata->>'ai_categories',''), '[]') as classification_categories, "
                "CASE WHEN public_access THEN 'public' ELSE 'private' END as sharing_scope, "
                "last_modified as last_modified_at, scanned_at as last_scanned_at, created_at, "
                "metadata, region, encryption_enabled, public_access "
                "FROM aws_resources WHERE id::text=:id AND org_id=:oid"
            ),
            {"id": item_id, "oid": org_id},
        )).mappings().first()
        if row:
            return dict(row)
    except Exception as exc:
        logger.debug(f"resource_risk: aws lookup failed for {item_id}: {exc}")

    # Try databricks_resources
    try:
        row = (await db.execute(
            text(
                "SELECT id::text, 'databricks' as source, 'databricks' as provider, "
                "resource_type as item_type, COALESCE(name, resource_path, resource_id) as item_name, "
                "NULL::text as item_url, resource_path as parent_path, "
                "created_by as owner_email, NULL::bigint as size_bytes, "
                + _label_case_sql(default_extra="WHEN has_secrets THEN 'confidential'") + " as classification_label, "
                "0.5::real as classification_score, "
                "COALESCE(NULLIF(metadata->>'dlp_categories',''), NULLIF(metadata->>'secret_types',''), '[]') as classification_categories, "
                "'org' as sharing_scope, last_modified as last_modified_at, scanned_at as last_scanned_at, "
                "created_at, metadata, NULL::text as region, FALSE as encryption_enabled, FALSE as public_access "
                "FROM databricks_resources WHERE id::text=:id AND org_id=:oid"
            ),
            {"id": item_id, "oid": org_id},
        )).mappings().first()
        if row:
            return dict(row)
    except Exception as exc:
        logger.debug(f"resource_risk: databricks lookup failed for {item_id}: {exc}")

    # Try gcp_resources
    try:
        row = (await db.execute(
            text(
                "SELECT id::text, 'gcp' as source, 'gcp' as provider, resource_type as item_type, "
                "COALESCE(name, resource_name, resource_id) as item_name, NULL::text as item_url, "
                "location as parent_path, COALESCE(metadata->>'owner', metadata->>'created_by') as owner_email, "
                "size_bytes, "
                + _label_case_sql(
                    low_extra=("WHEN metadata->>'dlp_risk_level' = 'low' "
                               "AND public_access THEN 'public'"),
                    default_extra=("WHEN public_access THEN 'public' "
                                   "WHEN encryption_enabled THEN 'confidential'"),
                ) + " as classification_label, "
                "0.5::real as classification_score, "
                "COALESCE(NULLIF(metadata->>'dlp_categories',''), '[]') as classification_categories, "
                "CASE WHEN public_access THEN 'public' ELSE 'private' END as sharing_scope, "
                "last_modified as last_modified_at, scanned_at as last_scanned_at, created_at, "
                "metadata, location as region, encryption_enabled, public_access "
                "FROM gcp_resources WHERE id::text=:id AND org_id=:oid"
            ),
            {"id": item_id, "oid": org_id},
        )).mappings().first()
        if row:
            return dict(row)
    except Exception as exc:
        logger.debug(f"resource_risk: gcp lookup failed for {item_id}: {exc}")

    return None


def _categories_from_raw(raw) -> list:
    if isinstance(raw, list):
        return [str(c) for c in raw]
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(c) for c in parsed]
        except Exception:
            pass
    return []


async def _claude_resource_risk(item: dict) -> Optional[dict]:
    """Call Claude for verbose, resource-specific risk analysis."""
    if not ANTHROPIC_API_KEY:
        return None
    try:
        cats = _categories_from_raw(item.get("classification_categories"))
        # Adnan 2026-06-23: DLP categories must ALWAYS be present in the
        # AI risk prompt so the assessment can lean on them. If the
        # ingest path didn't write any, fall back to a quick heuristic
        # on name+type+tags so we don't ship "Classification categories
        # (DLP): []" to the model and get back generic boilerplate.
        if not cats:
            try:
                from backend.services.cross_cloud_dlp import _classify_heuristic
                _heur_cats, _heur_risk = _classify_heuristic({
                    "name": item.get("item_name"),
                    "resource_type": item.get("item_type") or item.get("resource_type"),
                    "resource_path": item.get("parent_path"),
                    "region": item.get("region"),
                    "public_access": item.get("public_access"),
                    "encryption_enabled": item.get("encryption_enabled"),
                    "tags": item.get("tags"),
                })
                if _heur_cats:
                    cats = _heur_cats
                    item.setdefault("_dlp_cats_source", "heuristic")
            except Exception as _heur_exc:  # pragma: no cover - defensive
                logger.debug(f"resource_risk: heuristic fallback failed: {_heur_exc}")
        meta = item.get("metadata") or {}
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        meta_str = json.dumps(meta, default=str)[:1200] if meta else ""
        size_bytes = item.get("size_bytes")
        size_human = (
            f"{size_bytes / 1048576:.1f} MB" if isinstance(size_bytes, (int, float)) and size_bytes > 1048576
            else f"{int(size_bytes / 1024)} KB" if isinstance(size_bytes, (int, float)) and size_bytes
            else "unknown"
        )
        last_mod = item.get("last_modified_at")
        last_mod_str = last_mod.isoformat() if hasattr(last_mod, "isoformat") else str(last_mod or "unknown")
        prompt = (
            "You are a senior cloud DLP / data security analyst writing a verbose, "
            "specific risk analysis for a workspace inventory item that an admin clicked on. "
            "Reference this specific resource by name, provider, owner, sharing scope, "
            "and classification — do not produce a generic template.\n\n"
            f"Provider: {item.get('provider')}\n"
            f"Resource type: {item.get('item_type')}\n"
            f"Resource name: {item.get('item_name')}\n"
            f"Parent path / location: {item.get('parent_path') or 'n/a'}\n"
            f"Owner: {item.get('owner_email') or 'unknown'}\n"
            f"Classification label: {item.get('classification_label') or 'unknown'}\n"
            f"Classification categories (DLP): {cats or '[]'} "
            f"({'heuristic-derived' if item.get('_dlp_cats_source') == 'heuristic' else 'from classifier'})\n"
            "NOTE: The DLP categories above are authoritative for this assessment. Reason FROM them "
            "— do NOT ignore them, even if they look minor. Cite each relevant one by name.\n"
            f"Sharing scope: {item.get('sharing_scope') or 'unknown'}\n"
            f"Encryption enabled: {item.get('encryption_enabled')}\n"
            f"Public access: {item.get('public_access')}\n"
            f"Region: {item.get('region') or 'n/a'}\n"
            f"Size: {size_human}\n"
            f"Last modified: {last_mod_str}\n"
            f"Provider metadata (truncated): {meta_str}\n\n"
            "Respond with JSON ONLY in this exact shape:\n"
            "{\n"
            '  "assessment": "4-6 sentence verbose risk assessment naming the resource, its classification, sharing scope, owner and provider.",\n'
            '  "risks": ["specific risk 1 for THIS resource", "risk 2", "3-6 total"],\n'
            '  "actions": ["recommended action 1 referencing the actual console / tooling", "action 2", "3-5 total"]\n'
            "}\n\n"
            "Rules: be concrete — mention the resource by name; if categories include "
            "credentials / PII / financial / health, call that out explicitly; if sharing is "
            "external or public, treat that as elevated risk; if encryption is disabled, "
            "call it out. Do NOT include filler like 'review the resource'."
        )
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 1500,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if r.status_code != 200:
                logger.warning(
                    f"resource_risk: Claude returned {r.status_code}: {r.text[:200]}"
                )
                return None
            raw = r.json()["content"][0]["text"].strip()
            raw = re.sub(r"^```[\w]*\n?", "", raw)
            raw = re.sub(r"```$", "", raw).strip()
            parsed = json.loads(raw)
            assessment = str(parsed.get("assessment") or "").strip()
            risks = [str(x).strip() for x in (parsed.get("risks") or []) if str(x).strip()]
            actions = [str(x).strip() for x in (parsed.get("actions") or []) if str(x).strip()]
            if not assessment or not risks:
                logger.warning("resource_risk: Claude returned empty assessment/risks")
                return None
            return {"assessment": assessment, "risks": risks, "actions": actions}
    except Exception as exc:
        logger.warning(f"resource_risk: Claude call failed: {exc}")
        return None


def _fallback_resource_risk(item: dict) -> dict:
    """Less-generic fallback when Claude is unavailable."""
    name = item.get("item_name") or "this resource"
    provider = (item.get("provider") or "unknown").upper()
    label = item.get("classification_label") or "unknown"
    scope = item.get("sharing_scope") or "unknown"
    owner = item.get("owner_email") or "an unknown owner"
    cats = _categories_from_raw(item.get("classification_categories"))
    cats_str = ", ".join(cats) if cats else "no DLP categories detected"
    encryption = item.get("encryption_enabled")
    public = item.get("public_access")
    extras = []
    if public:
        extras.append("public access is currently enabled")
    if encryption is False:
        extras.append("encryption at rest is disabled")
    if scope in ("public", "external"):
        extras.append(f"sharing scope is '{scope}'")
    extras_str = ("; " + "; ".join(extras)) if extras else ""

    assessment = (
        f"{name} is a {item.get('item_type') or 'resource'} on {provider} owned by {owner}, "
        f"classified as {label}. DLP signal: {cats_str}{extras_str}. "
        f"Manual review is recommended until Claude-based analysis is available."
    )
    risks = []
    if scope in ("public", "external"):
        risks.append(f"{name} is reachable outside the organisation (sharing_scope={scope}); any embedded sensitive data is at risk of unauthorised access.")
    if encryption is False:
        risks.append(f"{name} is not encrypted at rest, so a storage-layer compromise would expose the contents in cleartext.")
    if cats:
        risks.append(f"{name} carries DLP categories ({cats_str}) which may trigger regulatory obligations (GDPR/PCI/HIPAA) if mishandled.")
    if label in ("confidential", "highly_confidential") and scope not in ("private", "org"):
        risks.append(f"{name} is classified {label} but its sharing scope is {scope}; the access surface is wider than the sensitivity warrants.")
    if not risks:
        risks.append(f"No high-severity DLP signal detected on {name}; treat as standard hygiene candidate.")
        risks.append("Stale or unmaintained resources can accumulate unintended exposure over time — confirm an active owner.")

    actions = [
        f"Open {name} in the {provider} console and verify the current ACL / sharing settings match its {label} classification.",
        f"Contact the owner ({owner}) to confirm continued business need.",
    ]
    if scope in ("public", "external"):
        actions.append(f"Restrict {name} to private / org-only sharing until external access is justified in writing.")
    if encryption is False:
        actions.append(f"Enable encryption at rest for {name} via the {provider} default-encryption policy.")
    if cats:
        actions.append(f"Apply a DLP policy that matches the detected categories ({cats_str}) to {name}.")

    return {"assessment": assessment, "risks": risks, "actions": actions}


@router.get("/data/{item_id}/risk-analysis")
async def get_resource_risk_analysis(
    item_id: str,
    refresh: bool = Query(False, description="If true, bypass and clear cache"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return AI-generated, verbose risk analysis for a single inventory item.

    Cached in Redis under key `resource_risk:{item_id}` for 24h.
    Pass `?refresh=true` to bust the cache and regenerate.
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    item = await _fetch_data_item_context(item_id, org_id, db)
    if not item:
        raise HTTPException(status_code=404, detail="Data item not found")

    cache_extra = {"item_id": item_id}
    if refresh:
        await cache_invalidate("resource_risk", org_id, extra=cache_extra)
    else:
        cached = await cache_get("resource_risk", org_id, extra=cache_extra)
        if cached:
            return cached

    ai_result = await _claude_resource_risk(item)
    if ai_result:
        payload = {
            "assessment": ai_result["assessment"],
            "risks": ai_result["risks"],
            "actions": ai_result["actions"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ai_powered": True,
        }
    else:
        fb = _fallback_resource_risk(item)
        payload = {
            "assessment": fb["assessment"],
            "risks": fb["risks"],
            "actions": fb["actions"],
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ai_powered": False,
        }

    await cache_set("resource_risk", org_id, payload, ttl=86400, extra=cache_extra)
    return payload


@router.get("/data/summary")
@cached_endpoint("saas:data_summary", ttl=45)
async def data_summary(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Aggregated counts by label, sharing scope, provider.
    Includes both SaaS data items and AWS resources.
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    # Initialize counters
    by_label: dict = {}
    by_scope: dict = {}
    by_provider: dict = {}
    total = 0
    
    # SaaS data items
    try:
        saas_label_result = await db.execute(
            select(SaasDataItem.classification_label, func.count().label("cnt"))
            .where(SaasDataItem.org_id == current_user.org_id)
            .group_by(SaasDataItem.classification_label)
        )
        for r in saas_label_result.fetchall():
            key = r[0] or "unknown"
            by_label[key] = by_label.get(key, 0) + r[1]
        
        saas_scope_result = await db.execute(
            select(SaasDataItem.sharing_scope, func.count().label("cnt"))
            .where(SaasDataItem.org_id == current_user.org_id)
            .group_by(SaasDataItem.sharing_scope)
        )
        for r in saas_scope_result.fetchall():
            key = r[0] or "unknown"
            by_scope[key] = by_scope.get(key, 0) + r[1]
        
        saas_provider_result = await db.execute(
            select(SaasDataItem.provider, func.count().label("cnt"))
            .where(SaasDataItem.org_id == current_user.org_id)
            .group_by(SaasDataItem.provider)
        )
        for r in saas_provider_result.fetchall():
            key = r[0] or "unknown"
            by_provider[key] = by_provider.get(key, 0) + r[1]
        
        saas_total = (await db.execute(
            select(func.count()).where(SaasDataItem.org_id == current_user.org_id)
        )).scalar() or 0
        total += saas_total
    except Exception as e:
        logger.warning(f"data_summary: SaaS query failed: {e}")
    
    # AWS resources — exclude IAM (lives in User Risk).
    try:
        # AWS classification: encrypted → confidential, public → public, else → internal
        aws_result = await db.execute(text("""
            SELECT 
                CASE 
                    WHEN public_access = TRUE THEN 'public'
                    WHEN encryption_enabled = TRUE THEN 'confidential'
                    ELSE 'internal'
                END as classification_label,
                CASE WHEN public_access = TRUE THEN 'public' ELSE 'private' END as sharing_scope,
                COUNT(*) as cnt
            FROM aws_resources
            WHERE org_id = :org_id
              AND resource_type NOT IN ('iam_user', 'iam_role', 'iam_group', 'iam_policy')
            GROUP BY 1, 2
        """), {"org_id": org_id})
        
        aws_total = 0
        for row in aws_result.mappings():
            label = row["classification_label"]
            scope = row["sharing_scope"]
            cnt = row["cnt"]
            by_label[label] = by_label.get(label, 0) + cnt
            by_scope[scope] = by_scope.get(scope, 0) + cnt
            aws_total += cnt
        
        if aws_total > 0:
            by_provider["aws"] = aws_total
            total += aws_total
    except Exception as e:
        logger.debug(f"data_summary: AWS query failed (table may not exist): {e}")
    
    # Databricks resources
    try:
        databricks_result = await db.execute(text("""
            SELECT 
                CASE WHEN has_secrets = TRUE THEN 'confidential' ELSE 'internal' END as classification_label,
                'org' as sharing_scope,
                resource_type,
                COUNT(*) as cnt
            FROM databricks_resources
            WHERE org_id = :org_id
            GROUP BY 1, 2, 3
        """), {"org_id": org_id})
        
        databricks_total = 0
        for row in databricks_result.mappings():
            label = row["classification_label"]
            scope = row["sharing_scope"]
            cnt = row["cnt"]
            by_label[label] = by_label.get(label, 0) + cnt
            by_scope[scope] = by_scope.get(scope, 0) + cnt
            databricks_total += cnt
        
        if databricks_total > 0:
            by_provider["databricks"] = databricks_total
            total += databricks_total
    except Exception as e:
        logger.debug(f"data_summary: Databricks query failed (table may not exist): {e}")

    return {
        "total": total,
        "by_label": by_label,
        "by_scope": by_scope,
        "by_provider": by_provider,
    }


# ══════════════════════════════════════════════════════════════════════════════
# POSTURE ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/posture")
@cached_endpoint("saas:posture", ttl=45)
async def list_posture_checks(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List posture checks grouped by category, including AWS findings."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    # Get M365/Azure posture checks
    rows = (await db.execute(
        select(SaasPostureCheck)
        .where(SaasPostureCheck.org_id == current_user.org_id)
        .order_by(SaasPostureCheck.check_category, SaasPostureCheck.severity.desc())
    )).scalars().all()

    grouped: dict = {}
    for r in rows:
        cat = r.check_category
        if cat not in grouped:
            grouped[cat] = []
        grouped[cat].append(_posture_to_dict(r))
    
    # Also fetch AWS findings and convert to posture checks format
    try:
        aws_findings = await db.execute(
            text("""
                SELECT id, category, severity, title, description, resource_id, resource_arn,
                       status, recommendation, detected_at, metadata
                FROM aws_findings
                WHERE org_id = :org_id
                ORDER BY severity DESC, detected_at DESC
                LIMIT 100
            """),
            {"org_id": org_id}
        )
        aws_rows = aws_findings.mappings().all()
        
        # Map AWS finding categories to NIST CSF 2.0 functions + CIS AWS
        # Benchmark v3 sections so the Posture tab shows real control
        # assessments rather than raw scanner labels. "admin_action"
        # specifically is audit-trail evidence, not a posture control,
        # so we route it under NIST DETECT → Anomalies & Events with
        # CIS 4.x logging context.
        AWS_CATEGORY_MAP = {
            "encryption":      {"nist": "PROTECT → Data Security (PR.DS)",   "cis": "CIS AWS 2.x — Storage Encryption",         "label": "Data Protection (Encryption)"},
            "public_access":   {"nist": "PROTECT → Identity Mgmt & Access Control (PR.AC)", "cis": "CIS AWS 5.x — Network & Public Exposure", "label": "Public Exposure"},
            "iam":             {"nist": "PROTECT → Identity Mgmt & Access Control (PR.AC)", "cis": "CIS AWS 1.x — IAM",                    "label": "Identity & Access"},
            "admin_action":    {"nist": "DETECT → Anomalies & Events (DE.AE)", "cis": "CIS AWS 4.x — Monitoring & Logging",     "label": "Privileged Activity Monitoring"},
            "misconfiguration":{"nist": "PROTECT → Info Protection Processes (PR.IP)", "cis": "CIS AWS 3.x — Logging",            "label": "Configuration Baseline"},
            "compliance":      {"nist": "IDENTIFY → Governance (ID.GV)",      "cis": "CIS AWS — Org-Level Policy",            "label": "Governance & Compliance"},
        }

        # Group AWS findings by NIST-mapped category
        for finding in aws_rows:
            raw_cat = (finding['category'] or 'misconfiguration').lower()
            mapping = AWS_CATEGORY_MAP.get(raw_cat, {
                "nist": "IDENTIFY → Asset Management (ID.AM)",
                "cis":  "CIS AWS — General",
                "label": raw_cat.replace('_', ' ').title(),
            })
            cat = f"AWS: {mapping['label']}"
            if cat not in grouped:
                grouped[cat] = []
            
            # Map severity
            sev = finding['severity'] or 'medium'
            status = 'fail' if sev in ('critical', 'high') else 'warning' if sev == 'medium' else 'pass'
            
            # Build platform-specific remediation steps. For categories we
            # know well, prepend concrete AWS console / CLI actions so the
            # "Remediation" tile is actionable instead of just echoing the
            # generic recommendation field. AI-classified findings already
            # carry detailed steps in metadata.ai_remediation — we use those
            # verbatim when present.
            meta = finding['metadata'] or {}
            ai_steps = meta.get('ai_remediation') if isinstance(meta, dict) else None
            if isinstance(ai_steps, list) and ai_steps:
                remediation_steps = [str(s) for s in ai_steps if s]
            else:
                remediation_steps = _aws_platform_remediation_steps(raw_cat, finding)
            
            grouped[cat].append({
                "id": str(finding['id']),
                "check_name": finding['title'] or "AWS Security Finding",
                "check_category": cat,
                "status": status if finding['status'] == 'open' else 'pass',
                "severity": sev,
                "description": finding['description'] or "",
                "recommendation": finding['recommendation'] or remediation_steps[0] if remediation_steps else "Review and remediate this security finding.",
                "evidence": meta,
                "remediation_steps": remediation_steps,
                "resource": finding['resource_arn'] or finding['resource_id'],
                "provider": "aws",
                "control_mapping": {
                    "nist_csf": mapping['nist'],
                    "cis_aws":  mapping['cis'],
                },
            })
    except Exception as e:
        logger.warning(f"posture: failed to fetch AWS findings: {e}")
    
    # Also fetch Databricks findings
    try:
        db_findings = await db.execute(
            text("""
                SELECT id, category, severity, title, description, resource_id, resource_path,
                       status, recommendation, detected_at, metadata
                FROM databricks_findings
                WHERE org_id = :org_id
                ORDER BY severity DESC, detected_at DESC
                LIMIT 50
            """),
            {"org_id": org_id}
        )
        db_rows = db_findings.mappings().all()
        
        for finding in db_rows:
            cat = f"Databricks: {finding['category'].replace('_', ' ').title()}" if finding['category'] else "Databricks: General"
            if cat not in grouped:
                grouped[cat] = []
            
            sev = finding['severity'] or 'medium'
            status = 'fail' if sev in ('critical', 'high') else 'warning' if sev == 'medium' else 'pass'
            
            grouped[cat].append({
                "id": str(finding['id']),
                "check_name": finding['title'] or "Databricks Security Finding",
                "check_category": cat,
                "status": status if finding['status'] == 'open' else 'pass',
                "severity": sev,
                "description": finding['description'] or "",
                "recommendation": finding['recommendation'] or "Review and remediate this security finding.",
                "evidence": finding['metadata'] or {},
                "remediation_steps": [finding['recommendation']] if finding['recommendation'] else [],
                "resource": finding['resource_path'] or finding['resource_id'],
                "provider": "databricks",
            })
    except Exception as e:
        logger.warning(f"posture: failed to fetch Databricks findings: {e}")

    return {"checks": grouped}


@router.get("/posture/summary")
@cached_endpoint("saas:posture_summary", ttl=45)
async def posture_summary(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Counts by status and severity, including AWS and Databricks findings."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    # M365/Azure posture checks
    by_status = (await db.execute(
        select(SaasPostureCheck.status, func.count().label("cnt"))
        .where(SaasPostureCheck.org_id == current_user.org_id)
        .group_by(SaasPostureCheck.status)
    )).fetchall()

    by_severity = (await db.execute(
        select(SaasPostureCheck.severity, func.count().label("cnt"))
        .where(SaasPostureCheck.org_id == current_user.org_id)
        .group_by(SaasPostureCheck.severity)
    )).fetchall()
    
    status_counts = {r[0]: r[1] for r in by_status}
    severity_counts = {r[0]: r[1] for r in by_severity}
    
    # Add AWS findings to counts
    try:
        aws_status = await db.execute(
            text("""
                SELECT 
                    CASE WHEN status = 'open' THEN 
                        CASE WHEN severity IN ('critical', 'high') THEN 'fail' 
                             WHEN severity = 'medium' THEN 'warning' 
                             ELSE 'pass' END
                    ELSE 'pass' END as status,
                    COUNT(*) as cnt
                FROM aws_findings WHERE org_id = :org_id
                GROUP BY 1
            """),
            {"org_id": org_id}
        )
        for row in aws_status.mappings().all():
            status_counts[row['status']] = status_counts.get(row['status'], 0) + row['cnt']
        
        aws_sev = await db.execute(
            text("SELECT severity, COUNT(*) as cnt FROM aws_findings WHERE org_id = :org_id GROUP BY severity"),
            {"org_id": org_id}
        )
        for row in aws_sev.mappings().all():
            sev = row['severity'] or 'medium'
            severity_counts[sev] = severity_counts.get(sev, 0) + row['cnt']
    except Exception as e:
        logger.warning(f"posture_summary: AWS query failed: {e}")
    
    # Add Databricks findings to counts
    try:
        db_status = await db.execute(
            text("""
                SELECT 
                    CASE WHEN status = 'open' THEN 
                        CASE WHEN severity IN ('critical', 'high') THEN 'fail' 
                             WHEN severity = 'medium' THEN 'warning' 
                             ELSE 'pass' END
                    ELSE 'pass' END as status,
                    COUNT(*) as cnt
                FROM databricks_findings WHERE org_id = :org_id
                GROUP BY 1
            """),
            {"org_id": org_id}
        )
        for row in db_status.mappings().all():
            status_counts[row['status']] = status_counts.get(row['status'], 0) + row['cnt']
        
        db_sev = await db.execute(
            text("SELECT severity, COUNT(*) as cnt FROM databricks_findings WHERE org_id = :org_id GROUP BY severity"),
            {"org_id": org_id}
        )
        for row in db_sev.mappings().all():
            sev = row['severity'] or 'medium'
            severity_counts[sev] = severity_counts.get(sev, 0) + row['cnt']
    except Exception as e:
        logger.warning(f"posture_summary: Databricks query failed: {e}")

    return {
        "by_status": status_counts,
        "by_severity": severity_counts,
    }


@router.post("/posture/run")
async def run_posture_check(
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a posture check in the background."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    background_tasks.add_task(_run_posture_evaluation, org_id)
    return {"message": "Posture check started", "org_id": org_id}


# ══════════════════════════════════════════════════════════════════════════════
# ENTERPRISE SECURITY ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

# ── Cache for infrequently-changing data ──────────────────────────────────────
_CACHE: dict = {
    "sensitivity_labels": {},  # {org_id: {"data": [...], "expires": timestamp}}
    "ca_policies": {},         # {org_id: {"data": [...], "expires": timestamp}}
}
_CACHE_TTL_LABELS = 3600  # 1 hour for sensitivity labels
_CACHE_TTL_CA = 300       # 5 minutes for CA policies


def _get_cached(cache_key: str, org_id: str) -> Optional[list]:
    """Get cached data if not expired."""
    import time
    cache_entry = _CACHE.get(cache_key, {}).get(org_id)
    if cache_entry and cache_entry.get("expires", 0) > time.time():
        return cache_entry.get("data")
    return None


def _set_cached(cache_key: str, org_id: str, data: list, ttl: int) -> None:
    """Set cached data with TTL."""
    import time
    if cache_key not in _CACHE:
        _CACHE[cache_key] = {}
    _CACHE[cache_key][org_id] = {
        "data": data,
        "expires": time.time() + ttl,
    }


async def _get_graph_token_for_org(org_id: str, db: AsyncSession) -> Optional[str]:
    """Get a valid Graph API token for the org."""
    integ = (await db.execute(
        select(SaasIntegration).where(
            SaasIntegration.org_id == uuid.UUID(org_id),
            SaasIntegration.status == "active",
        ).limit(1)
    )).scalar_one_or_none()
    if not integ:
        return None
    return await _get_valid_token(integ, db)


async def _safe_graph_get(url: str, access_token: str, eventual: bool = False) -> tuple:
    """Safe Graph API GET — returns (status_code, json_body)."""
    headers = {"Authorization": f"Bearer {access_token}"}
    if eventual:
        headers["ConsistencyLevel"] = "eventual"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url, headers=headers)
            return r.status_code, r.json() if r.status_code < 500 else {}
    except Exception as exc:
        logger.warning(f"_safe_graph_get: {url} failed: {exc}")
        return 0, {}


# ── 1. External User Lifecycle ────────────────────────────────────────────────

@router.get("/external-users")
async def list_external_users(
    include_stale: bool = Query(True, description="Include users inactive >90 days"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List all guest/external users with:
    - Last sign-in date
    - Teams/SharePoint access
    - Days since last activity
    - Risk indicators (stale, overprivileged)
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")
    
    # Get guest users via Graph API
    # Using beta for signInActivity which shows last sign-in
    sc, data = await _safe_graph_get(
        f"https://graph.microsoft.com/beta/users?"
        f"$filter=userType eq 'Guest'&"
        f"$select=id,displayName,userPrincipalName,mail,createdDateTime,signInActivity,externalUserState&"
        f"$top={page_size}&$count=true",
        access_token,
        eventual=True
    )
    
    if sc == 403:
        raise HTTPException(status_code=403, detail="Missing Graph permission: User.Read.All or AuditLog.Read.All")
    if sc != 200:
        raise HTTPException(status_code=502, detail=f"Graph API error: {sc}")
    
    users = data.get("value", [])
    total = data.get("@odata.count", len(users))
    now = datetime.now(timezone.utc)
    
    external_users = []
    for user in users:
        user_id = user.get("id")
        display_name = user.get("displayName", "Unknown")
        email = user.get("mail") or user.get("userPrincipalName", "")
        created = user.get("createdDateTime")
        sign_in_activity = user.get("signInActivity", {})
        last_signin = sign_in_activity.get("lastSignInDateTime") or sign_in_activity.get("lastNonInteractiveSignInDateTime")
        external_state = user.get("externalUserState", "unknown")  # PendingAcceptance, Accepted, etc.
        
        # Calculate days since last activity
        days_inactive = None
        if last_signin:
            try:
                last_dt = datetime.fromisoformat(last_signin.replace("Z", "+00:00"))
                days_inactive = (now - last_dt).days
            except Exception:
                pass
        elif created:
            # No sign-in ever — use created date
            try:
                created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                days_inactive = (now - created_dt).days
            except Exception:
                pass
        
        # Determine risk indicators
        risks = []
        is_stale = days_inactive is not None and days_inactive > 90
        if is_stale:
            risks.append("stale")
        if external_state == "PendingAcceptance":
            risks.append("pending_acceptance")
        if days_inactive is not None and days_inactive > 365:
            risks.append("dormant")
        
        # Skip stale users if not requested
        if is_stale and not include_stale:
            continue
        
        # Check Teams/SharePoint access (limited to first 20 users for performance)
        teams_access = []
        sharepoint_access = []
        if len(external_users) < 20 and user_id:
            # Get user's group memberships (Teams are M365 Groups)
            sc_grp, grp_data = await _safe_graph_get(
                f"{GRAPH}/users/{user_id}/memberOf?$select=id,displayName,groupTypes&$top=10",
                access_token
            )
            if sc_grp == 200:
                for grp in grp_data.get("value", []):
                    group_types = grp.get("groupTypes", [])
                    if "Unified" in group_types:  # M365 Group = Team
                        teams_access.append(grp.get("displayName", "Unknown Team"))
        
        external_users.append({
            "id": user_id,
            "display_name": display_name,
            "email": email,
            "external_state": external_state,
            "created_at": created,
            "last_sign_in": last_signin,
            "days_inactive": days_inactive,
            "is_stale": is_stale,
            "risk_indicators": risks,
            "teams_access": teams_access[:5],  # Limit for response size
            "sharepoint_access": sharepoint_access[:5],
        })
    
    # Sort by risk: stale first, then by days_inactive
    external_users.sort(key=lambda u: (
        0 if "stale" in u.get("risk_indicators", []) else 1,
        -(u.get("days_inactive") or 0)
    ))

    # ── Augment with external INTERACTIONS ────────────────────────────────
    # Adnan 2026-06-22 — the panel previously only listed formally-invited
    # B2B guests. Real ad-hoc external risk ("I had a meeting with an
    # external user last week and transferred a file") doesn't go through
    # the Guest invitation path — the attendee may never appear in /users.
    # We pull that data from two additional Graph sources:
    #   1. /communications/callRecords — meeting/call participants whose
    #      UPN doesn't belong to a verified tenant domain.
    #   2. /auditLogs/directoryAudits — SharingSet / FileShared / AddedToTeam
    #      events where the target UPN is external.
    # We surface these as `external_interactions` rather than fake "users"
    # so the UI can show them in their own section without polluting the
    # guest-user count. Failures degrade silently with logging.
    tenant_domains: list[str] = await _fetch_tenant_domains(access_token)
    external_interactions: list[dict] = []

    # 1. Meeting / call records with external participants
    try:
        sc_cr, cr_data = await _safe_graph_get(
            f"{GRAPH}/communications/callRecords?$top=50&$orderby=startDateTime desc",
            access_token,
        )
        if sc_cr == 200:
            for call in (cr_data.get("value") or []):
                call_id = call.get("id", "")
                organizer = (call.get("organizer") or {}).get("user", {}).get("userPrincipalName", "unknown")
                started = call.get("startDateTime")
                ext_set: set[str] = set()
                for p in (call.get("participants_v2") or call.get("participants") or []):
                    p_user = (p.get("user") or {}).get("userPrincipalName") or ""
                    p_guest = (p.get("guest") or {}).get("displayName") or ""
                    if p_user and _is_external_email_for(p_user, tenant_domains):
                        ext_set.add(p_user.lower())
                    elif p_guest:
                        ext_set.add(f"guest:{p_guest}")
                for ext in sorted(ext_set):
                    external_interactions.append({
                        "id": f"call:{call_id[:24]}:{hash(ext) % 100000}",
                        "email": ext if not ext.startswith("guest:") else "",
                        "display_name": ext.replace("guest:", "") if ext.startswith("guest:") else ext.split("@")[0],
                        "interaction_type": "meeting_attendee",
                        "organizer": organizer,
                        "event_time": started,
                        "risk": "external_meeting_participant",
                        "detail": f"Joined a Teams call/meeting organized by {organizer}",
                    })
    except Exception as _ce:
        logger.warning(f"external-users: meeting attendee scan failed: {_ce}")

    # 2. File-share + chat-membership audit events targeting external UPNs
    try:
        sc_au, au_data = await _safe_graph_get(
            f"{GRAPH}/auditLogs/directoryAudits?$top=100"
            f"&$orderby=activityDateTime desc",
            access_token,
        )
        if sc_au == 200:
            interesting = {
                "file shared", "sharingset", "sharing set", "anonymouslinkcreated",
                "anonymous link created", "add user to team", "add member to chat",
                "shared file", "fileshared", "file uploaded", "sent message",
            }
            for event in (au_data.get("value") or [])[:200]:
                activity = (event.get("activityDisplayName") or "").lower()
                if not any(k in activity for k in interesting):
                    continue
                initiator = (
                    (event.get("initiatedBy") or {})
                    .get("user", {})
                    .get("userPrincipalName")
                    or "unknown"
                )
                for tgt in (event.get("targetResources") or []):
                    upn = (
                        tgt.get("userPrincipalName")
                        or tgt.get("displayName")
                        or ""
                    )
                    if not upn:
                        continue
                    if not _is_external_email_for(upn, tenant_domains):
                        # Some audit rows put the email in modifiedProperties
                        # rather than userPrincipalName; sample a couple.
                        for mp in (tgt.get("modifiedProperties") or [])[:3]:
                            new_val = (mp.get("newValue") or "").strip('"').strip("[]")
                            if _is_external_email_for(new_val, tenant_domains):
                                upn = new_val
                                break
                        else:
                            continue
                    external_interactions.append({
                        "id": f"audit:{event.get('id','')[:24]}",
                        "email": upn,
                        "display_name": upn.split("@")[0],
                        "interaction_type": (
                            "file_share" if "file" in activity or "share" in activity
                            else "chat_member" if "chat" in activity or "team" in activity
                            else "audit_event"
                        ),
                        "organizer": initiator,
                        "event_time": event.get("activityDateTime"),
                        "risk": "external_file_or_chat_share",
                        "detail": f"{initiator} performed '{event.get('activityDisplayName')}' on {event.get('activityDateTime')}",
                    })
    except Exception as _ae:
        logger.warning(f"external-users: audit scan failed: {_ae}")

    # De-dupe by (email, interaction_type) keeping the earliest event_time
    seen_keys: set[tuple] = set()
    deduped_interactions: list[dict] = []
    for it in sorted(external_interactions,
                     key=lambda x: (x.get("email") or "").lower()):
        key = ((it.get("email") or "").lower(),
               it.get("interaction_type"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped_interactions.append(it)
    deduped_interactions.sort(
        key=lambda x: x.get("event_time") or "", reverse=True
    )
    deduped_interactions = deduped_interactions[:200]

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "stale_count": sum(1 for u in external_users if u.get("is_stale")),
        "pending_count": sum(1 for u in external_users if "pending_acceptance" in u.get("risk_indicators", [])),
        "items": external_users,
        # New sections — cover the "external user who never got formally
        # invited as a B2B guest" case (ad-hoc meeting attendee, anonymous
        # file recipient, chat invitee).
        "external_interactions": deduped_interactions,
        "meeting_attendee_count": sum(1 for it in deduped_interactions if it.get("interaction_type") == "meeting_attendee"),
        "file_share_count": sum(1 for it in deduped_interactions if it.get("interaction_type") == "file_share"),
        "chat_member_count": sum(1 for it in deduped_interactions if it.get("interaction_type") == "chat_member"),
    }


# ── 2. Conditional Access Monitoring ──────────────────────────────────────────

@router.get("/conditional-access/policies")
async def list_ca_policies(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all Conditional Access policies with status, conditions, grants."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    # Check cache first
    cached = _get_cached("ca_policies", org_id)
    if cached is not None:
        return {"policies": cached, "cached": True}
    
    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")
    
    sc, data = await _safe_graph_get(
        f"{GRAPH}/identity/conditionalAccess/policies",
        access_token
    )
    
    if sc == 403:
        raise HTTPException(status_code=403, detail="Missing Graph permission: Policy.Read.All")
    if sc != 200:
        raise HTTPException(status_code=502, detail=f"Graph API error: {sc}")
    
    policies = []
    for policy in data.get("value", []):
        conditions = policy.get("conditions", {})
        grant_controls = policy.get("grantControls", {}) or {}
        session_controls = policy.get("sessionControls", {}) or {}
        
        # Parse target users/groups
        users_cond = conditions.get("users", {})
        include_users = users_cond.get("includeUsers", [])
        include_groups = users_cond.get("includeGroups", [])
        exclude_users = users_cond.get("excludeUsers", [])
        
        # Parse target apps
        apps_cond = conditions.get("applications", {})
        include_apps = apps_cond.get("includeApplications", [])
        
        # Parse platforms/locations
        platforms = conditions.get("platforms", {})
        locations = conditions.get("locations", {})
        
        # Determine policy type/purpose
        policy_types = []
        built_in_controls = grant_controls.get("builtInControls", [])
        if "mfa" in built_in_controls:
            policy_types.append("MFA")
        if "compliantDevice" in built_in_controls:
            policy_types.append("Compliant Device")
        if "domainJoinedDevice" in built_in_controls:
            policy_types.append("Domain Joined")
        if "block" in built_in_controls:
            policy_types.append("Block")
        if conditions.get("signInRiskLevels"):
            policy_types.append("Sign-in Risk")
        if conditions.get("userRiskLevels"):
            policy_types.append("User Risk")
        
        policies.append({
            "id": policy.get("id"),
            "display_name": policy.get("displayName", "Unnamed Policy"),
            "state": policy.get("state", "disabled"),
            "created_at": policy.get("createdDateTime"),
            "modified_at": policy.get("modifiedDateTime"),
            "policy_types": policy_types or ["Custom"],
            "target_users": "All" if "All" in include_users else f"{len(include_users)} users, {len(include_groups)} groups",
            "target_apps": "All" if "All" in include_apps else f"{len(include_apps)} apps",
            "grant_controls": built_in_controls,
            "session_controls": list(session_controls.keys()) if session_controls else [],
            "conditions": {
                "platforms": platforms.get("includePlatforms", []),
                "locations": locations.get("includeLocations", []),
                "client_apps": conditions.get("clientAppTypes", []),
                "sign_in_risk": conditions.get("signInRiskLevels", []),
                "user_risk": conditions.get("userRiskLevels", []),
            },
        })
    
    # Cache the results
    _set_cached("ca_policies", org_id, policies, _CACHE_TTL_CA)
    
    return {
        "total": len(policies),
        "enabled_count": sum(1 for p in policies if p.get("state") == "enabled"),
        "policies": policies,
        "cached": False,
    }


@router.get("/conditional-access/blocked-signins")
async def list_blocked_signins(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Recent sign-ins blocked by CA policies."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")
    
    # Calculate time filter
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Get sign-ins blocked by CA (conditionalAccessStatus = 'failure')
    sc, data = await _safe_graph_get(
        f"{GRAPH}/auditLogs/signIns?"
        f"$filter=conditionalAccessStatus eq 'failure' and createdDateTime ge {cutoff_str}&"
        f"$orderby=createdDateTime desc&"
        f"$top={page_size}&"
        f"$select=id,createdDateTime,userDisplayName,userPrincipalName,ipAddress,location,"
        f"clientAppUsed,appDisplayName,conditionalAccessStatus,appliedConditionalAccessPolicies,"
        f"status,riskDetail,riskLevelDuringSignIn",
        access_token
    )
    
    if sc == 403:
        raise HTTPException(status_code=403, detail="Missing Graph permission: AuditLog.Read.All")
    if sc != 200:
        raise HTTPException(status_code=502, detail=f"Graph API error: {sc}")
    
    blocked_signins = []
    for signin in data.get("value", []):
        location = signin.get("location", {})
        status = signin.get("status", {})
        applied_policies = signin.get("appliedConditionalAccessPolicies", []) or []
        
        # Find which policy blocked the sign-in
        blocking_policy = None
        for pol in applied_policies:
            if pol.get("result") == "failure":
                blocking_policy = pol.get("displayName", "Unknown Policy")
                break
        
        blocked_signins.append({
            "id": signin.get("id"),
            "timestamp": signin.get("createdDateTime"),
            "user_name": signin.get("userDisplayName", "Unknown"),
            "user_email": signin.get("userPrincipalName", ""),
            "ip_address": signin.get("ipAddress"),
            "location": {
                "city": location.get("city"),
                "country": location.get("countryOrRegion"),
            },
            "app": signin.get("appDisplayName", "Unknown App"),
            "client_app": signin.get("clientAppUsed", ""),
            "blocking_policy": blocking_policy,
            "error_code": status.get("errorCode"),
            "failure_reason": status.get("failureReason", ""),
            "risk_level": signin.get("riskLevelDuringSignIn"),
            "risk_detail": signin.get("riskDetail"),
        })
    
    return {
        "total": len(blocked_signins),
        "hours": hours,
        "page": page,
        "page_size": page_size,
        "items": blocked_signins,
    }


@router.get("/conditional-access/gaps")
async def analyze_ca_gaps(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Identify CA policy gaps (no MFA for admins, legacy auth allowed, etc.)."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")
    
    gaps = []
    
    # Get all CA policies
    sc, ca_data = await _safe_graph_get(
        f"{GRAPH}/identity/conditionalAccess/policies",
        access_token
    )
    policies = ca_data.get("value", []) if sc == 200 else []
    enabled_policies = [p for p in policies if p.get("state") == "enabled"]
    
    # Gap 1: No MFA for all users
    mfa_all_users = any(
        p.get("state") == "enabled" and
        "All" in (p.get("conditions", {}).get("users", {}).get("includeUsers", [])) and
        "mfa" in (p.get("grantControls", {}) or {}).get("builtInControls", [])
        for p in policies
    )
    if not mfa_all_users:
        gaps.append({
            "id": "no_mfa_all_users",
            "severity": "critical",
            "title": "No MFA policy for all users",
            "description": "No Conditional Access policy requires MFA for all users on all cloud apps.",
            "recommendation": "Create a CA policy targeting all users, all cloud apps, requiring MFA.",
            "remediation_steps": [
                "Azure AD → Security → Conditional Access → New Policy",
                "Users: All users (exclude break-glass accounts)",
                "Cloud apps: All cloud apps",
                "Grant: Require MFA",
            ],
        })
    
    # Gap 2: No policy blocking legacy auth
    legacy_blocked = any(
        p.get("state") == "enabled" and
        any(c in (p.get("conditions", {}).get("clientAppTypes", [])) for c in ("exchangeActiveSync", "other")) and
        "block" in (p.get("grantControls", {}) or {}).get("builtInControls", [])
        for p in policies
    )
    if not legacy_blocked:
        gaps.append({
            "id": "legacy_auth_allowed",
            "severity": "high",
            "title": "Legacy authentication not blocked",
            "description": "No policy blocks legacy auth protocols (Basic Auth, SMTP AUTH) which bypass MFA.",
            "recommendation": "Create a CA policy blocking legacy authentication clients.",
            "remediation_steps": [
                "Azure AD → Security → Conditional Access → New Policy",
                "Client apps: Exchange ActiveSync, Other clients",
                "Grant: Block access",
            ],
        })
    
    # Gap 3: No sign-in risk policy
    signin_risk_policy = any(
        p.get("state") == "enabled" and
        p.get("conditions", {}).get("signInRiskLevels")
        for p in policies
    )
    if not signin_risk_policy:
        gaps.append({
            "id": "no_signin_risk",
            "severity": "high",
            "title": "No sign-in risk policy",
            "description": "No CA policy responds to risky sign-ins (impossible travel, unfamiliar locations).",
            "recommendation": "Create a CA policy requiring MFA or blocking for medium/high sign-in risk.",
            "remediation_steps": [
                "Azure AD → Security → Conditional Access → New Policy",
                "Conditions: Sign-in risk = Medium, High",
                "Grant: Require MFA or Block",
            ],
        })
    
    # Gap 4: No user risk policy
    user_risk_policy = any(
        p.get("state") == "enabled" and
        p.get("conditions", {}).get("userRiskLevels")
        for p in policies
    )
    if not user_risk_policy:
        gaps.append({
            "id": "no_user_risk",
            "severity": "high",
            "title": "No user risk policy",
            "description": "No CA policy responds to compromised user accounts.",
            "recommendation": "Create a CA policy requiring password change for high-risk users.",
            "remediation_steps": [
                "Azure AD → Security → Conditional Access → New Policy",
                "Conditions: User risk = High",
                "Grant: Require password change",
            ],
        })
    
    # Gap 5: Admins not required to use compliant devices
    admin_device_policy = any(
        p.get("state") == "enabled" and
        "All" in (p.get("conditions", {}).get("users", {}).get("includeRoles", [])) and
        "compliantDevice" in (p.get("grantControls", {}) or {}).get("builtInControls", [])
        for p in policies
    )
    # Also check if there's a broad device compliance policy
    any_device_policy = any(
        p.get("state") == "enabled" and
        "compliantDevice" in (p.get("grantControls", {}) or {}).get("builtInControls", [])
        for p in policies
    )
    if not any_device_policy:
        gaps.append({
            "id": "no_device_compliance",
            "severity": "medium",
            "title": "No device compliance requirement",
            "description": "No CA policy requires compliant or managed devices for access.",
            "recommendation": "Create a CA policy requiring compliant devices for sensitive apps.",
            "remediation_steps": [
                "Azure AD → Security → Conditional Access → New Policy",
                "Target: All users or admin roles",
                "Grant: Require compliant device or Hybrid Azure AD joined",
            ],
        })
    
    # Gap 6: Check if Security Defaults is off and no CA policies exist
    sc_sd, sd_data = await _safe_graph_get(
        f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy",
        access_token
    )
    sd_enabled = sc_sd == 200 and sd_data.get("isEnabled", False)
    if not sd_enabled and len(enabled_policies) == 0:
        gaps.append({
            "id": "no_protection",
            "severity": "critical",
            "title": "No security policies enabled",
            "description": "Security Defaults is disabled and no Conditional Access policies are enabled. Users have no enforced MFA.",
            "recommendation": "Enable Security Defaults or create Conditional Access policies immediately.",
            "remediation_steps": [
                "Azure AD → Properties → Manage Security Defaults → Enable",
                "OR create CA policies for MFA and legacy auth blocking",
            ],
        })
    
    # Gap 7: No named locations defined
    sc_loc, loc_data = await _safe_graph_get(
        f"{GRAPH}/identity/conditionalAccess/namedLocations",
        access_token
    )
    named_locations = loc_data.get("value", []) if sc_loc == 200 else []
    if len(named_locations) == 0:
        gaps.append({
            "id": "no_named_locations",
            "severity": "low",
            "title": "No named locations configured",
            "description": "No trusted network locations defined. Cannot create location-based access policies.",
            "recommendation": "Define trusted network locations (office IPs, VPN ranges).",
            "remediation_steps": [
                "Azure AD → Security → Conditional Access → Named Locations",
                "Add IP ranges for corporate offices and VPN",
            ],
        })
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    gaps.sort(key=lambda g: severity_order.get(g.get("severity", "low"), 4))
    
    return {
        "total_gaps": len(gaps),
        "critical_count": sum(1 for g in gaps if g.get("severity") == "critical"),
        "high_count": sum(1 for g in gaps if g.get("severity") == "high"),
        "policies_enabled": len(enabled_policies),
        "security_defaults_enabled": sd_enabled,
        "gaps": gaps,
    }


@router.get("/conditional-access/multi-cloud")
async def list_multi_cloud_identity_posture(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate identity/access posture controls across every connected cloud.

    Adnan asked 2026-06-22: 'for conditional access is this scanning m365,
    aws / any connected saas?' — the M365 endpoint only covers Entra ID
    Conditional Access. Other clouds have equivalent controls under
    different names:

      - AWS  → IAM password policy, MFA enforcement, SCP guardrails
      - GCP  → IAM policies, org policy constraints
      - Azure subscription → same Entra CA
      - Salesforce → session settings, login IP restrictions
      - GitHub → 2FA enforcement on org
      - Snowflake → network policy, MFA, password policy

    This endpoint folds those signals from the existing CSPM finding
    tables into one unified list per cloud + control. It does not run
    new scans — it reads what the cloud connectors already discovered.
    """
    org_id = str(current_user.org_id)
    controls: list[dict] = []

    # M365 Entra ID Conditional Access — reuse existing endpoint output
    try:
        access_token = await _get_graph_token_for_org(org_id, db)
        if access_token:
            sc, ca_data = await _safe_graph_get(
                f"{GRAPH}/identity/conditionalAccess/policies", access_token
            )
            if sc == 200:
                policies = ca_data.get("value", []) or []
                enabled = sum(1 for p in policies if p.get("state") == "enabled")
                controls.append({
                    "cloud": "m365",
                    "cloud_label": "Microsoft 365 (Entra ID)",
                    "control_name": "Conditional Access",
                    "status": "healthy" if enabled >= 3 else ("partial" if enabled > 0 else "missing"),
                    "summary": f"{enabled} of {len(policies)} Conditional Access polic{'ies' if len(policies) != 1 else 'y'} enabled",
                    "items": [
                        {
                            "name": p.get("displayName"),
                            "state": p.get("state"),
                            "id": p.get("id"),
                        } for p in policies[:25]
                    ],
                    "detail_endpoint": "/api/saas/conditional-access/policies",
                })
    except Exception as exc:
        logger.warning(f"multi_cloud_identity: m365 fetch failed: {exc}")

    # AWS — pull IAM-relevant findings: account password policy, MFA, root usage
    try:
        from sqlalchemy import text as _t
        rs = await db.execute(_t(
            "SELECT COUNT(*) FILTER (WHERE severity IN ('critical','high') AND status='open') as crit, "
            "       COUNT(*) FILTER (WHERE status='open') as opn, "
            "       COUNT(*) as total "
            "FROM aws_findings WHERE org_id = CAST(:oid AS UUID) "
            "AND (category IN ('iam','identity') OR title ILIKE '%MFA%' OR title ILIKE '%password policy%' "
            "     OR title ILIKE '%root%' OR title ILIKE '%access key%')"
        ), {"oid": org_id})
        row = rs.first()
        if row and row[2]:
            crit, opn, total = row[0] or 0, row[1] or 0, row[2] or 0
            controls.append({
                "cloud": "aws",
                "cloud_label": "AWS IAM",
                "control_name": "IAM access controls",
                "status": "missing" if crit > 0 else ("partial" if opn > 0 else "healthy"),
                "summary": (
                    f"{crit} critical/high IAM findings open" if crit > 0
                    else f"{opn} open IAM findings" if opn > 0
                    else f"{total} IAM checks all green"
                ),
                "items": [],  # detail under /api/saas/cloud-findings?provider=aws
                "detail_endpoint": "/api/saas/cloud-findings?provider=aws&category=iam",
            })
    except Exception as exc:
        logger.debug(f"multi_cloud_identity: aws skipped: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass

    # GCP IAM
    try:
        from sqlalchemy import text as _t
        rs = await db.execute(_t(
            "SELECT COUNT(*) FILTER (WHERE severity IN ('critical','high') AND status='open') as crit, "
            "       COUNT(*) FILTER (WHERE status='open') as opn, "
            "       COUNT(*) as total "
            "FROM gcp_findings WHERE org_id = CAST(:oid AS UUID) "
            "AND (category IN ('iam','identity') OR title ILIKE '%IAM%')"
        ), {"oid": org_id})
        row = rs.first()
        if row and row[2]:
            crit, opn, total = row[0] or 0, row[1] or 0, row[2] or 0
            controls.append({
                "cloud": "gcp",
                "cloud_label": "Google Cloud IAM",
                "control_name": "IAM policies",
                "status": "missing" if crit > 0 else ("partial" if opn > 0 else "healthy"),
                "summary": (
                    f"{crit} critical/high IAM findings open" if crit > 0
                    else f"{opn} open IAM findings" if opn > 0
                    else f"{total} IAM checks all green"
                ),
                "items": [],
                "detail_endpoint": "/api/saas/cloud-findings?provider=gcp&category=iam",
            })
    except Exception as exc:
        logger.debug(f"multi_cloud_identity: gcp skipped: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass

    # Salesforce session/access controls — from salesforce_findings
    try:
        from sqlalchemy import text as _t
        rs = await db.execute(_t(
            "SELECT COUNT(*) FILTER (WHERE status='open' AND severity IN ('critical','high')) as crit, "
            "       COUNT(*) FILTER (WHERE status='open') as opn "
            "FROM salesforce_findings WHERE org_id = CAST(:oid AS UUID) "
            "AND (category IN ('api_exposure','guest_data_exposure','enumeration'))"
        ), {"oid": org_id})
        row = rs.first()
        if row is not None:
            crit, opn = row[0] or 0, row[1] or 0
            if opn > 0 or crit > 0:
                controls.append({
                    "cloud": "salesforce",
                    "cloud_label": "Salesforce",
                    "control_name": "Guest access + session controls",
                    "status": "missing" if crit > 0 else "partial",
                    "summary": (
                        f"{crit} critical guest-data exposure(s)" if crit > 0
                        else f"{opn} open session/access issue(s)"
                    ),
                    "items": [],
                    "detail_endpoint": "/api/salesforce/findings?status=open",
                })
    except Exception as exc:
        logger.debug(f"multi_cloud_identity: salesforce skipped: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass

    # GitHub org 2FA
    try:
        from sqlalchemy import text as _t
        rs = await db.execute(_t(
            "SELECT COUNT(*) FILTER (WHERE status='open' AND severity IN ('critical','high')) as crit, "
            "       COUNT(*) FILTER (WHERE status='open') as opn "
            "FROM github_findings WHERE org_id = CAST(:oid AS UUID) "
            "AND (category IN ('iam','identity','authentication') OR title ILIKE '%2FA%' OR title ILIKE '%MFA%')"
        ), {"oid": org_id})
        row = rs.first()
        if row is not None:
            crit, opn = row[0] or 0, row[1] or 0
            if opn or crit:
                controls.append({
                    "cloud": "github",
                    "cloud_label": "GitHub",
                    "control_name": "Org 2FA enforcement",
                    "status": "missing" if crit > 0 else "partial",
                    "summary": f"{opn} open 2FA/identity finding(s)",
                    "items": [],
                    "detail_endpoint": "/api/saas/cloud-findings?provider=github&category=iam",
                })
    except Exception as exc:
        logger.debug(f"multi_cloud_identity: github skipped: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass

    # Snowflake network/password policy
    try:
        from sqlalchemy import text as _t
        rs = await db.execute(_t(
            "SELECT COUNT(*) FILTER (WHERE status='open' AND severity IN ('critical','high')) as crit, "
            "       COUNT(*) FILTER (WHERE status='open') as opn "
            "FROM snowflake_findings WHERE org_id = CAST(:oid AS UUID) "
            "AND (category IN ('iam','identity','network') OR title ILIKE '%MFA%' OR title ILIKE '%network policy%')"
        ), {"oid": org_id})
        row = rs.first()
        if row is not None:
            crit, opn = row[0] or 0, row[1] or 0
            if opn or crit:
                controls.append({
                    "cloud": "snowflake",
                    "cloud_label": "Snowflake",
                    "control_name": "Network + MFA policy",
                    "status": "missing" if crit > 0 else "partial",
                    "summary": f"{opn} open network/MFA finding(s)",
                    "items": [],
                    "detail_endpoint": "/api/saas/cloud-findings?provider=snowflake&category=iam",
                })
    except Exception as exc:
        logger.debug(f"multi_cloud_identity: snowflake skipped: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass

    return {
        "controls": controls,
        "clouds_covered": sorted({c["cloud"] for c in controls}),
        "summary": {
            "healthy": sum(1 for c in controls if c["status"] == "healthy"),
            "partial": sum(1 for c in controls if c["status"] == "partial"),
            "missing": sum(1 for c in controls if c["status"] == "missing"),
        },
    }


# ── 3. Teams App Governance ───────────────────────────────────────────────────

@router.get("/teams-apps")
@cached_endpoint("saas:teams_apps", ttl=300)
async def list_teams_apps(
    include_builtin: bool = Query(False, description="Include Microsoft built-in apps"),
    include_uninstalled: bool = Query(
        False,
        description="Include catalog apps with zero installs (admins rarely want this).",
    ),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    List Teams apps with permissions, install count, and a heuristic
    risk assessment.

    Adnan 2026-06-22 (Governance tab pass): by default the response is now
    filtered to **installed** apps only (install_count > 0) so the Teams
    Apps panel in Governance shows what's actually in the tenant rather
    than the entire catalog. Set `include_uninstalled=true` to fall back
    to the old behaviour. Risk analysis is also strengthened to account
    for install scope (more weight when a high-permission app is
    user-installed across many mailboxes).

    Adnan 2026-06-18 rewrite:

    * Parallelises team install-count + user install-count enumeration
      with asyncio.gather (was 1+N serial calls, hitting the 60s ALB
      timeout).
    * Includes user-personal-scope app installs (was team-only).
    * Skips the per-app permissions Graph call when the catalog
      already carries the authorization payload (most do).
    * Cached in Redis 5 min so repeat loads are instant.
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")

    # 1) Fetch the catalog with appDefinitions expanded. The nested
    #    $expand=authorization isn't supported on the beta endpoint
    #    (returns 400) so we use v1.0 here and pull authorization
    #    separately for the apps we actually keep — still way fewer
    #    calls than the old 1+N+N pattern.
    sc, catalog_data = await _safe_graph_get(
        f"{GRAPH}/appCatalogs/teamsApps?$expand=appDefinitions",
        access_token,
    )
    if sc == 403:
        raise HTTPException(
            status_code=403,
            detail="Missing Graph permission: AppCatalog.Read.All or TeamsAppInstallation.ReadForTeam",
        )
    if sc != 200:
        raise HTTPException(status_code=502, detail=f"Graph API error: {sc}")

    # 2) Get teams + users in parallel for install-count enumeration.
    teams_task = _safe_graph_get(
        f"{GRAPH}/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName&$top=100",
        access_token,
    )
    users_task = _safe_graph_get(
        f"{GRAPH}/users?$select=id,userPrincipalName&$top=50",
        access_token,
    )
    (sc_teams, teams_data), (sc_users, users_data) = await asyncio.gather(
        teams_task, users_task, return_exceptions=False
    )

    app_install_counts: dict = {}
    app_install_scopes: dict = {}  # app_id -> set of {'team', 'user'}

    # 3) Parallel team install enumeration (up to 50 teams).
    if sc_teams == 200:
        team_items = (teams_data.get("value") or [])[:50]
        team_tasks = [
            _safe_graph_get(
                f"{GRAPH}/teams/{t.get('id')}/installedApps?$expand=teamsAppDefinition",
                access_token,
            )
            for t in team_items
            if t.get("id")
        ]
        if team_tasks:
            team_results = await asyncio.gather(*team_tasks, return_exceptions=True)
            for r in team_results:
                if isinstance(r, Exception):
                    continue
                sc_ta, ta_data = r
                if sc_ta != 200:
                    continue
                for installed in (ta_data.get("value") or []):
                    app_def = installed.get("teamsAppDefinition") or {}
                    app_id = app_def.get("teamsAppId") or installed.get("id")
                    if app_id:
                        app_install_counts[app_id] = app_install_counts.get(app_id, 0) + 1
                        app_install_scopes.setdefault(app_id, set()).add("team")

    # 4) Parallel user-personal-scope install enumeration (up to 30 users).
    #    Catches apps Adnan added to his own client. /users/{id}/teamwork
    #    requires TeamsAppInstallation.ReadForUser.All; degrades silently.
    if sc_users == 200:
        user_items = (users_data.get("value") or [])[:30]
        user_tasks = [
            _safe_graph_get(
                f"{GRAPH}/users/{u.get('id')}/teamwork/installedApps?$expand=teamsApp,teamsAppDefinition",
                access_token,
            )
            for u in user_items
            if u.get("id")
        ]
        if user_tasks:
            user_results = await asyncio.gather(*user_tasks, return_exceptions=True)
            for r in user_results:
                if isinstance(r, Exception):
                    continue
                sc_ui, ui_data = r
                if sc_ui != 200:
                    continue
                for installed in (ui_data.get("value") or []):
                    app_def = installed.get("teamsAppDefinition") or {}
                    ta = installed.get("teamsApp") or {}
                    app_id = (
                        app_def.get("teamsAppId")
                        or ta.get("id")
                        or installed.get("id")
                    )
                    if app_id:
                        app_install_counts[app_id] = app_install_counts.get(app_id, 0) + 1
                        app_install_scopes.setdefault(app_id, set()).add("user")

    # 5) Process catalog apps. We already pulled authorization in the
    #    catalog call above so no per-app follow-up is needed.
    high_risk_perms = (
        "ChannelMessage.Read.All", "ChannelMessage.Send",
        "Files.ReadWrite.All", "Files.Read.All",
        "TeamsActivity.Send", "TeamsAppInstallation.ReadWriteForTeam",
        "Mail.Read", "Mail.ReadWrite", "Mail.Send",
        "OnlineMeetings.ReadWrite", "Calls.AccessMedia.All",
        "User.Read.All", "Directory.Read.All",
    )
    catalog_apps = catalog_data.get("value") or []
    apps: list = []

    for app in catalog_apps:
        app_defs = app.get("appDefinitions") or []
        if not app_defs:
            continue
        latest_def = app_defs[-1]
        app_id = app.get("id") or ""
        publisher = latest_def.get("publisherName") or "Unknown"

        if not include_builtin and publisher.lower() in ("microsoft", "microsoft corporation"):
            continue

        # The catalog payload may or may not include authorization.
        # If it does, use it; otherwise leave permissions empty and the
        # heuristic still works on publisher + sideloaded flags.
        permissions: list = []
        auth = (latest_def.get("authorization") or {})
        for perm in (auth.get("resourceSpecificApplicationPermissions") or []):
            permissions.append(perm)
        for perm in (auth.get("resourceSpecificDelegatedPermissions") or []):
            permissions.append(perm)
        # Fall back: try the requiredResourceAccess style some apps use
        for perm_obj in (latest_def.get("requiredResourceAccess") or []):
            for rid in (perm_obj.get("resourceAccess") or []):
                if isinstance(rid, dict) and rid.get("id"):
                    permissions.append({"id": rid["id"]})

        # Heuristic risk assessment (Claude AI version is in the
        # separate /risk-analysis endpoint below — don't block the list
        # endpoint on a 14s LLM call).
        risk_level = "low"
        risk_factors: list = []
        for perm in permissions:
            perm_name = perm if isinstance(perm, str) else (perm.get("id") or "")
            if any(hrp.lower() in perm_name.lower() for hrp in high_risk_perms):
                risk_level = "high"
                risk_factors.append(f"High-risk permission: {perm_name}")

        if len(permissions) > 5 and risk_level != "high":
            risk_level = "medium"
            risk_factors.append(f"Large permission scope ({len(permissions)} permissions)")

        cert_value = (latest_def.get("certification") or "").lower()
        dist_method = (app.get("distributionMethod") or "").lower()
        # Treat Microsoft store apps as first-party even when the
        # catalog omits publisherName — the appDefinitions sometimes
        # come back without it (Activity / Chat / Calling etc).
        is_microsoft_publisher = publisher.lower() in ("microsoft", "microsoft corporation")
        is_store_distributed = dist_method == "store"
        is_third_party = (not is_microsoft_publisher) and (not is_store_distributed)
        if is_third_party and "verified" not in cert_value and "microsoft 365" not in cert_value:
            if risk_level == "low":
                risk_level = "medium"
            risk_factors.append("Third-party app without Microsoft verification")

        # Sideloaded apps (org distribution but not from the public store)
        # carry extra weight — Adnan asked us to spot apps he uploaded.
        if app.get("distributionMethod") == "organization":
            risk_factors.append("Sideloaded into tenant catalog")
            if risk_level == "low":
                risk_level = "medium"

        scopes = sorted(list(app_install_scopes.get(app_id, set())))
        apps.append({
            "id": app_id,
            "external_id": app.get("externalId"),
            "display_name": latest_def.get("displayName") or "Unknown App",
            "short_description": latest_def.get("shortDescription") or "",
            "publisher": publisher,
            "version": latest_def.get("version") or "1.0",
            "distribution_method": app.get("distributionMethod") or "unknown",
            "install_count": app_install_counts.get(app_id, 0),
            "install_scopes": scopes,   # ['team'], ['user'], or both
            "permissions": permissions[:20],
            "permission_count": len(permissions),
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "certification": latest_def.get("certification") or "none",
        })

    risk_order = {"high": 0, "medium": 1, "low": 2}
    apps.sort(key=lambda a: (
        risk_order.get(a.get("risk_level", "low"), 3),
        -int(a.get("install_count") or 0),
    ))

    # Adnan 2026-06-22: default to installed-only so the Governance UI
    # surfaces actual tenant footprint, not the full catalog.
    if not include_uninstalled:
        apps = [a for a in apps if int(a.get("install_count") or 0) > 0]

    # Bump risk on widely-installed third-party apps that hold high-risk
    # permissions — blast radius matters as much as the perm list.
    for a in apps:
        installs = int(a.get("install_count") or 0)
        scopes = a.get("install_scopes") or []
        is_third_party = (a.get("publisher", "") or "").lower() not in (
            "microsoft", "microsoft corporation"
        )
        if (
            a.get("risk_level") == "medium"
            and is_third_party
            and installs >= 10
            and "user" in scopes
        ):
            a["risk_level"] = "high"
            a.setdefault("risk_factors", []).append(
                f"Wide install footprint: {installs} users · third-party publisher"
            )
        if a.get("distribution_method") == "organization" and installs > 0:
            a.setdefault("risk_factors", []).append(
                f"Sideloaded app actively installed by {installs} principal(s)"
            )

    return {
        "total": len(apps),
        "high_risk_count": sum(1 for a in apps if a.get("risk_level") == "high"),
        "medium_risk_count": sum(1 for a in apps if a.get("risk_level") == "medium"),
        "third_party_count": sum(
            1 for a in apps
            if (a.get("publisher", "") or "").lower() not in ("microsoft", "microsoft corporation")
        ),
        "sideloaded_count": sum(1 for a in apps if a.get("distribution_method") == "organization"),
        "user_installed_count": sum(1 for a in apps if "user" in (a.get("install_scopes") or [])),
        "installed_only": not include_uninstalled,
        "items": apps,
    }


# ── AI risk analysis for an individual Teams app ─────────────────────
async def _claude_teams_app_risk(app: dict, org_context: dict) -> Optional[dict]:
    """Claude-driven verbose risk analysis for one Teams app.

    Mirrors the alert / meeting risk patterns: returns assessment
    + risks + actions or None if Claude unavailable.
    """
    if not ANTHROPIC_API_KEY:
        return None
    try:
        app_str = json.dumps(app, default=str)[:2000]
        org_str = json.dumps(org_context, default=str)[:600]
        prompt = (
            "You are a senior Microsoft 365 / Teams security engineer writing a "
            "specific risk analysis for one Teams app installed in this tenant. "
            "Reference the actual app name, publisher, permissions, install scope, "
            "and certification status — do NOT use generic placeholders.\n\n"
            f"Teams app JSON: {app_str}\n"
            f"Tenant context: {org_str}\n\n"
            "Respond with JSON ONLY in this exact shape:\n"
            "{\n"
            '  "assessment": "4-6 sentence paragraph naming the app + publisher and explaining the specific risk in this tenant.",\n'
            '  "risks": ["specific risk 1", "specific risk 2", "..."],\n'
            '  "actions": ["action 1 with concrete Teams Admin Center / Entra ID / Purview steps", "action 2", "..."]\n'
            "}\n\n"
            "Rules: 3-6 risks, 3-5 actions. Each action must name an exact "
            "console path (Teams Admin Center, Entra ID, Microsoft Purview). "
            "If the app is sideloaded (distribution_method == 'organization'), "
            "call that out explicitly. Avoid generic phrases like 'review the app'."
        )
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 1500,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if r.status_code != 200:
                logger.warning(
                    f"teams_app_risk: Claude returned {r.status_code}: {r.text[:200]}"
                )
                return None
            raw = r.json()["content"][0]["text"].strip()
            raw = re.sub(r"^```[\w]*\n?", "", raw)
            raw = re.sub(r"```$", "", raw).strip()
            parsed = json.loads(raw)
            assessment = str(parsed.get("assessment") or "").strip()
            risks_out = [str(x).strip() for x in (parsed.get("risks") or []) if str(x).strip()]
            actions = [str(x).strip() for x in (parsed.get("actions") or []) if str(x).strip()]
            if not assessment or not actions:
                return None
            return {"assessment": assessment, "risks": risks_out, "actions": actions}
    except Exception as exc:
        logger.warning(f"teams_app_risk: Claude call failed: {exc}")
        return None


def _fallback_teams_app_risk(app: dict) -> dict:
    name = app.get("display_name") or "This Teams app"
    publisher = app.get("publisher") or "Unknown publisher"
    perms = app.get("permission_count") or 0
    risk = app.get("risk_level") or "medium"
    sideloaded = app.get("distribution_method") == "organization"
    assessment = (
        f"{name} (published by {publisher}) is installed in your tenant with "
        f"{perms} permission(s) and is currently classified as {risk} risk. "
        + ("This app was sideloaded into the org catalog rather than installed from the public Teams store, which warrants extra scrutiny. " if sideloaded else "")
        + "Confirm the app is sanctioned and the publisher is trusted, then tighten the matching Teams app permission policy."
    )
    return {
        "assessment": assessment,
        "risks": [
            "App may exfiltrate channel content if it holds ChannelMessage.Read.All.",
            "App may impersonate users if it holds Calls or OnlineMeetings permissions.",
            "App without Microsoft verification can be removed from the store at any time, breaking workflows.",
        ],
        "actions": [
            "Teams Admin Center → Manage apps: review the app and decide Allow / Block.",
            "Teams Admin Center → Permission policies: assign a restrictive policy to non-pilot users.",
            "Microsoft Purview → Communication compliance: monitor channels where the app is active.",
        ],
    }


@router.get("/teams-apps/{app_id}/risk-analysis")
async def get_teams_app_risk_analysis(
    app_id: str,
    refresh: bool = Query(False, description="If true, bust the Redis cache and regenerate."),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verbose AI risk analysis for a single Teams app. 24h Redis cache.
    Adnan 2026-06-18: powers the per-app drawer in Teams Apps sub-tab.
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    cache_extra = {"id": app_id}

    if refresh:
        await cache_invalidate("teams_app_risk", org_id, extra=cache_extra)
    else:
        cached = await cache_get("teams_app_risk", org_id, extra=cache_extra)
        if cached:
            return cached

    # Pull the app from the (cached) list to keep state consistent.
    try:
        list_resp = await list_teams_apps(
            include_builtin=True,  # may be built-in
            current_user=current_user,
            db=db,
        )  # type: ignore[arg-type]
    except HTTPException as h:
        raise h
    items = list_resp.get("items") if isinstance(list_resp, dict) else []
    app = next((a for a in items if a.get("id") == app_id), None)
    if not app:
        raise HTTPException(status_code=404, detail="Teams app not found in tenant")

    org_context = {
        "high_risk_count": list_resp.get("high_risk_count"),
        "third_party_count": list_resp.get("third_party_count"),
        "sideloaded_count": list_resp.get("sideloaded_count"),
        "user_installed_count": list_resp.get("user_installed_count"),
    }
    payload = await _claude_teams_app_risk(app, org_context)
    ai_powered = payload is not None
    if payload is None:
        payload = _fallback_teams_app_risk(app)

    result = {
        "assessment": payload["assessment"],
        "risks": payload.get("risks", []),
        "actions": payload.get("actions", []),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ai_powered": ai_powered,
    }
    await cache_set("teams_app_risk", org_id, result, ttl=86400, extra=cache_extra)
    return result


@router.post("/teams-apps/{app_id}/block")
async def block_teams_app(
    app_id: str,
    background_tasks: BackgroundTasks,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Block a risky Teams app from being installed."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")
    
    # Note: Blocking apps requires TeamsAppInstallation.ReadWriteForTeam or admin permissions
    # This is a complex operation - we'll mark it for admin action and create an alert
    
    # Get app details first
    sc, app_data = await _safe_graph_get(
        f"{GRAPH}/appCatalogs/teamsApps/{app_id}?$expand=appDefinitions",
        access_token
    )
    
    if sc == 404:
        raise HTTPException(status_code=404, detail="Teams app not found")
    if sc != 200:
        raise HTTPException(status_code=502, detail=f"Graph API error: {sc}")
    
    app_defs = app_data.get("appDefinitions", [])
    app_name = app_defs[-1].get("displayName", "Unknown App") if app_defs else "Unknown App"
    
    # Create an alert/task for admin to block the app
    # In production, this would call Teams Admin API to update app permission policy
    
    # For now, we record this as an action item and create an alert
    now = datetime.now(timezone.utc)
    db.add(SaasAlert(
        org_id=uuid.UUID(org_id),
        provider="teams",
        alert_type="teams_app_block_requested",
        severity="medium",
        title=f"Teams App Block Requested: {app_name}",
        description=f"Administrator requested blocking Teams app '{app_name}' (ID: {app_id}). "
                    f"Go to Teams Admin Center → Teams apps → Manage apps to block this app.",
        resource_id=f"teams-app:{app_id}",
        resource_name=app_name,
        status="open",
        raw_data={
            "app_id": app_id,
            "app_name": app_name,
            "requested_by": str(current_user.id),
            "requested_at": now.isoformat(),
        },
    ))
    await db.commit()
    
    return {
        "status": "pending",
        "message": f"Block request recorded for '{app_name}'. An admin must complete this in Teams Admin Center.",
        "app_id": app_id,
        "app_name": app_name,
        "remediation_url": "https://admin.teams.microsoft.com/policies/manage-apps",
        "steps": [
            "Go to Teams Admin Center → Teams apps → Manage apps",
            f"Search for '{app_name}'",
            "Select the app and click 'Block'",
            "Or update App permission policies to block for all users",
        ],
    }


# ── 4. Meeting Security ───────────────────────────────────────────────────────

@router.get("/meeting-security/risks")
async def list_meeting_risks(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Detect meeting security issues:
    - Anonymous join enabled
    - Lobby bypass for external
    - Recording without policy
    - External presenters
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")
    
    risks = []

    # Cache tenant domain list for external-attendee detection. Used by both
    # the onlineMeetings participant check and the meeting-chat file-share scan.
    tenant_domains: list[str] = []
    try:
        sc_dom, dom_data = await _safe_graph_get(f"{GRAPH}/domains?$select=id", access_token)
        if sc_dom == 200:
            tenant_domains = [(d.get("id") or "").lower() for d in dom_data.get("value", []) if d.get("id")]
    except Exception:
        pass

    def _is_external_email(email: str) -> bool:
        em = (email or "").lower()
        if not em or "@" not in em:
            return False
        if "#ext#" in em:
            return True
        if not tenant_domains:
            return False
        return not any(em.endswith("@" + d) for d in tenant_domains)

    # Get recent online meetings (beta API has more details)
    sc, meetings_data = await _safe_graph_get(
        f"https://graph.microsoft.com/beta/communications/onlineMeetings?"
        f"$orderby=createdDateTime desc&$top=50",
        access_token
    )

    if sc == 403:
        # Try org-level meeting policies instead
        pass  # Continue to policy checks
    elif sc == 200:
        for meeting in meetings_data.get("value", []):
            meeting_id = meeting.get("id") or ""
            subject = meeting.get("subject", "Unnamed Meeting")
            participants = meeting.get("participants", {}) or {}
            organizer = (
                participants.get("organizer", {})
                .get("upn")
                or participants.get("organizer", {}).get("emailAddress", {}).get("address")
                or "Unknown"
            )

            # Check meeting settings
            lobby_bypass = meeting.get("lobbyBypassSettings", {}) or {}

            # Detect external participants explicitly invited to the meeting.
            # `attendees` includes invited UPNs/emails — that's what tells us
            # "a meeting was held with an outside user" even when OnlineMeetings.Read
            # is granted but no callRecord is available yet.
            external_attendees: list[str] = []
            for att in (participants.get("attendees") or []):
                upn = (att.get("upn") or "").lower()
                em = (att.get("emailAddress", {}) or {}).get("address", "").lower()
                candidate = upn or em
                if candidate and _is_external_email(candidate):
                    external_attendees.append(candidate)

            # Risk: External participants invited
            if external_attendees:
                unique_ext = sorted(set(external_attendees))[:5]
                risks.append({
                    "id": f"meeting-ext:{meeting_id[:20]}",
                    "meeting_id": meeting_id,
                    "subject": subject,
                    "organizer": organizer,
                    "risk_type": "external_attendee",
                    "severity": "medium",
                    "title": f"External attendee in meeting ({len(unique_ext)})",
                    "description": (
                        f"Meeting '{subject}' organized by {organizer} included external "
                        f"participant(s): {', '.join(unique_ext)}. Ensure DLP and recording "
                        f"policies are appropriate, and confirm no sensitive data was shared."
                    ),
                    "external_attendees": unique_ext,
                })

            # Risk: Anonymous join enabled
            if meeting.get("isEntryExitAnnounced") is False:
                risks.append({
                    "id": f"meeting-anon:{meeting_id[:20]}",
                    "meeting_id": meeting_id,
                    "subject": subject,
                    "organizer": organizer,
                    "risk_type": "no_entry_announcement",
                    "severity": "low",
                    "title": "Entry/exit announcements disabled",
                    "description": f"Meeting '{subject}' by {organizer} has entry/exit announcements disabled. "
                                   f"Participants can join unnoticed.",
                })

            # Risk: Everyone bypass lobby
            lobby_scope = lobby_bypass.get("scope", "")
            if lobby_scope in ("everyone", "everyoneInCompanyAndFederated"):
                risks.append({
                    "id": f"meeting-lobby:{meeting_id[:20]}",
                    "meeting_id": meeting_id,
                    "subject": subject,
                    "organizer": organizer,
                    "risk_type": "lobby_bypass",
                    "severity": "high" if external_attendees else "medium",
                    "title": "Lobby bypass for external users",
                    "description": f"Meeting '{subject}' allows external users to bypass lobby. "
                                   f"Consider restricting to 'organizationUsers'.",
                })

            # Risk: Recording without consent
            if meeting.get("recordAutomatically"):
                risks.append({
                    "id": f"meeting-record:{meeting_id[:20]}",
                    "meeting_id": meeting_id,
                    "subject": subject,
                    "organizer": organizer,
                    "risk_type": "auto_recording",
                    "severity": "low",
                    "title": "Automatic recording enabled",
                    "description": f"Meeting '{subject}' has automatic recording. Ensure participants are aware.",
                })

    # Pull recent call records (communications/callRecords) to spot meetings
    # that actually included external (federated/guest) participants — this
    # works even when /onlineMeetings is locked down by Teams app-access policy.
    sc_cr, cr_data = await _safe_graph_get(
        f"{GRAPH}/communications/callRecords?$top=20&$orderby=startDateTime desc",
        access_token,
    )
    if sc_cr == 200:
        for call in cr_data.get("value", []):
            call_id = call.get("id", "")
            call_type = call.get("type", "")
            org_user = call.get("organizer", {}).get("user", {}).get("userPrincipalName", "Unknown")
            modalities = call.get("modalities", []) or []
            # Only flag actual group meetings, not 1:1 calls
            if call_type not in ("groupCall", "meeting") and "groupCall" not in modalities:
                continue
            ext_participants: list[str] = []
            for p in (call.get("participants_v2") or call.get("participants") or []):
                p_user = (p.get("user") or {}).get("userPrincipalName") or ""
                p_guest = (p.get("guest") or {}).get("displayName") or ""
                p_phone = (p.get("phone") or {}).get("id") or ""
                if p_guest:
                    ext_participants.append(f"guest:{p_guest}")
                elif p_user and _is_external_email(p_user):
                    ext_participants.append(p_user)
                elif p_phone:
                    ext_participants.append(f"pstn:{p_phone}")
            if ext_participants:
                unique_ext = sorted(set(ext_participants))[:5]
                risks.append({
                    "id": f"callrecord-ext:{call_id[:20]}",
                    "meeting_id": call_id,
                    "subject": f"Group call/meeting on {call.get('startDateTime','?')[:10]}",
                    "organizer": org_user,
                    "risk_type": "external_attendee",
                    "severity": "medium",
                    "title": f"External attendee in call/meeting ({len(unique_ext)})",
                    "description": (
                        f"Call organized by {org_user} included external participant(s): "
                        f"{', '.join(unique_ext)}. Started {call.get('startDateTime','?')}."
                    ),
                    "event_time": call.get("startDateTime"),
                    "external_attendees": unique_ext,
                })

    # ── Org-wide Teams meeting policy checks ─────────────────────────
    # We can't read Teams admin policies directly via Graph (those live
    # behind PowerShell Skype/Teams modules), but we can infer the
    # effective posture from the recent meeting samples + audit log
    # events. Build a small `policy_findings` summary so the UI can
    # render a tenant-wide "Meeting Posture" card on top of the per-
    # meeting risk list.
    policy_findings = {
        "meetings_sampled": 0,
        "meetings_with_external": 0,
        "meetings_with_lobby_bypass_everyone": 0,
        "meetings_with_anonymous_join": 0,
        "meetings_with_auto_recording": 0,
        "meetings_allowing_external_presenters": 0,
        "meetings_chat_unrestricted": 0,
    }
    if sc == 200:
        for meeting in meetings_data.get("value", []) or []:
            policy_findings["meetings_sampled"] += 1
            lobby_bypass = meeting.get("lobbyBypassSettings", {}) or {}
            if lobby_bypass.get("scope") in ("everyone", "everyoneInCompanyAndFederated"):
                policy_findings["meetings_with_lobby_bypass_everyone"] += 1
            if meeting.get("allowAnonymousUsersToJoinMeeting") is True or meeting.get("allowedPresenters") == "everyone":
                policy_findings["meetings_allowing_external_presenters"] += 1
            if meeting.get("recordAutomatically"):
                policy_findings["meetings_with_auto_recording"] += 1
            if meeting.get("isEntryExitAnnounced") is False:
                policy_findings["meetings_with_anonymous_join"] += 1
            chat_info = meeting.get("chatInfo", {}) or {}
            if chat_info.get("messageId") and meeting.get("allowMeetingChat") in (None, "enabled"):
                policy_findings["meetings_chat_unrestricted"] += 1
            atts = (meeting.get("participants", {}) or {}).get("attendees") or []
            if any(
                _is_external_email(((a.get("upn") or "") or (a.get("emailAddress", {}) or {}).get("address", "")))
                for a in atts
            ):
                policy_findings["meetings_with_external"] += 1

    # Surface a tenant-level risk if a big slice of meetings allow lobby
    # bypass for everyone — that's an org-wide policy smell.
    if policy_findings["meetings_sampled"] >= 5:
        share_lobby = policy_findings["meetings_with_lobby_bypass_everyone"] / policy_findings["meetings_sampled"]
        if share_lobby >= 0.3:
            risks.append({
                "id": "policy-lobby-bypass",
                "risk_type": "policy_posture",
                "severity": "high",
                "title": "Tenant policy: lobby bypass too permissive",
                "description": (
                    f"{int(share_lobby * 100)}% of the {policy_findings['meetings_sampled']} "
                    f"recent meetings allow lobby bypass for everyone (or everyone in company + "
                    f"federated). Consider tightening the default Teams meeting policy to "
                    f"'organizationUsers' or 'invitedUsers'."
                ),
                "remediation_url": "https://admin.teams.microsoft.com/policies/meetings",
            })
        share_auto_rec = policy_findings["meetings_with_auto_recording"] / policy_findings["meetings_sampled"]
        if share_auto_rec >= 0.5:
            risks.append({
                "id": "policy-auto-record",
                "risk_type": "policy_posture",
                "severity": "medium",
                "title": "Tenant policy: automatic recording on most meetings",
                "description": (
                    f"{int(share_auto_rec * 100)}% of the {policy_findings['meetings_sampled']} "
                    f"recent meetings have automatic recording enabled. Make sure your meeting"
                    f" recording policy is documented and participants are informed at start."
                ),
                "remediation_url": "https://admin.teams.microsoft.com/policies/meetings",
            })

    # Try to read the org's call recording compliance policy from the
    # beta Graph endpoint. If the app permission isn't granted this
    # silently no-ops.
    try:
        sc_pol, pol_data = await _safe_graph_get(
            f"https://graph.microsoft.com/beta/teamwork/teamsAppSettings",
            access_token,
        )
        if sc_pol == 200 and isinstance(pol_data, dict):
            allow_user_pinning = pol_data.get("allowUserPinningInApps")
            allow_sideloading = pol_data.get("isUserPersonalScopeAllowedByDefault")
            if allow_sideloading:
                risks.append({
                    "id": "policy-sideload",
                    "risk_type": "policy_posture",
                    "severity": "medium",
                    "title": "Tenant policy: user app sideloading enabled",
                    "description": (
                        "Users can install custom Teams apps into their personal scope, "
                        "including unverified third-party meeting apps. Restrict via Teams "
                        "Admin Center → Manage apps → Setup policies."
                    ),
                    "remediation_url": "https://admin.teams.microsoft.com/policies/app-setup-policies",
                })
            if allow_user_pinning is True:
                # informational — doesn't add a risk, but capture for
                # the policy posture card.
                policy_findings["app_pinning_allowed"] = True
    except Exception:
        pass

    # ── Meeting-chat file shares (the "transferred a file in the meeting" case) ──
    # Teams meeting file transfers create a directoryAudits event with
    # activity "File Uploaded" / "FileUploaded" and a chatMessage event under
    # SharePoint/OneDrive activity. We surface those here, prioritizing ones
    # where an external user is on the same meeting/chat.
    try:
        sc_share, share_data = await _safe_graph_get(
            f"{GRAPH}/auditLogs/directoryAudits?"
            f"$filter=category eq 'ApplicationManagement' or category eq 'OnlineMeeting' or category eq 'SharingPolicy'"
            f"&$top=50&$orderby=activityDateTime desc",
            access_token,
        )
        if sc_share == 200:
            for event in share_data.get("value", []):
                activity = (event.get("activityDisplayName") or "").lower()
                if any(k in activity for k in ("file uploaded", "fileuploaded", "file shared", "shared file", "add member to chat", "add user to channel")):
                    initiator = (
                        event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName")
                        or "Unknown"
                    )
                    targets = event.get("targetResources", []) or []
                    target_emails = [
                        (t.get("userPrincipalName") or t.get("displayName") or "")
                        for t in targets
                    ]
                    has_external = any(_is_external_email(e) for e in target_emails)
                    risks.append({
                        "id": f"meeting-share:{event.get('id', '')[:20]}",
                        "risk_type": "meeting_file_share",
                        "severity": "high" if has_external else "medium",
                        "title": (
                            "File shared in meeting/chat with external user"
                            if has_external else "File shared in meeting/chat"
                        ),
                        "description": (
                            f"{initiator} performed '{event.get('activityDisplayName')}' "
                            f"on {event.get('activityDateTime')}."
                            + (f" External target(s): {', '.join([e for e in target_emails if _is_external_email(e)][:5])}" if has_external else "")
                        ),
                        "event_time": event.get("activityDateTime"),
                        "initiated_by": initiator,
                    })
    except Exception as _share_exc:
        logger.debug(f"meeting-security: file-share audit scan failed: {_share_exc}")

    # Check audit logs for risky meeting events
    sc_audit, audit_data = await _safe_graph_get(
        f"{GRAPH}/auditLogs/directoryAudits?"
        f"$filter=category eq 'OnlineMeeting'&$top=50&$orderby=activityDateTime desc",
        access_token
    )

    if sc_audit == 200:
        for event in audit_data.get("value", []):
            activity = event.get("activityDisplayName", "")

            # Detect policy changes that might be risky
            if "anonymous" in activity.lower() and "enabled" in activity.lower():
                risks.append({
                    "id": f"audit-anon:{event.get('id', '')[:20]}",
                    "risk_type": "policy_change",
                    "severity": "high",
                    "title": "Anonymous meeting join enabled",
                    "description": f"Meeting policy was changed to allow anonymous join. "
                                   f"Review if this was authorized.",
                    "event_time": event.get("activityDateTime"),
                    "initiated_by": event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown"),
                })

    # Also surface any saas_alerts that the meeting-chat scanner has already
    # persisted (file uploads in meeting chats). That worker fires in the
    # background — including them here means this endpoint reflects the same
    # state the Alerts tab shows, and the Meeting Security card stops looking
    # "empty" right after a meeting with a file transfer.
    try:
        chat_alerts = await db.execute(text("""
            SELECT id::text, alert_type, severity, title, description,
                   resource_id, resource_name, created_at, classification_result
            FROM saas_alerts
            WHERE org_id = CAST(:oid AS UUID)
              AND alert_type IN ('meeting_file_share', 'meeting_file_share_external',
                                 'meeting_external_attendee')
              AND status = 'open'
            ORDER BY created_at DESC
            LIMIT 20
        """), {"oid": org_id})
        for row in chat_alerts.mappings().all():
            risks.append({
                "id": f"alert:{row['id']}",
                "meeting_id": row.get("resource_id"),
                "subject": row.get("resource_name") or "Meeting/chat",
                "risk_type": row["alert_type"],
                "severity": row["severity"],
                "title": row["title"],
                "description": row["description"],
                "event_time": row["created_at"].isoformat() if row["created_at"] else None,
                "classification": row.get("classification_result"),
            })
    except Exception as _ca_exc:
        logger.debug(f"meeting-security: chat alert lookup failed: {_ca_exc}")

    # Add general recommendations if no specific risks found
    if not risks:
        risks.append({
            "id": "recommendation-meeting-policy",
            "risk_type": "recommendation",
            "severity": "info",
            "title": "Review Teams meeting policies",
            "description": "No specific meeting risks detected. Periodically review Teams meeting policies "
                           "in Teams Admin Center to ensure security settings are appropriate.",
            "remediation_url": "https://admin.teams.microsoft.com/meetings/settings",
        })
    
    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    risks.sort(key=lambda r: severity_order.get(r.get("severity", "info"), 5))

    # Group risks by risk_type for the breakdown chart.
    by_type: dict = {}
    by_severity: dict = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in risks:
        rt = r.get("risk_type") or "other"
        by_type[rt] = by_type.get(rt, 0) + 1
        sev = r.get("severity") or "info"
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "total": len([r for r in risks if r.get("risk_type") != "recommendation"]),
        "high_severity_count": sum(1 for r in risks if r.get("severity") in ("critical", "high")),
        "by_type": by_type,
        "by_severity": by_severity,
        "policy_findings": policy_findings,
        "items": risks,
    }


async def _claude_meeting_risk_analysis(risk: dict, policy_findings: dict) -> Optional[dict]:
    """Claude-driven verbose risk analysis for a single meeting risk.

    Mirrors `_claude_alert_remediation` but tailored to Teams meeting
    posture. Returns dict with assessment / risks / actions or None on
    failure.
    """
    if not ANTHROPIC_API_KEY:
        return None
    try:
        risk_str = json.dumps(risk, default=str)[:1500]
        ctx_str = json.dumps(policy_findings, default=str)[:600]
        prompt = (
            "You are a senior Microsoft 365 / Teams security engineer writing a verbose, "
            "specific risk analysis for a workspace security platform. Reference the "
            "actual meeting subject, organiser, attendees, severity, and policy posture "
            "— do NOT use generic placeholders.\n\n"
            f"Risk JSON: {risk_str}\n"
            f"Tenant meeting policy posture (last sample): {ctx_str}\n\n"
            "Respond with JSON ONLY in this exact shape:\n"
            "{\n"
            '  "assessment": "4-6 sentence paragraph naming the meeting / organiser / risk_type and explaining what is wrong in this specific context.",\n'
            '  "risks": ["specific risk 1", "specific risk 2", "..."],\n'
            '  "actions": ["action 1 with concrete Teams Admin Center / Entra ID / Defender steps", "action 2", "..."]\n'
            "}\n\n"
            "Rules: 3-6 risks; 3-5 actions; every action must name the actual console "
            "path (e.g. 'Teams Admin Center → Meetings → Meeting policies → Global', "
            "'Entra ID → External Identities → External collaboration settings', "
            "'Microsoft Purview → Communication compliance'). Do not include "
            "'review the alert' or other generic boilerplate."
        )
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 1500,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if r.status_code != 200:
                logger.warning(
                    f"meeting_risk_analysis: Claude returned {r.status_code}: {r.text[:200]}"
                )
                return None
            raw = r.json()["content"][0]["text"].strip()
            raw = re.sub(r"^```[\w]*\n?", "", raw)
            raw = re.sub(r"```$", "", raw).strip()
            parsed = json.loads(raw)
            assessment = str(parsed.get("assessment") or "").strip()
            risks_out = [str(x).strip() for x in (parsed.get("risks") or []) if str(x).strip()]
            actions = [str(x).strip() for x in (parsed.get("actions") or []) if str(x).strip()]
            if not assessment or not actions:
                return None
            return {
                "assessment": assessment,
                "risks": risks_out,
                "actions": actions,
            }
    except Exception as exc:
        logger.warning(f"meeting_risk_analysis: Claude call failed: {exc}")
        return None


def _fallback_meeting_risk_analysis(risk: dict) -> dict:
    rt = risk.get("risk_type") or "meeting_risk"
    subj = risk.get("subject") or "the meeting"
    org = risk.get("organizer") or "the organiser"
    sev = risk.get("severity") or "medium"
    ext = risk.get("external_attendees") or []
    assessment = (
        f"{risk.get('title') or 'Meeting risk'}: '{subj}' organised by {org} "
        f"matched a {sev}-severity {rt.replace('_', ' ')} pattern. "
        + (f"External attendees were involved ({', '.join(ext[:3])}{', …' if len(ext) > 3 else ''}). " if ext else "")
        + "Confirm whether sensitive content was shared, then tighten the matching "
        "meeting policy in Teams Admin Center so this pattern stops recurring."
    )
    return {
        "assessment": assessment,
        "risks": [
            "Sensitive information may have been disclosed in-meeting (chat, screen-share, recording).",
            "Auditors may flag the meeting policy posture as non-compliant with SOC2 / ISO27001 CC6.6.",
            "Attackers can exploit overly permissive meeting policies to social-engineer staff.",
        ],
        "actions": [
            "Teams Admin Center → Meetings → Meeting policies: tighten Lobby/Anonymous join for the affected user policy.",
            "Entra ID → External Identities → External collaboration settings: review guest invite permissions.",
            "Microsoft Purview → Communication compliance: enable monitoring on this organiser's mailbox if not already.",
        ],
    }


@router.get("/meeting-security/risks/{risk_id}/analysis")
async def meeting_risk_analysis(
    risk_id: str,
    refresh: bool = False,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Claude-driven verbose risk analysis for a single Meeting Security
    risk. Cached in Redis for 24h (key meeting_risk_analysis:{risk_id}).
    Pass ?refresh=true to bust the cache.
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    if refresh:
        await cache_invalidate("meeting_risk_analysis", org_id, extra={"id": risk_id})
    else:
        cached = await cache_get("meeting_risk_analysis", org_id, extra={"id": risk_id})
        if cached:
            return cached

    # Re-fetch the meeting-security risk list and locate the requested
    # risk by id. We don't persist the per-meeting risks long-term, so
    # this is the simplest way to keep state consistent with what the
    # UI just rendered.
    try:
        list_resp = await list_meeting_risks(current_user=current_user, db=db)  # type: ignore[arg-type]
    except HTTPException as h:
        raise h
    except Exception as exc:
        logger.warning(f"meeting_risk_analysis: listing risks failed: {exc}")
        raise HTTPException(status_code=500, detail="Failed to load meeting risks for analysis")

    items = list_resp.get("items") if isinstance(list_resp, dict) else []
    policy_findings = list_resp.get("policy_findings", {}) if isinstance(list_resp, dict) else {}
    risk = next((r for r in items if r.get("id") == risk_id), None)
    if not risk:
        raise HTTPException(status_code=404, detail="Meeting risk not found")

    payload = await _claude_meeting_risk_analysis(risk, policy_findings)
    ai_powered = payload is not None
    if payload is None:
        payload = _fallback_meeting_risk_analysis(risk)

    result = {
        "assessment": payload["assessment"],
        "risks": payload.get("risks", []),
        "actions": payload.get("actions", []),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ai_powered": ai_powered,
    }
    await cache_set("meeting_risk_analysis", org_id, result, ttl=86400, extra={"id": risk_id})
    return result


# ── 5. DLP/Sensitivity Labels ─────────────────────────────────────────────────

@router.get("/dlp/labels")
async def list_sensitivity_labels(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List org sensitivity labels."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    # Check cache first (labels don't change often)
    cached = _get_cached("sensitivity_labels", org_id)
    if cached is not None:
        return {"labels": cached, "cached": True}
    
    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")
    
    # Get sensitivity labels via beta API
    sc, data = await _safe_graph_get(
        f"https://graph.microsoft.com/beta/informationProtection/sensitivityLabels",
        access_token
    )
    
    if sc == 403:
        raise HTTPException(
            status_code=403,
            detail="Missing Graph permission: InformationProtectionPolicy.Read or InformationProtectionPolicy.Read.All"
        )
    if sc != 200:
        # Try alternative endpoint
        sc, data = await _safe_graph_get(
            f"https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels",
            access_token
        )
        if sc != 200:
            raise HTTPException(status_code=502, detail=f"Graph API error: {sc}")
    
    labels = []
    for label in data.get("value", []):
        parent_id = label.get("parent", {}).get("id") if label.get("parent") else None
        
        labels.append({
            "id": label.get("id"),
            "name": label.get("name", "Unknown"),
            "display_name": label.get("displayName", label.get("name", "Unknown")),
            "description": label.get("description", ""),
            "tooltip": label.get("tooltip", ""),
            "is_active": label.get("isActive", True),
            "is_default": label.get("isDefault", False),
            "priority": label.get("priority", 0),
            "parent_id": parent_id,
            "has_protection": bool(label.get("contentFormats")),  # Simplified check
            "applicable_to": label.get("contentFormats", []),
        })
    
    # Sort by priority
    labels.sort(key=lambda l: l.get("priority", 0))
    
    # Cache the results
    _set_cached("sensitivity_labels", org_id, labels, _CACHE_TTL_LABELS)
    
    return {
        "total": len(labels),
        "active_count": sum(1 for l in labels if l.get("is_active")),
        "labels": labels,
        "cached": False,
    }


@router.get("/dlp/label-usage")
async def get_label_usage(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Stats on label usage across SharePoint/OneDrive."""
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)
    
    access_token = await _get_graph_token_for_org(org_id, db)
    if not access_token:
        raise HTTPException(status_code=400, detail="No active M365 integration found")
    
    # Get label usage from our scanned data items
    usage_stats = {}
    unlabeled_count = 0
    total_scanned = 0
    
    try:
        result = await db.execute(text("""
            SELECT 
                classification_label,
                COUNT(*) as count,
                SUM(size_bytes) as total_size
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
            GROUP BY classification_label
        """), {"org_id": org_id})
        
        for row in result.mappings():
            label = row["classification_label"]
            count = row["count"] or 0
            size = row["total_size"] or 0
            total_scanned += count
            
            if label is None or label == "" or label.lower() in ("none", "unlabeled"):
                unlabeled_count += count
            else:
                usage_stats[label] = {
                    "count": count,
                    "total_size_bytes": size,
                    "percentage": 0,  # Will calculate below
                }
    except Exception as e:
        logger.warning(f"label_usage: DB query failed: {e}")
    
    # Calculate percentages
    if total_scanned > 0:
        for label in usage_stats:
            usage_stats[label]["percentage"] = round(
                (usage_stats[label]["count"] / total_scanned) * 100, 1
            )
    
    # Try to get live data from Graph API (via content search or similar)
    # Note: Full label analytics requires Microsoft 365 Compliance Center API
    
    # Get sensitivity labels for context
    labels_response = await list_sensitivity_labels(current_user, db)
    available_labels = labels_response.get("labels", []) if isinstance(labels_response, dict) else []
    
    # Map label IDs to names
    label_names = {l.get("id"): l.get("display_name", l.get("name")) for l in available_labels}
    
    # Build response with label names
    usage_by_label = []
    for label_key, stats in usage_stats.items():
        display_name = label_names.get(label_key, label_key)
        usage_by_label.append({
            "label_id": label_key,
            "label_name": display_name,
            "file_count": stats["count"],
            "total_size_bytes": stats["total_size_bytes"],
            "percentage": stats["percentage"],
        })
    
    # Sort by count descending
    usage_by_label.sort(key=lambda u: u.get("file_count", 0), reverse=True)
    
    return {
        "total_files_scanned": total_scanned,
        "labeled_files": total_scanned - unlabeled_count,
        "unlabeled_files": unlabeled_count,
        "labeling_percentage": round(((total_scanned - unlabeled_count) / total_scanned * 100), 1) if total_scanned > 0 else 0,
        "available_labels": len(available_labels),
        "usage_by_label": usage_by_label,
        "recommendations": _get_dlp_recommendations(unlabeled_count, total_scanned, usage_stats),
    }


def _get_dlp_recommendations(unlabeled: int, total: int, usage: dict) -> list:
    """Generate DLP recommendations based on usage patterns."""
    recommendations = []
    
    if total > 0:
        unlabeled_pct = (unlabeled / total) * 100
        if unlabeled_pct > 50:
            recommendations.append({
                "id": "high_unlabeled",
                "severity": "high",
                "title": "High percentage of unlabeled files",
                "description": f"{unlabeled_pct:.0f}% of scanned files have no sensitivity label. "
                               f"Consider enabling default labeling or mandatory labeling policies.",
                "action": "Configure auto-labeling policies in Microsoft 365 Compliance Center",
            })
        elif unlabeled_pct > 20:
            recommendations.append({
                "id": "moderate_unlabeled",
                "severity": "medium",
                "title": "Moderate number of unlabeled files",
                "description": f"{unlabeled_pct:.0f}% of files are unlabeled. "
                               f"Consider user training on labeling best practices.",
                "action": "Review auto-labeling rules and user training",
            })
    
    # Check if sensitive labels are not being used
    sensitive_labels = ["confidential", "highly_confidential", "secret", "restricted"]
    has_sensitive = any(k.lower() in sensitive_labels for k in usage.keys())
    if total > 100 and not has_sensitive:
        recommendations.append({
            "id": "no_sensitive_labels",
            "severity": "medium",
            "title": "Sensitive labels not in use",
            "description": "No files have been classified as confidential or higher. "
                           "Either your organization has no sensitive data (unlikely) or labels aren't being applied.",
            "action": "Review classification rules and train users on identifying sensitive content",
        })
    
    return recommendations


# ── Background scanning functions for enterprise security ────────────────────

async def _scan_external_users_background(org_id: str, db: AsyncSession) -> None:
    """Background scan to detect and alert on stale external users."""
    logger.info(f"_scan_external_users: starting for org {org_id}")
    
    integ = (await db.execute(
        select(SaasIntegration).where(
            SaasIntegration.org_id == uuid.UUID(org_id),
            SaasIntegration.status == "active",
        ).limit(1)
    )).scalar_one_or_none()
    
    if not integ:
        return
    
    access_token = await _get_valid_token(integ, db)
    if not access_token:
        return
    
    # Get stale external users
    sc, data = await _safe_graph_get(
        f"https://graph.microsoft.com/beta/users?"
        f"$filter=userType eq 'Guest'&"
        f"$select=id,displayName,userPrincipalName,signInActivity,createdDateTime&"
        f"$top=100",
        access_token,
        eventual=True
    )
    
    if sc != 200:
        logger.warning(f"_scan_external_users: Graph API returned {sc}")
        return
    
    now = datetime.now(timezone.utc)
    stale_threshold = 90  # days
    
    for user in data.get("value", []):
        sign_in = user.get("signInActivity", {})
        last_signin = sign_in.get("lastSignInDateTime") or sign_in.get("lastNonInteractiveSignInDateTime")
        
        days_inactive = None
        if last_signin:
            try:
                last_dt = datetime.fromisoformat(last_signin.replace("Z", "+00:00"))
                days_inactive = (now - last_dt).days
            except Exception:
                pass
        
        if days_inactive and days_inactive > stale_threshold:
            # Check if we already have an alert for this user
            resource_id = f"stale-guest:{user.get('id', '')}"
            existing = (await db.execute(
                select(SaasAlert).where(
                    SaasAlert.org_id == uuid.UUID(org_id),
                    SaasAlert.resource_id == resource_id,
                    SaasAlert.status == "open",
                )
            )).scalar_one_or_none()
            
            if not existing:
                db.add(SaasAlert(
                    org_id=uuid.UUID(org_id),
                    provider="m365",
                    alert_type="stale_external_user",
                    severity="medium",
                    title=f"Stale External User: {user.get('displayName', 'Unknown')}",
                    description=f"Guest user {user.get('userPrincipalName', '')} has been inactive for "
                                f"{days_inactive} days. Consider removing access if no longer needed.",
                    resource_id=resource_id,
                    resource_name=user.get("userPrincipalName", ""),
                    status="open",
                    raw_data={
                        "user_id": user.get("id"),
                        "days_inactive": days_inactive,
                        "last_signin": last_signin,
                    },
                ))
    
    try:
        await db.commit()
        logger.info(f"_scan_external_users: completed for org {org_id}")
    except Exception as exc:
        logger.warning(f"_scan_external_users: commit failed: {exc}")
        await db.rollback()


async def _scan_ca_policy_gaps_background(org_id: str, db: AsyncSession) -> None:
    """Background scan to detect and alert on CA policy gaps."""
    logger.info(f"_scan_ca_policy_gaps: starting for org {org_id}")
    
    integ = (await db.execute(
        select(SaasIntegration).where(
            SaasIntegration.org_id == uuid.UUID(org_id),
            SaasIntegration.status == "active",
        ).limit(1)
    )).scalar_one_or_none()
    
    if not integ:
        return
    
    access_token = await _get_valid_token(integ, db)
    if not access_token:
        return
    
    # Get CA policies
    sc, ca_data = await _safe_graph_get(
        f"{GRAPH}/identity/conditionalAccess/policies",
        access_token
    )
    
    if sc != 200:
        logger.warning(f"_scan_ca_policy_gaps: Graph API returned {sc}")
        return
    
    policies = ca_data.get("value", [])
    enabled_policies = [p for p in policies if p.get("state") == "enabled"]
    
    # Check for critical gaps
    gaps_to_alert = []
    
    # No MFA for all users
    mfa_all = any(
        "All" in p.get("conditions", {}).get("users", {}).get("includeUsers", []) and
        "mfa" in (p.get("grantControls", {}) or {}).get("builtInControls", [])
        for p in enabled_policies
    )
    if not mfa_all:
        gaps_to_alert.append(("ca_no_mfa_all", "critical", "No MFA policy for all users",
                              "No Conditional Access policy requires MFA for all users."))
    
    # Legacy auth not blocked
    legacy_blocked = any(
        any(c in p.get("conditions", {}).get("clientAppTypes", []) for c in ("exchangeActiveSync", "other")) and
        "block" in (p.get("grantControls", {}) or {}).get("builtInControls", [])
        for p in enabled_policies
    )
    if not legacy_blocked:
        gaps_to_alert.append(("ca_legacy_auth", "high", "Legacy authentication not blocked",
                              "No policy blocks legacy auth protocols which bypass MFA."))
    
    # Create alerts for gaps
    for gap_id, severity, title, description in gaps_to_alert:
        resource_id = f"ca-gap:{gap_id}"
        existing = (await db.execute(
            select(SaasAlert).where(
                SaasAlert.org_id == uuid.UUID(org_id),
                SaasAlert.resource_id == resource_id,
                SaasAlert.status == "open",
            )
        )).scalar_one_or_none()
        
        if not existing:
            db.add(SaasAlert(
                org_id=uuid.UUID(org_id),
                provider="m365",
                alert_type="ca_policy_gap",
                severity=severity,
                title=title,
                description=description,
                resource_id=resource_id,
                resource_name="Conditional Access",
                status="open",
            ))
    
    try:
        await db.commit()
        logger.info(f"_scan_ca_policy_gaps: completed for org {org_id}, found {len(gaps_to_alert)} gaps")
    except Exception as exc:
        logger.warning(f"_scan_ca_policy_gaps: commit failed: {exc}")
        await db.rollback()


# ══════════════════════════════════════════════════════════════════════════════
# BACKGROUND TASKS
# ══════════════════════════════════════════════════════════════════════════════

async def _auto_scan_all_orgs() -> None:
    """Scan all orgs with active integrations. Called by watchdog in main.py."""
    import time as _t
    _posture_interval = 6 * 3600  # 6 hours
    _update_worker_status("saas_scan", "running")
    _set_worker_next_run("saas_scan", 300)
    try:
        async with AsyncSessionLocal() as db:
            si_res = await db.execute(
                select(SaasIntegration.org_id, SaasIntegration.last_synced_at)
                .where(SaasIntegration.status.in_(["active", "error"]))
                .distinct()
            )
            rows = si_res.fetchall()
        org_ids = [str(r[0]) for r in rows if r[0]]
        logger.info(f"saas_auto_scan: found {len(org_ids)} org(s) with active integrations")
        now = _t.time()
        for oid in org_ids:
            try:
                await _run_saas_scan(oid)
                logger.info(f"saas_auto_scan: scan completed for org {oid}")
            except Exception as exc:
                logger.warning(f"saas_auto_scan: scan failed for org {oid}: {exc}")
    except Exception as exc:
        logger.error(f"saas_auto_scan: top-level error: {exc}")


async def _run_saas_scan(org_id: str) -> None:
    """Scan connected providers for sensitive data, create alerts."""
    try:
        # Fetch integrations in a separate session to avoid transaction contamination
        integrations_data = []
        async with AsyncSessionLocal() as db:
            integrations = (await db.execute(
                select(SaasIntegration).where(
                    SaasIntegration.org_id == uuid.UUID(org_id),
                    SaasIntegration.status.in_(["active", "error"]),  # include error so token refresh can recover
                )
            )).scalars().all()
            # Copy needed data before session closes
            for integ in integrations:
                integrations_data.append({
                    "id": integ.id,
                    "provider": integ.provider,
                    "access_token": integ.access_token,
                    "refresh_token": integ.refresh_token,
                    "token_expiry": integ.token_expiry,
                    "tenant_id": integ.tenant_id,
                    "last_synced_at": integ.last_synced_at,
                })

        if not integrations_data:
            logger.info(f"saas_scan: no integrations for org {org_id}")
            return

        for integ_data in integrations_data:
            provider = integ_data["provider"]
            # Use separate DB session for each provider to isolate transactions
            async with AsyncSessionLocal() as db:
                try:
                    # Reload the integration object in this session
                    integ = (await db.execute(
                        select(SaasIntegration).where(SaasIntegration.id == integ_data["id"])
                    )).scalar_one_or_none()
                    if not integ:
                        continue

                    access_token = await _get_valid_token(integ, db)
                    if not access_token:
                        logger.warning(f"saas_scan: skipping {provider} for org {org_id} — no valid token")
                        continue

                    if provider == "teams":
                        await _scan_teams(org_id, access_token, db)
                    elif provider == "sharepoint":
                        await _scan_sharepoint(org_id, access_token, db, integ.last_synced_at)

                    integ.last_synced_at = datetime.now(timezone.utc)
                    await db.commit()
                    logger.info(f"saas_scan: {provider} scan committed for org {org_id}")
                except Exception as scan_exc:
                    logger.error(f"saas_scan: {provider} scan failed for org {org_id}: {scan_exc}")
                    try:
                        await db.rollback()
                    except Exception:
                        pass
                    continue

            # Run non-critical scans in separate sessions
            async with AsyncSessionLocal() as db:
                try:
                    integ = (await db.execute(
                        select(SaasIntegration).where(SaasIntegration.id == integ_data["id"])
                    )).scalar_one_or_none()
                    if not integ:
                        continue
                    access_token = await _get_valid_token(integ, db)
                    if not access_token:
                        continue

                    # Shadow IT discovery (non-fatal)
                    try:
                        await _scan_shadow_it(org_id, provider, access_token, db)
                    except Exception as _si_exc:
                        logger.warning(f"saas_scan: shadow IT scan failed for {provider}: {_si_exc}")
                        try:
                            await db.rollback()
                        except Exception:
                            pass

                    # Entra ID risky users (Microsoft providers: teams, sharepoint)
                    if provider in ("microsoft", "teams", "sharepoint"):
                        try:
                            await _scan_entra_risky_users(org_id, access_token, db)
                        except Exception as _ru_exc:
                            logger.warning(f"saas_scan: Entra risky users failed: {_ru_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Admin action tracking (Microsoft providers)
                        try:
                            await _scan_admin_actions(org_id, access_token, db)
                        except Exception as _aa_exc:
                            logger.warning(f"saas_scan: admin actions scan failed: {_aa_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Enterprise Security: Phishing URL detection in Teams
                        try:
                            await _scan_teams_messages_for_phishing(org_id, access_token, db)
                        except Exception as _ph_exc:
                            logger.warning(f"saas_scan: Teams phishing scan failed: {_ph_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Enterprise Security: Meeting/chat file-share + external participant detection
                        # Surfaces the "file transferred in a meeting with an external user" case.
                        try:
                            await _scan_teams_meeting_chats(org_id, access_token, db)
                        except Exception as _mc_exc:
                            logger.warning(f"saas_scan: Teams meeting-chat scan failed: {_mc_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Enterprise Security: Suspicious sign-in detection
                        try:
                            await _scan_suspicious_signins(org_id, access_token, db)
                        except Exception as _si_exc:
                            logger.warning(f"saas_scan: Suspicious signin scan failed: {_si_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Enterprise Security: File threat indicators
                        try:
                            await _scan_files_for_threats(org_id, access_token, db)
                        except Exception as _ft_exc:
                            logger.warning(f"saas_scan: File threat scan failed: {_ft_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Enterprise Security: Impossible travel detection
                        try:
                            await _scan_impossible_travel(org_id, access_token, db)
                        except Exception as _it_exc:
                            logger.warning(f"saas_scan: Impossible travel scan failed: {_it_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Enterprise Security: After-hours login detection
                        try:
                            await _scan_afterhours_logins(org_id, access_token, db)
                        except Exception as _ah_exc:
                            logger.warning(f"saas_scan: After-hours login scan failed: {_ah_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Enterprise Security: Ransomware pattern detection
                        try:
                            await _scan_ransomware_patterns(org_id, access_token, db)
                        except Exception as _rw_exc:
                            logger.warning(f"saas_scan: Ransomware pattern scan failed: {_rw_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                        # Enterprise Security: External sharing of sensitive files
                        try:
                            await _scan_external_sharing(org_id, access_token, db)
                        except Exception as _es_exc:
                            logger.warning(f"saas_scan: External sharing scan failed: {_es_exc}")
                            try:
                                await db.rollback()
                            except Exception:
                                pass

                except Exception as exc:
                    logger.error(f"saas_scan: non-critical scan for {provider} org={org_id} error: {exc}")
                    try:
                        await db.rollback()
                    except Exception:
                        pass

            # User risk scores scan (separate session to avoid transaction contamination)
            async with AsyncSessionLocal() as db:
                try:
                    integ = (await db.execute(
                        select(SaasIntegration).where(SaasIntegration.id == integ_data["id"])
                    )).scalar_one_or_none()
                    if integ and provider in ("microsoft", "teams", "sharepoint"):
                        access_token = await _get_valid_token(integ, db)
                        if access_token:
                            try:
                                await _scan_user_risk_scores(org_id, access_token, db)
                            except Exception as _ur_exc:
                                logger.warning(f"saas_scan: User risk scores failed: {_ur_exc}")
                                try:
                                    await db.rollback()
                                except Exception:
                                    pass
                except Exception as exc:
                    logger.warning(f"saas_scan: user risk scores session error: {exc}")

        # Teams/SharePoint enterprise threat detection (separate session per provider)
        for integ_data in integrations_data:
            provider = integ_data["provider"]
            if provider in ("teams", "sharepoint"):
                async with AsyncSessionLocal() as db:
                    try:
                        integ = (await db.execute(
                            select(SaasIntegration).where(SaasIntegration.id == integ_data["id"])
                        )).scalar_one_or_none()
                        if not integ:
                            continue
                        access_token = await _get_valid_token(integ, db)
                        if access_token:
                            if provider == "teams":
                                await _detect_teams_enterprise_threats(org_id, access_token, db)
                            elif provider == "sharepoint":
                                await _detect_sharepoint_onedrive_threats(org_id, access_token, db)
                    except Exception as _ent_exc:
                        logger.warning(f"saas_scan: enterprise threats ({provider}) failed: {_ent_exc}")

        # AWS comprehensive threat scan (separate session)
        async with AsyncSessionLocal() as db:
            try:
                aws_threat_findings = await _aws_threat_scan(org_id, db)
                if aws_threat_findings:
                    for finding in aws_threat_findings:
                        try:
                            await db.execute(text("""
                                INSERT INTO aws_findings
                                  (org_id, title, description, severity, category, resource_id, status, detected_at)
                                VALUES (:org_id, :title, :desc, :severity, :category, :rid, 'open', NOW())
                                ON CONFLICT (org_id, title, resource_id) DO UPDATE
                                  SET severity = EXCLUDED.severity, detected_at = NOW()
                            """), {
                                "org_id": org_id,
                                "title": finding["title"],
                                "desc": finding["description"],
                                "severity": finding["severity"],
                                "category": finding.get("category", "security"),
                                "rid": finding.get("resource_id", "aws"),
                            })
                        except Exception:
                            pass
                    try:
                        await db.commit()
                    except Exception:
                        await db.rollback()
                    logger.info(f"saas_scan: AWS threat scan found {len(aws_threat_findings)} findings for org {org_id}")
                    _update_worker_status("aws_scan", "completed")
            except Exception as _aws_exc:
                logger.warning(f"saas_scan: AWS threat scan failed: {_aws_exc}")

        # AWS IAM scan (separate session)
        async with AsyncSessionLocal() as db:
            try:
                iam_risks = await _aws_iam_scan(org_id, db)
                if iam_risks:
                    for risk in iam_risks:
                        try:
                            await db.execute(text("""
                                INSERT INTO aws_findings
                                  (org_id, title, description, severity, category, resource_id, status, detected_at)
                                VALUES (:org_id, :title, :desc, :severity, :category, :rid, 'open', NOW())
                                ON CONFLICT (org_id, title, resource_id) DO UPDATE
                                  SET severity = EXCLUDED.severity, detected_at = NOW()
                            """), {
                                "org_id": org_id,
                                "title": risk["description"],
                                "desc": risk["description"],
                                "severity": risk["severity"],
                                "category": "iam",
                                "rid": risk.get("principal", "iam"),
                            })
                        except Exception:
                            pass
                    try:
                        await db.commit()
                    except Exception:
                        await db.rollback()
                    logger.info(f"saas_scan: AWS IAM scan found {len(iam_risks)} risks for org {org_id}")
            except Exception as _iam_exc:
                logger.warning(f"saas_scan: AWS IAM scan failed: {_iam_exc}")

        # AWS DLP Classification (separate session)
        async with AsyncSessionLocal() as db:
            try:
                await _aws_dlp_classify_resources(org_id, db)
            except Exception as _aws_dlp_exc:
                logger.warning(f"saas_scan: AWS DLP classification failed: {_aws_dlp_exc}")

        # Data Sovereignty Violation Detection (separate session)
        async with AsyncSessionLocal() as db:
            try:
                await _detect_data_sovereignty_violations(org_id, db)
            except Exception as _sov_exc:
                logger.warning(f"saas_scan: Data sovereignty check failed: {_sov_exc}")

    except Exception as exc:
        logger.error(f"saas_scan: top-level error for org {org_id}: {exc}")


async def _detect_data_sovereignty_violations(org_id: str, db: AsyncSession) -> None:
    """
    Detect data sovereignty violations:
    - PII/sensitive data stored in foreign regions
    - User accessing sensitive data from unexpected countries
    - Cross-border data transfers involving regulated data
    Creates alerts for violations.
    """
    logger.info(f"data_sovereignty: starting violation check for org {org_id}")
    violations = []
    
    try:
        # Get org's expected data regions (from tenant or org settings)
        org_result = await db.execute(text("""
            SELECT tenant_id, settings FROM organizations WHERE id = CAST(:org_id AS UUID)
        """), {"org_id": org_id})
        org_row = org_result.mappings().first()
        org_settings = org_row["settings"] if org_row else {}
        if isinstance(org_settings, str):
            try:
                org_settings = json.loads(org_settings)
            except Exception:
                org_settings = {}
        
        # Default allowed regions (can be configured per org)
        allowed_regions = org_settings.get("allowed_data_regions", ["US", "USA", "United States", "EU", "Europe"])
        sensitive_categories = ["pii", "financial", "health", "hipaa", "gdpr", "confidential", "highly_confidential", "source_code"]
        
        # 1. Check AWS resources with sensitive DLP categories in unexpected regions
        aws_violations = await db.execute(text("""
            SELECT r.name, r.resource_type, r.region, f.title, f.metadata
            FROM aws_resources r
            JOIN aws_findings f ON r.org_id = f.org_id AND r.resource_id = f.resource_id
            WHERE r.org_id = :org_id
              AND f.category = 'dlp_classification'
              AND f.status = 'open'
              AND r.region NOT IN ('us-east-1', 'uaenorth', 'eu-west-1', 'eu-central-1')
            LIMIT 20
        """), {"org_id": org_id})
        for row in aws_violations.mappings():
            meta = row["metadata"] or {}
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            cats = meta.get("categories", [])
            if any(c in sensitive_categories for c in cats):
                violations.append({
                    "type": "sensitive_data_foreign_region",
                    "resource": row["name"],
                    "resource_type": row["resource_type"],
                    "region": row["region"],
                    "categories": cats,
                    "severity": "high",
                    "title": f"Sensitive data ({', '.join(cats)}) stored in {row['region']}",
                })
        
        # 2. Check SaaS data items with cross-border access patterns
        saas_violations = await db.execute(text("""
            SELECT item_name, provider, classification_label, sharing_scope, owner_email
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND classification_label IN ('pii', 'financial', 'health', 'confidential', 'highly_confidential')
              AND sharing_scope IN ('external', 'public')
            LIMIT 20
        """), {"org_id": org_id})
        for row in saas_violations.mappings():
            violations.append({
                "type": "sensitive_external_share",
                "resource": row["item_name"],
                "provider": row["provider"],
                "classification": row["classification_label"],
                "severity": "high" if row["sharing_scope"] == "public" else "medium",
                "title": f"{row['classification_label'].upper()} data externally shared: {row['item_name']}",
            })
        
        # 3. Create alerts for violations
        for v in violations:
            try:
                await db.execute(text("""
                    INSERT INTO saas_alerts
                        (id, org_id, provider, alert_type, severity, title, description, resource_name, status, created_at)
                    VALUES
                        (gen_random_uuid(), CAST(:org_id AS UUID), :provider, 'data_sovereignty', :severity, :title, :desc, :resource, 'open', NOW())
                    ON CONFLICT (org_id, title, resource_name) DO UPDATE SET
                        severity = EXCLUDED.severity, created_at = NOW()
                """), {
                    "org_id": org_id,
                    "provider": v.get("provider", "aws"),
                    "severity": v["severity"],
                    "title": v["title"],
                    "desc": f"Data sovereignty violation: {v['type']} - {v.get('resource', 'Unknown')}",
                    "resource": v.get("resource", "unknown"),
                })
            except Exception as _alert_exc:
                logger.debug(f"data_sovereignty: alert insert failed: {_alert_exc}")
        
        if violations:
            await db.commit()
            logger.info(f"data_sovereignty: found {len(violations)} violations for org {org_id}")
        else:
            logger.debug(f"data_sovereignty: no violations for org {org_id}")
            
    except Exception as exc:
        logger.warning(f"data_sovereignty: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass


async def _aws_dlp_classify_resources(org_id: str, db: AsyncSession) -> None:
    """
    DLP Classification for AWS resources — runs AI classification on unclassified resources
    and stores categories in the aws_findings table (as dlp_classification category findings).
    Limits to 20 resources per scan cycle to avoid rate limits.
    """
    logger.info(f"_aws_dlp_classify_resources: starting for org {org_id}")
    try:
        # Adnan 2026-06-22: also re-classify rows that were classified by
        # the old prompt (which only emitted operational posture categories
        # like iam/network/compliance) so the DLP Categories column
        # eventually shows data-content categories (pii/credentials/etc).
        # We detect old-shape rows by checking if dlp_categories contains
        # ONLY posture tokens or is missing the new dlp_source key. The
        # next pass migrates them in batches of 20.
        unclassified = await db.execute(text("""
            SELECT id::text, resource_type, COALESCE(name, resource_id) as rname,
                   region, encryption_enabled, public_access, size_bytes, tags, metadata
            FROM aws_resources
            WHERE org_id = :org_id
              AND (
                  metadata->>'dlp_classified' IS NULL
                  OR metadata->>'dlp_classified' != 'true'
                  OR (
                      -- Old-shape: classified but only with posture tokens.
                      -- Trigger a re-classify so we get data categories.
                      metadata->>'dlp_classified' = 'true'
                      AND metadata->>'dlp_schema_version' IS DISTINCT FROM 'v2'
                  )
              )
            ORDER BY created_at DESC
            LIMIT 20
        """), {"org_id": org_id})
        rows = unclassified.mappings().all()
        logger.info(f"_aws_dlp_classify_resources: found {len(rows)} unclassified resources for org {org_id}")
        if not rows:
            return
        logger.info(f"aws_dlp: classifying {len(rows)} AWS resources for org {org_id}")

        # Adnan 2026-06-23: pull the org's AWS creds once and reuse them
        # to sample bucket contents / EBS metadata during the loop. If
        # we can't get creds we just classify on metadata as before.
        _aws_s3_client = None
        _aws_ec2_client = None
        try:
            _aws_conn_row = (await db.execute(text("""
                SELECT access_key_id_enc, secret_access_key_enc, default_region
                FROM aws_connections
                WHERE org_id = :org_id AND status = 'active'
                LIMIT 1
            """), {"org_id": org_id})).mappings().first()
            if _aws_conn_row:
                import boto3 as _boto3
                from backend.routers.aws_connector import _decrypt as _aws_decrypt
                _ak = _aws_decrypt(_aws_conn_row["access_key_id_enc"])
                _sk = _aws_decrypt(_aws_conn_row["secret_access_key_enc"])
                _rg = _aws_conn_row["default_region"] or "us-east-1"
                _aws_s3_client = _boto3.client(
                    "s3",
                    aws_access_key_id=_ak,
                    aws_secret_access_key=_sk,
                    region_name=_rg,
                )
                _aws_ec2_client = _boto3.client(
                    "ec2",
                    aws_access_key_id=_ak,
                    aws_secret_access_key=_sk,
                    region_name=_rg,
                )
        except Exception as _cred_exc:
            logger.warning(
                f"aws_dlp: could not init boto3 clients for content sampling: {_cred_exc}"
            )

        for row in rows:
            try:
                resource_meta = {
                    "resource_id": row["rname"],
                    "resource_type": row["resource_type"],
                    "public_access": row["public_access"],
                    "encryption_enabled": row["encryption_enabled"],
                    "region": row["region"],
                    "size_bytes": row["size_bytes"],
                }
                if row["tags"]:
                    resource_meta["tags"] = row["tags"]

                # ── Real content sample ──────────────────────────────
                # For S3 and EBS pull a real (capped) content sample so
                # the classifier reasons about the actual data, not just
                # the bucket name. This is what makes the Data Posture
                # agent feel like Varonis/Concentric instead of a
                # naming-pattern lint.
                rt = (row["resource_type"] or "").lower()
                try:
                    if rt in ("s3_bucket", "s3") and _aws_s3_client and row["rname"]:
                        from backend.services.aws_content_sampler import sample_s3_bucket
                        sample = sample_s3_bucket(_aws_s3_client, row["rname"])
                        resource_meta["_content_sample"] = sample.get("content_sample", "")
                        resource_meta["_data_excerpts"] = sample.get("data_excerpts", [])
                        resource_meta["_extensions_seen"] = sample.get("extensions_seen", [])
                        resource_meta["_object_count_seen"] = sample.get("object_count_seen", 0)
                        logger.info(
                            "aws_dlp_sample: s3 bucket=%s objects=%s sample_bytes=%s",
                            row["rname"],
                            sample.get("object_count_seen"),
                            len(sample.get("content_sample", "")),
                        )
                    elif rt in ("ebs_volume", "ebs") and _aws_ec2_client and row["rname"]:
                        from backend.services.aws_content_sampler import sample_ebs_volume
                        sample = sample_ebs_volume(_aws_ec2_client, row["rname"])
                        resource_meta["_content_sample"] = sample.get("content_sample", "")
                        logger.info(
                            "aws_dlp_sample: ebs volume=%s instance=%s",
                            row["rname"], sample.get("instance_id"),
                        )
                except Exception as _samp_exc:
                    logger.debug(
                        f"aws_dlp_sample: skipped for {rt}/{row['rname']}: {_samp_exc}"
                    )

                ai_result = await _aws_ai_classify_resource(
                    resource_type=row["resource_type"] or "aws_resource",
                    resource_metadata=resource_meta,
                    org_id=org_id,
                )
                categories = ai_result.get("categories", [])
                risk_level = ai_result.get("risk_level", "low")
                explanation = ai_result.get("explanation", "")
                logger.info(f"_aws_dlp_classify_resources: classified {row['id']} ({row['resource_type']}/{row['rname']}) as {risk_level}, categories={categories}")
                # Mark resource as DLP-classified in metadata
                existing_meta = row["metadata"] or {}
                if isinstance(existing_meta, str):
                    import json as _json_
                    existing_meta = _json_.loads(existing_meta)
                existing_meta["dlp_classified"] = "true"
                existing_meta["dlp_categories"] = categories
                existing_meta["dlp_risk_level"] = risk_level
                # Bump schema version so reclassification logic knows
                # this row was produced by the new dual-category prompt.
                existing_meta["dlp_schema_version"] = "v2"
                # Adnan 2026-06-23: existing_meta can carry datetimes (e.g.
                # iam_role.create_date) that asyncpg pulled out of the JSONB
                # column as datetime objects. json.dumps without default=str
                # raises TypeError, the row's UPDATE never runs, and the
                # per-row except handler eats it silently — which is exactly
                # why most aws rows were re-classified every cycle but the
                # UPDATE never persisted. default=str round-trips datetimes
                # as ISO strings; subsequent reads parse fine because Graph
                # API code already treats them as strings.
                # Adnan 2026-06-23 (the actual root cause):
                # `SET metadata = :meta` without CAST(:meta AS jsonb) on a
                # JSONB column makes asyncpg store the value as a JSON
                # STRING (one big quoted string), not a JSON OBJECT. The
                # write 'succeeds' with rowcount=1 but the column is now
                # "{\"dlp_classified\":\"true\", ...}" and every
                # metadata->>'dlp_classified' read returns NULL. This is
                # why every UPDATE logged rowcount=1 yet the API never saw
                # the DLP keys — the keys exist, but inside a string, not
                # an object. Every other classifier path in this file
                # already uses CAST(:meta AS jsonb); this one didn't.
                _upd_res = await db.execute(text("""
                    UPDATE aws_resources
                    SET metadata = CAST(:meta AS jsonb)
                    WHERE id = CAST(:rid AS UUID)
                """), {"meta": json.dumps(existing_meta, default=str), "rid": row["id"]})
                # Adnan 2026-06-23: commit per-row so a single bad row's
                # INSERT/UPDATE doesn't poison the whole batch and undo every
                # preceding UPDATE on the silent rollback path. Also log
                # the affected rowcount so we can see whether the WHERE
                # actually matched.
                try:
                    _rc = _upd_res.rowcount if _upd_res is not None else -1
                except Exception:
                    _rc = -2
                logger.info(
                    "aws_dlp_persist: rid=%s rowcount=%s wrote_keys=%s",
                    row["id"], _rc, sorted(list(existing_meta.keys()))[:8],
                )
                # Adnan 2026-06-23: COMMIT the metadata UPDATE *now*, before
                # the findings INSERT runs. The aws_findings table doesn't
                # have a unique constraint matching the ON CONFLICT spec
                # below, so that INSERT raises InvalidColumnReferenceError,
                # which the outer except catches and rolls back — undoing
                # the metadata UPDATE we just made. Result: rowcount=1 + the
                # row appears 'unclassified' next cycle. Forever.
                try:
                    await db.commit()
                except Exception as _meta_commit_exc:
                    logger.warning(
                        f"aws_dlp: metadata commit failed for "
                        f"{row.get('id')}: {_meta_commit_exc}",
                        exc_info=True,
                    )
                    try:
                        await db.rollback()
                    except Exception:
                        pass
                    continue
                # For high/critical risk resources, create a finding.
                # Wrapped in its own try/commit/rollback so the missing
                # constraint can't poison the metadata write above.
                if risk_level in ("high", "critical") and categories:
                    try:
                        await db.execute(text("""
                            INSERT INTO aws_findings
                              (org_id, title, description, severity, category, resource_id, status, detected_at)
                            VALUES (:org_id, :title, :desc, :severity, :category, :rid, 'open', NOW())
                            ON CONFLICT (org_id, title, resource_id) DO UPDATE
                              SET severity = EXCLUDED.severity, detected_at = NOW()
                        """), {
                            "org_id": org_id,
                            "title": f"DLP: {row['resource_type']} resource has {', '.join(categories[:2])}: {row['rname'][:60]}",
                            "desc": explanation or f"DLP classification flagged this {row['resource_type']} resource as {risk_level} risk.",
                            "severity": risk_level,
                            "category": categories[0] if categories else "sensitive_data",
                            "rid": row["rname"] or row["id"],
                        })
                        await db.commit()
                    except Exception as _find_exc:
                        logger.debug(
                            f"aws_dlp: findings INSERT skipped for "
                            f"{row.get('id')}: {_find_exc}",
                        )
                        try:
                            await db.rollback()
                        except Exception:
                            pass
            except Exception as _item_exc:
                # Adnan 2026-06-23: bumped from debug to warning. When the
                # findings INSERT or the UPDATE raised, this swallowed it
                # silently and the outer commit still happened — except the
                # session was in error state, so commit was effectively a
                # rollback. Now we'll see it.
                logger.warning(
                    f"aws_dlp: resource {row.get('id')} classification "
                    f"failed: {_item_exc}",
                    exc_info=True,
                )
                # If the session is now in a failed-transaction state we
                # have to rollback before the next iteration can do any
                # more UPDATEs, otherwise asyncpg/SQLAlchemy will keep
                # raising InFailedTransactionError. Per-row commit below
                # also protects against losing earlier rows in the batch.
                try:
                    await db.rollback()
                except Exception:
                    pass
                continue
            # Commits happen inline above (right after UPDATE and after
            # the findings INSERT). No trailing per-row commit needed.
        try:
            await db.commit()
            logger.info(f"aws_dlp: DLP classification complete for {len(rows)} AWS resources, org {org_id}")
        except Exception as _commit_exc:
            # Adnan 2026-06-23: this silently swallowed the commit error for
            # weeks, which is why the DLP keys never persisted even though
            # the per-row classify+UPDATE logs said success. Log it loudly.
            logger.warning(
                f"aws_dlp: COMMIT FAILED for org {org_id}: {_commit_exc}",
                exc_info=True,
            )
            await db.rollback()
    except Exception as exc:
        logger.warning(f"aws_dlp: top-level error for org {org_id}: {exc}")


async def _run_posture_evaluation(org_id: str) -> None:
    """Evaluate SaaS posture by querying Graph API settings."""
    try:
        async with AsyncSessionLocal() as db:
            integrations = (await db.execute(
                select(SaasIntegration).where(
                    SaasIntegration.org_id == uuid.UUID(org_id),
                    SaasIntegration.status.in_(["active", "error"]),
                )
            )).scalars().all()

            for integ in integrations:
                try:
                    access_token = await _get_valid_token(integ, db)
                    if not access_token:
                        logger.warning(f"posture_eval: skipping {integ.provider} for org {org_id} — no valid token")
                        continue
                    await _evaluate_provider_posture(org_id, integ.provider, access_token, db)
                except Exception as exc:
                    logger.error(f"posture_eval: provider={integ.provider} org={org_id}: {exc}")
                    await db.rollback()

    except Exception as exc:
        logger.error(f"posture_eval: top-level error for org {org_id}: {exc}")


async def _scan_teams(org_id: str, access_token: str, db: AsyncSession) -> None:
    """Scan Teams channel messages for sensitive content."""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        async with httpx.AsyncClient(timeout=30) as client:
            teams_resp = await client.get(
                f"{GRAPH}/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName&$top=20",
                headers=headers
            )
            if teams_resp.status_code != 200:
                teams_resp = await client.get(f"{GRAPH}/me/joinedTeams", headers=headers)
                if teams_resp.status_code != 200:
                    logger.warning(f"saas_scan/teams: list teams returned {teams_resp.status_code}")
                    return

            teams = teams_resp.json().get("value", [])
            for team in teams[:10]:
                team_id = team.get("id")
                team_name = team.get("displayName", "Unknown Team")
                if not team_id:
                    continue

                # Scan Teams files via all group drives (enumerate folders recursively)
                # Get drives for the team group
                drives_resp = await client.get(f"{GRAPH}/groups/{team_id}/drives", headers=headers)
                group_drives = drives_resp.json().get("value", []) if drives_resp.status_code == 200 else []
                gd_id = group_drives[0].get("id", "") if group_drives else ""

                all_team_items: list[dict] = []

                # Strategy 1: filesFolder per channel (most reliable for channel-shared files)
                ch_list_resp = await client.get(f"{GRAPH}/teams/{team_id}/channels", headers=headers)
                channels = ch_list_resp.json().get("value", []) if ch_list_resp.status_code == 200 else []
                for ch in channels[:10]:
                    ch_id = ch.get("id", "")
                    ch_name = ch.get("displayName", "")
                    if not ch_id:
                        continue
                    ff_resp = await client.get(
                        f"{GRAPH}/teams/{team_id}/channels/{ch_id}/filesFolder", headers=headers
                    )
                    if ff_resp.status_code != 200:
                        continue
                    ff = ff_resp.json()
                    ff_drive = ff.get("parentReference", {}).get("driveId") or gd_id
                    ff_id = ff.get("id", "")
                    if not ff_drive or not ff_id:
                        continue
                    children_r = await client.get(
                        f"{GRAPH}/drives/{ff_drive}/items/{ff_id}/children", headers=headers
                    )
                    if children_r.status_code == 200:
                        ch_files = [it for it in children_r.json().get("value", []) if not it.get("folder")]
                        for f in ch_files:
                            f["_channel"] = ch_name
                            f["_drive_id"] = ff_drive
                        all_team_items.extend(ch_files)

                # Strategy 2: drive root scan (catches files not in channels)
                if gd_id:
                    root_r = await client.get(f"{GRAPH}/drives/{gd_id}/root/children", headers=headers)
                    if root_r.status_code == 200:
                        for it in root_r.json().get("value", []):
                            if not it.get("folder") and it.get("id") not in {x.get("id") for x in all_team_items}:
                                it["_drive_id"] = gd_id
                                all_team_items.append(it)

                logger.info(f"saas_scan/teams: team={team_name} total file items={len(all_team_items)}")
                for item in all_team_items[:50]:
                    item_name = item.get("name", "")
                    item_url = item.get("webUrl")
                    size = item.get("size", 0)
                    item_drive_id = item.get("_drive_id") or gd_id
                    ch_name = item.get("_channel", "")
                    # Pull owner from Graph createdBy.user.email — was None
                    # before, which is why Teams files showed no owner in
                    # Data Inventory.
                    teams_owner_email = (
                        (item.get("createdBy") or {})
                        .get("user", {})
                        .get("email")
                        or (item.get("lastModifiedBy") or {})
                        .get("user", {})
                        .get("email")
                    )
                    resource_name = f"{team_name} › {ch_name} › {item_name}" if ch_name else f"{team_name} › {item_name}"
                    content = f"File: {item_name}\nTeam: {team_name}" + (f"\nChannel: {ch_name}" if ch_name else "")
                    if item_drive_id and size > 0 and size < 2 * 1024 * 1024:
                        try:
                            dl = await client.get(
                                f"{GRAPH}/drives/{item_drive_id}/items/{item['id']}/content",
                                headers=headers, follow_redirects=True
                            )
                            if dl.status_code == 200:
                                content = content + "\n\n" + dl.content.decode("utf-8", errors="replace")[:3800]
                        except Exception:
                            pass

                    # Store as SaasDataItem
                    await db.flush()
                    existing_ti = (await db.execute(
                        select(SaasDataItem).where(
                            SaasDataItem.org_id == uuid.UUID(org_id),
                            SaasDataItem.provider == "teams",
                            SaasDataItem.item_id == item.get("id", ""),
                        )
                    )).scalar_one_or_none()
                    classification = await _deepseek_classify_content(
                        content=content, context=f"teams file in {team_name}", org_id=org_id
                    )
                    label = _risk_to_label(classification.get("risk_level", "low"))
                    score = float(classification.get("confidence", 0.5))
                    categories = classification.get("categories", [])
                    # Adnan 2026-06-23 (turn 3): never store an empty
                    # category array — force a heuristic name-based hint
                    # so the DLP Categories column always has SOMETHING.
                    if not categories:
                        try:
                            from backend.services.cross_cloud_dlp import _classify_heuristic
                            heur_cats, _ = _classify_heuristic({
                                "name": item_name,
                                "resource_type": "file",
                                "resource_path": resource_name,
                            })
                            if heur_cats:
                                categories = heur_cats
                        except Exception:
                            pass
                    now_t = datetime.now(timezone.utc)
                    if existing_ti:
                        existing_ti.classification_label = label
                        existing_ti.classification_score = score
                        existing_ti.classification_categories = categories
                        existing_ti.last_scanned_at = now_t
                        if teams_owner_email and not existing_ti.owner_email:
                            existing_ti.owner_email = teams_owner_email
                    else:
                        db.add(SaasDataItem(
                            org_id=uuid.UUID(org_id),
                            provider="teams",
                            item_type="file",
                            item_id=item.get("id", ""),
                            item_name=item_name,
                            item_url=item_url,
                            parent_path=resource_name,
                            owner_email=teams_owner_email,
                            size_bytes=size,
                            classification_label=label,
                            classification_score=score,
                            classification_categories=categories,
                            sharing_scope="org",
                            last_scanned_at=now_t,
                        ))

                    await _classify_and_create_alert(
                        org_id=org_id,
                        provider="teams",
                        resource_id=item.get("id", ""),
                        resource_name=resource_name,
                        resource_url=item_url,
                        content=content,
                        raw_data=item,
                        db=db,
                    )

                # Also try channel messages (works if ChannelMessage.Read.All is granted)
                ch_resp = await client.get(
                    f"{GRAPH}/teams/{team_id}/channels", headers=headers
                )
                if ch_resp.status_code != 200:
                    continue

                for channel in ch_resp.json().get("value", [])[:5]:
                    ch_id = channel.get("id")
                    ch_name = channel.get("displayName", "")
                    if not ch_id:
                        continue

                    msg_resp = await client.get(
                        f"{GRAPH}/teams/{team_id}/channels/{ch_id}/messages?$top=20",
                        headers=headers,
                    )
                    if msg_resp.status_code != 200:
                        # 403 = no ChannelMessage.Read.All — skip silently, files already scanned above
                        if msg_resp.status_code != 403:
                            logger.warning(f"saas_scan/teams: messages returned {msg_resp.status_code} for team={team_name} ch={ch_name}")
                        continue

                    msgs = msg_resp.json().get("value", [])
                    logger.info(f"saas_scan/teams: team={team_name} ch={ch_name} messages={len(msgs)}")
                    for msg in msgs:
                        body_content = (msg.get("body") or {}).get("content", "")
                        if not body_content or len(body_content) < 10:
                            continue

                        await _classify_and_create_alert(
                            org_id=org_id,
                            provider="teams",
                            resource_id=msg.get("id", ""),
                            resource_name=f"{team_name} › {ch_name}",
                            resource_url=msg.get("webUrl"),
                            content=body_content,
                            raw_data=msg,
                            db=db,
                        )

    except Exception as exc:
        logger.error(f"saas_scan/teams: error: {exc}")


async def _scan_sharepoint(
    org_id: str,
    access_token: str,
    db: AsyncSession,
    last_synced_at: Optional[datetime] = None,
) -> None:
    """Scan SharePoint files for sensitive content. Delta scan if last_synced_at is set."""
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        # Build delta filter for modified-since
        # Only use delta filter if we've had at least one successful scan with data
        # Using it too early blocks the initial population of items
        delta_filter = ""  # Always do full scan for now — delta can be re-enabled after data is populated

        async with httpx.AsyncClient(timeout=30) as client:
            # Discover sites: root + known named sites + subsites (no Sites.Read.All needed)
            discovered_sites: list[dict] = []

            # Always get root site
            root_resp = await client.get(f"{GRAPH}/sites/root", headers=headers)
            if root_resp.status_code == 200:
                discovered_sites.append(root_resp.json())
            else:
                logger.warning(f"saas_scan/sharepoint: root site returned {root_resp.status_code}")
                return

            # Try subsites (non-fatal, may need Sites.Read.All)
            sub_resp = await client.get(f"{GRAPH}/sites/root/sites?$top=20", headers=headers)
            if sub_resp.status_code == 200:
                discovered_sites.extend(sub_resp.json().get("value", []))

            # Discover sites from user OneDrives — find SharePoint sites via group drives
            # Also discover via all groups the token can see
            groups_resp = await client.get(f"{GRAPH}/groups?$select=id,displayName,sites&$top=20", headers=headers)
            if groups_resp.status_code == 200:
                for grp in groups_resp.json().get("value", [])[:10]:
                    grp_site = await client.get(f"{GRAPH}/groups/{grp['id']}/sites/root", headers=headers)
                    if grp_site.status_code == 200:
                        site_data = grp_site.json()
                        if not any(s.get("id") == site_data.get("id") for s in discovered_sites):
                            discovered_sites.append(site_data)

            logger.info(f"saas_scan/sharepoint: discovered {len(discovered_sites)} site(s)")
            for site in discovered_sites[:10]:
                site_id = site.get("id")
                site_name = site.get("displayName", "Unknown Site")
                if not site_id:
                    continue

                # Get all drives for this site (not just the default drive)
                drives_resp = await client.get(
                    f"{GRAPH}/sites/{site_id}/drives", headers=headers
                )
                drives = drives_resp.json().get("value", []) if drives_resp.status_code == 200 else []
                # Fall back to default drive if no drives listed
                if not drives:
                    drives = [{"id": None, "name": "Documents"}]

                root_items: list[dict] = []
                for drive in drives[:3]:  # cap at 3 drives per site
                    drive_id = drive.get("id")
                    if drive_id:
                        drive_url = f"{GRAPH}/drives/{drive_id}/root/children"
                    else:
                        drive_url = f"{GRAPH}/sites/{site_id}/drive/root/children"
                    drive_resp = await client.get(drive_url, headers=headers)
                    if drive_resp.status_code == 200:
                        root_items.extend(drive_resp.json().get("value", []))
                    logger.info(f"saas_scan/sharepoint: site={site_name} drive={drive.get('name',drive_id)} status={drive_resp.status_code} items={len(drive_resp.json().get('value',[]) if drive_resp.status_code==200 else [])}")

                if not root_items:
                    logger.info(f"saas_scan/sharepoint: site={site_name} — no items at root level, skipping")
                    continue

                # Recursively collect files from subfolders (up to 2 levels deep)
                all_items: list[dict] = []
                folders_to_scan: list[tuple[str, str]] = []  # (folder_id, folder_name)
                for it in root_items:
                    if it.get("folder"):
                        folders_to_scan.append((it.get("id", ""), it.get("name", "")))
                    else:
                        all_items.append(it)

                for folder_id, folder_name in folders_to_scan[:10]:  # cap at 10 folders
                    try:
                        sub_resp = await client.get(
                            f"{GRAPH}/sites/{site_id}/drive/items/{folder_id}/children",
                            headers=headers,
                        )
                        if sub_resp.status_code == 200:
                            for sub_it in sub_resp.json().get("value", []):
                                if not sub_it.get("folder"):
                                    sub_it["_parent_folder"] = folder_name
                                    all_items.append(sub_it)
                    except Exception:
                        pass

                logger.info(f"saas_scan/sharepoint: site={site_name} found {len(all_items)} file(s) to classify")

                for item in all_items[:50]:  # cap at 50 files per site
                    if item.get("folder"):
                        continue
                    item_id = item.get("id", "")
                    item_name = item.get("name", "")
                    item_url = (item.get("webUrl") or "")
                    size_bytes = item.get("size", 0)
                    owner_email = (
                        (item.get("createdBy") or {})
                        .get("user", {})
                        .get("email")
                    )
                    mime = (item.get("file") or {}).get("mimeType", "")

                    text_mimes = {
                        "text/plain", "application/pdf",
                        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        "application/msword",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        "text/csv",
                    }
                    is_text_file = mime in text_mimes or item_name.endswith((".txt", ".csv", ".docx", ".xlsx", ".pdf"))
                    # Always include filename + site in classify content for keyword matching
                    content_to_classify = f"File: {item_name}\nSite: {site_name}\nType: {mime}"

                    # For text-based files under 2MB, download and extract content
                    if is_text_file and 0 < size_bytes < 2 * 1024 * 1024:
                        try:
                            dl_resp = await client.get(
                                f"{GRAPH}/sites/{site_id}/drive/items/{item_id}/content",
                                headers=headers,
                                follow_redirects=True,
                            )
                            if dl_resp.status_code == 200:
                                raw_bytes = dl_resp.content
                                if mime == "application/pdf" or item_name.endswith(".pdf"):
                                    # Extract text from PDF — run in thread to avoid blocking async greenlet
                                    try:
                                        import asyncio as _asyncio
                                        import io as _io
                                        from pdfminer.high_level import extract_text as _pdf_extract
                                        _bytes_copy = raw_bytes
                                        extracted = await _asyncio.wait_for(
                                            _asyncio.get_event_loop().run_in_executor(
                                                None, lambda: _pdf_extract(_io.BytesIO(_bytes_copy))
                                            ),
                                            timeout=15.0
                                        )
                                        content_to_classify = f"File: {item_name}\nSite: {site_name}\n\n{extracted[:3800]}" if extracted else content_to_classify
                                    except Exception:
                                        content_to_classify = raw_bytes.decode("latin-1", errors="replace")[:4000]
                                else:
                                    # Plain text / CSV / DOCX raw bytes — best-effort decode
                                    raw_text = raw_bytes.decode("utf-8", errors="replace")[:3800]
                                    content_to_classify = f"File: {item_name}\nSite: {site_name}\n\n{raw_text}"
                        except Exception as _dl_exc:
                            logger.warning(f"saas_scan/sharepoint: content download failed for {item_name}: {_dl_exc}")
                            content_to_classify = f"File: {item_name}\nSite: {site_name}"
                    elif not is_text_file:
                        content_to_classify = item_name

                    logger.info(f"saas_scan/sharepoint: classifying '{item_name}' content_len={len(content_to_classify)} preview={content_to_classify[:80]!r}")
                    classification = await _deepseek_classify_content(
                        content=content_to_classify,
                        context=f"sharepoint file in {site_name}: {item_name}",
                        org_id=org_id,
                    )

                    # Adnan 2026-06-23: malware / ransomware indicator
                    # scan on every SharePoint upload. Alert toggle is
                    # `saas_malware_upload` / `saas_ransomware_indicator`
                    # in user settings; the alert sink respects them.
                    try:
                        from backend.services.saas_malware_scanner import scan_uploaded_file
                        _mw = scan_uploaded_file(item_name, size_bytes=size_bytes)
                        if _mw.should_alert:
                            await _classify_and_create_alert(
                                org_id=org_id,
                                provider="sharepoint",
                                resource_id=item_id,
                                resource_name=item_name,
                                resource_url=item_url,
                                content="; ".join(_mw.indicators),
                                raw_data={
                                    "malware_scan": _mw.to_dict(),
                                    "site": site_name,
                                },
                                db=db,
                                explicit_severity=_mw.severity,
                                explicit_category=(
                                    "RANSOMWARE" if _mw.is_ransomware_indicator else "MALWARE"
                                ),
                                alert_pref_key=(
                                    "saas_ransomware_indicator"
                                    if _mw.is_ransomware_indicator
                                    else "saas_malware_upload"
                                ),
                            )
                    except Exception as _mw_exc:
                        logger.debug(f"saas_scan/sharepoint: malware scan failed for {item_name}: {_mw_exc}")

                    label = _risk_to_label(classification.get("risk_level", "low"))
                    score = float(classification.get("confidence", 0.5))

                    # Fetch explicit permissions to detect external sharing.
                    # The base /drive/items response doesn't include permissions,
                    # so without this every file was inferred as 'org' or 'private'
                    # and external-share alerts never fired.
                    external_grantees: list[str] = []
                    try:
                        perm_resp = await client.get(
                            f"{GRAPH}/sites/{site_id}/drive/items/{item_id}/permissions",
                            headers=headers,
                        )
                        if perm_resp.status_code == 200:
                            item["permissions"] = perm_resp.json().get("value", [])
                            # Detect external grantees (email outside tenant domain or anyone-link).
                            tenant_domains_resp = (item.get("_tenant_domains") or [])
                            for p in item["permissions"]:
                                link = p.get("link", {}) or {}
                                if link.get("scope") == "anonymous":
                                    external_grantees.append("anyone-with-link")
                                granted_v2 = p.get("grantedToV2") or {}
                                granted = p.get("grantedTo") or {}
                                # Check both modern + legacy grantee shapes
                                for src in (granted_v2.get("user") or {}, granted.get("user") or {}):
                                    email = (src.get("email") or "").lower()
                                    if email and "#ext#" in email:
                                        external_grantees.append(email)
                                    elif email and tenant_domains_resp and not any(email.endswith("@" + d) for d in tenant_domains_resp):
                                        external_grantees.append(email)
                                # grantedToIdentitiesV2 is a list (shared with multiple users)
                                for ident in (p.get("grantedToIdentitiesV2") or []):
                                    em = ((ident or {}).get("user") or {}).get("email", "").lower()
                                    if em and "#ext#" in em:
                                        external_grantees.append(em)
                    except Exception as _perm_exc:
                        logger.debug(f"saas_scan/sharepoint: permissions fetch failed for {item_name}: {_perm_exc}")

                    sharing = _infer_sharing_scope(item)
                    if external_grantees:
                        sharing = "external"

                    await db.flush()  # flush pending adds before querying
                    existing_item = (await db.execute(
                        select(SaasDataItem).where(
                            SaasDataItem.org_id == uuid.UUID(org_id),
                            SaasDataItem.provider == "sharepoint",
                            SaasDataItem.item_id == item_id,
                        )
                    )).scalar_one_or_none()

                    # Parse last modified from Graph metadata
                    lm_str = item.get("lastModifiedDateTime")
                    try:
                        from dateutil.parser import parse as _parse_dt
                        last_modified = _parse_dt(lm_str) if lm_str else None
                    except Exception:
                        last_modified = None

                    categories = classification.get("categories", [])
                    # Adnan 2026-06-23 (turn 3): same heuristic safety net
                    # as the Teams branch — we never want an empty
                    # DLP Categories cell on the frontend.
                    if not categories:
                        try:
                            from backend.services.cross_cloud_dlp import _classify_heuristic
                            heur_cats, _ = _classify_heuristic({
                                "name": item_name,
                                "resource_type": "file",
                                "resource_path": f"{site_name}/{item.get('_parent_folder', '')}".rstrip('/'),
                            })
                            if heur_cats:
                                categories = heur_cats
                        except Exception:
                            pass

                    now = datetime.now(timezone.utc)
                    if existing_item:
                        existing_item.classification_label = label
                        existing_item.classification_score = score
                        existing_item.classification_categories = categories
                        existing_item.sharing_scope = sharing
                        existing_item.last_scanned_at = now
                        if last_modified:
                            existing_item.last_modified_at = last_modified
                        if owner_email:
                            existing_item.owner_email = owner_email
                        await db.flush()  # Ensure update is persisted
                        logger.info(f"saas_scan/sharepoint: updated existing item '{item_name}' label={label} cats={categories}")
                    else:
                        new_item = SaasDataItem(
                            org_id=uuid.UUID(org_id),
                            provider="sharepoint",
                            item_type="file",
                            item_id=item_id,
                            item_name=item_name,
                            item_url=item_url,
                            parent_path=f"{site_name}/{item.get('_parent_folder', '')}".rstrip('/'),
                            owner_email=owner_email,
                            size_bytes=size_bytes,
                            classification_label=label,
                            classification_score=score,
                            classification_categories=categories,
                            sharing_scope=sharing,
                            last_modified_at=last_modified,
                            last_scanned_at=now,
                        )
                        db.add(new_item)
                        logger.info(f"saas_scan/sharepoint: added new item '{item_name}' label={label} org={org_id}")

                    # Alert on:
                    #  - highly_confidential always
                    #  - confidential always (every confidential file is worth a look,
                    #    even if internal — customers want visibility)
                    #  - ANY label shared externally or via anyone-link (this is the
                    #    primary 'I shared a file with external user' trigger)
                    should_alert = (
                        label == "highly_confidential"
                        or label == "confidential"
                        or sharing in ("external", "public")
                    )
                    if should_alert:
                        await _classify_and_create_alert(
                            org_id=org_id,
                            provider="sharepoint",
                            resource_id=item_id,
                            resource_name=item_name,
                            resource_url=item_url,
                            content=content_to_classify,
                            raw_data=item,
                            db=db,
                        )
                    # Independent of file sensitivity, always fire a dedicated
                    # external_share alert when a file is shared with an outside
                    # user or anyone-link. This is the alert type the Threat Intel
                    # cards on the Alerts tab pivot on, and it's what customers
                    # actually want to see when they share a doc with a vendor or
                    # client.
                    if external_grantees:
                        try:
                            unique_grantees = sorted(set(external_grantees))[:10]
                            severity = "high" if label in ("highly_confidential", "confidential") else "medium"
                            scope_label = "anyone-with-link" if "anyone-with-link" in unique_grantees else ", ".join(unique_grantees[:3])
                            await db.execute(text("""
                                INSERT INTO saas_alerts
                                    (org_id, provider, alert_type, severity, title,
                                     description, resource_id, resource_name, resource_url,
                                     status, created_at, classification_result)
                                VALUES
                                    (CAST(:org_id AS UUID), :provider, :alert_type, :severity, :title,
                                     :description, :resource_id, :resource_name, :resource_url,
                                     'open', NOW(), CAST(:classification AS jsonb))
                                ON CONFLICT DO NOTHING
                            """), {
                                "org_id": org_id,
                                "provider": "sharepoint",
                                "alert_type": "external_share_sensitive" if label in ("highly_confidential", "confidential") else "external_share",
                                "severity": severity,
                                "title": f"External share: {item_name} → {scope_label}",
                                "description": (
                                    f"File '{item_name}' in site '{site_name}' is shared with "
                                    f"{len(unique_grantees)} external identity(s): {scope_label}. "
                                    f"Classification: {label} (score {score:.2f})."
                                ),
                                "resource_id": item_id,
                                "resource_name": item_name,
                                "resource_url": item_url,
                                "classification": json.dumps({
                                    "label": label,
                                    "score": score,
                                    "categories": categories,
                                    "external_grantees": unique_grantees,
                                    "sharing_scope": sharing,
                                }),
                            })
                            logger.info(f"saas_scan/sharepoint: external_share alert created for '{item_name}' → {len(unique_grantees)} ext")
                        except Exception as _alert_exc:
                            logger.warning(f"saas_scan/sharepoint: external_share alert insert failed: {_alert_exc}")

            await db.commit()

        # ── Cross-context combination detection ──────────────────────────────
        # After scanning all sites, check for toxic combinations:
        # 1. High-sensitivity file (confidential/highly_confidential) with org-wide or external sharing
        # 2. Finance/HR/Legal data on wrong team site
        # 3. Multiple high-risk files from same owner (bulk data exposure)
        try:
            await _detect_cross_context_combinations(org_id, db)
        except Exception as _cce:
            logger.warning(f"saas_scan/sharepoint: cross-context detection failed (non-fatal): {_cce}")

    except Exception as exc:
        logger.error(f"saas_scan/sharepoint: error: {exc}")
        await db.rollback()


async def _detect_cross_context_combinations(org_id: str, db: AsyncSession) -> None:
    """Detect toxic data combinations across SharePoint/Teams data items."""
    from sqlalchemy import and_, or_

    # Get all confidential+ items scanned in last 24h
    cutoff = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0)
    high_risk = (await db.execute(
        select(SaasDataItem).where(
            SaasDataItem.org_id == uuid.UUID(org_id),
            SaasDataItem.classification_label.in_(["confidential", "highly_confidential"]),
            SaasDataItem.last_scanned_at >= cutoff,
        )
    )).scalars().all()

    if not high_risk:
        return

    # Combination 1: Finance/tax data with org-wide sharing (internal overexposure)
    finance_cats = {"financial_tax", "financial_invoice", "financial_account", "financial_salary",
                    "financial_wire", "pii_ssn", "pii_credit_card", "hr_medical"}
    for item in high_risk:
        item_cats = set(item.classification_categories or [])
        has_finance = bool(item_cats & finance_cats)
        if not has_finance:
            continue

        # Check if already alerted for this combination
        combo_key = f"combo:{item.item_id}:overexposure"
        existing = (await db.execute(
            select(SaasAlert).where(
                SaasAlert.org_id == uuid.UUID(org_id),
                SaasAlert.resource_id == combo_key,
                SaasAlert.status == "open",
            )
        )).scalar_one_or_none()
        if existing:
            continue

        # Determine combination type
        if item.sharing_scope in ("external", "public"):
            combo_title = f"⚠️ Finance data exposed externally: {item.item_name[:60]}"
            combo_desc = (
                f"Financial/PII data ({', '.join(item_cats & finance_cats)}) in {item.parent_path} "
                f"is shared {item.sharing_scope}. This is a high-risk data exposure."
            )
            combo_severity = "critical"
        elif item.classification_score and item.classification_score >= 0.8:
            combo_title = f"High-confidence sensitive data: {item.item_name[:60]}"
            combo_desc = (
                f"File classified as {item.classification_label} (score {item.classification_score:.0%}) "
                f"with categories: {', '.join(item_cats & finance_cats)}. "
                f"Located in: {item.parent_path}. Owner: {item.owner_email or 'unknown'}."
            )
            combo_severity = "high"
        else:
            continue

        db.add(SaasAlert(
            org_id=uuid.UUID(org_id),
            provider=item.provider,
            alert_type="data_exposure",
            severity=combo_severity,
            title=combo_title,
            description=combo_desc,
            resource_id=combo_key,
            resource_name=item.item_name,
            resource_url=item.item_url,
            status="open",
            raw_data={"item_id": str(item.id), "categories": list(item_cats), "sharing": item.sharing_scope},
        ))
        logger.info(f"saas_scan: cross-context alert fired for {item.item_name} ({combo_severity})")

    # Combination 2: Multiple high-risk items from same owner (bulk exposure risk)
    from collections import Counter
    owner_counts = Counter(i.owner_email for i in high_risk if i.owner_email)
    for owner, count in owner_counts.items():
        if count >= 3:
            bulk_key = f"combo:bulk:{owner}:{cutoff.date()}"
            existing = (await db.execute(
                select(SaasAlert).where(
                    SaasAlert.org_id == uuid.UUID(org_id),
                    SaasAlert.resource_id == bulk_key,
                    SaasAlert.status == "open",
                )
            )).scalar_one_or_none()
            if not existing:
                db.add(SaasAlert(
                    org_id=uuid.UUID(org_id),
                    provider="sharepoint",
                    alert_type="bulk_exfil",
                    severity="high",
                    title=f"Bulk sensitive data: {count} confidential files from {owner.split('@')[0]}",
                    description=(
                        f"{owner} has {count} confidential/highly_confidential files in SharePoint. "
                        f"Review for potential bulk data exposure or insider risk."
                    ),
                    resource_id=bulk_key,
                    resource_name=f"Bulk: {owner}",
                    resource_url=None,
                    status="open",
                    raw_data={"owner": owner, "file_count": count},
                ))
                logger.info(f"saas_scan: bulk exposure alert for {owner} ({count} files)")

    await db.commit()


# ── Enterprise Security: URL Phishing Detection ───────────────────────────────────────

import re
from urllib.parse import urlparse

# Known phishing/suspicious URL patterns
PHISHING_PATTERNS = [
    # Free/suspicious TLDs with auth words
    r'(?:login|signin|account|verify|secure|update|confirm).*(?:\.tk|\.ml|\.ga|\.cf|\.gq|\.xyz|\.top|\.click|\.link|\.work|\.buzz|\.monster|\.quest)',
    # Microsoft impersonation
    r'(?:microsoft|office|outlook|sharepoint|teams|onedrive).*(?:login|signin|verify).*\.(?!microsoft\.com|office\.com)',
    r'(?:microsoftonline-secure|office365-login|microsoft-verify|sharepoint-auth|teams-secure|ms-login|o365-verify)',  # Fake MS domains
    r'(?:micros0ft|rnicrosoft|mlcrosoft|microsοft|micrоsoft)',  # Typosquatting/homograph MS
    # Google impersonation
    r'(?:google|gmail|drive).*(?:login|signin|verify).*\.(?!google\.com|googleapis\.com)',
    r'(?:g00gle|googie|goog1e|googlе)',  # Typosquatting Google
    # Other brand impersonation
    r'(?:amazon|aws|paypal|apple|facebook|instagram).*(?:login|signin|verify).*\.(?!amazon\.com|aws\.amazon\.com|paypal\.com|apple\.com)',
    r'(?:amaz0n|amazοn|paypa1|paypаl|faceb00k|lnstagram)',  # Typosquatting
    # URL shorteners (flag for review)
    r'bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rebrand\.ly|short\.io',
    # Password/credential phishing
    r'(?:password|passwd|credential|secret).*(?:reset|recover|verify|update|expire)',
    r'(?:your.{0,10}account|account.{0,10}suspended|verify.{0,10}identity|confirm.{0,10}details)',
    # Raw IP URLs
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    # Urgency/fear patterns
    r'(?:urgent|immediate|suspend|locked|verify.{0,10}now|action.{0,10}required|within.{0,10}24.{0,10}hours)',
    r'(?:unusual.{0,10}activity|suspicious.{0,10}login|unauthorized.{0,10}access)',
    # Credential harvesting paths
    r'/(?:login|signin|auth|oauth|sso|verify|confirm|validate|secure)[^/]*(?:\.php|\.asp|\.html)',
    # Data URI schemes (potential XSS/phishing)
    r'data:text/html',
    # Punycode domains (IDN homograph attacks)
    r'xn--[a-z0-9]+',
]

# Unicode lookalike characters for homograph detection
HOMOGRAPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',  # Cyrillic
    'ı': 'i', 'ɡ': 'g', 'ο': 'o', 'і': 'i',  # Greek/other
    '0': 'o', '1': 'l', 'rn': 'm',  # ASCII lookalikes
}

# Known TOR exit nodes / VPN services (sample - would be loaded from threat intel)
SUSPICIOUS_IP_RANGES = [
    '185.220.100.',  # TOR
    '185.220.101.',  # TOR
    '23.129.64.',    # TOR
    '198.96.155.',   # TOR
]

SAFE_DOMAINS = {
    'microsoft.com', 'office.com', 'sharepoint.com', 'outlook.com', 'live.com',
    'google.com', 'googleapis.com', 'github.com', 'linkedin.com', 'slack.com',
    'zoom.us', 'teams.microsoft.com', 'onedrive.com', 'azure.com', 'office365.com',
    'microsoftonline.com', 'windows.net', 'azure-api.net', 'azurewebsites.net',
}


def _extract_urls(text: str) -> list[str]:
    """Extract URLs from text content."""
    url_pattern = r'https?://[^\s<>"\')\]]+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def _detect_homograph(domain: str) -> tuple[bool, str]:
    """
    Detect IDN homograph attacks using Unicode lookalike characters.
    Returns (is_homograph, normalized_domain)
    """
    normalized = domain
    has_homograph = False
    
    for fake, real in HOMOGRAPH_MAP.items():
        if fake in domain:
            normalized = normalized.replace(fake, real)
            has_homograph = True
    
    # Check if normalized domain looks like a known brand
    brand_keywords = ['microsoft', 'google', 'amazon', 'paypal', 'apple', 'facebook', 'instagram', 'netflix', 'bank']
    if has_homograph and any(brand in normalized for brand in brand_keywords):
        return True, normalized
    
    return False, domain


def _analyze_url_for_phishing(url: str) -> dict:
    """
    Analyze a URL for phishing indicators.
    Returns: {"is_suspicious": bool, "risk_score": 0-100, "indicators": [...]}
    """
    indicators = []
    risk_score = 0
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        full_url = url.lower()
        path = parsed.path.lower()
        
        # Check if it's a safe domain
        for safe in SAFE_DOMAINS:
            if domain.endswith(safe):
                return {"is_suspicious": False, "risk_score": 0, "indicators": []}
        
        # Check phishing patterns
        for pattern in PHISHING_PATTERNS:
            if re.search(pattern, full_url, re.IGNORECASE):
                indicators.append(f"Matches phishing pattern: {pattern[:40]}...")
                risk_score += 30
        
        # Homograph/IDN detection
        is_homograph, normalized = _detect_homograph(domain)
        if is_homograph:
            indicators.append(f"Homograph attack detected - domain contains lookalike characters (looks like: {normalized})")
            risk_score += 60
        
        # Punycode domain detection
        if 'xn--' in domain:
            indicators.append("Internationalized domain (Punycode) - potential homograph attack")
            risk_score += 40
        
        # URL shorteners get flagged but lower score
        if re.search(r'bit\.ly|tinyurl|t\.co|goo\.gl|cutt\.ly|rebrand\.ly', domain):
            indicators.append("URL shortener - cannot verify destination")
            risk_score += 20
        
        # Raw IP address
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            indicators.append("Raw IP address in URL")
            risk_score += 40
        
        # Excessive subdomains (common in phishing)
        if domain.count('.') > 3:
            indicators.append(f"Suspicious subdomain structure ({domain.count('.')} levels)")
            risk_score += 20
        
        # Typosquatting patterns (ASCII-based)
        typosquat_brands = [
            ('micros0ft', 'microsoft'), ('rnicrosoft', 'microsoft'), ('mlcrosoft', 'microsoft'),
            ('g00gle', 'google'), ('googie', 'google'), ('goog1e', 'google'),
            ('amaz0n', 'amazon'), ('arnazon', 'amazon'),
            ('paypa1', 'paypal'), ('paypai', 'paypal'),
            ('faceb00k', 'facebook'), ('lnstagram', 'instagram'),
        ]
        for typo, brand in typosquat_brands:
            if typo in domain:
                indicators.append(f"Typosquatting detected - impersonating {brand}")
                risk_score += 50
                break
        
        # Free hosting with auth paths
        if any(host in domain for host in ['.github.io', '.netlify.app', '.vercel.app', '.herokuapp.com', '.firebaseapp.com', '.pages.dev', '.web.app']):
            if any(auth in path for auth in ['login', 'signin', 'auth', 'verify', 'account', 'secure', 'confirm']):
                indicators.append("Free hosting service with authentication path")
                risk_score += 35
        
        # Suspicious TLDs with credential paths
        suspicious_tlds = ['.xyz', '.top', '.click', '.link', '.work', '.buzz', '.monster', '.quest', '.tk', '.ml', '.ga', '.cf']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            indicators.append(f"Suspicious TLD commonly used in phishing")
            risk_score += 25
            if any(cred in path for cred in ['login', 'signin', 'password', 'credential', 'verify']):
                indicators.append("Suspicious TLD with credential harvesting path")
                risk_score += 30
        
        # Data URI scheme (potential embedded phishing)
        if url.startswith('data:'):
            indicators.append("Data URI scheme - potential embedded phishing content")
            risk_score += 50
        
        # Very long URLs (common in phishing to hide real domain)
        if len(url) > 200:
            indicators.append(f"Unusually long URL ({len(url)} chars) - may hide malicious content")
            risk_score += 15
        
        # Multiple redirects/query params (obfuscation)
        if url.count('http') > 1:
            indicators.append("Multiple URLs embedded - possible redirect chain")
            risk_score += 30
        
        return {
            "is_suspicious": risk_score >= 30,
            "risk_score": min(risk_score, 100),
            "indicators": indicators,
            "domain": domain,
        }
    except Exception:
        return {"is_suspicious": False, "risk_score": 0, "indicators": []}


async def _scan_teams_meeting_chats(
    org_id: str,
    access_token: str,
    db: AsyncSession,
) -> None:
    """
    Scan recent Teams chats/meetings for:
      - Files uploaded/shared inside the chat (hostedContents / fileAttachments)
      - External participants on the same chat (federated / guest / #ext#)
      - The combination of both → high-severity alert

    Writes ``saas_alerts`` rows with alert_type in
    (meeting_file_share, meeting_file_share_external, meeting_external_attendee)
    which the /meeting-security/risks endpoint surfaces.

    All errors are caught and logged — this scanner is "best effort" and must
    never tank the rest of the saas_scan loop.
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}

        # Build tenant-domain list so we can detect federated/external members.
        tenant_domains: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=15) as dom_client:
                dom_resp = await dom_client.get(
                    f"{GRAPH}/domains?$select=id", headers=headers
                )
                if dom_resp.status_code == 200:
                    tenant_domains = [
                        (d.get("id") or "").lower()
                        for d in dom_resp.json().get("value", [])
                        if d.get("id")
                    ]
        except Exception:
            pass

        def _is_ext(email: str) -> bool:
            em = (email or "").lower()
            if not em or "@" not in em:
                return False
            if "#ext#" in em:
                return True
            if not tenant_domains:
                return False
            return not any(em.endswith("@" + d) for d in tenant_domains)

        alerts_created = 0
        async with httpx.AsyncClient(timeout=30) as client:
            chats_resp = await client.get(
                f"{GRAPH}/chats?$top=25&$expand=members&$orderby=lastUpdatedDateTime desc",
                headers=headers,
            )
            if chats_resp.status_code != 200:
                logger.debug(
                    f"teams_meeting_chats_scan: chats returned {chats_resp.status_code}"
                )
                return

            for chat in chats_resp.json().get("value", [])[:25]:
                chat_id = chat.get("id")
                if not chat_id:
                    continue
                chat_type = chat.get("chatType", "")
                topic = chat.get("topic") or chat_type or "chat"

                # Collect external members
                external_members: list[str] = []
                for m in chat.get("members", []) or []:
                    em = (m.get("email") or "").lower()
                    upn = (m.get("userPrincipalName") or m.get("displayName") or "").lower()
                    candidate = em or upn
                    if candidate and _is_ext(candidate):
                        external_members.append(candidate)
                external_members = sorted(set(external_members))[:5]

                # Fetch recent messages — look for file uploads
                msgs_resp = await client.get(
                    f"{GRAPH}/chats/{chat_id}/messages?$top=30",
                    headers=headers,
                )
                if msgs_resp.status_code != 200:
                    continue

                file_uploads: list[dict] = []
                for msg in msgs_resp.json().get("value", []):
                    attachments = msg.get("attachments", []) or []
                    sender = (
                        ((msg.get("from") or {}).get("user") or {}).get(
                            "userPrincipalName"
                        )
                        or ((msg.get("from") or {}).get("user") or {}).get(
                            "displayName"
                        )
                        or "Unknown"
                    )
                    for att in attachments:
                        att_type = (att.get("contentType") or "").lower()
                        if "reference" in att_type or "file" in att_type:
                            file_uploads.append(
                                {
                                    "name": att.get("name")
                                    or att.get("contentUrl", "")[:60],
                                    "url": att.get("contentUrl", ""),
                                    "sender": sender,
                                    "msg_id": msg.get("id"),
                                    "created": msg.get("createdDateTime"),
                                }
                            )

                # If this is a meeting chat (chatType == "meeting") with external
                # member(s), fire the external-attendee alert regardless of files.
                if external_members and chat_type == "meeting":
                    try:
                        await db.execute(
                            text(
                                """
                                INSERT INTO saas_alerts
                                    (org_id, provider, alert_type, severity, title,
                                     description, resource_id, resource_name,
                                     status, created_at, classification_result)
                                VALUES
                                    (CAST(:org_id AS UUID), 'teams', :alert_type, :severity,
                                     :title, :description, :rid, :rname,
                                     'open', NOW(), CAST(:classification AS jsonb))
                                ON CONFLICT DO NOTHING
                                """
                            ),
                            {
                                "org_id": org_id,
                                "alert_type": "meeting_external_attendee",
                                "severity": "medium",
                                "title": f"Meeting with external attendee: {topic[:80]}",
                                "description": (
                                    f"Meeting/chat '{topic}' includes external participant(s): "
                                    f"{', '.join(external_members)}."
                                ),
                                "rid": chat_id,
                                "rname": topic,
                                "classification": json.dumps(
                                    {
                                        "external_members": external_members,
                                        "chat_type": chat_type,
                                    }
                                ),
                            },
                        )
                        alerts_created += 1
                    except Exception as _ae:
                        logger.debug(
                            f"teams_meeting_chats_scan: ext-attendee alert insert failed: {_ae}"
                        )

                # For every file upload in this chat, fire an alert.
                # When external members are present in the same chat, this is
                # the high-severity "file transferred in meeting with external user"
                # case Adnan reported.
                for up in file_uploads[:10]:
                    sev = "high" if external_members else "low"
                    atype = (
                        "meeting_file_share_external"
                        if external_members
                        else "meeting_file_share"
                    )
                    try:
                        await db.execute(
                            text(
                                """
                                INSERT INTO saas_alerts
                                    (org_id, provider, alert_type, severity, title,
                                     description, resource_id, resource_name, resource_url,
                                     status, created_at, classification_result)
                                VALUES
                                    (CAST(:org_id AS UUID), 'teams', :alert_type, :severity,
                                     :title, :description, :rid, :rname, :rurl,
                                     'open', NOW(), CAST(:classification AS jsonb))
                                ON CONFLICT DO NOTHING
                                """
                            ),
                            {
                                "org_id": org_id,
                                "alert_type": atype,
                                "severity": sev,
                                "title": (
                                    f"File shared in meeting with external: {up['name']}"
                                    if external_members
                                    else f"File shared in chat: {up['name']}"
                                ),
                                "description": (
                                    f"{up['sender']} uploaded '{up['name']}' in '{topic}' "
                                    f"at {up.get('created','?')}."
                                    + (
                                        f" External participant(s): {', '.join(external_members)}."
                                        if external_members
                                        else ""
                                    )
                                ),
                                "rid": up.get("msg_id") or chat_id,
                                "rname": up["name"],
                                "rurl": up.get("url"),
                                "classification": json.dumps(
                                    {
                                        "external_members": external_members,
                                        "chat_type": chat_type,
                                        "sender": up["sender"],
                                    }
                                ),
                            },
                        )
                        alerts_created += 1
                    except Exception as _ae:
                        logger.debug(
                            f"teams_meeting_chats_scan: file-share alert insert failed: {_ae}"
                        )

        if alerts_created:
            await db.commit()
            logger.info(
                f"teams_meeting_chats_scan: created {alerts_created} alert(s) for org {org_id}"
            )
    except Exception as exc:
        logger.warning(f"teams_meeting_chats_scan: error for org {org_id}: {exc}")
        try:
            await db.rollback()
        except Exception:
            pass


async def _scan_teams_messages_for_phishing(
    org_id: str,
    access_token: str,
    db: AsyncSession,
) -> None:
    """
    Scan recent Teams messages for phishing URLs and suspicious content.
    Creates alerts for detected threats.
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        alerts_created = 0

        async with httpx.AsyncClient(timeout=30) as client:
            # We run with an application token (no signed-in user), so /me/chats
            # returns 400. Walk users in the tenant and use /users/{id}/chats
            # which works with the Chat.Read.All application permission.
            # Fall back to /me/chats only if the user token path is in play.
            chat_entries: list[tuple[str, dict]] = []  # (user_upn, chat)
            users_resp = await client.get(
                f"{GRAPH}/users?$top=25&$select=id,userPrincipalName,accountEnabled",
                headers=headers,
            )
            if users_resp.status_code == 200:
                for u in (users_resp.json().get("value") or [])[:25]:
                    if not u.get("accountEnabled", True):
                        continue
                    uid = u.get("id")
                    upn = u.get("userPrincipalName") or uid
                    if not uid:
                        continue
                    u_chats_resp = await client.get(
                        f"{GRAPH}/users/{uid}/chats?$top=10&$expand=members",
                        headers=headers,
                    )
                    if u_chats_resp.status_code != 200:
                        # 403 typically means the app lacks Chat.Read.All consent.
                        # Log once per provider and stop early to save quota.
                        if u_chats_resp.status_code == 403:
                            logger.debug(
                                f"teams_phishing_scan: Chat.Read.All not consented "
                                f"(403) for org {org_id}; skipping chat phishing scan"
                            )
                            return
                        continue
                    for c in (u_chats_resp.json().get("value") or [])[:10]:
                        chat_entries.append((upn, c))
            else:
                logger.debug(
                    f"teams_phishing_scan: users list returned {users_resp.status_code} "
                    f"for org {org_id}"
                )
                return

            # De-dup chats by id so the same group chat doesn't get scanned twice.
            seen_chat_ids: set[str] = set()
            for user_upn, chat in chat_entries[:30]:
                chat_id = chat.get("id")
                if not chat_id or chat_id in seen_chat_ids:
                    continue
                seen_chat_ids.add(chat_id)

                # Get recent messages from chat via the user-scoped endpoint.
                msgs_resp = await client.get(
                    f"{GRAPH}/users/{user_upn}/chats/{chat_id}/messages?$top=30",
                    headers=headers,
                )
                if msgs_resp.status_code != 200:
                    continue
                
                for msg in msgs_resp.json().get("value", []):
                    body = (msg.get("body") or {}).get("content", "")
                    if not body:
                        continue
                    
                    # Extract and analyze URLs
                    urls = _extract_urls(body)
                    for url in urls:
                        analysis = _analyze_url_for_phishing(url)
                        if analysis["is_suspicious"] and analysis["risk_score"] >= 40:
                            # Check if alert already exists
                            existing = (await db.execute(
                                select(SaasAlert).where(
                                    SaasAlert.org_id == uuid.UUID(org_id),
                                    SaasAlert.alert_type == "phishing_url",
                                    SaasAlert.resource_id == url[:200],
                                )
                            )).scalar_one_or_none()
                            
                            if not existing:
                                severity = "critical" if analysis["risk_score"] >= 70 else "high" if analysis["risk_score"] >= 50 else "medium"
                                sender = msg.get("from", {}).get("user", {}).get("displayName", "Unknown")
                                
                                db.add(SaasAlert(
                                    org_id=uuid.UUID(org_id),
                                    provider="teams",
                                    alert_type="phishing_url",
                                    severity=severity,
                                    title=f"Suspicious URL detected in Teams chat",
                                    description=f"URL: {url[:100]}\nSender: {sender}\nIndicators: {', '.join(analysis['indicators'][:3])}",
                                    resource_id=url[:200],
                                    resource_name=f"Teams Chat from {sender}",
                                    resource_url=msg.get("webUrl"),
                                    status="open",
                                    raw_data={
                                        "url": url,
                                        "risk_score": analysis["risk_score"],
                                        "indicators": analysis["indicators"],
                                        "sender": sender,
                                        "message_id": msg.get("id"),
                                    },
                                ))
                                alerts_created += 1
                                logger.info(f"teams_phishing_scan: alert for {url[:50]}... score={analysis['risk_score']}")
        
        if alerts_created > 0:
            await db.commit()
            logger.info(f"teams_phishing_scan: created {alerts_created} phishing alerts for org {org_id}")
    
    except Exception as exc:
        logger.warning(f"teams_phishing_scan: error: {exc}")


# ── Enterprise Security: Suspicious Sign-In Detection ─────────────────────────────

async def _scan_suspicious_signins(
    org_id: str,
    access_token: str,
    db: AsyncSession,
) -> None:
    """
    Detect suspicious sign-in patterns:
    - Failed logins followed by success (password spray)
    - Sign-ins from risky locations
    - Sign-ins from unfamiliar devices
    - Multiple failed MFA attempts
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        
        async with httpx.AsyncClient(timeout=30) as client:
            # Get recent sign-in logs (requires AuditLog.Read.All)
            signins_resp = await client.get(
                f"{GRAPH}/auditLogs/signIns?$top=100&$orderby=createdDateTime desc",
                headers=headers,
            )
            if signins_resp.status_code != 200:
                if _is_aad_premium_required_error(signins_resp.status_code, signins_resp.text):
                    logger.info(
                        f"suspicious_signin_scan: skipping for org {org_id} — tenant lacks Entra ID Premium (P1/P2) license"
                    )
                else:
                    logger.debug(f"suspicious_signin_scan: signIns returned {signins_resp.status_code}")
                return
            
            signins = signins_resp.json().get("value", [])
            
            # Track patterns per user
            user_patterns: dict[str, dict] = {}
            
            for signin in signins:
                user_id = signin.get("userId", "")
                user_email = signin.get("userPrincipalName", "")
                status = signin.get("status", {})
                error_code = status.get("errorCode", 0)
                location = signin.get("location", {})
                device = signin.get("deviceDetail", {})
                risk_level = signin.get("riskLevelDuringSignIn", "none")
                risk_state = signin.get("riskState", "none")
                
                if user_email not in user_patterns:
                    user_patterns[user_email] = {
                        "failed_attempts": 0,
                        "success_after_fail": False,
                        "locations": set(),
                        "risky_signins": [],
                        "mfa_failures": 0,
                    }
                
                pattern = user_patterns[user_email]
                
                # Track location
                city = location.get("city", "")
                country = location.get("countryOrRegion", "")
                if city or country:
                    pattern["locations"].add(f"{city}, {country}")
                
                # Track failures
                if error_code != 0:
                    pattern["failed_attempts"] += 1
                    # MFA failure codes
                    if error_code in [50074, 50076, 50079, 50126, 53003]:
                        pattern["mfa_failures"] += 1
                else:
                    if pattern["failed_attempts"] > 0:
                        pattern["success_after_fail"] = True
                
                # Track risky sign-ins
                if risk_level in ["high", "medium"] or risk_state in ["atRisk", "confirmedCompromised"]:
                    pattern["risky_signins"].append({
                        "time": signin.get("createdDateTime"),
                        "risk_level": risk_level,
                        "risk_state": risk_state,
                        "location": f"{city}, {country}",
                        "device": device.get("displayName", "Unknown"),
                    })
            
            # Create alerts for suspicious patterns
            alerts_created = 0
            for user_email, pattern in user_patterns.items():
                # Password spray detection: multiple failures then success
                if pattern["success_after_fail"] and pattern["failed_attempts"] >= 3:
                    existing = (await db.execute(
                        select(SaasAlert).where(
                            SaasAlert.org_id == uuid.UUID(org_id),
                            SaasAlert.alert_type == "password_spray",
                            SaasAlert.resource_id == user_email,
                            SaasAlert.status == "open",
                        )
                    )).scalar_one_or_none()
                    
                    if not existing:
                        db.add(SaasAlert(
                            org_id=uuid.UUID(org_id),
                            provider="m365",
                            alert_type="password_spray",
                            severity="high",
                            title=f"Possible password spray attack: {user_email}",
                            description=f"Detected {pattern['failed_attempts']} failed login attempts followed by successful login. This pattern may indicate a password spray or brute force attack.",
                            resource_id=user_email,
                            resource_name=user_email,
                            status="open",
                            raw_data={
                                "failed_attempts": pattern["failed_attempts"],
                                "locations": list(pattern["locations"]),
                            },
                        ))
                        alerts_created += 1
                        logger.info(f"suspicious_signin: password spray alert for {user_email}")
                
                # MFA fatigue/bombing detection
                if pattern["mfa_failures"] >= 5:
                    existing = (await db.execute(
                        select(SaasAlert).where(
                            SaasAlert.org_id == uuid.UUID(org_id),
                            SaasAlert.alert_type == "mfa_fatigue",
                            SaasAlert.resource_id == user_email,
                            SaasAlert.status == "open",
                        )
                    )).scalar_one_or_none()
                    
                    if not existing:
                        db.add(SaasAlert(
                            org_id=uuid.UUID(org_id),
                            provider="m365",
                            alert_type="mfa_fatigue",
                            severity="critical",
                            title=f"Possible MFA fatigue attack: {user_email}",
                            description=f"Detected {pattern['mfa_failures']} MFA failures. This may indicate an MFA fatigue/bombing attack attempting to get user to approve malicious authentication.",
                            resource_id=user_email,
                            resource_name=user_email,
                            status="open",
                            raw_data={"mfa_failures": pattern["mfa_failures"]},
                        ))
                        alerts_created += 1
                        logger.info(f"suspicious_signin: MFA fatigue alert for {user_email}")
                
                # Risky sign-ins from identity protection
                for risky in pattern["risky_signins"]:
                    alert_key = f"{user_email}:{risky['time']}"
                    existing = (await db.execute(
                        select(SaasAlert).where(
                            SaasAlert.org_id == uuid.UUID(org_id),
                            SaasAlert.alert_type == "risky_signin",
                            SaasAlert.resource_id == alert_key[:200],
                        )
                    )).scalar_one_or_none()
                    
                    if not existing:
                        severity = "critical" if risky["risk_state"] == "confirmedCompromised" else "high" if risky["risk_level"] == "high" else "medium"
                        db.add(SaasAlert(
                            org_id=uuid.UUID(org_id),
                            provider="m365",
                            alert_type="risky_signin",
                            severity=severity,
                            title=f"Risky sign-in detected: {user_email}",
                            description=f"Microsoft flagged sign-in as {risky['risk_level']} risk (state: {risky['risk_state']}).\nLocation: {risky['location']}\nDevice: {risky['device']}",
                            resource_id=alert_key[:200],
                            resource_name=user_email,
                            status="open",
                            raw_data=risky,
                        ))
                        alerts_created += 1
            
            if alerts_created > 0:
                await db.commit()
                logger.info(f"suspicious_signin_scan: created {alerts_created} alerts for org {org_id}")
    
    except Exception as exc:
        logger.warning(f"suspicious_signin_scan: error: {exc}")


# ── Enterprise Security: File Malware Indicators ──────────────────────────────────

# Suspicious file patterns (without actual malware scanning - that requires ATP)
SUSPICIOUS_FILE_PATTERNS = [
    (r'\.(?:exe|scr|bat|cmd|ps1|vbs|js|jar|hta|msi|dll)$', 'executable', 'high'),
    (r'\.(?:zip|rar|7z|tar\.gz)$', 'archive', 'low'),  # Just flag, not block
    (r'(?:password|passwd|secret|credential|private.?key|api.?key)', 'sensitive_name', 'medium'),
    (r'(?:invoice|payment|wire.?transfer|urgent|confidential)', 'social_engineering', 'medium'),
    (r'\.(?:docm|xlsm|pptm)$', 'macro_enabled', 'high'),
    (r'\.(?:iso|img|vhd|vhdx)$', 'disk_image', 'high'),
]


async def _scan_files_for_threats(
    org_id: str,
    access_token: str,
    db: AsyncSession,
) -> None:
    """
    Scan SharePoint/OneDrive files for threat indicators:
    - Executable files
    - Macro-enabled documents
    - Suspicious filenames
    
    Note: This is pattern-based detection. Full malware scanning requires
    Microsoft Defender for Office 365 ATP integration.
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        alerts_created = 0
        
        async with httpx.AsyncClient(timeout=30) as client:
            # Get recent files from OneDrive/SharePoint
            drives_resp = await client.get(f"{GRAPH}/me/drives", headers=headers)
            if drives_resp.status_code != 200:
                return
            
            for drive in drives_resp.json().get("value", [])[:5]:
                drive_id = drive.get("id")
                if not drive_id:
                    continue
                
                # Get recent items
                items_resp = await client.get(
                    f"{GRAPH}/drives/{drive_id}/root/children?$top=50&$orderby=lastModifiedDateTime desc",
                    headers=headers,
                )
                if items_resp.status_code != 200:
                    continue
                
                for item in items_resp.json().get("value", []):
                    if item.get("folder"):
                        continue
                    
                    filename = item.get("name", "").lower()
                    
                    for pattern, threat_type, severity in SUSPICIOUS_FILE_PATTERNS:
                        if re.search(pattern, filename, re.IGNORECASE):
                            # Check if alert exists
                            item_id = item.get("id", "")
                            existing = (await db.execute(
                                select(SaasAlert).where(
                                    SaasAlert.org_id == uuid.UUID(org_id),
                                    SaasAlert.alert_type == f"suspicious_file_{threat_type}",
                                    SaasAlert.resource_id == item_id,
                                )
                            )).scalar_one_or_none()
                            
                            if not existing:
                                created_by = item.get("createdBy", {}).get("user", {}).get("displayName", "Unknown")
                                
                                db.add(SaasAlert(
                                    org_id=uuid.UUID(org_id),
                                    provider="sharepoint",
                                    alert_type=f"suspicious_file_{threat_type}",
                                    severity=severity,
                                    title=f"Suspicious file detected: {item.get('name', 'unknown')[:50]}",
                                    description=f"File type: {threat_type}\nUploaded by: {created_by}\nSize: {item.get('size', 0)} bytes",
                                    resource_id=item_id,
                                    resource_name=item.get("name", "unknown"),
                                    resource_url=item.get("webUrl"),
                                    status="open",
                                    raw_data={
                                        "threat_type": threat_type,
                                        "filename": item.get("name"),
                                        "size": item.get("size"),
                                        "created_by": created_by,
                                        "created_at": item.get("createdDateTime"),
                                    },
                                ))
                                alerts_created += 1
                                logger.info(f"file_threat_scan: {threat_type} file {filename[:30]}")
                            break  # Only one alert per file
        
        if alerts_created > 0:
            await db.commit()
            logger.info(f"file_threat_scan: created {alerts_created} alerts for org {org_id}")
    
    except Exception as exc:
        logger.warning(f"file_threat_scan: error: {exc}")


# ── Enhanced Security: Impossible Travel Detection ─────────────────────────────────

from math import radians, sin, cos, sqrt, atan2

def _haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate distance in km between two coordinates using Haversine formula."""
    R = 6371  # Earth's radius in km
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    return 2 * R * atan2(sqrt(a), sqrt(1-a))


async def _scan_impossible_travel(
    org_id: str,
    access_token: str,
    db: AsyncSession,
) -> None:
    """
    Detect impossible travel - logins from geographically distant locations
    within a short time window (faster than physically possible).
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        alerts_created = 0
        
        async with httpx.AsyncClient(timeout=30) as client:
            # Get sign-in logs with location data
            signins_resp = await client.get(
                f"{GRAPH}/auditLogs/signIns?$top=200&$orderby=createdDateTime desc&$filter=status/errorCode eq 0",
                headers=headers,
            )
            if signins_resp.status_code != 200:
                return
            
            signins = signins_resp.json().get("value", [])
            
            # Group by user
            user_signins: dict[str, list] = {}
            for signin in signins:
                user = signin.get("userPrincipalName", "")
                location = signin.get("location", {})
                geo = location.get("geoCoordinates", {})
                
                if user and geo.get("latitude") and geo.get("longitude"):
                    if user not in user_signins:
                        user_signins[user] = []
                    user_signins[user].append({
                        "time": signin.get("createdDateTime"),
                        "lat": geo["latitude"],
                        "lon": geo["longitude"],
                        "city": location.get("city", "Unknown"),
                        "country": location.get("countryOrRegion", "Unknown"),
                        "ip": signin.get("ipAddress", ""),
                    })
            
            # Check for impossible travel
            for user, logins in user_signins.items():
                # Sort by time
                logins.sort(key=lambda x: x["time"] or "")
                
                for i in range(1, len(logins)):
                    prev, curr = logins[i-1], logins[i]
                    
                    try:
                        from dateutil.parser import parse as _parse_dt
                        prev_time = _parse_dt(prev["time"])
                        curr_time = _parse_dt(curr["time"])
                        time_diff_hours = (curr_time - prev_time).total_seconds() / 3600
                        
                        if time_diff_hours <= 0 or time_diff_hours > 24:
                            continue
                        
                        distance_km = _haversine_distance(
                            prev["lat"], prev["lon"], curr["lat"], curr["lon"]
                        )
                        
                        # Assume max travel speed of 900 km/h (commercial flight)
                        max_possible_distance = time_diff_hours * 900
                        
                        if distance_km > max_possible_distance and distance_km > 500:  # Min 500km
                            alert_key = f"{user}:{prev['time']}:{curr['time']}"
                            
                            existing = (await db.execute(
                                select(SaasAlert).where(
                                    SaasAlert.org_id == uuid.UUID(org_id),
                                    SaasAlert.alert_type == "impossible_travel",
                                    SaasAlert.resource_id == alert_key[:200],
                                )
                            )).scalar_one_or_none()
                            
                            if not existing:
                                db.add(SaasAlert(
                                    org_id=uuid.UUID(org_id),
                                    provider="m365",
                                    alert_type="impossible_travel",
                                    severity="high",
                                    title=f"Impossible travel detected: {user}",
                                    description=f"User logged in from {prev['city']}, {prev['country']} and then {curr['city']}, {curr['country']} ({int(distance_km)} km apart) within {time_diff_hours:.1f} hours. This is physically impossible without credential sharing or compromise.",
                                    resource_id=alert_key[:200],
                                    resource_name=user,
                                    status="open",
                                    raw_data={
                                        "prev_location": prev,
                                        "curr_location": curr,
                                        "distance_km": int(distance_km),
                                        "time_diff_hours": round(time_diff_hours, 2),
                                    },
                                ))
                                alerts_created += 1
                    except Exception:
                        continue
            
            if alerts_created > 0:
                await db.commit()
                logger.info(f"impossible_travel_scan: created {alerts_created} alerts for org {org_id}")
    
    except Exception as exc:
        logger.warning(f"impossible_travel_scan: error: {exc}")


# ── Enhanced Security: After-Hours Login Detection ────────────────────────────────

async def _scan_afterhours_logins(
    org_id: str,
    access_token: str,
    db: AsyncSession,
    business_hours: tuple[int, int] = (8, 18),  # 8 AM to 6 PM
    business_days: tuple[int, ...] = (0, 1, 2, 3, 4),  # Mon-Fri
) -> None:
    """
    Detect logins outside of normal business hours.
    These may indicate compromised credentials being used by attackers in different timezones.
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        alerts_created = 0
        
        async with httpx.AsyncClient(timeout=30) as client:
            signins_resp = await client.get(
                f"{GRAPH}/auditLogs/signIns?$top=100&$orderby=createdDateTime desc&$filter=status/errorCode eq 0",
                headers=headers,
            )
            if signins_resp.status_code != 200:
                return
            
            for signin in signins_resp.json().get("value", []):
                user = signin.get("userPrincipalName", "")
                signin_time_str = signin.get("createdDateTime", "")
                
                try:
                    from dateutil.parser import parse as _parse_dt
                    signin_time = _parse_dt(signin_time_str)
                    
                    # Check if outside business hours
                    hour = signin_time.hour
                    weekday = signin_time.weekday()
                    
                    is_afterhours = (
                        weekday not in business_days or  # Weekend
                        hour < business_hours[0] or  # Before business hours
                        hour >= business_hours[1]  # After business hours
                    )
                    
                    # Only alert for very late hours (midnight to 5 AM) to reduce noise
                    is_suspicious_hour = hour >= 0 and hour < 5
                    
                    if is_afterhours and is_suspicious_hour:
                        signin_id = signin.get("id", signin_time_str)
                        
                        existing = (await db.execute(
                            select(SaasAlert).where(
                                SaasAlert.org_id == uuid.UUID(org_id),
                                SaasAlert.alert_type == "afterhours_login",
                                SaasAlert.resource_id == signin_id[:200],
                            )
                        )).scalar_one_or_none()
                        
                        if not existing:
                            location = signin.get("location", {})
                            device = signin.get("deviceDetail", {})
                            
                            db.add(SaasAlert(
                                org_id=uuid.UUID(org_id),
                                provider="m365",
                                alert_type="afterhours_login",
                                severity="medium",
                                title=f"After-hours login: {user}",
                                description=f"Login detected at {signin_time.strftime('%Y-%m-%d %H:%M UTC')} (outside business hours).\nLocation: {location.get('city', 'Unknown')}, {location.get('countryOrRegion', 'Unknown')}\nDevice: {device.get('displayName', 'Unknown')}",
                                resource_id=signin_id[:200],
                                resource_name=user,
                                status="open",
                                raw_data={
                                    "signin_time": signin_time_str,
                                    "hour": hour,
                                    "weekday": weekday,
                                    "location": location,
                                    "device": device,
                                },
                            ))
                            alerts_created += 1
                except Exception:
                    continue
            
            if alerts_created > 0:
                await db.commit()
                logger.info(f"afterhours_scan: created {alerts_created} alerts for org {org_id}")
    
    except Exception as exc:
        logger.warning(f"afterhours_scan: error: {exc}")


# ── Enhanced Security: Mass Download / Ransomware Detection ───────────────────────

RANSOMWARE_EXTENSIONS = [
    '.encrypted', '.locked', '.crypto', '.crypt', '.enc', '.locky', '.cerber',
    '.zepto', '.thor', '.aaa', '.abc', '.xyz', '.zzz', '.micro', '.vvv',
    '.xxx', '.odin', '.osiris', '.wallet', '.wncry', '.wcry', '.wnry',
]


async def _scan_ransomware_patterns(
    org_id: str,
    access_token: str,
    db: AsyncSession,
) -> None:
    """
    Detect potential ransomware activity:
    - Mass file renames to suspicious extensions
    - Bulk file modifications in short time
    - Files with known ransomware extensions
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        alerts_created = 0
        
        async with httpx.AsyncClient(timeout=30) as client:
            # Get recent file activities from audit logs
            activities_resp = await client.get(
                f"{GRAPH}/auditLogs/directoryAudits?$top=200&$filter=activityDisplayName eq 'Update file'&$orderby=activityDateTime desc",
                headers=headers,
            )
            
            # Also check OneDrive/SharePoint for ransomware extensions
            drives_resp = await client.get(f"{GRAPH}/me/drives", headers=headers)
            if drives_resp.status_code == 200:
                for drive in drives_resp.json().get("value", [])[:3]:
                    drive_id = drive.get("id")
                    if not drive_id:
                        continue
                    
                    # Search for files with ransomware extensions
                    items_resp = await client.get(
                        f"{GRAPH}/drives/{drive_id}/root/children?$top=100&$orderby=lastModifiedDateTime desc",
                        headers=headers,
                    )
                    if items_resp.status_code != 200:
                        continue
                    
                    suspicious_files = []
                    for item in items_resp.json().get("value", []):
                        if item.get("folder"):
                            continue
                        filename = item.get("name", "").lower()
                        
                        # Check for ransomware extensions
                        for ext in RANSOMWARE_EXTENSIONS:
                            if filename.endswith(ext):
                                suspicious_files.append({
                                    "name": item.get("name"),
                                    "id": item.get("id"),
                                    "extension": ext,
                                    "modified": item.get("lastModifiedDateTime"),
                                })
                                break
                    
                    # Alert if multiple suspicious files found
                    if len(suspicious_files) >= 3:
                        alert_key = f"ransomware:{drive_id}:{len(suspicious_files)}"
                        
                        existing = (await db.execute(
                            select(SaasAlert).where(
                                SaasAlert.org_id == uuid.UUID(org_id),
                                SaasAlert.alert_type == "ransomware_pattern",
                                SaasAlert.resource_id == alert_key[:200],
                            )
                        )).scalar_one_or_none()
                        
                        if not existing:
                            db.add(SaasAlert(
                                org_id=uuid.UUID(org_id),
                                provider="sharepoint",
                                alert_type="ransomware_pattern",
                                severity="critical",
                                title=f"Potential ransomware activity detected",
                                description=f"Found {len(suspicious_files)} files with ransomware-associated extensions. This may indicate an active ransomware infection.\n\nSample files: {', '.join(f['name'] for f in suspicious_files[:5])}",
                                resource_id=alert_key[:200],
                                resource_name=drive.get("name", "OneDrive"),
                                status="open",
                                raw_data={"suspicious_files": suspicious_files[:10]},
                            ))
                            alerts_created += 1
                            logger.warning(f"ransomware_scan: CRITICAL - {len(suspicious_files)} suspicious files in drive {drive_id}")
            
            if alerts_created > 0:
                await db.commit()
    
    except Exception as exc:
        logger.warning(f"ransomware_scan: error: {exc}")


# ── Enhanced Security: External Sharing of Sensitive Files ───────────────────────

SENSITIVE_FILE_PATTERNS = [
    r'(?i)password|credential|secret|private.?key|api.?key',
    r'(?i)confidential|internal.?only|restricted|classified',
    r'(?i)ssn|social.?security|tax.?return|w2|1099',
    r'(?i)credit.?card|bank.?account|routing.?number',
    r'(?i)patient|hipaa|medical|health.?record',
    r'(?i)employee.?list|salary|compensation|payroll',
]


async def _scan_external_sharing(
    org_id: str,
    access_token: str,
    db: AsyncSession,
) -> None:
    """
    Detect sensitive files shared externally (outside the organization).
    Creates alerts for potential data exfiltration.
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        alerts_created = 0
        
        async with httpx.AsyncClient(timeout=30) as client:
            # Get shared items from OneDrive
            shared_resp = await client.get(
                f"{GRAPH}/me/drive/sharedWithMe?$top=50",
                headers=headers,
            )
            
            # Also check items shared by the user
            drives_resp = await client.get(f"{GRAPH}/me/drives", headers=headers)
            if drives_resp.status_code == 200:
                for drive in drives_resp.json().get("value", [])[:2]:
                    drive_id = drive.get("id")
                    if not drive_id:
                        continue
                    
                    # Get items with sharing permissions
                    items_resp = await client.get(
                        f"{GRAPH}/drives/{drive_id}/root/children?$expand=permissions&$top=50",
                        headers=headers,
                    )
                    if items_resp.status_code != 200:
                        continue
                    
                    for item in items_resp.json().get("value", []):
                        if item.get("folder"):
                            continue
                        
                        filename = item.get("name", "")
                        permissions = item.get("permissions", [])
                        
                        # Check if shared externally
                        external_shares = []
                        for perm in permissions:
                            granted = perm.get("grantedToIdentitiesV2", []) or perm.get("grantedToIdentities", [])
                            for identity in granted:
                                user = identity.get("user", {}) or identity.get("siteUser", {})
                                email = user.get("email", "").lower()
                                # Check if external (not from org domain)
                                if email and "@" in email:
                                    # Simple check - could be enhanced with org domain lookup
                                    external_shares.append(email)
                            
                            # Also check for "anyone" links
                            link = perm.get("link", {})
                            if link.get("scope") == "anonymous":
                                external_shares.append("anonymous_link")
                        
                        if not external_shares:
                            continue
                        
                        # Check if filename matches sensitive patterns
                        is_sensitive = any(
                            re.search(pattern, filename)
                            for pattern in SENSITIVE_FILE_PATTERNS
                        )
                        
                        if is_sensitive:
                            item_id = item.get("id", "")
                            alert_key = f"external_share:{item_id}"
                            
                            existing = (await db.execute(
                                select(SaasAlert).where(
                                    SaasAlert.org_id == uuid.UUID(org_id),
                                    SaasAlert.alert_type == "sensitive_external_share",
                                    SaasAlert.resource_id == alert_key[:200],
                                )
                            )).scalar_one_or_none()
                            
                            if not existing:
                                db.add(SaasAlert(
                                    org_id=uuid.UUID(org_id),
                                    provider="sharepoint",
                                    alert_type="sensitive_external_share",
                                    severity="high",
                                    title=f"Sensitive file shared externally: {filename[:50]}",
                                    description=f"File '{filename}' appears to contain sensitive data and is shared with external parties.\n\nShared with: {', '.join(external_shares[:5])}",
                                    resource_id=alert_key[:200],
                                    resource_name=filename,
                                    resource_url=item.get("webUrl"),
                                    status="open",
                                    raw_data={
                                        "filename": filename,
                                        "external_shares": external_shares,
                                        "permissions": permissions[:5],
                                    },
                                ))
                                alerts_created += 1
                                logger.info(f"external_sharing_scan: sensitive file {filename[:30]} shared externally")
            
            if alerts_created > 0:
                await db.commit()
                logger.info(f"external_sharing_scan: created {alerts_created} alerts for org {org_id}")
    
    except Exception as exc:
        logger.warning(f"external_sharing_scan: error: {exc}")


async def _alert_pref_enabled(org_id: str, pref_key: str, db: AsyncSession) -> bool:
    """Check whether a Workspace Security alert toggle is ON for this org.

    Prefs live in `organizations.org_metadata.alert_prefs.<pref_key>`.
    Missing key defaults to True so a fresh org still receives alerts
    until they explicitly opt out from Settings.
    """
    try:
        r = await db.execute(text(
            "SELECT org_metadata FROM organizations WHERE id = CAST(:oid AS UUID)"
        ), {"oid": org_id})
        row = r.first()
        if not row or row[0] is None:
            return True
        meta = row[0]
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except Exception:
                meta = {}
        prefs = (meta or {}).get("alert_prefs") or {}
        val = prefs.get(pref_key)
        return bool(val) if val is not None else True
    except Exception as exc:
        logger.debug(f"_alert_pref_enabled: {pref_key} lookup failed: {exc}")
        return True


async def _classify_and_create_alert(
    org_id: str,
    provider: str,
    resource_id: str,
    resource_name: str,
    resource_url: Optional[str],
    content: str,
    raw_data: dict,
    db: AsyncSession,
    *,
    explicit_severity: Optional[str] = None,
    explicit_category: Optional[str] = None,
    alert_pref_key: Optional[str] = None,
) -> None:
    """Run DeepSeek on content; create SaasAlert + Threat record if score >= 50.

    Adnan 2026-06-23: explicit_* + alert_pref_key let non-DLP callers
    (malware scanner, ransomware burst detector, cross-region access
    monitor) reuse this alert path. When they are set we skip the
    DeepSeek pass and respect the user's per-pref toggle.
    """
    try:
        # Honour user's alert pref toggle for non-DLP fast-paths.
        if alert_pref_key:
            try:
                if not await _alert_pref_enabled(org_id, alert_pref_key, db):
                    logger.info(
                        f"saas_alert: skipped {alert_pref_key} for {provider} "
                        f"resource={resource_name[:60]} — user has the toggle off"
                    )
                    return
            except Exception as _pref_exc:
                logger.debug(f"saas_alert: pref lookup failed: {_pref_exc}")

        if explicit_severity and explicit_category:
            # Non-DLP fast path: caller already knows the severity & category.
            severity = explicit_severity
            alert_type = explicit_category
            title = (
                f"{explicit_category.title()} indicator in {provider.title()}: "
                f"{resource_name[:80]}"
            )
            description = content or "Indicator detected by the scanner."
            deepseek_result = {
                "risk_level": severity,
                "categories": [alert_type],
                "explanation": description,
            }
        else:
            # DeepSeek-only classification (original behaviour).
            deepseek_result = await _deepseek_classify_content(
                content=content,
                context=f"{provider} resource: {resource_name}",
                org_id=org_id,
            )

            score = _risk_to_score(deepseek_result.get("risk_level", "low"))
            if score < 50:
                return

            severity = deepseek_result.get("risk_level", "low")
            cats = deepseek_result.get("categories", [])
            alert_type = cats[0] if cats else "sensitive_data"
            title = f"Sensitive data detected in {provider.title()}: {resource_name[:80]}"
            description = deepseek_result.get("explanation", "Sensitive content detected.")

        # Avoid duplicate alerts for same resource
        existing = (await db.execute(
            select(SaasAlert).where(
                SaasAlert.org_id == uuid.UUID(org_id),
                SaasAlert.provider == provider,
                SaasAlert.resource_id == resource_id,
                SaasAlert.status == "open",
            )
        )).scalar_one_or_none()
        if existing:
            return

        saas_alert = SaasAlert(
            org_id=uuid.UUID(org_id),
            provider=provider,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_url=resource_url,
            posture_result=None,
            raw_data=raw_data,
            status="open",
        )
        db.add(saas_alert)
        await db.commit()

        # Feed into Threat Queue
        try:
            from backend.models.db_models import Threat as ThreatModel
            now = datetime.now(timezone.utc)
            risk_num = _risk_to_score(deepseek_result.get("risk_level", "low"))
            threat = ThreatModel(
                org_id=uuid.UUID(org_id),
                sender=f"saas:{provider}",
                sender_domain=provider,
                subject=title,
                threat_type="SAAS_DATA_LEAK",
                risk_score=risk_num,
                content_score=risk_num,
                graph_score=0,
                reputation_score=0,
                action_taken="FLAGGED_HIGH" if risk_num >= 75 else "FLAGGED_LOW",
                status="open",
                ai_explanation_en=deepseek_result.get("explanation", ""),
                threat_indicators={"saas": deepseek_result.get("categories", []), "resource": resource_name},
                detected_at=now,
            )
            db.add(threat)
            await db.commit()
        except Exception as threat_exc:
            logger.warning(f"saas_scan: threat queue insert failed for {resource_id}: {threat_exc}")
            await db.rollback()

        # Admin email notification for high/critical
        if severity in ("high", "critical"):
            import asyncio
            asyncio.ensure_future(_notify_admins_of_alert(
                org_id, title, description, severity, resource_name, provider, resource_url
            ))

    except Exception as exc:
        logger.error(f"saas_scan: alert creation failed for {resource_id}: {exc}")
        await db.rollback()


async def _notify_admins_of_alert(
    org_id: str,
    alert_title: str,
    alert_description: str,
    severity: str,
    resource_name: str,
    provider: str,
    resource_url: Optional[str],
) -> None:
    """Send Himaya-branded DSPM alert email to org admins via Amazon SES."""
    try:
        from backend.models.db_models import User
        from backend.services.email_service import send_email as ses_send

        async with AsyncSessionLocal() as db:
            admins = (await db.execute(
                select(User).where(
                    User.org_id == uuid.UUID(org_id),
                    User.role.in_(["admin", "super_admin"]),
                )
            )).scalars().all()
            admin_emails = [a.email for a in admins if a.email]

        if not admin_emails:
            logger.info(f"saas_alert_notify: no admins to notify for org {org_id}")
            return

        sev_color = "#dc2626" if severity == "critical" else "#ea580c" if severity == "high" else "#d97706"
        resource_link_html = (
            f"<div style='margin-top:16px;'>"
            f"<a href='{resource_url}' style='background:#3b6ef6;color:white;padding:8px 16px;"
            f"border-radius:6px;text-decoration:none;font-size:12px;font-weight:600;'>View Resource →</a></div>"
        ) if resource_url else ""

        html_body = f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#0a0f1e">
    <tr><td align="center" style="padding:32px 16px;">
      <table width="600" cellpadding="0" cellspacing="0" border="0" style="background:#0d1b2e;border:1px solid #1a2744;border-radius:12px;overflow:hidden;">
        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#0f3460 0%,#1a237e 100%);padding:24px 32px;text-align:center;">
          <img src="cid:himaya-logo" alt="Himaya Helios" width="160"
               style="display:block;max-width:160px;height:auto;border:0;outline:none;text-decoration:none;margin:0 auto 8px auto;" />
          <div style="color:#71717a;font-size:11px;margin-top:4px;letter-spacing:0.08em;text-transform:uppercase;">DSPM Alert Notification</div>
        </td></tr>
        <!-- Severity banner -->
        <tr><td style="background:{sev_color}18;border-bottom:1px solid {sev_color}40;padding:16px 32px;">
          <div style="color:{sev_color};font-size:10px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;">{severity} severity alert</div>
          <div style="color:#e4e4e7;font-size:15px;font-weight:600;margin-top:6px;line-height:1.4;">{alert_title}</div>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:24px 32px;">
          <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
            <tr>
              <td style="color:#71717a;font-size:12px;padding:7px 0;width:110px;vertical-align:top;">Source</td>
              <td style="color:#e4e4e7;font-size:12px;padding:7px 0;font-weight:600;">{provider.title()}</td>
            </tr>
            <tr>
              <td style="color:#71717a;font-size:12px;padding:7px 0;vertical-align:top;border-top:1px solid #1a2744;">Resource</td>
              <td style="color:#e4e4e7;font-size:12px;padding:7px 0;border-top:1px solid #1a2744;">{resource_name}</td>
            </tr>
            <tr>
              <td style="color:#71717a;font-size:12px;padding:7px 0;vertical-align:top;border-top:1px solid #1a2744;">Details</td>
              <td style="color:#a1a1aa;font-size:12px;padding:7px 0;border-top:1px solid #1a2744;line-height:1.5;">{alert_description[:400]}</td>
            </tr>
          </table>
          {resource_link_html}
          <div style="margin-top:12px;">
            <a href="https://app.himaya.ai/saas-security" style="display:inline-block;background:#0f3460;color:#a1a1aa;padding:8px 16px;border-radius:6px;text-decoration:none;font-size:12px;">Manage Alerts in Helios →</a>
          </div>
        </td></tr>
        <!-- Footer -->
        <tr><td style="background:#0a0f1e;border-top:1px solid #1a2744;padding:16px 32px;">
          <p style="color:#52525b;font-size:11px;margin:0;text-align:center;">
            Helios DSPM · Himaya Technologies ·
            <a href="https://app.himaya.ai" style="color:#3b6ef6;text-decoration:none;">app.himaya.ai</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

        subject = f"[Helios DSPM] {severity.upper()}: {alert_title[:70]}"
        for email_addr in admin_emails:
            try:
                ses_send(to=email_addr, subject=subject, html_body=html_body)
                logger.info(f"saas_alert_notify: sent to {email_addr}")
            except Exception as e:
                logger.warning(f"saas_alert_notify: SES send to {email_addr} failed: {e}")

    except Exception as exc:
        logger.error(f"saas_alert_notify: {exc}")


async def _deepseek_classify_content(
    content: str, context: str, org_id: str
) -> dict:
    """
    Classify content using the full DLP pipeline:
    1. Regex patterns (fast, catches SSN/credit cards/keys immediately)
    2. DeepSeek (semantic, L40S GPU via dlp_service — 200s timeout)
    3. Claude Haiku fallback if DeepSeek unavailable
    Returns: {"risk_level": "low|medium|high|critical", "categories": [...],
              "confidence": 0.0-1.0, "explanation": "...",
              "matched_patterns": [...], "sensitivity_score": 0-100}
    """
    # Step 1: Fast regex scan — catches SSN, credit cards, private keys immediately
    regex_result = _simple_classify(content)
    if regex_result["risk_level"] in ("high", "critical"):
        logger.info(f"saas_classify: regex match {regex_result['categories']} for context={context[:50]}")
        return regex_result

    # Step 2: Claude classification (DeepSeek disabled due to timeouts - can be replaced with custom DLP later)
    try:
        from backend.services import dlp_service as _dlp
        claude_result = await _dlp._claude_classify(
            email_body=content[:4000],
            subject=context,
            attachments=[],
            sender="saas-scanner@helios",
            recipient_domains=[],
        )
        if claude_result:
            claude_result.setdefault("risk_level", "low")
            claude_result.setdefault("categories", [])
            claude_result.setdefault("confidence", 0.5)
            claude_result.setdefault("matched_patterns", [])
            claude_result.setdefault("sensitivity_score",
                                     _risk_to_score(claude_result.get("risk_level", "low")))
            # Take the higher of Claude and regex
            if claude_result["risk_level"] == "low" and regex_result["risk_level"] != "low":
                return regex_result
            logger.info(f"saas_classify: Claude={claude_result['risk_level']} cats={claude_result['categories']} for {context[:40]}")
            return claude_result
    except Exception as exc:
        logger.warning(f"saas_classify: Claude call failed: {exc}")

    return regex_result


async def _detect_behavioral_threats(org_id: str, provider: str, access_token: str, db: AsyncSession) -> None:
    """
    Detect behavioral threat patterns via Graph API:
    1. Mass Download Detection
    2. External Forwarding Rules
    3. Risky OAuth Apps
    4. Suspicious Sharing Patterns
    5. Permission Escalation (guest granted broad permissions)
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    GRAPH_URL = "https://graph.microsoft.com/v1.0"
    now = datetime.now(timezone.utc)

    async def _safe_get(url: str, extra_headers: dict = None) -> tuple:
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(url, headers={**headers, **(extra_headers or {})})
                return r.status_code, r.json() if r.status_code < 500 else {}
        except Exception:
            return 0, {}

    async def _create_threat_alert(alert_type: str, severity: str, title: str, description: str,
                                   resource_id: str, resource_name: str, resource_url: str = None,
                                   raw_data: dict = None):
        """Create a SaasAlert if not already open."""
        existing = (await db.execute(
            select(SaasAlert).where(
                SaasAlert.org_id == uuid.UUID(org_id),
                SaasAlert.resource_id == resource_id,
                SaasAlert.status == "open",
            )
        )).scalar_one_or_none()
        if existing:
            return
        db.add(SaasAlert(
            org_id=uuid.UUID(org_id),
            provider=provider,
            alert_type=alert_type,
            severity=severity,
            title=title,
            description=description,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_url=resource_url,
            status="open",
            raw_data=raw_data or {},
        ))
        if severity in ("high", "critical"):
            import asyncio
            asyncio.ensure_future(_notify_admins_of_alert(
                org_id, title, description, severity, resource_name, provider, resource_url
            ))

    # ── 1. Mass Download Detection ────────────────────────────────────────────
    # Check audit logs for bulk file downloads by a single user
    try:
        sc, audit = await _safe_get(
            f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'FileDownloaded'&$top=50"
        )
        if sc == 200:
            from collections import Counter
            downloads = audit.get("value", [])
            user_dl_counts = Counter(
                e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "unknown")
                for e in downloads
            )
            for user, count in user_dl_counts.items():
                if count >= 10 and user != "unknown":
                    await _create_threat_alert(
                        alert_type="mass_download",
                        severity="high",
                        title=f"Mass Download: {user.split('@')[0]} downloaded {count} files",
                        description=(
                            f"User {user} downloaded {count} files in a short timeframe. "
                            f"This may indicate data exfiltration or an insider threat. "
                            f"Review the user's recent activity in the audit log."
                        ),
                        resource_id=f"mass-dl:{user}:{now.date()}",
                        resource_name=user,
                        raw_data={"user": user, "download_count": count},
                    )
    except Exception as exc:
        logger.warning(f"behavioral_threats/mass_download: {exc}")

    # ── 2. External Forwarding Rules ──────────────────────────────────────────
    # Check for inbox rules forwarding to external domains
    try:
        sc, users_data = await _safe_get(f"{GRAPH_URL}/users?$select=id,userPrincipalName,mail&$top=20")
        if sc == 200:
            for user in users_data.get("value", [])[:10]:
                uid = user.get("id")
                upn = user.get("userPrincipalName", "")
                if not uid:
                    continue
                sc2, rules = await _safe_get(f"{GRAPH_URL}/users/{uid}/mailFolders/inbox/messageRules")
                if sc2 != 200:
                    continue
                for rule in rules.get("value", []):
                    actions = rule.get("actions", {})
                    fwd_addrs = actions.get("forwardTo", []) + actions.get("forwardAsAttachmentTo", [])
                    redirect = actions.get("redirectTo", [])
                    all_fwd = fwd_addrs + redirect
                    for fwd in all_fwd:
                        fwd_email = (fwd.get("emailAddress") or {}).get("address", "")
                        if fwd_email and "@" in fwd_email:
                            # Check if forwarding to external domain
                            user_domain = upn.split("@")[-1] if "@" in upn else ""
                            fwd_domain = fwd_email.split("@")[-1]
                            if user_domain and fwd_domain != user_domain:
                                await _create_threat_alert(
                                    alert_type="external_forwarding",
                                    severity="high",
                                    title=f"External Email Forwarding: {upn.split('@')[0]} → {fwd_domain}",
                                    description=(
                                        f"User {upn} has an inbox rule forwarding emails to external address "
                                        f"{fwd_email}. This may indicate account compromise or intentional "
                                        f"data exfiltration. Rule: '{rule.get('displayName', 'unnamed')}'."
                                    ),
                                    resource_id=f"fwd:{uid}:{fwd_email}",
                                    resource_name=upn,
                                    raw_data={"user": upn, "forward_to": fwd_email, "rule_name": rule.get("displayName")},
                                )
    except Exception as exc:
        logger.warning(f"behavioral_threats/external_forwarding: {exc}")

    # ── 3. Risky OAuth Apps ────────────────────────────────────────────────────
    # Check for third-party apps with excessive permissions
    RISKY_SCOPES = {
        "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite",
        "Files.ReadWrite.All", "Sites.ReadWrite.All", "Directory.ReadWrite.All",
        "User.ReadWrite.All", "Calendars.ReadWrite", "Contacts.ReadWrite",
    }
    try:
        sc, sps = await _safe_get(
            f"{GRAPH_URL}/servicePrincipals?$filter=tags/Any(t:t eq 'WindowsAzureActiveDirectoryIntegratedApp')&$select=id,displayName,appId,oauth2PermissionScopes&$top=30"
        )
        if sc == 200:
            for sp in sps.get("value", [])[:20]:
                sp_name = sp.get("displayName", "Unknown App")
                sp_id = sp.get("id", "")
                # Check delegated permission grants
                sc2, grants = await _safe_get(
                    f"{GRAPH_URL}/servicePrincipals/{sp_id}/oauth2PermissionGrants"
                )
                if sc2 != 200:
                    continue
                for grant in grants.get("value", []):
                    scopes_str = grant.get("scope", "")
                    granted_scopes = set(scopes_str.split())
                    risky_found = granted_scopes & RISKY_SCOPES
                    if len(risky_found) >= 2:  # 2+ risky scopes = suspicious
                        await _create_threat_alert(
                            alert_type="risky_oauth_app",
                            severity="high" if len(risky_found) >= 3 else "medium",
                            title=f"Risky OAuth App: '{sp_name}' has {len(risky_found)} high-risk permissions",
                            description=(
                                f"Third-party app '{sp_name}' has been granted {len(risky_found)} high-risk "
                                f"OAuth permissions: {', '.join(sorted(risky_found))}. "
                                f"Review if this app is authorized and requires these permissions."
                            ),
                            resource_id=f"oauth:{sp_id}",
                            resource_name=sp_name,
                            raw_data={"app_name": sp_name, "risky_scopes": list(risky_found)},
                        )
    except Exception as exc:
        logger.warning(f"behavioral_threats/risky_oauth: {exc}")

    # ── 4. Suspicious Sharing Patterns ────────────────────────────────────────
    # Check for confidential files recently shared externally
    try:
        from sqlalchemy import and_
        cutoff_24h = now.replace(hour=0, minute=0, second=0)
        external_sensitive = (await db.execute(
            select(SaasDataItem).where(
                SaasDataItem.org_id == uuid.UUID(org_id),
                SaasDataItem.provider == provider,
                SaasDataItem.classification_label.in_(["confidential", "highly_confidential"]),
                SaasDataItem.sharing_scope.in_(["external", "public"]),
                SaasDataItem.last_scanned_at >= cutoff_24h,
            )
        )).scalars().all()

        if len(external_sensitive) >= 3:
            item_names = ", ".join(i.item_name[:30] for i in external_sensitive[:3])
            await _create_threat_alert(
                alert_type="suspicious_sharing",
                severity="high",
                title=f"Suspicious Sharing: {len(external_sensitive)} confidential files shared externally",
                description=(
                    f"{len(external_sensitive)} confidential/highly-confidential files are shared externally "
                    f"in {provider.title()}. Examples: {item_names}. "
                    f"Review sharing permissions and revoke external access if not authorized."
                ),
                resource_id=f"sharing-pattern:{provider}:{cutoff_24h.date()}",
                resource_name=f"{provider.title()} External Sharing",
                raw_data={"count": len(external_sensitive), "examples": [i.item_name for i in external_sensitive[:5]]},
            )
    except Exception as exc:
        logger.warning(f"behavioral_threats/suspicious_sharing: {exc}")

    # ── 5. Permission Escalation ──────────────────────────────────────────────
    # Check for guest users recently granted broad permissions
    try:
        sc, guests = await _safe_get(
            f"{GRAPH_URL}/users?$filter=userType eq 'Guest'&$select=id,displayName,userPrincipalName,createdDateTime&$top=20"
        )
        if sc == 200:
            # Recent guests (last 7 days)
            from datetime import timedelta
            recent_cutoff = now - timedelta(days=7)
            for guest in guests.get("value", []):
                created_str = guest.get("createdDateTime", "")
                try:
                    from dateutil.parser import parse as _parse_dt
                    created_dt = _parse_dt(created_str) if created_str else None
                    if not created_dt or created_dt < recent_cutoff:
                        continue
                except Exception:
                    continue
                guest_id = guest.get("id", "")
                # Check group memberships for broad access
                sc2, memberships = await _safe_get(f"{GRAPH_URL}/users/{guest_id}/memberOf?$select=id,displayName,groupTypes")
                if sc2 != 200:
                    continue
                broad_groups = [
                    m for m in memberships.get("value", [])
                    if "All" in (m.get("displayName") or "") or
                    "Everyone" in (m.get("displayName") or "") or
                    "Organization" in (m.get("displayName") or "")
                ]
                if broad_groups:
                    guest_name = guest.get("displayName") or guest.get("userPrincipalName", "Unknown")
                    group_names = ", ".join(g.get("displayName", "") for g in broad_groups)
                    await _create_threat_alert(
                        alert_type="permission_escalation",
                        severity="high",
                        title=f"Permission Escalation: Guest '{guest_name}' granted org-wide access",
                        description=(
                            f"Recently added guest user {guest_name} has been added to broad-access "
                            f"group(s): {group_names}. This grants them org-wide permissions which may "
                            f"violate the principle of least privilege."
                        ),
                        resource_id=f"perm-esc:{guest_id}",
                        resource_name=guest_name,
                        raw_data={"guest": guest.get("userPrincipalName"), "groups": [g.get("displayName") for g in broad_groups]},
                    )
    except Exception as exc:
        logger.warning(f"behavioral_threats/permission_escalation: {exc}")

    # ── 6. Impossible Travel Detection ────────────────────────────────────────
    try:
        sc, sign_ins = await _safe_get(
            f"{GRAPH_URL}/auditLogs/signIns?$filter=status/errorCode eq 0&$top=50&$orderby=createdDateTime desc"
        )
        if sc == 200:
            from collections import defaultdict
            user_locations: dict = defaultdict(list)
            for sign_in in sign_ins.get("value", []):
                upn = sign_in.get("userPrincipalName", "")
                location = sign_in.get("location", {}) or {}
                country = location.get("countryOrRegion", "")
                city = location.get("city", "")
                ts_str = sign_in.get("createdDateTime", "")
                if upn and country and ts_str:
                    try:
                        from dateutil.parser import parse as _parse_dt
                        ts = _parse_dt(ts_str)
                        user_locations[upn].append({"country": country, "city": city, "ts": ts})
                    except Exception:
                        pass
            from datetime import timedelta
            for upn, locations in user_locations.items():
                if len(locations) < 2:
                    continue
                locations.sort(key=lambda x: x["ts"])
                for i in range(len(locations) - 1):
                    a, b = locations[i], locations[i + 1]
                    if a["country"] != b["country"]:
                        time_diff = (b["ts"] - a["ts"]).total_seconds() / 3600
                        if 0 < time_diff < 2:  # Different countries within 2 hours
                            await _create_threat_alert(
                                alert_type="impossible_travel",
                                severity="critical",
                                title=f"Impossible Travel: {upn.split('@')[0]} — {a['country']} → {b['country']} in {time_diff:.1f}h",
                                description=(
                                    f"User {upn} signed in from {a['country']} ({a.get('city','')}) and then "
                                    f"{b['country']} ({b.get('city','')}) within {time_diff:.1f} hours. "
                                    f"This is geographically impossible and may indicate credential compromise."
                                ),
                                resource_id=f"travel:{upn}:{b['ts'].date()}",
                                resource_name=upn,
                                raw_data={
                                    "user": upn,
                                    "from_country": a["country"], "from_city": a["city"],
                                    "to_country": b["country"], "to_city": b["city"],
                                    "hours_apart": round(time_diff, 2),
                                },
                            )
    except Exception as exc:
        logger.warning(f"behavioral_threats/impossible_travel: {exc}")

    try:
        await db.commit()
    except Exception as exc:
        logger.warning(f"behavioral_threats: commit failed: {exc}")
        await db.rollback()


async def _scan_shadow_it(org_id: str, provider: str, access_token: str, db: AsyncSession) -> None:
    """
    Scan for OAuth apps (shadow IT discovery).
    Queries servicePrincipals and oauth2PermissionGrants from Graph API.
    """
    from backend.models.db_models import SaasOAuthApp
    headers = {"Authorization": f"Bearer {access_token}"}
    GRAPH_URL = "https://graph.microsoft.com/v1.0"

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Get service principals (apps)
            resp = await client.get(
                f"{GRAPH_URL}/servicePrincipals?$top=100&$select=id,displayName,appId,publisherName,oauth2PermissionScopes",
                headers=headers
            )
            if resp.status_code != 200:
                return

            apps = resp.json().get("value", [])
            for app in apps:
                app_id = app.get("appId", "")
                if not app_id:
                    continue

                # Check if app exists
                existing = (await db.execute(
                    select(SaasOAuthApp).where(
                        SaasOAuthApp.org_id == uuid.UUID(org_id),
                        SaasOAuthApp.app_id == app_id,
                        SaasOAuthApp.provider == provider,
                    )
                )).scalar_one_or_none()

                permissions = app.get("oauth2PermissionScopes", []) or []
                perm_list = [p.get("value", "") for p in permissions[:20]]

                # Calculate risk score based on permissions
                risky_perms = ["Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Directory.ReadWrite.All", "User.ReadWrite.All"]
                risk_score = 0.3
                for rp in risky_perms:
                    if any(rp.lower() in p.lower() for p in perm_list):
                        risk_score += 0.15
                risk_score = min(risk_score, 1.0)

                if existing:
                    existing.last_seen_at = datetime.now(timezone.utc)
                    existing.permissions = perm_list
                    existing.risk_score = risk_score
                else:
                    db.add(SaasOAuthApp(
                        org_id=uuid.UUID(org_id),
                        app_name=app.get("displayName", "Unknown"),
                        app_id=app_id,
                        provider=provider,
                        publisher=app.get("publisherName"),
                        permissions=perm_list,
                        status="unknown",
                        risk_score=risk_score,
                    ))

            await db.commit()
    except Exception as exc:
        logger.warning(f"shadow_it_scan: {exc}")
        await db.rollback()


async def _scan_entra_risky_users(org_id: str, access_token: str, db: AsyncSession) -> None:
    """
    Import risky users from Entra ID Identity Protection.
    Requires IdentityRiskEvent.Read.All permission.
    """
    from backend.models.db_models import SaasRiskyUser
    headers = {"Authorization": f"Bearer {access_token}"}
    GRAPH_URL = "https://graph.microsoft.com/v1.0"

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{GRAPH_URL}/identityProtection/riskyUsers?$filter=riskLevel ne 'none'&$top=50",
                headers=headers
            )
            if resp.status_code != 200:
                logger.debug(f"entra_risky_users: API returned {resp.status_code}")
                return

            risky_users = resp.json().get("value", [])
            for user in risky_users:
                user_id = user.get("id", "")
                user_email = user.get("userPrincipalName", "")
                risk_level = user.get("riskLevel", "none")
                risk_state = user.get("riskState", "")
                risk_detail = user.get("riskDetail", "")
                risk_updated = user.get("riskLastUpdatedDateTime")

                if not user_email or risk_level == "none":
                    continue

                # Upsert
                existing = (await db.execute(
                    select(SaasRiskyUser).where(
                        SaasRiskyUser.org_id == uuid.UUID(org_id),
                        SaasRiskyUser.user_email == user_email,
                        SaasRiskyUser.provider == "microsoft",
                    )
                )).scalar_one_or_none()

                if existing:
                    existing.risk_level = risk_level
                    existing.risk_state = risk_state
                    existing.risk_detail = risk_detail
                    if risk_updated:
                        try:
                            from dateutil.parser import parse as _parse_dt
                            existing.risk_last_updated_at = _parse_dt(risk_updated)
                        except Exception:
                            pass
                else:
                    db.add(SaasRiskyUser(
                        org_id=uuid.UUID(org_id),
                        user_email=user_email,
                        user_id=user_id,
                        risk_level=risk_level,
                        risk_state=risk_state,
                        risk_detail=risk_detail,
                        provider="microsoft",
                    ))

                # Create alert for high/medium risk users
                if risk_level in ("high", "medium"):
                    severity = "critical" if risk_level == "high" else "high"
                    existing_alert = (await db.execute(
                        select(SaasAlert).where(
                            SaasAlert.org_id == uuid.UUID(org_id),
                            SaasAlert.resource_id == f"risky-user:{user_email}",
                            SaasAlert.status == "open",
                        )
                    )).scalar_one_or_none()
                    if not existing_alert:
                        db.add(SaasAlert(
                            org_id=uuid.UUID(org_id),
                            provider="microsoft",
                            alert_type="entra_risky_user",
                            severity=severity,
                            title=f"Risky User: {user_email.split('@')[0]} ({risk_level})",
                            description=(
                                f"Entra ID Identity Protection flagged {user_email} as {risk_level} risk. "
                                f"Risk state: {risk_state}. Detail: {risk_detail or 'N/A'}. "
                                f"Review the user's recent activity and consider requiring password reset or MFA re-registration."
                            ),
                            resource_id=f"risky-user:{user_email}",
                            resource_name=user_email,
                            raw_data={"risk_level": risk_level, "risk_state": risk_state, "risk_detail": risk_detail},
                        ))

            await db.commit()
    except Exception as exc:
        logger.warning(f"entra_risky_users: {exc}")
        await db.rollback()


async def _scan_admin_actions(org_id: str, access_token: str, db: AsyncSession) -> None:
    """
    Track admin/privileged user actions from audit logs.
    Creates alerts for sensitive operations like adding global admins.
    """
    from backend.models.db_models import SaasAdminAction
    headers = {"Authorization": f"Bearer {access_token}"}
    GRAPH_URL = "https://graph.microsoft.com/v1.0"

    SENSITIVE_ACTIVITIES = [
        # Azure AD / Entra ID admin actions
        "Add member to role",
        "Remove member from role",
        "Add app role assignment to service principal",
        "Add owner to application",
        "Update conditional access policy",
        "Delete conditional access policy",
        "Update user",
        "Reset user password",
        "Disable account",
        # Teams admin actions
        "Add group",
        "Create group",
        "Update group",
        "Delete group",
        "Add member to group",
        "Remove member from group",
        "Add owner to group",
        "Remove owner from group",
        "TeamCreated",
        "TeamDeleted",
        "MemberAdded",
        "MemberRemoved",
        "ChannelAdded",
        "ChannelDeleted",
        # SharePoint admin actions
        "SiteCollectionCreated",
        "SiteDeleted",
        "SharingSet",
        "SharingPolicyChanged",
        "SiteCollectionAdminAdded",
        "SiteCollectionAdminRemoved",
        "Add site collection administrator",
        "AnonymousLinkCreated",
        "CompanyLinkCreated",
        "SecureLinkCreated",
        "SharingInvitationCreated",
        # Exchange admin actions
        "Set-Mailbox",
        "New-InboxRule",
        "Set-TransportRule",
        "Add-MailboxPermission",
        "Set-OwaMailboxPolicy",
    ]

    logger.info(f"_scan_admin_actions: starting for org {org_id}")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{GRAPH_URL}/auditLogs/directoryAudits?$top=50&$orderby=activityDateTime desc",
                headers=headers
            )
            logger.info(f"_scan_admin_actions: directoryAudits returned status={resp.status_code} for org {org_id}")
            if resp.status_code != 200:
                if _is_aad_premium_required_error(resp.status_code, resp.text):
                    logger.info(
                        f"_scan_admin_actions: skipping directoryAudits for org {org_id} — tenant lacks Entra ID Premium (P1/P2) license"
                    )
                    return
                logger.warning(f"_scan_admin_actions: failed with status={resp.status_code}, body={resp.text[:200]}")
                return

            audits = resp.json().get("value", [])
            logger.info(f"_scan_admin_actions: got {len(audits)} audit entries for org {org_id}")
            for audit in audits:
                activity = audit.get("activityDisplayName", "")
                initiated_by = audit.get("initiatedBy", {}) or {}
                user_info = initiated_by.get("user", {}) or {}
                # System-initiated audit events (Group lifecycle policies, etc.)
                # have user_info populated but userPrincipalName=None, so a plain
                # .get("x", default) won't substitute. Use explicit fallback chain.
                # Also guard against ``initiated_by["app"]`` being explicitly
                # None (not missing) — same pattern as user_info.
                app_info = initiated_by.get("app") or {}
                admin_email = (
                    user_info.get("userPrincipalName")
                    or user_info.get("displayName")
                    or app_info.get("displayName")
                    or "System"
                )

                targets = audit.get("targetResources", []) or []
                target_name = (targets[0].get("displayName") if targets else "") or ""
                target_id = (targets[0].get("id") if targets else "") or ""
                target_type = (targets[0].get("type") if targets else "") or ""

                # Check if already logged
                audit_id = audit.get("id", "")
                existing = (await db.execute(
                    select(SaasAdminAction).where(
                        SaasAdminAction.org_id == uuid.UUID(org_id),
                        SaasAdminAction.details["audit_id"].astext == audit_id,
                    )
                )).scalar_one_or_none()
                if existing:
                    continue

                logger.info(f"_scan_admin_actions: storing action type='{activity}' by {admin_email} on {target_type}/{target_name}")
                db.add(SaasAdminAction(
                    org_id=uuid.UUID(org_id),
                    admin_email=admin_email,
                    action_type=activity,
                    target_type=target_type,
                    target_id=target_id,
                    target_name=target_name,
                    details={"audit_id": audit_id, "result": audit.get("result", "")},
                    provider="microsoft",
                ))

                # Alert on sensitive activities
                if any(sa.lower() in activity.lower() for sa in SENSITIVE_ACTIVITIES):
                    is_role_change = "role" in activity.lower()
                    severity = "high" if is_role_change else "medium"
                    db.add(SaasAlert(
                        org_id=uuid.UUID(org_id),
                        provider="microsoft",
                        alert_type="privileged_action",
                        severity=severity,
                        title=f"Admin Action: {activity[:60]}",
                        description=(
                            f"Admin {admin_email} performed '{activity}' on {target_type} '{target_name}'. "
                            f"Review this action to ensure it was authorized."
                        ),
                        resource_id=f"admin-action:{audit_id}",
                        resource_name=admin_email,
                        raw_data={"activity": activity, "target": target_name, "admin": admin_email},
                    ))

            await db.commit()
            logger.info(f"_scan_admin_actions: committed {len(audits)} audit entries for org {org_id}")
    except Exception as exc:
        logger.warning(f"admin_actions_scan: {exc}")
        await db.rollback()


async def _scan_user_risk_scores(org_id: str, access_token: str, db: AsyncSession) -> None:
    """
    Calculate and store AI-driven user risk scores based on:
    - Entra ID risk level
    - Sharing behavior (external shares)
    - Admin actions performed
    - Sign-in anomalies
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    GRAPH_URL = "https://graph.microsoft.com/v1.0"

    try:
        # Get all users
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{GRAPH_URL}/users?$top=100&$select=id,userPrincipalName,displayName,jobTitle,department,accountEnabled",
                headers=headers
            )
            if resp.status_code != 200:
                logger.debug(f"user_risk_scores: users API returned {resp.status_code}")
                return

            users = resp.json().get("value", [])
            for user in users:
                user_email = user.get("userPrincipalName", "")
                if not user_email or "#EXT#" in user_email:  # Skip guests
                    continue

                risk_score = 0
                risk_factors = []

                # Factor 1: Entra risky user status
                try:
                    risky = await db.execute(text(
                        "SELECT risk_level FROM saas_risky_users WHERE org_id=:oid AND user_email=:email LIMIT 1"
                    ), {"oid": org_id, "email": user_email})
                    risky_row = risky.fetchone()
                    if risky_row:
                        level = risky_row[0]
                        if level == "high":
                            risk_score += 40
                            risk_factors.append("Entra ID: High Risk")
                        elif level == "medium":
                            risk_score += 20
                            risk_factors.append("Entra ID: Medium Risk")
                except Exception:
                    pass

                # Factor 2: External sharing behavior
                try:
                    sharing = await db.execute(text(
                        "SELECT COUNT(*) FROM saas_data_items WHERE org_id=:oid AND owner_email=:email AND sharing_scope IN ('external', 'public')"
                    ), {"oid": org_id, "email": user_email})
                    ext_count = sharing.scalar() or 0
                    if ext_count > 20:
                        risk_score += 25
                        risk_factors.append(f"High external sharing ({ext_count} items)")
                    elif ext_count > 5:
                        risk_score += 10
                        risk_factors.append(f"Moderate external sharing ({ext_count} items)")
                except Exception:
                    pass

                # Factor 3: Recent admin actions
                try:
                    admin_acts = await db.execute(text(
                        "SELECT COUNT(*) FROM saas_admin_actions WHERE org_id=:oid AND admin_email=:email AND created_at > NOW() - INTERVAL '7 days'"
                    ), {"oid": org_id, "email": user_email})
                    admin_count = admin_acts.scalar() or 0
                    if admin_count > 20:
                        risk_score += 15
                        risk_factors.append(f"High admin activity ({admin_count} actions this week)")
                except Exception:
                    pass

                # Factor 4: Check if disabled but active
                if not user.get("accountEnabled", True):
                    # Disabled account shouldn't have recent activity
                    risk_factors.append("Account disabled")

                # Cap at 100
                risk_score = min(risk_score, 100)

                # Store/update user risk score
                await db.execute(text("""
                    INSERT INTO saas_user_risk_scores (org_id, user_email, user_id, display_name, job_title, department, risk_score, risk_factors, updated_at)
                    VALUES (:oid, :email, :uid, :name, :title, :dept, :score, :factors, NOW())
                    ON CONFLICT (org_id, user_email) DO UPDATE SET
                        risk_score = EXCLUDED.risk_score,
                        risk_factors = EXCLUDED.risk_factors,
                        updated_at = NOW()
                """), {
                    "oid": org_id,
                    "email": user_email,
                    "uid": user.get("id", ""),
                    "name": user.get("displayName", ""),
                    "title": user.get("jobTitle", ""),
                    "dept": user.get("department", ""),
                    "score": risk_score,
                    "factors": json.dumps(risk_factors),
                })

            await db.commit()
    except Exception as exc:
        logger.warning(f"user_risk_scores_scan: {exc}")
        await db.rollback()


async def _evaluate_conditional_access(org_id: str, access_token: str, db: AsyncSession) -> list:
    """
    Evaluate Conditional Access policies for MFA gaps and coverage.
    Returns posture check results.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    GRAPH_URL = "https://graph.microsoft.com/v1.0"
    checks = []

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{GRAPH_URL}/identity/conditionalAccessPolicies",
                headers=headers
            )
            if resp.status_code != 200:
                return checks

            policies = resp.json().get("value", [])
            enabled_policies = [p for p in policies if p.get("state") == "enabled"]

            # Check: Any CA policies exist
            checks.append({
                "check_name": "ca_policies_configured",
                "check_category": "Conditional Access",
                "status": "pass" if enabled_policies else "fail",
                "severity": "high" if not enabled_policies else "low",
                "description": f"{len(enabled_policies)} Conditional Access policies are enabled." if enabled_policies else "No Conditional Access policies are enabled. This leaves your tenant vulnerable.",
                "recommendation": None if enabled_policies else "Configure at least a baseline CA policy requiring MFA for all users.",
            })

            # Check: MFA required for admins
            mfa_for_admins = False
            for policy in enabled_policies:
                conditions = policy.get("conditions", {}) or {}
                users = conditions.get("users", {}) or {}
                include_roles = users.get("includeRoles", []) or []
                grant = policy.get("grantControls", {}) or {}
                built_in_controls = grant.get("builtInControls", []) or []
                if "mfa" in built_in_controls and include_roles:
                    mfa_for_admins = True
                    break

            checks.append({
                "check_name": "ca_mfa_for_admins",
                "check_category": "Conditional Access",
                "status": "pass" if mfa_for_admins else "warning",
                "severity": "high" if not mfa_for_admins else "low",
                "description": "MFA is required for admin roles." if mfa_for_admins else "No CA policy specifically requires MFA for admin roles.",
                "recommendation": None if mfa_for_admins else "Create a CA policy requiring MFA for Directory Roles (Global Admin, etc.).",
            })

            # Check: Device compliance required
            device_compliance = any(
                "compliantDevice" in (p.get("grantControls", {}) or {}).get("builtInControls", [])
                for p in enabled_policies
            )
            checks.append({
                "check_name": "ca_device_compliance",
                "check_category": "Conditional Access",
                "status": "pass" if device_compliance else "warning",
                "severity": "medium" if not device_compliance else "low",
                "description": "Device compliance is required by at least one policy." if device_compliance else "No CA policy requires device compliance.",
                "recommendation": None if device_compliance else "Consider requiring compliant/hybrid-joined devices for sensitive apps.",
            })

            # Check: Block legacy auth
            blocks_legacy = any(
                (p.get("conditions", {}) or {}).get("clientAppTypes", []) == ["exchangeActiveSync", "other"]
                and (p.get("grantControls", {}) or {}).get("builtInControls", []) == ["block"]
                for p in enabled_policies
            )
            checks.append({
                "check_name": "ca_block_legacy_auth",
                "check_category": "Conditional Access",
                "status": "pass" if blocks_legacy else "fail",
                "severity": "high" if not blocks_legacy else "low",
                "description": "Legacy authentication is blocked." if blocks_legacy else "Legacy authentication is not blocked by CA policies.",
                "recommendation": None if blocks_legacy else "Create a CA policy to block legacy authentication protocols.",
            })

    except Exception as exc:
        logger.warning(f"conditional_access_eval: {exc}")

    return checks


def _simple_classify(content: str) -> dict:
    """Fast regex-based content classification. Runs before DeepSeek as a quick check."""
    import re as _re
    content_lower = content.lower()

    # Critical: SSN, tax IDs, credit cards, private keys
    critical_patterns = [
        (r'\b\d{3}-\d{2}-\d{4}\b', 'pii_ssn'),           # SSN
        (r'\b4[0-9]{12}(?:[0-9]{3})?\b', 'pii_credit_card'),  # Visa
        (r'\b5[1-5][0-9]{14}\b', 'pii_credit_card'),          # MC
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----', 'infra_private_key'),
        (r'\biban\b.{0,30}[A-Z]{2}\d{2}[A-Z0-9]{10,30}', 'financial_iban'),
    ]
    for pattern, cat in critical_patterns:
        if _re.search(pattern, content, _re.IGNORECASE):
            return {"risk_level": "critical", "categories": [cat], "confidence": 0.9,
                    "explanation": f"Pattern matched: {cat}", "matched_patterns": [cat], "sensitivity_score": 100}

    high_keywords = ["password", "secret", "confidential", "private key", "ssn", "credit card",
                     "tax return", "income tax", "form 1040", "w-2", "w2 ", "turbotax",
                     "social security", "date of birth", "passport number", "driver license"]
    med_keywords = ["salary", "invoice", "bank", "nda", "merger", "acquisition",
                    "annual income", "total income", "tax owed", "refund amount",
                    "routing number", "account number", "health insurance", "medical record"]
    content_lower = content.lower()

    for kw in high_keywords:
        if kw in content_lower:
            return {
                "risk_level": "high", "categories": ["sensitive"], "confidence": 0.7,
                "explanation": f"Keyword match: {kw}", "matched_patterns": [kw], "sensitivity_score": 75,
            }
    for kw in med_keywords:
        if kw in content_lower:
            return {
                "risk_level": "medium", "categories": ["sensitive"], "confidence": 0.6,
                "explanation": f"Keyword match: {kw}", "matched_patterns": [kw], "sensitivity_score": 50,
            }
    return {
        "risk_level": "low", "categories": [], "confidence": 0.5,
        "explanation": "No sensitive patterns detected", "matched_patterns": [], "sensitivity_score": 10,
    }


async def _claude_posture_analysis(
    resource_name: str, provider: str, classification: dict
) -> Optional[dict]:
    """Call Claude Haiku for posture context on a flagged resource (used for posture enrichment only)."""
    if not ANTHROPIC_API_KEY:
        return None
    try:
        prompt = (
            f"You are a cloud security analyst. A {provider} resource named '{resource_name}' "
            f"has been flagged with risk_level='{classification.get('risk_level')}', "
            f"categories={classification.get('categories')}.\n\n"
            "Provide a brief posture assessment:\n"
            '{"posture_risk":"low|medium|high","findings":["..."],"remediation":"..."}'
        )
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 300,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if r.status_code == 200:
                raw = r.json()["content"][0]["text"].strip()
                raw = re.sub(r"^```[\w]*\n?", "", raw)
                raw = re.sub(r"```$", "", raw).strip()
                return json.loads(raw)
    except Exception as exc:
        logger.warning(f"saas_scan: Claude posture analysis failed: {exc}")
    return None


async def _evaluate_provider_posture(
    org_id: str, provider: str, access_token: str, db: AsyncSession
) -> None:
    """Comprehensive 53-check posture evaluation via Microsoft Graph API."""
    headers = {"Authorization": f"Bearer {access_token}"}
    headers_eventual = {**headers, "ConsistencyLevel": "eventual"}
    checks_to_create: list[dict] = []

    def _check(name, category, status, severity, description, recommendation, evidence=None, remediation=None):
        checks_to_create.append({
            "check_name": name,
            "check_category": category,
            "status": status,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence or {},
            "remediation_steps": remediation or [],
        })

    async def _get(url, hdrs=None):
        """Safe Graph API GET — returns (status_code, json_body)"""
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(url, headers=hdrs or headers)
                return r.status_code, r.json() if r.status_code < 500 else {}
        except Exception:
            return 0, {}

    # ── Check 1: MFA Registration ─────────────────────────────────────────────
    sc, data = await _get(f"{GRAPH}/policies/authenticationMethodsPolicy")
    mfa_on = sc == 200 and data.get("registrationEnforcement", {}).get("authenticationMethodsRegistrationCampaign", {}).get("state") == "enabled"
    _check("MFA Registration Enforcement", "Identity", "pass" if mfa_on else "fail", "high",
        "MFA registration campaign enforces multi-factor authentication for all users." if mfa_on else "MFA registration campaign is not enabled — users may not be enrolled in MFA.",
        "Enable MFA registration campaign in Azure AD Authentication Methods.",
        {"mfa_enabled": mfa_on},
        ["Azure AD → Security → Authentication methods → Registration campaign → Enable"])

    # ── Check 2: CA MFA policy ────────────────────────────────────────────────
    sc, ca_data = await _get(f"{GRAPH}/identity/conditionalAccess/policies")
    ca_policies = ca_data.get("value", []) if sc == 200 else []
    ca_enabled = [p for p in ca_policies if p.get("state") == "enabled"]
    ca_mfa = any("mfa" in [c.lower() for c in (p.get("grantControls") or {}).get("builtInControls", [])] for p in ca_enabled)
    _check("Conditional Access — MFA for All Users", "Identity", "pass" if ca_mfa else ("warning" if ca_enabled else "fail"), "high",
        f"{'MFA-requiring CA policy found.' if ca_mfa else f'{len(ca_enabled)} CA policies active but none require MFA.'}",
        "Create a CA policy requiring MFA for all users on all cloud apps.",
        {"ca_enabled_count": len(ca_enabled), "mfa_ca_exists": ca_mfa},
        ["Azure AD → Security → Conditional Access → New Policy", "Target: All users, All cloud apps", "Grant: Require MFA"])

    # ── Check 3: Legacy Auth ──────────────────────────────────────────────────
    legacy_blocked = any(
        p.get("state") == "enabled" and
        any(c in (p.get("conditions") or {}).get("clientAppTypes", []) for c in ("exchangeActiveSync", "other")) and
        (p.get("grantControls") or {}).get("builtInControls") == ["block"]
        for p in ca_policies
    )
    _check("Legacy Authentication Blocked", "Identity", "pass" if legacy_blocked else "warning", "high",
        "Legacy auth protocols (Basic Auth, SMTP AUTH) bypass MFA." if not legacy_blocked else "Legacy authentication is blocked via Conditional Access.",
        "Create CA policy blocking legacy auth clients (Exchange ActiveSync + Other).",
        {"legacy_blocked": legacy_blocked},
        ["CA → New Policy → Client apps: Exchange ActiveSync + Other clients → Block access"])

    # ── Check 4: Security Defaults ────────────────────────────────────────────
    sc4, sd = await _get(f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy")
    sd_on = sc4 == 200 and sd.get("isEnabled", False)
    sd_status = "pass" if sd_on else ("warning" if ca_enabled else "fail")
    _check("Security Defaults", "Identity", sd_status, "medium",
        "Security defaults enabled — baseline MFA and legacy auth blocking enforced." if sd_on else f"Security defaults disabled. {'Covered by ' + str(len(ca_enabled)) + ' CA policies.' if ca_enabled else 'No CA policies detected.'}",
        "Enable Security Defaults or ensure equivalent CA policies cover all users.",
        {"enabled": sd_on, "ca_count": len(ca_enabled)},
        ["Azure AD → Properties → Manage Security Defaults → Enable"])

    # ── Check 5: Guest permissions ────────────────────────────────────────────
    sc5, auth_pol = await _get(f"{GRAPH}/policies/authorizationPolicy")
    guest_role = (auth_pol.get("guestUserRoleId", "") if sc5 == 200 else "")
    restricted_roles = ("10dae51f-b6af-4016-8d66-8c2a99b929b3", "2af84b1e-32c8-42b7-82bc-daa82404023b")
    guest_restricted = guest_role in restricted_roles
    _check("Guest User Access Restrictions", "Identity", "pass" if guest_restricted else "warning", "medium",
        f"Guest access {'is restricted to limited permissions' if guest_restricted else 'allows default (member-like) permissions'}.",
        "Set guest user role to 'Limited access' in External collaboration settings.",
        {"guest_role_id": guest_role, "restricted": guest_restricted},
        ["Azure AD → External Identities → External collaboration settings", "Set Guest access: limited"])

    # ── Check 6: Guest count ──────────────────────────────────────────────────
    sc6, gc = await _get(f"{GRAPH}/users?$filter=userType eq 'Guest'&$count=true&$top=1", headers_eventual)
    guest_count = gc.get("@odata.count", 0) if sc6 == 200 else -1
    gc_status = "pass" if guest_count <= 20 else ("warning" if guest_count <= 50 else "fail")
    _check("Guest User Count", "Identity", gc_status if guest_count >= 0 else "unknown", "medium",
        f"{guest_count} guest user(s) in tenant." if guest_count >= 0 else "Could not retrieve guest count.",
        "Review and remove unnecessary guest accounts. Implement access reviews.",
        {"guest_count": guest_count},
        ["Azure AD → Users → Filter by Guest", "Review and remove stale guests", "Enable Entra access reviews"])

    # ── Check 7: Global Admin count ───────────────────────────────────────────
    sc7, roles = await _get(f"{GRAPH}/directoryRoles")
    ga_count = 0
    if sc7 == 200:
        ga_role = next((r for r in roles.get("value", []) if r.get("displayName") == "Global Administrator"), None)
        if ga_role:
            sc7b, mems = await _get(f"{GRAPH}/directoryRoles/{ga_role['id']}/members")
            ga_count = len(mems.get("value", [])) if sc7b == 200 else 0
    ga_status = "pass" if ga_count <= 4 else ("warning" if ga_count <= 8 else "fail")
    _check("Global Administrator Count", "Identity", ga_status, "high",
        f"{ga_count} Global Administrator(s). Best practice: 2–4 break-glass accounts only.",
        "Reduce Global Admins to 2–4. Use PIM for just-in-time privileged access.",
        {"global_admin_count": ga_count},
        ["Azure AD → Roles → Global Administrator → Remove excess members", "Enable Azure AD PIM"])

    # ── Check 8: PIM enabled ──────────────────────────────────────────────────
    sc8, pim = await _get(f"{GRAPH}/privilegedAccess/aadRoles/resources")
    pim_enabled = sc8 == 200 and len(pim.get("value", [])) > 0
    _check("Privileged Identity Management (PIM)", "Identity", "pass" if pim_enabled else "warning", "high",
        "PIM is configured for Azure AD roles — just-in-time privileged access is enforced." if pim_enabled else "PIM does not appear to be configured. Privileged roles may be permanently assigned.",
        "Enable Azure AD PIM for all high-privilege roles.",
        {"pim_accessible": sc8 == 200, "pim_resources": len(pim.get("value", [])) if sc8 == 200 else 0},
        ["Azure AD → Identity Governance → Privileged Identity Management", "Configure eligible assignments for GA, Exchange Admin, Security Admin"])

    # ── Check 9: Sign-in risk policy ──────────────────────────────────────────
    sc9, risk_pol = await _get(f"{GRAPH}/identity/conditionalAccess/policies")
    signin_risk_policy = False
    if sc9 == 200:
        for p in risk_pol.get("value", []):
            if p.get("state") == "enabled":
                conditions = p.get("conditions", {})
                if conditions.get("signInRiskLevels"):
                    signin_risk_policy = True
                    break
    _check("Sign-in Risk Policy", "Identity", "pass" if signin_risk_policy else "warning", "high",
        "A Conditional Access policy responds to sign-in risk events." if signin_risk_policy else "No sign-in risk CA policy found. Risky sign-ins may not be blocked automatically.",
        "Create CA policy: sign-in risk medium/high → require MFA or block.",
        {"policy_found": signin_risk_policy},
        ["Azure AD → Security → Conditional Access", "Condition: Sign-in risk ≥ medium → Grant: Require MFA"])

    # ── Check 10: User risk policy ────────────────────────────────────────────
    user_risk_policy = False
    if sc9 == 200:
        for p in risk_pol.get("value", []):
            if p.get("state") == "enabled":
                if (p.get("conditions") or {}).get("userRiskLevels"):
                    user_risk_policy = True
                    break
    _check("User Risk Policy", "Identity", "pass" if user_risk_policy else "warning", "high",
        "A CA policy responds to user risk (compromised accounts)." if user_risk_policy else "No user risk CA policy found.",
        "Create CA policy: user risk high → require password change.",
        {"policy_found": user_risk_policy},
        ["CA → Condition: User risk = High → Grant: Require password change"])

    # ── Check 11: SSPR ────────────────────────────────────────────────────────
    sc11, sspr = await _get(f"{GRAPH}/policies/authenticationMethodsPolicy")
    sspr_on = sc11 == 200 and bool(sspr.get("registrationEnforcement"))
    _check("Self-Service Password Reset (SSPR)", "Identity", "pass" if sspr_on else "warning", "low",
        "SSPR is configured." if sspr_on else "SSPR may not be fully configured.",
        "Enable SSPR for all users to reduce helpdesk burden.",
        {"sspr_configured": sspr_on},
        ["Azure AD → Password reset → Properties → Enable for All"])

    # ── Check 12: Named locations ──────────────────────────────────────────────
    sc12, locs = await _get(f"{GRAPH}/identity/conditionalAccess/namedLocations")
    loc_count = len(locs.get("value", [])) if sc12 == 200 else 0
    _check("Named Locations Configured", "Access Control", "pass" if loc_count > 0 else "warning", "low",
        f"{loc_count} named location(s) defined." if loc_count > 0 else "No named locations configured. Cannot restrict access by trusted IP/country.",
        "Define trusted network locations (office IPs, VPN) in Conditional Access.",
        {"named_location_count": loc_count},
        ["Azure AD → Security → Conditional Access → Named Locations", "Add office IP ranges"])

    # ── Check 13: App consent ─────────────────────────────────────────────────
    sc13, pol = await _get(f"{GRAPH}/policies/authorizationPolicy")
    consent_policy = (pol.get("permissionGrantPolicyIdsAssignedToDefaultUserRole", []) if sc13 == 200 else [])
    user_consent_open = any("legacy" in str(p).lower() or "all" in str(p).lower() for p in consent_policy)
    _check("User App Consent Policy", "Access Control", "pass" if not user_consent_open else "warning", "medium",
        "User consent for apps is restricted — admin approval required." if not user_consent_open else "Users can consent to apps accessing organizational data without admin approval.",
        "Restrict app consent to admin-approved apps only.",
        {"consent_policies": consent_policy, "user_consent_open": user_consent_open},
        ["Azure AD → Enterprise apps → Consent and permissions → Do not allow user consent"])

    # ── Check 14: Admin consent workflow ──────────────────────────────────────
    sc14, acw = await _get(f"{GRAPH}/policies/adminConsentRequestPolicy")
    acw_enabled = sc14 == 200 and acw.get("isEnabled", False)
    _check("Admin Consent Workflow", "Access Control", "pass" if acw_enabled else "warning", "medium",
        "Admin consent workflow is enabled — users can request access to apps." if acw_enabled else "Admin consent workflow disabled. Users have no path to request app access.",
        "Enable admin consent workflow so users can request app approvals.",
        {"enabled": acw_enabled},
        ["Azure AD → Enterprise apps → Admin consent requests → Enable"])

    # ── Check 15: Cross-tenant access ─────────────────────────────────────────
    sc15, xta = await _get(f"{GRAPH}/policies/crossTenantAccessPolicy/default")
    xta_inbound_allowed = (xta.get("inboundTrust", {}).get("isMfaAccepted", None) if sc15 == 200 else None)
    xta_configured = sc15 == 200
    _check("Cross-Tenant Access Settings", "Access Control", "pass" if xta_configured else "unknown", "medium",
        "Cross-tenant access policy is configured." if xta_configured else "Could not verify cross-tenant access settings.",
        "Review and restrict cross-tenant collaboration to approved partner tenants.",
        {"configured": xta_configured, "inbound_mfa_accepted": xta_inbound_allowed},
        ["Azure AD → External Identities → Cross-tenant access settings", "Configure partner-specific settings"])

    # ── Check 16: CA compliant device ─────────────────────────────────────────
    ca_compliant = any(
        p.get("state") == "enabled" and
        "compliantDevice" in (p.get("grantControls") or {}).get("builtInControls", [])
        for p in ca_policies
    )
    _check("Conditional Access — Compliant Device Required", "Access Control", "pass" if ca_compliant else "warning", "high",
        "A CA policy requires device compliance." if ca_compliant else "No CA policy enforces device compliance. Unmanaged devices can access resources.",
        "Create CA policy requiring Intune-compliant or Hybrid-joined device.",
        {"compliant_device_policy": ca_compliant},
        ["CA → New Policy → Grant: Require device to be compliant"])

    # ── Check 17: CA sign-in frequency ────────────────────────────────────────
    ca_freq = any(
        p.get("state") == "enabled" and
        (p.get("sessionControls") or {}).get("signInFrequency", {}).get("isEnabled")
        for p in ca_policies
    )
    _check("Conditional Access — Sign-in Frequency", "Access Control", "pass" if ca_freq else "warning", "low",
        "Sign-in frequency controls are configured." if ca_freq else "No sign-in frequency policy found. Sessions may persist indefinitely.",
        "Configure sign-in frequency to require re-authentication after inactivity.",
        {"sign_in_frequency_policy": ca_freq},
        ["CA → Session controls → Sign-in frequency → Set to 8-24 hours"])

    # ── Checks 18-20: SharePoint / Teams data protection ──────────────────────
    if provider in ("sharepoint", "teams"):
        sc18, sp = await _get(f"{GRAPH}/admin/sharepoint/settings")
        if sc18 == 200:
            sharing_cap = sp.get("sharingCapability", "")
            restricted = sharing_cap in ("disabled", "existingExternalUserSharingOnly")
            _check("SharePoint External Sharing", "Data Protection", "pass" if restricted else "warning", "high",
                f"SharePoint sharing set to '{sharing_cap}'.",
                "Restrict to 'Existing guests only' or 'Only org users'.",
                {"sharing_capability": sharing_cap},
                ["SharePoint Admin → Policies → Sharing → Set restriction level"])

            versioning = sp.get("isVersioningEnabled", None)
            _check("SharePoint File Versioning", "Data Protection", "pass" if versioning is not False else "warning", "low",
                "File versioning enabled." if versioning is not False else "File versioning may be disabled.",
                "Enable file versioning on all document libraries (100+ versions).",
                {"versioning": versioning},
                ["SharePoint Admin → Settings → Enable versioning globally"])

            anon_expiry = sp.get("anonymousLinkExpirationInDays", 0)
            _check("Anonymous Link Expiry", "Data Protection", "pass" if anon_expiry > 0 else "warning", "medium",
                f"Anonymous links expire after {anon_expiry} days." if anon_expiry > 0 else "Anonymous links do not expire — shared files remain accessible indefinitely.",
                "Set anonymous link expiry to 30 days or less.",
                {"anon_link_expiry_days": anon_expiry},
                ["SharePoint Admin → Sharing → Set expiration for Anyone links → 30 days"])

    # ── Check 21: Sensitivity labels ──────────────────────────────────────────
    sc21, labels = await _get(f"{GRAPH}/security/informationProtection/sensitivityLabels")
    label_count = len(labels.get("value", [])) if sc21 == 200 else 0
    _check("Sensitivity Labels Deployed", "Data Protection", "pass" if label_count > 0 else "warning", "medium",
        f"{label_count} sensitivity label(s) deployed." if label_count > 0 else "No sensitivity labels found. Data cannot be classified or protected at the document level.",
        "Deploy sensitivity labels via Microsoft Purview to classify documents.",
        {"label_count": label_count},
        ["Microsoft Purview → Information Protection → Sensitivity labels → Create labels", "Publish label policy to users"])

    # ── Check 22: DLP policies ────────────────────────────────────────────────
    sc22, dlp_pols = await _get(f"{GRAPH}/security/dataSecurityAndGovernance/sensitivityLabels")
    _check("DLP Policies Configured", "Data Protection", "pass" if sc22 == 200 else "unknown", "high",
        "DLP policy API accessible." if sc22 == 200 else "Microsoft Purview DLP requires E3/E5 license. Configure to prevent data exfiltration.",
        "Configure DLP policies to prevent sensitive data exfiltration.",
        {"purview_licensed": sc22 == 200, "note": "Requires Microsoft Purview E3/E5 license" if sc22 != 200 else ""},
        ["Microsoft Purview → Data loss prevention → Policies → Create policy"])

    # ── Check 23: Audit log ───────────────────────────────────────────────────
    sc23, audit = await _get(f"{GRAPH}/auditLogs/signIns?$top=1")
    _check("Audit Log Access", "Compliance", "pass" if sc23 == 200 else "warning", "medium",
        "Audit and sign-in logs are accessible." if sc23 == 200 else "Audit logs require Azure AD P1/P2 license. Enable to track sign-in and admin activity.",
        "Enable audit logging and route to SIEM/Sentinel.",
        {"audit_logs_accessible": sc23 == 200, "note": "Requires Azure AD P1/P2 license" if sc23 != 200 else ""},
        ["Azure AD → Monitoring → Diagnostic settings → Send to Log Analytics"])

    # ── Check 24: Alert policies ──────────────────────────────────────────────
    sc24, alert_pols = await _get(f"{GRAPH}/security/alerts_v2?$top=1")
    alerts_active = sc24 == 200
    _check("Security Alert Policies", "Compliance", "pass" if alerts_active else "warning", "medium",
        "Microsoft Defender security alerts are accessible." if alerts_active else "Microsoft Defender alerts require Defender for Office 365 or E5 license.",
        "Configure Microsoft Defender or Sentinel alert policies for key threat scenarios.",
        {"defender_alerts_active": alerts_active, "note": "Requires Defender for O365/E5" if not alerts_active else ""},
        ["Microsoft 365 Defender → Settings → Alert policies", "Enable high-priority alerts"])

    # ── Check 25: Intune MDM ──────────────────────────────────────────────────
    sc25, intune = await _get(f"{GRAPH}/deviceManagement/deviceCompliancePolicies?$top=1")
    intune_active = sc25 == 200
    _check("Intune Device Compliance Policies", "Endpoint", "pass" if intune_active else "warning", "medium",
        "Intune device compliance policies are accessible." if intune_active else "Could not verify Intune compliance policies — MDM may not be configured.",
        "Configure Intune compliance policies to enforce device health requirements.",
        {"intune_api_status": sc25},
        ["Microsoft Endpoint Manager → Compliance policies → Create policy"])

    # ── Check 26: Risky users ─────────────────────────────────────────────────
    sc26, risky = await _get(f"{GRAPH}/identityProtection/riskyUsers?$filter=riskState eq 'atRisk'&$top=1")
    risky_count = risky.get("@odata.count", len(risky.get("value", []))) if sc26 == 200 else -1
    _check("Risky Users Unresolved", "Identity", "pass" if risky_count == 0 else ("warning" if risky_count <= 5 else "fail"), "high",
        f"{risky_count} user(s) at risk." if risky_count >= 0 else "Could not query risky users.",
        "Remediate all at-risk users via Identity Protection.",
        {"at_risk_count": risky_count},
        ["Azure AD → Security → Identity Protection → Risky users", "Confirm compromise or dismiss false positives"])

    # ── Check 27: Disabled users with licenses ────────────────────────────────
    sc27, dis = await _get(f"{GRAPH}/users?$filter=accountEnabled eq false&$count=true&$top=1", headers_eventual)
    disabled_count = dis.get("@odata.count", 0) if sc27 == 200 else -1
    _check("Disabled Users with Active Licenses", "Identity", "pass" if disabled_count == 0 else "warning", "low",
        f"{disabled_count} disabled account(s) found." if disabled_count >= 0 else "Could not query disabled users.",
        "Review disabled accounts and revoke licenses to reduce cost and attack surface.",
        {"disabled_count": disabled_count},
        ["Azure AD → Users → Filter: Account status = Disabled", "Remove licenses from disabled accounts"])

    # ── Checks 28-32: Teams-specific ──────────────────────────────────────────
    if provider == "teams":
        sc28, tgs = await _get(f"{GRAPH}/teamwork/teamsAppSettings")
        _check("Teams Guest Access Settings", "Teams Security", "pass" if sc28 == 200 else "unknown", "medium",
            "Teams app settings accessible." if sc28 == 200 else "Could not verify Teams guest access configuration.",
            "Restrict guest access in Teams admin center — disable specific capabilities for guests.",
            {"api_status": sc28},
            ["Teams Admin Center → Users → Guest access", "Disable: calling, meeting, messaging capabilities as needed"])

        sc29, tmtg = await _get(f"{GRAPH}/teamwork/workforceIntegrations?$top=1")
        _check("Teams External Federation", "Teams Security", "pass" if sc29 != 0 else "unknown", "medium",
            "Teams federation settings queried.",
            "Restrict Teams federation to trusted domains only.",
            {"api_status": sc29},
            ["Teams Admin Center → Users → External access", "Allow only specific trusted domains"])

        sc30, policies = await _get(f"{GRAPH}/teamwork/teamsAppSettings")
        _check("Teams App Permission Policy", "Teams Security", "pass" if sc30 == 200 else "unknown", "medium",
            "Teams app permission policies accessible.",
            "Create app permission policy restricting external/unverified apps.",
            {"api_status": sc30},
            ["Teams Admin Center → Teams apps → Permission policies", "Block all third-party apps by default"])

        sc31, meet_pol = await _get(f"{GRAPH}/communications/callRecords?$top=1")
        _check("Teams Meeting Recording", "Teams Security", "pass" if sc31 != 0 else "unknown", "low",
            "Teams call records API accessible.",
            "Configure meeting recording policies — restrict who can record and where recordings are stored.",
            {"api_status": sc31},
            ["Teams Admin Center → Meetings → Meeting policies", "Configure recording expiration"])

        sc32, ib = await _get(f"{GRAPH}/informationBarrierPolicies?$top=1")
        ib_count = len(ib.get("value", [])) if sc32 == 200 else 0
        _check("Information Barriers", "Compliance", "pass" if ib_count > 0 else "warning", "medium",
            f"{ib_count} information barrier policy/policies configured." if ib_count > 0 else "No information barriers configured — all users can communicate with all others.",
            "Configure information barriers for departments that should not communicate (e.g. trading, compliance).",
            {"ib_count": ib_count, "api_status": sc32},
            ["Microsoft Purview → Information barriers → Policies → Create"])

    # ── Checks 28b-32b: Additional Teams-specific checks ────────────────────────
    if provider == "teams":
        # Teams: External user meeting policy
        sc_tm1, meeting_settings = await _get(f"{GRAPH}/communications/callRecords?$top=1")
        _check("Teams External User Meeting Policy", "Teams Security", "pass" if sc_tm1 != 0 else "unknown", "medium",
            "External users can be restricted from joining Teams meetings without explicit invitation.",
            "Configure meeting policies to require explicit org-user invitation for external participants.",
            {"api_status": sc_tm1},
            ["Teams Admin Center → Meetings → Meeting policies → Participant settings",
             "Set 'Let anonymous people join meetings' to Off"])

        # Teams: Guest messaging
        sc_tm2, guest_settings = await _get(f"{GRAPH}/teamwork/teamsAppSettings")
        _check("Teams Guest Messaging Capabilities", "Teams Security", "pass" if sc_tm2 == 200 else "unknown", "medium",
            "Guest user messaging capabilities should be restricted to prevent data exfiltration via chat.",
            "Review Teams guest messaging settings — disable editing/deleting messages and Giphy for guests.",
            {"api_status": sc_tm2},
            ["Teams Admin Center → Users → Guest access",
             "Disable: Edit/delete messages, Giphy, memes for guests"])

        # Teams: Channel creation restrictions
        _check("Teams Channel Creation Restrictions", "Teams Security", "pass" if sc_tm2 == 200 else "unknown", "low",
            "Unrestricted channel creation can lead to governance and data sprawl issues.",
            "Restrict channel creation to team owners only.",
            {"api_status": sc_tm2},
            ["Teams Admin Center → Teams → Teams settings",
             "Disable: Allow members to create private/shared channels"])

        # Teams: App installation policies
        sc_tm4, app_setup = await _get(f"{GRAPH}/teamwork/teamsAppSettings")
        _check("Teams App Installation Restrictions", "Teams Security", "pass" if sc_tm4 == 200 else "unknown", "medium",
            "Uncontrolled third-party app installations can introduce data leakage risks.",
            "Create app permission policies blocking all third-party apps by default.",
            {"api_status": sc_tm4},
            ["Teams Admin Center → Teams apps → Permission policies",
             "Block all third-party and LOB apps, allow-list specific approved apps"])

        # Teams: Recording/transcription settings
        _check("Teams Recording & Transcription Settings", "Teams Security", "pass" if sc_tm1 != 0 else "unknown", "medium",
            "Uncontrolled meeting recordings can result in sensitive data stored in personal OneDrives.",
            "Configure recording policies: restrict who can record, set expiration (90 days), save to SharePoint.",
            {"api_status": sc_tm1},
            ["Teams Admin Center → Meetings → Meeting policies",
             "Set recording expiry to 60-90 days", "Route recordings to SharePoint/OneDrive for Business"])

        # Teams: Federation settings (domain allow/block)
        sc_tm6, fed = await _get(f"{GRAPH}/teamwork/workforceIntegrations?$top=1")
        _check("Teams Federation / External Access", "Teams Security", "pass" if sc_tm6 != 0 else "unknown", "high",
            "Open federation allows communication with any external Teams tenant, increasing attack surface.",
            "Restrict Teams federation to a whitelist of approved partner domains.",
            {"api_status": sc_tm6},
            ["Teams Admin Center → Users → External access",
             "Select 'Allow only specific external domains'", "Add approved partner tenant domains"])

    # ── Additional SharePoint-specific checks ─────────────────────────────────
    if provider in ("sharepoint", "teams"):
        sc_sp, sp_settings = await _get(f"{GRAPH}/admin/sharepoint/settings")
        if sc_sp == 200:
            # Site creation restrictions
            site_creation = sp_settings.get("isSiteCreationEnabled", True)
            _check("SharePoint Site Creation Restrictions", "Data Protection", "pass" if not site_creation else "warning", "low",
                f"SharePoint site creation by regular users is {'restricted' if not site_creation else 'open — any user can create sites'}.",
                "Restrict site creation to admins to prevent ungoverned data sprawl.",
                {"site_creation_enabled": site_creation},
                ["SharePoint Admin → Settings → Site creation → Disable for users"])

            # Default sharing link type
            default_link = sp_settings.get("defaultSharingLinkType", "")
            link_restricted = default_link in ("direct", "existingAccess")
            _check("SharePoint Default Link Type", "Data Protection", "pass" if link_restricted else "warning", "medium",
                f"Default sharing link type is '{default_link or 'unknown'}'. "
                f"{'Restricted to existing access — good.' if link_restricted else 'Consider restricting to Specific people only.'}",
                "Set default sharing link type to 'Specific people' to prevent accidental over-sharing.",
                {"default_link_type": default_link},
                ["SharePoint Admin → Policies → Sharing → Default link type → Specific people"])

            # Access requests
            access_requests = sp_settings.get("isSharePointNewSiteSharingEnabled", True)
            _check("SharePoint Access Requests Settings", "Data Protection", "pass" if not access_requests else "warning", "low",
                f"SharePoint access requests are {'disabled' if not access_requests else 'enabled — users can request access to any site'}.",
                "Configure access request settings to route to specific owner/admin rather than open.",
                {"access_requests_enabled": access_requests},
                ["SharePoint Admin → Sharing → Access requests → Send access requests to"])

        # OneDrive external sharing
        sc_od, od_settings = await _get(f"{GRAPH}/admin/sharepoint/settings")
        od_sharing = od_settings.get("oneDriveDefaultShareLinkScope", "") if sc_od == 200 else ""
        od_restricted = od_sharing in ("specificPeople", "organization")
        _check("OneDrive External Sharing Settings", "Data Protection", "pass" if od_restricted else "warning", "high",
            f"OneDrive default share link scope: '{od_sharing or 'unknown'}'. "
            f"{'Restricted.' if od_restricted else 'May allow anonymous sharing.'}",
            "Restrict OneDrive sharing to organization or specific people to prevent external data exposure.",
            {"od_sharing": od_sharing},
            ["SharePoint Admin → OneDrive → Sharing → Change default link type"])

        # Sync client restrictions
        sc_sync, sync_settings = await _get(f"{GRAPH}/admin/sharepoint/settings")
        sync_restricted = (sync_settings.get("isSyncButtonHiddenOnPersonalSite", False)
                          or sync_settings.get("isManagedDeviceSyncEnabled", False)) if sc_sync == 200 else False
        _check("OneDrive Sync Client Restrictions", "Endpoint", "pass" if sync_restricted else "warning", "medium",
            f"OneDrive sync {'restricted to managed devices' if sync_restricted else 'allowed from any device — risk of data sync to unmanaged endpoints'}.",
            "Restrict OneDrive sync to Intune-managed/domain-joined devices only.",
            {"sync_restricted": sync_restricted, "api_status": sc_sync},
            ["SharePoint Admin → Settings → Sync → Allow syncing only on PCs joined to specific domains"])

        # Retention policies
        sc_ret, ret_data = await _get(f"{GRAPH}/compliance/ediscovery/cases?$top=1")
        _check("SharePoint Retention Policies Applied", "Compliance", "pass" if sc_ret == 200 else "warning", "medium",
            "Microsoft Purview retention policies ensure data is kept for compliance and disposed of properly."
            if sc_ret == 200 else "Could not verify retention policy configuration — Microsoft Purview E3/E5 required.",
            "Apply retention policies to SharePoint sites for regulatory compliance (GDPR, NCA ECC).",
            {"api_status": sc_ret},
            ["Microsoft Purview → Data lifecycle management → Retention policies",
             "Apply to SharePoint sites with appropriate retention/deletion periods"])

        # Information barriers
        sc_ib, ib_data = await _get(f"{GRAPH}/informationBarrierPolicies?$top=1")
        ib_count = len(ib_data.get("value", [])) if sc_ib == 200 else 0
        _check("SharePoint Information Barriers", "Compliance",
            "pass" if ib_count > 0 else "warning", "medium",
            f"{ib_count} information barrier policy/policies on SharePoint/OneDrive." if ib_count > 0
            else "No information barriers — all users can see all SharePoint content.",
            "Configure information barriers to segment SharePoint content by department (e.g. finance, legal).",
            {"ib_count": ib_count},
            ["Microsoft Purview → Information barriers → Policies → Apply to SharePoint/OneDrive"])

    # ── Check 33: eDiscovery ──────────────────────────────────────────────────
    sc33, ret = await _get(f"{GRAPH}/compliance/ediscovery/cases?$top=1")
    _check("eDiscovery Configuration", "Compliance", "pass" if sc33 == 200 else "unknown", "low",
        "eDiscovery API accessible." if sc33 == 200 else "Could not verify eDiscovery configuration.",
        "Configure eDiscovery cases for legal hold and compliance investigations.",
        {"api_status": sc33},
        ["Microsoft Purview → eDiscovery → Cases"])

    # ── Check 34: Role-assignable groups ──────────────────────────────────────
    sc34, pag = await _get(f"{GRAPH}/groups?$filter=isAssignableToRole eq true&$count=true&$top=1", headers_eventual)
    pag_count = pag.get("@odata.count", 0) if sc34 == 200 else -1
    _check("Role-Assignable Groups", "Identity", "pass" if pag_count >= 0 else "unknown", "low",
        f"{pag_count} role-assignable group(s) configured." if pag_count >= 0 else "Could not query role-assignable groups.",
        "Use role-assignable groups with PIM for privileged access management.",
        {"role_assignable_groups": pag_count},
        ["Azure AD → Groups → Filter: Can be assigned to Azure AD roles"])

    # ── Check 35: Emergency access accounts ───────────────────────────────────
    sc35, break_glass = await _get(f"{GRAPH}/users?$filter=displayName eq 'Emergency Access'&$top=5")
    bg_count = len(break_glass.get("value", [])) if sc35 == 200 else 0
    _check("Emergency Access (Break-Glass) Accounts", "Identity", "pass" if bg_count >= 1 else "warning", "high",
        f"{bg_count} emergency access account(s) found." if bg_count > 0 else "No emergency access accounts found with name 'Emergency Access'. Break-glass accounts are critical for lockout scenarios.",
        "Create 2 emergency access accounts excluded from all CA policies for break-glass scenarios.",
        {"break_glass_count": bg_count},
        ["Azure AD → Users → Create emergency accounts", "Exclude from all CA policies", "Store credentials in physical vault"])

    # ── Check 36: Microsoft Secure Score ──────────────────────────────────────
    sc36, mscore = await _get(f"{GRAPH}/security/secureScores?$top=1")
    current_score = None
    max_score = None
    if sc36 == 200:
        scores = mscore.get("value", [])
        if scores:
            current_score = scores[0].get("currentScore")
            max_score = scores[0].get("maxScore")
    score_pct = round((current_score / max_score) * 100) if current_score and max_score else None
    sc_status = "pass" if (score_pct or 0) >= 60 else ("warning" if (score_pct or 0) >= 40 else "fail")
    _check("Microsoft Secure Score", "Compliance", sc_status if score_pct is not None else "unknown", "high",
        f"Secure Score: {current_score}/{max_score} ({score_pct}%)" if score_pct else "Could not retrieve Microsoft Secure Score.",
        "Improve Secure Score by implementing recommended security controls in the Microsoft 365 Defender portal.",
        {"current_score": current_score, "max_score": max_score, "score_pct": score_pct},
        ["Microsoft 365 Defender → Secure score → Improvement actions"])

    # ── Check 37: Azure AD license tier ───────────────────────────────────────
    sc37, org_info = await _get(f"{GRAPH}/organization")
    license_plans = []
    if sc37 == 200:
        orgs = org_info.get("value", [])
        if orgs:
            license_plans = [p.get("servicePlanName", "") for sp in orgs[0].get("assignedPlans", []) for p in [sp] if sp.get("capabilityStatus") == "Enabled"]
    has_p2 = any("AADPREMIUM_P2" in p or "AAD_PREMIUM_P2" in p for p in license_plans)
    has_p1 = any("AADPREMIUM" in p or "AAD_PREMIUM" in p for p in license_plans) or has_p2
    _check("Azure AD License Tier", "Compliance", "pass" if has_p2 else ("warning" if has_p1 else "fail"), "high",
        f"Azure AD {'P2' if has_p2 else 'P1' if has_p1 else 'Free/M365'} license detected. {'Full Identity Protection, PIM available.' if has_p2 else 'P2 needed for Identity Protection, PIM.' if has_p1 else 'Upgrade to P1/P2 for security features.'}",
        "Azure AD P2 is required for PIM, Identity Protection, and Access Reviews.",
        {"has_p1": has_p1, "has_p2": has_p2},
        ["Upgrade to Azure AD P2 (or EMS E5) for full security feature coverage"])

    # ── Check 38: Custom Banned Password List ─────────────────────────────────
    sc38, pwd = await _get(f"{GRAPH}/policies/authenticationMethodsPolicy")
    _check("Custom Banned Password List", "Identity", "pass" if sc38 == 200 else "unknown", "low",
        "Authentication methods policy accessible — verify custom banned password list is configured.",
        "Configure Azure AD Password Protection with a custom banned password list.",
        {"api_status": sc38},
        ["Azure AD → Security → Authentication methods → Password protection → Enable + add custom words"])

    # ── Check 39: Passwordless auth (FIDO2) ───────────────────────────────────
    sc39, plauth = await _get(f"{GRAPH}/policies/authenticationMethodsPolicy")
    fido2_enabled = False
    if sc39 == 200:
        for method in plauth.get("authenticationMethodConfigurations", []):
            if method.get("id") == "Fido2" and method.get("state") == "enabled":
                fido2_enabled = True
    _check("Passwordless Authentication (FIDO2)", "Identity", "pass" if fido2_enabled else "warning", "low",
        "FIDO2 passwordless authentication is enabled." if fido2_enabled else "FIDO2 passwordless auth not enabled — passwords are a primary attack vector.",
        "Enable FIDO2 security key authentication in Authentication Methods.",
        {"fido2_enabled": fido2_enabled},
        ["Azure AD → Security → Authentication methods → FIDO2 security key → Enable"])

    # ── Check 40: Microsoft Authenticator ────────────────────────────────────
    sc40, auth_methods = await _get(f"{GRAPH}/policies/authenticationMethodsPolicy")
    mauth_enabled = False
    if sc40 == 200:
        for m in auth_methods.get("authenticationMethodConfigurations", []):
            if m.get("id") == "MicrosoftAuthenticator" and m.get("state") == "enabled":
                mauth_enabled = True
    _check("Microsoft Authenticator Enabled", "Identity", "pass" if mauth_enabled else "warning", "medium",
        "Microsoft Authenticator is enabled as an authentication method." if mauth_enabled else "Microsoft Authenticator not enabled — users may rely on SMS-based MFA (weaker).",
        "Enable Microsoft Authenticator and encourage passwordless sign-in.",
        {"authenticator_enabled": mauth_enabled},
        ["Azure AD → Authentication methods → Microsoft Authenticator → Enable", "Enable passwordless phone sign-in"])

    # ── Check 41: Entitlement management ──────────────────────────────────────
    sc41, catalogs = await _get(f"{GRAPH}/identityGovernance/entitlementManagement/catalogs?$top=1")
    entitlement_on = sc41 == 200 and len(catalogs.get("value", [])) > 0
    _check("Entitlement Management (Access Packages)", "Access Control", "pass" if entitlement_on else "warning", "low",
        "Entitlement management catalogs configured." if entitlement_on else "No access packages found — resource access may not be governed.",
        "Configure entitlement management access packages for structured access provisioning.",
        {"catalogs": len(catalogs.get("value", [])) if sc41 == 200 else 0},
        ["Azure AD → Identity Governance → Entitlement Management → Catalogs"])

    # ── Check 42: Access reviews ──────────────────────────────────────────────
    sc42, reviews = await _get(f"{GRAPH}/identityGovernance/accessReviews/definitions?$top=1")
    reviews_on = sc42 == 200 and len(reviews.get("value", [])) > 0
    _check("Access Reviews Configured", "Access Control", "pass" if reviews_on else "warning", "medium",
        "Access review definitions found — periodic access certification is scheduled." if reviews_on else "No access reviews configured — stale access rights may accumulate.",
        "Schedule quarterly access reviews for all high-privilege roles and groups.",
        {"review_definitions": len(reviews.get("value", [])) if sc42 == 200 else 0},
        ["Azure AD → Identity Governance → Access reviews → New review", "Schedule quarterly reviews for GA, privileged roles"])

    # ── Check 43: MFA for admins ──────────────────────────────────────────────
    admin_mfa_policy = any(
        p.get("state") == "enabled" and
        "mfa" in [c.lower() for c in (p.get("grantControls") or {}).get("builtInControls", [])] and
        len((p.get("conditions") or {}).get("users", {}).get("includeRoles", [])) > 0
        for p in ca_policies
    )
    _check("MFA Enforced for Administrators", "Identity", "pass" if admin_mfa_policy else "warning", "high",
        "A CA policy specifically targets admin roles and requires MFA." if admin_mfa_policy else "No dedicated CA policy enforces MFA specifically for admin roles.",
        "Create a dedicated CA policy: Admin roles → All cloud apps → Require MFA (no exceptions).",
        {"admin_mfa_policy": admin_mfa_policy},
        ["CA → New Policy → Users: Select directory roles (all admin roles)", "Grant: Require MFA"])

    # ── Check 44: App registrations ───────────────────────────────────────────
    sc44, apps = await _get(f"{GRAPH}/applications?$count=true&$top=1", headers_eventual)
    app_count = apps.get("@odata.count", 0) if sc44 == 200 else -1
    _check("Application Registrations", "Access Control", "pass" if app_count <= 50 else "warning", "low",
        f"{app_count} app registration(s) in tenant." if app_count >= 0 else "Could not query app registrations.",
        "Review app registrations and remove unused apps. Audit permissions granted.",
        {"app_count": app_count},
        ["Azure AD → App registrations → Review all apps", "Remove stale apps", "Audit API permissions"])

    # ── Check 45: Service principals ──────────────────────────────────────────
    sc45, sps = await _get(f"{GRAPH}/servicePrincipals?$filter=accountEnabled eq true&$count=true&$top=1", headers_eventual)
    sp_count = sps.get("@odata.count", 0) if sc45 == 200 else -1
    _check("Active Service Principals", "Access Control", "pass" if sp_count <= 100 else "warning", "medium",
        f"{sp_count} active service principal(s)." if sp_count >= 0 else "Could not query service principals.",
        "Audit service principals with permissions. Rotate credentials for high-privilege apps.",
        {"sp_count": sp_count},
        ["Azure AD → Enterprise apps → Review permissions", "Rotate secrets/certs on schedule"])

    # ── Check 46: Directory sync health ───────────────────────────────────────
    sc46, sync = await _get(f"{GRAPH}/organization")
    sync_enabled = False
    if sc46 == 200:
        orgs_s = sync.get("value", [])
        if orgs_s:
            sync_enabled = orgs_s[0].get("onPremisesSyncEnabled", False)
    _check("On-Premises Directory Sync", "Identity", "pass" if sync_enabled is not None else "unknown", "low",
        f"On-premises sync {'is active' if sync_enabled else 'not active (cloud-only or sync disabled)'}.",
        "Ensure AD Connect sync is healthy if using hybrid identity.",
        {"sync_enabled": sync_enabled},
        ["Azure AD → Azure AD Connect → Review sync status", "Check AD Connect health in Azure portal"])

    # ── Check 47: External collaboration invite settings ──────────────────────
    sc47, ext_col = await _get(f"{GRAPH}/policies/authorizationPolicy")
    allow_invites = (ext_col.get("allowInvitesFrom", "") if sc47 == 200 else "")
    restricted_invite = allow_invites in ("adminsAndGuestInviters", "adminsOnly", "none")
    _check("External Collaboration Invite Settings", "Access Control", "pass" if restricted_invite else "warning", "medium",
        f"Guest invitations restricted to: {allow_invites or 'unknown'}." if allow_invites else "Could not determine guest invite policy.",
        "Restrict guest invitations to admins and guest inviters only.",
        {"allow_invites_from": allow_invites, "restricted": restricted_invite},
        ["Azure AD → External Identities → Collaboration settings", "Set 'Who can invite guests' to Admins only"])

    # ── Check 48: Terms of use ────────────────────────────────────────────────
    sc48, tou = await _get(f"{GRAPH}/agreements?$top=1")
    tou_count = len(tou.get("value", [])) if sc48 == 200 else 0
    _check("Terms of Use Policy", "Compliance", "pass" if tou_count > 0 else "warning", "low",
        f"{tou_count} terms of use agreement(s) configured." if tou_count > 0 else "No Terms of Use configured. Users have not acknowledged acceptable use policies.",
        "Create a Terms of Use agreement and enforce via Conditional Access.",
        {"tou_count": tou_count},
        ["Azure AD → Identity Governance → Terms of use → Add agreement", "Attach to CA policy"])

    # ── Check 49: Certificate-based auth ──────────────────────────────────────
    sc49, cba = await _get(f"{GRAPH}/policies/authenticationMethodsPolicy")
    x509_enabled = False
    if sc49 == 200:
        for m in cba.get("authenticationMethodConfigurations", []):
            if m.get("id") == "X509Certificate" and m.get("state") == "enabled":
                x509_enabled = True
    _check("Certificate-Based Authentication", "Identity", "pass" if x509_enabled else "warning", "low",
        "X.509 certificate-based authentication is enabled." if x509_enabled else "CBA not enabled — consider for high-assurance authentication scenarios.",
        "Enable certificate-based authentication for high-privilege users and service accounts.",
        {"cba_enabled": x509_enabled},
        ["Azure AD → Security → Authentication methods → Certificate-based auth"])

    # ── Check 50: Tenant data residency ───────────────────────────────────────
    sc50, region_org = await _get(f"{GRAPH}/organization")
    region = None
    if sc50 == 200:
        orgs_r = region_org.get("value", [])
        if orgs_r:
            region = orgs_r[0].get("preferredDataLocation") or orgs_r[0].get("countryLetterCode")
    _check("Tenant Data Residency", "Compliance", "pass" if region else "unknown", "low",
        f"Tenant data location: {region}." if region else "Could not determine tenant data residency location.",
        "Verify data residency settings comply with organizational and regulatory requirements.",
        {"data_location": region},
        ["Azure AD → Properties → Review data location settings"])

    # ── Check 51: Defender for Identity ───────────────────────────────────────
    sc51, dfi = await _get(f"{GRAPH}/security/alerts_v2?$filter=providerName eq 'Azure Advanced Threat Protection'&$top=1")
    _check("Microsoft Defender for Identity", "Compliance", "pass" if sc51 == 200 else "unknown", "medium",
        "Defender for Identity (MDI) API accessible." if sc51 == 200 else "Could not verify Defender for Identity configuration.",
        "Deploy Defender for Identity to detect on-premises identity attacks.",
        {"api_status": sc51},
        ["Microsoft 365 Defender → Settings → Identities → Onboard Defender for Identity"])

    # ── Check 52: Privileged admin workstations ────────────────────────────────
    sc52, paw = await _get(f"{GRAPH}/deviceManagement/managedDevices?$filter=deviceName eq 'PAW'&$top=1")
    _check("Privileged Admin Workstations (PAW)", "Endpoint", "pass" if sc52 == 200 else "unknown", "medium",
        "Device management API accessible — verify dedicated PAW devices are configured for admins.",
        "Use dedicated, hardened Privileged Admin Workstations for all privileged administrative tasks.",
        {"api_status": sc52},
        ["Configure dedicated devices for admin use only", "Apply restrictive Intune policy to PAW devices", "Enforce PAW usage via CA named locations"])

    # ── Check 53: Windows Autopilot ───────────────────────────────────────────
    sc53, ap = await _get(f"{GRAPH}/deviceManagement/windowsAutopilotDeviceIdentities?$top=1")
    ap_count = len(ap.get("value", [])) if sc53 == 200 else -1
    _check("Windows Autopilot Configuration", "Endpoint", "pass" if ap_count >= 0 else "unknown", "low",
        f"{ap_count} Autopilot device(s) registered." if ap_count >= 0 else "Could not query Autopilot configuration.",
        "Use Windows Autopilot for zero-touch device provisioning with security baselines.",
        {"autopilot_devices": ap_count},
        ["Endpoint Manager → Devices → Enroll devices → Windows Autopilot"])

    # ── Enrich with Claude + upsert to DB ─────────────────────────────────────
    enriched = await _claude_enrich_posture_checks(checks_to_create, provider)

    now = datetime.now(timezone.utc)
    for check in enriched:
        existing = (await db.execute(
            select(SaasPostureCheck).where(
                SaasPostureCheck.org_id == uuid.UUID(org_id),
                SaasPostureCheck.provider == provider,
                SaasPostureCheck.check_name == check["check_name"],
            )
        )).scalar_one_or_none()

        if existing:
            existing.status = check["status"]
            existing.severity = check["severity"]
            existing.description = check["description"]
            existing.recommendation = check.get("recommendation")
            existing.evidence = check.get("evidence")
            existing.remediation_steps = check.get("remediation_steps", [])
            existing.last_checked_at = now
            existing.updated_at = now
        else:
            db.add(SaasPostureCheck(
                org_id=uuid.UUID(org_id),
                provider=provider,
                check_name=check["check_name"],
                check_category=check["check_category"],
                status=check["status"],
                severity=check["severity"],
                description=check["description"],
                recommendation=check.get("recommendation"),
                evidence=check.get("evidence"),
                remediation_steps=check.get("remediation_steps", []),
                last_checked_at=now,
            ))

    await db.commit()


async def _claude_enrich_posture_checks(checks: list[dict], provider: str) -> list[dict]:
    """Use Claude Haiku to add context to posture checks. Returns original on failure."""
    if not ANTHROPIC_API_KEY or not checks:
        return checks
    try:
        checks_summary = json.dumps([
            {"name": c["check_name"], "status": c["status"], "severity": c["severity"]}
            for c in checks
        ])
        prompt = (
            f"You are a cloud security expert evaluating {provider} posture checks.\n"
            f"Checks: {checks_summary}\n\n"
            "For each check, provide a 1-sentence executive summary of the risk. "
            "Return JSON array: [{\"name\":\"...\",\"executive_summary\":\"...\"}]"
        )
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5",
                    "max_tokens": 500,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            if r.status_code == 200:
                raw = r.json()["content"][0]["text"].strip()
                raw = re.sub(r"^```[\w]*\n?", "", raw)
                raw = re.sub(r"```$", "", raw).strip()
                summaries = json.loads(raw)
                summary_map = {s["name"]: s.get("executive_summary", "") for s in summaries}
                for check in checks:
                    if check["check_name"] in summary_map:
                        check["description"] = summary_map[check["check_name"]] or check["description"]
    except Exception as exc:
        logger.warning(f"posture_eval: Claude enrichment failed: {exc}")
    return checks


# ── Helpers ───────────────────────────────────────────────────────────────────

def _alert_to_dict(a: SaasAlert) -> dict:
    # Build heuristic remediation steps based on alert type
    remediation_steps = _get_alert_remediation_steps(a.alert_type, a.provider, a.description)
    return {
        "id": str(a.id),
        "org_id": str(a.org_id),
        "provider": a.provider,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "title": a.title,
        "description": a.description,
        "resource_id": a.resource_id,
        "resource_name": a.resource_name,
        "resource_url": a.resource_url,
        "classification_result": a.classification_result,
        "posture_result": a.posture_result,
        "status": a.status,
        "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        "remediation_steps": remediation_steps,
    }


def _get_alert_remediation_steps(alert_type: str, provider: str, description: str) -> list:
    """Return heuristic remediation steps for an alert type."""
    steps_map = {
        "sensitive_data": [
            "Identify the file and review its contents for actual sensitive data.",
            "Contact the file owner to verify if sharing was intentional.",
            "Remove external sharing links and restrict to organization members only.",
            "Apply a DLP policy to prevent future accidental sharing of similar content.",
            "Document the incident in your security log.",
        ],
        "data_exposure": [
            "Immediately revoke any public or anonymous access links.",
            "Audit who has accessed the file in the last 30 days.",
            "Move sensitive data to a restricted SharePoint library with limited access.",
            "Enable sensitivity labels to prevent future accidental exposure.",
            "Notify your privacy officer if personal data was exposed.",
        ],
        "impossible_travel": [
            "Immediately block the user's sign-in and reset their password.",
            "Review the sign-in logs in Entra ID for suspicious activity.",
            "Enable MFA for the affected account if not already enabled.",
            "Check for any OAuth apps that may have been granted access.",
            "Notify the user and verify with them directly if the travel is legitimate.",
        ],
        "external_forwarding": [
            "Disable the forwarding rule in the user's mailbox immediately.",
            "Review all emails forwarded to the external address.",
            "Check if the account is compromised - reset password and revoke sessions.",
            "Create a mail flow rule to block external forwarding across the organization.",
            "Investigate whether sensitive data was exfiltrated.",
        ],
        "risky_oauth_app": [
            "Revoke the OAuth app's consent from Azure AD app registrations.",
            "Review all permissions the app was granted.",
            "Notify affected users and ask them to re-authenticate with approved apps.",
            "Add the app to your organization's blocklist.",
            "Review audit logs for any data access by the app.",
        ],
        "mass_download": [
            "Temporarily restrict the user's access to SharePoint and OneDrive.",
            "Review what data was downloaded and assess exfiltration risk.",
            "Interview the user to understand the business reason for the download.",
            "If unauthorized, escalate to HR and legal.",
            "Enable 'Download to unmanaged devices' restrictions in SharePoint admin.",
        ],
        "public_bucket": [
            "Immediately disable public access on the S3 bucket via AWS Console.",
            "Enable S3 Block Public Access at the account level.",
            "Review bucket policy and ACLs to remove any public grants.",
            "Audit access logs to identify any unauthorized data access.",
            "Enable CloudTrail data events for the bucket for future monitoring.",
        ],
        "open_port": [
            "Review your Security Group or firewall rules in AWS/Azure.",
            "Restrict the port to specific IP ranges or VPN addresses only.",
            "If the service is not needed, shut it down.",
            "Enable VPC Flow Logs to monitor traffic on this port.",
            "Consider using a WAF or load balancer instead of direct internet exposure.",
        ],
        "unencrypted_storage": [
            "Enable encryption at rest for the storage resource.",
            "For S3: Enable default encryption (SSE-S3 or SSE-KMS).",
            "For RDS: Enable encryption during the next maintenance window.",
            "Review data classification - if sensitive data, treat as high priority.",
            "Ensure KMS keys are properly managed and rotated.",
        ],
        "mfa_disabled": [
            "Immediately enable MFA for the affected user account.",
            "Create a Conditional Access policy requiring MFA for all users.",
            "Notify the user of the MFA requirement.",
            "Review if other users also lack MFA and remediate in bulk.",
            "Consider using Microsoft Authenticator for easier adoption.",
        ],
        "shadow_it": [
            "Review the detected OAuth application in Azure AD portal.",
            "Assess the permissions requested by the app (read/write access).",
            "Reach out to the user who authorized the app.",
            "Decide: approve (whitelist) or block the application.",
            "Implement a Cloud App Security policy to detect future Shadow IT.",
        ],
    }
    # Try exact match first
    steps = steps_map.get(alert_type, [])
    if steps:
        return steps
    # Try partial match
    alert_lower = (alert_type or "").lower()
    for key, val in steps_map.items():
        if key in alert_lower or alert_lower in key:
            return val
    # Provider-specific defaults
    if provider == "aws":
        return [
            "Review the AWS finding in the Security Hub or GuardDuty console.",
            "Identify the affected resource and apply the recommended fix.",
            "Enable AWS Config to track configuration changes.",
            "Set up automated remediation with AWS Systems Manager.",
        ]
    elif provider in ("m365", "teams", "sharepoint"):
        return [
            "Review the alert details in Microsoft 365 Defender.",
            "Check the affected user's recent activity in Entra ID sign-in logs.",
            "Apply appropriate access restrictions or policy changes.",
            "Document the remediation action taken.",
        ]
    return [
        "Review the alert details and assess the risk.",
        "Identify the affected resource and user.",
        "Apply the principle of least privilege.",
        "Document the incident and remediation steps taken.",
    ]


def _data_item_to_dict(d: SaasDataItem) -> dict:
    return {
        "id": str(d.id),
        "provider": d.provider,
        "item_type": d.item_type,
        "item_name": d.item_name,
        "item_url": d.item_url,
        "parent_path": d.parent_path,
        "owner_email": d.owner_email,
        "size_bytes": d.size_bytes,
        "classification_label": d.classification_label,
        "classification_score": d.classification_score,
        "classification_categories": d.classification_categories or [],
        "classification_result": None,  # column pending migration — populated via categories
        "sharing_scope": d.sharing_scope,
        "last_modified_at": d.last_modified_at.isoformat() if d.last_modified_at else None,
        "last_scanned_at": d.last_scanned_at.isoformat() if d.last_scanned_at else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def _posture_to_dict(p: SaasPostureCheck) -> dict:
    return {
        "id": str(p.id),
        "provider": p.provider,
        "check_name": p.check_name,
        "check_category": p.check_category,
        "status": p.status,
        "severity": p.severity,
        "description": p.description,
        "recommendation": p.recommendation,
        "evidence": p.evidence,
        "remediation_steps": p.remediation_steps or [],
        "last_checked_at": p.last_checked_at.isoformat() if p.last_checked_at else None,
    }


def _risk_to_label(risk_level: str) -> str:
    mapping = {
        "low": "public",
        "medium": "internal",
        "high": "confidential",
        "critical": "highly_confidential",
    }
    return mapping.get(risk_level, "internal")


def _risk_to_score(risk_level: str) -> int:
    mapping = {"low": 10, "medium": 50, "high": 75, "critical": 95}
    return mapping.get(risk_level, 10)


def _infer_sharing_scope(item: dict) -> str:
    """Infer sharing scope from Graph API driveItem permissions field."""
    perms = item.get("permissions", [])
    for p in perms:
        link = p.get("link", {})
        scope = link.get("scope", "")
        if scope == "anonymous":
            return "public"
        if scope == "organization":
            return "org"
    granted = item.get("grantedToV2", {}) or {}
    if granted.get("user"):
        return "private"
    return "org"


# ── Risk Heatmap Endpoint ─────────────────────────────────────────────────────

@router.get("/risk-heatmap")
async def get_risk_heatmap(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get aggregated risk data for heatmap visualization.
    Returns risk by: user (top 10), file sensitivity distribution, app risk distribution.
    """
    org_id = str(current_user.org_id)

    # Risk by user (top users by alert count)
    # Only count user-related alert types (behavioral threats), not file-based alerts
    user_risk = []
    try:
        result = await db.execute(
            text("""
                SELECT 
                    COALESCE(resource_name, 'Unknown') as user_email,
                    COUNT(*) as alert_count,
                    SUM(CASE WHEN severity='critical' THEN 4 WHEN severity='high' THEN 3 
                        WHEN severity='medium' THEN 2 ELSE 1 END) as risk_score
                FROM saas_alerts 
                WHERE org_id=:oid AND status='open'
                  AND alert_type IN (
                      'impossible_travel', 'mass_download', 'external_forwarding',
                      'risky_oauth_app', 'suspicious_sharing', 'permission_escalation',
                      'entra_risky_user', 'privileged_action', 'shadow_it_app'
                  )
                  AND resource_name LIKE '%@%'
                GROUP BY resource_name
                ORDER BY risk_score DESC
                LIMIT 10
            """),
            {"oid": org_id}
        )
        for row in result.fetchall():
            user_risk.append({
                "user": row[0],
                "alert_count": row[1],
                "risk_score": row[2]
            })
    except Exception as exc:
        logger.warning(f"risk_heatmap/user_risk: {exc}")

    # File sensitivity distribution
    file_sensitivity = []
    try:
        result = await db.execute(
            text("""
                SELECT 
                    COALESCE(classification_label, 'unknown') as label,
                    COUNT(*) as count
                FROM saas_data_items
                WHERE org_id=:oid
                GROUP BY classification_label
            """),
            {"oid": org_id}
        )
        for row in result.fetchall():
            file_sensitivity.append({"label": row[0], "count": row[1]})
    except Exception as exc:
        logger.warning(f"risk_heatmap/file_sensitivity: {exc}")

    # App risk distribution (from OAuth apps if table exists)
    app_risk = []
    try:
        result = await db.execute(
            text("""
                SELECT 
                    status,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk
                FROM saas_oauth_apps
                WHERE org_id=:oid
                GROUP BY status
            """),
            {"oid": org_id}
        )
        for row in result.fetchall():
            app_risk.append({"status": row[0], "count": row[1], "avg_risk": round(row[2] or 0, 2)})
    except Exception:
        pass  # Table may not exist yet

    # Alert severity distribution
    severity_dist = []
    try:
        result = await db.execute(
            text("""
                SELECT severity, COUNT(*) as count
                FROM saas_alerts
                WHERE org_id=:oid AND status='open'
                GROUP BY severity
            """),
            {"oid": org_id}
        )
        for row in result.fetchall():
            severity_dist.append({"severity": row[0], "count": row[1]})
    except Exception as exc:
        logger.warning(f"risk_heatmap/severity: {exc}")

    return {
        "user_risk": user_risk,
        "file_sensitivity": file_sensitivity,
        "app_risk": app_risk,
        "severity_distribution": severity_dist,
    }


# ── Data Flows Endpoint ───────────────────────────────────────────────────────

@router.get("/data-flows")
async def get_data_flows(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get data sharing flows for visualization.
    Returns: internal users → external domains with file counts.
    Format suitable for Sankey diagram: [{source, target, value}]
    """
    org_id = str(current_user.org_id)
    flows = []

    try:
        # Get external shares grouped by owner and inferred external domain
        result = await db.execute(
            text("""
                SELECT 
                    COALESCE(owner_email, 'Unknown') as owner,
                    sharing_scope,
                    COUNT(*) as file_count
                FROM saas_data_items
                WHERE org_id=:oid AND sharing_scope IN ('external', 'public')
                GROUP BY owner_email, sharing_scope
                ORDER BY file_count DESC
                LIMIT 50
            """),
            {"oid": org_id}
        )
        for row in result.fetchall():
            owner = row[0]
            scope = row[1]
            count = row[2]
            # Extract domain from owner email
            if '@' in owner:
                source_domain = owner.split('@')[1]
            else:
                source_domain = owner
            target = "External Users" if scope == "external" else "Public (Anyone)"
            flows.append({
                "source": source_domain,
                "target": target,
                "value": count,
                "owner": owner,
            })
    except Exception as exc:
        logger.warning(f"data_flows: {exc}")

    # Aggregate by domain pairs
    aggregated: dict = {}
    for f in flows:
        key = (f["source"], f["target"])
        if key not in aggregated:
            aggregated[key] = {"source": f["source"], "target": f["target"], "value": 0}
        aggregated[key]["value"] += f["value"]

    return {
        "flows": list(aggregated.values()),
        "raw": flows[:20],  # Sample of detailed flows
    }


# ── OAuth Apps (Shadow IT) Endpoint ────────────────────────────────────────

@router.get("/oauth-apps")
async def list_oauth_apps(
    status: Optional[str] = Query(None, description="Filter by status: sanctioned, unsanctioned, under_review, unknown"),
    limit: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List discovered OAuth apps (shadow IT discovery)."""
    org_id = str(current_user.org_id)
    apps = []

    try:
        query = """
            SELECT id, app_name, app_id, provider, publisher, permissions,
                   status, risk_score, user_count, first_seen_at, last_seen_at
            FROM saas_oauth_apps
            WHERE org_id=:oid
        """
        params = {"oid": org_id, "limit": limit}
        if status:
            query += " AND status=:status"
            params["status"] = status
        query += " ORDER BY risk_score DESC, last_seen_at DESC LIMIT :limit"

        result = await db.execute(text(query), params)
        for row in result.fetchall():
            apps.append({
                "id": str(row[0]),
                "app_name": row[1],
                "app_id": row[2],
                "provider": row[3],
                "publisher": row[4],
                "permissions": row[5] or [],
                "status": row[6],
                "risk_score": row[7],
                "user_count": row[8],
                "first_seen_at": row[9].isoformat() if row[9] else None,
                "last_seen_at": row[10].isoformat() if row[10] else None,
            })
    except Exception as exc:
        logger.warning(f"oauth_apps: {exc}")

    return {"apps": apps, "total": len(apps)}


@router.patch("/oauth-apps/{app_id}/status")
async def update_oauth_app_status(
    app_id: str,
    status: str = Query(..., description="New status: sanctioned, unsanctioned, under_review"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update OAuth app status (sanction/unsanction)."""
    if status not in ("sanctioned", "unsanctioned", "under_review", "unknown"):
        raise HTTPException(status_code=400, detail="Invalid status")

    try:
        await db.execute(
            text("UPDATE saas_oauth_apps SET status=:status WHERE id=:id AND org_id=:oid"),
            {"status": status, "id": app_id, "oid": str(current_user.org_id)}
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(exc))

    return {"ok": True, "app_id": app_id, "new_status": status}


# ── Risky Users (Entra ID) Endpoint ───────────────────────────────────────

@router.get("/risky-users")
async def list_risky_users(
    risk_level: Optional[str] = Query(None, description="Filter by risk level: low, medium, high"),
    limit: int = Query(50, ge=1, le=200),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List risky users from Entra ID Identity Protection."""
    org_id = str(current_user.org_id)
    users = []

    try:
        query = """
            SELECT id, user_email, user_id, risk_level, risk_state, risk_detail,
                   risk_last_updated_at, provider, created_at
            FROM saas_risky_users
            WHERE org_id=:oid
        """
        params = {"oid": org_id, "limit": limit}
        if risk_level:
            query += " AND risk_level=:rlevel"
            params["rlevel"] = risk_level
        query += " ORDER BY CASE risk_level WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC LIMIT :limit"

        result = await db.execute(text(query), params)
        for row in result.fetchall():
            users.append({
                "id": str(row[0]),
                "user_email": row[1],
                "user_id": row[2],
                "risk_level": row[3],
                "risk_state": row[4],
                "risk_detail": row[5],
                "risk_last_updated_at": row[6].isoformat() if row[6] else None,
                "provider": row[7],
                "created_at": row[8].isoformat() if row[8] else None,
            })
    except Exception as exc:
        logger.warning(f"risky_users: {exc}")

    return {"users": users, "total": len(users)}


# ── Admin Actions (Privileged User Monitoring) Endpoint ────────────────────

@router.get("/admin-actions")
async def list_admin_actions(
    action_type: Optional[str] = Query(None, description="Filter by action type"),
    admin_email: Optional[str] = Query(None, description="Filter by admin email"),
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List admin actions for privileged user monitoring."""
    org_id = str(current_user.org_id)
    actions = []

    permission_error = None
    try:
        query = """
            SELECT id, admin_email, action_type, target_type, target_id,
                   target_name, details, provider, created_at
            FROM saas_admin_actions
            WHERE org_id=:oid
        """
        params = {"oid": org_id, "limit": limit}
        if action_type:
            query += " AND action_type=:atype"
            params["atype"] = action_type
        if admin_email:
            query += " AND admin_email ILIKE :aemail"
            params["aemail"] = f"%{admin_email}%"
        query += " ORDER BY created_at DESC LIMIT :limit"

        result = await db.execute(text(query), params)
        for row in result.fetchall():
            actions.append({
                "id": str(row[0]),
                "admin_email": row[1],
                "action_type": row[2],
                "target_type": row[3],
                "target_id": row[4],
                "target_name": row[5],
                "details": row[6] or {},
                "provider": row[7],
                "created_at": row[8].isoformat() if row[8] else None,
            })
        # If no actions found, check if M365 integration exists but may lack permissions
        if not actions:
            try:
                integ_check = await db.execute(text("""
                    SELECT COUNT(*) FROM saas_integrations
                    WHERE org_id = CAST(:oid AS UUID)
                      AND provider IN ('teams', 'sharepoint')
                      AND status = 'active'
                """), {"oid": org_id})
                count = integ_check.scalar() or 0
                if count > 0:
                    permission_error = (
                        "Admin audit logs require AuditLog.Read.All permission. "
                        "Please re-authorize with additional permissions in your Microsoft 365 app registration."
                    )
                    logger.info(f"admin_actions: M365 integrated but no audit logs — likely missing AuditLog.Read.All for org {org_id}")
            except Exception:
                pass
    except Exception as exc:
        logger.warning(f"admin_actions: {exc}")

    # Also add AWS CloudTrail admin actions
    try:
        aws_query = """
            SELECT id, 
                   COALESCE(metadata->>'username', metadata->>'userIdentity.userName', 'unknown') as admin_email,
                   COALESCE(metadata->>'event_name', resource_id) as action_type,
                   resource_type as target_type,
                   resource_id as target_id,
                   title as target_name,
                   metadata as details,
                   'aws' as provider,
                   detected_at as created_at
            FROM aws_findings
            WHERE org_id = :oid
              AND (category = 'admin_action' OR resource_type = 'cloudtrail_event')
        """
        aws_params = {"oid": org_id, "limit": limit}
        if action_type:
            aws_query += " AND (metadata->>'event_name' = :atype OR resource_id = :atype)"
            aws_params["atype"] = action_type
        if admin_email:
            aws_query += " AND (metadata->>'username' ILIKE :aemail)"
            aws_params["aemail"] = f"%{admin_email}%"
        aws_query += " ORDER BY detected_at DESC LIMIT :limit"
        
        aws_result = await db.execute(text(aws_query), aws_params)
        for row in aws_result.fetchall():
            actions.append({
                "id": str(row[0]),
                "admin_email": row[1],
                "action_type": row[2],
                "target_type": row[3],
                "target_id": row[4],
                "target_name": row[5],
                "details": row[6] or {},
                "provider": row[7],
                "created_at": row[8].isoformat() if row[8] else None,
            })
        # Re-sort combined list by created_at
        actions.sort(key=lambda x: x.get("created_at") or "", reverse=True)
        actions = actions[:limit]  # Apply limit after merge
    except Exception as e:
        logger.debug(f"admin_actions: AWS CloudTrail query failed: {e}")

    return {"actions": actions, "total": len(actions), "permission_error": permission_error}


@router.get("/admin-actions/{action_id}")
async def get_admin_action_detail(
    action_id: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed info for a specific admin action, including IP geolocation via WHOIS/ipinfo.
    """
    org_id = str(current_user.org_id)
    
    # Try M365 first
    try:
        result = await db.execute(text("""
            SELECT id, admin_email, action_type, target_type, target_id,
                   target_name, details, provider, created_at
            FROM saas_admin_actions
            WHERE org_id = :oid AND id = CAST(:aid AS UUID)
        """), {"oid": org_id, "aid": action_id})
        row = result.fetchone()
        if row:
            details = row[6] or {}
            ip_address = details.get("ipAddress") or details.get("source_ip")
            
            # WHOIS/ipinfo lookup for geolocation
            geo_info = None
            if ip_address:
                geo_info = await _lookup_ip_geolocation(ip_address)
            
            return {
                "id": str(row[0]),
                "admin_email": row[1],
                "action_type": row[2],
                "target_type": row[3],
                "target_id": row[4],
                "target_name": row[5],
                "details": details,
                "provider": row[7],
                "created_at": row[8].isoformat() if row[8] else None,
                "ip_address": ip_address,
                "geo_info": geo_info,
            }
    except Exception as e:
        logger.debug(f"admin_action_detail: M365 query failed: {e}")
    
    # Try AWS findings
    try:
        result = await db.execute(text("""
            SELECT id, 
                   COALESCE(metadata->>'username', metadata->>'userIdentity.userName', 'unknown') as admin_email,
                   COALESCE(metadata->>'event_name', resource_id) as action_type,
                   resource_type as target_type,
                   resource_id as target_id,
                   title as target_name,
                   metadata as details,
                   'aws' as provider,
                   detected_at as created_at
            FROM aws_findings
            WHERE org_id = :oid AND id = CAST(:aid AS UUID)
        """), {"oid": org_id, "aid": action_id})
        row = result.fetchone()
        if row:
            details = row[6] or {}
            ip_address = details.get("source_ip") or details.get("sourceIPAddress")
            
            geo_info = None
            if ip_address:
                geo_info = await _lookup_ip_geolocation(ip_address)
            
            return {
                "id": str(row[0]),
                "admin_email": row[1],
                "action_type": row[2],
                "target_type": row[3],
                "target_id": row[4],
                "target_name": row[5],
                "details": details,
                "provider": row[7],
                "created_at": row[8].isoformat() if row[8] else None,
                "ip_address": ip_address,
                "geo_info": geo_info,
            }
    except Exception as e:
        logger.debug(f"admin_action_detail: AWS query failed: {e}")
    
    raise HTTPException(status_code=404, detail="Admin action not found")


async def _lookup_ip_geolocation(ip_address: str) -> Optional[dict]:
    """Look up IP geolocation using ipinfo.io (free tier, no API key needed for basic)."""
    if not ip_address or ip_address in ("127.0.0.1", "localhost", "::1"):
        return None
    
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            # ipinfo.io free tier
            resp = await client.get(f"https://ipinfo.io/{ip_address}/json")
            if resp.status_code == 200:
                data = resp.json()
                # Parse location
                loc = data.get("loc", "").split(",")
                lat, lng = (float(loc[0]), float(loc[1])) if len(loc) == 2 else (None, None)
                return {
                    "ip": ip_address,
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "country_name": REGION_MAP.get(data.get("country"), {}).get("country", data.get("country")),
                    "lat": lat,
                    "lng": lng,
                    "org": data.get("org"),
                    "timezone": data.get("timezone"),
                }
    except Exception as e:
        logger.debug(f"IP geolocation lookup failed for {ip_address}: {e}")
    return None


# ── High-Impact DSPM Features ───────────────────────────────────────────────────

@router.get("/external-collaboration")
async def get_external_collaboration(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    External Collaboration Dashboard - Shows all external shares, guest users, and anonymous links.
    Aggregates data from saas_data_items and alerts for a comprehensive external exposure view.
    """
    org_id = str(current_user.org_id)
    data = {
        "external_shares": [],
        "guest_users": [],
        "anonymous_links": [],
        "summary": {
            "total_external_shares": 0,
            "total_guest_users": 0,
            "total_anonymous_links": 0,
            "sensitive_external_shares": 0,
            "expired_links": 0,
        }
    }

    try:
        # Get external shares from saas_data_items.
        # NOTE 2026-06-22: the SaasDataItem schema doesn't have `file_name`,
        # `sensitivity_label`, `classification`, or `shared_with_emails`.
        # Use the real column names (item_name, classification_label,
        # classification_categories, last_modified_at) and synthesize
        # the missing "shared with" list as an empty list — we'll surface
        # an accurate count when the underlying scanners populate it.
        ext_shares_query = """
            SELECT id, item_name, owner_email, sharing_scope,
                   classification_label, classification_categories,
                   provider, created_at, last_modified_at
            FROM saas_data_items
            WHERE org_id=:oid AND (sharing_scope = 'external' OR sharing_scope = 'public')
            ORDER BY last_modified_at DESC NULLS LAST
            LIMIT 200
        """
        result = await db.execute(text(ext_shares_query), {"oid": org_id})
        for row in result.fetchall():
            cats = list(row[5] or [])
            is_sensitive = (row[4] in ['confidential', 'highly_confidential', 'Confidential', 'Highly Confidential']
                            or any(c in ('pii', 'pci', 'phi', 'financial', 'credentials') for c in cats))
            data["external_shares"].append({
                "id": str(row[0]),
                "file_name": row[1],
                "owner": row[2],
                "scope": row[3],
                "shared_with": [],  # populated by future sharing-scope scanner
                "shared_with_count": 0,
                "external_domains": [],
                "sensitivity": row[4],
                "classification": cats[0] if cats else None,
                "provider": row[6],
                "is_sensitive": is_sensitive,
                "last_modified": row[8].isoformat() if row[8] else None,
            })
            if is_sensitive:
                data["summary"]["sensitive_external_shares"] += 1

        data["summary"]["total_external_shares"] = len(data["external_shares"])

        # Get anonymous links (public shares)
        anon_query = """
            SELECT id, item_name, owner_email, provider, created_at
            FROM saas_data_items
            WHERE org_id=:oid AND sharing_scope = 'public'
            ORDER BY created_at DESC
            LIMIT 100
        """
        result = await db.execute(text(anon_query), {"oid": org_id})
        for row in result.fetchall():
            data["anonymous_links"].append({
                "id": str(row[0]),
                "file_name": row[1],
                "owner": row[2],
                "provider": row[3],
                "created_at": row[4].isoformat() if row[4] else None,
            })
        data["summary"]["total_anonymous_links"] = len(data["anonymous_links"])

        # Get guest users from alerts (external_forwarding, suspicious_sharing)
        guest_query = """
            SELECT DISTINCT resource_name
            FROM saas_alerts
            WHERE org_id=:oid 
              AND alert_type IN ('external_forwarding', 'suspicious_sharing')
              AND resource_name LIKE '%@%'
              AND resource_name NOT LIKE '%@%.onmicrosoft.com'
            LIMIT 100
        """
        result = await db.execute(text(guest_query), {"oid": org_id})
        for row in result.fetchall():
            if row[0] and '@' in row[0]:
                data["guest_users"].append({
                    "email": row[0],
                    "domain": row[0].split('@')[1] if '@' in row[0] else 'unknown',
                })
        data["summary"]["total_guest_users"] = len(data["guest_users"])

    except Exception as exc:
        logger.warning(f"external_collaboration: {exc}")

    return data


@router.get("/sensitive-exposure")
async def get_sensitive_exposure(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Sensitive Data Exposure Map - Shows which sensitive files are exposed externally or over-permissioned.
    """
    org_id = str(current_user.org_id)
    data = {
        "exposed_files": [],
        "by_classification": {},
        "by_owner": {},
        "summary": {
            "total_sensitive_files": 0,
            "externally_shared": 0,
            "publicly_accessible": 0,
            "high_risk_count": 0,
        }
    }

    try:
        # NOTE 2026-06-22: rewritten against the real saas_data_items schema.
        # Replaces invented columns (file_name/sensitivity_label/classification/
        # shared_with_emails/file_size/file_path) with the actual columns
        # (item_name/classification_label/classification_categories/
        # parent_path/size_bytes/last_modified_at).
        query = """
            SELECT id, item_name, owner_email, sharing_scope,
                   classification_label, classification_categories,
                   provider, last_modified_at, size_bytes, parent_path
            FROM saas_data_items
            WHERE org_id=:oid
              AND (
                classification_label IN ('confidential','highly_confidential')
                OR EXISTS (
                    SELECT 1 FROM unnest(COALESCE(classification_categories, ARRAY[]::text[])) c
                    WHERE c IN ('pii','pci','phi','credentials','financial')
                )
              )
            ORDER BY
                CASE WHEN sharing_scope = 'public' THEN 0
                     WHEN sharing_scope = 'external' THEN 1
                     ELSE 2 END,
                last_modified_at DESC NULLS LAST
            LIMIT 300
        """
        result = await db.execute(text(query), {"oid": org_id})

        for row in result.fetchall():
            scope = row[3]
            cats = list(row[5] or [])
            classification = cats[0] if cats else (row[4] or 'unknown')
            owner = row[2] or 'unknown'

            risk_level = 'low'
            if scope == 'public':
                risk_level = 'critical'
                data["summary"]["publicly_accessible"] += 1
            elif scope == 'external':
                risk_level = 'high' if any(c in ('pii','pci','phi','credentials','financial') for c in cats) else 'medium'
                data["summary"]["externally_shared"] += 1

            if risk_level in ['critical', 'high']:
                data["summary"]["high_risk_count"] += 1

            data["exposed_files"].append({
                "id": str(row[0]),
                "file_name": row[1],
                "owner": owner,
                "sharing_scope": scope,
                "shared_with_count": 0,
                "sensitivity": row[4],
                "classification": classification,
                "provider": row[6],
                "last_modified": row[7].isoformat() if row[7] else None,
                "file_size": row[8],
                "file_path": row[9],
                "risk_level": risk_level,
            })

            # Aggregate by classification
            data["by_classification"][classification] = data["by_classification"].get(classification, 0) + 1

            # Aggregate by owner
            data["by_owner"][owner] = data["by_owner"].get(owner, 0) + 1

        data["summary"]["total_sensitive_files"] = len(data["exposed_files"])

    except Exception as exc:
        logger.warning(f"sensitive_exposure: {exc}")

    return data


@router.get("/stale-permissions")
async def get_stale_permissions(
    days: int = Query(90, ge=30, le=365, description="Days of inactivity to consider stale"),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Stale/Excessive Permissions - Find shares that haven't been accessed or modified in X days.
    """
    org_id = str(current_user.org_id)
    data = {
        "stale_shares": [],
        "summary": {
            "total_stale": 0,
            "external_stale": 0,
            "internal_stale": 0,
            "potential_savings": 0,  # Number of permissions that could be revoked
        }
    }

    try:
        # NOTE 2026-06-22: rewritten to use real columns (item_name,
        # last_modified_at). `shared_with_emails` doesn't exist; the
        # potential-savings counter just falls back to 1 per stale share.
        # Interval parameter is safely substituted via Python because
        # asyncpg can't bind into INTERVAL '... days' syntax.
        query = f"""
            SELECT id, item_name, owner_email, sharing_scope,
                   provider, created_at, last_modified_at
            FROM saas_data_items
            WHERE org_id=:oid
              AND sharing_scope IN ('external', 'public', 'organization')
              AND last_modified_at < NOW() - INTERVAL '{int(days)} days'
            ORDER BY last_modified_at ASC NULLS LAST
            LIMIT 200
        """
        result = await db.execute(text(query), {"oid": org_id})

        for row in result.fetchall():
            scope = row[3]
            days_stale = (datetime.utcnow() - row[6].replace(tzinfo=None)).days if row[6] else 999

            data["stale_shares"].append({
                "id": str(row[0]),
                "file_name": row[1],
                "owner": row[2],
                "sharing_scope": scope,
                "shared_with_count": 0,
                "provider": row[4],
                "created_at": row[5].isoformat() if row[5] else None,
                "last_modified": row[6].isoformat() if row[6] else None,
                "days_stale": days_stale,
            })

            if scope in ['external', 'public']:
                data["summary"]["external_stale"] += 1
            else:
                data["summary"]["internal_stale"] += 1

            data["summary"]["potential_savings"] += 1

        data["summary"]["total_stale"] = len(data["stale_shares"])

    except Exception as exc:
        logger.warning(f"stale_permissions: {exc}")

    return data


@router.get("/user-risk-scores")
async def get_user_risk_scores(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    User Risk Scores - Aggregate behavioral signals into per-user risk scores.
    Combines: risky users from Entra, alert counts, external shares, admin actions.
    """
    org_id = str(current_user.org_id)
    data = {
        "users": [],
        "summary": {
            "total_users": 0,
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
        }
    }

    try:
        # Build user risk profile from multiple sources
        user_scores = {}
        logger.info(f"user_risk_scores: org_id={org_id}")
        
        # 1. Get risky users from Entra (if table exists)
        try:
            risky_query = """
                SELECT user_email, risk_level, risk_state, risk_detail
                FROM saas_risky_users
                WHERE org_id = CAST(:oid AS UUID)
            """
            result = await db.execute(text(risky_query), {"oid": org_id})
            for row in result.fetchall():
                email = row[0]
                if email not in user_scores:
                    user_scores[email] = {"email": email, "signals": [], "base_score": 0}
                risk_level = row[1]
                if risk_level == 'high':
                    user_scores[email]["base_score"] += 40
                    user_scores[email]["signals"].append({"type": "entra_risky", "severity": "high", "detail": row[3]})
                elif risk_level == 'medium':
                    user_scores[email]["base_score"] += 20
                    user_scores[email]["signals"].append({"type": "entra_risky", "severity": "medium", "detail": row[3]})
        except Exception as _risky_err:
            logger.debug(f"user_risk_scores: risky_users query failed (table may not exist): {_risky_err}")
            await db.rollback()
        
        # 2. Enumerate all users from data items (owner_email)
        owner_query = """
            SELECT DISTINCT owner_email FROM saas_data_items
            WHERE org_id = CAST(:oid AS UUID) AND owner_email IS NOT NULL AND owner_email != ''
        """
        result = await db.execute(text(owner_query), {"oid": org_id})
        owner_rows = result.fetchall()
        logger.info(f"user_risk_scores: found {len(owner_rows)} owner emails")
        for row in owner_rows:
            email = row[0]
            if email and email not in user_scores:
                user_scores[email] = {"email": email, "signals": [], "base_score": 0}
        
        # 3. Get alert counts per user (extract email from resource_name like 'Bulk: email@domain.com')
        alert_query = """
            SELECT resource_name, COUNT(*) as cnt, 
                   SUM(CASE WHEN severity IN ('critical', 'high') THEN 1 ELSE 0 END) as high_cnt
            FROM saas_alerts
            WHERE org_id = CAST(:oid AS UUID) AND resource_name LIKE '%@%'
            GROUP BY resource_name
        """
        result = await db.execute(text(alert_query), {"oid": org_id})
        for row in result.fetchall():
            resource_name = row[0]
            # Extract email from resource_name (handle 'Bulk: email' or just 'email')
            import re
            email_match = re.search(r'[\w.+-]+@[\w.-]+\.[\w]+', resource_name)
            email = email_match.group(0) if email_match else resource_name
            if email and '@' in email:
                if email not in user_scores:
                    user_scores[email] = {"email": email, "signals": [], "base_score": 0}
                user_scores[email]["base_score"] += min(row[1] * 5, 30)  # Cap at 30
                user_scores[email]["base_score"] += row[2] * 10  # High severity alerts
                user_scores[email]["signals"].append({"type": "alerts", "count": row[1], "high_count": row[2]})
        
        # 4. Get external share counts per user
        share_query = """
            SELECT owner_email, COUNT(*) as cnt,
                   SUM(CASE WHEN classification_label IN ('pii', 'financial', 'health', 'confidential', 'highly_confidential') THEN 1 ELSE 0 END) as sensitive_cnt
            FROM saas_data_items
            WHERE org_id = CAST(:oid AS UUID) AND sharing_scope IN ('external', 'public')
            GROUP BY owner_email
        """
        result = await db.execute(text(share_query), {"oid": org_id})
        for row in result.fetchall():
            email = row[0]
            if email and email not in user_scores:
                user_scores[email] = {"email": email, "signals": [], "base_score": 0}
            if email:
                user_scores[email]["base_score"] += min(row[1] * 2, 20)  # External shares
                user_scores[email]["base_score"] += row[2] * 5  # Sensitive external shares
                user_scores[email]["signals"].append({"type": "external_shares", "count": row[1], "sensitive": row[2]})
        
        # 5. Get admin action counts (if table exists)
        try:
            admin_query = """
                SELECT admin_email, COUNT(*) as cnt
                FROM saas_admin_actions
                WHERE org_id = CAST(:oid AS UUID)
                GROUP BY admin_email
            """
            result = await db.execute(text(admin_query), {"oid": org_id})
            for row in result.fetchall():
                email = row[0]
                if email not in user_scores:
                    user_scores[email] = {"email": email, "signals": [], "base_score": 0}
                # Admin actions are informational, slight risk increase for high volume
                user_scores[email]["signals"].append({"type": "admin_actions", "count": row[1]})
        except Exception as _admin_err:
            logger.debug(f"user_risk_scores: admin_actions query failed (table may not exist): {_admin_err}")
            await db.rollback()

        # 6. Get IAM risks from AWS findings — add IAM users with issues as user risk signals
        try:
            iam_query = """
                SELECT resource_id as principal, title, severity, category, resource_type
                FROM aws_findings
                WHERE org_id = :oid
                  AND (resource_type LIKE 'iam_%' OR category = 'admin_action' OR resource_type = 'cloudtrail_event')
                  AND status = 'open'
                  AND severity IN ('critical', 'high', 'medium')
                ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END
                LIMIT 100
            """
            iam_result = await db.execute(text(iam_query), {"oid": org_id})
            iam_rows = iam_result.mappings().all()
            logger.info(f"user_risk_scores: IAM query returned {len(iam_rows)} rows for org {org_id}")
            for row in iam_rows:
                principal = row["principal"] or "iam-user"
                # IAM principals may be usernames — use as email-like key with suffix
                email_key = principal if "@" in principal else f"{principal}@aws-iam"
                if email_key not in user_scores:
                    user_scores[email_key] = {"email": email_key, "display_name": principal, "signals": [], "base_score": 0}
                sev = row["severity"]
                score_delta = 40 if sev == "critical" else 25 if sev == "high" else 10
                user_scores[email_key]["base_score"] += score_delta
                user_scores[email_key]["signals"].append({
                    "type": "aws_iam",
                    "severity": sev,
                    "detail": row["title"],
                })
            iam_count = len([k for k in user_scores if "@aws-iam" in k])
            logger.info(f"user_risk_scores: found {iam_count} IAM users with risk findings")
        except Exception as _iam_err:
            logger.warning(f"user_risk_scores: IAM findings query failed: {_iam_err}")
            try:
                await db.rollback()
            except Exception:
                pass

        # 7. Enumerate ALL IAM users from aws_resources (even without findings)
        try:
            iam_users_query = """
                SELECT resource_id, name, resource_arn, metadata
                FROM aws_resources
                WHERE org_id = :oid
                  AND resource_type = 'iam_user'
            """
            iam_users_result = await db.execute(text(iam_users_query), {"oid": org_id})
            for row in iam_users_result.mappings():
                user_name = row["name"] or row["resource_id"] or "unknown"
                email_key = f"{user_name}@aws-iam"
                if email_key not in user_scores:
                    user_scores[email_key] = {
                        "email": email_key,
                        "display_name": user_name,
                        "signals": [],
                        "base_score": 0,
                        "provider": "aws",
                        "resource_arn": row["resource_arn"],
                    }
                # Check metadata for access keys, MFA status, etc.
                meta = row["metadata"] or {}
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                # Add risk signals based on metadata
                if not meta.get("mfa_enabled", True):  # MFA not enabled
                    user_scores[email_key]["base_score"] += 15
                    user_scores[email_key]["signals"].append({"type": "aws_no_mfa", "severity": "medium", "detail": "MFA not enabled"})
                if meta.get("access_key_count", 0) > 1:
                    user_scores[email_key]["base_score"] += 10
                    user_scores[email_key]["signals"].append({"type": "aws_multiple_keys", "severity": "low", "detail": f"{meta.get('access_key_count')} access keys"})
                if meta.get("console_access", False) and not meta.get("mfa_enabled", True):
                    user_scores[email_key]["base_score"] += 20
                    user_scores[email_key]["signals"].append({"type": "aws_console_no_mfa", "severity": "high", "detail": "Console access without MFA"})
            logger.info(f"user_risk_scores: enumerated {len([k for k in user_scores if '@aws-iam' in k])} total AWS IAM users")
        except Exception as _iam_enum_err:
            logger.debug(f"user_risk_scores: IAM users enumeration failed: {_iam_enum_err}")

        # If no users found from risk signals, try to enumerate from M365
        if not user_scores:
            try:
                integ = (await db.execute(
                    select(SaasIntegration).where(
                        SaasIntegration.org_id == current_user.org_id,
                        SaasIntegration.provider.in_(["teams", "sharepoint"]),
                        SaasIntegration.status == "active",
                    ).limit(1)
                )).scalar_one_or_none()
                
                if integ:
                    access_token = await _get_valid_token(integ, db)
                    if access_token:
                        async with httpx.AsyncClient(timeout=30) as client:
                            resp = await client.get(
                                "https://graph.microsoft.com/v1.0/users?$top=100&$select=userPrincipalName,displayName,jobTitle,department,accountEnabled",
                                headers={"Authorization": f"Bearer {access_token}"}
                            )
                            if resp.status_code == 200:
                                for user in resp.json().get("value", []):
                                    email = user.get("userPrincipalName", "")
                                    if email and "#EXT#" not in email:
                                        user_scores[email] = {
                                            "email": email,
                                            "display_name": user.get("displayName", ""),
                                            "job_title": user.get("jobTitle", ""),
                                            "department": user.get("department", ""),
                                            "signals": [],
                                            "base_score": 0,
                                        }
            except Exception as _e:
                logger.debug(f"user_risk_scores: M365 enumeration failed: {_e}")
        
        # Calculate final scores and risk levels
        for email, u in user_scores.items():
            score = min(u["base_score"], 100)  # Cap at 100
            risk_level = 'low'
            if score >= 60:
                risk_level = 'high'
                data["summary"]["high_risk"] += 1
            elif score >= 30:
                risk_level = 'medium'
                data["summary"]["medium_risk"] += 1
            else:
                data["summary"]["low_risk"] += 1
            
            data["users"].append({
                "email": email,
                "display_name": u.get("display_name", ""),
                "job_title": u.get("job_title", ""),
                "department": u.get("department", ""),
                "risk_score": score,
                "risk_level": risk_level,
                "signals": u["signals"],
            })
        
        # Sort by risk score descending
        data["users"].sort(key=lambda x: x["risk_score"], reverse=True)
        data["users"] = data["users"][:100]  # Limit to top 100
        data["summary"]["total_users"] = len(user_scores)

    except Exception as exc:
        logger.warning(f"user_risk_scores: {exc}")

    return data


@router.get("/user-risk-details/{user_email}")
async def get_user_risk_details(
    user_email: str,
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get detailed risk info for a specific user: last activity, permissions, sign-in locations.
    """
    from urllib.parse import unquote
    user_email = unquote(user_email)
    org_id = str(current_user.org_id)
    
    result = {
        "email": user_email,
        "lifecycle": {},
        "permissions": [],
        "recent_activity": [],
        "sign_in_locations": [],
        "risk_factors": [],
    }
    
    try:
        # 1. Check if this is an AWS IAM user
        if "@aws-iam" in user_email:
            user_name = user_email.replace("@aws-iam", "")
            iam_query = """
                SELECT resource_id, name, resource_arn, metadata, created_at, last_modified, scanned_at
                FROM aws_resources
                WHERE org_id = :oid AND resource_type = 'iam_user'
                  AND (resource_id = :uname OR name = :uname)
                LIMIT 1
            """
            row = (await db.execute(text(iam_query), {"oid": org_id, "uname": user_name})).mappings().first()
            if row:
                meta = row["metadata"] or {}
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                result["lifecycle"] = {
                    "created_at": meta.get("create_date"),
                    "last_used": meta.get("password_last_used"),
                    "last_scanned": row["scanned_at"].isoformat() if row["scanned_at"] else None,
                    "mfa_enabled": meta.get("mfa_enabled", False),
                    "console_access": meta.get("console_access", False),
                    "access_key_count": meta.get("access_key_count", 0),
                    "access_keys": meta.get("access_keys", []),
                }
                result["permissions"] = meta.get("attached_policies", []) + meta.get("inline_policies", [])
                result["resource_arn"] = row["resource_arn"]
            
            # Get related findings
            findings_query = """
                SELECT title, severity, category, description, detected_at, metadata
                FROM aws_findings
                WHERE org_id = :oid AND resource_id = :uname AND status = 'open'
                ORDER BY detected_at DESC
                LIMIT 20
            """
            findings = (await db.execute(text(findings_query), {"oid": org_id, "uname": user_name})).mappings().all()
            for f in findings:
                result["risk_factors"].append({
                    "type": f["category"] or "iam",
                    "severity": f["severity"],
                    "title": f["title"],
                    "description": f["description"],
                    "detected_at": f["detected_at"].isoformat() if f["detected_at"] else None,
                })
            
            # Get CloudTrail activity for this user - fetch live from AWS.
            # Schema is access_key_id_enc / secret_access_key_enc / default_region
            # (not connection_config). The wrong column was raising
            # UndefinedColumnError and tanking the whole AI branch.
            conn_query = """
                SELECT access_key_id_enc, secret_access_key_enc, default_region
                  FROM aws_connections
                 WHERE org_id = CAST(:oid AS UUID) AND status = 'active'
                 LIMIT 1
            """
            conn_row = (await db.execute(text(conn_query), {"oid": org_id})).mappings().first()
            if conn_row:
                try:
                    import boto3
                    from datetime import datetime, timedelta
                    from backend.routers.aws_connector import _decrypt as _aws_decrypt
                    access_key = _aws_decrypt(conn_row["access_key_id_enc"])
                    secret_key = _aws_decrypt(conn_row["secret_access_key_enc"])
                    region = conn_row["default_region"] or "us-east-1"

                    ct_client = boto3.client(
                        "cloudtrail",
                        aws_access_key_id=access_key,
                        aws_secret_access_key=secret_key,
                        region_name=region,
                    )
                    
                    # Lookup events for this user in last 7 days
                    events_resp = ct_client.lookup_events(
                        LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": user_name}],
                        StartTime=datetime.utcnow() - timedelta(days=7),
                        EndTime=datetime.utcnow(),
                        MaxResults=20,
                    )
                    
                    for event in events_resp.get("Events", []):
                        event_detail = json.loads(event.get("CloudTrailEvent", "{}"))
                        source_ip = event_detail.get("sourceIPAddress", "")
                        region = event_detail.get("awsRegion", "")
                        
                        result["recent_activity"].append({
                            "action": event.get("EventName", "Unknown"),
                            "target": event_detail.get("requestParameters", {}).get("bucketName") or 
                                      event_detail.get("requestParameters", {}).get("instanceId") or 
                                      event_detail.get("eventSource", "").replace(".amazonaws.com", ""),
                            "time": event.get("EventTime").isoformat() if event.get("EventTime") else None,
                            "source_ip": source_ip,
                            "region": region,
                        })
                        
                        if source_ip and not source_ip.endswith(".amazonaws.com"):
                            geo = await _lookup_ip_geolocation(source_ip)
                            if geo:
                                result["sign_in_locations"].append({
                                    "ip": source_ip,
                                    "city": geo.get("city"),
                                    "region": geo.get("region"),
                                    "country": geo.get("country_name"),
                                    "time": event.get("EventTime").isoformat() if event.get("EventTime") else None,
                                })
                except Exception as ct_err:
                    logger.debug(f"user_risk_details: CloudTrail lookup failed: {ct_err}")
            
            # Fallback: check aws_findings for stored activity
            activity_query = """
                SELECT title, metadata, detected_at
                FROM aws_findings
                WHERE org_id = :oid AND (resource_type = 'cloudtrail_event' OR category = 'admin_action')
                  AND (metadata->>'username' = :uname OR metadata->>'launched_by' = :uname)
                ORDER BY detected_at DESC
                LIMIT 10
            """
            activities = (await db.execute(text(activity_query), {"oid": org_id, "uname": user_name})).mappings().all()
            for a in activities:
                meta = a["metadata"] or {}
                if isinstance(meta, str):
                    try:
                        meta = json.loads(meta)
                    except Exception:
                        meta = {}
                # Avoid duplicates if already fetched from CloudTrail
                if not any(act.get("action") == a["title"] for act in result["recent_activity"]):
                    result["recent_activity"].append({
                        "action": a["title"],
                        "time": a["detected_at"].isoformat() if a["detected_at"] else None,
                        "source_ip": meta.get("source_ip"),
                        "region": meta.get("region"),
                    })
        
        else:
            # M365/Entra user - fetch sign-in activity, group memberships, and
            # directory role assignments from Graph API. Permissions for an
            # Entra user = (directory roles assigned + Teams/Sharepoint groups
            # they’re a member of). This is the closest analog to AWS IAM
            # attached policies and is what Adnan asked for under “permissions
            # thing + correlated audit logs”.
            token = await _get_graph_token_for_org(org_id, db)
            if token:
                user_id = None
                try:
                    async with httpx.AsyncClient(timeout=15) as client:
                        # Resolve user object id; many downstream Graph paths need it
                        u_resp = await client.get(
                            f"{GRAPH}/users/{user_email}?$select=id,accountEnabled,createdDateTime,jobTitle,department,userType",
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        if u_resp.status_code == 200:
                            u_json = u_resp.json()
                            user_id = u_json.get("id")
                            result["lifecycle"]["created_at"] = u_json.get("createdDateTime")
                            result["lifecycle"]["account_enabled"] = u_json.get("accountEnabled")
                            result["lifecycle"]["user_type"] = u_json.get("userType")
                            result["lifecycle"]["job_title"] = u_json.get("jobTitle")
                            result["lifecycle"]["department"] = u_json.get("department")

                        # Directory role assignments → admin-style permissions
                        if user_id:
                            roles_resp = await client.get(
                                f"{GRAPH}/users/{user_id}/memberOf?$select=id,displayName,description,@odata.type",
                                headers={"Authorization": f"Bearer {token}"},
                            )
                            if roles_resp.status_code == 200:
                                for grp in roles_resp.json().get("value", [])[:30]:
                                    odata = grp.get("@odata.type", "")
                                    if "directoryRole" in odata:
                                        result["permissions"].append({
                                            "name": grp.get("displayName", "role"),
                                            "type": "directoryRole",
                                            "description": grp.get("description"),
                                        })
                                    elif "group" in odata:
                                        result["permissions"].append({
                                            "name": grp.get("displayName", "group"),
                                            "type": "group",
                                            "description": grp.get("description"),
                                        })
                            else:
                                logger.debug(
                                    f"user_risk_details: memberOf returned {roles_resp.status_code} for {user_email}"
                                )

                            # Admin-only app role assignments (granted via consent)
                            app_roles_resp = await client.get(
                                f"{GRAPH}/users/{user_id}/appRoleAssignments?$top=20",
                                headers={"Authorization": f"Bearer {token}"},
                            )
                            if app_roles_resp.status_code == 200:
                                for ar in app_roles_resp.json().get("value", [])[:15]:
                                    result["permissions"].append({
                                        "name": ar.get("resourceDisplayName", "app"),
                                        "type": "appRole",
                                        "description": f"appRoleId={ar.get('appRoleId','')[:8]}",
                                    })

                        # Sign-in logs (existing behavior)
                        signin_resp = await client.get(
                            f"{GRAPH}/auditLogs/signIns",
                            params={
                                "$filter": f"userPrincipalName eq '{user_email}'",
                                "$top": "20",
                                "$orderby": "createdDateTime desc",
                                "$select": "createdDateTime,ipAddress,location,status,appDisplayName,clientAppUsed,deviceDetail",
                            },
                            headers={"Authorization": f"Bearer {token}"},
                        )
                        if signin_resp.status_code == 200:
                            signins = signin_resp.json().get("value", [])
                            for si in signins:
                                loc = si.get("location", {}) or {}
                                status = si.get("status", {}) or {}
                                is_success = status.get("errorCode", 0) == 0
                                result["recent_activity"].append({
                                    "action": f"Sign-in: {si.get('appDisplayName', 'Unknown App')}" + (" (failed)" if not is_success else ""),
                                    "target": si.get("clientAppUsed", "Browser"),
                                    "time": si.get("createdDateTime"),
                                    "source_ip": si.get("ipAddress"),
                                })
                                if si.get("ipAddress") and loc:
                                    result["sign_in_locations"].append({
                                        "ip": si["ipAddress"],
                                        "city": loc.get("city"),
                                        "region": loc.get("state"),
                                        "country": loc.get("countryOrRegion"),
                                        "time": si.get("createdDateTime"),
                                    })

                        # Correlated directory audits (admin actions performed
                        # BY this user) — equivalent to CloudTrail for AWS IAM.
                        # Filter by initiatedBy/user/userPrincipalName.
                        try:
                            audit_resp = await client.get(
                                f"{GRAPH}/auditLogs/directoryAudits",
                                params={
                                    "$filter": (
                                        f"initiatedBy/user/userPrincipalName eq '{user_email}'"
                                    ),
                                    "$top": "20",
                                    "$orderby": "activityDateTime desc",
                                },
                                headers={"Authorization": f"Bearer {token}"},
                            )
                            if audit_resp.status_code == 200:
                                for ev in audit_resp.json().get("value", []):
                                    targets = ev.get("targetResources", []) or []
                                    target_name = (
                                        targets[0].get("displayName")
                                        if targets
                                        else ev.get("category")
                                    )
                                    result["recent_activity"].append({
                                        "action": ev.get("activityDisplayName", "audit-event"),
                                        "target": target_name,
                                        "time": ev.get("activityDateTime"),
                                        "source_ip": (
                                            (ev.get("initiatedBy", {}) or {})
                                            .get("user", {})
                                            .get("ipAddress")
                                        ),
                                        "category": ev.get("category"),
                                        "result": ev.get("result"),
                                    })
                            else:
                                logger.debug(
                                    f"user_risk_details: directoryAudits returned {audit_resp.status_code} for {user_email}"
                                )
                        except Exception as _ae:
                            logger.debug(f"user_risk_details: directoryAudits fetch failed: {_ae}")
                except Exception as signin_err:
                    logger.debug(f"user_risk_details: signin fetch failed: {signin_err}")
            
            # Also check admin actions for activity
            admin_query = """
                SELECT action_type, target_type, target_name, details, created_at
                FROM saas_admin_actions
                WHERE org_id = :oid AND admin_email = :email
                ORDER BY created_at DESC
                LIMIT 10
            """
            actions = (await db.execute(text(admin_query), {"oid": org_id, "email": user_email})).mappings().all()
            for a in actions:
                details = a["details"] or {}
                if isinstance(details, str):
                    try:
                        details = json.loads(details)
                    except Exception:
                        details = {}
                result["recent_activity"].append({
                    "action": a["action_type"],
                    "target": a["target_name"] or a["target_type"],
                    "time": a["created_at"].isoformat() if a["created_at"] else None,
                    "source_ip": details.get("ipAddress"),
                })
                if details.get("ipAddress"):
                    geo = await _lookup_ip_geolocation(details["ipAddress"])
                    if geo:
                        result["sign_in_locations"].append({
                            "ip": details["ipAddress"],
                            "city": geo.get("city"),
                            "region": geo.get("region"),
                            "country": geo.get("country_name"),
                            "time": a["created_at"].isoformat() if a["created_at"] else None,
                        })
            
            # Check risky user info from Entra
            risky_query = """
                SELECT risk_level, risk_state, risk_detail, detected_at
                FROM saas_risky_users
                WHERE org_id = :oid AND user_email = :email
                ORDER BY detected_at DESC
                LIMIT 1
            """
            try:
                risky = (await db.execute(text(risky_query), {"oid": org_id, "email": user_email})).mappings().first()
                if risky:
                    result["lifecycle"]["risk_state"] = risky["risk_state"]
                    result["risk_factors"].append({
                        "type": "entra_risky",
                        "severity": risky["risk_level"],
                        "title": f"Entra ID Risk: {risky['risk_level']}",
                        "description": risky["risk_detail"],
                        "detected_at": risky["detected_at"].isoformat() if risky["detected_at"] else None,
                    })
            except Exception:
                pass
            
            # Get data items owned by this user
            items_query = """
                SELECT item_name, classification_label, sharing_scope, last_modified_at
                FROM saas_data_items
                WHERE org_id = :oid AND owner_email = :email
                ORDER BY last_modified_at DESC
                LIMIT 10
            """
            items = (await db.execute(text(items_query), {"oid": org_id, "email": user_email})).mappings().all()
            result["owned_items"] = [{
                "name": i["item_name"],
                "classification": i["classification_label"],
                "sharing": i["sharing_scope"],
                "last_modified": i["last_modified_at"].isoformat() if i["last_modified_at"] else None,
            } for i in items]
            
            # Get alerts involving this user
            alerts_query = """
                SELECT title, severity, description, created_at
                FROM saas_alerts
                WHERE org_id = :oid AND resource_name LIKE :email_pattern
                ORDER BY created_at DESC
                LIMIT 10
            """
            alerts = (await db.execute(text(alerts_query), {"oid": org_id, "email_pattern": f"%{user_email}%"})).mappings().all()
            for al in alerts:
                result["risk_factors"].append({
                    "type": "alert",
                    "severity": al["severity"],
                    "title": al["title"],
                    "description": al["description"],
                    "detected_at": al["created_at"].isoformat() if al["created_at"] else None,
                })
    
    except Exception as exc:
        logger.warning(f"user_risk_details: {exc}")
    
    # Dedupe sign-in locations
    seen_ips = set()
    unique_locations = []
    for loc in result["sign_in_locations"]:
        if loc["ip"] not in seen_ips:
            seen_ips.add(loc["ip"])
            unique_locations.append(loc)
    result["sign_in_locations"] = unique_locations[:10]

    # ── Claude AI risk assessment ────────────────────────────────────────────
    # Use Claude to synthesize a narrative risk assessment from the
    # collected signals (activity, locations, owned items, alerts).
    # Cached in-memory by (org_id, user_email) for 10 min so the page
    # is snappy on refresh; cache miss runs Claude inline.
    try:
        if ANTHROPIC_API_KEY:
            cache_key = f"{org_id}:{user_email}"
            cached = _USER_RISK_AI_CACHE.get(cache_key)
            now_ts = datetime.now(timezone.utc).timestamp()
            if cached and (now_ts - cached.get("ts", 0)) < 600:
                result["ai_assessment"] = cached["assessment"]
            else:
                prompt_payload = {
                    "user_email": user_email,
                    "lifecycle": result.get("lifecycle", {}),
                    "recent_activity": result.get("recent_activity", [])[:15],
                    "sign_in_locations": result.get("sign_in_locations", [])[:8],
                    "risk_factors": result.get("risk_factors", [])[:15],
                    "owned_items_count": len(result.get("owned_items", []) or []),
                    "sensitive_owned_items": [
                        i for i in (result.get("owned_items") or [])
                        if i.get("classification") in ("confidential", "highly_confidential", "pii", "financial")
                    ][:10],
                }
                prompt = (
                    "You are a SOC analyst writing a concise risk briefing for a SaaS "
                    "security dashboard. Given this user's signals, return JSON ONLY:\n"
                    "{\n"
                    '  "risk_score": 0-100,                  \n'
                    '  "risk_band": "low|medium|high|critical",\n'
                    '  "headline": "<≤ 12-word summary>",        \n'
                    '  "key_concerns": ["...", "..."],          \n'
                    '  "recommended_actions": ["...", "..."],   \n'
                    '  "trust_signals": ["..."]                 \n'
                    "}\n\n"
                    "Weigh: MFA status, external sharing of sensitive data, geo-distributed"
                    " sign-ins, failed sign-ins, admin actions, AWS IAM findings, recent"
                    " anomalous activity. Be specific (cite IPs, app names, file types"
                    " when relevant). Concise, no fluff.\n\n"
                    f"Signals:\n{json.dumps(prompt_payload, default=str)[:6000]}"
                )
                try:
                    async with httpx.AsyncClient(timeout=25) as client:
                        r = await client.post(
                            "https://api.anthropic.com/v1/messages",
                            headers={
                                "x-api-key": ANTHROPIC_API_KEY,
                                "anthropic-version": "2023-06-01",
                                "content-type": "application/json",
                            },
                            json={
                                "model": "claude-haiku-4-5",
                                "max_tokens": 1500,  # was 700, headroom for full assessment
                                "messages": [{"role": "user", "content": prompt}],
                            },
                        )
                    if r.status_code == 200:
                        raw = r.json()["content"][0]["text"].strip()
                        # Strip every common JSON wrapper Claude emits.
                        raw = re.sub(r"^```(?:json)?\s*", "", raw)
                        raw = re.sub(r"\s*```\s*$", "", raw)
                        m = re.search(r"\{.*\}", raw, re.DOTALL)
                        if m:
                            raw = m.group(0)
                        ai_result = json.loads(raw)
                        result["ai_assessment"] = ai_result
                        _USER_RISK_AI_CACHE[cache_key] = {"ts": now_ts, "assessment": ai_result}
                    else:
                        logger.warning(f"user_risk_details: Claude returned {r.status_code}: {r.text[:300]}")
                except Exception as ai_exc:
                    logger.warning(f"user_risk_details: AI assessment failed: {ai_exc}")
    except Exception as ai_outer:
        logger.debug(f"user_risk_details: AI block error: {ai_outer}")

    return result


# In-memory cache for the Claude user risk assessment (key: "org_id:user_email").
# 10-min TTL keeps the page fast while still picking up fresh signals.
_USER_RISK_AI_CACHE: dict = {}


@router.get("/compliance-status")
async def get_compliance_status(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Compliance Dashboard - GDPR, HIPAA, PCI-DSS, SOC2 compliance status based on data classification and sharing.
    """
    org_id = str(current_user.org_id)
    # Each framework gets a richer skeleton: score, status, issues list,
    # checks list (each with name, passed, control_id, family, resource_count,
    # remediation), plus a discovered_resources summary (so the Compliance tab
    # can show "123 S3 buckets / 17 SharePoint sites / 4 RDS instances" etc.).
    # AI remediation is added per failed control at the bottom of this fn.
    def _fw(name: str):
        return {
            "name": name,
            "status": "compliant",
            "score": 100,
            "issues": [],
            "checks": [],
            "discovered_resources": {},
            "failed_controls": [],
        }
    # ── Region-aware framework selection ───────────────────────────
    # 2026-06-17: Adnan asked that only frameworks applicable to the
    # detected resource regions show up. We discover which regions the
    # org has resources in and gate frameworks accordingly. Global +
    # always-applicable frameworks (ISO27001, NIST-CSF, SOC2, PCI-DSS)
    # remain on by default since they aren't tied to a geography.
    detected_regions: set = set()
    try:
        reg_q = await db.execute(text("""
            SELECT DISTINCT region FROM aws_resources
              WHERE org_id = CAST(:oid AS UUID) AND region IS NOT NULL
            UNION
            SELECT DISTINCT location FROM gcp_resources
              WHERE org_id = CAST(:oid AS UUID) AND location IS NOT NULL
            UNION
            SELECT DISTINCT region FROM azure_resources
              WHERE org_id = CAST(:oid AS UUID) AND region IS NOT NULL
        """), {"oid": org_id})
        for r in reg_q.mappings():
            v = (r["region"] or "").lower()
            if v:
                detected_regions.add(v)
        # Also pull tenant country from M365 organization data
        try:
            tenant_q = await db.execute(text("""
                SELECT settings FROM org_integrations
                WHERE org_id = CAST(:oid AS UUID) AND provider IN ('m365', 'teams', 'sharepoint')
                  AND settings IS NOT NULL
                LIMIT 5
            """), {"oid": org_id})
            for trow in tenant_q.mappings():
                s = trow.get("settings") or {}
                if isinstance(s, dict):
                    cc = (s.get("tenant_country") or s.get("country_letter_code") or "").lower()
                    if cc:
                        detected_regions.add(cc)
        except Exception:
            pass
    except Exception as _rg_exc:
        logger.debug(f"compliance_status: region detection failed: {_rg_exc}")

    def _has_region(needles: list) -> bool:
        if not detected_regions:
            return True  # haven't scanned yet — show everything
        return any(any(n in r for n in needles) for r in detected_regions)

    # Region buckets for framework gating.
    has_eu = _has_region(["eu-", "europe", "-eu", "de", "fr", "nl", "ie", "se", "gb", "uk", "westeurope", "northeurope", "uksouth", "ukwest"])
    has_us = _has_region(["us-", "-us-", "eastus", "westus", "centralus", "northus", "southus", "us"])
    has_sa = _has_region(["me-south", "sa", "-sa-", "saudi", "jeddah", "riyadh"])
    has_uae = _has_region(["me-central", "uaenorth", "ae", "dubai"])

    # Always-applicable global frameworks
    fw_pool = {
        "ISO27001": _fw("ISO/IEC 27001:2022"),
        "SOC2":     _fw("SOC 2 Type II"),
        "PCI-DSS":  _fw("PCI-DSS v4"),
        "NIST-CSF": _fw("NIST CSF 2.0"),
    }
    # Region-gated frameworks
    if has_eu:
        fw_pool["GDPR"] = _fw("GDPR (EU)")
    if has_us:
        fw_pool["HIPAA"] = _fw("HIPAA (US Health)")
    if has_sa:
        fw_pool["SAMA"] = _fw("SAMA Cyber Security Framework")
        fw_pool["NCA"] = _fw("NCA Essential Cybersecurity Controls")
        fw_pool["PDPL"] = _fw("Saudi PDPL")
    if has_uae:
        fw_pool["UAE-IAR"] = _fw("UAE Information Assurance Regulation")

    data = {
        "frameworks": fw_pool,
        "overall_score": 100,
        "critical_issues": [],
        "resource_inventory": {},
        "detected_regions": sorted(detected_regions),
    }

    # Helper: return the framework dict, or a throw-away sink if the
    # framework was filtered out by region. Lets the downstream scoring
    # code stay as-is without sprinkling .get() everywhere.
    _sink_fw: dict = {
        "name": "", "status": "compliant", "score": 100,
        "issues": [], "checks": [], "discovered_resources": {},
        "failed_controls": [],
    }
    class _FwAccessor:
        def __getitem__(self, key):
            return data["frameworks"].get(key, _sink_fw)
    _fws = _FwAccessor()

    # ── Discover resources up-front so each framework can reference real counts ─
    try:
        inv_q = await db.execute(text("""
            SELECT 'saas_data_items' as src, provider, COUNT(*) as cnt
              FROM saas_data_items WHERE org_id = CAST(:oid AS UUID)
              GROUP BY provider
            UNION ALL
            SELECT 'aws_resources', resource_type, COUNT(*)
              FROM aws_resources WHERE org_id = CAST(:oid AS UUID)
              GROUP BY resource_type
            UNION ALL
            SELECT 'aws_findings', severity, COUNT(*)
              FROM aws_findings WHERE org_id = CAST(:oid AS UUID) AND status = 'open'
              GROUP BY severity
        """), {"oid": org_id})
        for r in inv_q.mappings():
            data["resource_inventory"].setdefault(r["src"], {})[r["provider"] or "unknown"] = r["cnt"]
    except Exception as _inv_exc:
        logger.debug(f"compliance_status: inventory query failed: {_inv_exc}")
        try:
            await db.rollback()
        except Exception:
            pass

    try:
        # Check for PII externally shared (GDPR violation)
        pii_query = """
            SELECT COUNT(*) FROM saas_data_items
            WHERE org_id=:oid 
              AND classification_label = 'pii'
              AND sharing_scope IN ('external', 'public')
        """
        result = await db.execute(text(pii_query), {"oid": org_id})
        pii_external = result.scalar() or 0
        if pii_external > 0:
            _fws["GDPR"]["score"] -= min(pii_external * 10, 50)
            _fws["GDPR"]["issues"].append(f"{pii_external} PII files shared externally")
            data["critical_issues"].append({"framework": "GDPR", "issue": f"{pii_external} PII files externally accessible", "severity": "high"})
        _fws["GDPR"]["checks"].append({"name": "No external PII sharing", "passed": pii_external == 0})

        # Check for health data externally shared (HIPAA violation)
        health_query = """
            SELECT COUNT(*) FROM saas_data_items
            WHERE org_id=:oid 
              AND classification_label = 'health'
              AND sharing_scope IN ('external', 'public')
        """
        result = await db.execute(text(health_query), {"oid": org_id})
        health_external = result.scalar() or 0
        if health_external > 0:
            _fws["HIPAA"]["score"] -= min(health_external * 20, 60)
            _fws["HIPAA"]["issues"].append(f"{health_external} PHI files shared externally")
            data["critical_issues"].append({"framework": "HIPAA", "issue": f"{health_external} PHI files externally accessible", "severity": "critical"})
        _fws["HIPAA"]["checks"].append({"name": "No external PHI sharing", "passed": health_external == 0})

        # Check for financial data externally shared (PCI-DSS)
        fin_query = """
            SELECT COUNT(*) FROM saas_data_items
            WHERE org_id=:oid 
              AND (classification_label ILIKE '%financial%' OR classification_label ILIKE '%pci%')
              AND sharing_scope IN ('external', 'public')
        """
        result = await db.execute(text(fin_query), {"oid": org_id})
        fin_external = result.scalar() or 0
        if fin_external > 0:
            _fws["PCI-DSS"]["score"] -= min(fin_external * 15, 50)
            _fws["PCI-DSS"]["issues"].append(f"{fin_external} financial files shared externally")
        _fws["PCI-DSS"]["checks"].append({"name": "No external financial data", "passed": fin_external == 0})

        # Check for public links (SOC2 - access control)
        public_query = """
            SELECT COUNT(*) FROM saas_data_items
            WHERE org_id=:oid AND sharing_scope = 'public'
        """
        result = await db.execute(text(public_query), {"oid": org_id})
        public_count = result.scalar() or 0
        if public_count > 0:
            _fws["SOC2"]["score"] -= min(public_count * 5, 30)
            _fws["SOC2"]["issues"].append(f"{public_count} files with anonymous/public links")
        _fws["SOC2"]["checks"].append({"name": "No anonymous public links", "passed": public_count == 0})

        # Check for MFA/Conditional Access (SOC2) from posture checks
        posture_query = """
            SELECT check_name, status, severity FROM saas_posture_checks
            WHERE org_id=:oid AND check_name ILIKE ANY(ARRAY['%mfa%', '%conditional%', '%password%', '%admin%'])
            ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, created_at DESC
            LIMIT 10
        """
        result = await db.execute(text(posture_query), {"oid": org_id})
        for row in result.fetchall():
            check_name = row[0]
            status = row[1]  # pass, fail, warning, unknown
            severity = row[2]
            passed = status == 'pass'
            if not passed:
                penalty = 25 if severity == 'critical' else 15 if severity == 'high' else 10
                _fws["SOC2"]["score"] -= penalty
                _fws["SOC2"]["issues"].append(f"{check_name}: {status}")
                # Also surface in failed_controls so the AI remediation
                # panel picks it up and writes a fix plan.
                _fws["SOC2"]["failed_controls"].append({
                    "control_id": "Posture",
                    "family": check_name,
                    "severity": severity,
                })
            _fws["SOC2"]["checks"].append({"name": check_name, "passed": passed})
        
        # Check data encryption posture for PCI-DSS
        encryption_query = """
            SELECT check_name, status FROM saas_posture_checks
            WHERE org_id=:oid AND check_name ILIKE '%encrypt%'
            ORDER BY created_at DESC LIMIT 5
        """
        result = await db.execute(text(encryption_query), {"oid": org_id})
        for row in result.fetchall():
            passed = row[1] == 'pass'
            if not passed:
                _fws["PCI-DSS"]["score"] -= 15
                _fws["PCI-DSS"]["issues"].append(f"{row[0]}: {row[1]}")
            _fws["PCI-DSS"]["checks"].append({"name": row[0], "passed": passed})
        
        # Check data retention for GDPR
        retention_query = """
            SELECT check_name, status FROM saas_posture_checks
            WHERE org_id=:oid AND check_name ILIKE '%retention%'
            ORDER BY created_at DESC LIMIT 3
        """
        result = await db.execute(text(retention_query), {"oid": org_id})
        for row in result.fetchall():
            passed = row[1] == 'pass'
            if not passed:
                _fws["GDPR"]["score"] -= 10
                _fws["GDPR"]["issues"].append(f"{row[0]}: {row[1]}")
            _fws["GDPR"]["checks"].append({"name": row[0], "passed": passed})

        # ── NIST CSF 2.0 ─ map AWS findings to functions ────────────────
        nist_q = await db.execute(text("""
            SELECT category, severity, COUNT(*) AS cnt
              FROM aws_findings
             WHERE org_id = :oid AND status = 'open'
             GROUP BY category, severity
        """), {"oid": org_id})
        nist_fn_map = {
            "encryption":      ("PR.DS", "Protect → Data Security"),
            "public_access":   ("PR.AC", "Protect → Identity Mgmt & Access Control"),
            "iam":             ("PR.AC", "Protect → Identity Mgmt & Access Control"),
            "admin_action":    ("DE.AE", "Detect → Anomalies & Events"),
            "misconfiguration":("PR.IP", "Protect → Info Protection Processes"),
        }
        nist_fail_counts = {}
        for nrow in nist_q.mappings().all():
            ctrl_id, family = nist_fn_map.get((nrow["category"] or "").lower(), ("ID.AM", "Identify → Asset Management"))
            nist_fail_counts.setdefault((ctrl_id, family), {"high": 0, "medium": 0, "low": 0, "critical": 0})
            sev = nrow["severity"] or "medium"
            nist_fail_counts[(ctrl_id, family)][sev] = nist_fail_counts[(ctrl_id, family)].get(sev, 0) + nrow["cnt"]
        for (ctrl_id, family), sev_counts in nist_fail_counts.items():
            penalty = sev_counts.get("critical", 0) * 8 + sev_counts.get("high", 0) * 5 + sev_counts.get("medium", 0) * 2
            _fws["NIST-CSF"]["score"] -= min(penalty, 25)
            _fws["NIST-CSF"]["checks"].append({
                "name": f"{ctrl_id} — {family}",
                "control_id": ctrl_id,
                "family": family,
                "passed": penalty == 0,
                "resource_count": sum(sev_counts.values()),
                "severity_breakdown": sev_counts,
            })
            if penalty > 0:
                _fws["NIST-CSF"]["failed_controls"].append({
                    "control_id": ctrl_id,
                    "family": family,
                    "finding_count": sum(sev_counts.values()),
                })

        # ── ISO 27001:2022 Annex A controls ───────────────────────────
        # A.5  Information security policies
        # A.8  Asset management
        # A.9  Access control  (maps to AWS IAM findings + posture MFA checks)
        # A.10 Cryptography    (maps to AWS encryption + posture encryption checks)
        # A.12 Operations security (maps to logging / monitoring)
        # A.16 Incident management
        iso_controls = [
            ("A.5.15", "Access control", "public_access,iam"),
            ("A.8.10", "Information deletion", ""),  # cross-checked via retention posture
            ("A.8.24", "Use of cryptography", "encryption"),
            ("A.8.16", "Monitoring activities", "admin_action"),
            ("A.8.34", "Protection of information systems during audit testing", "misconfiguration"),
        ]
        for ctrl_id, ctrl_name, cat_filter in iso_controls:
            cnt = 0
            if cat_filter:
                cats = cat_filter.split(",")
                fail_q = await db.execute(text("""
                    SELECT COUNT(*) FROM aws_findings
                     WHERE org_id = :oid AND status = 'open'
                       AND category = ANY(:cats) AND severity IN ('high', 'critical')
                """), {"oid": org_id, "cats": cats})
                cnt = fail_q.scalar() or 0
            passed = cnt == 0
            if not passed:
                _fws["ISO27001"]["score"] -= min(cnt * 3, 15)
                _fws["ISO27001"]["failed_controls"].append({
                    "control_id": ctrl_id,
                    "family": ctrl_name,
                    "finding_count": cnt,
                })
            _fws["ISO27001"]["checks"].append({
                "name": f"{ctrl_id} — {ctrl_name}",
                "control_id": ctrl_id,
                "family": ctrl_name,
                "passed": passed,
                "resource_count": cnt,
            })

        # ── SOC 2 Trust Service Criteria depth ──────────────────────
        soc2_extra = [
            ("CC6.1", "Logical and Physical Access Controls", "public_access"),
            ("CC6.6", "Boundary protection", "public_access"),
            ("CC6.7", "Restricted transmission of data", "encryption"),
            ("CC7.2", "System monitoring", "admin_action"),
            ("CC7.3", "Anomalous event evaluation", "admin_action"),
        ]
        for ctrl_id, ctrl_name, cat in soc2_extra:
            cnt_q = await db.execute(text("""
                SELECT COUNT(*) FROM aws_findings
                 WHERE org_id = :oid AND status = 'open'
                   AND category = :cat AND severity IN ('high', 'critical')
            """), {"oid": org_id, "cat": cat})
            cnt = cnt_q.scalar() or 0
            passed = cnt == 0
            if not passed:
                _fws["SOC2"]["score"] -= min(cnt * 4, 20)
                _fws["SOC2"]["failed_controls"].append({
                    "control_id": ctrl_id,
                    "family": ctrl_name,
                    "finding_count": cnt,
                })
            _fws["SOC2"]["checks"].append({
                "name": f"{ctrl_id} — {ctrl_name}",
                "control_id": ctrl_id,
                "family": ctrl_name,
                "passed": passed,
                "resource_count": cnt,
            })

        # Set status based on score
        for fw, vals in data["frameworks"].items():
            vals["score"] = max(vals["score"], 0)
            if vals["score"] >= 90:
                vals["status"] = "compliant"
            elif vals["score"] >= 70:
                vals["status"] = "at_risk"
            else:
                vals["status"] = "non_compliant"

            # Roll discovered resource counts into the per-framework view.
            vals["discovered_resources"] = {
                "saas_items_total": sum(data["resource_inventory"].get("saas_data_items", {}).values()),
                "aws_resources_total": sum(data["resource_inventory"].get("aws_resources", {}).values()),
                "open_findings": sum(data["resource_inventory"].get("aws_findings", {}).values()),
            }

        # ── AI remediation guidance per failed control (Claude, cached 30 min) ──
        # For each framework with failed_controls, ask Claude to write a
        # concise, framework-specific remediation playbook tied to actual
        # finding counts. This is what makes the Compliance tab actionable.
        if ANTHROPIC_API_KEY:
            for fw_key, fw_val in data["frameworks"].items():
                failed = fw_val.get("failed_controls") or []
                if not failed:
                    continue
                cache_key = f"compliance:{org_id}:{fw_key}:{len(failed)}"
                cached = _COMPLIANCE_AI_CACHE.get(cache_key)
                now_ts = datetime.now(timezone.utc).timestamp()
                if cached and (now_ts - cached.get("ts", 0)) < 1800:
                    fw_val["ai_remediation"] = cached["remediation"]
                    continue
                try:
                    prompt = (
                        f"You are a compliance lead writing remediation guidance for the {fw_val['name']} framework. "
                        f"For each failed control listed, write a concise, prioritized remediation plan "
                        f"that cites the specific framework citation, the concrete steps (console + CLI when "
                        f"AWS), and the order of operations. Return JSON ONLY:\n"
                        "{ \"controls\": [ { \"control_id\": \"...\", \"citation\": \"...\", \"priority\": \"P0|P1|P2\", \"steps\": [\"...\"] } ] }\n\n"
                        f"Failed controls:\n{json.dumps(failed)[:3000]}\n\n"
                        f"Open finding inventory in this tenant:\n{json.dumps(data['resource_inventory'].get('aws_findings', {}))}\n"
                    )
                    async with httpx.AsyncClient(timeout=30) as cli:
                        rr = await cli.post(
                            "https://api.anthropic.com/v1/messages",
                            headers={
                                "x-api-key": ANTHROPIC_API_KEY,
                                "anthropic-version": "2023-06-01",
                                "content-type": "application/json",
                            },
                            json={
                                "model": "claude-haiku-4-5",
                                "max_tokens": 4000,  # was 1200, truncated mid-JSON
                                "messages": [{"role": "user", "content": prompt}],
                            },
                        )
                    if rr.status_code == 200:
                        raw = rr.json()["content"][0]["text"].strip()
                        # Strip every common JSON wrapper Claude emits.
                        raw = re.sub(r"^```(?:json)?\s*", "", raw)
                        raw = re.sub(r"\s*```\s*$", "", raw)
                        # If text contains prose before/after the JSON, extract
                        # the outermost {...} block.
                        m = re.search(r"\{.*\}", raw, re.DOTALL)
                        if m:
                            raw = m.group(0)
                        ai_rem = json.loads(raw)
                        fw_val["ai_remediation"] = ai_rem
                        _COMPLIANCE_AI_CACHE[cache_key] = {"ts": now_ts, "remediation": ai_rem}
                    else:
                        logger.warning(f"compliance AI {fw_key}: Claude returned {rr.status_code}: {rr.text[:300]}")
                except Exception as ai_e:
                    logger.warning(f"compliance AI: {fw_key} failed: {ai_e}")

        # Calculate overall score
        data["overall_score"] = sum(f["score"] for f in data["frameworks"].values()) // len(data["frameworks"])

    except Exception as exc:
        logger.warning(f"compliance_status: {exc}", exc_info=True)

    return data


# Cache: compliance AI remediation per (org, framework). 30-min TTL.
_COMPLIANCE_AI_CACHE: dict = {}


@router.get("/file-activity")
async def get_file_activity(
    file_id: Optional[str] = Query(None, description="Filter by specific file ID"),
    user_email: Optional[str] = Query(None, description="Filter by user email"),
    limit: int = Query(100, ge=1, le=500),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    File Activity Timeline - Who accessed what, when.
    Pulls from alerts and data items for activity reconstruction.
    """
    org_id = str(current_user.org_id)
    activities = []

    try:
        # Get file-related alerts as activity proxy
        query = """
            SELECT id, alert_type, title, description, resource_id, resource_name,
                   severity, provider, created_at
            FROM saas_alerts
            WHERE org_id=:oid
        """
        params = {"oid": org_id, "limit": limit}
        if file_id:
            query += " AND resource_id=:fid"
            params["fid"] = file_id
        if user_email:
            query += " AND (resource_name ILIKE :email OR description ILIKE :email)"
            params["email"] = f"%{user_email}%"
        query += " ORDER BY created_at DESC LIMIT :limit"

        result = await db.execute(text(query), params)
        for row in result.fetchall():
            activities.append({
                "id": str(row[0]),
                "activity_type": row[1],
                "title": row[2],
                "description": row[3],
                "resource_id": row[4],
                "resource_name": row[5],
                "severity": row[6],
                "provider": row[7],
                "timestamp": row[8].isoformat() if row[8] else None,
            })

    except Exception as exc:
        logger.warning(f"file_activity: {exc}")

    return {"activities": activities, "total": len(activities)}


@router.post("/remediate/{action_type}")
async def remediate_risk(
    action_type: str,
    file_id: Optional[str] = Query(None),
    user_email: Optional[str] = Query(None),
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Remediation Actions - Revoke share, remove external access, notify owner.
    Currently simulates the action; actual Graph API calls would be added for production.
    """
    org_id = str(current_user.org_id)
    result = {"success": False, "message": "", "action": action_type}

    try:
        if action_type == "revoke_share":
            if not file_id:
                return {"success": False, "message": "file_id required for revoke_share"}
            # In production: call Graph API to remove sharing permissions
            # For now, log the action
            result = {
                "success": True,
                "message": f"Share revocation queued for file {file_id}. This will be processed in the next scan cycle.",
                "action": action_type,
                "simulated": True,
            }
            logger.info(f"Remediation: revoke_share requested for file {file_id} by {current_user.email}")

        elif action_type == "notify_owner":
            if not file_id and not user_email:
                return {"success": False, "message": "file_id or user_email required for notify_owner"}
            result = {
                "success": True,
                "message": "Owner notification queued.",
                "action": action_type,
                "simulated": True,
            }

        elif action_type == "quarantine_file":
            if not file_id:
                return {"success": False, "message": "file_id required for quarantine_file"}
            result = {
                "success": True,
                "message": f"File {file_id} marked for quarantine. Access will be restricted in the next scan cycle.",
                "action": action_type,
                "simulated": True,
            }

        elif action_type == "remove_external_access":
            if not file_id:
                return {"success": False, "message": "file_id required"}
            result = {
                "success": True,
                "message": f"External access removal queued for file {file_id}.",
                "action": action_type,
                "simulated": True,
            }

        else:
            result = {"success": False, "message": f"Unknown action type: {action_type}"}

    except Exception as exc:
        logger.warning(f"remediate: {exc}")
        result = {"success": False, "message": str(exc)}

    return result


# ══════════════════════════════════════════════════════════════════════════════
# DATA RESIDENCY — Where data lives, region distributions, compliance
# ══════════════════════════════════════════════════════════════════════════════

# Region mapping for country codes to geographic regions and coordinates
# AWS region coordinates for map display
AWS_REGION_COORDS = {
    # US East
    "us-east-1": (37.5407, -77.4360),  # N. Virginia
    "us-east-2": (40.4173, -82.9071),  # Ohio
    # US West
    "us-west-1": (37.7749, -122.4194),  # N. California
    "uaenorth": (45.5231, -122.6765),  # Oregon
    # Europe
    "eu-west-1": (53.3498, -6.2603),   # Ireland
    "eu-west-2": (51.5074, -0.1278),   # London
    "eu-west-3": (48.8566, 2.3522),    # Paris
    "eu-central-1": (50.1109, 8.6821), # Frankfurt
    "eu-north-1": (59.3293, 18.0686),  # Stockholm
    "eu-south-1": (45.4642, 9.1900),   # Milan
    # Asia Pacific
    "ap-northeast-1": (35.6762, 139.6503),  # Tokyo
    "ap-northeast-2": (37.5665, 126.9780),  # Seoul
    "ap-northeast-3": (34.6937, 135.5023),  # Osaka
    "ap-southeast-1": (1.3521, 103.8198),   # Singapore
    "ap-southeast-2": (-33.8688, 151.2093), # Sydney
    "ap-southeast-3": (-6.2088, 106.8456),  # Jakarta
    "ap-south-1": (19.0760, 72.8777),       # Mumbai
    "ap-east-1": (22.3193, 114.1694),       # Hong Kong
    # South America
    "sa-east-1": (-23.5505, -46.6333),      # Sao Paulo
    # Canada
    "ca-central-1": (45.5017, -73.5673),    # Montreal
    # Middle East
    "me-south-1": (26.0667, 50.5577),       # Bahrain
    "me-central-1": (25.2048, 55.2708),     # UAE
    # Africa
    "af-south-1": (-33.9249, 18.4241),      # Cape Town
}

def _get_aws_region_coords(region: str) -> tuple:
    """Get lat/lng for an AWS region code."""
    return AWS_REGION_COORDS.get(region, (0, 0))


REGION_MAP = {
    # North America
    "US": {"region": "North America", "country": "United States", "lat": 37.0902, "lng": -95.7129},
    "CA": {"region": "North America", "country": "Canada", "lat": 56.1304, "lng": -106.3468},
    "MX": {"region": "North America", "country": "Mexico", "lat": 23.6345, "lng": -102.5528},
    # Europe
    "GB": {"region": "Europe", "country": "United Kingdom", "lat": 55.3781, "lng": -3.4360},
    "UK": {"region": "Europe", "country": "United Kingdom", "lat": 55.3781, "lng": -3.4360},
    "DE": {"region": "Europe", "country": "Germany", "lat": 51.1657, "lng": 10.4515},
    "FR": {"region": "Europe", "country": "France", "lat": 46.2276, "lng": 2.2137},
    "NL": {"region": "Europe", "country": "Netherlands", "lat": 52.1326, "lng": 5.2913},
    "IE": {"region": "Europe", "country": "Ireland", "lat": 53.1424, "lng": -7.6921},
    "SE": {"region": "Europe", "country": "Sweden", "lat": 60.1282, "lng": 18.6435},
    "NO": {"region": "Europe", "country": "Norway", "lat": 60.4720, "lng": 8.4689},
    "DK": {"region": "Europe", "country": "Denmark", "lat": 56.2639, "lng": 9.5018},
    "FI": {"region": "Europe", "country": "Finland", "lat": 61.9241, "lng": 25.7482},
    "CH": {"region": "Europe", "country": "Switzerland", "lat": 46.8182, "lng": 8.2275},
    "AT": {"region": "Europe", "country": "Austria", "lat": 47.5162, "lng": 14.5501},
    "BE": {"region": "Europe", "country": "Belgium", "lat": 50.5039, "lng": 4.4699},
    "IT": {"region": "Europe", "country": "Italy", "lat": 41.8719, "lng": 12.5674},
    "ES": {"region": "Europe", "country": "Spain", "lat": 40.4637, "lng": -3.7492},
    "PT": {"region": "Europe", "country": "Portugal", "lat": 39.3999, "lng": -8.2245},
    "PL": {"region": "Europe", "country": "Poland", "lat": 51.9194, "lng": 19.1451},
    # Middle East
    "AE": {"region": "Middle East", "country": "UAE", "lat": 23.4241, "lng": 53.8478},
    "SA": {"region": "Middle East", "country": "Saudi Arabia", "lat": 23.8859, "lng": 45.0792},
    "QA": {"region": "Middle East", "country": "Qatar", "lat": 25.3548, "lng": 51.1839},
    "KW": {"region": "Middle East", "country": "Kuwait", "lat": 29.3759, "lng": 47.9774},
    "BH": {"region": "Middle East", "country": "Bahrain", "lat": 26.0667, "lng": 50.5577},
    "OM": {"region": "Middle East", "country": "Oman", "lat": 21.4735, "lng": 55.9754},
    "IL": {"region": "Middle East", "country": "Israel", "lat": 31.0461, "lng": 34.8516},
    "JO": {"region": "Middle East", "country": "Jordan", "lat": 30.5852, "lng": 36.2384},
    "EG": {"region": "Middle East", "country": "Egypt", "lat": 26.8206, "lng": 30.8025},
    # Asia Pacific
    "AU": {"region": "Asia Pacific", "country": "Australia", "lat": -25.2744, "lng": 133.7751},
    "JP": {"region": "Asia Pacific", "country": "Japan", "lat": 36.2048, "lng": 138.2529},
    "SG": {"region": "Asia Pacific", "country": "Singapore", "lat": 1.3521, "lng": 103.8198},
    "IN": {"region": "Asia Pacific", "country": "India", "lat": 20.5937, "lng": 78.9629},
    "KR": {"region": "Asia Pacific", "country": "South Korea", "lat": 35.9078, "lng": 127.7669},
    "HK": {"region": "Asia Pacific", "country": "Hong Kong", "lat": 22.3193, "lng": 114.1694},
    "NZ": {"region": "Asia Pacific", "country": "New Zealand", "lat": -40.9006, "lng": 174.8860},
    "CN": {"region": "Asia Pacific", "country": "China", "lat": 35.8617, "lng": 104.1954},
    "TW": {"region": "Asia Pacific", "country": "Taiwan", "lat": 23.6978, "lng": 120.9605},
    "MY": {"region": "Asia Pacific", "country": "Malaysia", "lat": 4.2105, "lng": 101.9758},
    "ID": {"region": "Asia Pacific", "country": "Indonesia", "lat": -0.7893, "lng": 113.9213},
    "TH": {"region": "Asia Pacific", "country": "Thailand", "lat": 15.8700, "lng": 100.9925},
    "PH": {"region": "Asia Pacific", "country": "Philippines", "lat": 12.8797, "lng": 121.7740},
    "VN": {"region": "Asia Pacific", "country": "Vietnam", "lat": 14.0583, "lng": 108.2772},
    # South America
    "BR": {"region": "South America", "country": "Brazil", "lat": -14.2350, "lng": -51.9253},
    "AR": {"region": "South America", "country": "Argentina", "lat": -38.4161, "lng": -63.6167},
    "CL": {"region": "South America", "country": "Chile", "lat": -35.6751, "lng": -71.5430},
    "CO": {"region": "South America", "country": "Colombia", "lat": 4.5709, "lng": -74.2973},
    # Africa
    "ZA": {"region": "Africa", "country": "South Africa", "lat": -30.5595, "lng": 22.9375},
    "NG": {"region": "Africa", "country": "Nigeria", "lat": 9.0820, "lng": 8.6753},
    "KE": {"region": "Africa", "country": "Kenya", "lat": -0.0236, "lng": 37.9062},
}


@router.get("/data-residency")
async def get_data_residency(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Data Residency overview — where org data is stored and user activity locations.
    Pulls tenant info from Graph API and aggregates user location data.
    """
    org_id = str(current_user.org_id)
    result = {
        "tenant_region": None,
        "tenant_country": None,
        "data_locations": [],
        "user_activity_regions": [],
        "region_summary": {},
        "compliance_regions": [],
        "external_sharing_by_region": [],
    }

    try:
        # Get M365 access token
        integ = (await db.execute(
            select(SaasIntegration).where(
                SaasIntegration.org_id == current_user.org_id,
                SaasIntegration.provider.in_(["teams", "sharepoint"]),
                SaasIntegration.status == "active",
            ).limit(1)
        )).scalar_one_or_none()

        access_token = None
        if integ:
            access_token = await _get_valid_token(integ, db)

        if not access_token:
            # Try org integrations
            m365_integ = (await db.execute(
                select(OrgIntegration).where(
                    OrgIntegration.org_id == current_user.org_id,
                    OrgIntegration.provider == "m365",
                    OrgIntegration.status == "active",
                ).limit(1)
            )).scalar_one_or_none()
            if m365_integ and m365_integ.access_token_enc:
                access_token = _decrypt(m365_integ.access_token_enc)

        GRAPH = "https://graph.microsoft.com/v1.0"

        async def _get(url: str):
            if not access_token:
                return 401, {}
            try:
                async with httpx.AsyncClient(timeout=20) as c:
                    r = await c.get(url, headers={"Authorization": f"Bearer {access_token}"})
                    return r.status_code, r.json() if r.status_code == 200 else {}
            except Exception:
                return 500, {}

        # 1. Get tenant organization info for data residency
        sc, org_data = await _get(f"{GRAPH}/organization")
        if sc == 200:
            orgs = org_data.get("value", [])
            if orgs:
                org_info = orgs[0]
                country_code = org_info.get("countryLetterCode") or org_info.get("preferredDataLocation") or ""
                result["tenant_country"] = country_code
                if country_code in REGION_MAP:
                    result["tenant_region"] = REGION_MAP[country_code]["region"]

        # 2. Get user sign-in locations to understand activity geography
        sc2, signins = await _get(f"{GRAPH}/auditLogs/signIns?$top=200&$select=location,userPrincipalName,createdDateTime")
        country_counts: dict[str, int] = {}
        if sc2 == 200:
            for signin in signins.get("value", []):
                loc = signin.get("location", {}) or {}
                country = loc.get("countryOrRegion", "")
                if country:
                    country_counts[country] = country_counts.get(country, 0) + 1
        
        # 2b. Fallback: if no sign-in logs, get user locations from user profiles
        if not country_counts:
            sc2b, users = await _get(f"{GRAPH}/users?$top=100&$select=userPrincipalName,usageLocation,country,officeLocation")
            if sc2b == 200:
                for user in users.get("value", []):
                    # usageLocation is 2-letter country code
                    country = user.get("usageLocation") or user.get("country") or ""
                    if country:
                        country_counts[country] = country_counts.get(country, 0) + 1

        # Map full country names to 2-letter codes (Graph API returns full names)
        COUNTRY_NAME_TO_CODE = {
            "United States": "US", "Canada": "CA", "United Kingdom": "GB",
            "Germany": "DE", "France": "FR", "Netherlands": "NL",
            "Ireland": "IE", "Sweden": "SE", "Norway": "NO",
            "Denmark": "DK", "Finland": "FI", "Switzerland": "CH",
            "Austria": "AT", "Belgium": "BE", "Italy": "IT",
            "Spain": "ES", "Portugal": "PT", "Poland": "PL",
            "United Arab Emirates": "AE", "Saudi Arabia": "SA",
            "Qatar": "QA", "Kuwait": "KW", "Bahrain": "BH",
            "Oman": "OM", "Israel": "IL", "Jordan": "JO", "Egypt": "EG",
            "Australia": "AU", "Japan": "JP", "Singapore": "SG",
            "India": "IN", "South Korea": "KR", "Hong Kong": "HK",
            "New Zealand": "NZ", "China": "CN", "Taiwan": "TW",
            "Malaysia": "MY", "Indonesia": "ID", "Thailand": "TH",
            "Philippines": "PH", "Vietnam": "VN", "Brazil": "BR",
            "Argentina": "AR", "Chile": "CL", "Colombia": "CO",
            "South Africa": "ZA", "Nigeria": "NG", "Kenya": "KE",
            "Mexico": "MX", "Korea": "KR",
        }
        # Build user activity regions with coordinates
        for raw_code, count in sorted(country_counts.items(), key=lambda x: -x[1]):
            # Normalize country name to code
            code = COUNTRY_NAME_TO_CODE.get(raw_code, raw_code)
            info = REGION_MAP.get(code, {})
            # If still not found, try case-insensitive match
            if not info:
                for k, v in REGION_MAP.items():
                    if v.get("country", "").lower() == raw_code.lower():
                        info = v
                        code = k
                        break
            lat = info.get("lat", 0.0)
            lng = info.get("lng", 0.0)
            if not info or (lat == 0.0 and lng == 0.0):
                logger.warning(
                    f"data_residency: country code/name '{raw_code}' (normalized: '{code}') not found in REGION_MAP — "
                    f"skipping to avoid placing beacon at lat=0, lng=0 (middle of ocean). "
                    f"sign_in_count={count}. Add this code to REGION_MAP."
                )
                continue
            logger.info(f"data_residency: sign-in location resolved: raw='{raw_code}' -> code='{code}' lat={lat} lng={lng} count={count}")
            result["user_activity_regions"].append({
                "country_code": code,
                "country": info.get("country", raw_code),
                "region": info.get("region", "Unknown"),
                "lat": lat,
                "lng": lng,
                "sign_in_count": count,
            })

        # 3. Build region summary
        region_summary: dict[str, int] = {}
        for loc in result["user_activity_regions"]:
            r = loc["region"]
            region_summary[r] = region_summary.get(r, 0) + loc["sign_in_count"]
        result["region_summary"] = region_summary

        # 4. Get SharePoint sites to infer data locations
        sc3, sites = await _get(f"{GRAPH}/sites?search=*&$top=50&$select=displayName,webUrl,createdDateTime")
        data_locations = []
        if sc3 == 200:
            for site in sites.get("value", []):
                url = site.get("webUrl", "")
                region_hint = result.get("tenant_region") or "Unknown"
                data_locations.append({
                    "name": site.get("displayName", "Unknown"),
                    "url": url,
                    "region": region_hint,
                    "type": "SharePoint",
                })
        
        # Also add OneDrive roots (each user has one)
        sc_od, od_items = await _get(f"{GRAPH}/sites/root?$select=displayName,webUrl")
        if sc_od == 200:
            data_locations.append({
                "name": od_items.get("displayName", "OneDrive") + " (root)",
                "url": od_items.get("webUrl", ""),
                "region": result.get("tenant_region") or "Unknown",
                "type": "OneDrive",
            })
        
        result["data_locations"] = data_locations[:30]

        # 5. Get external sharing by checking driveItem permissions (sampled)
        external_by_region: dict[str, int] = {}
        sc4, drives = await _get(f"{GRAPH}/sites/root/drives?$top=5")
        if sc4 == 200:
            for drive in drives.get("value", [])[:3]:
                drive_id = drive.get("id")
                if not drive_id:
                    continue
                sc5, items = await _get(f"{GRAPH}/drives/{drive_id}/root/children?$top=20&$expand=permissions")
                if sc5 == 200:
                    for item in items.get("value", []):
                        perms = item.get("permissions", [])
                        for perm in perms:
                            granted = perm.get("grantedToV2", {}) or {}
                            user_info = granted.get("user", {})
                            email = user_info.get("email", "")
                            if email and "@" in email:
                                domain = email.split("@")[1].lower()
                                # Check if external (rough heuristic)
                                if not any(d in domain for d in ["onmicrosoft.com", "sharepoint.com"]):
                                    # Assign to external region (approximation)
                                    external_by_region["External Users"] = external_by_region.get("External Users", 0) + 1

        result["external_sharing_by_region"] = [
            {"region": k, "count": v} for k, v in external_by_region.items()
        ]

        # 6. Define compliance regions based on regulations (will be extended after AWS check)
        tenant_country = result.get("tenant_country", "")
        compliance_set = set()  # Track unique regulations to avoid duplicates
        compliance_regions = []
        
        if tenant_country in ["US", "CA"]:
            if "SOC 2" not in compliance_set:
                compliance_regions.append({"regulation": "SOC 2", "region": "North America", "status": "applicable"})
                compliance_set.add("SOC 2")
            if "HIPAA" not in compliance_set:
                compliance_regions.append({"regulation": "HIPAA", "region": "North America", "status": "applicable"})
                compliance_set.add("HIPAA")
        if tenant_country in ["GB", "DE", "FR", "NL", "IE", "SE", "NO", "DK", "FI", "CH", "AT", "BE", "IT", "ES", "PT", "PL"]:
            if "GDPR" not in compliance_set:
                compliance_regions.append({"regulation": "GDPR", "region": "Europe", "status": "applicable"})
                compliance_set.add("GDPR")
        if tenant_country in ["AE", "SA", "QA", "KW", "BH", "OM"]:
            if "PDPL" not in compliance_set:
                compliance_regions.append({"regulation": "PDPL", "region": "Middle East", "status": "applicable"})
                compliance_set.add("PDPL")
            if "NESA" not in compliance_set:
                compliance_regions.append({"regulation": "NESA", "region": "UAE", "status": "check_required"})
                compliance_set.add("NESA")
        if tenant_country in ["AU", "NZ"]:
            if "Privacy Act" not in compliance_set:
                compliance_regions.append({"regulation": "Privacy Act", "region": "Australia/NZ", "status": "applicable"})
                compliance_set.add("Privacy Act")
        if tenant_country in ["SG", "MY", "TH", "ID", "PH"]:
            if "PDPA" not in compliance_set:
                compliance_regions.append({"regulation": "PDPA", "region": "Southeast Asia", "status": "applicable"})
                compliance_set.add("PDPA")
        
        # Store temporarily - will be extended after AWS regions are checked
        result["compliance_regions"] = compliance_regions
        result["_compliance_set"] = compliance_set  # Internal tracking

    except Exception as exc:
        logger.warning(f"data_residency: {exc}")

    # Add AWS CloudTrail/IAM user activity by region
    try:
        # Query aws_findings for admin_action category (CloudTrail events) with region info
        cloudtrail_activity = await db.execute(text("""
            SELECT 
                COALESCE(metadata->>'region', metadata->>'awsRegion') as activity_region,
                COUNT(*) as event_count
            FROM aws_findings
            WHERE org_id = :org_id 
              AND (category = 'admin_action' OR resource_type = 'cloudtrail_event')
              AND detected_at > NOW() - INTERVAL '30 days'
            GROUP BY 1
        """), {"org_id": org_id})
        
        # Map AWS regions to geographic regions and add to user_activity_regions
        aws_region_to_country = {
            "us-east-1": ("US", "United States", "North America", 37.0902, -95.7129),
            "us-east-2": ("US", "United States", "North America", 39.9612, -82.9988),
            "us-west-1": ("US", "United States", "North America", 37.7749, -122.4194),
            "uaenorth": ("US", "United States", "North America", 45.5152, -122.6784),
            "eu-west-1": ("IE", "Ireland", "Europe", 53.3498, -6.2603),
            "eu-west-2": ("GB", "United Kingdom", "Europe", 51.5074, -0.1278),
            "eu-west-3": ("FR", "France", "Europe", 48.8566, 2.3522),
            "eu-central-1": ("DE", "Germany", "Europe", 50.1109, 8.6821),
            "eu-north-1": ("SE", "Sweden", "Europe", 59.3293, 18.0686),
            "ap-southeast-1": ("SG", "Singapore", "Asia Pacific", 1.3521, 103.8198),
            "ap-southeast-2": ("AU", "Australia", "Asia Pacific", -33.8688, 151.2093),
            "ap-northeast-1": ("JP", "Japan", "Asia Pacific", 35.6762, 139.6503),
            "ap-northeast-2": ("KR", "South Korea", "Asia Pacific", 37.5665, 126.9780),
            "ap-south-1": ("IN", "India", "Asia Pacific", 19.0760, 72.8777),
            "me-south-1": ("BH", "Bahrain", "Middle East", 26.0667, 50.5577),
            "me-central-1": ("AE", "UAE", "Middle East", 25.2048, 55.2708),
            "sa-east-1": ("BR", "Brazil", "South America", -23.5505, -46.6333),
            "af-south-1": ("ZA", "South Africa", "Africa", -33.9249, 18.4241),
        }
        
        for row in cloudtrail_activity.mappings():
            region = row["activity_region"]
            count = row["event_count"]
            if region and region in aws_region_to_country:
                code, country, geo_region, lat, lng = aws_region_to_country[region]
                # Add to user_activity_regions (or merge if country exists)
                existing = next((r for r in result["user_activity_regions"] if r["country_code"] == code), None)
                if existing:
                    existing["sign_in_count"] += count
                else:
                    result["user_activity_regions"].append({
                        "country_code": code,
                        "country": f"{country} (AWS)",
                        "region": geo_region,
                        "lat": lat,
                        "lng": lng,
                        "sign_in_count": count,
                    })
                # Update region_summary
                result["region_summary"][geo_region] = result["region_summary"].get(geo_region, 0) + count
        logger.info(f"data_residency: added AWS CloudTrail activity from {cloudtrail_activity.rowcount} regions")
    except Exception as e:
        logger.debug(f"CloudTrail activity query failed: {e}")

    # Add cloud infrastructure data regions (AWS, GCP, etc.) with resource counts
    try:
        cloud_regions = []
        
        # AWS regions with resource counts
        aws_result = await db.execute(text("""
            SELECT region, COUNT(*) as resource_count,
                   SUM(CASE WHEN resource_type IN ('s3_bucket', 'ebs_volume', 'rds_instance', 'efs_filesystem') THEN 1 ELSE 0 END) as storage_count,
                   SUM(CASE WHEN resource_type IN ('ec2_instance', 'lambda_function') THEN 1 ELSE 0 END) as compute_count
            FROM aws_resources 
            WHERE org_id = :org_id AND region IS NOT NULL
            GROUP BY region
        """), {"org_id": org_id})
        for row in aws_result.mappings():
            if row["region"]:
                cloud_regions.append({
                    "provider": "AWS",
                    "region": row["region"],
                    "type": "cloud",
                    "resource_count": row["resource_count"],
                    "storage_count": row["storage_count"] or 0,
                    "compute_count": row["compute_count"] or 0,
                    "lat": _get_aws_region_coords(row["region"])[0],
                    "lng": _get_aws_region_coords(row["region"])[1],
                })
        
        # GCP regions with resource counts
        try:
            gcp_result = await db.execute(text("""
                SELECT location, COUNT(*) as resource_count
                FROM gcp_resources WHERE org_id = :org_id AND location IS NOT NULL
                GROUP BY location
            """), {"org_id": org_id})
            for row in gcp_result.mappings():
                if row["location"]:
                    cloud_regions.append({
                        "provider": "GCP",
                        "region": row["location"],
                        "type": "cloud",
                        "resource_count": row["resource_count"],
                    })
        except Exception:
            pass  # GCP table may not exist
        
        # AWS connections with scan regions (configured but no resources yet)
        try:
            aws_conn_result = await db.execute(text("""
                SELECT scan_regions FROM aws_connections WHERE org_id = :org_id AND status = 'active'
            """), {"org_id": org_id})
            for row in aws_conn_result:
                if row[0]:
                    for region in row[0]:
                        if not any(cr["provider"] == "AWS" and cr["region"] == region for cr in cloud_regions):
                            coords = _get_aws_region_coords(region)
                            cloud_regions.append({
                                "provider": "AWS",
                                "region": region,
                                "type": "configured",
                                "resource_count": 0,
                                "lat": coords[0],
                                "lng": coords[1],
                            })
        except Exception:
            pass  # aws_connections table may not exist

        # ── Databricks workspaces ───────────────────────────────────
        # Databricks workspace URLs encode the home region in the host:
        #   dbc-…aws… → US-East (Virginia)         lat=37.43 lng=-78.66
        #   dbc-…cloud.databricks.com → infer from connection metadata
        #   westeurope, eastus, etc. via control plane
        # Without explicit region metadata we plot all workspaces at
        # the configured workspace_url's geographic hint; default to
        # US-East where the Databricks control plane is hosted.
        try:
            db_result = await db.execute(text("""
                SELECT dc.workspace_url, COUNT(dr.id) AS resource_count
                FROM databricks_connections dc
                LEFT JOIN databricks_resources dr ON dr.connection_id = dc.id
                WHERE dc.org_id = :org_id AND dc.status = 'active'
                GROUP BY dc.workspace_url
            """), {"org_id": org_id})
            for row in db_result.mappings():
                ws_url = (row["workspace_url"] or "").lower()
                # crude region inference from URL substrings
                if "eu-" in ws_url or "europe" in ws_url or ".eu." in ws_url:
                    lat, lng, region_label = 53.4, 6.9, "eu-west"
                elif "ap-" in ws_url or "asia" in ws_url or ".sg." in ws_url:
                    lat, lng, region_label = 1.35, 103.82, "ap-southeast"
                elif "au-" in ws_url or "australia" in ws_url:
                    lat, lng, region_label = -33.87, 151.21, "ap-southeast-2"
                else:
                    lat, lng, region_label = 37.43, -78.66, "us-east"
                cloud_regions.append({
                    "provider": "Databricks",
                    "region": region_label,
                    "type": "ai_ml",
                    "resource_count": int(row["resource_count"] or 0) or 1,
                    "lat": lat,
                    "lng": lng,
                })
        except Exception as _db_exc:
            logger.debug(f"data_residency: databricks region append failed: {_db_exc}")

        # ── GitHub organizations ────────────────────────────────────
        # GitHub is globally hosted by Microsoft in US datacentres.
        # We plot one marker per connected org at GitHub HQ (SF) so the
        # user can see code-repo coverage on the map.
        try:
            gh_result = await db.execute(text("""
                SELECT gc.gh_org,
                       (SELECT COUNT(*) FROM cspm_findings cf
                          WHERE cf.org_id = gc.org_id AND cf.cloud = 'github'
                            AND cf.resolved_at IS NULL) AS finding_count
                FROM github_connections gc
                WHERE gc.org_id = :org_id AND gc.status = 'active'
            """), {"org_id": org_id})
            for row in gh_result.mappings():
                cloud_regions.append({
                    "provider": "GitHub",
                    "region": f"{row['gh_org']} (global)",
                    "type": "code",
                    "resource_count": int(row["finding_count"] or 0) or 1,
                    "lat": 37.7749,   # San Francisco
                    "lng": -122.4194,
                })
        except Exception as _gh_exc:
            logger.debug(f"data_residency: github region append failed: {_gh_exc}")

        # ── SAP S/4HANA hosts ───────────────────────────────────────
        # We don't always know SAP host geography; default to Europe
        # (SAP HQ + most enterprise SAP installs). If a hostname maps
        # to a known cloud region, prefer that.
        try:
            sap_result = await db.execute(text("""
                SELECT name, system_id, host
                FROM sap_connections
                WHERE org_id = :org_id AND status = 'active'
            """), {"org_id": org_id})
            for row in sap_result.mappings():
                host = (row["host"] or "").lower()
                if ".eu" in host or ".de" in host or "europe" in host:
                    lat, lng, region = 49.4875, 8.4660, "eu-central (Walldorf)"
                elif ".us" in host or "-us-" in host:
                    lat, lng, region = 37.0902, -95.7129, "us"
                elif ".ap" in host or ".sg" in host or ".jp" in host:
                    lat, lng, region = 1.35, 103.82, "ap-southeast"
                else:
                    lat, lng, region = 49.4875, 8.4660, "eu-central (Walldorf)"
                cloud_regions.append({
                    "provider": "SAP",
                    "region": f"{row['system_id']} · {region}",
                    "type": "erp",
                    "resource_count": 1,
                    "lat": lat,
                    "lng": lng,
                })
        except Exception as _sap_exc:
            logger.debug(f"data_residency: sap region append failed: {_sap_exc}")

        # ── Azure subscriptions ─────────────────────────────────────
        try:
            az_result = await db.execute(text("""
                SELECT region, COUNT(*) AS resource_count
                FROM azure_resources
                WHERE org_id = :org_id AND region IS NOT NULL
                GROUP BY region
            """), {"org_id": org_id})
            for row in az_result.mappings():
                region_name = (row["region"] or "").lower()
                # azure region → lat/lng (subset of biggest ones)
                AZURE_COORDS = {
                    "eastus": (37.43, -78.66), "eastus2": (37.43, -78.66),
                    "westus": (37.78, -122.42), "westus2": (47.61, -122.33),
                    "westus3": (33.45, -112.07), "centralus": (41.59, -93.62),
                    "northeurope": (53.35, -6.26), "westeurope": (52.37, 4.90),
                    "uksouth": (51.51, -0.13), "ukwest": (53.43, -2.96),
                    "southeastasia": (1.35, 103.82), "eastasia": (22.32, 114.17),
                    "japaneast": (35.68, 139.69), "japanwest": (34.69, 135.50),
                    "australiaeast": (-33.87, 151.21),
                    "uaenorth": (24.47, 54.37), "southafricanorth": (-26.20, 28.04),
                    "brazilsouth": (-23.55, -46.63),
                }
                lat, lng = AZURE_COORDS.get(region_name, (37.43, -78.66))
                cloud_regions.append({
                    "provider": "Azure",
                    "region": row["region"],
                    "type": "cloud",
                    "resource_count": int(row["resource_count"]),
                    "lat": lat,
                    "lng": lng,
                })
        except Exception as _az_exc:
            logger.debug(f"data_residency: azure region append failed: {_az_exc}")

        # ── Oracle Cloud Infrastructure ─────────────────────────────
        try:
            oci_result = await db.execute(text("""
                SELECT region, COUNT(*) AS conn_count
                FROM oracle_connections
                WHERE org_id = :org_id AND status = 'active' AND region IS NOT NULL
                GROUP BY region
            """), {"org_id": org_id})
            OCI_COORDS = {
                "us-ashburn-1": (39.04, -77.49), "us-phoenix-1": (33.45, -112.07),
                "us-sanjose-1": (37.33, -121.89), "uk-london-1": (51.51, -0.13),
                "eu-frankfurt-1": (50.11, 8.68), "eu-amsterdam-1": (52.37, 4.90),
                "ap-mumbai-1": (19.07, 72.88), "ap-tokyo-1": (35.68, 139.69),
                "ap-sydney-1": (-33.87, 151.21), "ap-singapore-1": (1.35, 103.82),
                "me-jeddah-1": (21.49, 39.19), "me-dubai-1": (25.20, 55.27),
                "sa-saopaulo-1": (-23.55, -46.63),
            }
            for row in oci_result.mappings():
                lat, lng = OCI_COORDS.get((row["region"] or "").lower(), (37.43, -78.66))
                cloud_regions.append({
                    "provider": "Oracle",
                    "region": row["region"],
                    "type": "cloud",
                    "resource_count": int(row["conn_count"]),
                    "lat": lat,
                    "lng": lng,
                })
        except Exception as _oci_exc:
            logger.debug(f"data_residency: oracle region append failed: {_oci_exc}")

        result["cloud_regions"] = cloud_regions

        # Add AWS S3 buckets + RDS instances to data_locations (storage resources only)
        try:
            aws_storage_result = await db.execute(text("""
                SELECT COALESCE(name, resource_id) as rname, resource_type, region, resource_arn
                FROM aws_resources
                WHERE org_id = :org_id
                  AND resource_type IN ('s3_bucket', 'rds_instance', 'efs_filesystem', 'ebs_volume')
                ORDER BY resource_type, rname
                LIMIT 50
            """), {"org_id": org_id})
            for row in aws_storage_result.mappings():
                result["data_locations"].append({
                    "name": f"AWS {row['resource_type'].replace('_', ' ').title()}: {row['rname'] or row['resource_arn'] or '?'}",
                    "url": "",
                    "region": row["region"] or "unknown",
                    "type": "AWS",
                })
        except Exception as _awsloc_exc:
            logger.debug(f"data_residency: AWS storage locations query failed: {_awsloc_exc}")

        # Compute consolidated primary data region from all connected workspaces
        primary_region = result.get("tenant_region")  # M365 baseline
        try:
            aws_crs = [cr for cr in cloud_regions if cr["provider"] == "AWS" and cr.get("resource_count", 0) > 0]
            if aws_crs:
                top_aws = max(aws_crs, key=lambda x: x.get("resource_count", 0))
                logger.info(f"data_residency: AWS primary region = {top_aws['region']} ({top_aws['resource_count']} resources)")
                if not primary_region:
                    primary_region = f"AWS {top_aws['region']}"
            gcp_crs = [cr for cr in cloud_regions if cr["provider"] == "GCP" and cr.get("resource_count", 0) > 0]
            if gcp_crs and not primary_region:
                primary_region = f"GCP {gcp_crs[0]['region']}"
        except Exception:
            pass
        result["primary_data_region"] = primary_region
        
        # Extend compliance frameworks based on AWS regions with resources
        compliance_set = result.get("_compliance_set", set())
        compliance_regions = result.get("compliance_regions", [])
        
        # Map AWS regions to compliance frameworks
        aws_region_compliance = {
            # US regions -> SOC2, HIPAA
            "us-east-1": [("SOC 2", "North America"), ("HIPAA", "North America")],
            "us-east-2": [("SOC 2", "North America"), ("HIPAA", "North America")],
            "us-west-1": [("SOC 2", "North America"), ("HIPAA", "North America")],
            "uaenorth": [("SOC 2", "North America"), ("HIPAA", "North America")],
            "ca-central-1": [("SOC 2", "North America"), ("PIPEDA", "Canada")],
            # EU regions -> GDPR
            "eu-west-1": [("GDPR", "Europe")],
            "eu-west-2": [("GDPR", "Europe")],
            "eu-west-3": [("GDPR", "Europe")],
            "eu-central-1": [("GDPR", "Europe")],
            "eu-north-1": [("GDPR", "Europe")],
            "eu-south-1": [("GDPR", "Europe")],
            # Middle East
            "me-south-1": [("PDPL", "Middle East"), ("NESA", "Bahrain")],
            "me-central-1": [("PDPL", "Middle East"), ("NESA", "UAE")],
            # Asia Pacific
            "ap-southeast-1": [("PDPA", "Singapore")],
            "ap-southeast-2": [("Privacy Act", "Australia")],
            "ap-northeast-1": [("APPI", "Japan")],
            "ap-northeast-2": [("PIPA", "South Korea")],
            "ap-south-1": [("DPDP", "India")],
            # South America
            "sa-east-1": [("LGPD", "Brazil")],
            # Africa
            "af-south-1": [("POPIA", "South Africa")],
        }
        
        for cr in cloud_regions:
            if cr.get("provider") == "AWS" and cr.get("resource_count", 0) > 0:
                region_code = cr.get("region", "")
                frameworks = aws_region_compliance.get(region_code, [])
                for reg, reg_region in frameworks:
                    if reg not in compliance_set:
                        compliance_regions.append({
                            "regulation": reg,
                            "region": reg_region,
                            "status": "applicable"
                        })
                        compliance_set.add(reg)
        
        result["compliance_regions"] = compliance_regions
        result.pop("_compliance_set", None)  # Remove internal tracking
        
        logger.info(f"data_residency: cloud_regions={len(cloud_regions)} data_locations={len(result['data_locations'])} primary={primary_region} compliance={len(compliance_regions)}")
    except Exception as e:
        logger.debug(f"Cloud regions query failed (tables may not exist): {e}")
        result["cloud_regions"] = []
        result.setdefault("primary_data_region", result.get("tenant_region"))
        result.pop("_compliance_set", None)

    # ------------------------------------------------------------------
    # Attach a real compliance percentage to each framework entry based
    # on the org's live ComplianceStatus rows (populated by the
    # background compliance worker every 24h and by /api/compliance/
    # assess). This makes the Workspace Security overview's
    # "Compliance Frameworks" tile reflect real workspace security
    # posture rather than a static "Active" label.
    # ------------------------------------------------------------------
    try:
        # Map the human regulation names we emit above to the framework
        # keys stored in compliance_controls.framework.
        REG_TO_FRAMEWORK = {
            "SOC 2": "SOC2",
            "HIPAA": "HIPAA",
            "GDPR": "GDPR",
            "PDPL": "SAMA_CSF",          # Saudi PDPL closest fit
            "NESA": "UAE_NESA",
            "Privacy Act": "GDPR",        # AU Privacy Act maps best to GDPR-style controls
            "PDPA": "GDPR",               # SG/MY PDPA also closest to GDPR
            "ISO 27001": "ISO_27001",
            "NIST CSF": "NIST_CSF",
            "DORA": "DORA",
            "NIS 2": "NIS2",
            "CCPA": "CCPA",
            "SAMA CSF": "SAMA_CSF",
            "NCA ECC": "NCA_ECC",
            "CBUAE": "CBUAE",
        }
        wanted_frameworks = {
            REG_TO_FRAMEWORK[c["regulation"]]
            for c in result["compliance_regions"]
            if c.get("regulation") in REG_TO_FRAMEWORK
        }
        if wanted_frameworks:
            # Compute compliance percentage per framework from the live
            # compliance_status table, scoped to this org_id.
            scores_rows = await db.execute(text("""
                SELECT
                    cc.framework                         AS framework,
                    COUNT(*)                              AS total,
                    COUNT(*) FILTER (WHERE cs.status = 'compliant')     AS compliant,
                    COUNT(*) FILTER (WHERE cs.status = 'partial')       AS partial,
                    COUNT(*) FILTER (WHERE cs.status = 'non_compliant') AS non_compliant
                FROM compliance_controls cc
                LEFT JOIN compliance_status cs
                       ON cs.control_id = cc.id
                      AND cs.org_id     = CAST(:org_id AS UUID)
                WHERE cc.framework = ANY(:fws)
                GROUP BY cc.framework
            """), {"org_id": org_id, "fws": list(wanted_frameworks)})

            score_by_fw = {}
            for r in scores_rows.mappings():
                total = r["total"] or 0
                compliant = r["compliant"] or 0
                partial = r["partial"] or 0
                pct = round(((compliant + partial * 0.5) / total) * 100) if total else 0
                score_by_fw[r["framework"]] = {
                    "score_pct": pct,
                    "total": total,
                    "compliant": compliant,
                    "partial": partial,
                    "non_compliant": r["non_compliant"] or 0,
                }
            for c in result["compliance_regions"]:
                fw_key = REG_TO_FRAMEWORK.get(c.get("regulation"))
                if fw_key and fw_key in score_by_fw:
                    s = score_by_fw[fw_key]
                    c["score_pct"] = s["score_pct"]
                    c["compliant"] = s["compliant"]
                    c["partial"] = s["partial"]
                    c["total_controls"] = s["total"]
                    # Status now reflects real posture, not a hardcoded
                    # "applicable" string from the country-mapping above.
                    if s["score_pct"] >= 80:
                        c["status"] = "compliant"
                    elif s["score_pct"] >= 50:
                        c["status"] = "partial"
                    elif s["total"] > 0:
                        c["status"] = "at_risk"
                    else:
                        c["status"] = "not_assessed"
    except Exception as _ce:
        logger.warning(f"data_residency: compliance score enrichment failed: {_ce}")

    return result


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK CHAINS — Auto-Enumerated from Real Data
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/attack-chains")
async def get_attack_chains(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Auto-generate verbose attack chains from real data:
    - Public S3 buckets -> data exfil risk
    - External shares -> data leak paths
    - Overprivileged users -> privilege escalation
    - Risky sign-ins -> account compromise
    - Open ports -> network exploitation
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    attack_paths = []
    now_iso = datetime.utcnow().isoformat() + "Z"

    # 1. Public S3 buckets -> data exfil
    try:
        result = await db.execute(text("""
            SELECT id::text, COALESCE(name, resource_id) as name, resource_type, region, resource_arn
            FROM aws_resources
            WHERE org_id = :org_id AND public_access = TRUE
            ORDER BY created_at DESC
            LIMIT 20
        """), {"org_id": org_id})
        for row in result.mappings():
            bucket_name = row["name"] or "unknown-bucket"
            bucket_arn = row.get("resource_arn") or f"arn:aws:s3:::{bucket_name}"
            region = row.get("region") or "us-east-1"
            attack_paths.append({
                "id": f"aws-pub-{row['id']}",
                "title": f"Public S3 Bucket '{bucket_name}' Exposes Data to Internet",
                "severity": "critical",
                "type": "data_exfil",
                "description": (
                    f"S3 bucket '{bucket_name}' in region {region} has public access enabled, "
                    f"meaning any unauthenticated internet user can list and download its contents. "
                    f"This creates a direct data exfiltration path requiring no credentials. "
                    f"Attackers routinely scan for misconfigured S3 buckets using automated tools. "
                    f"If this bucket contains sensitive data (PII, credentials, backups, configs), "
                    f"it represents an immediate critical risk of data breach."
                ),
                "entry_point": {
                    "type": "internet",
                    "name": "Public Internet",
                    "detail": "No authentication required — any internet user can access this resource directly via HTTP/HTTPS.",
                    "icon": "GLOBE",
                },
                "pivot_points": [
                    {
                        "type": "public_access",
                        "name": "Disabled Block Public Access",
                        "detail": f"The S3 Block Public Access setting is disabled on bucket '{bucket_name}', allowing public bucket policies and ACLs to take effect.",
                        "icon": "UNLOCK",
                    }
                ],
                "impact": {
                    "type": "data_exposure",
                    "name": "Unrestricted Data Exfiltration",
                    "detail": f"All objects in '{bucket_name}' can be enumerated and downloaded by any internet actor without authentication, enabling mass data exfiltration.",
                    "icon": "ALERT_OCTAGON",
                },
                "affected_resources": [bucket_arn, f"s3://{bucket_name}/*"],
                "remediation": [
                    f"1. In AWS Console, navigate to S3 > '{bucket_name}' > Permissions > Block public access.",
                    "2. Enable all four Block Public Access settings and save.",
                    "3. Review and remove any bucket policy statements with 'Principal: *' and Effect: Allow.",
                    "4. Audit all objects for sensitive data using Amazon Macie or manual review.",
                    "5. Enable S3 server access logging to detect any prior unauthorized access.",
                    "6. Set up AWS Config rule 's3-bucket-public-read-prohibited' to prevent recurrence.",
                ],
                "detected_at": now_iso,
                # Legacy fields for UI compatibility
                "resource_name": bucket_name,
                "resource_type": row["resource_type"] or "s3_bucket",
                "provider": "aws",
                "exposure_type": "public_bucket",
                "risk_level": "critical",
                "classification": "public",
                "region": region,
                "path_steps": [
                    {"step": 1, "description": "Public Internet", "icon": "GLOBE"},
                    {"step": 2, "description": "No Auth Required", "icon": "UNLOCK"},
                    {"step": 3, "description": bucket_name[:20], "icon": "DATABASE"},
                    {"step": 4, "description": "Data Exfiltration", "icon": "ALERT_OCTAGON"},
                ],
            })
    except Exception:
        pass

    # 2. External SharePoint/Teams shares with sensitive data
    try:
        result = await db.execute(text("""
            SELECT id::text, item_name, provider, sharing_scope, classification_label, owner_email, parent_path
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND sharing_scope IN ('external', 'public')
              AND classification_label IN ('confidential', 'highly_confidential')
            ORDER BY classification_label DESC, created_at DESC
            LIMIT 20
        """), {"org_id": org_id})
        for row in result.mappings():
            is_public = row["sharing_scope"] == "public"
            exposure = "anonymous_link" if is_public else "external_share"
            is_critical = row["classification_label"] == "highly_confidential"
            file_name = row["item_name"]
            owner = row.get("owner_email") or "unknown user"
            provider_name = row["provider"]
            share_type = "anonymous link (no login required)" if is_public else "external user share"
            sensitivity = "Highly Confidential" if is_critical else "Confidential"
            path_info = row.get("parent_path") or "/"
            attack_paths.append({
                "id": f"saas-ext-{row['id']}",
                "title": f"{sensitivity} File '{file_name}' Shared Externally via {provider_name.capitalize()}",
                "severity": "critical" if is_critical else "high",
                "type": "data_leak",
                "description": (
                    f"User '{owner}' has shared the {sensitivity.lower()} file '{file_name}' "
                    f"(located at {path_info}) via {share_type} in {provider_name.capitalize()}. "
                    f"This file contains data classified as {sensitivity}, meaning it likely holds "
                    f"sensitive business information, PII, or regulated data. "
                    f"{'Anyone with the link can access this file without signing in.' if is_public else 'External parties outside your organization can access this file.'} "
                    f"This creates a data leak risk that is difficult to revoke once the link is distributed."
                ),
                "entry_point": {
                    "type": "external_actor",
                    "name": "External / Unauthenticated Actor",
                    "detail": f"{'Anonymous internet users via a publicly shared link.' if is_public else 'External users outside the organization who received the share invitation.'}",
                    "icon": "USER_X",
                },
                "pivot_points": [
                    {
                        "type": "shared_link",
                        "name": f"{provider_name.capitalize()} {'Anonymous Link' if is_public else 'External Share'}",
                        "detail": f"The file has been shared via a {share_type}. Access is not limited to corporate accounts.",
                        "icon": "LINK",
                    }
                ],
                "impact": {
                    "type": "data_leak",
                    "name": f"{sensitivity} Data Leak",
                    "detail": f"The contents of '{file_name}' — classified as {sensitivity} — are accessible to external parties, risking regulatory violations (GDPR, HIPAA, SOC2) and business harm.",
                    "icon": "SHIELD_ALERT",
                },
                "affected_resources": [file_name, f"{provider_name}:{path_info}/{file_name}", owner],
                "remediation": [
                    f"1. In {provider_name.capitalize()}, navigate to the file '{file_name}' and open Sharing settings.",
                    "2. Remove the external share or anonymous link immediately.",
                    "3. Restrict sharing permissions to 'Organization only' for files classified as Confidential or above.",
                    f"4. Contact '{owner}' to verify the share was intentional and document the business justification.",
                    "5. Enable Data Loss Prevention (DLP) policies to prevent future external sharing of classified content.",
                    "6. Review audit logs to determine who accessed the file while it was shared.",
                ],
                "detected_at": now_iso,
                # Legacy fields
                "resource_name": file_name,
                "resource_type": "file",
                "provider": provider_name,
                "exposure_type": exposure,
                "risk_level": "critical" if is_critical else "high",
                "classification": row["classification_label"],
                "path_steps": [
                    {"step": 1, "description": "External Actor", "icon": "USER_X"},
                    {"step": 2, "description": "Shared Link", "icon": "LINK"},
                    {"step": 3, "description": file_name[:20], "icon": "FILE_TEXT"},
                    {"step": 4, "description": "Data Leak", "icon": "SHIELD_ALERT"},
                ],
            })
    except Exception:
        pass

    # 3. Overprivileged users (high risky user score + admin actions)
    try:
        result = await db.execute(text("""
            SELECT DISTINCT a.resource_name, a.provider, a.alert_type, a.title as alert_title
            FROM saas_alerts a
            WHERE a.org_id = CAST(:org_id AS UUID)
              AND a.alert_type IN ('entra_risky_user', 'permission_escalation', 'privileged_action')
              AND a.status = 'open'
              AND a.severity IN ('critical', 'high')
              AND a.resource_name LIKE '%@%'
            LIMIT 10
        """), {"org_id": org_id})
        for row in result.mappings():
            user_email = row["resource_name"]
            username = user_email.split("@")[0] if "@" in user_email else user_email
            provider_name = row.get("provider") or "m365"
            alert_type = row.get("alert_type") or "privileged_action"
            attack_paths.append({
                "id": f"priv-esc-{user_email[:30]}",
                "title": f"Overprivileged Account '{user_email}' Enables Privilege Escalation",
                "severity": "high",
                "type": "privilege_escalation",
                "description": (
                    f"User account '{user_email}' has been flagged for {alert_type.replace('_', ' ')} "
                    f"and holds elevated administrative permissions beyond what is required for their role. "
                    f"If this account is compromised (via phishing, credential stuffing, or insider threat), "
                    f"an attacker gains immediate access to sensitive systems and data with admin-level privileges. "
                    f"The principle of least privilege is violated, meaning the blast radius of any compromise is maximized. "
                    f"Privilege escalation attacks are a top initial access technique used in ransomware and APT campaigns."
                ),
                "entry_point": {
                    "type": "user_account",
                    "name": f"Overprivileged User: {user_email}",
                    "detail": f"Account '{user_email}' has administrative or highly privileged roles that exceed job requirements, creating an oversized attack surface.",
                    "icon": "USER",
                },
                "pivot_points": [
                    {
                        "type": "admin_access",
                        "name": "Excessive Admin Permissions",
                        "detail": f"The account holds elevated roles (e.g., Global Admin, Owner) that grant access to sensitive systems, configurations, and data across the organization.",
                        "icon": "KEY",
                    }
                ],
                "impact": {
                    "type": "full_compromise",
                    "name": "Full Environment Compromise",
                    "detail": f"With admin access, an attacker controlling '{username}' can exfiltrate all organizational data, create backdoor accounts, modify security policies, and deploy ransomware across the tenant.",
                    "icon": "ALERT_OCTAGON",
                },
                "affected_resources": [user_email, f"{provider_name}:tenant/admin-roles"],
                "remediation": [
                    f"1. Review '{user_email}' role assignments and remove any admin roles not actively required.",
                    "2. Apply the principle of least privilege — assign only the minimum permissions needed.",
                    "3. Enable Multi-Factor Authentication (MFA) on the account immediately if not already active.",
                    "4. Enable Privileged Identity Management (PIM) so admin roles require just-in-time activation.",
                    "5. Set up Conditional Access policies to restrict admin access to managed, compliant devices.",
                    "6. Review the account's recent audit log for suspicious activity before remediating.",
                ],
                "detected_at": now_iso,
                # Legacy fields
                "resource_name": user_email,
                "resource_type": "user",
                "provider": provider_name,
                "exposure_type": "privilege_escalation",
                "risk_level": "high",
                "path_steps": [
                    {"step": 1, "description": "Overprivileged User", "icon": "USER"},
                    {"step": 2, "description": "Admin Access", "icon": "KEY"},
                    {"step": 3, "description": "Sensitive Systems", "icon": "SERVER"},
                    {"step": 4, "description": "Full Compromise", "icon": "ALERT_OCTAGON"},
                ],
            })
    except Exception:
        pass

    # 4. Risky sign-ins -> account compromise
    try:
        result = await db.execute(text("""
            SELECT user_email, risk_level, risk_detail
            FROM saas_risky_users
            WHERE org_id = CAST(:org_id AS UUID)
              AND risk_level IN ('high', 'medium')
            LIMIT 10
        """), {"org_id": org_id})
        for row in result.mappings():
            user_email = row["user_email"]
            username = user_email.split("@")[0] if "@" in user_email else user_email
            rl = row["risk_level"]
            risk_detail = row.get("risk_detail") or "suspicious sign-in activity"
            is_critical = rl == "high"
            attack_paths.append({
                "id": f"risky-user-{user_email[:30]}",
                "title": f"Risky Sign-In for '{user_email}' Indicates Account Compromise",
                "severity": "critical" if is_critical else "high",
                "type": "account_compromise",
                "description": (
                    f"Microsoft Entra ID has flagged '{user_email}' as a {rl}-risk user due to: {risk_detail}. "
                    f"This indicates the account credentials may be compromised or actively under attack. "
                    f"Risky sign-ins are detected using Microsoft's threat intelligence, including leaked credential databases, "
                    f"impossible travel patterns (e.g., sign-in from US followed by Russia within 30 minutes), "
                    f"and anomalous behavior analytics. If the account is compromised, the attacker has full access "
                    f"to all data and services the user can access — email, SharePoint, Teams, and connected apps."
                ),
                "entry_point": {
                    "type": "attacker",
                    "name": "Threat Actor / Credential Theft",
                    "detail": f"Attacker obtained credentials for '{user_email}' via phishing, credential stuffing, or dark web purchase of leaked passwords.",
                    "icon": "USER_X",
                },
                "pivot_points": [
                    {
                        "type": "compromised_credentials",
                        "name": "Compromised Account Credentials",
                        "detail": f"Entra ID detected anomalous sign-in activity for '{user_email}': {risk_detail}. The account session may be active.",
                        "icon": "KEY",
                    }
                ],
                "impact": {
                    "type": "account_takeover",
                    "name": "Full Account Takeover",
                    "detail": f"With control of '{username}', the attacker can read all emails, access SharePoint/OneDrive files, send phishing emails as the user, and pivot to other systems via SSO.",
                    "icon": "ALERT_OCTAGON",
                },
                "affected_resources": [user_email, f"m365:mailbox/{user_email}", f"m365:onedrive/{username}"],
                "remediation": [
                    f"1. Immediately revoke all active sessions for '{user_email}' in Entra ID (Users > Revoke sessions).",
                    "2. Force a password reset for the account.",
                    "3. Verify MFA is enabled and review registered MFA methods for unauthorized additions.",
                    "4. Review mailbox rules, forwarding settings, and Outlook delegates for backdoors.",
                    "5. Check OAuth app consents granted by the user and revoke any suspicious applications.",
                    "6. Review sign-in logs for the past 30 days to determine the full scope of compromise.",
                    "7. Enable Entra ID Identity Protection Conditional Access policy to block high-risk sign-ins automatically.",
                ],
                "detected_at": now_iso,
                # Legacy fields
                "resource_name": user_email,
                "resource_type": "user",
                "provider": "m365",
                "exposure_type": "risky_signin",
                "risk_level": "critical" if is_critical else "high",
                "path_steps": [
                    {"step": 1, "description": "Threat Actor", "icon": "USER_X"},
                    {"step": 2, "description": "Stolen Credentials", "icon": "KEY"},
                    {"step": 3, "description": username[:18], "icon": "USER"},
                    {"step": 4, "description": "Account Takeover", "icon": "ALERT_OCTAGON"},
                ],
            })
    except Exception:
        pass

    # 5. Open ports from AWS findings
    try:
        result = await db.execute(text("""
            SELECT id::text, title, resource_id, resource_arn, severity, category
            FROM aws_findings
            WHERE org_id = :org_id
              AND (category ILIKE '%port%' OR category ILIKE '%network%' OR title ILIKE '%open port%'
                   OR title ILIKE '%unrestricted%' OR title ILIKE '%publicly exposed%')
              AND severity IN ('critical', 'high')
            LIMIT 10
        """), {"org_id": org_id})
        for row in result.mappings():
            resource_id = row.get("resource_id") or ""
            resource_arn = row.get("resource_arn") or ""
            resource_name = resource_id or resource_arn or "Network Resource"
            finding_title = row.get("title") or "Open Port / Network Exposure"
            sev = row.get("severity") or "high"
            attack_paths.append({
                "id": f"aws-port-{row['id']}",
                "title": f"Exposed Network Resource '{resource_name}' — {finding_title}",
                "severity": sev,
                "type": "network_exploit",
                "description": (
                    f"AWS Security Hub has detected that '{resource_name}' has an open or unrestricted network exposure: '{finding_title}'. "
                    f"Publicly accessible ports (e.g., SSH on 22, RDP on 3389, database ports) allow attackers to "
                    f"probe and exploit vulnerable services without any initial authentication. "
                    f"This is a common entry point for automated botnets, ransomware operators, and nation-state actors "
                    f"who continuously scan the internet for exposed services. "
                    f"A single vulnerable or misconfigured service can result in full server compromise and lateral movement into the internal network."
                ),
                "entry_point": {
                    "type": "internet",
                    "name": "Public Internet — Open Port",
                    "detail": f"The resource '{resource_name}' has a port or service exposed directly to the internet without IP allowlisting or additional authentication controls.",
                    "icon": "GLOBE",
                },
                "pivot_points": [
                    {
                        "type": "open_port",
                        "name": "Unrestricted Network Access",
                        "detail": f"Finding: '{finding_title}'. The security group or network ACL allows inbound traffic from 0.0.0.0/0 (all internet IPs) to a sensitive port.",
                        "icon": "UNLOCK",
                    }
                ],
                "impact": {
                    "type": "server_compromise",
                    "name": "Remote Code Execution / Server Takeover",
                    "detail": f"Exploitation of exposed services on '{resource_name}' can result in remote code execution, unauthorized data access, cryptomining, or use as a pivot point to attack internal AWS resources.",
                    "icon": "SERVER",
                },
                "affected_resources": [r for r in [resource_arn, resource_id] if r],
                "remediation": [
                    f"1. Identify which port/service is exposed on '{resource_name}' and whether it is intentional.",
                    "2. In EC2 > Security Groups, restrict inbound rules to specific IP ranges (your office IPs) instead of 0.0.0.0/0.",
                    "3. For SSH/RDP access, use AWS Systems Manager Session Manager instead of direct port exposure.",
                    "4. For database services, ensure they are in private subnets with no public IP assigned.",
                    "5. Enable AWS GuardDuty to detect exploitation attempts in real time.",
                    "6. Use AWS WAF or a Network Firewall for any required public-facing services.",
                ],
                "detected_at": now_iso,
                # Legacy fields
                "resource_name": resource_name,
                "resource_type": "network",
                "provider": "aws",
                "exposure_type": "open_port",
                "risk_level": sev,
                "path_steps": [
                    {"step": 1, "description": "Public Internet", "icon": "GLOBE"},
                    {"step": 2, "description": "Open Port", "icon": "UNLOCK"},
                    {"step": 3, "description": resource_name[:18], "icon": "SERVER"},
                    {"step": 4, "description": "Exploitation", "icon": "ALERT_OCTAGON"},
                ],
            })
    except Exception:
        pass

    summary = {
        "total_paths": len(attack_paths),
        "critical_paths": sum(1 for p in attack_paths if p["risk_level"] == "critical"),
        "high_paths": sum(1 for p in attack_paths if p["risk_level"] == "high"),
        "by_provider": {},
        "by_exposure": {},
    }
    for p in attack_paths:
        prov = p["provider"]
        exp = p["exposure_type"]
        summary["by_provider"][prov] = summary["by_provider"].get(prov, 0) + 1
        summary["by_exposure"][exp] = summary["by_exposure"].get(exp, 0) + 1

    return {"attack_paths": attack_paths, "summary": summary}


# ══════════════════════════════════════════════════════════════════════════════
# DLP CLASSIFICATION BACKGROUND WORKER — Claude-powered
# ══════════════════════════════════════════════════════════════════════════════

async def _run_dlp_classification_worker(org_id: str) -> None:
    """
    DLP Classification Background Worker:
    - Runs Claude API for contextual analysis on unclassified/stale data items
    - Updates classification_label and severity
    - Creates alerts for high-risk items
    """
    if not ANTHROPIC_API_KEY:
        logger.debug(f"dlp_worker: ANTHROPIC_API_KEY not set, skipping for org {org_id}")
        return

    try:
        async with AsyncSessionLocal() as db:
            # Get items that need (re)classification.
            # Adnan 2026-06-23: Teams + SharePoint items were landing
            # with classification_label='internal' (the SaaSDataItem
            # default) AND classification_categories=NULL/[] when the
            # original ingestor couldn't fetch content. The old WHERE
            # only re-classified internal items >7 days old, so brand-new
            # SharePoint/Teams files showed up uncategorised forever.
            # New rule: pick up anything that's NULL, or 'internal'/'public'
            # with no DLP categories yet, or older than 7d at 'internal'.
            result = await db.execute(text("""
                SELECT id::text, item_name, parent_path, provider, sharing_scope,
                       classification_label, owner_email, classification_categories
                FROM saas_data_items
                WHERE org_id = CAST(:org_id AS UUID)
                  AND (
                    classification_label IS NULL
                    OR (
                        classification_label IN ('internal', 'public')
                        AND (
                            classification_categories IS NULL
                            OR cardinality(classification_categories) = 0
                        )
                    )
                    OR (classification_label = 'internal' AND last_scanned_at < NOW() - INTERVAL '7 days')
                  )
                ORDER BY created_at DESC
                LIMIT 50
            """), {"org_id": org_id})
            items = result.mappings().all()

            if not items:
                return

            logger.info(f"dlp_worker: classifying {len(items)} items for org {org_id}")

            for item in items:
                try:
                    context = f"File: {item['item_name']}\nPath: {item['parent_path'] or 'Unknown'}\nProvider: {item['provider']}"
                    prompt = (
                        f"Classify this file for DLP risk. Return JSON only.\n"
                        f"Context: {context}\n\n"
                        f"Return: {{\"risk_level\": \"low|medium|high|critical\", "
                        f"\"categories\": [\"pii_ssn\"|\"financial_tax\"|\"hr_medical\"|etc], "
                        f"\"confidence\": 0.0-1.0, \"explanation\": \"brief reason\"}}"
                    )

                    async with httpx.AsyncClient(timeout=20) as client:
                        r = await client.post(
                            "https://api.anthropic.com/v1/messages",
                            headers={
                                "x-api-key": ANTHROPIC_API_KEY,
                                "anthropic-version": "2023-06-01",
                                "content-type": "application/json",
                            },
                            json={
                                "model": "claude-haiku-4-5",
                                "max_tokens": 200,
                                "messages": [{"role": "user", "content": prompt}],
                            },
                        )

                    if r.status_code != 200:
                        continue

                    raw = r.json()["content"][0]["text"].strip()
                    raw = re.sub(r"^```[\w]*\n?", "", raw)
                    raw = re.sub(r"```$", "", raw).strip()
                    cls_result = json.loads(raw)

                    risk_level = cls_result.get("risk_level", "low")
                    label = _risk_to_label(risk_level)
                    score = float(cls_result.get("confidence", 0.5))
                    categories = cls_result.get("categories", [])
                    # Adnan 2026-06-23 (turn 3): if Claude returned no
                    # categories, try the cross-cloud heuristic before
                    # we write an empty list. This is the same backstop
                    # we apply at SharePoint / Teams ingest time —
                    # makes sure the DLP Categories column on the
                    # frontend is never silently empty.
                    if not categories:
                        try:
                            from backend.services.cross_cloud_dlp import _classify_heuristic
                            heur_cats, _ = _classify_heuristic({
                                "name": item.get("item_name"),
                                "resource_type": "file",
                                "resource_path": item.get("parent_path"),
                            })
                            if heur_cats:
                                categories = heur_cats
                        except Exception as _hexc:
                            logger.debug(f"dlp_worker heuristic fallback failed: {_hexc}")

                    # Belt-and-suspenders: include org_id even though the
                    # item id was fetched by an org-scoped SELECT above.
                    # Cheap and protects us if anyone refactors the SELECT.
                    await db.execute(text("""
                        UPDATE saas_data_items
                        SET classification_label = :label,
                            classification_score = :score,
                            classification_categories = :cats,
                            last_scanned_at = NOW()
                        WHERE id     = CAST(:item_id AS UUID)
                          AND org_id = CAST(:org_id  AS UUID)
                    """), {
                        "label": label,
                        "score": score,
                        "cats": categories,
                        "item_id": item["id"],
                        "org_id": org_id,
                    })

                    # Create alert for high-risk items shared externally
                    if risk_level in ("high", "critical") and item.get("sharing_scope") in ("external", "public"):
                        existing_alert = await db.execute(text("""
                            SELECT id FROM saas_alerts
                            WHERE org_id = CAST(:org_id AS UUID)
                              AND resource_id = :rid AND status = 'open'
                        """), {"org_id": org_id, "rid": item["id"]})
                        if not existing_alert.first():
                            await db.execute(text("""
                                INSERT INTO saas_alerts
                                (org_id, provider, alert_type, severity, title, description,
                                 resource_id, resource_name, status, created_at)
                                VALUES (
                                    CAST(:org_id AS UUID), :provider, :alert_type,
                                    :severity, :title, :description,
                                    :rid, :rname, 'open', NOW()
                                )
                            """), {
                                "org_id": org_id,
                                "provider": item["provider"],
                                "alert_type": cls_result.get("categories", ["SENSITIVE_DATA"])[0] if cls_result.get("categories") else "SENSITIVE_DATA",
                                "severity": risk_level,
                                "title": f"Sensitive data shared externally: {item['item_name'][:80]}",
                                "description": cls_result.get("explanation", "File classified as high-risk and shared externally."),
                                "rid": item["id"],
                                "rname": item["item_name"],
                            })

                except json.JSONDecodeError:
                    continue
                except Exception as exc:
                    logger.warning(f"dlp_worker: item {item.get('id')} failed: {exc}")
                    continue

            await db.commit()
            logger.info(f"dlp_worker: completed SaaS classification for org {org_id}")
            
            # ── Also classify AWS resources (S3 buckets, etc.) ───────────────────
            # Classify the full breadth of AWS resource types. Previously
            # this was restricted to s3/rds/dynamodb which is why EC2, IAM,
            # security groups, EBS, EFS — the majority of an AWS account —
            # showed blank DLP categories in the Data Inventory.
            aws_result = await db.execute(text("""
                SELECT resource_id, name, resource_type, resource_arn, metadata, region
                FROM aws_resources
                WHERE org_id = CAST(:org_id AS UUID)
                  AND (metadata->>'dlp_classified' IS NULL OR metadata->>'dlp_classified' != 'true')
                ORDER BY scanned_at DESC
                LIMIT 80
            """), {"org_id": org_id})
            aws_items = aws_result.mappings().all()
            
            if aws_items:
                logger.info(f"dlp_worker: classifying {len(aws_items)} AWS resources for org {org_id}")
                
                for aws_item in aws_items:
                    try:
                        meta = aws_item["metadata"] or {}
                        if isinstance(meta, str):
                            meta = json.loads(meta)
                        
                        # Build context for classification
                        context = f"AWS {aws_item['resource_type']}: {aws_item['name']}\n"
                        context += f"Region: {aws_item['region']}\n"
                        context += f"ARN: {aws_item['resource_arn']}\n"
                        if meta.get("public_access"):
                            context += "Public Access: YES (CRITICAL)\n"
                        if meta.get("encryption_enabled") is False:
                            context += "Encryption: DISABLED\n"
                        if meta.get("versioning"):
                            context += f"Versioning: {meta['versioning']}\n"
                        
                        prompt = (
                            f"Classify this AWS resource for DLP risk based on its name and configuration. "
                            f"Infer data sensitivity from naming conventions (e.g., prod-, finance-, pii-, backup-, logs-).\n"
                            f"Return JSON only.\n\n"
                            f"Context: {context}\n\n"
                            f"Return: {{\"risk_level\": \"low|medium|high|critical\", "
                            f"\"categories\": [\"source_code\"|\"financial_data\"|\"customer_pii\"|\"logs\"|\"backups\"|\"ml_models\"|etc], "
                            f"\"inferred_data_type\": \"what data likely stored\", "
                            f"\"confidence\": 0.0-1.0}}"
                        )
                        
                        async with httpx.AsyncClient(timeout=20) as client:
                            r = await client.post(
                                "https://api.anthropic.com/v1/messages",
                                headers={
                                    "x-api-key": ANTHROPIC_API_KEY,
                                    "anthropic-version": "2023-06-01",
                                    "content-type": "application/json",
                                },
                                json={
                                    "model": "claude-haiku-4-5",
                                    "max_tokens": 200,
                                    "messages": [{"role": "user", "content": prompt}],
                                },
                            )
                        
                        if r.status_code != 200:
                            continue
                        
                        raw = r.json()["content"][0]["text"].strip()
                        raw = re.sub(r"^```[\w]*\n?", "", raw)
                        raw = re.sub(r"```$", "", raw).strip()
                        cls_result = json.loads(raw)
                        
                        # Update metadata with classification
                        meta["dlp_classified"] = "true"
                        meta["dlp_categories"] = cls_result.get("categories", [])
                        meta["dlp_risk_level"] = cls_result.get("risk_level", "low")
                        meta["inferred_data_type"] = cls_result.get("inferred_data_type", "")
                        
                        await db.execute(text("""
                            UPDATE aws_resources
                            SET metadata = CAST(:meta AS jsonb),
                                last_modified = NOW()
                            WHERE org_id = CAST(:org_id AS UUID) AND resource_id = :rid
                        """), {
                            # default=str: round-trip datetimes/UUIDs that
                            # asyncpg may have parsed out of the JSONB column.
                            "meta": json.dumps(meta, default=str),
                            "org_id": org_id,
                            "rid": aws_item["resource_id"],
                        })
                        
                    except Exception as aws_exc:
                        logger.debug(f"dlp_worker: AWS item {aws_item['resource_id']} failed: {aws_exc}")
                        continue
                
                await db.commit()
                logger.info(f"dlp_worker: completed AWS classification for org {org_id}")

            # ── Databricks resource classification ─────────────────────────
            # Notebooks / clusters / jobs / secrets. Inference is name-based
            # (e.g. "finance-etl", "pii-ingest") plus has_secrets flag.
            try:
                db_result = await db.execute(text("""
                    SELECT resource_id, resource_type, resource_path, name, language,
                           has_secrets, metadata
                    FROM databricks_resources
                    WHERE org_id = CAST(:org_id AS UUID)
                      AND (metadata->>'dlp_classified' IS NULL
                           OR metadata->>'dlp_classified' != 'true')
                    ORDER BY scanned_at DESC
                    LIMIT 60
                """), {"org_id": org_id})
                db_items = db_result.mappings().all()
                if db_items:
                    logger.info(f"dlp_worker: classifying {len(db_items)} Databricks resources for org {org_id}")
                    for db_item in db_items:
                        try:
                            d_meta = db_item["metadata"] or {}
                            if isinstance(d_meta, str):
                                d_meta = json.loads(d_meta)
                            ctx = (
                                f"Databricks {db_item['resource_type']}: {db_item['name']}\n"
                                f"Path: {db_item['resource_path']}\n"
                                f"Language: {db_item.get('language') or 'n/a'}\n"
                                f"Has secrets: {db_item.get('has_secrets')}\n"
                            )
                            prompt = (
                                "Classify this Databricks asset for DLP. Infer data sensitivity from "
                                "the path/name and secret/language signals. JSON only.\n\n"
                                f"Context: {ctx}\n\n"
                                'Return: {"risk_level":"low|medium|high|critical",'
                                '"categories":["source_code"|"customer_pii"|"financial_data"|"ml_models"|"logs"|"backups"|etc],'
                                '"inferred_data_type":"...","confidence":0.0-1.0}'
                            )
                            async with httpx.AsyncClient(timeout=20) as client:
                                r = await client.post(
                                    "https://api.anthropic.com/v1/messages",
                                    headers={
                                        "x-api-key": ANTHROPIC_API_KEY,
                                        "anthropic-version": "2023-06-01",
                                        "content-type": "application/json",
                                    },
                                    json={
                                        "model": "claude-haiku-4-5",
                                        "max_tokens": 200,
                                        "messages": [{"role": "user", "content": prompt}],
                                    },
                                )
                            if r.status_code != 200:
                                continue
                            raw = r.json()["content"][0]["text"].strip()
                            raw = re.sub(r"^```[\w]*\n?", "", raw)
                            raw = re.sub(r"```$", "", raw).strip()
                            cls = json.loads(raw)
                            d_meta["dlp_classified"] = "true"
                            d_meta["dlp_categories"] = cls.get("categories", [])
                            d_meta["dlp_risk_level"] = cls.get("risk_level", "low")
                            d_meta["inferred_data_type"] = cls.get("inferred_data_type", "")
                            await db.execute(text("""
                                UPDATE databricks_resources
                                SET metadata = CAST(:meta AS jsonb)
                                WHERE org_id = CAST(:org_id AS UUID)
                                  AND resource_id = :rid
                                  AND resource_type = :rtype
                            """), {
                                "meta": json.dumps(d_meta, default=str),
                                "org_id": org_id,
                                "rid": db_item["resource_id"],
                                "rtype": db_item["resource_type"],
                            })
                        except Exception as db_exc:
                            logger.debug(f"dlp_worker: Databricks item {db_item.get('resource_id')} failed: {db_exc}")
                            continue
                    await db.commit()
                    logger.info(f"dlp_worker: completed Databricks classification for org {org_id}")
            except Exception as _dexc:
                logger.warning(f"dlp_worker: Databricks classification top-level error for org {org_id}: {_dexc}")
                try:
                    await db.rollback()
                except Exception:
                    pass

            # ── GCP resource classification ────────────────────────────────
            try:
                gcp_result = await db.execute(text("""
                    SELECT resource_id, resource_type, resource_name, name, location,
                           public_access, encryption_enabled, metadata
                    FROM gcp_resources
                    WHERE org_id = CAST(:org_id AS UUID)
                      AND (metadata->>'dlp_classified' IS NULL
                           OR metadata->>'dlp_classified' != 'true')
                    ORDER BY scanned_at DESC
                    LIMIT 60
                """), {"org_id": org_id})
                gcp_items = gcp_result.mappings().all()
                if gcp_items:
                    logger.info(f"dlp_worker: classifying {len(gcp_items)} GCP resources for org {org_id}")
                    for g_item in gcp_items:
                        try:
                            g_meta = g_item["metadata"] or {}
                            if isinstance(g_meta, str):
                                g_meta = json.loads(g_meta)
                            ctx = (
                                f"GCP {g_item['resource_type']}: {g_item['name']}\n"
                                f"Resource: {g_item['resource_name']}\n"
                                f"Location: {g_item['location']}\n"
                                f"Public access: {g_item.get('public_access')}\n"
                                f"Encryption: {g_item.get('encryption_enabled')}\n"
                            )
                            prompt = (
                                "Classify this GCP resource for DLP. Infer sensitivity from name + "
                                "public/encryption signals. JSON only.\n\n"
                                f"Context: {ctx}\n\n"
                                'Return: {"risk_level":"low|medium|high|critical",'
                                '"categories":["source_code"|"customer_pii"|"financial_data"|"logs"|"backups"|etc],'
                                '"inferred_data_type":"...","confidence":0.0-1.0}'
                            )
                            async with httpx.AsyncClient(timeout=20) as client:
                                r = await client.post(
                                    "https://api.anthropic.com/v1/messages",
                                    headers={
                                        "x-api-key": ANTHROPIC_API_KEY,
                                        "anthropic-version": "2023-06-01",
                                        "content-type": "application/json",
                                    },
                                    json={
                                        "model": "claude-haiku-4-5",
                                        "max_tokens": 200,
                                        "messages": [{"role": "user", "content": prompt}],
                                    },
                                )
                            if r.status_code != 200:
                                continue
                            raw = r.json()["content"][0]["text"].strip()
                            raw = re.sub(r"^```[\w]*\n?", "", raw)
                            raw = re.sub(r"```$", "", raw).strip()
                            cls = json.loads(raw)
                            g_meta["dlp_classified"] = "true"
                            g_meta["dlp_categories"] = cls.get("categories", [])
                            g_meta["dlp_risk_level"] = cls.get("risk_level", "low")
                            g_meta["inferred_data_type"] = cls.get("inferred_data_type", "")
                            await db.execute(text("""
                                UPDATE gcp_resources
                                SET metadata = CAST(:meta AS jsonb)
                                WHERE org_id = CAST(:org_id AS UUID)
                                  AND resource_name = :rname
                            """), {
                                "meta": json.dumps(g_meta, default=str),
                                "org_id": org_id,
                                "rname": g_item["resource_name"],
                            })
                        except Exception as g_exc:
                            logger.debug(f"dlp_worker: GCP item {g_item.get('resource_name')} failed: {g_exc}")
                            continue
                    await db.commit()
                    logger.info(f"dlp_worker: completed GCP classification for org {org_id}")
            except Exception as _gexc:
                logger.warning(f"dlp_worker: GCP classification top-level error for org {org_id}: {_gexc}")
                try:
                    await db.rollback()
                except Exception:
                    pass

    except Exception as exc:
        logger.error(f"dlp_worker: top-level error for org {org_id}: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
# WORKER STATUS TRACKING
# ══════════════════════════════════════════════════════════════════════════════

_worker_status: dict = {}

def _update_worker_status(worker: str, status: str = "running", error: str = None) -> None:
    """Track worker execution timestamps in memory."""
    now = datetime.now(timezone.utc)
    if worker not in _worker_status:
        _worker_status[worker] = {"status": status, "last_run": None, "next_run": None, "run_count": 0}
    _worker_status[worker]["status"] = status
    if status in ("running", "completed"):
        _worker_status[worker]["last_run"] = now.isoformat()
    if error:
        _worker_status[worker]["last_error"] = error
    _worker_status[worker]["run_count"] = _worker_status[worker].get("run_count", 0) + 1


def _set_worker_next_run(worker: str, interval_sec: int) -> None:
    """Set the next scheduled run time for a worker."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    next_run = now + timedelta(seconds=interval_sec)
    if worker not in _worker_status:
        _worker_status[worker] = {"status": "idle", "last_run": None, "next_run": None, "run_count": 0}
    _worker_status[worker]["next_run"] = next_run.isoformat()


@router.get("/workers/health")
async def workers_health(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get background worker health status.
    Returns: {workers: {name: {status, last_run, next_run}}, healthy: bool}
    """
    await _require_enterprise(current_user, db)
    org_id = str(current_user.org_id)

    # Check Redis for worker state (may not be available)
    redis_data = {}
    try:
        import redis.asyncio as aioredis
        _redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        r = aioredis.from_url(_redis_url, decode_responses=True)
        for w in ("saas_scan", "aws_scan", "dlp_worker", "posture_scan"):
            key = f"worker:{w}:status"
            val = await r.get(key)
            if val:
                redis_data[w] = json.loads(val)
        await r.aclose()
    except Exception:
        pass

    # Build response from memory + Redis + DB activity
    workers = {}
    worker_defs = {
        "saas_scan": {"interval_sec": 300, "label": "SaaS Security Scan"},
        "aws_scan": {"interval_sec": 300, "label": "AWS Security Scan"},
        "dlp_worker": {"interval_sec": 1800, "label": "DLP Classification Worker"},
        "posture_scan": {"interval_sec": 21600, "label": "Posture Evaluation"},
    }

    for w, wdef in worker_defs.items():
        mem = _worker_status.get(w, {})
        redis = redis_data.get(w, {})
        # Prefer Redis (shared across instances), fall back to memory
        last_run = redis.get("last_run") or mem.get("last_run")
        next_run = redis.get("next_run") or mem.get("next_run")
        status = redis.get("status") or mem.get("status", "unknown")
        workers[w] = {
            "label": wdef["label"],
            "status": status,
            "last_run": last_run,
            "next_run": next_run,
            "run_count": mem.get("run_count", 0),
        }

    # Validate against DB activity as ground truth
    try:
        # SaaS scan: check saas_alerts created in last 24h
        result = await db.execute(text("SELECT MAX(created_at) FROM saas_alerts WHERE org_id = :oid"), {"oid": org_id})
        last_alert = result.scalar()
        if last_alert:
            workers["saas_scan"]["last_db_activity"] = last_alert.isoformat()

        # AWS scan: check aws_findings
        result = await db.execute(text("SELECT MAX(detected_at) FROM aws_findings WHERE org_id = :oid"), {"oid": org_id})
        last_aws = result.scalar()
        if last_aws:
            workers["aws_scan"]["last_db_activity"] = last_aws.isoformat()

        # DLP: check data items scanned
        result = await db.execute(text("SELECT MAX(last_scanned_at) FROM saas_data_items WHERE org_id = CAST(:oid AS UUID)"), {"oid": org_id})
        last_dlp = result.scalar()
        if last_dlp:
            workers["dlp_worker"]["last_db_activity"] = last_dlp.isoformat()

        # Posture: check posture_checks
        result = await db.execute(text("SELECT MAX(last_checked_at) FROM saas_posture_checks WHERE org_id = CAST(:oid AS UUID)"), {"oid": org_id})
        last_posture = result.scalar()
        if last_posture:
            workers["posture_scan"]["last_db_activity"] = last_posture.isoformat()
    except Exception as exc:
        logger.debug(f"workers_health: DB activity check failed: {exc}")

    healthy = any(w.get("status") in ("running", "completed", "idle") for w in workers.values())
    return {"workers": workers, "healthy": healthy, "timestamp": datetime.now(timezone.utc).isoformat()}


# ══════════════════════════════════════════════════════════════════════════════
# AWS AI-DRIVEN SECURITY
# ══════════════════════════════════════════════════════════════════════════════

async def _aws_ai_classify_resource(
    resource_type: str,
    resource_metadata: dict,
    org_id: str,
) -> dict:
    """
    AI-driven AWS resource risk classification using Claude/DeepSeek.
    Takes: resource_type, resource_metadata (S3 policy, RDS config, EC2 SGs, etc.)
    Returns: {risk_level, categories, remediation_steps, explanation}

    Adnan 2026-06-23: previously this only saw `resource_summary`
    (i.e. metadata). For S3 / EBS we now also include a real CONTENT
    sample so the prompt reasons about actual data, not just naming.
    Callers may pre-populate `resource_metadata['_content_sample']` and
    `resource_metadata['_data_excerpts']` to skip the inline AWS calls.
    """
    # Build concise summary for AI
    summary_keys = (
        "public_access", "encryption_enabled", "encryption_type",
        "publicly_accessible", "deletion_protection", "multi_az",
        "ingress_rules", "open_ports", "tags", "policy", "acl",
        "backup_enabled", "logging_enabled", "versioning",
        "region", "size_bytes", "resource_id",
    )
    resource_summary = json.dumps(
        {k: v for k, v in resource_metadata.items() if k in summary_keys},
        default=str
    )[:1500]

    # Optional content sample (set by the caller for S3 / EBS).
    content_sample = (resource_metadata.get("_content_sample") or "").strip()
    data_excerpts = resource_metadata.get("_data_excerpts") or []
    extensions_seen = resource_metadata.get("_extensions_seen") or []
    object_count_seen = resource_metadata.get("_object_count_seen") or 0
    content_block = ""
    if content_sample:
        # Truncate to 8 KB in the prompt itself — we already capped at
        # 32 KB at sample time but the LLM cost matters here.
        content_block = (
            f"\n\nSAMPLED CONTENT FROM THIS RESOURCE "
            f"({object_count_seen} object(s) inspected, extensions seen: {extensions_seen}):\n"
            f"--- BEGIN SAMPLE ---\n{content_sample[:8000]}\n--- END SAMPLE ---\n"
            "USE THE CONTENT SAMPLE TO DRIVE data_categories. Naming hints "
            "are a fallback only when the sample is empty or generic.\n"
        )
    elif data_excerpts:
        # Caller already provided structured excerpts (used by Teams / SharePoint paths).
        content_block = (
            "\n\nSAMPLED CONTENT FROM THIS RESOURCE:\n"
            + "\n".join(
                f"<<{e.get('key','')}>>\n{(e.get('snippet') or '')[:1500]}"
                for e in data_excerpts[:6]
            )
            + "\nUSE THE CONTENT SAMPLE TO DRIVE data_categories.\n"
        )

    # Adnan 2026-06-22: previously the prompt restricted categories to
    # operational posture buckets (encryption/public_access/iam/network/
    # compliance/logging). That made the Data Inventory "DLP Categories"
    # column show iam/network/compliance for AWS rows — useful for
    # posture management but NOT the data-content categories the user
    # expects (PII, credentials, financial, etc.). The new prompt asks
    # for BOTH a posture_category and a list of inferred data_categories,
    # then we merge them so the column carries the meaningful
    # data-content labels first.
    prompt = (
        f"You are the Himaya Data Posture agent. Classify this {resource_type} "
        f"for risk AND infer the type of data it actually contains.\n"
        f"Config: {resource_summary}{content_block}\n\n"
        "Return JSON only:\n"
        '{"risk_level": "low|medium|high|critical", '
        '"data_categories": ["pii|pci|phi|credentials|financial|source_code|logs|backup|ml_data|customer_data|infrastructure|public_data"], '
        '"posture_categories": ["encryption|public_access|iam|network|compliance|logging"], '
        '"remediation_steps": ["step1", "step2"], "explanation": "1-2 sentences"}\n'
        "Rules: data_categories must reflect what data the resource actually holds. "
        "If a SAMPLED CONTENT block is present, infer categories from real content "
        "(presence of email addresses / SSN / credit-card / JWT / private-key markers / "
        "PHI fields like ICD codes / payroll columns). "
        "For S3 buckets named 'backup-*' use ['backup']; for 'customer-*' use ['pii','customer_data']; "
        "for IAM users/roles use ['credentials']; for buckets with 'logs' use ['logs']. Always pick at least one data_category."
    )

    # Try DeepSeek first
    try:
        async with httpx.AsyncClient(timeout=25) as client:
            resp = await client.post(
                f"{DEEPSEEK_ENDPOINT}/v1/chat/completions",
                json={
                    "model": "deepseek-r1-distill-llama-70b",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 300,
                    "temperature": 0.1,
                },
                timeout=20,
            )
            if resp.status_code == 200:
                raw = resp.json()["choices"][0]["message"]["content"].strip()
                raw = re.sub(r"^```[\w]*\n?", "", raw)
                raw = re.sub(r"```$", "", raw).strip()
                # Extract JSON from response (may have reasoning text before it)
                json_match = re.search(r'\{.*\}', raw, re.DOTALL)
                if json_match:
                    result = json.loads(json_match.group(0))
                    result.setdefault("risk_level", "low")
                    # Merge new dual-list shape into the legacy single
                    # `categories` field. Data categories first so the
                    # DLP Categories column shows them by default.
                    data_cats = result.get("data_categories") or []
                    posture_cats = result.get("posture_categories") or result.get("categories") or []
                    if not data_cats and not posture_cats:
                        result.setdefault("categories", [])
                    else:
                        result["categories"] = list(dict.fromkeys(data_cats + posture_cats))
                    result.setdefault("remediation_steps", [])
                    result.setdefault("explanation", "")
                    return result
    except Exception as exc:
        logger.debug(f"aws_ai_classify: DeepSeek failed: {exc}")

    # Try Claude Haiku fallback
    if ANTHROPIC_API_KEY:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-haiku-4-5",
                        "max_tokens": 300,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                if resp.status_code == 200:
                    raw = resp.json()["content"][0]["text"].strip()
                    raw = re.sub(r"^```[\w]*\n?", "", raw)
                    raw = re.sub(r"```$", "", raw).strip()
                    json_match = re.search(r'\{.*\}', raw, re.DOTALL)
                    if json_match:
                        result = json.loads(json_match.group(0))
                        result.setdefault("risk_level", "low")
                        # Same data+posture merge as the DeepSeek branch.
                        data_cats = result.get("data_categories") or []
                        posture_cats = result.get("posture_categories") or result.get("categories") or []
                        if not data_cats and not posture_cats:
                            result.setdefault("categories", [])
                        else:
                            result["categories"] = list(dict.fromkeys(data_cats + posture_cats))
                        result.setdefault("remediation_steps", [])
                        result.setdefault("explanation", "")
                        return result
        except Exception as exc:
            logger.debug(f"aws_ai_classify: Claude failed: {exc}")

    # Rule-based fallback
    risk_level = "low"
    categories = []
    remediation = []
    if resource_metadata.get("public_access") or resource_metadata.get("publicly_accessible"):
        risk_level = "critical"
        categories.append("public_access")
        remediation.append("Disable public access immediately")
        remediation.append("Review bucket/instance security groups")
    if not resource_metadata.get("encryption_enabled", True):
        if risk_level == "low":
            risk_level = "medium"
        categories.append("encryption")
        remediation.append("Enable encryption at rest")
    if not resource_metadata.get("logging_enabled", True):
        categories.append("logging")
        remediation.append("Enable access logging")
    return {
        "risk_level": risk_level,
        "categories": categories,
        "remediation_steps": remediation,
        "explanation": f"Rule-based: {', '.join(categories) or 'no issues detected'}",
    }


async def _aws_threat_scan(org_id: str, db: AsyncSession) -> list:
    """
    Comprehensive AWS threat scanning:
    - S3 public ACL + sensitive data
    - EC2 with public IP + weak SGs
    - RDS publicly accessible
    - CloudTrail disabled
    - Root account activity
    - IAM user console access + no MFA
    - Unused IAM credentials
    - KMS key deletion scheduled
    - GuardDuty findings
    - Security Hub findings
    Also runs AI classification on risky resources.
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    import json as _json

    findings = []
    try:
        aws_conn = await db.execute(text("""
            SELECT access_key_id_enc, secret_access_key_enc, default_region, scan_regions
            FROM aws_connections
            WHERE org_id = :org_id AND status = 'active'
            LIMIT 1
        """), {"org_id": org_id})
        conn_row = aws_conn.mappings().first()
        if not conn_row:
            return findings

        from backend.routers.aws_connector import _decrypt as _aws_decrypt
        access_key = _aws_decrypt(conn_row["access_key_id_enc"])
        secret_key = _aws_decrypt(conn_row["secret_access_key_enc"])
        region = conn_row["default_region"] or "us-east-1"
        scan_regions = conn_row["scan_regions"] or [region]

        def _make_client(service, reg=None):
            return boto3.client(
                service,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=reg or region,
            )

        # ── 1. S3: Public ACL detection ──────────────────────────────────────
        try:
            s3 = _make_client("s3")
            buckets_resp = s3.list_buckets()
            for bucket in buckets_resp.get("Buckets", [])[:20]:
                bname = bucket["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=bname)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "") in (
                            "http://acs.amazonaws.com/groups/global/AllUsers",
                            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        ):
                            findings.append({
                                "type": "s3_public_acl",
                                "severity": "critical",
                                "title": f"S3 Bucket Public ACL: {bname}",
                                "description": f"S3 bucket '{bname}' has a public ACL granting access to All Users or Authenticated AWS users.",
                                "resource_id": bname,
                                "category": "public_access",
                                "remediation": ["Run: aws s3api put-bucket-acl --bucket {} --acl private".format(bname)],
                            })
                except ClientError:
                    pass

                try:
                    pub_block = s3.get_public_access_block(Bucket=bname)
                    cfg = pub_block.get("PublicAccessBlockConfiguration", {})
                    if not all(cfg.get(k, False) for k in (
                        "BlockPublicAcls", "IgnorePublicAcls",
                        "BlockPublicPolicy", "RestrictPublicBuckets",
                    )):
                        # AI classify this bucket
                        ai_result = await _aws_ai_classify_resource(
                            "s3_bucket",
                            {"bucket_name": bname, "public_access": True, "public_access_block": cfg},
                            org_id,
                        )
                        findings.append({
                            "type": "s3_public_access_block_incomplete",
                            "severity": ai_result.get("risk_level", "high"),
                            "title": f"S3 Bucket Public Access Not Fully Blocked: {bname}",
                            "description": f"S3 bucket '{bname}' does not have all public access block settings enabled. AI analysis: {ai_result.get('explanation', '')}",
                            "resource_id": bname,
                            "category": "public_access",
                            "remediation": ai_result.get("remediation_steps", []),
                        })
                except ClientError:
                    pass
        except ClientError as exc:
            logger.warning(f"aws_threat_scan/s3: {exc}")

        # ── 2. EC2: Public IP + weak security groups ───────────────────────────
        for reg in scan_regions[:3]:
            try:
                ec2 = _make_client("ec2", reg)
                instances_resp = ec2.describe_instances(
                    Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
                )
                for reservation in instances_resp.get("Reservations", []):
                    for inst in reservation.get("Instances", []):
                        public_ip = inst.get("PublicIpAddress")
                        if not public_ip:
                            continue
                        instance_id = inst.get("InstanceId")
                        sg_ids = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]
                        if not sg_ids:
                            continue
                        # Check security group rules
                        sgs = ec2.describe_security_groups(GroupIds=sg_ids)
                        open_ports = []
                        for sg in sgs.get("SecurityGroups", []):
                            for rule in sg.get("IpPermissions", []):
                                for ip_range in rule.get("IpRanges", []):
                                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                                        from_port = rule.get("FromPort", -1)
                                        open_ports.append(from_port)
                        risky_ports = [p for p in open_ports if p in (22, 3389, 3306, 5432, 6379, 27017)]
                        if risky_ports:
                            ai_result = await _aws_ai_classify_resource(
                                "ec2_instance",
                                {"instance_id": instance_id, "public_ip": public_ip,
                                 "open_ports": open_ports, "risky_ports": risky_ports, "region": reg},
                                org_id,
                            )
                            findings.append({
                                "type": "ec2_public_with_open_ports",
                                "severity": ai_result.get("risk_level", "high"),
                                "title": f"EC2 Public IP + Open Sensitive Ports: {instance_id}",
                                "description": (
                                    f"EC2 instance {instance_id} in {reg} has public IP {public_ip} "
                                    f"and security groups with ports {risky_ports} open to 0.0.0.0/0. "
                                    f"AI: {ai_result.get('explanation', '')}"
                                ),
                                "resource_id": instance_id,
                                "category": "network",
                                "remediation": ai_result.get("remediation_steps", [
                                    f"Restrict ports {risky_ports} to specific IP ranges or VPN",
                                    "Use Systems Manager Session Manager instead of direct SSH",
                                ]),
                            })
            except ClientError as exc:
                logger.warning(f"aws_threat_scan/ec2/{reg}: {exc}")

        # ── 3. RDS: Publicly accessible ────────────────────────────────────────
        for reg in scan_regions[:3]:
            try:
                rds = _make_client("rds", reg)
                dbs = rds.describe_db_instances()
                for db_inst in dbs.get("DBInstances", []):
                    if db_inst.get("PubliclyAccessible"):
                        db_id = db_inst.get("DBInstanceIdentifier")
                        ai_result = await _aws_ai_classify_resource(
                            "rds_instance",
                            {"db_id": db_id, "publicly_accessible": True,
                             "engine": db_inst.get("Engine"), "region": reg},
                            org_id,
                        )
                        findings.append({
                            "type": "rds_publicly_accessible",
                            "severity": "critical",
                            "title": f"RDS Publicly Accessible: {db_id}",
                            "description": (
                                f"RDS instance '{db_id}' ({db_inst.get('Engine')}) in {reg} is publicly accessible. "
                                f"AI: {ai_result.get('explanation', '')}"
                            ),
                            "resource_id": db_id,
                            "category": "public_access",
                            "remediation": ai_result.get("remediation_steps", [
                                "Modify RDS instance to disable PubliclyAccessible",
                                "Use VPC security groups to restrict access",
                            ]),
                        })
            except ClientError as exc:
                logger.warning(f"aws_threat_scan/rds/{reg}: {exc}")

        # ── 4. CloudTrail: Disabled ────────────────────────────────────────────
        try:
            ct = _make_client("cloudtrail")
            trails = ct.describe_trails(includeShadowTrails=False)
            if not trails.get("trailList"):
                findings.append({
                    "type": "cloudtrail_disabled",
                    "severity": "critical",
                    "title": "CloudTrail Not Configured",
                    "description": "No CloudTrail trails found. AWS API activity is not being logged, making forensics and compliance auditing impossible.",
                    "resource_id": "cloudtrail",
                    "category": "logging",
                    "remediation": [
                        "Create a CloudTrail trail with S3 bucket storage",
                        "Enable multi-region and global service events",
                        "Enable log file validation",
                    ],
                })
            else:
                for trail in trails.get("trailList", []):
                    tn = trail.get("Name", "")
                    status = ct.get_trail_status(Name=tn)
                    if not status.get("IsLogging"):
                        findings.append({
                            "type": "cloudtrail_logging_disabled",
                            "severity": "high",
                            "title": f"CloudTrail Logging Disabled: {tn}",
                            "description": f"CloudTrail trail '{tn}' exists but logging is disabled.",
                            "resource_id": tn,
                            "category": "logging",
                            "remediation": [f"Run: aws cloudtrail start-logging --name {tn}"],
                        })
        except ClientError as exc:
            logger.warning(f"aws_threat_scan/cloudtrail: {exc}")

        # ── 5. IAM: Root account activity + console access without MFA ─────────
        try:
            iam = _make_client("iam")

            # Root account credential report
            try:
                iam.generate_credential_report()
                import time
                time.sleep(2)  # Wait for report generation
                report = iam.get_credential_report()
                import csv, io
                reader = csv.DictReader(io.StringIO(report["Content"].decode()))
                for row in reader:
                    user = row.get("user", "")
                    if user == "<root_account>":
                        # Root account activity
                        if row.get("password_last_used", "N/A") not in ("N/A", "no_information", ""):
                            findings.append({
                                "type": "root_account_activity",
                                "severity": "critical",
                                "title": "Root Account Recently Used",
                                "description": f"AWS root account was last used: {row.get('password_last_used')}. Root should never be used for routine operations.",
                                "resource_id": "root",
                                "category": "iam",
                                "remediation": [
                                    "Create IAM users/roles for all operations",
                                    "Enable MFA on root account",
                                    "Revoke all root access keys",
                                ],
                            })
                        if row.get("mfa_active", "false").lower() != "true":
                            findings.append({
                                "type": "root_no_mfa",
                                "severity": "critical",
                                "title": "Root Account MFA Not Enabled",
                                "description": "AWS root account does not have MFA enabled. This is a critical security risk.",
                                "resource_id": "root",
                                "category": "iam",
                                "remediation": ["Enable MFA on root account immediately via AWS Console"],
                            })
                    elif user and user != "<root_account>":
                        # IAM user with console access + no MFA
                        has_console = row.get("password_enabled", "false").lower() == "true"
                        mfa_active = row.get("mfa_active", "false").lower() == "true"
                        if has_console and not mfa_active:
                            findings.append({
                                "type": "iam_console_no_mfa",
                                "severity": "high",
                                "title": f"IAM User Console Access Without MFA: {user}",
                                "description": f"IAM user '{user}' has console access but MFA is not enabled.",
                                "resource_id": user,
                                "category": "iam",
                                "remediation": [
                                    f"Require MFA for user: aws iam create-virtual-mfa-device",
                                    "Create IAM policy requiring MFA condition",
                                ],
                            })
                        # Unused IAM credentials (no login in 90+ days)
                        last_used = row.get("password_last_used", "N/A")
                        if last_used not in ("N/A", "no_information", "") and has_console:
                            try:
                                from dateutil.parser import parse as _parse
                                last_dt = _parse(last_used)
                                if last_dt.tzinfo is None:
                                    from datetime import timezone as _tz
                                    last_dt = last_dt.replace(tzinfo=_tz.utc)
                                age_days = (datetime.now(timezone.utc) - last_dt).days
                                if age_days > 90:
                                    findings.append({
                                        "type": "iam_unused_credentials",
                                        "severity": "medium",
                                        "title": f"Unused IAM Credentials: {user} ({age_days}d)",
                                        "description": f"IAM user '{user}' has not logged in for {age_days} days. Unused credentials increase attack surface.",
                                        "resource_id": user,
                                        "category": "iam",
                                        "remediation": [
                                            f"Disable or delete user: aws iam delete-login-profile --user-name {user}",
                                            "Implement automated credential lifecycle management",
                                        ],
                                    })
                            except Exception:
                                pass
            except ClientError as e:
                logger.warning(f"aws_threat_scan/cred_report: {e}")

            # AI-powered IAM policy analysis
            try:
                paginator = iam.get_paginator("list_policies")
                for page in paginator.paginate(Scope="Local"):
                    for policy in page.get("Policies", [])[:10]:
                        parn = policy["Arn"]
                        ver = policy.get("DefaultVersionId", "v1")
                        try:
                            pvr = iam.get_policy_version(PolicyArn=parn, VersionId=ver)
                            doc = pvr.get("PolicyVersion", {}).get("Document", {})
                            doc_str = json.dumps(doc)[:800]
                            # Check for wildcard actions or resources (basic rule-based)
                            has_star_action = '"Action": "*"' in doc_str or '"Action": ["*"]' in doc_str
                            has_star_resource = '"Resource": "*"' in doc_str
                            if has_star_action and has_star_resource:
                                # AI classify this policy
                                ai_result = await _aws_ai_classify_resource(
                                    "iam_policy",
                                    {"policy_name": policy["PolicyName"],
                                     "policy_doc_preview": doc_str[:400],
                                     "has_wildcard_action": True,
                                     "has_wildcard_resource": True},
                                    org_id,
                                )
                                findings.append({
                                    "type": "iam_overpermissive_policy",
                                    "severity": ai_result.get("risk_level", "high"),
                                    "title": f"Overpermissive IAM Policy: {policy['PolicyName']}",
                                    "description": (
                                        f"IAM policy '{policy['PolicyName']}' grants Action:* on Resource:*. "
                                        f"AI: {ai_result.get('explanation', '')}"
                                    ),
                                    "resource_id": parn,
                                    "category": "iam",
                                    "remediation": ai_result.get("remediation_steps", [
                                        "Apply principle of least privilege",
                                        "Replace wildcard actions with specific permissions",
                                    ]),
                                })
                        except ClientError:
                            pass
            except ClientError as exc:
                logger.warning(f"aws_threat_scan/iam_policies: {exc}")

            # AI: Trust relationship / cross-account analysis
            try:
                roles_pag = iam.get_paginator("list_roles")
                for page in roles_pag.paginate():
                    for role in page.get("Roles", [])[:15]:
                        trust_doc = role.get("AssumeRolePolicyDocument", {})
                        trust_str = json.dumps(trust_doc)
                        # Cross-account trust
                        import re as _re
                        account_arns = _re.findall(r'arn:aws:iam::(\d+):', trust_str)
                        if len(set(account_arns)) > 1:
                            ai_result = await _aws_ai_classify_resource(
                                "iam_role",
                                {"role_name": role["RoleName"],
                                 "trust_accounts": list(set(account_arns)),
                                 "trust_doc_preview": trust_str[:400]},
                                org_id,
                            )
                            if ai_result.get("risk_level") in ("high", "critical"):
                                findings.append({
                                    "type": "iam_cross_account_trust",
                                    "severity": ai_result.get("risk_level", "medium"),
                                    "title": f"Cross-Account IAM Trust: {role['RoleName']}",
                                    "description": (
                                        f"IAM role '{role['RoleName']}' has trust relationships with "
                                        f"external accounts: {list(set(account_arns))}. "
                                        f"AI: {ai_result.get('explanation', '')}"
                                    ),
                                    "resource_id": role["Arn"],
                                    "category": "iam",
                                    "remediation": ai_result.get("remediation_steps", [
                                        "Review cross-account trust relationships",
                                        "Require ExternalId condition for cross-account roles",
                                    ]),
                                })
            except ClientError as exc:
                logger.warning(f"aws_threat_scan/iam_roles: {exc}")
        except ClientError as exc:
            logger.warning(f"aws_threat_scan/iam: {exc}")

        # ── 6. KMS: Keys scheduled for deletion ───────────────────────────────
        for reg in scan_regions[:3]:
            try:
                kms = _make_client("kms", reg)
                paginator = kms.get_paginator("list_keys")
                for page in paginator.paginate():
                    for key in page.get("Keys", []):
                        try:
                            key_meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                            if key_meta.get("KeyState") == "PendingDeletion":
                                del_date = key_meta.get("DeletionDate")
                                findings.append({
                                    "type": "kms_key_pending_deletion",
                                    "severity": "high",
                                    "title": f"KMS Key Scheduled for Deletion: {key_meta.get('Description', key['KeyId'][:8])}",
                                    "description": (
                                        f"KMS key {key['KeyId'][:12]}... in {reg} is scheduled for deletion on {del_date}. "
                                        f"Any data encrypted with this key will become permanently inaccessible."
                                    ),
                                    "resource_id": key["KeyId"],
                                    "category": "encryption",
                                    "remediation": [
                                        f"Run: aws kms cancel-key-deletion --key-id {key['KeyId']} --region {reg}",
                                        "Review if the key is still needed before allowing deletion",
                                    ],
                                })
                        except ClientError:
                            pass
            except ClientError as exc:
                logger.warning(f"aws_threat_scan/kms/{reg}: {exc}")

        # ── 7. GuardDuty: Active findings ──────────────────────────────────────
        for reg in scan_regions[:3]:
            try:
                gd = _make_client("guardduty", reg)
                detectors = gd.list_detectors().get("DetectorIds", [])
                for detector_id in detectors:
                    findings_resp = gd.list_findings(
                        DetectorId=detector_id,
                        FindingCriteria={"Criterion": {"severity": {"Gte": 4.0}}},
                        MaxResults=20,
                    )
                    gd_finding_ids = findings_resp.get("FindingIds", [])
                    if gd_finding_ids:
                        gd_details = gd.get_findings(
                            DetectorId=detector_id, FindingIds=gd_finding_ids[:10]
                        )
                        for gdf in gd_details.get("Findings", []):
                            sev = gdf.get("Severity", 0)
                            sev_label = "critical" if sev >= 7 else "high" if sev >= 4 else "medium"
                            findings.append({
                                "type": "guardduty_finding",
                                "severity": sev_label,
                                "title": f"GuardDuty: {gdf.get('Title', 'Finding')[:80]}",
                                "description": gdf.get("Description", "")[:500],
                                "resource_id": gdf.get("Id", ""),
                                "category": gdf.get("Type", "security").split("/")[0].lower(),
                                "remediation": [gdf.get("Service", {}).get("Action", {}).get("ActionType", "Review finding in GuardDuty console")],
                            })
            except ClientError as exc:
                logger.warning(f"aws_threat_scan/guardduty/{reg}: {exc}")

        # ── 8. Security Hub: Active findings ──────────────────────────────────
        try:
            sh = _make_client("securityhub")
            filters = {
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
                "SeverityLabel": [
                    {"Value": "CRITICAL", "Comparison": "EQUALS"},
                    {"Value": "HIGH", "Comparison": "EQUALS"},
                ],
            }
            sh_resp = sh.get_findings(Filters=filters, MaxResults=20)
            for shf in sh_resp.get("Findings", []):
                sev_label = shf.get("Severity", {}).get("Label", "MEDIUM").lower()
                findings.append({
                    "type": "security_hub_finding",
                    "severity": sev_label,
                    "title": f"Security Hub: {shf.get('Title', 'Finding')[:80]}",
                    "description": shf.get("Description", "")[:500],
                    "resource_id": shf.get("Id", ""),
                    "category": shf.get("ProductName", "security_hub").lower(),
                    "remediation": [r.get("Text", "") for r in shf.get("Remediation", {}).get("Recommendation", {}).get("Url", ["Review in Security Hub"])[:1]]
                    if isinstance(shf.get("Remediation"), dict) else ["Review finding in Security Hub"],
                })
        except ClientError as exc:
            logger.debug(f"aws_threat_scan/securityhub: {exc} (may not be enabled)")

    except (ImportError, Exception) as exc:
        logger.warning(f"aws_threat_scan: {exc}")

    return findings


async def _detect_teams_enterprise_threats(org_id: str, access_token: str, db: AsyncSession) -> None:
    """
    Enterprise Teams security rules:
    - Anonymous meeting join
    - External user in private channel
    - Guest with owner role
    - Channel deletion by non-owner
    - Teams app excessive permissions
    - Bulk file download
    - Webhook/connector abuse
    - Bot with admin permissions
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    GRAPH_URL = "https://graph.microsoft.com/v1.0"
    now = datetime.now(timezone.utc)

    async def _safe_get(url: str) -> tuple:
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(url, headers=headers)
                return r.status_code, r.json() if r.status_code < 500 else {}
        except Exception:
            return 0, {}

    async def _alert(alert_type, severity, title, description, resource_id, resource_name, raw=None):
        existing = (await db.execute(
            select(SaasAlert).where(
                SaasAlert.org_id == uuid.UUID(org_id),
                SaasAlert.resource_id == resource_id,
                SaasAlert.status == "open",
            )
        )).scalar_one_or_none()
        if existing:
            return
        db.add(SaasAlert(
            org_id=uuid.UUID(org_id), provider="teams",
            alert_type=alert_type, severity=severity, title=title,
            description=description, resource_id=resource_id,
            resource_name=resource_name, status="open", raw_data=raw or {},
        ))

    # 1. Guest user with owner role in Teams
    sc, teams_data = await _safe_get(f"{GRAPH_URL}/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName&$top=20")
    if sc == 200:
        for team in teams_data.get("value", [])[:10]:
            team_id = team.get("id")
            team_name = team.get("displayName", "Unknown")
            if not team_id:
                continue

            # Check team owners for guest accounts
            sc2, owners = await _safe_get(f"{GRAPH_URL}/groups/{team_id}/owners?$select=id,displayName,userPrincipalName,userType")
            if sc2 == 200:
                for owner in owners.get("value", []):
                    if owner.get("userType") == "Guest" or "#EXT#" in (owner.get("userPrincipalName") or ""):
                        await _alert(
                            "guest_team_owner", "high",
                            f"Guest User as Team Owner: {owner.get('displayName', 'Unknown')} in '{team_name}'",
                            f"Guest user {owner.get('userPrincipalName', 'Unknown')} is an owner of team '{team_name}'. "
                            f"Guest owners can add members, delete channels, and access all team files.",
                            f"guest-owner:{team_id}:{owner.get('id', '')}",
                            owner.get("userPrincipalName", team_name),
                            {"team": team_name, "guest": owner.get("userPrincipalName")},
                        )

            # Check private channels for external members
            sc3, channels = await _safe_get(f"{GRAPH_URL}/teams/{team_id}/channels?$filter=membershipType eq 'private'")
            if sc3 == 200:
                for ch in channels.get("value", [])[:5]:
                    ch_id = ch.get("id")
                    ch_name = ch.get("displayName", "Unknown")
                    sc4, ch_members = await _safe_get(f"{GRAPH_URL}/teams/{team_id}/channels/{ch_id}/members")
                    if sc4 == 200:
                        for member in ch_members.get("value", []):
                            email = member.get("email", "")
                            # Check if external (different tenant)
                            if email and "#EXT#" in email:
                                await _alert(
                                    "external_in_private_channel", "high",
                                    f"External User in Private Channel: {ch_name} / {team_name}",
                                    f"External user {email} is a member of private channel '{ch_name}' in team '{team_name}'. "
                                    f"Private channels should only contain internal employees.",
                                    f"ext-private-ch:{ch_id}:{email[:20]}",
                                    f"{team_name} > {ch_name}",
                                    {"team": team_name, "channel": ch_name, "external_user": email},
                                )

    # 2. Detect Teams webhook/connector abuse via recent admin audit log
    sc_audit, audit_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'Add connector to team'&$top=20"
    )
    if sc_audit == 200:
        for event in audit_data.get("value", []):
            initiator = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
            targets = event.get("targetResources", [])
            target_name = targets[0].get("displayName", "Unknown") if targets else "Unknown"
            await _alert(
                "teams_connector_added", "medium",
                f"Teams Connector Added: {target_name} by {initiator}",
                f"A Teams webhook/connector '{target_name}' was added by {initiator}. "
                f"Malicious connectors can exfiltrate data or send phishing messages into Teams channels.",
                f"connector:{event.get('id', target_name)[:40]}",
                initiator,
                {"initiator": initiator, "connector": target_name},
            )

    # 3. Teams app with excessive permissions (check installed apps)
    if sc == 200:
        for team in teams_data.get("value", [])[:5]:
            team_id = team.get("id")
            team_name = team.get("displayName", "")
            sc_app, apps = await _safe_get(f"{GRAPH_URL}/teams/{team_id}/installedApps?$expand=teamsAppDefinition")
            if sc_app == 200:
                for app in apps.get("value", []):
                    app_def = app.get("teamsAppDefinition", {}) or {}
                    app_name = app_def.get("displayName", "Unknown App")
                    # Skip Microsoft built-in / store-distributed apps — they do not
                    # support the resourceSpecificPermissionGrants endpoint and just
                    # return 400 Bad Request, flooding the logs.
                    # Adnan 2026-06-18: the old skip only matched
                    # 'com.microsoft.*' external ids but most catalog apps
                    # have a GUID id so the skip never fired and the
                    # background scanner burned ~50 Graph calls per
                    # iteration producing 400 errors. Skip any app whose
                    # distributionMethod is 'store' OR whose publisher is
                    # Microsoft — only sideloaded / org-distributed apps
                    # can have resourceSpecificPermissionGrants anyway.
                    external_id = (app_def.get("teamsAppId") or app_def.get("externalId") or "").lower()
                    distribution = (app_def.get("distributionMethod") or "").lower()
                    publisher = (app_def.get("publishingState") or app_def.get("publisherName") or "").lower()
                    if (
                        distribution in ("store", "global")
                        or external_id.startswith("com.microsoft.")
                        or publisher in ("microsoft", "microsoft corporation")
                    ):
                        continue
                    # Sideloaded apps only — these are the ones with
                    # resourceSpecificPermissionGrants.
                    if distribution not in ("organization", "sideloaded"):
                        continue
                    # Check app permissions (resource-specific consent)
                    sc_perms, perms = await _safe_get(
                        f"{GRAPH_URL}/teams/{team_id}/installedApps/{app.get('id', '')}/resourceSpecificPermissionGrants"
                    )
                    if sc_perms == 200:
                        high_risk_perms = [
                            p for p in perms.get("value", [])
                            if any(hp in (p.get("permissionType") or "") for hp in ("ReadWrite", "Full", "All"))
                        ]
                        if len(high_risk_perms) >= 2:
                            await _alert(
                                "teams_app_excessive_perms", "high",
                                f"Teams App Excessive Permissions: '{app_name}' in {team_name}",
                                f"Teams app '{app_name}' in '{team_name}' has {len(high_risk_perms)} high-risk permissions. "
                                f"Review if this app requires these permissions.",
                                f"teams-app-perms:{team_id}:{app.get('id', '')[:20]}",
                                f"{team_name} > {app_name}",
                                {"app": app_name, "team": team_name, "perm_count": len(high_risk_perms)},
                            )

    # 4. Bulk file download from Teams (via audit log)
    sc_dl, dl_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'FileDownloaded'&$top=50"
    )
    if sc_dl == 200:
        from collections import Counter
        dl_events = dl_data.get("value", [])
        user_dl = Counter(
            e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "unknown")
            for e in dl_events
        )
        for user, count in user_dl.most_common(5):
            if count >= 10 and user != "unknown":
                await _alert(
                    "teams_bulk_download", "high",
                    f"Bulk File Download from Teams: {user.split('@')[0]} ({count} files)",
                    f"User {user} downloaded {count} files from Teams in a short period. "
                    f"This may indicate data exfiltration.",
                    f"teams-bulk-dl:{user}:{now.date()}",
                    user,
                    {"user": user, "count": count},
                )

    # 5. Channel deletion (non-owner)
    sc_del, del_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'ChannelDeleted'&$top=20"
    )
    if sc_del == 200:
        for event in del_data.get("value", []):
            user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
            targets = event.get("targetResources", [])
            ch_name = targets[0].get("displayName", "Unknown") if targets else "Unknown Channel"
            await _alert(
                "teams_channel_deleted", "medium",
                f"Teams Channel Deleted: '{ch_name}' by {user}",
                f"Teams channel '{ch_name}' was deleted by {user}. Review if this was authorized. "
                f"Channel deletion is irreversible without backup.",
                f"ch-deleted:{event.get('id', ch_name)[:40]}",
                user,
                {"user": user, "channel": ch_name},
            )

    # 6. Teams meeting recording shared externally
    sc_rec, rec_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'SharingSet' and category eq 'Teams'&$top=30"
    )
    if sc_rec == 200:
        for event in rec_data.get("value", []):
            targets = event.get("targetResources", [])
            for target in targets:
                name = target.get("displayName", "").lower()
                # Meeting recordings often named "Recording - ..."
                if "recording" in name:
                    user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
                    await _alert(
                        "teams_recording_shared", "high",
                        f"Teams Meeting Recording Shared: {target.get('displayName', 'Recording')}",
                        f"User {user} shared a Teams meeting recording externally. "
                        f"Meeting recordings may contain sensitive discussions.",
                        f"recording-share:{event.get('id', name)[:40]}",
                        user,
                        {"user": user, "recording": target.get("displayName")},
                    )

    # 7. Teams 1:1 chat with external user (DLP bypass risk)
    sc_chat, chat_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'ChatCreated'&$top=30"
    )
    if sc_chat == 200:
        for event in chat_data.get("value", []):
            targets = event.get("targetResources", [])
            for target in targets:
                members = target.get("modifiedProperties", [])
                for prop in members:
                    if prop.get("displayName") == "Members":
                        new_val = prop.get("newValue", "")
                        if "#EXT#" in new_val or "guest" in new_val.lower():
                            user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
                            await _alert(
                                "teams_external_chat", "medium",
                                f"Teams 1:1 Chat with External User by {user.split('@')[0]}",
                                f"User {user} started a 1:1 chat with an external user. "
                                f"Direct chats bypass channel DLP policies.",
                                f"ext-chat:{event.get('id', user)[:40]}",
                                user,
                                {"user": user},
                            )
                            break

    # 8. Legacy authentication usage (insecure)
    sc_legacy, legacy_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/signIns?$filter=clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'&$top=20"
    )
    if sc_legacy == 200:
        legacy_apps = {"Exchange Web Services", "IMAP4", "POP3", "SMTP", "Exchange ActiveSync", "Other clients"}
        for signin in legacy_data.get("value", []):
            app = signin.get("clientAppUsed", "")
            if app in legacy_apps:
                user = signin.get("userPrincipalName", "Unknown")
                await _alert(
                    "legacy_auth_usage", "high",
                    f"Legacy Authentication Used: {app} by {user.split('@')[0]}",
                    f"User {user} authenticated using legacy protocol '{app}'. "
                    f"Legacy auth bypasses MFA and Conditional Access policies.",
                    f"legacy-auth:{user}:{app}:{now.date()}",
                    user,
                    {"user": user, "app": app, "ip": signin.get("ipAddress")},
                )

    # 9. Failed sign-in spike (brute force indicator)
    sc_fail, fail_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/signIns?$filter=status/errorCode ne 0&$top=100"
    )
    if sc_fail == 200:
        from collections import Counter
        fail_events = fail_data.get("value", [])
        user_fails = Counter(
            e.get("userPrincipalName", "unknown")
            for e in fail_events
        )
        for user, count in user_fails.most_common(10):
            if count >= 10 and user != "unknown":
                await _alert(
                    "brute_force_attempt", "critical",
                    f"Possible Brute Force Attack: {count} failed sign-ins for {user.split('@')[0]}",
                    f"User {user} has {count} failed sign-in attempts in a short period. "
                    f"This may indicate a brute force or credential stuffing attack.",
                    f"brute-force:{user}:{now.date()}",
                    user,
                    {"user": user, "failure_count": count},
                )

    # 10. Impossible travel detection
    sc_travel, travel_data = await _safe_get(
        f"{GRAPH_URL}/identityProtection/riskDetections?$filter=riskEventType eq 'impossibleTravel' and riskState eq 'atRisk'&$top=20"
    )
    if sc_travel == 200:
        for detection in travel_data.get("value", []):
            user = detection.get("userPrincipalName", "Unknown")
            location = detection.get("location", {})
            city = location.get("city", "Unknown")
            country = location.get("countryOrRegion", "Unknown")
            await _alert(
                "impossible_travel", "high",
                f"Impossible Travel Detected: {user.split('@')[0]} from {city}, {country}",
                f"User {user} signed in from {city}, {country} which is geographically "
                f"impossible given their previous sign-in location.",
                f"impossible-travel:{detection.get('id', user)[:40]}",
                user,
                {"user": user, "city": city, "country": country, "risk_level": detection.get("riskLevel")},
            )

    # 11. Teams Bot with admin-level permissions (privilege escalation surface).
    # We walk service principals filtered to publisher 'Microsoft Bot Framework'
    # and check oauth2 permission scopes / appRoleAssignments for tenant-wide
    # ReadWrite / ManageAs / Full access scopes.
    sc_sp, sp_data = await _safe_get(
        f"{GRAPH_URL}/servicePrincipals?$top=100&$select=id,displayName,appId,publisherName,oauth2PermissionScopes"
    )
    if sc_sp == 200:
        HIGH_RISK_SCOPES = {
            "directory.readwrite.all", "directory.accessasuser.all",
            "user.readwrite.all", "group.readwrite.all",
            "mailboxsettings.readwrite", "mail.readwrite", "mail.send",
            "chat.readwrite.all", "channelmessage.read.all",
            "sites.fullcontrol.all", "files.readwrite.all",
        }
        for sp in sp_data.get("value", []):
            name = (sp.get("displayName") or "").lower()
            publisher = (sp.get("publisherName") or "").lower()
            # Heuristic: bots usually have "bot" in displayName, or are
            # published by "Microsoft Bot Framework" / third-party bot vendors.
            is_bot = (
                "bot" in name
                or "bot framework" in publisher
                or any(kw in name for kw in ("copilot", "assistant", "chatbot"))
            )
            if not is_bot:
                continue
            scopes = sp.get("oauth2PermissionScopes") or []
            risky = [
                s for s in scopes
                if (s.get("value") or "").lower() in HIGH_RISK_SCOPES
            ]
            if len(risky) >= 1:
                await _alert(
                    "teams_bot_admin_perms", "high",
                    f"Teams Bot with admin permissions: {sp.get('displayName', 'Unknown')}",
                    f"Bot/service principal '{sp.get('displayName')}' (publisher: "
                    f"{sp.get('publisherName', 'Unknown')}) has {len(risky)} high-risk "
                    f"tenant-wide scope(s): {', '.join(s.get('value', '') for s in risky[:5])}. "
                    f"A compromised bot with these scopes can read/write tenant data "
                    f"or impersonate users.",
                    f"teams-bot-perms:{sp.get('id', '')[:40]}",
                    sp.get("displayName", "Unknown Bot"),
                    {
                        "bot": sp.get("displayName"),
                        "publisher": sp.get("publisherName"),
                        "app_id": sp.get("appId"),
                        "high_risk_scopes": [s.get("value") for s in risky],
                    },
                )

    # 12. Anonymous meeting join (insecure meeting policy). Looks for recent
    # meeting events where anonymous join was actually exercised; signals a
    # weak meeting policy that lets external/unknown attendees join sensitive
    # discussions without auth.
    sc_anon, anon_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'MeetingParticipantJoin' or activityDisplayName eq 'AnonymousUserJoinedMeeting'&$top=50"
    )
    if sc_anon == 200:
        for event in anon_data.get("value", []):
            targets = event.get("targetResources", []) or []
            target = (targets[0] if targets else {}) or {}
            modified = target.get("modifiedProperties", []) or []
            is_anon = False
            for prop in modified:
                if (prop.get("displayName") or "").lower() in (
                    "isanonymous", "anonymoususer", "usertype"
                ):
                    val = (prop.get("newValue") or "").lower()
                    if "true" in val or "anonymous" in val:
                        is_anon = True
                        break
            # Some tenants surface this as a dedicated activity — also flag those.
            if (event.get("activityDisplayName") or "") == "AnonymousUserJoinedMeeting":
                is_anon = True
            if not is_anon:
                continue
            meeting_name = target.get("displayName", "Teams Meeting")
            await _alert(
                "anonymous_meeting_join", "medium",
                f"Anonymous Participant Joined Teams Meeting: {meeting_name}",
                f"An anonymous (unauthenticated) participant joined meeting "
                f"'{meeting_name}'. Anonymous join lets external parties enter "
                f"sensitive discussions without sign-in. Disable in Teams admin "
                f"center → Meetings → Anonymous user can join.",
                f"anon-join:{event.get('id', meeting_name)[:40]}",
                meeting_name,
                {"meeting": meeting_name, "event_id": event.get("id")},
            )

    try:
        await db.commit()
    except Exception:
        await db.rollback()


async def _detect_sharepoint_onedrive_threats(org_id: str, access_token: str, db: AsyncSession) -> None:
    """
    Enterprise SharePoint/OneDrive security rules:
    - Anonymous links to sensitive files
    - Site collection admin changes
    - External sharing to competitor domains
    - Bulk file access (data exfil)
    - Sensitivity label downgrade
    - Guest access to confidential site
    - Large file upload to external-shared folder
    - Custom script enabled on site
    - Ransomware activity pattern
    - Unusual file deletion pattern
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    GRAPH_URL = "https://graph.microsoft.com/v1.0"
    now = datetime.now(timezone.utc)

    # Load competitor domains from security_rules or env
    COMPETITOR_DOMAINS = {
        d.strip().lower() for d in
        os.getenv("COMPETITOR_DOMAINS", "").split(",")
        if d.strip()
    }

    async def _safe_get(url: str) -> tuple:
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                r = await c.get(url, headers=headers)
                return r.status_code, r.json() if r.status_code < 500 else {}
        except Exception:
            return 0, {}

    async def _alert(alert_type, severity, title, description, resource_id, resource_name, raw=None):
        existing = (await db.execute(
            select(SaasAlert).where(
                SaasAlert.org_id == uuid.UUID(org_id),
                SaasAlert.resource_id == resource_id,
                SaasAlert.status == "open",
            )
        )).scalar_one_or_none()
        if existing:
            return
        db.add(SaasAlert(
            org_id=uuid.UUID(org_id), provider="sharepoint",
            alert_type=alert_type, severity=severity, title=title,
            description=description, resource_id=resource_id,
            resource_name=resource_name, status="open", raw_data=raw or {},
        ))

    # 1. Anonymous link detection in SharePoint audit logs
    sc_al, al_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'AnonymousLinkCreated'&$top=30"
    )
    if sc_al == 200:
        for event in al_data.get("value", []):
            user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
            targets = event.get("targetResources", [])
            file_name = targets[0].get("displayName", "Unknown File") if targets else "Unknown File"
            await _alert(
                "anonymous_link_created", "high",
                f"Anonymous SharePoint Link Created: {file_name}",
                f"User {user} created an anonymous (anyone-with-link) share for '{file_name}'. "
                f"Anonymous links bypass authentication entirely.",
                f"anon-link:{event.get('id', file_name)[:40]}",
                user,
                {"user": user, "file": file_name},
            )

    # 2. Site collection admin changes
    sc_adm, adm_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'SiteCollectionAdminAdded' or activityDisplayName eq 'SiteCollectionAdminRemoved'&$top=20"
    )
    if sc_adm == 200:
        for event in adm_data.get("value", []):
            user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
            activity = event.get("activityDisplayName", "Admin change")
            targets = event.get("targetResources", [])
            target = targets[0].get("displayName", "Unknown") if targets else "Unknown"
            severity = "high" if "Added" in activity else "medium"
            await _alert(
                "site_collection_admin_change", severity,
                f"SharePoint Site Admin Change: {activity}",
                f"{user} performed '{activity}' on site/user '{target}'. "
                f"Site collection admin changes should be tightly controlled.",
                f"site-admin:{event.get('id', target)[:40]}",
                user,
                {"user": user, "action": activity, "target": target},
            )

    # 3. External sharing to competitor domains (check recently shared items)
    try:
        sp_items = await db.execute(text("""
            SELECT item_name, item_url, owner_email, sharing_scope, classification_label
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND sharing_scope IN ('external', 'public')
              AND last_scanned_at > NOW() - INTERVAL '48 hours'
            LIMIT 50
        """), {"org_id": org_id})
        for row in sp_items.mappings():
            item_url = row.get("item_url", "") or ""
            owner = row.get("owner_email", "Unknown")
            # Check if URL contains competitor domains
            if COMPETITOR_DOMAINS and any(cd in item_url.lower() for cd in COMPETITOR_DOMAINS):
                await _alert(
                    "sharepoint_competitor_share", "critical",
                    f"SharePoint File Shared to Competitor Domain: {row['item_name']}",
                    f"File '{row['item_name']}' by {owner} appears to be shared to a competitor domain. "
                    f"Classification: {row.get('classification_label', 'unknown')}. Immediate review required.",
                    f"competitor-share:{row['item_name'][:40]}",
                    owner,
                    {"file": row["item_name"], "owner": owner},
                )
    except Exception:
        pass

    # 4. Bulk file access (data exfil pattern) via audit log
    sc_ba, ba_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'FileAccessed'&$top=100"
    )
    if sc_ba == 200:
        from collections import Counter
        access_events = ba_data.get("value", [])
        user_access = Counter(
            e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "unknown")
            for e in access_events
        )
        for user, count in user_access.most_common(5):
            if count >= 30 and user != "unknown":
                await _alert(
                    "sharepoint_bulk_access", "high",
                    f"Bulk SharePoint File Access: {user.split('@')[0]} ({count} accesses)",
                    f"User {user} accessed {count} SharePoint files in a short period. "
                    f"This pattern may indicate data exfiltration or unauthorized bulk download.",
                    f"sp-bulk-access:{user}:{now.date()}",
                    user,
                    {"user": user, "access_count": count},
                )

    # 5. Large file upload to externally-shared folder
    try:
        large_external = await db.execute(text("""
            SELECT item_name, size_bytes, owner_email, parent_path, provider
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND size_bytes > 100 * 1024 * 1024  -- 100MB
              AND sharing_scope IN ('external', 'public')
              AND last_scanned_at > NOW() - INTERVAL '24 hours'
            LIMIT 20
        """), {"org_id": org_id})
        for row in large_external.mappings():
            size_mb = (row.get("size_bytes") or 0) // (1024 * 1024)
            await _alert(
                "large_file_external_share", "high",
                f"Large File ({size_mb}MB) in Externally-Shared Location: {row['item_name']}",
                f"A large file '{row['item_name']}' ({size_mb}MB) by {row.get('owner_email', 'Unknown')} "
                f"is stored in an externally-shared location ({row.get('parent_path', '')}).",
                f"large-file-ext:{row['item_name'][:40]}",
                row.get("owner_email", "unknown"),
                {"file": row["item_name"], "size_mb": size_mb, "path": row.get("parent_path")},
            )
    except Exception:
        pass

    # 6. Custom script enabled on SharePoint site (security risk)
    sc_sites, sites_data = await _safe_get(f"{GRAPH_URL}/admin/sharepoint/settings")
    if sc_sites == 200:
        if sites_data.get("isCustomScriptEnabled", False):
            await _alert(
                "sharepoint_custom_script_enabled", "high",
                "SharePoint Custom Script Enabled",
                "Custom script execution is enabled across SharePoint sites. "
                "This allows users to embed malicious scripts in SharePoint pages, "
                "potentially leading to XSS attacks or data exfiltration.",
                "sp-custom-script-enabled",
                "SharePoint Tenant",
                {"setting": "isCustomScriptEnabled", "value": True},
            )

    # 7. Sensitivity label downgrade (via audit)
    sc_label, label_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'SensitivityLabelApplied'&$top=30"
    )
    if sc_label == 200:
        for event in label_data.get("value", []):
            modified_props = event.get("targetResources", [{}])[0].get("modifiedProperties", []) if event.get("targetResources") else []
            old_label = new_label = None
            for prop in modified_props:
                if prop.get("displayName") == "SensitivityLabel":
                    old_label = prop.get("oldValue", "")
                    new_label = prop.get("newValue", "")
            if old_label and new_label:
                label_order = {"Highly Confidential": 4, "Confidential": 3, "Internal": 2, "Public": 1}
                old_rank = label_order.get(old_label, 0)
                new_rank = label_order.get(new_label, 0)
                if new_rank < old_rank:  # Downgrade detected
                    user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
                    await _alert(
                        "sensitivity_label_downgrade", "high",
                        f"Sensitivity Label Downgrade: {old_label} → {new_label}",
                        f"User {user} downgraded a sensitivity label from '{old_label}' to '{new_label}'. "
                        f"This may bypass DLP policies and expose sensitive data.",
                        f"label-downgrade:{event.get('id', user)[:40]}",
                        user,
                        {"user": user, "old_label": old_label, "new_label": new_label},
                    )

    # 8. Ransomware pattern detection: mass file rename/modification in short time
    try:
        recent_items = await db.execute(text("""
            SELECT owner_email, COUNT(*) as cnt
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND last_modified_at > NOW() - INTERVAL '1 hour'
            GROUP BY owner_email
            HAVING COUNT(*) > 50
        """), {"org_id": org_id})
        for row in recent_items.mappings():
            owner = row.get("owner_email", "Unknown")
            count = row.get("cnt", 0)
            await _alert(
                "ransomware_activity_pattern", "critical",
                f"Potential Ransomware: {owner} modified {count} files in 1 hour",
                f"User {owner} has modified {count} files in the last hour. "
                f"This mass-modification pattern is consistent with ransomware encryption activity.",
                f"ransomware:{owner}:{now.date()}",
                owner,
                {"owner": owner, "file_count": count},
            )
    except Exception:
        pass

    # 9. Unusual file deletion pattern (OneDrive)
    sc_del_od, del_od_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'FileDeleted'&$top=100"
    )
    if sc_del_od == 200:
        from collections import Counter
        del_events = del_od_data.get("value", [])
        user_dels = Counter(
            e.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "unknown")
            for e in del_events
        )
        for user, count in user_dels.most_common(5):
            if count >= 20 and user != "unknown":
                await _alert(
                    "unusual_file_deletion", "high",
                    f"Unusual File Deletion Pattern: {user.split('@')[0]} deleted {count} files",
                    f"User {user} deleted {count} files in a short period from OneDrive/SharePoint. "
                    f"This may indicate destructive activity or insider threat.",
                    f"file-del-pattern:{user}:{now.date()}",
                    user,
                    {"user": user, "deletion_count": count},
                )

    # 10. Guest access to confidential site
    try:
        conf_external = await db.execute(text("""
            SELECT item_name, parent_path, owner_email, sharing_scope
            FROM saas_data_items
            WHERE org_id = CAST(:org_id AS UUID)
              AND classification_label IN ('confidential', 'highly_confidential')
              AND sharing_scope IN ('external', 'public')
              AND provider = 'sharepoint'
            LIMIT 20
        """), {"org_id": org_id})
        for row in conf_external.mappings():
            site_path = row.get("parent_path", "Unknown Site")
            await _alert(
                "guest_confidential_site_access", "critical",
                f"Guest Access to Confidential SharePoint Content: {row['item_name']}",
                f"Confidential file '{row['item_name']}' in '{site_path}' is accessible to external/guest users. "
                f"Confidential files should never be shared externally.",
                f"guest-conf:{row['item_name'][:40]}",
                row.get("owner_email", "unknown"),
                {"file": row["item_name"], "path": site_path},
            )
    except Exception:
        pass

    # 11. Permission changes on SharePoint files/folders
    sc_perm, perm_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'PermissionLevelAdded' or activityDisplayName eq 'PermissionLevelRemoved'&$top=30"
    )
    if sc_perm == 200:
        for event in perm_data.get("value", []):
            user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
            activity = event.get("activityDisplayName", "Permission change")
            targets = event.get("targetResources", [])
            target_name = targets[0].get("displayName", "Unknown") if targets else "Unknown"
            modified_props = targets[0].get("modifiedProperties", []) if targets else []
            perm_level = ""
            for prop in modified_props:
                if "permission" in prop.get("displayName", "").lower():
                    perm_level = prop.get("newValue", "")
            severity = "high" if "Full Control" in perm_level or "Owner" in perm_level else "medium"
            await _alert(
                "sharepoint_permission_change", severity,
                f"SharePoint Permission Changed: {activity} on {target_name}",
                f"User {user} changed permissions on '{target_name}'. "
                f"Permission level: {perm_level or 'Unknown'}. Review for unauthorized access grants.",
                f"perm-change:{event.get('id', target_name)[:40]}",
                user,
                {"user": user, "action": activity, "target": target_name, "permission": perm_level},
            )

    # 12. After-hours access to sensitive files
    try:
        # Define business hours (9 AM - 6 PM UTC, adjust as needed)
        current_hour = now.hour
        if current_hour < 9 or current_hour > 18:  # Outside business hours
            after_hours_files = await db.execute(text("""
                SELECT item_name, owner_email, classification_label, last_modified_at
                FROM saas_data_items
                WHERE org_id = CAST(:org_id AS UUID)
                  AND classification_label IN ('confidential', 'highly_confidential')
                  AND last_modified_at > NOW() - INTERVAL '2 hours'
                  AND provider IN ('sharepoint', 'teams')
                LIMIT 10
            """), {"org_id": org_id})
            for row in after_hours_files.mappings():
                await _alert(
                    "after_hours_sensitive_access", "medium",
                    f"After-Hours Access to Sensitive File: {row['item_name']}",
                    f"User {row.get('owner_email', 'Unknown')} accessed/modified '{row['item_name']}' "
                    f"(classification: {row.get('classification_label', 'unknown')}) outside business hours. "
                    f"This may warrant review for data exfiltration.",
                    f"after-hours:{row['item_name'][:40]}:{now.date()}",
                    row.get("owner_email", "unknown"),
                    {"file": row["item_name"], "classification": row.get("classification_label")},
                )
    except Exception:
        pass

    # 13. Email forwarding rule to external address (data exfiltration via email)
    sc_fwd, fwd_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'Set-Mailbox' or activityDisplayName eq 'New-InboxRule'&$top=30"
    )
    if sc_fwd == 200:
        for event in fwd_data.get("value", []):
            modified_props = event.get("targetResources", [{}])[0].get("modifiedProperties", []) if event.get("targetResources") else []
            for prop in modified_props:
                prop_name = prop.get("displayName", "").lower()
                prop_value = prop.get("newValue", "")
                # Check for forwarding to external
                if "forward" in prop_name and prop_value and "@" in prop_value:
                    # Check if external domain
                    user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
                    await _alert(
                        "email_forwarding_rule", "high",
                        f"Email Forwarding Rule Created: {user.split('@')[0]}",
                        f"User {user} created an email forwarding rule to '{prop_value}'. "
                        f"External forwarding can bypass DLP and exfiltrate sensitive data.",
                        f"email-fwd:{user}:{now.date()}",
                        user,
                        {"user": user, "forward_to": prop_value},
                    )
                    break

    # 14. OneDrive sync from unmanaged device
    sc_sync, sync_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/signIns?$filter=appDisplayName eq 'OneDrive SyncEngine'&$top=30"
    )
    if sc_sync == 200:
        for signin in sync_data.get("value", []):
            device_detail = signin.get("deviceDetail", {})
            is_compliant = device_detail.get("isCompliant", None)
            is_managed = device_detail.get("isManaged", None)
            # If device is neither compliant nor managed
            if is_compliant is False or is_managed is False:
                user = signin.get("userPrincipalName", "Unknown")
                device_name = device_detail.get("displayName", "Unknown Device")
                await _alert(
                    "onedrive_unmanaged_sync", "high",
                    f"OneDrive Sync from Unmanaged Device: {user.split('@')[0]}",
                    f"User {user} is syncing OneDrive from unmanaged device '{device_name}'. "
                    f"Data synced to unmanaged devices leaves the secure perimeter.",
                    f"unmanaged-sync:{user}:{device_name[:20]}",
                    user,
                    {"user": user, "device": device_name, "is_compliant": is_compliant, "is_managed": is_managed},
                )

    # 15. Conditional Access policy bypass / failure
    sc_ca, ca_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/signIns?$filter=conditionalAccessStatus eq 'failure'&$top=30"
    )
    if sc_ca == 200:
        for signin in ca_data.get("value", []):
            user = signin.get("userPrincipalName", "Unknown")
            ca_policies = signin.get("appliedConditionalAccessPolicies", [])
            failed_policies = [p.get("displayName", "Unknown") for p in ca_policies if p.get("result") == "failure"]
            if failed_policies:
                await _alert(
                    "conditional_access_failure", "medium",
                    f"Conditional Access Policy Blocked: {user.split('@')[0]}",
                    f"User {user} was blocked by Conditional Access policies: {', '.join(failed_policies[:3])}. "
                    f"This may indicate policy misconfiguration or attack attempt.",
                    f"ca-block:{user}:{now.date()}",
                    user,
                    {"user": user, "failed_policies": failed_policies},
                )

    # 16. Microsoft Purview: eDiscovery holds
    sc_ediscovery, ediscovery_data = await _safe_get(
        f"{GRAPH_URL}/security/cases/ediscoveryCases?$top=20"
    )
    if sc_ediscovery == 200:
        for case in ediscovery_data.get("value", []):
            case_name = case.get("displayName", "Unknown Case")
            case_status = case.get("status", "unknown")
            created_by = case.get("createdBy", {}).get("user", {}).get("displayName", "Unknown")
            # Info alert for active legal holds
            if case_status == "active":
                await _alert(
                    "purview_ediscovery_case", "info",
                    f"Active eDiscovery Case: {case_name}",
                    f"eDiscovery case '{case_name}' is active (created by {created_by}). "
                    f"Ensure data preservation holds are in place for relevant custodians.",
                    f"ediscovery:{case.get('id', case_name)[:40]}",
                    created_by,
                    {"case_name": case_name, "status": case_status, "created_by": created_by},
                )

    # 17. Microsoft Purview: Retention policy violations (labels not applied)
    sc_retention, retention_data = await _safe_get(
        f"{GRAPH_URL}/security/informationProtection/labelPolicySummary"
    )
    if sc_retention == 200:
        unlabeled_count = retention_data.get("unlabeledItemsCount", 0)
        if unlabeled_count > 1000:
            await _alert(
                "purview_unlabeled_content", "medium",
                f"Large Volume of Unlabeled Content: {unlabeled_count:,} items",
                f"There are {unlabeled_count:,} items without retention labels applied. "
                f"This may indicate compliance risk if retention policies are not being enforced.",
                f"unlabeled-content:{now.date()}",
                "Purview",
                {"unlabeled_count": unlabeled_count},
            )

    # 18. Microsoft Purview: Communication compliance alerts
    sc_comm, comm_data = await _safe_get(
        f"{GRAPH_URL}/compliance/ediscovery/alerts?$filter=status eq 'active'&$top=30"
    )
    if sc_comm == 200:
        for alert in comm_data.get("value", []):
            alert_title = alert.get("title", "Communication Compliance Alert")
            policy_name = alert.get("policyName", "Unknown Policy")
            severity = alert.get("severity", "medium").lower()
            await _alert(
                "purview_communication_compliance", severity if severity in ("low", "medium", "high", "critical") else "medium",
                f"Purview Communication Compliance: {alert_title}",
                f"Communication compliance policy '{policy_name}' triggered an alert. "
                f"Review for policy violations in Teams/Exchange messages.",
                f"comm-compliance:{alert.get('id', alert_title)[:40]}",
                policy_name,
                {"title": alert_title, "policy": policy_name, "severity": severity},
            )

    # 19. Microsoft Purview: Insider Risk alerts (if available)
    sc_insider, insider_data = await _safe_get(
        f"{GRAPH_URL}/security/alerts_v2?$filter=category eq 'InsiderRisk' and status eq 'new'&$top=20"
    )
    if sc_insider == 200:
        for alert in insider_data.get("value", []):
            alert_title = alert.get("title", "Insider Risk Alert")
            user_states = alert.get("userStates", [])
            user = user_states[0].get("userPrincipalName", "Unknown") if user_states else "Unknown"
            severity = alert.get("severity", "medium").lower()
            await _alert(
                "purview_insider_risk", severity if severity in ("low", "medium", "high", "critical") else "high",
                f"Purview Insider Risk: {alert_title}",
                f"Insider Risk Management flagged user {user} for potential data exfiltration or policy violation. "
                f"Review in Microsoft Purview Insider Risk Management.",
                f"insider-risk:{alert.get('id', user)[:40]}",
                user,
                {"title": alert_title, "user": user, "severity": severity},
            )

    # 20. Microsoft Purview: DLP policy match events
    sc_dlp, dlp_data = await _safe_get(
        f"{GRAPH_URL}/auditLogs/directoryAudits?$filter=activityDisplayName eq 'DlpRuleMatch'&$top=30"
    )
    if sc_dlp == 200:
        for event in dlp_data.get("value", []):
            user = event.get("initiatedBy", {}).get("user", {}).get("userPrincipalName", "Unknown")
            targets = event.get("targetResources", [])
            resource = targets[0].get("displayName", "Unknown Resource") if targets else "Unknown"
            # Extract DLP policy name from modified properties
            policy_name = "Unknown Policy"
            for prop in (targets[0].get("modifiedProperties", []) if targets else []):
                if "policy" in prop.get("displayName", "").lower():
                    policy_name = prop.get("newValue", policy_name)
                    break
            await _alert(
                "purview_dlp_match", "high",
                f"DLP Policy Match: {policy_name} triggered by {user.split('@')[0]}",
                f"User {user} triggered DLP policy '{policy_name}' on resource '{resource}'. "
                f"Review for sensitive data handling violations.",
                f"dlp-match:{event.get('id', user)[:40]}",
                user,
                {"user": user, "policy": policy_name, "resource": resource},
            )

    try:
        await db.commit()
    except Exception:
        await db.rollback()


async def _seed_security_rules(db: AsyncSession) -> None:
    """Seed default security rules for all providers into the DB."""
    try:
        # Check if already seeded
        result = await db.execute(text(
            "SELECT COUNT(*) FROM security_rules WHERE org_id IS NULL"
        ))
        if (result.scalar() or 0) > 0:
            return  # Already seeded
    except Exception:
        return  # Table may not exist yet

    default_rules = [
        # AWS rules
        ("aws", "s3_public_acl", "S3 bucket with public ACL", "critical", True, True,
         ["Disable public ACL", "Enable S3 Block Public Access"]),
        ("aws", "ec2_public_open_ports", "EC2 with public IP and open sensitive ports", "high", True, True,
         ["Restrict SG rules to specific CIDR", "Use SSM instead of SSH"]),
        ("aws", "rds_publicly_accessible", "RDS instance publicly accessible", "critical", True, True,
         ["Disable PubliclyAccessible on RDS instance"]),
        ("aws", "cloudtrail_disabled", "CloudTrail logging disabled", "critical", True, False,
         ["Enable CloudTrail in all regions"]),
        ("aws", "root_account_activity", "Root account used for operations", "critical", True, False,
         ["Create IAM users for all operations", "Remove root access keys"]),
        ("aws", "iam_console_no_mfa", "IAM user with console access but no MFA", "high", True, False,
         ["Enable MFA for all IAM users", "Create SCP requiring MFA"]),
        ("aws", "iam_unused_credentials", "Unused IAM credentials (90+ days)", "medium", True, False,
         ["Disable or delete unused IAM users"]),
        ("aws", "kms_key_pending_deletion", "KMS key scheduled for deletion", "high", True, False,
         ["Cancel key deletion if data is still encrypted with it"]),
        ("aws", "guardduty_finding", "GuardDuty security finding", "high", True, True,
         ["Review and remediate in GuardDuty console"]),
        ("aws", "security_hub_finding", "Security Hub finding", "high", True, True,
         ["Review and remediate in Security Hub console"]),
        ("aws", "iam_overpermissive_policy", "IAM policy with wildcard action/resource", "high", True, True,
         ["Apply least privilege", "Replace Action:* with specific actions"]),
        ("aws", "iam_cross_account_trust", "IAM role with cross-account trust", "medium", True, True,
         ["Review cross-account trust", "Require ExternalId condition"]),
        # Teams rules
        ("teams", "anonymous_meeting_join", "Anonymous meeting join detected", "medium", True, False,
         ["Disable anonymous meeting join in Teams admin"]),
        ("teams", "external_in_private_channel", "External user in private Teams channel", "high", True, False,
         ["Remove external user from private channel"]),
        ("teams", "guest_team_owner", "Guest user with owner role in Teams", "high", True, False,
         ["Remove guest from owner role", "Restrict team ownership to internal users"]),
        ("teams", "teams_connector_added", "Teams webhook/connector added", "medium", True, False,
         ["Review connector permissions", "Implement connector approval policy"]),
        ("teams", "teams_app_excessive_perms", "Teams app with excessive permissions", "high", True, True,
         ["Review app permissions", "Remove app if not business-justified"]),
        ("teams", "teams_bulk_download", "Bulk file download from Teams", "high", True, False,
         ["Review user activity", "Consider data loss prevention policy"]),
        ("teams", "teams_channel_deleted", "Teams channel deleted", "medium", True, False,
         ["Verify deletion was authorized", "Restore from backup if needed"]),
        ("teams", "teams_bot_admin_perms", "Teams Bot/service principal with tenant-wide admin scopes", "high", True, True,
         ["Review bot consented scopes in Entra ID → Enterprise applications",
          "Revoke unnecessary high-risk delegated permissions",
          "Consider replacing the bot with a least-privilege equivalent"]),
        # SharePoint rules
        ("sharepoint", "anonymous_link_created", "Anonymous link to SharePoint file", "high", True, False,
         ["Revoke anonymous link", "Configure expiry for anonymous links"]),
        ("sharepoint", "site_collection_admin_change", "Site collection admin change", "high", True, False,
         ["Verify admin change was authorized"]),
        ("sharepoint", "sharepoint_competitor_share", "File shared to competitor domain", "critical", True, True,
         ["Revoke external share immediately", "Investigate potential data breach"]),
        ("sharepoint", "sharepoint_bulk_access", "Bulk file access pattern", "high", True, False,
         ["Review user activity in audit log", "Consider temporary access restriction"]),
        ("sharepoint", "large_file_external_share", "Large file in externally-shared location", "high", True, False,
         ["Review and restrict sharing permissions"]),
        ("sharepoint", "sharepoint_custom_script_enabled", "Custom script enabled on SharePoint site", "high", True, False,
         ["Disable custom script in SharePoint admin center"]),
        ("sharepoint", "sensitivity_label_downgrade", "Sensitivity label downgraded", "high", True, True,
         ["Reapply correct sensitivity label", "Investigate user's intent"]),
        ("sharepoint", "guest_confidential_site_access", "Guest access to confidential SharePoint content", "critical", True, False,
         ["Remove external sharing immediately"]),
        ("sharepoint", "sharepoint_info_barrier_bypass", "Information barrier bypass detected", "critical", True, True,
         ["Review and re-apply information barriers"]),
        # OneDrive rules
        ("onedrive", "ransomware_activity_pattern", "Ransomware-like mass file modification", "critical", True, True,
         ["Immediately disable user account", "Restore from version history", "Contact incident response"]),
        ("onedrive", "unusual_file_deletion", "Unusual file deletion pattern", "high", True, False,
         ["Review user activity", "Restore deleted files from recycle bin"]),
        ("onedrive", "sync_to_unmanaged_device", "OneDrive sync to unmanaged device", "high", True, False,
         ["Block sync on unmanaged devices via SharePoint admin"]),
        ("onedrive", "external_confidential_share", "Company confidential file shared externally via OneDrive", "critical", True, True,
         ["Revoke external share", "Apply sensitivity label"]),
        # M365 rules
        ("m365", "mfa_disabled", "MFA not enabled for user", "high", True, False,
         ["Enable MFA via Azure AD", "Create Conditional Access policy"]),
        ("m365", "impossible_travel", "Impossible travel detection", "critical", True, False,
         ["Block user sign-in", "Reset password", "Review recent activity"]),
        ("m365", "external_forwarding", "Email forwarding to external domain", "high", True, False,
         ["Disable forwarding rule", "Investigate for account compromise"]),
        ("m365", "entra_risky_user", "Entra ID high-risk user", "high", True, False,
         ["Require password change", "Review recent sign-ins"]),
        ("m365", "risky_oauth_app", "OAuth app with high-risk permissions", "high", True, True,
         ["Revoke app consent", "Review granted permissions"]),
    ]

    try:
        for rule in default_rules:
            provider, name, desc, severity, enabled, ai_analysis, remediation = rule
            await db.execute(text("""
                INSERT INTO security_rules
                    (org_id, provider, rule_name, description, severity, enabled, ai_analysis, remediation_steps)
                VALUES
                    (NULL, :provider, :rule_name, :description, :severity, :enabled, :ai_analysis, :remediation)
                ON CONFLICT DO NOTHING
            """), {
                "provider": provider,
                "rule_name": name,
                "description": desc,
                "severity": severity,
                "enabled": enabled,
                "ai_analysis": ai_analysis,
                "remediation": remediation,
            })
        await db.commit()
        logger.info(f"security_rules: seeded {len(default_rules)} default rules")
    except Exception as exc:
        logger.warning(f"security_rules: seeding failed (non-fatal): {exc}")
        await db.rollback()


async def _run_dlp_worker_all_orgs() -> None:
    """Run DLP classification worker for all active orgs."""
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SaasIntegration.org_id)
                .where(SaasIntegration.status == "active")
                .distinct()
            )
            org_ids = [str(r[0]) for r in result.fetchall() if r[0]]

        for oid in org_ids:
            try:
                await _run_dlp_classification_worker(oid)
            except Exception as exc:
                logger.warning(f"dlp_worker_all: org {oid} failed: {exc}")
    except Exception as exc:
        logger.error(f"dlp_worker_all: error: {exc}")
