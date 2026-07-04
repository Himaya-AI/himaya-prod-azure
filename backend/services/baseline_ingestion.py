"""
Real email baseline ingestion — M365 (Microsoft Graph API) + Google Workspace (Gmail API).

Flow per org:
  1. Detect which providers are connected (m365 / google)
  2. For each provider: list all mailboxes
  3. For each mailbox: fetch last 90 days of email metadata in batches
  4. For each email: extract sender→recipient edges, build communication graph in Neo4j
  5. Track progress in Redis so the UI can show a progress bar
  6. Store aggregate stats (frequency, first_seen, last_seen) in PostgreSQL

This runs as a background task triggered on onboarding completion.
"""

import asyncio
import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text

from backend.database import AsyncSessionLocal
from backend.models.db_models import OrgIntegration, Organization, User
from backend.services.graph_service import graph_service

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


async def _upsert_directory_users(db: AsyncSession, org_id: str, users: list, provider: str,
                                    aliases_count: int = 0, shared_count: int = 0):
    """Upsert directory users, deactivate removed users, update per-provider counts."""
    if not users:
        return

    active_emails = set()
    for u in users:
        email = u.get("primaryEmail") or u.get("mail") or u.get("userPrincipalName", "")
        name = u.get("displayName") or u.get("name", {}).get("fullName") or email.split("@")[0]
        if not email:
            continue
        email = email.lower()
        active_emails.add(email)
        existing = await db.execute(select(User).where(User.org_id == org_id, User.email == email))
        user_row = existing.scalar_one_or_none()
        if user_row:
            user_row.name = name
            user_row.is_active = not u.get("suspended", False)
            if not user_row.directory_provider:
                user_row.directory_provider = provider
        else:
            db.add(User(
                org_id=org_id,
                email=email,
                name=name,
                role="user",
                is_active=not u.get("suspended", False),
                directory_provider=provider,
            ))

    # Deactivate users removed from this provider's directory
    # Scoped strictly to users enrolled by THIS provider to prevent cross-provider deactivation
    if active_emails:
        all_users_result = await db.execute(
            select(User).where(
                User.org_id == org_id,
                User.role == "user",
                User.is_active == True,
                User.directory_provider == provider,
            )
        )
        for stale in all_users_result.scalars().all():
            if stale.email.lower() not in active_emails:
                logger.info(f"Deactivating removed user {stale.email} (not in {provider} directory)")
                stale.is_active = False

    # Update per-provider OrgIntegration counts (guarded — columns added via migration)
    try:
        await db.execute(
            text("""UPDATE org_integrations
                    SET mailbox_count = :mc, aliases_count = :ac, shared_count = :sc, updated_at = NOW()
                    WHERE org_id = :oid AND provider = :prov"""),
            {"mc": len(active_emails), "ac": aliases_count, "sc": shared_count,
             "oid": org_id, "prov": provider},
        )
        await db.execute(
            text("""UPDATE organizations SET mailbox_count = (
                      SELECT COALESCE(SUM(mailbox_count),0) FROM org_integrations
                      WHERE org_id = :oid AND status = 'active'
                    ) WHERE id = :oid"""),
            {"oid": org_id},
        )
        await db.commit()
    except Exception as _ue:
        logger.warning(f"_upsert_directory_users OrgIntegration update failed (non-fatal): {_ue}")
        await db.rollback()
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
ADMIN_API_BASE = "https://admin.googleapis.com/admin/directory/v1"

# Batch sizes
M365_BATCH_SIZE = 100        # Graph API $top max
GMAIL_BATCH_SIZE = 100       # Gmail messages.list maxResults
DAYS_LOOKBACK = 90


async def run_baseline_ingestion(org_id: str, mailbox_count: int = 50):
    """
    Entry point. Auto-detects connected providers and runs ingestion for each.
    Called from /api/onboarding/baseline/start as a background task.
    """
    redis = aioredis.from_url(REDIS_URL)
    await redis.set(f"baseline:{org_id}:status", "running", ex=7200)
    await redis.set(f"baseline:{org_id}:progress", 1, ex=7200)   # 1% immediately so UI shows activity
    await redis.set(f"baseline:{org_id}:emails_processed", 0, ex=7200)
    await redis.delete(f"baseline:{org_id}:error")

    total_emails = 0

    try:
        async with AsyncSessionLocal() as db:
            # Get connected integrations
            result = await db.execute(
                select(OrgIntegration).where(
                    OrgIntegration.org_id == org_id,
                    OrgIntegration.status == "active",
                )
            )
            integrations = result.scalars().all()

            if not integrations:
                logger.warning(f"No active integrations for org {org_id}")
                await redis.set(f"baseline:{org_id}:status", "no_integrations", ex=3600)
                return

            total_providers = len(integrations)
            # Snapshot integration data before loop — each provider gets its own session
            # to prevent a failed transaction from poisoning subsequent providers
            integration_snapshots = [
                {
                    "provider": i.provider,
                    "access_token": _decrypt(i.access_token_enc),
                    "refresh_token": _decrypt(i.refresh_token_enc),
                    "scope_group_id": i.scope_group_id,
                }
                for i in integrations
            ]

        # Close the outer session — each provider runs in its own isolated session
        for idx, snap in enumerate(integration_snapshots):
            provider_base = idx / total_providers
            provider_share = 1.0 / total_providers

            try:
                async with AsyncSessionLocal() as pdb:
                    if snap["provider"] == "m365":
                        count = await _ingest_m365(
                            org_id=org_id,
                            access_token=snap["access_token"],
                            refresh_token=snap["refresh_token"],
                            db=pdb,
                            redis=redis,
                            progress_base=provider_base,
                            progress_share=provider_share,
                            scope_group_id=snap["scope_group_id"] or None,
                        )
                    elif snap["provider"] == "google":
                        org_result = await pdb.execute(
                            select(Organization).where(Organization.id == org_id)
                        )
                        org = org_result.scalar_one_or_none()
                        domain = org.domain if org else ""
                        count = await _ingest_google(
                            org_id=org_id,
                            domain=domain,
                            access_token=snap["access_token"],
                            refresh_token=snap["refresh_token"],
                            db=pdb,
                            redis=redis,
                            progress_base=provider_base,
                            progress_share=provider_share,
                            scope_group_id=snap["scope_group_id"] or None,
                        )
                    else:
                        count = 0
            except Exception as _pe:
                logger.error(f"Baseline failed for provider {snap['provider']}: {_pe}")
                count = 0

            total_emails += count

        await redis.set(f"baseline:{org_id}:progress", 100, ex=30*24*3600)
        await redis.set(f"baseline:{org_id}:status", "complete", ex=30*24*3600)
        await redis.set(f"baseline:{org_id}:emails_processed", total_emails, ex=30*24*3600)
        logger.info(f"Baseline complete for org {org_id}: {total_emails} emails processed")

    except Exception as e:
        logger.error(f"Baseline ingestion failed for org {org_id}: {e}", exc_info=True)
        await redis.set(f"baseline:{org_id}:status", "failed", ex=3600)
        await redis.set(f"baseline:{org_id}:error", str(e), ex=3600)
    finally:
        await redis.aclose()


# ─────────────────────────────────────────────────────────────────────────────
# M365 — Microsoft Graph API
# ─────────────────────────────────────────────────────────────────────────────

async def _ingest_m365(
    org_id: str,
    access_token: str,
    refresh_token: str,
    db: AsyncSession,
    redis,
    progress_base: float,
    progress_share: float,
    scope_group_id: str | None = None,
) -> int:
    """Fetch 90 days of mail metadata for all M365 mailboxes."""

    if access_token in ("demo_access_token", ""):
        logger.warning(f"M365 demo token for org {org_id} — skipping real ingestion")
        return await _run_simulated_baseline(org_id, 50, redis, progress_base, progress_share)

    headers = {"Authorization": f"Bearer {access_token}"}
    since_date = (datetime.now(timezone.utc) - timedelta(days=DAYS_LOOKBACK)).strftime("%Y-%m-%dT%H:%M:%SZ")
    total = 0

    async with httpx.AsyncClient(timeout=30) as client:
        # Step 1: list mailbox users (scoped to group if configured)
        users = await _m365_list_users(client, headers, org_id, scope_group_id=scope_group_id)
        if not users:
            logger.warning(f"No M365 users found for org {org_id}")
            return 0

        total_users = len(users)
        logger.info(f"M365 baseline: {total_users} mailboxes for org {org_id}")

        # Count M365 aliases (proxyAddresses) and shared mailboxes
        m365_aliases = sum(
            len([a for a in u.get("proxyAddresses", []) if a.lower().startswith("smtp:") and not a.startswith("SMTP:")])
            for u in users
        )
        m365_shared = sum(1 for u in users if u.get("userType", "Member") == "Member" and
                          not u.get("assignedLicenses") and u.get("mail"))

        # Also fetch M365 groups (distribution lists + M365 groups) in isolated session
        try:
            _grp_resp = await client.get(
                f"{GRAPH_API_BASE}/groups?$select=id,mail,displayName,description,groupTypes&$top=200",
                headers=headers,
            )
            if _grp_resp.status_code == 200:
                _grps = [g for g in _grp_resp.json().get("value", []) if g.get("mail")]
                if _grps:
                    from backend.database import AsyncSessionLocal as _GASL
                    async with _GASL() as _gdb:
                        try:
                            await _upsert_directory_groups(_gdb, org_id, [
                                {"id": g["id"], "email": g["mail"], "name": g["displayName"],
                                 "description": g.get("description", "")} for g in _grps
                            ], "m365")
                            await _gdb.execute(
                                text("UPDATE org_integrations SET groups_count = :gc WHERE org_id = :oid AND provider = 'm365'"),
                                {"gc": len(_grps), "oid": org_id},
                            )
                            await _gdb.commit()
                            logger.info(f"Upserted {len(_grps)} M365 groups for org {org_id}")
                        except Exception as _ge2:
                            await _gdb.rollback()
                            logger.warning(f"M365 groups DB write failed (non-fatal): {_ge2}")
        except Exception as _ge:
            logger.warning(f"M365 groups fetch failed (non-fatal): {_ge}")

        # Save directory users to DB with alias/shared counts
        await _upsert_directory_users(db, org_id, users, "m365",
                                       aliases_count=m365_aliases, shared_count=m365_shared)
        await redis.set(f"baseline:{org_id}:m365:status", "running", ex=7200)
        await redis.set(f"baseline:{org_id}:m365:mailboxes", total_users, ex=30*24*3600)

        for u_idx, user in enumerate(users):
            user_email = user.get("mail") or user.get("userPrincipalName", "")
            if not user_email:
                continue

            # Fetch messages for this user
            url = (
                f"{GRAPH_API_BASE}/users/{user_email}/messages"
                f"?$select=id,sender,toRecipients,receivedDateTime,subject,hasAttachments,internetMessageId"
                f"&$filter=receivedDateTime ge {since_date}"
                f"&$top={M365_BATCH_SIZE}&$orderby=receivedDateTime desc"
            )

            page_count = 0
            while url and page_count < 50:  # Max 50 pages = 5,000 emails per mailbox
                try:
                    resp = await client.get(url, headers=headers)

                    if resp.status_code == 401:
                        # Token expired — try refresh
                        new_token = await _refresh_m365_token(refresh_token)
                        if new_token:
                            access_token = new_token
                            headers = {"Authorization": f"Bearer {access_token}"}
                            resp = await client.get(url, headers=headers)
                        else:
                            break

                    if resp.status_code != 200:
                        logger.warning(f"M365 messages failed for {user_email}: {resp.status_code}")
                        break

                    data = resp.json()
                    messages = data.get("value", [])

                    for msg in messages:
                        sender_addr = _extract_m365_sender(msg)
                        recipients = _extract_m365_recipients(msg)
                        received_at = msg.get("receivedDateTime", "")

                        # Record communication edges in graph
                        for recipient in recipients:
                            await graph_service.record_communication(
                                org_id=org_id,
                                sender=sender_addr,
                                recipient=recipient,
                                timestamp=received_at,
                            )

                        # Store edge in PostgreSQL for faster querying
                        await _store_comm_edge(db, org_id, sender_addr, recipients, received_at)
                        total += 1

                    url = data.get("@odata.nextLink")
                    page_count += 1

                except Exception as e:
                    logger.error(f"Error fetching M365 messages for {user_email}: {e}")
                    break

            # Update progress
            progress = progress_base + progress_share * ((u_idx + 1) / total_users)
            pct = int(progress * 100)
            await redis.set(f"baseline:{org_id}:progress", pct, ex=7200)
            await redis.set(f"baseline:{org_id}:emails_processed", total, ex=7200)
            await redis.set(f"baseline:{org_id}:m365:progress", pct, ex=30*24*3600)
            await redis.set(f"baseline:{org_id}:m365:emails_processed", total, ex=30*24*3600)

    # Mark M365 baseline complete + timestamp in DB
    try:
        from backend.database import AsyncSessionLocal
        from backend.models.db_models import OrgIntegration as _OI2
        from sqlalchemy import select as _s2
        import datetime as _dt2
        async with AsyncSessionLocal() as _db2:
            _oi2 = (await _db2.execute(_s2(_OI2).where(_OI2.org_id == org_id, _OI2.provider == "m365"))).scalar_one_or_none()
            if _oi2:
                _oi2.last_baseline_at = _dt2.datetime.utcnow()
                _oi2.baseline_progress = 100
                await _db2.commit()
    except Exception as _e2:
        logger.debug(f"M365 baseline DB stamp failed (non-fatal): {_e2}")
    await redis.set(f"baseline:{org_id}:m365:status", "complete", ex=30*24*3600)

    return total


async def _m365_list_users(client: httpx.AsyncClient, headers: dict, org_id: str,
                           scope_group_id: str | None = None) -> list:
    """List M365 users. If scope_group_id set, only returns members of that group."""
    users = []
    if scope_group_id:
        # Scoped mode: only members of the specified security/distribution group
        url = (f"{GRAPH_API_BASE}/groups/{scope_group_id}/members"
               f"?$select=mail,userPrincipalName,displayName,accountEnabled&$top=999")
        logger.info(f"M365 scoped listing: group {scope_group_id} for org {org_id}")
    else:
        url = (f"{GRAPH_API_BASE}/users"
               f"?$select=mail,userPrincipalName,displayName,accountEnabled"
               f",assignedLicenses,proxyAddresses&$top=999&$filter=accountEnabled eq true")
    while url:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                logger.warning(f"M365 user list failed: {resp.status_code} body={resp.text[:200]}")
                break
            data = resp.json()
            batch = data.get("value", [])
            # Filter: only include users that have a mail address (skip service/device accounts)
            users.extend([u for u in batch if u.get("mail") or u.get("userPrincipalName")])
            url = data.get("@odata.nextLink")
        except Exception as e:
            logger.error(f"M365 list users error: {e}")
            break
    logger.info(f"M365 user list: {len(users)} users for org {org_id} (scope_group={scope_group_id or 'all'})")
    return users


async def _refresh_m365_token(refresh_token: str) -> Optional[str]:
    """
    Get a valid M365 access token.

    Strategy (in order):
    1. Client-credentials flow using M365_TENANT_ID env var — works when the app has
       application permissions (Mail.Read, User.Read.All etc.) granted in Azure AD.
       This is the preferred path for tenant-wide scanning.
    2. Delegated refresh_token grant — fallback for orgs still using user-delegated auth.
    """
    client_id = os.getenv("M365_CLIENT_ID", "")
    client_secret = os.getenv("M365_CLIENT_SECRET", "")
    tenant_id = os.getenv("M365_TENANT_ID", "")

    if not client_id or not client_secret:
        return None

    # ── Path 1: client_credentials (app-level) — preferred when tenant_id is set ──
    # Admin consent grants application-level Mail.Read covering ALL tenant mailboxes.
    # Prefer this over delegated tokens which only cover the consenting user.
    if tenant_id and tenant_id != "common":
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={
                        "client_id": client_id,
                        "client_secret": client_secret,
                        "grant_type": "client_credentials",
                        "scope": "https://graph.microsoft.com/.default",
                    },
                )
                if resp.status_code == 200:
                    logger.debug("M365 token acquired via client_credentials")
                    return resp.json().get("access_token")
                else:
                    logger.warning(f"M365 client_credentials failed ({resp.status_code}): {resp.text[:200]}")
        except Exception as e:
            logger.warning(f"M365 client_credentials error: {e}")

    # ── Path 2: refresh_token (delegated) — fallback for single-user orgs ──
    if refresh_token and refresh_token not in ("demo_refresh_token", ""):
        for _tid in ([tenant_id] if tenant_id and tenant_id != "common" else []) + ["common"]:
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(
                        f"https://login.microsoftonline.com/{_tid}/oauth2/v2.0/token",
                        data={
                            "client_id": client_id,
                            "client_secret": client_secret,
                            "refresh_token": refresh_token,
                            "grant_type": "refresh_token",
                            "scope": "https://graph.microsoft.com/.default offline_access",
                        },
                    )
                    if resp.status_code == 200:
                        logger.debug(f"M365 token acquired via refresh_token (tid={_tid})")
                        return resp.json().get("access_token")
                    else:
                        logger.debug(f"M365 refresh_token failed tid={_tid} ({resp.status_code}): {resp.text[:150]}")
            except Exception as e:
                logger.debug(f"M365 refresh_token error tid={_tid}: {e}")

    logger.error("M365 token acquisition failed on all paths")
    return None


def _extract_m365_sender(msg: dict) -> str:
    try:
        return msg["sender"]["emailAddress"]["address"].lower()
    except (KeyError, TypeError):
        return "unknown@unknown.com"


def _extract_m365_recipients(msg: dict) -> list[str]:
    recipients = []
    for r in msg.get("toRecipients", []):
        try:
            recipients.append(r["emailAddress"]["address"].lower())
        except (KeyError, TypeError):
            pass
    return recipients


# ─────────────────────────────────────────────────────────────────────────────
# Google Workspace — Gmail API
# ─────────────────────────────────────────────────────────────────────────────


def _get_service_account_headers_sync(subject_email: str = None) -> dict | None:
    """Build Authorization headers using the Google service account (domain-wide delegation).
    This function makes a synchronous blocking HTTP call — call it via asyncio.to_thread in async contexts.
    """
    import base64, json as _json
    sa_b64 = os.getenv("GOOGLE_SERVICE_ACCOUNT_B64", "")
    if not sa_b64:
        return None
    try:
        from google.oauth2 import service_account
        import google.auth.transport.requests as ga_requests
        sa_info = _json.loads(base64.b64decode(sa_b64).decode())
        scopes = [
            "https://www.googleapis.com/auth/gmail.modify",           # quarantine (move out of inbox)
            "https://www.googleapis.com/auth/gmail.settings.basic",   # posture: read/write inbox filters
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.user.security",  # posture: OAuth app tokens per user
        ]
        creds = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
        if subject_email:
            creds = creds.with_subject(subject_email)
        req = ga_requests.Request()
        creds.refresh(req)   # ← blocking HTTP call — must run in thread
        return {"Authorization": f"Bearer {creds.token}"}
    except Exception as e:
        logger.warning(f"Service account auth failed, falling back to OAuth: {e}")
        return None


def _get_service_account_headers(subject_email: str = None) -> dict | None:
    """Sync shim kept for backwards-compat; use _get_sa_headers_async in async code."""
    return _get_service_account_headers_sync(subject_email)


async def _get_sa_headers_async(subject_email: str = None) -> dict | None:
    """Async-safe wrapper: runs the blocking SA credential refresh in a thread pool."""
    import asyncio
    return await asyncio.to_thread(_get_service_account_headers_sync, subject_email)


async def _ingest_google(
    org_id: str,
    domain: str,
    access_token: str,
    refresh_token: str,
    db: AsyncSession,
    redis,
    progress_base: float,
    progress_share: float,
    scope_group_id: str | None = None,
) -> int:
    """Fetch 90 days of Gmail metadata for all Workspace users."""

    if access_token in ("demo_access_token", ""):
        logger.warning(f"Google demo token for org {org_id} — skipping real ingestion")
        return await _run_simulated_baseline(org_id, 50, redis, progress_base, progress_share)

    # Set progress to 3% immediately (before any blocking calls) so UI doesn't sit at 0%
    await redis.set(f"baseline:{org_id}:progress", 3, ex=7200)

    since_epoch = int((datetime.now(timezone.utc) - timedelta(days=DAYS_LOOKBACK)).timestamp())
    total = 0

    # Always refresh OAuth token before baseline (stored tokens expire in 1h)
    refreshed = await _refresh_google_token(refresh_token)
    if refreshed:
        access_token = refreshed
        logger.info(f"Google baseline: refreshed OAuth token for org {org_id}")
    else:
        logger.warning(f"Google baseline: could not refresh token for org {org_id}, using stored token")

    # Prefer service account (domain-wide delegation) over OAuth user token
    # Use async-safe wrapper to avoid blocking the event loop with the sync credential refresh
    sa_headers = await _get_sa_headers_async()
    headers = sa_headers if sa_headers else {"Authorization": f"Bearer {access_token}"}

    async with httpx.AsyncClient(timeout=30) as client:
        # Set progress to 5% immediately so UI doesn't look frozen
        await redis.set(f"baseline:{org_id}:progress", 5, ex=7200)

        # List workspace users — try SA first, fall back to OAuth
        users = await _google_list_users(client, headers, domain)
        if not users:
            # Retry with fresh OAuth if SA failed
            oauth_headers = {"Authorization": f"Bearer {access_token}"}
            users = await _google_list_users(client, oauth_headers, domain)
            if users:
                headers = oauth_headers

        # If scope group is set, filter down to only members of that group
        if scope_group_id and users:
            logger.info(f"Google baseline: scoping to group {scope_group_id} for org {org_id}")
            group_members = await _google_list_group_members(client, sa_headers or headers, scope_group_id)
            if group_members:
                users = group_members
                logger.info(f"Google baseline: replaced user list with {len(users)} group members (scope={scope_group_id})")
            else:
                logger.warning(f"Google baseline: group {scope_group_id} returned 0 members — keeping full user list")

        if not users:
            # Last resort: scan just the authenticated admin's mailbox via userinfo
            logger.warning(f"Directory listing failed for org {org_id} — falling back to admin mailbox only")
            try:
                me_resp = await client.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
                )
                if me_resp.status_code == 200:
                    admin_email = me_resp.json().get("email", "")
                    if admin_email:
                        users = [{"primaryEmail": admin_email, "suspended": False}]
                        logger.info(f"Falling back to admin mailbox only: {admin_email}")
            except Exception as _me:
                logger.error(f"Could not determine admin email: {_me}")

        if not users:
            logger.error(f"No users found at all for org {org_id} — baseline cannot proceed")
            await redis.set(f"baseline:{org_id}:status", "failed", ex=3600)
            await redis.set(f"baseline:{org_id}:error", "Could not list users. Check OAuth token and DWD setup.", ex=3600)
            return 0

        total_users = len(users)
        logger.info(f"Google baseline: {total_users} mailboxes for org {org_id}")

        # Count aliases across all users (Google stores them in user['aliases'] list)
        google_aliases = sum(len(u.get("aliases", [])) + len(u.get("nonEditableAliases", [])) for u in users)
        # Google doesn't have a native "shared mailbox" concept — use role-based detection
        # (users with delegated access or group emails serve as shared inboxes)
        google_shared = sum(1 for u in users if u.get("isAdmin") is False and u.get("isMailboxSetup") is True and u.get("isEnrolledIn2Sv") is False)

        # Save directory users to DB (now tracks aliases/shared counts too)
        await _upsert_directory_users(db, org_id, users, "google",
                                       aliases_count=google_aliases, shared_count=google_shared)

        # Per-provider baseline Redis keys
        await redis.set(f"baseline:{org_id}:google:status", "running", ex=7200)
        await redis.set(f"baseline:{org_id}:google:mailboxes", total_users, ex=30*24*3600)

        for u_idx, user in enumerate(users):
            user_email = user.get("primaryEmail", "")
            if not user_email or user.get("suspended"):
                continue

            # Get impersonated token for this specific user's mailbox (async-safe)
            impersonated = await _get_sa_headers_async(subject_email=user_email)
            user_headers = impersonated if impersonated else headers

            # List messages for this user (using admin impersonation if available)
            msg_url = (
                f"{GMAIL_API_BASE}/users/{user_email}/messages"
                f"?maxResults={GMAIL_BATCH_SIZE}&q=after:{since_epoch // 86400 * 86400}"
            )

            page_token = None
            page_count = 0

            while page_count < 50:
                try:
                    params_url = msg_url
                    if page_token:
                        params_url += f"&pageToken={page_token}"

                    resp = await client.get(params_url, headers=user_headers)

                    if resp.status_code == 401:
                        # Try refreshing impersonated token first
                        refreshed = await _get_sa_headers_async(subject_email=user_email)
                        if refreshed:
                            user_headers = refreshed
                            resp = await client.get(params_url, headers=user_headers)
                        else:
                            new_token = await _refresh_google_token(refresh_token)
                            if new_token:
                                access_token = new_token
                                user_headers = {"Authorization": f"Bearer {access_token}"}
                                resp = await client.get(params_url, headers=user_headers)
                            else:
                                break

                    if resp.status_code != 200:
                        logger.warning(f"Gmail messages failed for {user_email}: {resp.status_code}")
                        break

                    data = resp.json()
                    message_ids = data.get("messages", [])

                    # Fetch full message content for AI analysis + communication graph
                    for msg_ref in message_ids:
                        msg_id = msg_ref.get("id")
                        if not msg_id:
                            continue
                        try:
                            meta_resp = await client.get(
                                f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}",
                                headers=user_headers,
                                params={"format": "full"},
                            )
                            if meta_resp.status_code != 200:
                                continue
                            meta = meta_resp.json()
                            payload = meta.get("payload", {})
                            hdrs = {
                                h["name"].lower(): h["value"]
                                for h in payload.get("headers", [])
                            }
                            sender = _parse_email_addr(hdrs.get("from", ""))
                            recipients = [_parse_email_addr(r) for r in hdrs.get("to", "").split(",") if r.strip()]
                            date_str = hdrs.get("date", "")
                            subject = hdrs.get("subject", "(no subject)")

                            # Use Gmail internalDate (ms epoch) as the authoritative delivery timestamp
                            # — far more reliable than the Date: header which can be forged or malformed
                            internal_date_ms = meta.get("internalDate", "")
                            if internal_date_ms:
                                try:
                                    from datetime import timezone as _tz
                                    _delivery_dt = datetime.fromtimestamp(int(internal_date_ms) / 1000, tz=_tz.utc)
                                    email_date_str = _delivery_dt.isoformat()
                                except Exception:
                                    email_date_str = date_str
                            else:
                                email_date_str = date_str

                            # Extract body text — prefer text/plain, fall back to text/html
                            body_text = ""
                            html_body = ""
                            def _extract_body(part):
                                nonlocal body_text, html_body
                                import base64 as _b64
                                mime = part.get("mimeType", "")
                                data = part.get("body", {}).get("data", "")
                                if mime == "text/plain" and data and not body_text:
                                    body_text = _b64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
                                elif mime == "text/html" and data and not html_body:
                                    html_body = _b64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
                                for sub in part.get("parts", []):
                                    _extract_body(sub)
                            _extract_body(payload)
                            # Fall back to HTML if no plain text found
                            if not body_text and html_body:
                                import re as _html_re
                                # Strip HTML tags for AI analysis
                                body_text = _html_re.sub(r'<[^>]+>', ' ', html_body)
                                body_text = _html_re.sub(r'\s+', ' ', body_text).strip()

                            # Collect ALL authentication-results headers (Gmail sends multiple)
                            all_auth_hdrs = [
                                h["value"] for h in payload.get("headers", [])
                                if h.get("name", "").lower() in ("authentication-results", "arc-authentication-results")
                            ]
                            auth_results = _parse_auth_headers_multi(all_auth_hdrs, hdrs)

                            # Extract originating sender IP from Received: headers
                            # Gmail adds Received: headers per hop; the last external hop has the real IP
                            import re as _re
                            received_hdrs = [
                                h["value"] for h in payload.get("headers", [])
                                if h.get("name", "").lower() == "received"
                            ]
                            sender_ip = ""
                            for received_hdr in reversed(received_hdrs):
                                ip_match = _re.search(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]', received_hdr)
                                if ip_match:
                                    ip_candidate = ip_match.group(1)
                                    # Skip loopback and private ranges
                                    if not ip_candidate.startswith(('10.', '192.168.', '127.', '172.')):
                                        sender_ip = ip_candidate
                                        break
                            if sender_ip:
                                auth_results["sender_ip"] = sender_ip

                            # Build email dict for process_email()
                            email_data = {
                                "message_id": msg_id,
                                "sender": sender,
                                "recipient": user_email,   # mailbox owner = recipient
                                "recipients": recipients,
                                "subject": subject,
                                "body": body_text[:8000],  # cap for AI token limits
                                "date": email_date_str,    # internalDate-derived ISO string
                                "provider": "google",
                                "mailbox": user_email,
                                "auth_results": auth_results,
                            }

                            # Run through full AI pipeline — each email gets its OWN session
                            # so a failure on one email never poisons the transaction for others
                            try:
                                from backend.services.email_processor import process_email
                                from backend.database import AsyncSessionLocal
                                async with AsyncSessionLocal() as email_db:
                                    threat = await process_email(email_data, org_id, email_db)
                                    await email_db.commit()
                                # Retroactive quarantine — move message out of inbox if high-risk
                                # Pass access_token as fallback if SA (domain-wide delegation) isn't configured
                                if threat and threat.action_taken in ("QUARANTINED", "QUARANTINE", "BLOCK_DELETE"):
                                    try:
                                        from backend.services.quarantine_service import quarantine_gmail_message
                                        _fallback_token = access_token if not (impersonated) else None
                                        await quarantine_gmail_message(user_email, msg_id, access_token=_fallback_token)
                                    except Exception as _qe:
                                        logger.debug(f"Quarantine move failed (non-fatal): {_qe}")
                            except Exception as pe:
                                logger.warning(f"process_email failed for {msg_id}: {pe}")

                            # Also update communication graph
                            for recipient in recipients:
                                await graph_service.record_communication(
                                    org_id=org_id,
                                    sender=sender,
                                    recipient=recipient,
                                    timestamp=email_date_str,
                                )
                            try:
                                await _store_comm_edge(db, org_id, sender, recipients, email_date_str)
                            except Exception as _ce:
                                logger.debug(f"comm_edge store failed (non-fatal): {_ce}")
                            total += 1

                        except Exception as e:
                            logger.debug(f"Failed to fetch Gmail message {msg_id}: {e}")
                            continue

                    page_token = data.get("nextPageToken")
                    page_count += 1

                    # ── Update progress per batch (not just per user) so UI doesn't get stuck ──
                    # Rough estimate: 50 pages × 50 msgs/page = 2500 max per user
                    page_fraction = min(page_count / 50, 1.0)
                    user_fraction = (u_idx + page_fraction) / total_users
                    _cur_progress = progress_base + progress_share * user_fraction
                    _cur_pct = max(6, int(_cur_progress * 100))  # at least 6% so never shows 5% after start
                    await redis.set(f"baseline:{org_id}:progress", _cur_pct, ex=7200)
                    await redis.set(f"baseline:{org_id}:emails_processed", total, ex=7200)

                    if not page_token:
                        break

                except Exception as e:
                    logger.error(f"Error fetching Gmail for {user_email}: {e}")
                    break

            # Final progress for this user
            progress = progress_base + progress_share * ((u_idx + 1) / total_users)
            await redis.set(f"baseline:{org_id}:progress", int(progress * 100), ex=7200)
            await redis.set(f"baseline:{org_id}:emails_processed", total, ex=7200)
            # Per-provider progress
            await redis.set(f"baseline:{org_id}:google:progress", int(progress * 100), ex=30*24*3600)
            await redis.set(f"baseline:{org_id}:google:emails_processed", total, ex=30*24*3600)

    # Mark Google baseline complete + timestamp in DB
    try:
        from backend.database import AsyncSessionLocal
        from backend.models.db_models import OrgIntegration as _OI
        from sqlalchemy import select as _s
        import datetime as _dt
        async with AsyncSessionLocal() as _db:
            _oi = (await _db.execute(_s(_OI).where(_OI.org_id == org_id, _OI.provider == "google"))).scalar_one_or_none()
            if _oi:
                _oi.last_baseline_at = _dt.datetime.utcnow()
                _oi.baseline_progress = 100
                await _db.commit()
    except Exception as _e:
        logger.debug(f"Google baseline DB stamp failed (non-fatal): {_e}")
    await redis.set(f"baseline:{org_id}:google:status", "complete", ex=30*24*3600)

    return total


async def _google_list_users(client: httpx.AsyncClient, headers: dict, domain: str) -> list:
    users = []
    url = f"{ADMIN_API_BASE}/users?domain={domain}&maxResults=500&fields=users(primaryEmail,suspended)"
    while url:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                logger.warning(f"Google user list failed: {resp.status_code}")
                break
            data = resp.json()
            users.extend(data.get("users", []))
            page_token = data.get("nextPageToken")
            url = f"{ADMIN_API_BASE}/users?domain={domain}&maxResults=500&pageToken={page_token}" if page_token else None
        except Exception as e:
            logger.error(f"Google list users error: {e}")
            break
    return users


async def _google_list_group_members(client: httpx.AsyncClient, headers: dict, group_id: str) -> list:
    """Fetch members of a Google group (by group email or ID) using the Admin SDK.
    Returns a list of {"primaryEmail": ..., "suspended": False} dicts for active members.
    """
    members = []
    url = f"{ADMIN_API_BASE}/groups/{group_id}/members?maxResults=500"
    while url:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                logger.warning(f"Google group members fetch failed: {resp.status_code} body={resp.text[:200]}")
                break
            data = resp.json()
            for member in data.get("members", []):
                status = member.get("status", "ACTIVE")
                email = member.get("email", "")
                if email and status == "ACTIVE":
                    members.append({"primaryEmail": email, "suspended": False})
            page_token = data.get("nextPageToken")
            url = f"{ADMIN_API_BASE}/groups/{group_id}/members?maxResults=500&pageToken={page_token}" if page_token else None
        except Exception as e:
            logger.error(f"Google list group members error: {e}")
            break
    logger.info(f"Google group {group_id}: {len(members)} active members")
    return members


async def _refresh_google_token(refresh_token: str) -> Optional[str]:
    client_id = os.getenv("GOOGLE_CLIENT_ID", "")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
    if not client_id or refresh_token in ("demo_refresh_token", ""):
        return None
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "refresh_token": refresh_token,
                    "grant_type": "refresh_token",
                },
            )
            if resp.status_code == 200:
                return resp.json().get("access_token")
    except Exception as e:
        logger.error(f"Google token refresh failed: {e}")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

async def _store_comm_edge(db: AsyncSession, org_id: str, sender: str, recipients: list, timestamp: str):
    """Store sender→recipient edge in PostgreSQL for fast graph queries."""
    try:
        for recipient in recipients:
            await db.execute(
                text("""
                    INSERT INTO communication_edges
                        (org_id, sender, recipient, last_seen, frequency)
                    VALUES (:org_id, :sender, :recipient, :ts, 1)
                    ON CONFLICT (org_id, sender, recipient) DO UPDATE
                        SET frequency = communication_edges.frequency + 1,
                            last_seen = GREATEST(communication_edges.last_seen, :ts::timestamptz)
                """),
                {
                    "org_id": org_id,
                    "sender": sender[:255],
                    "recipient": recipient[:255],
                    "ts": timestamp or datetime.utcnow().isoformat(),
                },
            )
    except Exception as e:
        logger.debug(f"comm_edge store failed (non-fatal): {e}")


def _parse_email_addr(raw: str) -> str:
    """Extract email address from 'Display Name <email@domain.com>' format."""
    raw = raw.strip()
    if "<" in raw and ">" in raw:
        return raw.split("<")[1].split(">")[0].strip().lower()
    return raw.lower()


def _parse_auth_headers(hdrs: dict) -> dict:
    """Legacy single-header version — calls multi-header version."""
    return _parse_auth_headers_multi(
        [v for k, v in hdrs.items() if k in ("authentication-results", "arc-authentication-results")],
        hdrs,
    )


def _parse_auth_headers_multi(auth_header_values: list, hdrs: dict) -> dict:
    """
    Extract SPF, DKIM, DMARC from ALL authentication-results headers.
    Gmail sends one per processing hop — join all, grep for verdicts.
    Returns: {"spf": "pass"|"fail"|"none", "dkim": ..., "dmarc": ..., "raw": "..."}
    """
    import re as _re
    result = {"spf": "none", "dkim": "none", "dmarc": "none"}

    # Join all Authentication-Results headers — the Gmail one has dmarc/dkim/spf
    combined = " ".join(auth_header_values)
    if combined:
        result["raw"] = combined[:800]
        spf_m = _re.search(r'spf=(pass|fail|softfail|neutral|none|permerror|temperror)', combined, _re.I)
        if spf_m:
            result["spf"] = spf_m.group(1).lower()
        dkim_m = _re.search(r'dkim=(pass|fail|none|neutral|permerror|temperror)', combined, _re.I)
        if dkim_m:
            result["dkim"] = dkim_m.group(1).lower()
        dmarc_m = _re.search(r'dmarc=(pass|fail|none|bestguesspass)', combined, _re.I)
        if dmarc_m:
            result["dmarc"] = dmarc_m.group(1).lower()

    # Fallback: check DKIM-Signature header presence
    if result["dkim"] == "none" and hdrs.get("dkim-signature"):
        result["dkim"] = "present"   # Can't verify pass/fail without header, but at least show it's signed

    # Fallback: Received-SPF header
    if result["spf"] == "none":
        spf_hdr = hdrs.get("received-spf", "")
        if spf_hdr:
            m = _re.match(r'(pass|fail|softfail|neutral|none)', spf_hdr.strip(), _re.I)
            if m:
                result["spf"] = m.group(1).lower()

    return result


def _decrypt(token: str) -> str:
    """Decrypt stored token using Fernet."""
    try:
        from cryptography.fernet import Fernet
        key = os.getenv("ENCRYPTION_KEY", "").encode()
        if not key:
            return token
        f = Fernet(key)
        return f.decrypt(token.encode()).decode()
    except Exception:
        return token  # Return as-is if not encrypted or key missing


async def _run_simulated_baseline(
    org_id: str, mailbox_count: int, redis, progress_base: float, progress_share: float
) -> int:
    """Fallback simulation for demo tokens — at least moves the progress bar."""
    for i in range(mailbox_count):
        progress = progress_base + progress_share * ((i + 1) / mailbox_count)
        await redis.set(f"baseline:{org_id}:progress", int(progress * 100), ex=7200)
        await asyncio.sleep(0.05)
    return 0


async def get_baseline_status(org_id: str) -> dict:
    redis = aioredis.from_url(REDIS_URL)
    try:
        progress = await redis.get(f"baseline:{org_id}:progress")
        status = await redis.get(f"baseline:{org_id}:status")
        processed = await redis.get(f"baseline:{org_id}:emails_processed")
        error = await redis.get(f"baseline:{org_id}:error")

        def dec(v): return v.decode() if isinstance(v, bytes) else (v or "")

        progress_val = int(dec(progress) or 0)
        status_val = dec(status) or "not_started"
        processed_val = int(dec(processed) or 0)

        # Redis TTL expired — fall back to DB to check if baseline ever completed
        # If there are threats or users in the DB, the baseline ran
        if status_val == "not_started" and progress_val == 0:
            try:
                from backend.database import AsyncSessionLocal
                from backend.models.db_models import User, Threat
                from sqlalchemy import select, func as _func
                async with AsyncSessionLocal() as db:
                    import uuid as _uuid
                    try:
                        org_uuid = _uuid.UUID(org_id)
                    except ValueError:
                        org_uuid = org_id
                    user_count = (await db.execute(
                        select(_func.count(User.id)).where(User.org_id == org_uuid, User.is_active.is_(True))
                    )).scalar() or 0
                    threat_count = (await db.execute(
                        select(_func.count(Threat.id)).where(Threat.org_id == org_uuid)
                    )).scalar() or 0
                    if user_count > 0 or threat_count > 0:
                        # Baseline ran before Redis TTL expired — mark as complete
                        progress_val = 100
                        status_val = "complete"
                        processed_val = processed_val or threat_count
                        # Re-cache so future calls don't hit DB
                        await redis.set(f"baseline:{org_id}:progress", 100, ex=30*24*3600)
                        await redis.set(f"baseline:{org_id}:status", "complete", ex=30*24*3600)
                        await redis.set(f"baseline:{org_id}:emails_processed", processed_val, ex=30*24*3600)
            except Exception:
                pass  # DB check is best-effort

        return {
            "progress": progress_val,
            "status": status_val,
            "emails_processed": processed_val,
            "error": dec(error) or None,
        }
    finally:
        await redis.aclose()
