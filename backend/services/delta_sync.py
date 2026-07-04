"""
Delta sync — runs every 2 minutes per connected org to pull new emails since last sync.
Uses the same ingestion logic as baseline but only fetches messages newer than last_sync_at.
"""
import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta

import httpx
import redis.asyncio as aioredis
from sqlalchemy import select, text

from backend.database import AsyncSessionLocal
from backend.models.db_models import OrgIntegration, Organization
from backend.services.email_processor import process_email
from backend.services.baseline_ingestion import (
    _google_list_users, _google_list_group_members, _decrypt, _store_comm_edge, _parse_email_addr,
    _upsert_directory_users, _refresh_google_token, _get_service_account_headers,
    _get_sa_headers_async, _parse_auth_headers_multi,
)
from backend.services.graph_service import graph_service

logger = logging.getLogger(__name__)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1"
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"

# Tightened from 60s → 35s for near-real-time delivery.
# 35s is a careful balance:
#   - <30s starts running into M365 / Gmail rate limits at scale (multiple orgs)
#   - The current per-cycle work (sync + classify) takes 15–25s on a normal
#     burst; 35s leaves ~10s buffer for the cycle to finish before the next one
#     would otherwise start. With overlap-guard below, even a slow cycle just
#     skips the next tick rather than stacking.
DELTA_INTERVAL_SECONDS = int(os.getenv("DELTA_INTERVAL_SECONDS", "35"))
OUTBOUND_INTERVAL_SECONDS = int(os.getenv("OUTBOUND_INTERVAL_SECONDS", "20"))

# Safety net — if a cycle stalls past this, log a warning. Doesn't kill the cycle
# (it'll still finish in the background) but lets us see in CloudWatch that the
# new tighter cadence is causing overlap.
DELTA_CYCLE_WARN_AFTER_SECONDS = int(os.getenv("DELTA_CYCLE_WARN_AFTER_SECONDS", "45"))


async def run_delta_sync_loop():
    """
    Long-running background task: poll all orgs every DELTA_INTERVAL_SECONDS.

    Cycle-overlap guard: if the previous cycle is still running when the next
    tick fires, we skip the new tick (rather than stacking) so the system
    self-throttles on slow networks / large mailboxes.
    """
    logger.info(f"Delta sync loop started (interval: {DELTA_INTERVAL_SECONDS}s)")
    cycle = 0
    in_flight = False

    while True:
        cycle += 1
        try:
            # Heartbeat every 10 cycles (~6 min at 35s) at INFO level
            if cycle % 10 == 1:
                logger.info(f"Delta sync heartbeat: cycle {cycle}")

            if in_flight:
                logger.warning(
                    f"Delta sync cycle {cycle} skipped — previous cycle still in flight "
                    f"(consider increasing DELTA_INTERVAL_SECONDS or scaling backend tasks)"
                )
            else:
                in_flight = True
                cycle_start = asyncio.get_event_loop().time()
                try:
                    await _sync_all_orgs()
                finally:
                    elapsed = asyncio.get_event_loop().time() - cycle_start
                    if elapsed > DELTA_CYCLE_WARN_AFTER_SECONDS:
                        logger.warning(
                            f"Delta sync cycle {cycle} took {elapsed:.1f}s "
                            f"(> {DELTA_CYCLE_WARN_AFTER_SECONDS}s warning threshold)"
                        )
                    in_flight = False
        except asyncio.CancelledError:
            logger.warning("Delta sync loop cancelled")
            raise
        except Exception as e:
            in_flight = False
            logger.error(f"Delta sync loop error (cycle {cycle}): {e}", exc_info=True)

        try:
            await asyncio.sleep(DELTA_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logger.warning("Delta sync loop cancelled during sleep")
            raise


async def run_outbound_dlp_loop():
    """
    Fast outbound-only sync loop for DLP.
    Runs every 20 seconds to catch sent emails quickly for potential recall.
    Only checks Sent Items folders, no inbound processing.
    """
    logger.info(f"Outbound DLP loop started (interval: {OUTBOUND_INTERVAL_SECONDS}s)")
    cycle = 0
    while True:
        cycle += 1
        try:
            if cycle % 30 == 1:  # Log every 10 minutes
                logger.info(f"Outbound DLP heartbeat: cycle {cycle}")
            await _sync_outbound_only()
        except asyncio.CancelledError:
            logger.warning("Outbound DLP loop cancelled")
            raise
        except Exception as e:
            logger.error(f"Outbound DLP loop error (cycle {cycle}): {e}", exc_info=True)
        try:
            await asyncio.sleep(OUTBOUND_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            logger.warning("Outbound DLP loop cancelled during sleep")
            raise


async def _sync_all_orgs():
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        # Load integrations in one session, snapshot all needed fields eagerly,
        # then process each in its own fresh session to avoid greenlet/lazy-load issues.
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(OrgIntegration).where(OrgIntegration.status == "active")
            )
            integrations_raw = result.scalars().all()
            # Snapshot fields while session is still open
            integration_snapshots = [
                {
                    "id": i.id,
                    "org_id": i.org_id,
                    "provider": i.provider,
                    "status": i.status,
                    "access_token_enc": i.access_token_enc,
                    "refresh_token_enc": i.refresh_token_enc,
                    "org_domain": getattr(i, "org_domain", None),
                    "mailbox_count": i.mailbox_count,
                    "scope_group_id": getattr(i, "scope_group_id", None),
                    "scope_group_name": getattr(i, "scope_group_name", None),
                }
                for i in integrations_raw
            ]

        # Process each integration in its own session
        for snap in integration_snapshots:
            async with AsyncSessionLocal() as db:
                try:
                    await _delta_sync_integration_snap(db, redis, snap)
                    await db.commit()
                except Exception as e:
                    logger.warning(f"Delta sync failed for org {snap['org_id']} / {snap['provider']}: {e}")
                    try:
                        await db.rollback()
                    except Exception:
                        pass
    finally:
        await redis.aclose()


async def _delta_sync_integration_snap(db, redis, integration):
    # integration is a plain dict snapshot (not an ORM object)
    org_id = str(integration["org_id"])
    provider = integration["provider"]
    integration_id = integration["id"]
    _enc_at = integration.get("access_token_enc") or ""
    _enc_rt = integration.get("refresh_token_enc") or ""
    access_token = _decrypt(_enc_at) if _enc_at else ""
    refresh_token = _decrypt(_enc_rt) if _enc_rt else ""

    if access_token in ("demo_access_token", ""):
        return

    # Always try to refresh OAuth token (expires in 1h)
    if provider == "google":
        from backend.services.baseline_ingestion import _refresh_google_token
        new_token = await _refresh_google_token(refresh_token)
        if new_token:
            access_token = new_token
    elif provider == "m365":
        from backend.services.baseline_ingestion import _refresh_m365_token
        new_token = await _refresh_m365_token(refresh_token)
        if new_token:
            access_token = new_token
            # Note: token is refreshed in-memory for this sync cycle.
            # The 45-min background loop in main.py persists it back to DB.

    # Get last sync time from Redis (default: 5 min ago for first delta)
    last_sync_key = f"delta_sync:{org_id}:{provider}:last_at"
    last_sync_ts = await redis.get(last_sync_key)
    if last_sync_ts:
        since = datetime.fromtimestamp(float(last_sync_ts), tz=timezone.utc)
    else:
        since = datetime.now(timezone.utc) - timedelta(hours=24)

    since_epoch = int(since.timestamp())
    now_ts = datetime.now(timezone.utc).timestamp()
    new_count = 0

    if provider == "google":
        org_result = await db.execute(select(Organization).where(Organization.id == integration["org_id"]))
        org = org_result.scalar_one_or_none()
        domain = org.domain if org else ""

        # Skip stale/broken integrations with no domain — they'll just 400/401 forever
        if not domain:
            logger.debug(f"Delta sync: skipping google integration for org {org_id} — empty domain")
            return

        async with httpx.AsyncClient(timeout=20) as client:
            oauth_headers = {"Authorization": f"Bearer {access_token}"}

            # Use SA headers for directory listing (async-safe to avoid blocking event loop)
            sa_admin_headers = await _get_sa_headers_async() or oauth_headers
            users = await _google_list_users(client, sa_admin_headers, domain)
            if not users:
                # Fallback to OAuth if SA not configured
                users = await _google_list_users(client, oauth_headers, domain)

            # If scope group is set, restrict to group members only
            _google_scope_gid = integration.get("scope_group_id") or None
            if _google_scope_gid and users:
                logger.info(f"Google delta: scoping to group {_google_scope_gid} for org {org_id}")
                _group_members = await _google_list_group_members(client, sa_admin_headers, _google_scope_gid)
                if _group_members:
                    users = _group_members
                    logger.info(f"Google delta: replaced user list with {len(users)} group members (scope={_google_scope_gid})")
                else:
                    logger.warning(f"Google delta: group {_google_scope_gid} returned 0 members — keeping full user list")

            if users:
                await _upsert_directory_users(db, org_id, users, "google")
                # Explicitly stamp mailbox_count so the UI reflects it immediately
                # (_upsert_directory_users does this too but has its own try/except —
                # belt-and-suspenders so reconnect shows count on next delta cycle)
                try:
                    _active_google = [u for u in users if not u.get("suspended")]
                    await db.execute(
                        text(
                            "UPDATE org_integrations SET mailbox_count = :mc WHERE org_id = :oid AND provider = 'google'"
                        ),
                        {"mc": len(_active_google), "oid": org_id},
                    )
                    await db.execute(
                        text(
                            "UPDATE organizations SET mailbox_count = ("
                            "SELECT COALESCE(SUM(mailbox_count),0) FROM org_integrations "
                            "WHERE org_id = :oid AND status = 'active') WHERE id = :oid"
                        ),
                        {"oid": org_id},
                    )
                    await db.commit()
                    logger.info(f"Google delta: stamped mailbox_count={len(_active_google)} for org {org_id}")
                except Exception as _mce:
                    logger.warning(f"Google delta: mailbox_count stamp failed (non-fatal): {_mce}")
                    await db.rollback()
            else:
                # Directory API unavailable — fall back to users already known in DB
                # This ensures all previously-discovered mailboxes keep getting scanned
                from backend.models.db_models import User as _User
                from sqlalchemy import select as _usel
                _ures = await db.execute(
                    _usel(_User.email).where(
                        _User.org_id == integration["org_id"],
                        _User.is_active.is_not(False),
                    )
                )
                _db_emails = [r[0] for r in _ures.all() if r[0] and domain in r[0]]
                users = [{"primaryEmail": e, "suspended": False} for e in _db_emails]
                if users:
                    logger.info(f"Delta sync: directory API unavailable, using {len(users)} DB users for org {org_id}")

            # Also sync groups / distribution lists
            try:
                from backend.services.google_workspace_service import GoogleWorkspaceService
                from backend.services.baseline_ingestion import _decrypt as _dec
                _rt = integration.get("refresh_token_enc", "") or ""
                _svc = GoogleWorkspaceService(
                    access_token=access_token,
                    refresh_token=_decrypt(_rt) if _rt else "",
                    org_id=org_id,
                )
                groups = await _svc.list_groups(domain=domain)
                if groups:
                    await _upsert_directory_groups(db, org_id, groups, "google")
                    from sqlalchemy import text as _gtxt
                    await db.execute(_gtxt(
                        "UPDATE org_integrations SET groups_count = :gc WHERE org_id = :oid AND provider = 'google'"
                    ), {"gc": len(groups), "oid": org_id})
                    await db.commit()
                    logger.info(f"Google delta: refreshed {len(groups)} groups for org {org_id}")
            except Exception as _ge:
                logger.debug(f"Delta sync: group listing failed for org {org_id}: {_ge}")

            for user in users:
                user_email = user.get("primaryEmail", "")
                if not user_email or user.get("suspended"):
                    continue
                try:
                    # Impersonate this specific user's mailbox via SA DWD (async-safe)
                    impersonated = await _get_sa_headers_async(subject_email=user_email)
                    user_headers = impersonated if impersonated else oauth_headers

                    resp = await client.get(
                        f"{GMAIL_API_BASE}/users/{user_email}/messages",
                        headers=user_headers,
                        params={"maxResults": 50, "q": f"after:{since_epoch}"},
                    )
                    if resp.status_code == 401:
                        new_token = await _refresh_google_token(refresh_token)
                        if new_token:
                            access_token = new_token
                            oauth_headers = {"Authorization": f"Bearer {access_token}"}
                            user_headers = oauth_headers
                            resp = await client.get(
                                f"{GMAIL_API_BASE}/users/{user_email}/messages",
                                headers=user_headers,
                                params={"maxResults": 50, "q": f"after:{since_epoch}"},
                            )
                    if resp.status_code != 200:
                        logger.debug(f"Delta sync: Gmail list failed for {user_email}: {resp.status_code}")
                        continue

                    _msg_list = resp.json().get("messages", [])
                    logger.info(f"Gmail delta: {len(_msg_list)} messages for {user_email} (since epoch {since_epoch})")
                    for msg_ref in _msg_list:
                        msg_id = msg_ref.get("id")
                        if not msg_id:
                            continue
                        meta = await client.get(
                            f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}",
                            headers=user_headers,
                            params={"format": "full"},
                        )
                        if meta.status_code != 200:
                            continue
                        msg_json = meta.json()
                        # Check if this is an outbound (SENT) message
                        _label_ids = msg_json.get("labelIds", [])
                        _is_outbound = "SENT" in _label_ids and "INBOX" not in _label_ids
                        logger.debug(f"Gmail delta: msg {msg_id} labels={_label_ids} is_outbound={_is_outbound}")
                        
                        # For SENT messages: run DLP scan instead of threat scan
                        if _is_outbound:
                            logger.info(f"Gmail delta: OUTBOUND email detected - msg_id={msg_id} user={user_email}")
                            try:
                                from backend.services.dlp_inline import scan_email_for_dlp, get_dlp_config
                                dlp_config = await get_dlp_config(org_id, db)
                                logger.info(f"Gmail delta: DLP config for org {org_id}: enabled={dlp_config.enabled if dlp_config else 'N/A'}, scan_outbound={dlp_config.scan_outbound if dlp_config else 'N/A'}")
                                if dlp_config and dlp_config.enabled and dlp_config.scan_outbound:
                                    # Extract email details for DLP
                                    payload = msg_json.get("payload", {})
                                    hdrs = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
                                    dlp_sender = _parse_email_addr(hdrs.get("from", ""))
                                    dlp_recipients = [_parse_email_addr(r) for r in hdrs.get("to", "").split(",") if r.strip()]
                                    dlp_subject = hdrs.get("subject", "")
                                    
                                    # Extract body
                                    dlp_body = ""
                                    def _get_dlp_body(part):
                                        nonlocal dlp_body
                                        import base64 as _b64
                                        mime = part.get("mimeType", "")
                                        data = part.get("body", {}).get("data", "")
                                        if mime == "text/plain" and data and not dlp_body:
                                            dlp_body = _b64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
                                        for sub in part.get("parts", []):
                                            _get_dlp_body(sub)
                                    _get_dlp_body(payload)
                                    
                                    # Extract attachments with content
                                    dlp_attachments = []
                                    attachment_ids = []
                                    def _collect_attachment_ids(part):
                                        fname = part.get("filename", "")
                                        att_id = part.get("body", {}).get("attachmentId", "")
                                        if fname and att_id:
                                            attachment_ids.append({
                                                "name": fname,
                                                "content_type": part.get("mimeType", "application/octet-stream"),
                                                "attachment_id": att_id,
                                            })
                                        for sub in part.get("parts", []):
                                            _collect_attachment_ids(sub)
                                    _collect_attachment_ids(payload)
                                    
                                    # Download attachment content (limit to 5 attachments, 10MB each)
                                    for att_info in attachment_ids[:5]:
                                        try:
                                            att_resp = await client.get(
                                                f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}/attachments/{att_info['attachment_id']}",
                                                headers=user_headers,
                                                timeout=15.0,
                                            )
                                            if att_resp.status_code == 200:
                                                att_data = att_resp.json()
                                                # Gmail returns URL-safe base64
                                                import base64
                                                raw_b64 = att_data.get("data", "")
                                                # Convert URL-safe to standard base64
                                                std_b64 = raw_b64.replace("-", "+").replace("_", "/")
                                                # Add padding if needed
                                                padding = 4 - len(std_b64) % 4
                                                if padding != 4:
                                                    std_b64 += "=" * padding
                                                dlp_attachments.append({
                                                    "name": att_info["name"],
                                                    "content_type": att_info["content_type"],
                                                    "content_base64": std_b64,
                                                })
                                                logger.debug(f"DLP: Downloaded attachment '{att_info['name']}' for scanning")
                                        except Exception as att_err:
                                            logger.warning(f"DLP: Failed to download attachment '{att_info['name']}': {att_err}")
                                            # Still include without content for filename scanning
                                            dlp_attachments.append({
                                                "name": att_info["name"],
                                                "content_type": att_info["content_type"],
                                            })
                                    
                                    # Run DLP scan
                                    dlp_result = await scan_email_for_dlp(
                                        org_id=org_id,
                                        email_id=msg_id,
                                        subject=dlp_subject,
                                        body=dlp_body,
                                        sender=dlp_sender,
                                        recipients=dlp_recipients,
                                        attachments=dlp_attachments,
                                        direction="outbound",
                                        db=db,
                                    )
                                    
                                    if dlp_result.get("action") not in ("allow", None):
                                        logger.info(f"DLP scan for {msg_id}: action={dlp_result.get('action')}, categories={dlp_result.get('categories')}")
                                        new_count += 1
                            except Exception as _dlp_err:
                                logger.warning(f"DLP scan failed for sent message {msg_id}: {_dlp_err}")
                            continue  # Don't run threat scan on outbound messages
                        # Skip drafts
                        if "DRAFT" in _label_ids:
                            continue
                        payload = msg_json.get("payload", {})
                        hdrs = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
                        sender = _parse_email_addr(hdrs.get("from", ""))
                        recipients = [_parse_email_addr(r) for r in hdrs.get("to", "").split(",") if r.strip()]
                        subject = hdrs.get("subject", "")

                        # Use Gmail internalDate (ms epoch) as authoritative delivery timestamp
                        internal_date_ms = msg_json.get("internalDate", "")
                        if internal_date_ms:
                            try:
                                from datetime import timezone as _tz
                                _delivery_dt = datetime.fromtimestamp(int(internal_date_ms) / 1000, tz=_tz.utc)
                                email_date_str = _delivery_dt.isoformat()
                            except Exception:
                                email_date_str = hdrs.get("date", "")
                        else:
                            email_date_str = hdrs.get("date", "")

                        # Extract body — prefer text/plain, fall back to text/html
                        body_text = ""
                        html_body = ""
                        def _get_body(part):
                            nonlocal body_text, html_body
                            import base64 as _b64
                            mime = part.get("mimeType", "")
                            data = part.get("body", {}).get("data", "")
                            if mime == "text/plain" and data and not body_text:
                                body_text = _b64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
                            elif mime == "text/html" and data and not html_body:
                                html_body = _b64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
                            for sub in part.get("parts", []):
                                _get_body(sub)
                        _get_body(payload)
                        # Fall back to HTML if no plain text found
                        if not body_text and html_body:
                            import re as _html_re
                            # Strip HTML tags for AI analysis
                            body_text = _html_re.sub(r'<[^>]+>', ' ', html_body)
                            body_text = _html_re.sub(r'\s+', ' ', body_text).strip()
                        # Collect ALL auth headers (Gmail sends multiple per hop)
                        all_auth_vals = [
                            h["value"] for h in payload.get("headers", [])
                            if h.get("name", "").lower() in ("authentication-results", "arc-authentication-results")
                        ]
                        auth_results = _parse_auth_headers_multi(all_auth_vals, hdrs)

                        # Extract originating sender IP from Received: headers
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
                                if not ip_candidate.startswith(('10.', '192.168.', '127.', '172.')):
                                    sender_ip = ip_candidate
                                    break
                        if sender_ip:
                            auth_results["sender_ip"] = sender_ip

                        # Detect links and attachments before policy evaluation
                        import re as _link_re
                        has_link = bool(_link_re.search(r'https?://', body_text or ''))
                        email_attachments = []
                        def _collect_attachments(part):
                            fname = part.get('filename', '')
                            if fname:
                                email_attachments.append({
                                    "filename": fname,
                                    "mimeType": part.get("mimeType", ""),
                                    "size": part.get("body", {}).get("size", 0),
                                })
                            for sub in part.get("parts", []):
                                _collect_attachments(sub)
                        _collect_attachments(payload)
                        has_attachment = len(email_attachments) > 0
                        sender_domain_val = sender.split("@")[-1] if "@" in sender else sender

                        # Extract Reply-To header from Gmail headers
                        reply_to_val = ""
                        for _gh in payload.get("headers", []):
                            if _gh.get("name", "").lower() == "reply-to":
                                reply_to_val = _gh.get("value", "").strip()
                                break

                        # Build full email_data for policy evaluation and AI processing
                        email_data = {
                            "sender": sender,
                            "sender_domain": sender_domain_val,
                            "recipient": user_email,  # mailbox owner is always the recipient
                            "recipient_email": user_email,
                            "recipients": recipients,
                            "subject": subject,
                            "body": body_text[:8000],
                            "message_id": msg_id,
                            "date": email_date_str,
                            "provider": "google",
                            "auth_results": auth_results,
                            "has_link": has_link,
                            "has_attachment": has_attachment,
                            "attachments": email_attachments,
                            "reply_to": reply_to_val,
                        }

                        # ── Full policy evaluation BEFORE AI processing ─────────────────
                        # Evaluates ALL conditions: sender, recipient, has_link, has_attachment,
                        # attachment_types, keywords, subject_contains, threat_type, risk_score
                        from backend.services.policy_engine import evaluate_policies as _eval_policies
                        from backend.database import AsyncSessionLocal as _ASL

                        matched_policy = None
                        async with _ASL() as _policy_db:
                            try:
                                matched_policy = await _eval_policies(
                                    email_data=email_data,
                                    org_id=org_id,
                                    db=_policy_db,
                                )
                                await _policy_db.commit()
                            except Exception as _pe:
                                logger.warning(f"Policy evaluation failed for {msg_id}: {_pe}")

                        if matched_policy:
                            policy_action = matched_policy.get("action", "")

                            if policy_action in ("BLOCK", "BLOCK_DELETE"):
                                # ── BLOCK: trash + create threat record + notify all parties ──
                                try:
                                    from backend.services.quarantine_service import block_to_trash_gmail
                                    await block_to_trash_gmail(user_email, msg_id)
                                    logger.info(f"Delta: BLOCK policy '{matched_policy['name']}' — trashed {msg_id}")
                                except Exception as _te:
                                    logger.warning(f"Block trash failed (non-fatal): {_te}")

                                # Create a threat record for the blocked email
                                async with _ASL() as block_db:
                                    try:
                                        import uuid as _uuid, hashlib as _hashlib
                                        from backend.models.db_models import Threat as _BT
                                        _threat_rec = _BT(
                                            org_id=_uuid.UUID(org_id) if isinstance(org_id, str) else org_id,
                                            email_message_id=msg_id,
                                            sender=sender,
                                            sender_domain=sender_domain_val,
                                            recipient_email=user_email,
                                            subject=subject[:500] if subject else None,
                                            subject_hash=_hashlib.sha256((subject or "").encode()).hexdigest()[:64],
                                            email_received_at=None,
                                            auth_results=auth_results,
                                            threat_type="POLICY_BLOCK",
                                            risk_score=100,
                                            status="resolved",
                                            action_taken="BLOCK_DELETE",
                                            ai_explanation_en=f"Blocked by policy: {matched_policy['name']}",
                                            ai_explanation_ar=f"محجوب بموجب السياسة: {matched_policy['name']}",
                                            detected_at=datetime.utcnow(),
                                            resolved_at=datetime.utcnow(),
                                        )
                                        # Set policy_id if column exists
                                        try:
                                            _threat_rec.policy_id = matched_policy.get("id")
                                        except Exception:
                                            pass
                                        block_db.add(_threat_rec)
                                        await block_db.flush()

                                        # Send notifications: admin + recipient + sender (all with full context)
                                        _body_prev = (body_text or "")[:300]
                                        _link_ct = len(_link_re.findall(r'https?://\S+', body_text or ''))
                                        from backend.services.policy_engine import _send_policy_notifications
                                        await _send_policy_notifications(
                                            action="BLOCK_DELETE",
                                            recipient_email=user_email,
                                            sender_email=sender,
                                            subject=subject,
                                            threat_type="POLICY_BLOCK",
                                            risk_score=100,
                                            ai_explanation=f"Blocked by policy: {matched_policy['name']}",
                                            org_id=org_id,
                                            db=block_db,
                                            notify_sender=True,
                                            body_preview=_body_prev,
                                            attachments=email_attachments,
                                            link_count=_link_ct,
                                            received_at=email_date_str or "",
                                            policy_name=matched_policy.get("name", ""),
                                        )
                                        await block_db.commit()
                                    except Exception as _be:
                                        logger.warning(f"Block threat record failed (non-fatal): {_be}")
                                new_count += 1
                                continue  # Skip AI processing for blocked emails

                            elif policy_action == "ALLOW":
                                # ALLOW: skip AI — but store a CLEAN trace record so message trace shows it
                                logger.info(f"Delta: ALLOW policy '{matched_policy['name']}' — skipping AI for {msg_id}")
                                async with _ASL() as allow_db:
                                    try:
                                        import uuid as _uuid2, hashlib as _hashlib2
                                        from backend.models.db_models import Threat as _AT
                                        # Dedup check
                                        from sqlalchemy import select as _sel2
                                        _exists = (await allow_db.execute(
                                            _sel2(_AT.id).where(_AT.email_message_id == msg_id, _AT.org_id == (_uuid2.UUID(org_id) if isinstance(org_id, str) else org_id))
                                        )).scalar_one_or_none()
                                        if not _exists:
                                            _allow_rec = _AT(
                                                org_id=_uuid2.UUID(org_id) if isinstance(org_id, str) else org_id,
                                                email_message_id=msg_id,
                                                sender=sender,
                                                sender_domain=sender_domain_val,
                                                recipient_email=user_email,
                                                subject=subject[:500] if subject else None,
                                                subject_hash=_hashlib2.sha256((subject or "").encode()).hexdigest()[:64],
                                                email_received_at=None,
                                                auth_results=auth_results,
                                                threat_type="CLEAN",
                                                risk_score=0,
                                                status="resolved",
                                                action_taken="ALLOW",
                                                detected_at=__import__("datetime").datetime.utcnow(),
                                            )
                                            allow_db.add(_allow_rec)
                                            await allow_db.commit()
                                    except Exception as _ae:
                                        logger.debug(f"ALLOW trace record failed (non-fatal): {_ae}")
                                new_count += 1
                                continue

                            # For QUARANTINE/ALERT/TAG from policy — let process_email run for AI analysis
                            # Policy will be applied retroactively via apply_policy_action after AI result
                            email_data["_matched_policy"] = matched_policy

                        # Fresh session per email — failure on one never poisons others
                        threat = None
                        async with _ASL() as email_db:
                            try:
                                threat = await process_email(email_data, org_id, email_db)
                                await email_db.commit()
                            except Exception as _pe:
                                logger.warning(f"Delta process_email failed for {msg_id}: {_pe}")

                        try:
                            await _store_comm_edge(db, org_id, sender, recipients, email_date_str)
                        except Exception as _ce:
                            logger.debug(f"comm_edge store failed (non-fatal): {_ce}")

                        # Apply policy action to the AI-processed threat record
                        if threat and matched_policy:
                            policy_action = matched_policy.get("action", "")
                            async with _ASL() as pol_db:
                                try:
                                    from backend.services.policy_engine import apply_policy_action as _apa
                                    _link_ct2 = len(_link_re.findall(r'https?://\S+', body_text or ''))
                                    await _apa(
                                        policy=matched_policy,
                                        threat_id=str(threat.id),
                                        email_message_id=msg_id,
                                        recipient_email=user_email,
                                        org_id=org_id,
                                        db=pol_db,
                                        access_token=access_token,
                                        sender_email=sender,
                                        subject=subject,
                                        ai_explanation=threat.ai_explanation_en if threat else "",
                                        body_preview=(body_text or "")[:300],
                                        attachments=email_attachments,
                                        link_count=_link_ct2,
                                        received_at=email_date_str or "",
                                        provider="gmail",  # explicit — no inference needed for Google delta
                                    )
                                    await pol_db.commit()
                                except Exception as _pae:
                                    logger.warning(f"Policy apply failed (non-fatal): {_pae}")

                        # AI-determined quarantine (no policy matched, or policy was ALERT/TAG)
                        elif threat and threat.action_taken in ("QUARANTINED", "QUARANTINE"):
                            try:
                                from backend.services.quarantine_service import quarantine_gmail_message
                                await quarantine_gmail_message(user_email, msg_id, access_token=access_token)
                            except Exception as _qe:
                                logger.debug(f"Quarantine move failed (non-fatal): {_qe}")
                        new_count += 1
                except Exception as e:
                    logger.debug(f"Delta sync error for {user_email}: {e}")
                    continue

    elif provider == "m365":
        async with httpx.AsyncClient(timeout=30) as client:
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")

            # ── M365 user directory refresh (same cadence as email delta) ──────
            try:
                _scope_gid = integration.get("scope_group_id") or None
                if _scope_gid:
                    _usr_url = (f"{GRAPH_API_BASE}/groups/{_scope_gid}/members"
                                f"?$select=mail,userPrincipalName,displayName,accountEnabled&$top=200")
                else:
                    _usr_url = (f"{GRAPH_API_BASE}/users?$select=id,mail,displayName,userPrincipalName,"
                                "accountEnabled,assignedLicenses,proxyAddresses&$top=200")
                _usr_resp = await client.get(_usr_url, headers=headers)
                logger.info(f"M365 delta: user dir refresh status={_usr_resp.status_code} for org {org_id}")
                if _usr_resp.status_code == 200:
                    _all_users = _usr_resp.json().get("value", [])
                    _active_users = [u for u in _all_users if u.get("accountEnabled", True) and (u.get("mail") or u.get("userPrincipalName"))]
                    logger.info(f"M365 delta: {len(_active_users)} active users found for org {org_id}")
                    await _upsert_directory_users(db, org_id, _active_users, "m365")
                    # Explicitly stamp mailbox_count immediately after directory sync
                    # so UI shows correct count on next poll (belt-and-suspenders)
                    try:
                        from sqlalchemy import text as _mctxt
                        await db.execute(
                            _mctxt(
                                "UPDATE org_integrations SET mailbox_count = :mc "
                                "WHERE org_id = :oid AND provider = 'm365'"
                            ),
                            {"mc": len(_active_users), "oid": org_id},
                        )
                        await db.execute(
                            _mctxt(
                                "UPDATE organizations SET mailbox_count = ("
                                "SELECT COALESCE(SUM(mailbox_count),0) FROM org_integrations "
                                "WHERE org_id = :oid AND status = 'active') WHERE id = :oid"
                            ),
                            {"oid": org_id},
                        )
                        await db.commit()
                        logger.info(f"M365 delta: stamped mailbox_count={len(_active_users)} for org {org_id}")
                    except Exception as _mce:
                        logger.warning(f"M365 delta: mailbox_count stamp failed (non-fatal): {_mce}")
                        await db.rollback()
            except Exception as _ue:
                logger.warning(f"M365 user directory refresh failed: {_ue}")

            # ── M365 group refresh ───────────────────────────────────────────
            try:
                _grp_resp = await client.get(
                    f"{GRAPH_API_BASE}/groups?$select=id,mail,displayName,description&$top=200",
                    headers=headers,
                )
                if _grp_resp.status_code == 200:
                    _m365_groups = [g for g in _grp_resp.json().get("value", []) if g.get("mail")]
                    await _upsert_directory_groups(db, org_id, [
                        {"id": g["id"], "email": g["mail"], "name": g["displayName"],
                         "description": g.get("description", "")} for g in _m365_groups
                    ], "m365")
                    # Also stamp groups_count in OrgIntegration
                    from sqlalchemy import text as _dtxt
                    await db.execute(_dtxt(
                        "UPDATE org_integrations SET groups_count = :gc WHERE org_id = :oid AND provider = 'm365'"
                    ), {"gc": len(_m365_groups), "oid": org_id})
                    await db.commit()
                    logger.info(f"M365 delta: refreshed {len(_m365_groups)} groups for org {org_id}")
            except Exception as _ge:
                logger.warning(f"M365 group refresh failed (non-fatal): {_ge}")

            # ── M365 shared mailbox discovery ────────────────────────────────
            # Shared mailboxes are M365 users with no assigned licenses.
            # They are unscanned by default (no inbox scanning token), but we
            # should discover them and surface in the People / DL & Groups table
            # and update the shared_count + mailbox_count in OrgIntegration.
            try:
                _sh_resp = await client.get(
                    f"{GRAPH_API_BASE}/users"
                    f"?$select=id,mail,displayName,userPrincipalName,accountEnabled,assignedLicenses"
                    f"&$top=999",
                    headers=headers,
                )
                if _sh_resp.status_code == 200:
                    _all_m365_users = _sh_resp.json().get("value", [])
                    # Shared mailboxes = M365 users with mail, no assigned licenses.
                    # NOTE: shared mailboxes are typically accountEnabled=False (they can't sign in)
                    # so we intentionally do NOT filter on accountEnabled here.
                    _shared = [
                        u for u in _all_m365_users
                        if u.get("mail")
                        and not u.get("assignedLicenses")
                    ]
                    _licensed_count = len([
                        u for u in _all_m365_users
                        if u.get("mail") and u.get("assignedLicenses")
                    ])
                    # Upsert shared mailboxes into email_groups with a "shared" tag
                    if _shared:
                        _shared_group_rows = [
                            {
                                "id": u.get("id", u["mail"]),
                                "email": u["mail"],
                                "name": u.get("displayName", u["mail"]),
                                "description": "Shared Mailbox",
                            }
                            for u in _shared
                        ]
                        await _upsert_shared_mailboxes_as_groups(db, org_id, _shared_group_rows, "m365")
                        logger.info(f"M365 delta: discovered {len(_shared)} shared mailboxes for org {org_id}")

                    # Update shared_count and total mailbox_count in OrgIntegration
                    from sqlalchemy import text as _shtxt
                    _total_mailboxes = _licensed_count + len(_shared)
                    await db.execute(_shtxt(
                        "UPDATE org_integrations SET shared_count = :sc, mailbox_count = :mc "
                        "WHERE org_id = :oid AND provider = 'm365'"
                    ), {"sc": len(_shared), "mc": _total_mailboxes, "oid": org_id})
                    # Also update org.mailbox_count for billing/pill display
                    await db.execute(_shtxt(
                        "UPDATE organizations SET mailbox_count = :mc WHERE id = :oid"
                    ), {"mc": _total_mailboxes, "oid": org_id})
                    await db.commit()
            except Exception as _she:
                logger.warning(f"M365 shared mailbox discovery failed (non-fatal): {_she}")

            # ── Per-user email scan (mirrors baseline_ingestion pattern) ──────
            # /me/messages doesn't work with app-level tokens — must use
            # /users/{email}/messages for each mailbox individually.
            from backend.services.policy_engine import evaluate_policies as _m365_eval
            from backend.services.policy_engine import apply_policy_action as _m365_apa
            from backend.services.quarantine_service import (
                block_to_trash_m365,
                quarantine_m365_message_with_fallback,
            )
            from backend.database import AsyncSessionLocal as _M365ASL
            import re as _m365_re, uuid as _m365_uuid, hashlib as _m365_hash
            from backend.models.db_models import Threat as _M365T

            # Build scan list: try Graph /users first; fall back to our DB if 403
            m365_scan_users: list[str] = []
            try:
                _scope_gid2 = integration.get("scope_group_id") or None
                if _scope_gid2:
                    _su_url = (f"{GRAPH_API_BASE}/groups/{_scope_gid2}/members"
                               f"?$select=mail,userPrincipalName,accountEnabled&$top=200")
                else:
                    _su_url = (f"{GRAPH_API_BASE}/users"
                               f"?$select=mail,userPrincipalName,accountEnabled&$top=200")
                _su_resp = await client.get(_su_url, headers=headers)
                if _su_resp.status_code == 200:
                    m365_scan_users = [
                        u.get("mail") or u.get("userPrincipalName", "")
                        for u in _su_resp.json().get("value", [])
                        if u.get("accountEnabled", True) and (u.get("mail") or u.get("userPrincipalName"))
                    ]
                    logger.info(f"M365 delta: Graph returned {len(m365_scan_users)} users")
                else:
                    logger.warning(f"M365 delta: Graph /users returned {_su_resp.status_code} "
                                   f"(app permissions not yet granted?) — falling back to DB users")
            except Exception as _sue:
                logger.warning(f"M365 delta: Graph user fetch error: {_sue}")

            # Fallback: use users already stored in our DB for this org/provider
            # ONLY fall back to DB when no scope group is set — otherwise we'd scan out-of-scope users
            if not m365_scan_users:
                _scope_gid2 = integration.get("scope_group_id") or None
                if _scope_gid2:
                    logger.warning(
                        f"M365 delta: scoped to group {_scope_gid2} but Graph API failed "
                        f"— skipping scan to avoid out-of-scope users"
                    )
                else:
                    try:
                        from backend.models.db_models import User as _DBUser
                        _db_users_res = await db.execute(
                            select(_DBUser.email).where(
                                _DBUser.org_id == integration["org_id"],
                                _DBUser.directory_provider == "m365",
                                _DBUser.is_active == True,
                            )
                        )
                        m365_scan_users = [r[0] for r in _db_users_res.fetchall() if r[0]]
                        logger.info(f"M365 delta: using {len(m365_scan_users)} DB users as fallback")
                        # Stamp mailbox_count from DB fallback so UI shows correct count
                        # even when Graph /users returns 403 (delegated-only permissions)
                        if m365_scan_users:
                            try:
                                from sqlalchemy import text as _fb_txt
                                await db.execute(
                                    _fb_txt(
                                        "UPDATE org_integrations SET mailbox_count = :mc "
                                        "WHERE org_id = :oid AND provider = 'm365'"
                                    ),
                                    {"mc": len(m365_scan_users), "oid": org_id},
                                )
                                await db.execute(
                                    _fb_txt(
                                        "UPDATE organizations SET mailbox_count = ("
                                        "SELECT COALESCE(SUM(mailbox_count),0) FROM org_integrations "
                                        "WHERE org_id = :oid AND status = 'active') WHERE id = :oid"
                                    ),
                                    {"oid": org_id},
                                )
                                await db.commit()
                                logger.info(f"M365 delta: stamped mailbox_count={len(m365_scan_users)} from DB fallback for org {org_id}")
                            except Exception as _fbe:
                                logger.warning(f"M365 delta: DB fallback mailbox_count stamp failed: {_fbe}")
                    except Exception as _dbe:
                        logger.warning(f"M365 delta: DB user fallback failed: {_dbe}")

            logger.info(f"M365 delta: scanning {len(m365_scan_users)} mailboxes since {since_iso}")

            for _m365_user_email in m365_scan_users:
                if not _m365_user_email:
                    continue
                try:
                    # Fetch messages from inbox only — /messages queries ALL folders
                    # including Sent Items which causes sender=recipient bugs for outbound mail
                    _msg_url = (
                        f"{GRAPH_API_BASE}/users/{_m365_user_email}/mailFolders/inbox/messages"
                        f"?$top=50"
                        f"&$filter=receivedDateTime ge {since_iso}"
                        f"&$select=id,sender,toRecipients,receivedDateTime,subject,"
                        f"hasAttachments,body,internetMessageHeaders,isDraft"
                        f"&$orderby=receivedDateTime desc"
                    )
                    _msg_resp = await client.get(_msg_url, headers=headers)

                    if _msg_resp.status_code == 401:
                        # Token expired mid-scan — refresh and retry
                        _new_tok = await _refresh_m365_token(refresh_token)
                        if _new_tok:
                            access_token = _new_tok
                            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
                            _msg_resp = await client.get(_msg_url, headers=headers)

                    if _msg_resp.status_code != 200:
                        logger.warning(f"M365 delta messages failed for {_m365_user_email}: "
                                       f"{_msg_resp.status_code} {_msg_resp.text[:150]}")
                        continue

                    _m365_msgs = _msg_resp.json().get("value", [])
                    logger.info(f"M365 delta: {len(_m365_msgs)} new messages for {_m365_user_email}")

                    for msg in _m365_msgs:
                        m365_msg_id = msg.get("id", "")
                        # Skip drafts
                        if msg.get("isDraft"):
                            continue
                        sender      = msg.get("sender", {}).get("emailAddress", {}).get("address", "")
                        recipients  = [r.get("emailAddress", {}).get("address", "")
                                       for r in msg.get("toRecipients", [])]
                        subject     = msg.get("subject", "")
                        received_at_str = msg.get("receivedDateTime", "")

                        # Extract + strip body
                        body_obj    = msg.get("body", {})
                        body_raw    = body_obj.get("content", "")
                        # Keep raw HTML for sandbox detonation before stripping for AI
                        body_html_raw = body_raw[:8000] if body_obj.get("contentType", "").lower() == "html" else ""
                        if body_obj.get("contentType", "").lower() == "html" and body_raw:
                            body_raw = _m365_re.sub(r'<[^>]+>', ' ', body_raw)
                            body_raw = _m365_re.sub(r'\s+', ' ', body_raw).strip()
                        body_content = body_raw[:8000]

                        # Parse auth headers + Reply-To from M365 internetMessageHeaders
                        auth_results = {"spf": "none", "dkim": "none", "dmarc": "none"}
                        reply_to_m365 = ""
                        for hdr in msg.get("internetMessageHeaders", []):
                            _hn = hdr.get("name", "").lower()
                            _hv = hdr.get("value", "")
                            if _hn == "authentication-results":
                                for _proto in ("spf", "dkim", "dmarc"):
                                    if f"{_proto}=pass" in _hv.lower():
                                        auth_results[_proto] = "pass"
                                    elif f"{_proto}=fail" in _hv.lower():
                                        auth_results[_proto] = "fail"
                            elif _hn == "reply-to":
                                reply_to_m365 = _hv.strip()

                        sender_domain_val = sender.split("@")[-1] if "@" in sender else sender

                        # Fetch attachment filenames if present
                        attachment_names: list[str] = []
                        if msg.get("hasAttachments"):
                            try:
                                _att_resp = await client.get(
                                    f"https://graph.microsoft.com/v1.0/users/{_m365_user_email}/messages/{m365_msg_id}/attachments",
                                    headers={"Authorization": f"Bearer {access_token}"},
                                    params={"$select": "name,contentType,size"},
                                )
                                if _att_resp.status_code == 200:
                                    attachment_names = [
                                        a.get("name", "")
                                        for a in _att_resp.json().get("value", [])
                                        if a.get("name")
                                    ]
                            except Exception:
                                pass  # non-fatal

                        # The inbox owner is _m365_user_email; use that as primary recipient
                        # but still loop others in case email was to a group
                        scan_recipients = [_m365_user_email] if _m365_user_email not in recipients else recipients
                        for _rcpt in scan_recipients:
                            email_data = {
                                "sender":        sender,
                                "sender_domain": sender_domain_val,
                                "recipient":     _rcpt,
                                "recipient_email": _rcpt,
                                "subject":       subject,
                                "body":          body_content,
                                "html_body":     body_html_raw,
                                "message_id":    m365_msg_id,
                                "date":          received_at_str,
                                "provider":      "m365",
                                "auth_results":  auth_results,
                                "has_attachment": msg.get("hasAttachments", False),
                                "attachments":   attachment_names,
                                "reply_to":      reply_to_m365,
                            }

                            # ── Policy evaluation ──────────────────────────────────
                            m365_matched_policy = None
                            async with _M365ASL() as _pol_db:
                                try:
                                    m365_matched_policy = await _m365_eval(
                                        email_data=email_data,
                                        org_id=org_id,
                                        db=_pol_db,
                                    )
                                    await _pol_db.commit()
                                except Exception as _pe:
                                    logger.warning(f"M365 policy eval failed {m365_msg_id}: {_pe}")

                            if m365_matched_policy:
                                _pa = m365_matched_policy.get("action", "")
                                logger.info(f"M365 policy '{m365_matched_policy['name']}' matched "
                                            f"action={_pa} on {m365_msg_id} for {_rcpt}")

                                if _pa in ("BLOCK", "BLOCK_DELETE"):
                                    # Move to Deleted Items immediately — skip AI
                                    try:
                                        _moved = await block_to_trash_m365(
                                            user_email=_m365_user_email,
                                            m365_message_id=m365_msg_id,
                                            access_token=access_token,
                                            org_id=str(org_id),
                                        )
                                        logger.info(f"M365 BLOCK: moved={_moved} {m365_msg_id} for {_m365_user_email}")
                                    except Exception as _bte:
                                        logger.warning(f"M365 block_to_trash failed: {_bte}")
                                    # Record threat row
                                    async with _M365ASL() as _bdb:
                                        try:
                                            _oid_uuid = _m365_uuid.UUID(org_id) if isinstance(org_id, str) else org_id
                                            _t = _M365T(
                                                org_id=_oid_uuid,
                                                email_message_id=m365_msg_id,
                                                sender=sender,
                                                sender_domain=sender_domain_val,
                                                recipient_email=_rcpt,
                                                subject=subject[:500] if subject else None,
                                                subject_hash=_m365_hash.sha256((subject or "").encode()).hexdigest()[:64],
                                                auth_results=auth_results,
                                                threat_type="POLICY_BLOCK",
                                                risk_score=100,
                                                status="resolved",
                                                action_taken="BLOCK_DELETE",
                                                ai_explanation_en=f"Blocked by policy: {m365_matched_policy['name']}",
                                                ai_explanation_ar=f"محجوب بموجب السياسة: {m365_matched_policy['name']}",
                                                detected_at=datetime.utcnow(),
                                                resolved_at=datetime.utcnow(),
                                            )
                                            try: _t.policy_id = m365_matched_policy.get("id")
                                            except Exception: pass
                                            _bdb.add(_t)
                                            await _bdb.commit()
                                        except Exception as _be:
                                            logger.warning(f"M365 block threat record failed: {_be}")
                                    continue  # skip AI for blocked email

                                elif _pa == "ALLOW":
                                    # ALLOW: skip AI — but store a CLEAN trace record so message trace shows it
                                    logger.info(f"M365 ALLOW: skipping AI for {m365_msg_id}")
                                    async with _M365ASL() as allow_db:
                                        try:
                                            _oid_allow = _m365_uuid.UUID(org_id) if isinstance(org_id, str) else org_id
                                            # Dedup check
                                            _exists = (await allow_db.execute(
                                                select(_M365T.id).where(
                                                    _M365T.email_message_id == m365_msg_id,
                                                    _M365T.org_id == _oid_allow
                                                )
                                            )).scalar_one_or_none()
                                            if not _exists:
                                                _allow_rec = _M365T(
                                                    org_id=_oid_allow,
                                                    email_message_id=m365_msg_id,
                                                    sender=sender,
                                                    sender_domain=sender_domain_val,
                                                    recipient_email=_rcpt,
                                                    subject=subject[:500] if subject else None,
                                                    subject_hash=_m365_hash.sha256((subject or "").encode()).hexdigest()[:64],
                                                    auth_results=auth_results,
                                                    threat_type="CLEAN",
                                                    risk_score=0,
                                                    status="resolved",
                                                    action_taken="ALLOW",
                                                    detected_at=datetime.utcnow(),
                                                )
                                                allow_db.add(_allow_rec)
                                                await allow_db.commit()
                                        except Exception as _ae:
                                            logger.debug(f"M365 ALLOW trace record failed (non-fatal): {_ae}")
                                    new_count += 1
                                    continue

                                # QUARANTINE / ALERT / TAG → run AI, then apply action
                                email_data["_matched_policy"] = m365_matched_policy

                            # ── AI threat detection ────────────────────────────────
                            m365_threat = None
                            async with _M365ASL() as _email_db:
                                try:
                                    m365_threat = await process_email(email_data, org_id, _email_db)
                                    await _email_db.commit()
                                except Exception as _pe:
                                    logger.warning(f"M365 process_email failed {m365_msg_id}: {_pe}")

                            # ── Apply policy action ────────────────────────────────
                            if m365_threat and m365_matched_policy:
                                async with _M365ASL() as _pa_db:
                                    try:
                                        await _m365_apa(
                                            policy=m365_matched_policy,
                                            threat_id=str(m365_threat.id),
                                            email_message_id=m365_msg_id,
                                            recipient_email=_m365_user_email,
                                            org_id=org_id,
                                            db=_pa_db,
                                            access_token=access_token,
                                            sender_email=sender,
                                            subject=subject,
                                            ai_explanation=m365_threat.ai_explanation_en or "",
                                            body_preview=body_content[:300],
                                            received_at=received_at_str,
                                            provider="m365",
                                        )
                                        await _pa_db.commit()
                                        logger.info(f"M365 policy action applied: {m365_matched_policy.get('action')} "
                                                    f"on {m365_msg_id} for {_m365_user_email}")
                                    except Exception as _pae:
                                        logger.warning(f"M365 policy apply failed: {_pae}")

                            # AI-determined quarantine (no policy, but AI flagged it)
                            elif m365_threat and m365_threat.action_taken in ("QUARANTINED", "QUARANTINE"):
                                try:
                                    await quarantine_m365_message_with_fallback(
                                        user_email=_m365_user_email,
                                        m365_message_id=m365_msg_id,
                                        access_token=access_token,
                                        org_id=str(org_id),
                                    )
                                    logger.info(f"M365 AI-quarantine: moved {m365_msg_id} for {_m365_user_email}")
                                except Exception as _qe:
                                    logger.debug(f"M365 AI-quarantine failed (non-fatal): {_qe}")

                        await _store_comm_edge(db, org_id, sender, recipients, received_at_str)
                        new_count += 1

                    # ── M365 DLP: Scan Sent Items for outbound email ──────────────────
                    try:
                        from backend.services.dlp_inline import scan_email_for_dlp, get_dlp_config
                        dlp_config = await get_dlp_config(org_id, db)
                        if dlp_config and dlp_config.enabled and dlp_config.scan_outbound:
                            _sent_url = (
                                f"{GRAPH_API_BASE}/users/{_m365_user_email}/mailFolders/sentItems/messages"
                                f"?$top=25"
                                f"&$filter=sentDateTime ge {since_iso}"
                                f"&$select=id,sender,toRecipients,sentDateTime,subject,body,hasAttachments,isDraft"
                                f"&$orderby=sentDateTime desc"
                            )
                            _sent_resp = await client.get(_sent_url, headers=headers)
                            if _sent_resp.status_code == 200:
                                _sent_msgs = _sent_resp.json().get("value", [])
                                logger.info(f"M365 DLP: scanning {len(_sent_msgs)} sent items for {_m365_user_email}")
                                
                                for sent_msg in _sent_msgs:
                                    if sent_msg.get("isDraft"):
                                        continue
                                    sent_id = sent_msg.get("id", "")
                                    sent_sender = sent_msg.get("sender", {}).get("emailAddress", {}).get("address", "")
                                    sent_recipients = [r.get("emailAddress", {}).get("address", "")
                                                       for r in sent_msg.get("toRecipients", [])]
                                    sent_subject = sent_msg.get("subject", "")
                                    sent_body_obj = sent_msg.get("body", {})
                                    sent_body = sent_body_obj.get("content", "")
                                    if sent_body_obj.get("contentType", "").lower() == "html":
                                        sent_body = _m365_re.sub(r'<[^>]+>', ' ', sent_body)
                                        sent_body = _m365_re.sub(r'\s+', ' ', sent_body).strip()
                                    
                                    # Get attachments with content for DLP
                                    sent_attachments = []
                                    if sent_msg.get("hasAttachments"):
                                        try:
                                            # Request attachment content (base64)
                                            _att_resp = await client.get(
                                                f"{GRAPH_API_BASE}/users/{_m365_user_email}/messages/{sent_id}/attachments",
                                                headers=headers,
                                                params={"$select": "name,contentType,contentBytes"},
                                            )
                                            if _att_resp.status_code == 200:
                                                for a in _att_resp.json().get("value", [])[:5]:  # Limit to 5 attachments
                                                    att_data = {
                                                        "name": a.get("name", ""),
                                                        "content_type": a.get("contentType", ""),
                                                    }
                                                    # Graph API returns standard base64 in contentBytes
                                                    if a.get("contentBytes"):
                                                        att_data["content_base64"] = a.get("contentBytes")
                                                        logger.debug(f"M365 DLP: Downloaded attachment '{a.get('name')}' for scanning")
                                                    sent_attachments.append(att_data)
                                        except Exception as _att_err:
                                            logger.debug(f"M365 DLP: attachment fetch error: {_att_err}")
                                    
                                    # Run DLP scan
                                    dlp_result = await scan_email_for_dlp(
                                        org_id=org_id,
                                        email_id=sent_id,
                                        subject=sent_subject,
                                        body=sent_body[:8000],
                                        sender=sent_sender,
                                        recipients=sent_recipients,
                                        attachments=sent_attachments,
                                        direction="outbound",
                                        db=db,
                                    )
                                    
                                    if dlp_result.get("action") not in ("allow", None):
                                        logger.info(f"M365 DLP: {sent_id} action={dlp_result.get('action')} categories={dlp_result.get('categories')}")
                    except Exception as _dlp_m365_err:
                        logger.debug(f"M365 DLP scan failed for {_m365_user_email}: {_dlp_m365_err}")

                except Exception as _m365_user_err:
                    logger.warning(f"M365 delta: error scanning {_m365_user_email}: {_m365_user_err}")

    # Log sync run to Redis history (keep last 20)
    import json as _json
    run_log = _json.dumps({
        "ts": now_ts,
        "provider": provider,
        "new_emails": new_count,
        "status": "ok",
    })
    await redis.lpush(f"sync_history:{org_id}", run_log)
    await redis.ltrim(f"sync_history:{org_id}", 0, 19)
    await redis.expire(f"sync_history:{org_id}", 7 * 86400)

    if new_count > 0:
        logger.info(f"Delta sync: {new_count} new emails for org {org_id} / {provider}")
    await redis.set(last_sync_key, str(now_ts), ex=86400)


async def _upsert_directory_groups(db, org_id: str, groups: list[dict], provider: str) -> None:
    """Upsert email groups discovered from Google Workspace or M365 into email_groups table."""
    from sqlalchemy import text as _text
    import uuid as _uuid

    try:
        org_uuid = _uuid.UUID(org_id) if isinstance(org_id, str) else org_id
        for g in groups:
            g_email = (g.get("email") or g.get("mail") or "").strip().lower()
            if not g_email:
                continue
            g_name = g.get("name") or g.get("displayName") or g_email
            g_desc = g.get("description") or ""
            g_count = int(g.get("directMembersCount") or g.get("member_count") or 0)
            g_ext_id = str(g.get("id") or "")

            await db.execute(_text("""
                INSERT INTO email_groups (id, org_id, provider, group_email, group_name,
                    description, member_count, external_id, last_synced_at)
                VALUES (gen_random_uuid(), :org_id, :provider, :email, :name,
                    :desc, :count, :ext_id, NOW())
                ON CONFLICT (org_id, group_email)
                DO UPDATE SET
                    group_name = EXCLUDED.group_name,
                    description = EXCLUDED.description,
                    member_count = EXCLUDED.member_count,
                    external_id = EXCLUDED.external_id,
                    last_synced_at = NOW()
            """), {
                "org_id": org_uuid, "provider": provider,
                "email": g_email, "name": g_name,
                "desc": g_desc, "count": g_count, "ext_id": g_ext_id,
            })
        logger.info(f"Upserted {len(groups)} groups for org {org_id} / {provider}")
    except Exception as e:
        logger.warning(f"_upsert_directory_groups failed: {e}")


async def _upsert_shared_mailboxes_as_groups(
    db, org_id: str, shared_mailboxes: list[dict], provider: str
) -> None:
    """
    Upsert M365 shared mailboxes into the email_groups table so they appear
    in the DL & Groups tab on the People / Inbox pages.
    Uses description="Shared Mailbox" to distinguish from DLs.
    """
    from sqlalchemy import text as _text
    import uuid as _uuid

    try:
        org_uuid = _uuid.UUID(org_id) if isinstance(org_id, str) else org_id
        for sm in shared_mailboxes:
            sm_email = (sm.get("email") or sm.get("mail") or "").strip().lower()
            if not sm_email:
                continue
            sm_name = sm.get("name") or sm.get("displayName") or sm_email
            sm_ext_id = str(sm.get("id") or sm_email)

            await db.execute(_text("""
                INSERT INTO email_groups (
                    id, org_id, provider, group_email, group_name,
                    description, member_count, external_id, last_synced_at
                )
                VALUES (
                    gen_random_uuid(), :org_id, :provider, :email, :name,
                    'Shared Mailbox', 0, :ext_id, NOW()
                )
                ON CONFLICT (org_id, group_email)
                DO UPDATE SET
                    group_name    = EXCLUDED.group_name,
                    description   = 'Shared Mailbox',
                    external_id   = EXCLUDED.external_id,
                    last_synced_at = NOW()
            """), {
                "org_id": org_uuid,
                "provider": provider,
                "email": sm_email,
                "name": sm_name,
                "ext_id": sm_ext_id,
            })
        await db.flush()
        logger.info(f"Upserted {len(shared_mailboxes)} shared mailboxes for org {org_id} / {provider}")
    except Exception as e:
        logger.warning(f"_upsert_shared_mailboxes_as_groups failed: {e}")


# ════════════════════════════════════════════════════════════════════════════
# Fast Outbound-Only DLP Sync (20 second interval)
# ════════════════════════════════════════════════════════════════════════════

async def _sync_outbound_only():
    """
    Fast sync that ONLY checks outbound (sent) emails for DLP.
    Designed for quick recall capability - runs every 20 seconds.
    Skips all inbound processing, directory sync, and group updates.
    """
    from backend.services.dlp_inline import scan_email_for_dlp, get_dlp_config
    import re as _re
    
    async with AsyncSessionLocal() as db:
        # Get all active integrations with DLP enabled
        result = await db.execute(
            text("""
                SELECT i.org_id, i.provider, i.access_token_enc, i.refresh_token_enc,
                       i.updated_at, o.dlp_enabled, o.dlp_scan_outbound
                FROM org_integrations i
                JOIN organizations o ON o.id = i.org_id
                WHERE i.status = 'active' 
                  AND o.dlp_enabled = true 
                  AND o.dlp_scan_outbound = true
            """)
        )
        integrations = result.fetchall()
        
        if not integrations:
            return
        
        now_ts = int(datetime.now(timezone.utc).timestamp())
        
        for row in integrations:
            org_id = str(row[0])
            provider = row[1]
            encrypted_token = row[2]
            encrypted_refresh = row[3]
            last_sync = row[4]
            
            # Use a shorter lookback for outbound-only (2 minutes)
            if last_sync:
                since_epoch = int(last_sync.timestamp()) - 30  # 30s overlap
            else:
                since_epoch = now_ts - 120  # 2 minutes
            since_iso = datetime.fromtimestamp(since_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    if provider == "google":
                        await _sync_gmail_outbound_dlp(
                            client, db, org_id, encrypted_token, encrypted_refresh, since_epoch
                        )
                    elif provider == "m365":
                        await _sync_m365_outbound_dlp(
                            client, db, org_id, encrypted_token, encrypted_refresh, since_iso
                        )
            except Exception as e:
                logger.debug(f"Outbound DLP sync error for org {org_id}: {e}")


async def _sync_gmail_outbound_dlp(client, db, org_id, encrypted_token, encrypted_refresh, since_epoch):
    """Fast Gmail sent-items-only DLP scan."""
    from backend.services.dlp_inline import scan_email_for_dlp, get_dlp_config
    import base64
    
    dlp_config = await get_dlp_config(org_id, db)
    if not dlp_config or not dlp_config.enabled:
        return
    
    # Get user list (cached ideally, but quick query)
    result = await db.execute(
        text("SELECT email FROM users WHERE org_id = :org_id AND is_active = true"),
        {"org_id": org_id}
    )
    users = [r[0] for r in result.fetchall()]
    
    # Get Google token
    access_token = _decrypt(encrypted_token)
    refresh_token = _decrypt(encrypted_refresh) if encrypted_refresh else None
    
    for user_email in users[:20]:  # Limit users per cycle
        try:
            # Try SA headers first, fallback to OAuth
            hdrs = await _get_sa_headers_async(user_email) or {"Authorization": f"Bearer {access_token}"}
            
            # Query only SENT messages since last sync
            resp = await client.get(
                f"{GMAIL_API_BASE}/users/{user_email}/messages",
                headers=hdrs,
                params={
                    "maxResults": 10,
                    "q": f"after:{since_epoch} in:sent",
                },
            )
            if resp.status_code != 200:
                continue
            
            messages = resp.json().get("messages", [])
            if messages:
                logger.info(f"Gmail outbound DLP: {len(messages)} sent messages for {user_email} since {since_epoch}")
            for msg_stub in messages:
                msg_id = msg_stub.get("id")
                
                # Check if already processed (simple dedup via Redis)
                # For now, just process - the DLP logger handles dedup
                
                # Get full message
                msg_resp = await client.get(
                    f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}",
                    headers=hdrs,
                    params={"format": "full"},
                )
                if msg_resp.status_code != 200:
                    continue
                
                msg_json = msg_resp.json()
                payload = msg_json.get("payload", {})
                hdrs_dict = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
                
                sender = _parse_email_addr(hdrs_dict.get("from", ""))
                recipients = [_parse_email_addr(r) for r in hdrs_dict.get("to", "").split(",") if r.strip()]
                subject = hdrs_dict.get("subject", "")
                
                # Extract body
                body = ""
                def _get_body(part):
                    nonlocal body
                    mime = part.get("mimeType", "")
                    data = part.get("body", {}).get("data", "")
                    if mime == "text/plain" and data and not body:
                        body = base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="ignore")
                    for sub in part.get("parts", []):
                        _get_body(sub)
                _get_body(payload)
                
                # Extract and download attachments
                attachments = []
                def _collect_atts(part):
                    fname = part.get("filename", "")
                    att_id = part.get("body", {}).get("attachmentId", "")
                    if fname and att_id:
                        attachments.append({"name": fname, "attachment_id": att_id, 
                                           "content_type": part.get("mimeType", "")})
                    for sub in part.get("parts", []):
                        _collect_atts(sub)
                _collect_atts(payload)
                
                dlp_attachments = []
                for att_info in attachments[:5]:
                    try:
                        att_resp = await client.get(
                            f"{GMAIL_API_BASE}/users/{user_email}/messages/{msg_id}/attachments/{att_info['attachment_id']}",
                            headers=hdrs,
                            timeout=10.0,
                        )
                        if att_resp.status_code == 200:
                            raw_b64 = att_resp.json().get("data", "")
                            std_b64 = raw_b64.replace("-", "+").replace("_", "/")
                            padding = 4 - len(std_b64) % 4
                            if padding != 4:
                                std_b64 += "=" * padding
                            dlp_attachments.append({
                                "name": att_info["name"],
                                "content_type": att_info["content_type"],
                                "content_base64": std_b64,
                            })
                    except Exception:
                        dlp_attachments.append({"name": att_info["name"], "content_type": att_info["content_type"]})
                
                # Run DLP scan with recall capability
                logger.info(f"Gmail outbound DLP: scanning msg {msg_id} from {sender} to {recipients} subj='{subject[:40]}' atts={len(dlp_attachments)}")
                from backend.services.dlp_inline import process_email_with_dlp
                dlp_result = await process_email_with_dlp(
                    org_id=org_id,
                    email_data={
                        "id": msg_id,
                        "subject": subject,
                        "body": body[:8000],
                        "sender": sender,
                        "recipients": recipients,
                        "attachments": dlp_attachments,
                        "provider": "google",
                    },
                    direction="outbound",
                    db=db,
                )
                logger.info(f"[OUTBOUND-DLP] Gmail {msg_id}: action={dlp_result.get('action')} cats={dlp_result.get('categories')}")
                
                if dlp_result.get("action") not in ("allow", None):
                    logger.warning(f"[OUTBOUND-DLP] POLICY VIOLATION: Gmail {msg_id}: action={dlp_result.get('action')} cats={dlp_result.get('categories')}. Executing {dlp_result.get('action')} action.")
                    
        except Exception as e:
            logger.debug(f"Gmail outbound DLP error for {user_email}: {e}")


async def _sync_m365_outbound_dlp(client, db, org_id, encrypted_token, encrypted_refresh, since_iso):
    """Fast M365 sent-items-only DLP scan."""
    from backend.services.dlp_inline import scan_email_for_dlp, get_dlp_config
    import re as _m365_re
    
    dlp_config = await get_dlp_config(org_id, db)
    if not dlp_config or not dlp_config.enabled:
        return
    
    access_token = _decrypt(encrypted_token)
    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    
    # Get users
    result = await db.execute(
        text("SELECT email FROM users WHERE org_id = :org_id AND is_active = true"),
        {"org_id": org_id}
    )
    users = [r[0] for r in result.fetchall()]
    
    for user_email in users[:20]:
        try:
            sent_url = (
                f"{GRAPH_API_BASE}/users/{user_email}/mailFolders/sentItems/messages"
                f"?$top=10"
                f"&$filter=sentDateTime ge {since_iso}"
                f"&$select=id,sender,toRecipients,sentDateTime,subject,body,hasAttachments,isDraft"
                f"&$orderby=sentDateTime desc"
            )
            resp = await client.get(sent_url, headers=headers)
            if resp.status_code != 200:
                continue
            
            messages = resp.json().get("value", [])
            
            for msg in messages:
                if msg.get("isDraft"):
                    continue
                
                msg_id = msg.get("id", "")
                sender = msg.get("sender", {}).get("emailAddress", {}).get("address", "")
                recipients = [r.get("emailAddress", {}).get("address", "") for r in msg.get("toRecipients", [])]
                subject = msg.get("subject", "")
                body_obj = msg.get("body", {})
                body = body_obj.get("content", "")
                if body_obj.get("contentType", "").lower() == "html":
                    body = _m365_re.sub(r'<[^>]+>', ' ', body)
                    body = _m365_re.sub(r'\s+', ' ', body).strip()
                
                # Get attachments with content
                attachments = []
                if msg.get("hasAttachments"):
                    try:
                        att_resp = await client.get(
                            f"{GRAPH_API_BASE}/users/{user_email}/messages/{msg_id}/attachments",
                            headers=headers,
                            params={"$select": "name,contentType,contentBytes"},
                        )
                        if att_resp.status_code == 200:
                            for a in att_resp.json().get("value", [])[:5]:
                                att_data = {"name": a.get("name", ""), "content_type": a.get("contentType", "")}
                                if a.get("contentBytes"):
                                    att_data["content_base64"] = a.get("contentBytes")
                                attachments.append(att_data)
                    except Exception:
                        pass
                
                # Run DLP scan
                dlp_result = await scan_email_for_dlp(
                    org_id=org_id,
                    email_id=msg_id,
                    subject=subject,
                    body=body[:8000],
                    sender=sender,
                    recipients=recipients,
                    attachments=attachments,
                    direction="outbound",
                    db=db,
                )
                
                if dlp_result.get("action") not in ("allow", None):
                    logger.info(f"[OUTBOUND-DLP] M365 {msg_id}: action={dlp_result.get('action')} cats={dlp_result.get('categories')}")
                    
        except Exception as e:
            logger.debug(f"M365 outbound DLP error for {user_email}: {e}")
