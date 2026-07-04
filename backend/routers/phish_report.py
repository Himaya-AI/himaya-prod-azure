"""
Phish Report Router — Helios Employee Phish Report Add-on.

Provides endpoints for:
  - Gmail Add-on and Outlook Add-in to submit phishing reports (no JWT, keyed by X-Phish-Report-Key)
  - Admins to get/rotate the org's phish report key (JWT required)
  - Add-on to query public org info (keyed by X-Phish-Report-Key)
"""
import logging
import secrets
import uuid as _uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import get_db
from backend.models.db_models import Organization, Threat
from backend.routers.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/phish-report", tags=["phish-report"])


# ── Helper ──────────────────────────────────────────────────────────────────

async def _get_org_by_key(key: Optional[str], db: AsyncSession) -> Organization:
    """Look up and validate an org by its phish_report_key. Raises 401 if not found."""
    if not key:
        raise HTTPException(status_code=401, detail="Missing X-Phish-Report-Key header")
    result = await db.execute(
        select(Organization).where(Organization.phish_report_key == key)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=401, detail="Invalid phish report key")
    if org.status != "active":
        raise HTTPException(status_code=403, detail="Organization is not active")
    return org


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/submit")
async def submit_phish_report(
    x_phish_report_key: Optional[str] = Header(None),
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Submit a phishing report from the Gmail Add-on or Outlook Add-in.
    Auth: X-Phish-Report-Key header (no JWT required).
    """
    org = await _get_org_by_key(x_phish_report_key, db)

    now = datetime.utcnow()
    reporter_email = body.get("reporter_email", "")
    provider = body.get("provider", "unknown")

    # Build threat_indicators with source metadata
    threat_indicators = {
        "source": "user_reported",
        "reporter_email": reporter_email,
        "user_reported_at": now.isoformat(),
        "provider": provider,
    }

    threat = Threat(
        id=_uuid.uuid4(),
        org_id=org.id,
        status="open",  # open = immediately visible in threat queue; auto-triage will re-score
        action_taken="USER_REPORTED",
        threat_type="UNKNOWN",
        threat_indicators=threat_indicators,
        email_message_id=body.get("message_id"),
        recipient_email=reporter_email,
        sender=body.get("sender"),
        sender_domain=body.get("sender_domain"),
        subject=body.get("subject"),
        email_body_preview=body.get("body_preview"),
        risk_score=50,  # Default for user-reported; auto-triage will re-score
        detected_at=now,
    )

    db.add(threat)
    await db.commit()
    await db.refresh(threat)

    threat_id = str(threat.id)
    logger.info(
        f"phish_report: new user-reported threat={threat_id} org={org.id} "
        f"reporter={reporter_email} provider={provider}"
    )

    # Quarantine the reported email immediately (non-blocking)
    message_id = body.get("message_id")
    if message_id and reporter_email:
        import asyncio
        is_m365 = provider == "outlook" or (len(message_id) > 100 or message_id.startswith("AAMk"))
        try:
            if is_m365:
                from backend.services.quarantine_service import quarantine_m365_message
                asyncio.create_task(quarantine_m365_message(
                    user_email=reporter_email,
                    m365_message_id=message_id,
                    org_id=str(org.id),
                ))
            else:
                from backend.services.quarantine_service import quarantine_gmail_message
                asyncio.create_task(quarantine_gmail_message(
                    user_email=reporter_email,
                    gmail_message_id=message_id,
                ))
        except Exception as _e:
            logger.debug(f"phish_report: quarantine failed (non-fatal): {_e}")

    return {
        "status": "received",
        "threat_id": threat_id,
        "message": "Report received. Our system is investigating this email.",
    }


@router.post("/submit-keyless")
async def submit_phish_report_keyless(
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Keyless phish report submission for the published Google Workspace Marketplace add-on.
    Auth: none — org is resolved by the reporter's email domain.
    This endpoint is safe to call without any API key; it resolves the tenant
    automatically from the reporter_email domain, so a single published add-on
    works across all Helios customers.
    """
    reporter_email = (body.get("reporter_email") or "").strip().lower()
    if not reporter_email or "@" not in reporter_email:
        raise HTTPException(status_code=400, detail="reporter_email is required")

    domain = reporter_email.split("@")[-1]

    # Look up org by primary domain OR by any integration's org_domain
    from backend.models.db_models import OrgIntegration
    org_result = await db.execute(
        select(Organization).where(
            Organization.domain == domain,
            Organization.status == "active",
        )
    )
    org = org_result.scalar_one_or_none()

    if not org:
        # Try matching against OrgIntegration.org_domain (catches M365 .onmicrosoft.com domains etc.)
        intg_result = await db.execute(
            select(OrgIntegration).where(
                OrgIntegration.org_domain == domain,
                OrgIntegration.status == "active",
            )
        )
        intg = intg_result.scalar_one_or_none()
        if intg:
            org_result2 = await db.execute(
                select(Organization).where(
                    Organization.id == intg.org_id,
                    Organization.status == "active",
                )
            )
            org = org_result2.scalar_one_or_none()

    if not org:
        # Don't reveal whether the domain is registered — return generic success
        # (prevents domain enumeration attacks)
        logger.warning(f"phish_report_keyless: no active org found for domain={domain}")
        return {
            "status": "received",
            "message": "Report received.",
        }

    now = datetime.utcnow()
    provider = body.get("provider", "gmail")

    threat_indicators = {
        "source": "user_reported",
        "reporter_email": reporter_email,
        "user_reported_at": now.isoformat(),
        "provider": provider,
    }

    threat = Threat(
        id=_uuid.uuid4(),
        org_id=org.id,
        status="open",  # open = immediately visible in threat queue
        action_taken="USER_REPORTED",
        threat_type="UNKNOWN",
        threat_indicators=threat_indicators,
        email_message_id=body.get("message_id"),
        recipient_email=reporter_email,
        sender=body.get("sender"),
        sender_domain=body.get("sender_domain"),
        subject=body.get("subject"),
        email_body_preview=body.get("body_preview"),
        risk_score=50,
        detected_at=now,
    )

    db.add(threat)
    await db.commit()
    await db.refresh(threat)

    threat_id = str(threat.id)
    logger.info(
        f"phish_report_keyless: threat={threat_id} org={org.id} "
        f"reporter={reporter_email} provider={provider}"
    )

    # Apply Helios-Review label (non-blocking)
    message_id = body.get("message_id")
    if message_id and reporter_email:
        import asyncio
        try:
            from backend.services.quarantine_service import apply_review_label_gmail
            asyncio.create_task(apply_review_label_gmail(
                user_email=reporter_email,
                gmail_message_id=message_id,
            ))
        except Exception as _e:
            logger.debug(f"phish_report_keyless: label failed (non-fatal): {_e}")

    return {
        "status": "received",
        "threat_id": threat_id,
        "message": "Report received. Our AI is investigating this email.",
        "org_name": org.name,
    }


@router.get("/org-info")
async def get_org_info(
    x_phish_report_key: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Return public org info for the add-on to display.
    Auth: X-Phish-Report-Key header.
    """
    org = await _get_org_by_key(x_phish_report_key, db)
    return {
        "org_name": org.name,
        "org_id": str(org.id),
        "helios_url": "https://app.himaya.ai",
    }


@router.post("/validate-key")
async def validate_phish_report_key(
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Validate an org's phish report key. Used by the Chrome extension popup
    to confirm the key is valid and show the org name.
    Auth: none — key is the credential.
    """
    key = (body.get("key") or "").strip()
    if not key:
        return {"valid": False}
    try:
        org = await _get_org_by_key(key, db)
        return {"valid": True, "org_name": org.name, "org_id": str(org.id)}
    except HTTPException:
        return {"valid": False}


@router.post("/addon/init", include_in_schema=False)
async def addon_init(
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
):
    """
    Silent token init for the Chrome extension.
    Resolves the org from the user's email domain and returns a short-lived JWT.
    No API key required — org lookup is by domain.
    """
    import jwt as pyjwt
    import os
    from datetime import timedelta

    user_email = (body.get("user_email") or "").strip().lower()
    if not user_email or "@" not in user_email:
        raise HTTPException(status_code=400, detail="user_email required")

    domain = user_email.split("@")[-1]

    # Look up org by domain
    from backend.models.db_models import OrgIntegration
    org_result = await db.execute(
        select(Organization).where(
            Organization.domain == domain,
            Organization.status == "active",
        )
    )
    org = org_result.scalar_one_or_none()

    if not org:
        intg_result = await db.execute(
            select(OrgIntegration).where(
                OrgIntegration.org_domain == domain,
                OrgIntegration.status == "active",
            )
        )
        intg = intg_result.scalar_one_or_none()
        if intg:
            org_result2 = await db.execute(
                select(Organization).where(
                    Organization.id == intg.org_id,
                    Organization.status == "active",
                )
            )
            org = org_result2.scalar_one_or_none()

    if not org:
        raise HTTPException(status_code=404, detail="Organization not found for domain")

    secret = os.environ.get("SECRET_KEY", "changeme")
    now = datetime.utcnow()
    payload = {
        "sub": user_email,
        "org_id": str(org.id),
        "org_name": org.name,
        "provider": body.get("provider", "gmail"),
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "scope": "addon",
    }
    token = pyjwt.encode(payload, secret, algorithm="HS256")
    return {"token": token, "org_id": str(org.id), "org_name": org.name}


@router.get("/key")
async def get_phish_report_key(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get (or auto-generate) the org's phish report key.
    Auth: JWT (admin or analyst role).
    """
    org_id = str(current_user.org_id) if hasattr(current_user, "org_id") else ""
    if not org_id:
        raise HTTPException(status_code=403, detail="No org_id in token")

    result = await db.execute(
        select(Organization).where(Organization.id == _uuid.UUID(org_id))
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Auto-generate key if not set
    if not org.phish_report_key:
        org.phish_report_key = secrets.token_urlsafe(32)
        await db.commit()
        await db.refresh(org)
        logger.info(f"phish_report: generated new key for org={org_id}")

    return {
        "key": org.phish_report_key,
        "org_id": str(org.id),
    }


@router.post("/key/rotate")
async def rotate_phish_report_key(
    current_user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Rotate the org's phish report key. Invalidates all existing add-on configurations.
    Auth: JWT (admin role only).
    """
    role = getattr(current_user, "role", current_user.get("role", "") if isinstance(current_user, dict) else "")
    if role not in ("admin", "super_admin"):
        raise HTTPException(status_code=403, detail="Admin role required")

    org_id = str(current_user.org_id) if hasattr(current_user, "org_id") else ""
    if not org_id:
        raise HTTPException(status_code=403, detail="No org_id in token")

    result = await db.execute(
        select(Organization).where(Organization.id == _uuid.UUID(org_id))
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    org.phish_report_key = secrets.token_urlsafe(32)
    await db.commit()
    await db.refresh(org)
    logger.info(f"phish_report: rotated key for org={org_id}")

    return {
        "key": org.phish_report_key,
        "org_id": str(org.id),
        "message": "Key rotated. Update all add-on configurations with the new key.",
    }


@router.get("/manifest.xml", response_class=Response)
async def get_outlook_manifest(
    key: str = Query(..., description="Phish report key for this org"),
    db: AsyncSession = Depends(get_db),
):
    """
    Serve a ready-to-upload Outlook add-in manifest XML with the org's UUID and phish key baked in.
    Microsoft 365 admin center can fetch this URL directly (no manual upload needed).
    Auth: keyed by ?key= query param (same phish report key).
    """
    org = await _get_org_by_key(key, db)
    org_id = str(org.id)
    taskpane_url = f"https://app.himaya.ai/addons/outlook/taskpane.html?key={key}"

    xml = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<OfficeApp xmlns="http://schemas.microsoft.com/office/appforoffice/1.1"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns:bt="http://schemas.microsoft.com/office/officeappbasictypes/1.0"
           xmlns:mailappor="http://schemas.microsoft.com/office/mailappversionoverrides/1.0"
           xsi:type="MailApp">
  <Id>{org_id}</Id>
  <Version>1.0.0.5</Version>
  <ProviderName>Himaya Technologies</ProviderName>
  <DefaultLocale>en-US</DefaultLocale>
  <DisplayName DefaultValue="Helios Phish Reporter"/>
  <Description DefaultValue="Report suspicious emails to your Helios security platform"/>
  <IconUrl DefaultValue="https://app.himaya.ai/himaya-3-32.png"/>
  <HighResolutionIconUrl DefaultValue="https://app.himaya.ai/himaya-3-80.png"/>
  <SupportUrl DefaultValue="https://app.himaya.ai"/>
  <AppDomains>
    <AppDomain>app.himaya.ai</AppDomain>
  </AppDomains>
  <Hosts>
    <Host Name="Mailbox"/>
  </Hosts>
  <Requirements>
    <Sets>
      <Set Name="Mailbox" MinVersion="1.1"/>
    </Sets>
  </Requirements>
  <FormSettings>
    <Form xsi:type="ItemRead">
      <DesktopSettings>
        <SourceLocation DefaultValue="{taskpane_url}"/>
        <RequestedHeight>250</RequestedHeight>
      </DesktopSettings>
    </Form>
  </FormSettings>
  <Permissions>ReadWriteItem</Permissions>
  <Rule xsi:type="ItemIs" ItemType="Message" FormType="Read"/>
  <DisableEntityHighlighting>false</DisableEntityHighlighting>
  <VersionOverrides xmlns="http://schemas.microsoft.com/office/mailappversionoverrides" xsi:type="VersionOverridesV1_0">
    <Requirements>
      <bt:Sets DefaultMinVersion="1.3">
        <bt:Set Name="Mailbox"/>
      </bt:Sets>
    </Requirements>
    <Hosts>
      <Host xsi:type="MailHost">
        <DesktopFormFactor>
          <ExtensionPoint xsi:type="MessageReadCommandSurface">
            <OfficeTab id="TabDefault">
              <Group id="helios.group.report">
                <Label resid="Group.Label"/>
                <Control xsi:type="Button" id="helios.button.reportPhishing">
                  <Label resid="Button.Label"/>
                  <Supertip>
                    <Title resid="Button.Label"/>
                    <Description resid="Button.Tooltip"/>
                  </Supertip>
                  <Icon>
                    <bt:Image size="16" resid="Icon.16x16"/>
                    <bt:Image size="32" resid="Icon.32x32"/>
                    <bt:Image size="80" resid="Icon.80x80"/>
                  </Icon>
                  <Action xsi:type="ShowTaskpane">
                    <SourceLocation resid="Taskpane.Url"/>
                  </Action>
                </Control>
              </Group>
            </OfficeTab>
          </ExtensionPoint>
        </DesktopFormFactor>
      </Host>
    </Hosts>
    <Resources>
      <bt:Images>
        <bt:Image id="Icon.16x16" DefaultValue="https://app.himaya.ai/himaya-3-16.png"/>
        <bt:Image id="Icon.32x32" DefaultValue="https://app.himaya.ai/himaya-3-32.png"/>
        <bt:Image id="Icon.80x80" DefaultValue="https://app.himaya.ai/himaya-3-80.png"/>
      </bt:Images>
      <bt:Urls>
        <bt:Url id="Taskpane.Url" DefaultValue="{taskpane_url}"/>
      </bt:Urls>
      <bt:ShortStrings>
        <bt:String id="Group.Label" DefaultValue="Helios Security"/>
        <bt:String id="Button.Label" DefaultValue="Report Phishing"/>
      </bt:ShortStrings>
      <bt:LongStrings>
        <bt:String id="Button.Tooltip" DefaultValue="Report this email as suspicious to your Helios security platform."/>
      </bt:LongStrings>
    </Resources>
  </VersionOverrides>
</OfficeApp>"""

    return Response(
        content=xml,
        media_type="application/xml",
        headers={
            "Content-Disposition": "attachment; filename=helios-phish-reporter-manifest.xml",
            # Allow Microsoft's admin center to fetch this cross-origin
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
        },
    )

# ── Taskpane HTML served from API domain ──────────────────────────────────────
# Outlook add-in manifest declares AppDomain as app.himaya.ai, so the
# taskpane must also be served from that domain — not CloudFront.

TASKPANE_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<meta http-equiv="Content-Security-Policy" content="default-src 'self' https://app.himaya.ai; script-src 'self' 'unsafe-inline' https://appsforoffice.microsoft.com https://ajax.aspnetcdn.com; style-src 'self' 'unsafe-inline'; img-src 'self' https://app.himaya.ai data:; connect-src 'self' https://app.himaya.ai https://appsforoffice.microsoft.com;"/>
<title>Helios Phish Reporter</title>
<script src="https://appsforoffice.microsoft.com/lib/1/hosted/office.js" type="text/javascript"></script>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', -apple-system, Arial, sans-serif; background: #ffffff; color: #1a1a2e; font-size: 13px; line-height: 1.5; }
.header { background: #0f172a; padding: 14px 16px; display: flex; align-items: center; gap: 10px; border-bottom: 2px solid #2563eb; }
.header-text { color: #f8fafc; font-size: 13px; font-weight: 600; }
.header-sub { color: #94a3b8; font-size: 10px; margin-top: 1px; }
.body { padding: 20px 16px; }
.section-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; margin-bottom: 8px; }
.description { color: #475569; font-size: 12px; line-height: 1.6; margin-bottom: 20px; padding: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; }
.btn-report { width: 100%; padding: 10px 16px; background: #dc2626; color: #fff; border: none; border-radius: 3px; font-size: 13px; font-weight: 600; cursor: pointer; transition: background 0.15s; }
.btn-report:hover:not(:disabled) { background: #b91c1c; }
.btn-report:disabled { background: #cbd5e1; color: #94a3b8; cursor: not-allowed; }
.btn-report.success { background: #15803d; }
.status { margin-top: 12px; padding: 10px 12px; border-radius: 3px; font-size: 12px; display: none; border-left: 3px solid transparent; }
.status.success { display: block; background: #f0fdf4; border-left-color: #16a34a; color: #15803d; }
.status.error { display: block; background: #fef2f2; border-left-color: #dc2626; color: #b91c1c; }
.status.warning { display: block; background: #fffbeb; border-left-color: #d97706; color: #92400e; }
.footer { position: fixed; bottom: 0; left: 0; right: 0; padding: 10px 16px; background: #f8fafc; border-top: 1px solid #e2e8f0; font-size: 10px; color: #94a3b8; text-align: center; }
.footer a { color: #3b82f6; text-decoration: none; }
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="header-text">Helios Phish Reporter</div>
    <div class="header-sub">Himaya Technologies</div>
  </div>
</div>
<div class="body">
  <div class="section-title">Report Suspicious Email</div>
  <div class="description">If this email appears to be a phishing attempt, social engineering, or business email compromise, submit it for analysis.</div>
  <button class="btn-report" id="reportBtn" disabled onclick="reportPhishing()">Report as Phishing</button>
  <div class="status" id="status"></div>
</div>
<div class="footer">Helios by <a href="https://app.himaya.ai" target="_blank">Himaya Technologies</a></div>
<script>
var HELIOS_API = 'https://app.himaya.ai';
function getKey() { try { return new URLSearchParams(window.location.search).get('key') || ''; } catch(e) { return ''; } }
Office.onReady(function(info) {
  if (info.host === Office.HostType.Outlook) {
    var key = getKey();
    if (!key) {
      var s = document.getElementById('status'); s.className = 'status warning';
      s.textContent = 'Add-in not configured. Please reinstall using the URL from your IT admin.';
    } else { document.getElementById('reportBtn').disabled = false; }
  }
});
function reportPhishing() {
  var btn = document.getElementById('reportBtn'), status = document.getElementById('status'), key = getKey();
  if (!key) { status.className = 'status error'; status.textContent = 'Missing report key. Please reinstall the add-in.'; return; }
  btn.disabled = true; btn.textContent = 'Submitting...'; status.className = 'status'; status.style.display = 'none';
  var item = Office.context.mailbox.item, reporterEmail = '';
  try { reporterEmail = Office.context.mailbox.userProfile.emailAddress; } catch(e) {}
  var bodyFetched = false;
  var t = setTimeout(function() { if (!bodyFetched) doSubmit('', item, reporterEmail, key, btn, status); }, 3000);
  try {
    item.body.getAsync(Office.CoercionType.Text, function(r) {
      bodyFetched = true; clearTimeout(t);
      doSubmit(r && r.value ? r.value.substring(0,500) : '', item, reporterEmail, key, btn, status);
    });
  } catch(e) { bodyFetched = true; clearTimeout(t); doSubmit('', item, reporterEmail, key, btn, status); }
}
function doSubmit(bodyPreview, item, reporterEmail, key, btn, status) {
  var senderEmail = '', subject = '', messageId = '', receivedAt = new Date().toISOString();
  try { senderEmail = item.from ? (item.from.emailAddress || '') : ''; } catch(e) {}
  try { subject = item.subject || ''; } catch(e) {}
  try { messageId = item.itemId || ''; } catch(e) {}
  try { if (item.dateTimeCreated) receivedAt = item.dateTimeCreated.toISOString(); } catch(e) {}
  fetch(HELIOS_API + '/api/phish-report/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Phish-Report-Key': key },
    body: JSON.stringify({ reporter_email: reporterEmail, subject: subject, sender: senderEmail,
      sender_domain: senderEmail.indexOf('@') > -1 ? senderEmail.split('@').pop() : '',
      body_preview: bodyPreview, message_id: messageId, received_at: receivedAt, provider: 'outlook' })
  })
  .then(function(r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
  .then(function() {
    try { item.moveToAsync(Office.MailboxEnums.MoveToFolderType.DeletedItems, function() {}); } catch(e) {}
    btn.textContent = 'Reported'; btn.className = 'btn-report success';
    status.className = 'status success';
    status.textContent = 'Report submitted. Your security team has been notified.';
  })
  .catch(function(err) {
    status.className = 'status error';
    status.textContent = 'Submission failed' + (err.message ? ' (' + err.message + ')' : '') + '. Please try again.';
    btn.disabled = false; btn.textContent = 'Report as Phishing'; btn.className = 'btn-report';
  });
}
</script>
</body>
</html>"""

@router.get("/addons/outlook/taskpane.html", include_in_schema=False)
async def serve_taskpane():
    """Serve the Outlook add-in taskpane HTML from the API domain.
    Must be served from app.himaya.ai since that is the AppDomain in the manifest.
    """
    return Response(
        content=TASKPANE_HTML,
        media_type="text/html",
        headers={
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-store",
            "X-Frame-Options": "ALLOWALL",
        },
    )
