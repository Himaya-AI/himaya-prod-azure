"""
Himaya Helios Email Service — Azure Communication Email primary, Amazon SES fallback.
All transactional emails go through this service.
"""
import os
import base64 as _b64
import email as _email_module
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import boto3
from botocore.exceptions import ClientError
import logging
from typing import Optional

# Real Himaya logo (PNG) — loaded once at module level
_LOGO_PATH = os.path.join(os.path.dirname(__file__), "himaya_logo.png")
_LOGO_BYTES: bytes = b""
try:
    with open(_LOGO_PATH, "rb") as _f:
        _LOGO_BYTES = _f.read()
except Exception:
    pass

logger = logging.getLogger(__name__)

SES_CLIENT = boto3.client("ses", region_name=os.getenv("SES_REGION", "us-east-1"))
AZURE_COMMUNICATION_CONNECTION_STRING = os.getenv("AZURE_COMMUNICATION_CONNECTION_STRING", "")
FROM_EMAIL = "noreply@himaya.ai"
FROM_NAME = "Himaya Helios"
REPLY_TO = "support@himaya.ai"

# ─── Shared brand constants ────────────────────────────────────────────────────
BG        = "#0a0f1e"
CARD      = "#0d1b2e"
BORDER    = "#1a2744"
BLUE      = "#3b6ef6"
RED       = "#e94560"
GREEN     = "#4ade80"
WHITE     = "#ffffff"
MUTED     = "#a1a1aa"
FONT      = "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"

LOGO_HTML = """
<table cellpadding="0" cellspacing="0" border="0" align="center" style="margin:0 auto;">
  <tr>
    <td align="center">
      <img src="cid:himaya-logo"
           alt="Himaya Helios"
           width="180"
           style="display:block;max-width:180px;height:auto;border:0;outline:none;text-decoration:none;" />
    </td>
  </tr>
</table>
"""

def _footer() -> str:
    return f"""
    <tr><td style="background:{BG};padding:24px 40px;border-top:1px solid {BORDER};">
      <p style="margin:0 0 6px;color:{MUTED};font-size:11px;text-align:center;font-family:{FONT};">
        © 2026 Himaya Technologies Group Inc. — All rights reserved.
      </p>
      <p style="margin:0 0 6px;color:{MUTED};font-size:11px;text-align:center;font-family:{FONT};">
        Himaya Helios ·
        <a href="https://app.himaya.ai" style="color:{BLUE};text-decoration:none;">app.himaya.ai</a>
      </p>

      <p style="margin:0;font-size:11px;text-align:center;font-family:{FONT};">
        <a href="https://app.himaya.ai/notifications" style="color:{MUTED};text-decoration:underline;">
          Manage notification preferences
        </a>
      </p>
    </td></tr>
    """


def _build_mime_message(to: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bytes:
    """Build the raw MIME message used by both Azure and SES."""
    root = MIMEMultipart("related")
    root["Subject"] = subject
    root["From"] = f"{FROM_NAME} <{FROM_EMAIL}>"
    root["To"] = to
    root["Reply-To"] = REPLY_TO

    alt = MIMEMultipart("alternative")
    root.attach(alt)
    if text_body:
        alt.attach(MIMEText(text_body, "plain", "utf-8"))
    alt.attach(MIMEText(html_body, "html", "utf-8"))

    if _LOGO_BYTES:
        img = MIMEImage(_LOGO_BYTES, "png")
        img.add_header("Content-ID", "<himaya-logo>")
        img.add_header("Content-Disposition", "inline", filename="himaya-logo.png")
        root.attach(img)

    return root.as_bytes()


def send_email(to: str, subject: str, html_body: str, text_body: Optional[str] = None) -> bool:
    """Send email via Azure Communication Email if configured, otherwise Amazon SES."""
    raw = _build_mime_message(to, subject, html_body, text_body)

    # Try Azure Communication Email first
    if AZURE_COMMUNICATION_CONNECTION_STRING:
        try:
            from azure.communication.email import EmailClient

            client = EmailClient.from_connection_string(AZURE_COMMUNICATION_CONNECTION_STRING)
            poller = client.begin_send(
                {
                    "senderAddress": FROM_EMAIL,
                    "recipients": {"to": [{"address": to}]},
                    "content": {"subject": subject, "html": html_body, "plainText": text_body or ""},
                    "attachments": [],
                }
            )
            result = poller.result()
            logger.info(f"Email sent to {to} via Azure Communication: {result}")
            return True
        except Exception as e:
            logger.warning(f"Azure Communication Email failed, falling back to SES: {e}")

    # Fallback to SES
    try:
        response = SES_CLIENT.send_raw_email(
            Source=f"{FROM_NAME} <{FROM_EMAIL}>",
            Destinations=[to],
            RawMessage={"Data": raw},
            ConfigurationSetName="himaya-helios-transactional",
        )
        logger.info(f"Email sent to {to} via SES: {response['MessageId']}")
        return True
    except ClientError as e:
        logger.error(f"SES error sending to {to}: {e}")
        print(f"\n[EMAIL FALLBACK - SES failed]\nTo: {to}\nSubject: {subject}\n")
        return False


def send_admin_otp(to_email: str, otp: str) -> bool:
    """Send admin login OTP — Vendor Portal"""
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{BG};font-family:{FONT};">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};padding:48px 20px;">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="max-width:560px;background:{CARD};border-radius:16px;border:1px solid {BORDER};overflow:hidden;">

        <!-- Header -->
        <tr><td style="background:{CARD};padding:36px 40px 28px;text-align:center;border-bottom:2px solid {BLUE};">
          {LOGO_HTML}
          <p style="margin:12px 0 0;color:{MUTED};font-size:11px;letter-spacing:2px;text-transform:uppercase;font-family:{FONT};">
            Vendor Portal
          </p>
        </td></tr>

        <!-- Body -->
        <tr><td style="padding:40px;">
          <h2 style="margin:0 0 8px;color:{WHITE};font-size:20px;font-weight:700;font-family:{FONT};">
            Admin Login Verification
          </h2>
          <p style="margin:0 0 32px;color:{MUTED};font-size:14px;line-height:1.7;font-family:{FONT};">
            Enter the code below to complete sign-in to the Himaya Helios Vendor Portal.
            This code expires in <strong style="color:{WHITE};">10 minutes</strong>.
          </p>

          <!-- OTP box -->
          <div style="background:{BG};border:2px solid {BLUE};border-radius:14px;padding:32px 24px;text-align:center;margin-bottom:32px;">
            <p style="margin:0 0 8px;color:{MUTED};font-size:11px;letter-spacing:2px;text-transform:uppercase;font-family:{FONT};">
              One-Time Passcode
            </p>
            <div style="font-size:54px;font-weight:800;letter-spacing:18px;color:{BLUE};font-family:'Courier New',Courier,monospace;line-height:1.2;">
              {otp}
            </div>
          </div>

          <p style="margin:0;color:{MUTED};font-size:12px;line-height:1.6;font-family:{FONT};">
            ️ If you did not request this code, someone may be attempting to access your account.
            <strong style="color:{WHITE};">Do not share this code</strong> with anyone, including Himaya support.
          </p>
        </td></tr>

        {_footer()}
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    text = (
        f"Himaya Helios — Vendor Portal\n\n"
        f"Admin Login Verification\n\n"
        f"Your one-time passcode: {otp}\n\n"
        f"This code expires in 10 minutes. Do not share it with anyone.\n\n"
        f"© 2026 Himaya Technologies Group Inc. — app.himaya.ai"
    )
    return send_email(to_email, "Himaya Helios — Admin Login Code", html, text)


def send_threat_alert(to_email: str, org_name: str, threat_type: str,
                      risk_score: int, recipient: str, action: str,
                      detection_time: Optional[str] = None) -> bool:
    """Send threat detection alert to org admin"""
    severity = "CRITICAL" if risk_score >= 90 else "HIGH" if risk_score >= 70 else "MEDIUM"
    sev_color = RED if severity == "CRITICAL" else "#f97316" if severity == "HIGH" else "#facc15"
    risk_color = RED if risk_score >= 90 else "#f97316" if risk_score >= 70 else "#facc15"
    detection_time_str = detection_time or "Just now"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{BG};font-family:{FONT};">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};padding:48px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:{CARD};border-radius:16px;border:1px solid {BORDER};overflow:hidden;">

        <!-- Severity bar -->
        <tr><td style="background:{sev_color};height:5px;font-size:0;line-height:0;">&nbsp;</td></tr>

        <!-- Header -->
        <tr><td style="background:{CARD};padding:28px 40px;border-bottom:1px solid {BORDER};">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td style="vertical-align:middle;">
                {LOGO_HTML}
              </td>
              <td align="right" style="vertical-align:middle;">
                <span style="background:{sev_color};color:#000000;font-size:11px;font-weight:800;
                             padding:5px 12px;border-radius:6px;letter-spacing:1px;font-family:{FONT};">
                  {severity}
                </span>
              </td>
            </tr>
          </table>
        </td></tr>

        <!-- Alert title -->
        <tr><td style="padding:28px 40px 0;">
          <h2 style="margin:0 0 4px;color:{WHITE};font-size:22px;font-weight:700;font-family:{FONT};">
            ️ Threat Detected
          </h2>
          <p style="margin:0;color:{MUTED};font-size:13px;font-family:{FONT};">{org_name}</p>
        </td></tr>

        <!-- Threat badge -->
        <tr><td style="padding:16px 40px 0;">
          <span style="display:inline-block;background:{BG};border:1px solid {sev_color};color:{sev_color};
                       font-size:13px;font-weight:700;padding:6px 16px;border-radius:8px;font-family:{FONT};">
            {threat_type}
          </span>
        </td></tr>

        <!-- Details table -->
        <tr><td style="padding:24px 40px 32px;">
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
            <tr>
              <td style="padding:12px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;
                         width:160px;font-family:{FONT};">Threat Type</td>
              <td style="padding:12px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;
                         font-weight:600;font-family:{FONT};">{threat_type}</td>
            </tr>
            <tr>
              <td style="padding:12px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;
                         font-family:{FONT};">Risk Score</td>
              <td style="padding:12px 0;border-bottom:1px solid {BORDER};font-family:{FONT};">
                <span style="color:{risk_color};font-size:13px;font-weight:700;">{risk_score}</span>
                <span style="color:{MUTED};font-size:13px;">/100</span>
              </td>
            </tr>
            <tr>
              <td style="padding:12px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;
                         font-family:{FONT};">Target Recipient</td>
              <td style="padding:12px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;
                         font-family:{FONT};">{recipient}</td>
            </tr>
            <tr>
              <td style="padding:12px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;
                         font-family:{FONT};">Action Taken</td>
              <td style="padding:12px 0;border-bottom:1px solid {BORDER};color:{GREEN};font-size:13px;
                         font-weight:600;font-family:{FONT};"> {action}</td>
            </tr>
            <tr>
              <td style="padding:12px 0;color:{MUTED};font-size:13px;font-family:{FONT};">Detection Time</td>
              <td style="padding:12px 0;color:{WHITE};font-size:13px;font-family:{FONT};">{detection_time_str}</td>
            </tr>
          </table>

          <!-- CTA -->
          <div style="margin-top:28px;">
            <a href="https://app.himaya.ai/threats"
               style="display:inline-block;background:{BLUE};color:{WHITE};text-decoration:none;
                      padding:12px 28px;border-radius:10px;font-size:14px;font-weight:700;
                      letter-spacing:0.2px;font-family:{FONT};">
              View in Dashboard →
            </a>
          </div>
        </td></tr>

        <!-- Arabic summary -->
        <tr><td style="padding:20px 40px;background:{BG};border-top:1px solid {BORDER};border-bottom:1px solid {BORDER};">
          <p style="margin:0 0 6px;color:{MUTED};font-size:10px;letter-spacing:1px;text-transform:uppercase;font-family:{FONT};">
            Arabic Summary / ملخص بالعربية
          </p>
          <p style="margin:0;color:{MUTED};font-size:13px;line-height:1.8;text-align:right;direction:rtl;font-family:Tahoma,Arial,sans-serif;">
            تم اكتشاف تهديد إلكتروني من نوع <strong style="color:{WHITE};">{threat_type}</strong> بدرجة خطورة {risk_score}/100.
            <br>تم تطبيق الإجراء التالي تلقائيًا: <strong style="color:{GREEN};">{action}</strong>.
            <br>يُرجى مراجعة لوحة التحكم للاطلاع على التفاصيل الكاملة واتخاذ أي إجراء إضافي.
          </p>
        </td></tr>

        {_footer()}
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    return send_email(
        to_email,
        f"[{severity}] {threat_type} — Threat Detected · Himaya Helios",
        html
    )


def send_welcome_email(to_email: str, org_name: str, contact_name: str,
                       activation_url: str, onboarding_url: str) -> bool:
    """Send welcome / account activation email to newly provisioned customer"""
    # Real Himaya logo served from app.himaya.ai
    inline_logo = LOGO_HTML

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{BG};font-family:{FONT};">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};padding:48px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:{CARD};border-radius:16px;border:1px solid {BORDER};overflow:hidden;">

        <!-- Header -->
        <tr><td style="padding:36px 40px 28px;text-align:center;border-bottom:1px solid {BORDER};">
          {inline_logo}
        </td></tr>

        <!-- Body -->
        <tr><td style="padding:36px 40px 32px;">
          <h1 style="margin:0 0 8px;color:{WHITE};font-size:22px;font-weight:700;font-family:{FONT};line-height:1.3;">
            Your account is ready
          </h1>
          <p style="margin:0 0 6px;color:{MUTED};font-size:13px;font-family:{FONT};">
            Himaya Helios — AI-Powered Email Security
          </p>

          <hr style="border:none;border-top:1px solid {BORDER};margin:24px 0;" />

          <p style="margin:0 0 6px;color:{WHITE};font-size:15px;font-weight:600;font-family:{FONT};">
            Hi {contact_name},
          </p>
          <p style="margin:0 0 28px;color:{MUTED};font-size:14px;line-height:1.75;font-family:{FONT};">
            Your Himaya Helios account for <strong style="color:{WHITE};">{org_name}</strong> has been
            provisioned. Click the button below to set your password and access the platform.
          </p>

          <!-- Primary CTA -->
          <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:12px;">
            <tr><td align="center">
              <a href="{activation_url}"
                 style="display:inline-block;background:{BLUE};color:{WHITE};text-decoration:none;
                        padding:14px 44px;border-radius:10px;font-size:15px;font-weight:700;
                        font-family:{FONT};letter-spacing:0.2px;">
                Set Password &amp; Sign In
              </a>
            </td></tr>
          </table>
          <p style="margin:0 0 32px;color:{MUTED};font-size:11px;text-align:center;font-family:{FONT};">
            Link expires in 72 hours. Do not share this email.
          </p>

          <!-- Feature list — no emojis, clean text rows -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:32px;border:1px solid {BORDER};border-radius:10px;overflow:hidden;">
            <tr style="background:{BG};">
              <td style="padding:14px 18px;border-bottom:1px solid {BORDER};">
                <p style="margin:0;color:{WHITE};font-size:13px;font-weight:600;font-family:{FONT};">AI Threat Detection</p>
                <p style="margin:2px 0 0;color:{MUTED};font-size:12px;font-family:{FONT};">Real-time analysis of inbound email for phishing, BEC, and malware</p>
              </td>
            </tr>
            <tr style="background:{BG};">
              <td style="padding:14px 18px;border-bottom:1px solid {BORDER};">
                <p style="margin:0;color:{WHITE};font-size:13px;font-weight:600;font-family:{FONT};">Compliance Mapping</p>
                <p style="margin:2px 0 0;color:{MUTED};font-size:12px;font-family:{FONT};">Built-in NCA ECC, ISO 27001, and GDPR compliance reporting</p>
              </td>
            </tr>
            <tr style="background:{BG};">
              <td style="padding:14px 18px;">
                <p style="margin:0;color:{WHITE};font-size:13px;font-weight:600;font-family:{FONT};">Real-time Monitoring</p>
                <p style="margin:2px 0 0;color:{MUTED};font-size:12px;font-family:{FONT};">Live threat feed, delta sync every 2 minutes, instant alerts</p>
              </td>
            </tr>
          </table>

          <!-- Secondary CTA -->
          <table cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:28px;">
            <tr><td align="center">
              <a href="{onboarding_url}"
                 style="display:inline-block;background:transparent;color:{BLUE};text-decoration:none;
                        padding:11px 28px;border-radius:10px;font-size:13px;font-weight:600;
                        border:1px solid {BLUE};font-family:{FONT};">
                Start Onboarding
              </a>
            </td></tr>
          </table>

          <p style="margin:0;color:{MUTED};font-size:12px;line-height:1.6;text-align:center;font-family:{FONT};">
            Questions? Contact us at
            <a href="mailto:support@himaya.ai" style="color:{BLUE};text-decoration:none;">support@himaya.ai</a>
          </p>
        </td></tr>

        {_footer()}
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    text = (
        f"Welcome to Himaya Helios\n\n"
        f"Hi {contact_name},\n\n"
        f"Your account for {org_name} is ready. Set your password at the link below:\n\n"
        f"{activation_url}\n\n"
        f"This link expires in 72 hours.\n\n"
        f"Start onboarding: {onboarding_url}\n\n"
        f"Questions? support@himaya.ai\n\n"
        f"© 2026 Himaya Technologies Group Inc. — app.himaya.ai"
    )
    return send_email(to_email, "Your Himaya Helios account is ready", html, text)


def send_weekly_report(to_email: str, org_name: str, week_start: str, week_end: str,
                       emails_scanned: int, threats_detected: int, threats_blocked: int,
                       top_threat_type: str, risk_trend: str) -> bool:
    """Send weekly security summary report to org admin"""
    blocked_pct = round((threats_blocked / threats_detected * 100) if threats_detected > 0 else 100)

    # Trend indicator
    trend_lower = risk_trend.lower()
    if trend_lower in ("increasing", "up", "rising"):
        trend_icon = "↑"
        trend_color = RED
        trend_label = "Increasing"
    elif trend_lower in ("decreasing", "down", "falling", "improving"):
        trend_icon = "↓"
        trend_color = GREEN
        trend_label = "Decreasing"
    else:
        trend_icon = "→"
        trend_color = "#facc15"
        trend_label = "Stable"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{BG};font-family:{FONT};">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};padding:48px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:{CARD};border-radius:16px;border:1px solid {BORDER};overflow:hidden;">

        <!-- Header -->
        <tr><td style="background:{CARD};padding:36px 40px 28px;text-align:center;border-bottom:2px solid {BLUE};">
          {LOGO_HTML}
          <h1 style="margin:20px 0 4px;color:{WHITE};font-size:22px;font-weight:800;font-family:{FONT};">
            Your Weekly Security Report
          </h1>
          <p style="margin:0;color:{MUTED};font-size:13px;font-family:{FONT};">
            {org_name} · {week_start} – {week_end}
          </p>
        </td></tr>

        <!-- Body -->
        <tr><td style="padding:36px 40px;">

          <!-- 4 Stat boxes -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
            <tr>
              <td width="48%" style="text-align:center;padding:20px 12px;background:{BG};
                                     border-radius:12px;border:1px solid {BORDER};">
                <p style="margin:0 0 4px;color:{MUTED};font-size:10px;text-transform:uppercase;
                          letter-spacing:1px;font-family:{FONT};">Emails Scanned</p>
                <p style="margin:0;color:{BLUE};font-size:32px;font-weight:800;font-family:{FONT};">
                  {emails_scanned:,}
                </p>
              </td>
              <td width="4%"></td>
              <td width="48%" style="text-align:center;padding:20px 12px;background:{BG};
                                     border-radius:12px;border:1px solid {BORDER};">
                <p style="margin:0 0 4px;color:{MUTED};font-size:10px;text-transform:uppercase;
                          letter-spacing:1px;font-family:{FONT};">Threats Detected</p>
                <p style="margin:0;color:{RED};font-size:32px;font-weight:800;font-family:{FONT};">
                  {threats_detected:,}
                </p>
              </td>
            </tr>
            <tr><td colspan="3" style="height:10px;"></td></tr>
            <tr>
              <td width="48%" style="text-align:center;padding:20px 12px;background:{BG};
                                     border-radius:12px;border:1px solid {BORDER};">
                <p style="margin:0 0 4px;color:{MUTED};font-size:10px;text-transform:uppercase;
                          letter-spacing:1px;font-family:{FONT};">Threats Blocked</p>
                <p style="margin:0;color:{GREEN};font-size:32px;font-weight:800;font-family:{FONT};">
                  {threats_blocked:,}
                </p>
              </td>
              <td width="4%"></td>
              <td width="48%" style="text-align:center;padding:20px 12px;background:{BG};
                                     border-radius:12px;border:1px solid {BORDER};">
                <p style="margin:0 0 4px;color:{MUTED};font-size:10px;text-transform:uppercase;
                          letter-spacing:1px;font-family:{FONT};">Block Rate</p>
                <p style="margin:0;color:{GREEN};font-size:32px;font-weight:800;font-family:{FONT};">
                  {blocked_pct}%
                </p>
              </td>
            </tr>
          </table>

          <!-- Risk trend & top threat -->
          <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
            <tr>
              <td width="48%" style="padding:16px 20px;background:{BG};border-radius:12px;
                                     border:1px solid {BORDER};vertical-align:middle;">
                <p style="margin:0 0 4px;color:{MUTED};font-size:10px;text-transform:uppercase;
                          letter-spacing:1px;font-family:{FONT};">Risk Trend</p>
                <p style="margin:0;font-family:{FONT};">
                  <span style="font-size:28px;font-weight:800;color:{trend_color};">{trend_icon}</span>
                  <span style="font-size:14px;font-weight:700;color:{trend_color};margin-left:6px;">{trend_label}</span>
                </p>
              </td>
              <td width="4%"></td>
              <td width="48%" style="padding:16px 20px;background:{BG};border-radius:12px;
                                     border:1px solid {BORDER};vertical-align:middle;">
                <p style="margin:0 0 4px;color:{MUTED};font-size:10px;text-transform:uppercase;
                          letter-spacing:1px;font-family:{FONT};">Top Threat Type</p>
                <p style="margin:0;color:{WHITE};font-size:14px;font-weight:700;font-family:{FONT};">
                  {top_threat_type}
                </p>
              </td>
            </tr>
          </table>

          <!-- CTA -->
          <div style="text-align:center;margin-bottom:8px;">
            <a href="https://app.himaya.ai/reports"
               style="display:inline-block;background:{BLUE};color:{WHITE};text-decoration:none;
                      padding:13px 36px;border-radius:10px;font-size:14px;font-weight:700;
                      font-family:{FONT};">
              View Full Report →
            </a>
          </div>

        </td></tr>

        {_footer()}
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    text = (
        f"Himaya Helios — Weekly Security Report\n"
        f"{org_name} · {week_start} – {week_end}\n\n"
        f"Emails Scanned:   {emails_scanned:,}\n"
        f"Threats Detected: {threats_detected:,}\n"
        f"Threats Blocked:  {threats_blocked:,}\n"
        f"Block Rate:       {blocked_pct}%\n\n"
        f"Risk Trend:       {trend_icon} {trend_label}\n"
        f"Top Threat Type:  {top_threat_type}\n\n"
        f"View full report: https://app.himaya.ai/reports\n\n"
        f"© 2026 Himaya Technologies Group Inc. — app.himaya.ai"
    )
    return send_email(
        to_email,
        f"Himaya Helios Weekly Report · {week_start} – {week_end}",
        html,
        text
    )


def send_sender_block_notification(
    to_email: str,
    recipient_org: str,
    subject: str,
    threat_type: str,
    action: str = "BLOCK",
    recipient_email: str = "",
    body_preview: str = "",
    attachments: Optional[list] = None,
    link_count: int = 0,
    ai_explanation: str = "",
    policy_name: str = "",
) -> bool:
    """
    Notify the original sender that their outbound email was flagged and either
    blocked (deleted) or quarantined by the recipient org's email security policy.
    Works for both BLOCK and QUARANTINE actions.
    """
    is_blocked   = "BLOCK" in action.upper() or action.upper() == "BLOCK_DELETE"
    outcome_label = "permanently deleted and not delivered" if is_blocked else "held in quarantine pending review"
    outcome_color = RED if is_blocked else "#f97316"
    bar_color     = RED if is_blocked else "#f97316"
    action_word   = "Blocked" if is_blocked else "Quarantined"

    clean_preview = (body_preview or "").strip()[:800]
    clean_explanation = (ai_explanation or "").strip()[:700]
    att_list = attachments or []
    att_names = [a.get("filename", str(a)) if isinstance(a, dict) else str(a) for a in att_list]

    # Optional rows
    recipient_row = f"""
    <tr>
      <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;width:160px;font-family:{FONT};">Addressed To</td>
      <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-family:{FONT};">{recipient_email}</td>
    </tr>""" if recipient_email else ""

    att_row = f"""
    <tr>
      <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Attachments</td>
      <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-family:{FONT};">{', '.join(att_names)}</td>
    </tr>""" if att_names else ""

    link_row = f"""
    <tr>
      <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Links Detected</td>
      <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-family:{FONT};">{link_count} link(s) in message body</td>
    </tr>""" if link_count > 0 else ""

    policy_row = f"""
    <tr>
      <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Triggered By</td>
      <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-family:{FONT};">Policy: {policy_name}</td>
    </tr>""" if policy_name else ""

    preview_block = f"""
    <div style="background:{BG};border:1px solid {BORDER};border-radius:10px;padding:16px 20px;margin-bottom:20px;">
      <p style="margin:0 0 6px;color:{MUTED};font-size:10px;letter-spacing:1px;text-transform:uppercase;font-family:{FONT};">Message Preview</p>
      <p style="margin:0;color:#a1a1aa;font-size:13px;line-height:1.7;font-family:{FONT};font-style:italic;">"{clean_preview}…"</p>
    </div>""" if clean_preview else ""

    explanation_block = f"""
    <div style="background:#0f0d1a;border:1px solid #2d2455;border-radius:10px;padding:16px 20px;margin-bottom:20px;">
      <p style="margin:0 0 6px;color:#a78bfa;font-size:10px;letter-spacing:1px;text-transform:uppercase;font-family:{FONT};">Why it was flagged</p>
      <p style="margin:0;color:#c4b5fd;font-size:13px;line-height:1.7;font-family:{FONT};">{clean_explanation}</p>
    </div>""" if clean_explanation else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{BG};font-family:{FONT};">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};padding:48px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:{CARD};border-radius:16px;border:1px solid {BORDER};overflow:hidden;">

        <tr><td style="background:{bar_color};height:5px;font-size:0;line-height:0;">&nbsp;</td></tr>

        <!-- Header -->
        <tr><td style="background:{CARD};padding:28px 40px 20px;border-bottom:1px solid {BORDER};text-align:center;">
          {LOGO_HTML}
          <p style="margin:10px 0 0;color:{MUTED};font-size:11px;letter-spacing:2px;text-transform:uppercase;font-family:{FONT};">
            Delivery Failure Notice — Automated
          </p>
        </td></tr>

        <!-- Body -->
        <tr><td style="padding:32px 40px 36px;">
          <h2 style="margin:0 0 8px;color:{WHITE};font-size:20px;font-weight:700;font-family:{FONT};">
            Your email was {action_word.lower()} by {recipient_org}'s security system
          </h2>
          <p style="margin:0 0 24px;color:{MUTED};font-size:14px;line-height:1.75;font-family:{FONT};">
            An email you sent to <strong style="color:{WHITE};">{recipient_org}</strong> was intercepted by their
            AI-powered email security system (Himaya Helios) and has been
            <strong style="color:{outcome_color};">{outcome_label}</strong>.
          </p>

          <!-- Detail table -->
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin-bottom:24px;">
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;width:160px;font-family:{FONT};">Subject</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-family:{FONT};">{subject or "(no subject)"}</td>
            </tr>
            {recipient_row}
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Classification</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{outcome_color};font-size:13px;font-weight:600;font-family:{FONT};">{threat_type}</td>
            </tr>
            {att_row}
            {link_row}
            {policy_row}
            <tr>
              <td style="padding:11px 0;color:{MUTED};font-size:13px;font-family:{FONT};">Outcome</td>
              <td style="padding:11px 0;color:{outcome_color};font-size:13px;font-weight:600;font-family:{FONT};">{outcome_label.capitalize()}</td>
            </tr>
          </table>

          {preview_block}
          {explanation_block}

          <div style="background:#1a0a0a;border:1px solid #4a1515;border-radius:10px;padding:18px 20px;margin-bottom:24px;">
            <p style="margin:0 0 8px;color:#f87171;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;font-family:{FONT};">What can you do?</p>
            <ul style="margin:0;padding:0 0 0 18px;color:{MUTED};font-size:13px;line-height:1.8;font-family:{FONT};">
              <li>If you believe this is a mistake, contact <strong style="color:{WHITE};">{recipient_org}</strong> directly and ask them to whitelist your email address or domain.</li>
              <li>Review your email for content that may have triggered a security policy (links, attachments, urgent payment language).</li>
              <li>Do not resend the same email — it will be intercepted again until the policy is updated.</li>
            </ul>
          </div>

          <p style="margin:0;color:{MUTED};font-size:12px;line-height:1.6;font-family:{FONT};">
            This is an automated notice from Himaya Helios on behalf of {recipient_org}.
            Please do not reply to this email — it is not monitored.
          </p>
        </td></tr>

        {_footer()}
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    verb = "blocked" if is_blocked else "quarantined"
    text = (
        f"Himaya Helios — Delivery Failure Notice\n\n"
        f"Your email was {verb} by {recipient_org}'s security system.\n\n"
        f"Subject:        {subject or '(no subject)'}\n"
        + (f"Addressed To:   {recipient_email}\n" if recipient_email else "")
        + f"Classification: {threat_type}\n"
        + (f"Attachments:    {', '.join(att_names)}\n" if att_names else "")
        + (f"Links:          {link_count} detected\n" if link_count else "")
        + (f"Triggered By:   Policy — {policy_name}\n" if policy_name else "")
        + f"Outcome:        {outcome_label.capitalize()}\n\n"
        + (f"Why it was flagged:\n{clean_explanation}\n\n" if clean_explanation else "")
        + f"If you believe this is an error, contact {recipient_org} directly to request\n"
        f"whitelisting of your domain.\n\n"
        f"© 2026 Himaya Technologies Group Inc. — app.himaya.ai"
    )
    subject_line = (
        f"Your email to {recipient_org} was {verb} by their security policy"
    )
    return send_email(to_email, subject_line, html, text)


def send_quarantine_notification(
    to_email: str,
    org_name: str,
    threat_type: str,
    risk_score: int,
    sender_email: str,
    subject: str,
    action: str,
    ai_explanation: str,
    dashboard_url: str = "https://app.himaya.ai/quarantine",
    # ── Richer email context ─────────────────────────────────────
    body_preview: str = "",
    attachments: Optional[list] = None,
    link_count: int = 0,
    received_at: str = "",
    policy_name: str = "",
    is_admin_recipient: bool = False,   # Only show dashboard CTA for admins/analysts
) -> bool:
    """
    Send quarantine/block notification to the affected end-user (recipient).
    Includes full email context: body preview, attachments, links, policy, AI analysis.
    """
    severity = "CRITICAL" if risk_score >= 90 else "HIGH" if risk_score >= 70 else "MEDIUM"
    sev_color = RED if severity == "CRITICAL" else "#f97316" if severity == "HIGH" else "#facc15"
    action_label = "Quarantined" if "QUARANTINE" in action.upper() else "Blocked & Deleted"
    action_color = "#f97316" if "QUARANTINE" in action.upper() else RED
    clean_explanation = (ai_explanation or "").strip()[:700]
    clean_preview = (body_preview or "").strip()[:800]
    att_list = attachments or []
    att_names = [a.get("filename", str(a)) if isinstance(a, dict) else str(a) for a in att_list]

    # Optional detail rows
    received_row = f"""
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;width:160px;font-family:{FONT};">Received At</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-family:{FONT};">{received_at}</td>
            </tr>""" if received_at else ""

    att_row = f"""
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Attachments</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};font-family:{FONT};">
                {"".join(f'<span style="display:inline-block;background:#2d1515;border:1px solid #7f1d1d;color:#fca5a5;font-size:11px;font-weight:600;padding:2px 8px;border-radius:5px;margin:1px;">{n}</span>' for n in att_names)}
              </td>
            </tr>""" if att_names else ""

    link_row = f"""
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Links Found</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:#fbbf24;font-size:13px;font-weight:600;font-family:{FONT};">{link_count} link(s) detected in message body</td>
            </tr>""" if link_count > 0 else ""

    policy_row = f"""
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Matched Policy</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-family:{FONT};">
                <span style="display:inline-block;background:#1e1333;border:1px solid #4c1d95;color:#c4b5fd;font-size:12px;font-weight:600;padding:2px 10px;border-radius:5px;">{policy_name}</span>
              </td>
            </tr>""" if policy_name else ""

    preview_block = f"""
          <div style="background:{BG};border:1px solid {BORDER};border-left:3px solid {sev_color};border-radius:10px;padding:16px 20px;margin-bottom:20px;">
            <p style="margin:0 0 6px;color:{MUTED};font-size:10px;letter-spacing:1px;text-transform:uppercase;font-family:{FONT};">Message Preview</p>
            <p style="margin:0;color:#9ca3af;font-size:13px;line-height:1.7;font-family:{FONT};font-style:italic;">"{clean_preview}{"…" if len(body_preview or "") > 300 else ""}"</p>
          </div>""" if clean_preview else ""

    explanation_block = f"""
          <div style="background:#0b0f1f;border:1px solid #1e2d5e;border-radius:10px;padding:16px 20px;margin-bottom:20px;">
            <p style="margin:0 0 6px;color:#93b4fd;font-size:10px;letter-spacing:1px;text-transform:uppercase;font-family:{FONT};">Helios AI Analysis</p>
            <p style="margin:0;color:#c7d2fe;font-size:13px;line-height:1.75;font-family:{FONT};">{clean_explanation}</p>
          </div>""" if clean_explanation else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{BG};font-family:{FONT};">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:{BG};padding:48px 20px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;background:{CARD};border-radius:16px;border:1px solid {BORDER};overflow:hidden;">

        <tr><td style="background:{sev_color};height:5px;font-size:0;line-height:0;">&nbsp;</td></tr>

        <!-- Header -->
        <tr><td style="background:{CARD};padding:28px 40px 20px;border-bottom:1px solid {BORDER};text-align:center;">
          {LOGO_HTML}
          <p style="margin:10px 0 0;color:{MUTED};font-size:11px;letter-spacing:2px;text-transform:uppercase;font-family:{FONT};">
            Security Alert — {org_name}
          </p>
        </td></tr>

        <!-- Title -->
        <tr><td style="padding:28px 40px 8px;">
          <h2 style="margin:0 0 6px;color:{WHITE};font-size:20px;font-weight:700;font-family:{FONT};">
            ⚠️ Email {action_label} by Helios
          </h2>
          <p style="margin:0;color:{MUTED};font-size:13px;font-family:{FONT};">
            Himaya Helios intercepted a suspicious email directed to your inbox and took protective action automatically.
          </p>
        </td></tr>

        <!-- Badges -->
        <tr><td style="padding:12px 40px 0;">
          <span style="display:inline-block;background:{BG};border:1px solid {sev_color};color:{sev_color};
                       font-size:12px;font-weight:700;padding:4px 12px;border-radius:6px;font-family:{FONT};">
            {threat_type}
          </span>
          <span style="display:inline-block;background:{action_color}18;border:1px solid {action_color}55;
                       color:{action_color};font-size:12px;font-weight:600;padding:4px 12px;
                       border-radius:6px;margin-left:6px;font-family:{FONT};">
            {action_label}
          </span>
          <span style="display:inline-block;background:{sev_color}18;border:1px solid {sev_color}55;
                       color:{sev_color};font-size:12px;font-weight:700;padding:4px 12px;
                       border-radius:6px;margin-left:6px;font-family:{FONT};">
            Risk {risk_score}/100
          </span>
        </td></tr>

        <!-- Details -->
        <tr><td style="padding:20px 40px 28px;">

          <!-- Info table -->
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin-bottom:20px;">
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;width:140px;font-family:{FONT};">From</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-weight:600;font-family:{FONT};">{sender_email}</td>
            </tr>
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Subject</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{WHITE};font-size:13px;font-family:{FONT};">{subject or "(no subject)"}</td>
            </tr>
            {received_row}
            {att_row}
            {link_row}
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Threat Type</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{sev_color};font-size:13px;font-weight:600;font-family:{FONT};">{threat_type}</td>
            </tr>
            <tr>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};color:{MUTED};font-size:13px;font-family:{FONT};">Severity</td>
              <td style="padding:11px 0;border-bottom:1px solid {BORDER};font-family:{FONT};">
                <span style="color:{sev_color};font-weight:700;font-size:13px;">{severity}</span>
                <span style="color:{MUTED};font-size:13px;"> — Risk score {risk_score}/100</span>
              </td>
            </tr>
            {policy_row}
            <tr>
              <td style="padding:11px 0;color:{MUTED};font-size:13px;font-family:{FONT};">Action Taken</td>
              <td style="padding:11px 0;color:{action_color};font-size:13px;font-weight:600;font-family:{FONT};">
                ✓ {action_label} automatically
              </td>
            </tr>
          </table>

          {preview_block}
          {explanation_block}

          <!-- What to do -->
          <div style="background:#0a1e12;border:1px solid #1a4530;border-radius:10px;padding:16px 20px;margin-bottom:24px;">
            <p style="margin:0 0 8px;color:#4ade80;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px;font-family:{FONT};">
              What should you do?
            </p>
            <ul style="margin:0;padding:0 0 0 18px;color:{MUTED};font-size:13px;line-height:1.9;font-family:{FONT};">
              <li>If this email looks <strong style="color:{WHITE};">legitimate</strong>, contact your IT/security team to release it from quarantine.</li>
              <li><strong style="color:{RED};">Do not</strong> click any links or open attachments from this sender until verified by your security team.</li>
              <li>If you were expecting this email, ask your admin to mark it as a false positive in the Helios dashboard.</li>
            </ul>
          </div>

          <!-- CTA — only for admin/analyst portal users -->
          {f'''<div style="text-align:center;">
            <a href="{dashboard_url}"
               style="display:inline-block;background:{BLUE};color:{WHITE};text-decoration:none;
                      padding:13px 32px;border-radius:10px;font-size:14px;font-weight:700;
                      letter-spacing:0.2px;font-family:{FONT};">
              Review in Helios Dashboard →
            </a>
          </div>''' if is_admin_recipient else ''}
        </td></tr>

        <!-- Arabic summary -->
        <tr><td style="padding:18px 40px;background:{BG};border-top:1px solid {BORDER};border-bottom:1px solid {BORDER};">
          <p style="margin:0 0 6px;color:{MUTED};font-size:10px;letter-spacing:1px;text-transform:uppercase;font-family:{FONT};">
            Arabic Summary / ملخص بالعربية
          </p>
          <p style="margin:0;color:{MUTED};font-size:13px;line-height:1.9;text-align:right;direction:rtl;font-family:Tahoma,Arial,sans-serif;">
            تم رصد بريد إلكتروني مشبوه من <strong style="color:{WHITE};">{sender_email}</strong>
            بموضوع "<strong style="color:{WHITE};">{subject or 'بدون موضوع'}</strong>".
            <br>نوع التهديد: <strong style="color:{sev_color};">{threat_type}</strong> · درجة الخطورة: <strong style="color:{sev_color};">{risk_score}/100</strong>.
            <br>الإجراء المتخذ تلقائياً: <strong style="color:{action_color};">{action_label}</strong>.
            <br>إذا كان هذا البريد شرعياً، يُرجى التواصل مع مسؤول الأمن لديك لاسترجاعه.
          </p>
        </td></tr>

        {_footer()}
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    text = (
        f"Himaya Helios — Security Alert · {org_name}\n\n"
        f"An email directed to your inbox has been {action_label} by Helios.\n\n"
        f"FROM:         {sender_email}\n"
        f"SUBJECT:      {subject or '(no subject)'}\n"
        + (f"RECEIVED:     {received_at}\n" if received_at else "")
        + f"THREAT TYPE:  {threat_type}\n"
        f"RISK SCORE:   {risk_score}/100 ({severity})\n"
        f"ACTION:       {action_label} automatically\n"
        + (f"ATTACHMENTS:  {', '.join(att_names)}\n" if att_names else "")
        + (f"LINKS:        {link_count} detected\n" if link_count else "")
        + (f"POLICY:       {policy_name}\n" if policy_name else "")
        + (f"\nMESSAGE PREVIEW:\n\"{clean_preview}…\"\n" if clean_preview else "")
        + (f"\nAI ANALYSIS:\n{clean_explanation}\n" if clean_explanation else "")
        + f"\nWHAT TO DO:\n"
        f"- If legitimate, contact your IT/security team to release from quarantine.\n"
        f"- Do NOT click links or open attachments until verified.\n"
        f"- View details at: {dashboard_url}\n\n"
        f"© 2026 Himaya Technologies Group Inc. — app.himaya.ai"
    )
    return send_email(
        to_email,
        f"[{severity}] Email {action_label}: {threat_type} — Himaya Helios",
        html,
        text,
    )


def send_suspicious_recipient_notification(
    to_email: str,
    sender_email: str,
    subject: str,
    threat_type: str,
    risk_score: int,
    explanation: str = "",
    key_factors: list = None,
) -> bool:
    """
    Notify the original recipient that their email has been flagged as Helios Suspicious.
    No dashboard link — plain readable explanation only.
    """
    if not to_email:
        return False

    key_factors = key_factors or []
    clean_explanation = explanation.replace("<", "&lt;").replace(">", "&gt;") if explanation else ""
    clean_sender = sender_email.replace("<", "&lt;").replace(">", "&gt;") if sender_email else "(unknown)"
    clean_subject = subject.replace("<", "&lt;").replace(">", "&gt;") if subject else "(No Subject)"
    clean_threat = (threat_type or "Suspicious Content").replace("_", " ").title()

    severity_color = RED if risk_score >= 70 else "#f59e0b" if risk_score >= 40 else "#6366f1"

    factors_html = ""
    if key_factors:
        factor_items = "".join(
            f'<li style="margin:0 0 4px;color:{MUTED};font-family:{FONT};font-size:13px;">{str(f).replace("<","&lt;").replace(">","&gt;")}</li>'
            for f in key_factors[:8]
        )
        factors_html = f"""
        <tr><td style="background:{CARD};padding:16px 32px;">
          <p style="margin:0 0 8px;color:{WHITE};font-family:{FONT};font-size:13px;font-weight:600;">Detection Signals</p>
          <ul style="margin:0;padding-left:18px;">{factor_items}</ul>
        </td></tr>
        """

    explanation_html = ""
    if clean_explanation:
        explanation_html = f"""
        <tr><td style="background:{CARD};padding:16px 32px;border-top:1px solid {BORDER};">
          <p style="margin:0 0 4px;color:{MUTED};font-family:{FONT};font-size:11px;text-transform:uppercase;letter-spacing:0.05em;">Analysis</p>
          <p style="margin:0;color:{MUTED};font-family:{FONT};font-size:13px;line-height:1.5;">{clean_explanation[:600]}</p>
        </td></tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:{BG};font-family:{FONT};">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{BG};padding:32px 16px;">
<tr><td align="center">
<table width="560" cellpadding="0" cellspacing="0" border="0" style="max-width:560px;width:100%;">

  <!-- Logo -->
  <tr><td style="padding:0 0 24px;">{LOGO_HTML}</td></tr>

  <!-- Header -->
  <tr><td style="background:{CARD};border:1px solid {BORDER};border-radius:8px 8px 0 0;padding:24px 32px;">
    <p style="margin:0 0 4px;color:{severity_color};font-family:{FONT};font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;">
      Security Notice
    </p>
    <h1 style="margin:0 0 8px;color:{WHITE};font-family:{FONT};font-size:20px;font-weight:700;line-height:1.3;">
      An email you received has been flagged
    </h1>
    <p style="margin:0;color:{MUTED};font-family:{FONT};font-size:13px;">
      Helios has detected suspicious characteristics in an email delivered to your inbox and has marked it for review.
    </p>
  </td></tr>

  <!-- Email details -->
  <tr><td style="background:{CARD};padding:0 32px 16px;border-left:1px solid {BORDER};border-right:1px solid {BORDER};">
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-top:1px solid {BORDER};padding-top:16px;margin-top:0;">
      <tr>
        <td style="padding:6px 0;color:{MUTED};font-family:{FONT};font-size:12px;width:110px;vertical-align:top;">FROM</td>
        <td style="padding:6px 0;color:{WHITE};font-family:{FONT};font-size:13px;font-weight:500;">{clean_sender}</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:{MUTED};font-family:{FONT};font-size:12px;vertical-align:top;">SUBJECT</td>
        <td style="padding:6px 0;color:{WHITE};font-family:{FONT};font-size:13px;font-weight:500;">{clean_subject}</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:{MUTED};font-family:{FONT};font-size:12px;vertical-align:top;">THREAT TYPE</td>
        <td style="padding:6px 0;color:{severity_color};font-family:{FONT};font-size:13px;font-weight:600;">{clean_threat}</td>
      </tr>
      <tr>
        <td style="padding:6px 0;color:{MUTED};font-family:{FONT};font-size:12px;vertical-align:top;">RISK SCORE</td>
        <td style="padding:6px 0;color:{severity_color};font-family:{FONT};font-size:13px;font-weight:700;">{risk_score}/100</td>
      </tr>
    </table>
  </td></tr>

  {factors_html}
  {explanation_html}

  <!-- What to do -->
  <tr><td style="background:{CARD};padding:16px 32px;border-left:1px solid {BORDER};border-right:1px solid {BORDER};border-top:1px solid {BORDER};">
    <p style="margin:0 0 8px;color:{WHITE};font-family:{FONT};font-size:13px;font-weight:600;">What should you do?</p>
    <ul style="margin:0;padding-left:18px;">
      <li style="margin:0 0 4px;color:{MUTED};font-family:{FONT};font-size:13px;">Exercise caution with this email — do not click any links or open attachments unless you can verify the sender.</li>
      <li style="margin:0 0 4px;color:{MUTED};font-family:{FONT};font-size:13px;">If you believe this is a legitimate email, contact your IT or security team.</li>
      <li style="margin:0;color:{MUTED};font-family:{FONT};font-size:13px;">If you suspect this is a phishing attempt, do not reply to the sender.</li>
    </ul>
  </td></tr>

  <!-- Footer border -->
  <tr><td style="background:{CARD};border:1px solid {BORDER};border-top:none;border-radius:0 0 8px 8px;padding:16px 32px;">
    <p style="margin:0;color:{MUTED};font-family:{FONT};font-size:11px;">
      This notification was generated automatically by Himaya Helios email security. You are receiving this because you are a recipient of the flagged email.
    </p>
  </td></tr>

  {_footer()}
</table>
</td></tr>
</table>
</body>
</html>"""

    text = (
        "SECURITY NOTICE — Helios Email Security\n"
        "=========================================\n\n"
        "An email you received has been flagged by Helios as suspicious.\n\n"
        f"FROM:        {sender_email}\n"
        f"SUBJECT:     {subject or '(No Subject)'}\n"
        f"THREAT TYPE: {clean_threat}\n"
        f"RISK SCORE:  {risk_score}/100\n"
        + (f"\nDETECTION SIGNALS:\n" + "\n".join(f"  - {f}" for f in key_factors[:8]) + "\n" if key_factors else "")
        + (f"\nANALYSIS:\n{explanation[:500]}\n" if explanation else "")
        + "\nWHAT TO DO:\n"
        "  - Exercise caution — do not click links or open attachments until you can verify the sender.\n"
        "  - If legitimate, contact your IT or security team.\n"
        "  - If suspicious, do not reply to the sender.\n\n"
        "This notification was generated by Himaya Helios email security.\n"
        "© 2026 Himaya Technologies Group Inc."
    )

    return send_email(
        to_email,
        "Security Notice: An email you received has been flagged by Helios",
        html,
        text,
    )
