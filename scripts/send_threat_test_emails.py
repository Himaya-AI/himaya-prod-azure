"""
Helios Production Readiness — Threat Email Test Suite
Sends 4 flavors of simulated threat emails to real mailboxes across
Google (himaya.ai) and Microsoft 365 (sana085.onmicrosoft.com) tenants.

Threat types:
  1. MALWARE — malicious attachment lure (macro-enabled doc)
  2. ACCOUNT_TAKEOVER — fake security alert, credential reset urgency
  3. CREDENTIAL_HARVESTING — fake login portal link
  4. PHISHING — CEO impersonation invoice scam

Recipients: 2x Google mailboxes + 2x M365 mailboxes (one each per flavor)
"""
import boto3, json, sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime

SES = boto3.client("ses", region_name="us-east-1")
FROM = "Helios Security Test <noreply@himaya.ai>"
# X-header to identify these as test/simulation emails for audit
TEST_HEADER = "X-Helios-Test: threat-simulation-2026-04-14"

# Target recipients: mix of Google (himaya.ai) and M365 (sana085.onmicrosoft.com)
TARGETS = {
    "google_1": "adnanahmed@sana085.onmicrosoft.com",   # M365
    "google_2": "faraz@sana085.onmicrosoft.com",         # M365
    "m365_1":   "adnan@himaya.ai",                       # Google
    "m365_2":   "info@himaya.ai",                        # Google
}

# ─── 1. MALWARE LURE ──────────────────────────────────────────────────────────
MALWARE_HTML = """<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;font-size:14px;color:#333;">
<p>Dear Colleague,</p>
<p>Please find attached the <strong>Q1 2026 Financial Report</strong> with updated figures 
for the board review. The document requires macros to be enabled for the interactive charts.</p>
<p>Kindly open and review <strong>Q1_Financial_Report_2026.xlsm</strong> before the 9 AM meeting.</p>
<p>The password to unlock the protected sections is: <strong>Qfin2026!</strong></p>
<p>This message was sent from a secure external server. Please do not reply directly.</p>
<br>
<p>Best regards,<br>
<strong>Ahmed Al-Rashidi</strong><br>
Chief Financial Officer<br>
Gulf Capital Investments LLC<br>
<span style="color:#888;font-size:11px;">ahmed.alrashidi@gulf-capital-investments.co — Tel: +966 11 234 5678</span></p>
<p style="font-size:10px;color:#aaa;">CONFIDENTIAL: This email and any attachments are for the exclusive and confidential use of the intended recipient.</p>
</body></html>"""

MALWARE_TEXT = """Dear Colleague,

Please find attached the Q1 2026 Financial Report with updated figures for the board review.
The document requires macros to be enabled for the interactive charts.

Kindly open and review Q1_Financial_Report_2026.xlsm before the 9 AM meeting.
The password to unlock the protected sections is: Qfin2026!

Best regards,
Ahmed Al-Rashidi | CFO | Gulf Capital Investments LLC"""

# ─── 2. ACCOUNT TAKEOVER ──────────────────────────────────────────────────────
ATO_HTML = """<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;font-size:14px;color:#333;">
<div style="max-width:560px;margin:0 auto;border:1px solid #ddd;border-radius:4px;overflow:hidden;">
  <div style="background:#cc0000;padding:14px 20px;">
    <span style="color:#fff;font-size:16px;font-weight:bold;">⚠ Microsoft Security Alert</span>
  </div>
  <div style="padding:20px;">
    <p>We detected a sign-in attempt to your Microsoft 365 account from an unrecognized device.</p>
    <table style="font-size:12px;background:#f8f8f8;padding:10px;width:100%;border-collapse:collapse;">
      <tr><td style="padding:4px 8px;color:#666;">Location:</td><td style="padding:4px 8px;"><strong>Lagos, Nigeria</strong></td></tr>
      <tr><td style="padding:4px 8px;color:#666;">IP Address:</td><td style="padding:4px 8px;"><strong>197.210.54.121</strong></td></tr>
      <tr><td style="padding:4px 8px;color:#666;">Device:</td><td style="padding:4px 8px;"><strong>Unknown Android Device</strong></td></tr>
      <tr><td style="padding:4px 8px;color:#666;">Time:</td><td style="padding:4px 8px;"><strong>Apr 14, 2026 — 03:47 UTC</strong></td></tr>
    </table>
    <p style="margin-top:16px;">If this was not you, your account may be compromised. <strong>You must verify your identity within 24 hours</strong> or your account will be suspended.</p>
    <div style="text-align:center;margin:24px 0;">
      <a href="http://microsoft-secure-verify.account-protection-now.com/verify?token=eyJhbGciOiJSUzI1NiJ9.aW52YWxpZA" 
         style="background:#cc0000;color:#fff;padding:12px 28px;text-decoration:none;border-radius:4px;font-weight:bold;">
        Secure My Account Now
      </a>
    </div>
    <p style="font-size:11px;color:#999;">Microsoft Corporation | One Microsoft Way, Redmond, WA 98052<br>
    This is an automated security notification. Do not reply to this email.</p>
  </div>
</div>
</body></html>"""

ATO_TEXT = """MICROSOFT SECURITY ALERT

We detected a sign-in attempt from an unrecognized device.
Location: Lagos, Nigeria | IP: 197.210.54.121
Time: Apr 14, 2026 — 03:47 UTC

If this was not you, verify your identity within 24 hours or your account will be suspended.
Verify here: http://microsoft-secure-verify.account-protection-now.com/verify?token=eyJhbGciOiJSUzI1NiJ9.aW52YWxpZA

Microsoft Corporation"""

# ─── 3. CREDENTIAL HARVESTING ─────────────────────────────────────────────────
CRED_HTML = """<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;font-size:14px;color:#333;">
<div style="max-width:560px;margin:0 auto;">
  <div style="background:#0078d4;padding:12px 20px;">
    <span style="color:#fff;font-size:15px;font-weight:bold;">Google Workspace — Action Required</span>
  </div>
  <div style="padding:20px;border:1px solid #e0e0e0;border-top:none;">
    <p>Hello,</p>
    <p>Your Google Workspace account storage has reached <strong>95% capacity</strong>. 
    To avoid email delivery failures and data loss, you must verify your account and expand your storage.</p>
    <p>Accounts not verified within <strong>48 hours</strong> will have incoming emails automatically rejected.</p>
    <div style="background:#fff8e1;border-left:4px solid #ffc107;padding:12px;margin:16px 0;">
      <strong>Action required by:</strong> April 16, 2026 — 23:59 UTC
    </div>
    <div style="text-align:center;margin:20px 0;">
      <a href="http://google-workspace-storage-verify.accounts-google-portal.xyz/auth?redirect=storage&email=user@himaya.ai"
         style="background:#0078d4;color:#fff;padding:11px 26px;text-decoration:none;border-radius:4px;font-weight:bold;">
        Verify Account &amp; Expand Storage
      </a>
    </div>
    <p style="font-size:11px;color:#999;">Google LLC | 1600 Amphitheatre Parkway, Mountain View, CA 94043<br>
    You received this mandatory notification because you are an active Workspace user.</p>
  </div>
</div>
</body></html>"""

CRED_TEXT = """Google Workspace — Action Required

Your account storage has reached 95% capacity. Verify your account within 48 hours
or incoming emails will be rejected.

Action required by: April 16, 2026 — 23:59 UTC

Verify here: http://google-workspace-storage-verify.accounts-google-portal.xyz/auth?redirect=storage

Google LLC"""

# ─── 4. PHISHING — CEO IMPERSONATION ─────────────────────────────────────────
PHISHING_HTML = """<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;font-size:14px;color:#333;">
<p>Hi,</p>
<p>I'm currently in an urgent board meeting and I need your help with something sensitive.</p>
<p>We are finalizing an <strong>acquisition deal</strong> and I need you to process a wire transfer 
of <strong>USD $47,500</strong> to our legal escrow account before market close today. 
This is time-critical and must be kept confidential until the deal is announced.</p>
<p>Please initiate the transfer to:</p>
<blockquote style="background:#f5f5f5;padding:12px;border-left:3px solid #999;">
  <strong>Bank:</strong> Emirates NBD<br>
  <strong>Account Name:</strong> Argent Legal Holdings Ltd<br>
  <strong>IBAN:</strong> AE070331234567890123456<br>
  <strong>Reference:</strong> PROJ-ACQ-2026-Q2
</blockquote>
<p>Confirm by reply once done. Do not discuss this with anyone else in the office — 
legal compliance requires strict confidentiality before public disclosure.</p>
<p>I'll call you right after the meeting. Thank you for handling this.</p>
<br>
<p>Best,<br>
<strong>Adnan Ahmed</strong><br>
CEO, Himaya Technologies<br>
<span style="font-size:11px;color:#888;">Sent from iPhone — adnan.ahmed.ceo@himaya-tech-group.com</span></p>
</body></html>"""

PHISHING_TEXT = """Hi,

I'm in an urgent board meeting and need you to process a wire transfer of USD $47,500
to our legal escrow account before market close today. Keep this confidential.

Bank: Emirates NBD | Account: Argent Legal Holdings Ltd
IBAN: AE070331234567890123456 | Ref: PROJ-ACQ-2026-Q2

Confirm by reply. Do not discuss with others in the office.

Adnan Ahmed — CEO, Himaya Technologies"""


# SES verified envelope sender — all mail goes out from this address.
# The display-name From header carries the spoofed identity for realism.
SES_ENVELOPE_SENDER = "noreply@himaya.ai"


def build_message(to_addr, subject, html, text, display_from, add_attachment=None):
    """
    Build a MIME email.
    display_from  — the From: header the recipient sees (the spoofed attacker identity)
    SES_ENVELOPE_SENDER — the actual SMTP envelope sender (our verified domain)
    """
    if add_attachment:
        outer = MIMEMultipart("mixed")
        outer["Subject"] = subject
        outer["From"] = display_from          # Spoofed display name
        outer["To"] = to_addr
        outer["Reply-To"] = display_from
        outer[TEST_HEADER.split(":")[0]] = TEST_HEADER.split(": ")[1]
        outer.attach(MIMEText(text, "plain"))
        outer.attach(MIMEText(html, "html"))
        # Fake xlsm attachment (just enough magic bytes for heuristic detection)
        part = MIMEBase("application", "vnd.ms-excel.sheet.macroEnabled.12")
        part.set_payload(b"PK\x03\x04" + b"\x00" * 256)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{add_attachment}"')
        outer.attach(part)
        return outer

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = display_from
    msg["To"] = to_addr
    msg["Reply-To"] = display_from
    msg[TEST_HEADER.split(":")[0]] = TEST_HEADER.split(": ")[1]
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))
    return msg


def send(msg, destination):
    try:
        resp = SES.send_raw_email(
            Source=SES_ENVELOPE_SENDER,      # Verified sender — envelope only
            Destinations=[destination],
            RawMessage={"Data": msg.as_bytes()},
        )
        print(f"  ✅ Sent → {destination} | MsgId: {resp['MessageId'][:16]}...")
        return True
    except Exception as e:
        print(f"  ❌ Failed → {destination}: {e}")
        return False


emails = [
    {
        "flavor": "MALWARE (macro attachment lure)",
        "subject": "Q1 2026 Financial Report — Please Review Before 9 AM",
        "from_display": "Ahmed Al-Rashidi | CFO Gulf Capital <noreply@himaya.ai>",
        "html": MALWARE_HTML,
        "text": MALWARE_TEXT,
        "attachment": "Q1_Financial_Report_2026.xlsm",
        "recipients": [TARGETS["google_1"], TARGETS["m365_1"]],
    },
    {
        "flavor": "ACCOUNT TAKEOVER (fake Microsoft security alert)",
        "subject": "⚠ Microsoft Account: Unusual sign-in activity detected",
        "from_display": "Microsoft Security Alert <noreply@himaya.ai>",
        "html": ATO_HTML,
        "text": ATO_TEXT,
        "attachment": None,
        "recipients": [TARGETS["google_2"], TARGETS["m365_2"]],
    },
    {
        "flavor": "CREDENTIAL HARVESTING (fake Google storage warning)",
        "subject": "Action Required: Your Google Workspace storage is almost full",
        "from_display": "Google Workspace Notifications <noreply@himaya.ai>",
        "html": CRED_HTML,
        "text": CRED_TEXT,
        "attachment": None,
        "recipients": [TARGETS["google_1"], TARGETS["m365_2"]],
    },
    {
        "flavor": "PHISHING (CEO impersonation / BEC wire fraud)",
        "subject": "Urgent — Confidential Wire Transfer Request",
        "from_display": "Adnan Ahmed - CEO Himaya <noreply@himaya.ai>",
        "html": PHISHING_HTML,
        "text": PHISHING_TEXT,
        "attachment": None,
        "recipients": [TARGETS["google_2"], TARGETS["m365_1"]],
    },
]

print(f"\n{'='*65}")
print(f"  HELIOS THREAT TEST SUITE — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
print(f"  SES Production | From: noreply@himaya.ai")
print(f"{'='*65}\n")

total_sent = 0
for em in emails:
    print(f"📧 [{em['flavor']}]")
    print(f"   Subject: {em['subject'][:60]}")
    for recipient in em["recipients"]:
        msg = build_message(
            to_addr=recipient,
            subject=em["subject"],
            html=em["html"],
            text=em["text"],
            display_from=em["from_display"],
            add_attachment=em.get("attachment"),
        )
        ok = send(msg, recipient)
        if ok:
            total_sent += 1
    print()

print(f"{'='*65}")
print(f"  Total sent: {total_sent} emails across {len(emails)} threat flavors")
print(f"  Helios delta-sync will pick these up within ~60 seconds")
print(f"  Auto-triage agent is ON — watch audit trail for verdicts")
print(f"{'='*65}\n")
