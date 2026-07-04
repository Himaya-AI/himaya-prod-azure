"""
Helios — Subtle Phishing Simulation
Very realistic, low-noise phishing emails designed to test detection
sensitivity on both Outlook (sana085) and Gmail (himaya.ai) mailboxes.

These are crafted to look legitimate at a glance:
  - No obvious urgency caps/warnings
  - Realistic sender display names and lookalike domains
  - Subtle payload indicators (suspicious links, reply-to mismatch, macro lures)
  - Mix of social engineering tactics

Emails sent:
  Outlook targets:
    1. Vendor Invoice — subtle BEC, reply-to hijack to look-alike domain
    2. IT Policy Update — credential harvesting via SharePoint-lookalike link

  Gmail targets:
    3. Shared Drive Notification — Google Workspace impersonation, lookalike link
    4. Quiet Lateral Phish — HR/benefits update, no urgency, external redirect

Run: python3 scripts/send_subtle_phish_test.py
"""

import boto3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

SES = boto3.client("ses", region_name="us-east-1")
# Use helios-test-attacker@himaya.ai — verified SES identity but NOT in the
# processor's _HELIOS_SYSTEM_SENDERS loop guard (which blocks noreply@himaya.ai).
# Without this, all test emails are silently skipped before scoring.
VERIFIED_SENDER = "helios-test-attacker@himaya.ai"
NOW_DATE = datetime.utcnow().strftime("%B %d, %Y")

# ─── Targets ──────────────────────────────────────────────────────────────────
OUTLOOK_1 = "adnanahmed@sana085.onmicrosoft.com"
OUTLOOK_2 = "faraz@sana085.onmicrosoft.com"
GMAIL_1   = "adnan@himaya.ai"
GMAIL_2   = "faraz@himaya.ai"

# ─── Email definitions ────────────────────────────────────────────────────────

EMAILS = [

    # ── 1. OUTLOOK — Vendor Invoice BEC (subtle reply-to hijack) ─────────────
    {
        "label": "Outlook-1 | Vendor Invoice BEC — reply-to lookalike domain",
        "to": OUTLOOK_1,
        "from_name": "Al-Nasser Procurement Team",
        "reply_to": "procurement@al-nasser-group.co",   # lookalike — .co not .com
        "subject": f"Invoice #INV-2026-{NOW_DATE[:3].upper()}-0491 — Awaiting Approval",
        "html": f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:Calibri,Arial,sans-serif;font-size:14px;color:#1a1a1a;line-height:1.6;padding:20px;">
<p>Dear Adnan,</p>
<p>Please find the attached invoice for professional services rendered in {NOW_DATE[:7]}. 
This is a follow-up to our agreement from last quarter — payment terms are Net-30 as agreed.</p>
<table style="border-collapse:collapse;width:100%;max-width:480px;margin:16px 0;">
  <tr style="background:#f2f2f2;">
    <td style="padding:8px 12px;border:1px solid #ddd;font-weight:bold;">Invoice #</td>
    <td style="padding:8px 12px;border:1px solid #ddd;">INV-2026-APR-0491</td>
  </tr>
  <tr>
    <td style="padding:8px 12px;border:1px solid #ddd;font-weight:bold;">Amount Due</td>
    <td style="padding:8px 12px;border:1px solid #ddd;">SAR 84,200.00</td>
  </tr>
  <tr style="background:#f2f2f2;">
    <td style="padding:8px 12px;border:1px solid #ddd;font-weight:bold;">Due Date</td>
    <td style="padding:8px 12px;border:1px solid #ddd;">May 15, 2026</td>
  </tr>
  <tr>
    <td style="padding:8px 12px;border:1px solid #ddd;font-weight:bold;">Payment Ref</td>
    <td style="padding:8px 12px;border:1px solid #ddd;">ACQ-HL-2026-Q2</td>
  </tr>
</table>
<p>Please confirm receipt and process when convenient. For any adjustments, 
please reply to this email and our finance team will respond within one business day.</p>
<p>Bank details have changed from our previous correspondence — please use the following 
account for this and future payments:</p>
<blockquote style="border-left:3px solid #0070c0;padding-left:12px;color:#333;margin:16px 0;">
Bank: Riyad Bank · IBAN: SA0380000000608010167519 · SWIFT: RIBLSARI<br/>
Account Name: Al-Nasser Group For Consulting &amp; Advisory Services
</blockquote>
<p>Kind regards,<br/>
<strong>Tariq Hassan</strong><br/>
Senior Accounts Manager — Al-Nasser Group<br/>
<span style="font-size:12px;color:#666;">tariq.hassan@al-nasser-group.co | +966 55 774 3291</span></p>
<hr style="border:none;border-top:1px solid #eee;margin:20px 0;"/>
<p style="font-size:11px;color:#999;">
This message is intended solely for the addressee. If you are not the intended recipient, 
please notify the sender and delete this message.
</p>
</body></html>""",
        "text": f"""Dear Adnan,

Please find the attached invoice for professional services rendered in {NOW_DATE[:7]}.
Invoice # INV-2026-APR-0491 | Amount: SAR 84,200 | Due: May 15, 2026

Bank details have changed — please use:
Riyad Bank | IBAN: SA0380000000608010167519 | SWIFT: RIBLSARI
Account: Al-Nasser Group For Consulting & Advisory Services

Kind regards,
Tariq Hassan — Al-Nasser Group
tariq.hassan@al-nasser-group.co | +966 55 774 3291"""
    },

    # ── 2. OUTLOOK — IT Policy SharePoint credential harvest ─────────────────
    {
        "label": "Outlook-2 | IT Policy Update — SharePoint credential harvest",
        "to": OUTLOOK_2,
        "from_name": "IT Helpdesk Sana085",            # no em-dash: SES rejects non-ASCII encoded display names
        "reply_to": VERIFIED_SENDER,                    # SES requires verified reply-to; lookalike domain embedded in body link/contact
        "subject": "Action Required: Review Updated Acceptable Use Policy by Friday",
        "html": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#252525;padding:24px;max-width:600px;">
<div style="border-top:4px solid #0078d4;padding-top:16px;">
  <p style="color:#0078d4;font-weight:600;font-size:13px;margin:0 0 12px;">IT SERVICES — POLICY UPDATE NOTICE</p>
  <h2 style="font-size:18px;margin:0 0 16px;font-weight:600;">Updated Acceptable Use Policy — Acknowledgment Required</h2>
</div>
<p>Hi Faraz,</p>
<p>Our Information Security team has updated the <strong>Acceptable Use Policy (AUP)</strong> 
and <strong>Remote Access Guidelines</strong> effective May 1, 2026. All employees must 
review and acknowledge the updated policy before the end of this week.</p>
<p>Failure to acknowledge by <strong>Friday, May 2</strong> may result in temporary 
suspension of remote access credentials pending compliance review.</p>
<div style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;padding:16px;margin:20px 0;">
  <p style="margin:0 0 8px;font-size:13px;color:#555;">Document ready for review:</p>
  <p style="margin:0;font-weight:600;">📄 AUP-v4.2-2026 — Acceptable Use Policy</p>
  <p style="margin:4px 0 0;font-size:12px;color:#777;">Shared via SharePoint · Requires sign-in</p>
</div>
<div style="margin:24px 0;">
  <a href="http://sana085-sharepoint-portal.com/sites/IT/policies/AUP-v4.2?auth=required&redirect=true"
     style="background:#0078d4;color:white;padding:11px 24px;text-decoration:none;border-radius:3px;font-size:14px;display:inline-block;">
    Review &amp; Acknowledge Policy →
  </a>
</div>
<p>If you have already acknowledged, please disregard this reminder. 
For questions, contact the IT helpdesk by replying to this message.</p>
<p style="font-size:13px;">Thanks,<br/>
<strong>IT Services Team</strong><br/>
Sana085 Corporation</p>
<hr style="border:none;border-top:1px solid #eee;margin:20px 0;"/>
<p style="font-size:11px;color:#aaa;">
Automated notification from IT Services. 
<a href="#" style="color:#aaa;">Unsubscribe from policy reminders</a>
</p>
</body></html>""",
        "text": """Hi Faraz,

Our IT team has updated the Acceptable Use Policy (AUP), effective May 1, 2026.
All employees must review and acknowledge before Friday, May 2.

Review here (requires sign-in):
http://sana085-sharepoint-portal.com/sites/IT/policies/AUP-v4.2?auth=required

IT Services Team | Sana085 Corporation"""
    },

    # ── 3. GMAIL — Google Drive share notification impersonation ──────────────
    {
        "label": "Gmail-1 | Google Drive share impersonation — lookalike link",
        "to": GMAIL_1,
        "from_name": "Google Drive",
        "reply_to": "no-reply@drive-google-workspace.com",   # typosquat
        "subject": "Adnan Ahmed shared a file with you",
        "html": """<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:Roboto,Arial,sans-serif;background:#f1f3f4;padding:20px;">
<div style="max-width:520px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,0.12);">
  <div style="padding:24px 32px;border-bottom:1px solid #e8eaed;">
    <div style="display:flex;align-items:center;gap:12px;">
      <div style="width:40px;height:40px;border-radius:50%;background:#4285f4;display:flex;align-items:center;justify-content:center;color:white;font-weight:bold;font-size:16px;">A</div>
      <div>
        <p style="margin:0;font-size:14px;"><strong>Asim Khan</strong> shared a document with you</p>
        <p style="margin:2px 0 0;font-size:12px;color:#5f6368;">asim@himaya.ai</p>
      </div>
    </div>
  </div>
  <div style="padding:24px 32px;">
    <div style="display:flex;align-items:center;gap:12px;padding:16px;border:1px solid #e8eaed;border-radius:8px;margin-bottom:20px;">
      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M14 2H6C4.9 2 4 2.9 4 4v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6z" fill="#4285f4"/>
        <path d="M14 2v6h6" fill="#c5cae9"/>
      </svg>
      <div>
        <p style="margin:0;font-size:14px;font-weight:500;">Himaya_Board_Q2_Financials_DRAFT.docx</p>
        <p style="margin:2px 0 0;font-size:12px;color:#5f6368;">Google Docs · View access granted</p>
      </div>
    </div>
    <div style="text-align:center;">
      <a href="http://drive-google-workspace.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmULk22KKy/view?usp=sharing&authuser=adnan@himaya.ai"
         style="background:#1a73e8;color:white;padding:10px 24px;text-decoration:none;border-radius:4px;font-size:14px;display:inline-block;">
        Open in Docs
      </a>
    </div>
    <p style="font-size:12px;color:#5f6368;margin-top:20px;">
      Asim added a note: <em>"Adnan please review the Q2 projections section before tomorrow's call — your input on the KSA figures is needed urgently"</em>
    </p>
  </div>
  <div style="padding:16px 32px;background:#f8f9fa;border-top:1px solid #e8eaed;">
    <p style="font-size:11px;color:#5f6368;margin:0;">
      Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043 ·
      <a href="#" style="color:#1a73e8;text-decoration:none;">Privacy Policy</a>
    </p>
  </div>
</div>
</body></html>""",
        "text": """Asim Khan (asim@himaya.ai) has shared a document with you.

Himaya_Board_Q2_Financials_DRAFT.docx — View access granted

Asim's note: "Adnan please review the Q2 projections section before tomorrow's call"

Open: http://drive-google-workspace.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmULk22KKy/view

Google Drive Team"""
    },

    # ── 4. GMAIL — HR Benefits update, no urgency, quiet redirect ────────────
    {
        "label": "Gmail-2 | HR Benefits — quiet social engineering, no urgency",
        "to": GMAIL_2,
        "from_name": "Himaya HR Team",
        "reply_to": "hr@himaya-employee-portal.com",   # lookalike HR portal domain
        "subject": f"Your 2026 Benefits Summary is Ready",
        "html": f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="font-family:Helvetica,Arial,sans-serif;font-size:14px;color:#333;padding:32px;max-width:580px;margin:0 auto;">
<p style="color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-bottom:24px;">Himaya Employee Services</p>
<h2 style="font-size:20px;font-weight:600;margin:0 0 16px;">Your 2026 Benefits Summary</h2>
<p>Hi Faraz,</p>
<p>Your personalized 2026 benefits summary and enrollment confirmation is now available. 
This includes your health coverage details, leave balances, and any changes effective from 
January 1, 2026.</p>
<div style="background:#f9f9f9;border-radius:6px;padding:20px;margin:20px 0;">
  <p style="margin:0 0 8px;font-weight:600;">Summary includes:</p>
  <ul style="margin:0;padding-left:20px;line-height:2;">
    <li>Health &amp; dental coverage confirmation</li>
    <li>Annual leave balance as of {NOW_DATE}</li>
    <li>Updated end-of-service benefit calculation</li>
    <li>Q1 payslip archive link</li>
  </ul>
</div>
<p>
  <a href="http://himaya-employee-portal.com/benefits/2026?emp=faraz&token=bX8pLm3qZw2T&lang=en"
     style="color:#0070c0;text-decoration:underline;">
    View Your 2026 Benefits Summary →
  </a>
</p>
<p>If anything looks incorrect or you have questions, feel free to reply to this email 
and a member of our People team will be happy to help.</p>
<p style="margin-top:24px;">Warm regards,<br/>
<strong>Nour Al-Hasan</strong><br/>
People &amp; Culture · Himaya Technologies<br/>
<span style="font-size:12px;color:#888;">hr@himaya-employee-portal.com</span></p>
<hr style="border:none;border-top:1px solid #eee;margin:28px 0;"/>
<p style="font-size:11px;color:#aaa;">
You're receiving this because you are a registered Himaya employee. 
<a href="#" style="color:#aaa;">Manage notification preferences</a>
</p>
</body></html>""",
        "text": f"""Hi Faraz,

Your 2026 benefits summary is now available, including health coverage, leave balances, and Q1 payslip archive.

View your summary here:
http://himaya-employee-portal.com/benefits/2026?emp=faraz&token=bX8pLm3qZw2T

Warm regards,
Nour Al-Hasan — People & Culture, Himaya Technologies"""
    },
]

# ─── Send ─────────────────────────────────────────────────────────────────────

def send(email_def: dict) -> dict:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = email_def["subject"]
    msg["From"] = f"{email_def['from_name']} <{VERIFIED_SENDER}>"
    msg["To"] = email_def["to"]
    msg["Reply-To"] = email_def["reply_to"]
    msg["X-Helios-Test"] = "subtle-phish-simulation-2026-04-27"
    msg["X-Originating-IP"] = "5.188.206.14"  # known RU bulletproof hosting range

    msg.attach(MIMEText(email_def["text"], "plain"))
    msg.attach(MIMEText(email_def["html"], "html"))

    try:
        r = SES.send_raw_email(
            Source=VERIFIED_SENDER,
            Destinations=[email_def["to"]],
            RawMessage={"Data": msg.as_string()},
        )
        return {"ok": True, "mid": r["MessageId"]}
    except Exception as e:
        return {"ok": False, "err": str(e)}


if __name__ == "__main__":
    print("🎣 Helios — Subtle Phishing Simulation")
    print("=" * 64)
    print("4 emails: 2x Outlook (sana085) + 2x Gmail (himaya.ai)")
    print("All designed to be low-noise / realistic (no all-caps urgency)\n")

    passed = 0
    for i, em in enumerate(EMAILS, 1):
        r = send(em)
        status = "✅" if r["ok"] else "❌"
        mid = r.get("mid", r.get("err", ""))[:40]
        print(f"[{i}/4] {status} {em['label']}")
        print(f"       → {em['to']}")
        print(f"       Reply-To: {em['reply_to']}  (lookalike domain)")
        print(f"       MID: {mid}")
        print()
        if r["ok"]:
            passed += 1

    print("=" * 64)
    print(f"Sent: {passed}/4")
    print()
    print("⏱  Delta-sync runs every ~60s. Check threat queue in 2-3 min.")
    print()
    print("What to validate:")
    print("  Outlook emails (1 & 2):")
    print("    · Reply-to domain mismatch flagged (BEC / PHISHING signal)")
    print("    · Lookalike domain in link body detected")
    print("    · Risk score should be 60-100 — auto-triage should QUARANTINE")
    print()
    print("  Gmail emails (3 & 4):")
    print("    · Google impersonation (email 3) → CREDENTIAL_HARVESTING")
    print("    · HR portal lookalike (email 4) → PHISHING or SUSPICIOUS")
    print("    · Both should surface in threat queue within 2-3 min")
    print()
    print("  Both providers:")
    print("    · From: himaya.ai (verified SES) but Reply-To = attacker domain")
    print("    · X-Originating-IP = 5.188.206.14 (bulletproof RU range)")
    print("    · Neo4j graph score: sender should be new/unknown → lower trust")
