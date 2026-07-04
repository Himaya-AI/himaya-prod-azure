"""
Phishing test email sender — sends 3 different phishing flavors to the target Outlook inbox.
Uses AWS SES with spoofed-looking From headers (technically From: a verified domain,
Reply-To a fake attacker domain to make it look spoofed).

Target: adnanahmed@sana085.onmicrosoft.com

Run: python3 scripts/send_phishing_test.py
"""

import boto3
import json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import sys

TARGET = "adnanahmed@sana085.onmicrosoft.com"
SES_REGION = "us-east-1"

# Use verified sender identity but spoof the display name and reply-to
# SES requires From = a verified identity; we use our attacker test domain
# but craft the email body to look like it came from attacker domains
VERIFIED_SENDER = "helios-test-attacker@himaya.ai"

# Three distinct phishing flavors
PHISHING_EMAILS = [
    {
        "label": "Flavor 1: Credential Harvesting (Microsoft 365 Password Reset)",
        "from_display": "Microsoft Security Team",
        "from_address": VERIFIED_SENDER,  # SES requires verified sender
        "reply_to": "noreply@microsoft-account-protection.net",
        "subject": "⚠️ Urgent: Your Microsoft 365 Account Will Be Suspended in 24 Hours",
        "html": """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#f0f0f0;padding:20px;">
<div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;overflow:hidden;">
  <div style="background:#0078d4;padding:20px;text-align:center;">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/200px-Microsoft_logo.svg.png" width="120" alt="Microsoft" />
  </div>
  <div style="padding:30px;">
    <h2 style="color:#333;">Action Required: Verify Your Account Immediately</h2>
    <p>We detected unusual sign-in activity on your Microsoft 365 account. To prevent unauthorized access, you must verify your identity within <strong>24 hours</strong>.</p>
    <p><strong>Account:</strong> adnanahmed@sana085.onmicrosoft.com</p>
    <p><strong>Suspicious activity from:</strong> 185.220.101.47 (Russia)</p>
    <div style="text-align:center;margin:30px 0;">
      <a href="http://microsoft-account-protection.net/verify?token=8f3k2mNpQ9xL&user=adnanahmed" 
         style="background:#0078d4;color:white;padding:12px 30px;text-decoration:none;border-radius:4px;font-weight:bold;">
        Verify Account Now
      </a>
    </div>
    <p style="color:#666;font-size:12px;">If you do not verify within 24 hours, your account will be suspended. This is an automated security notification from Microsoft Corporation.</p>
    <p style="color:#666;font-size:12px;">© 2026 Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p>
  </div>
</div>
</body>
</html>""",
        "text": "ACTION REQUIRED: Your Microsoft 365 account shows suspicious activity from Russia (185.220.101.47). Verify at http://microsoft-account-protection.net/verify?token=8f3k2mNpQ9xL within 24 hours or account will be suspended."
    },
    {
        "label": "Flavor 2: Invoice Fraud / BEC (CFO Wire Transfer Request)",
        "from_display": "Khalid Al-Mansoor CFO",
        "from_address": VERIFIED_SENDER,  # SES requires verified sender
        "reply_to": "khalid.almansoor.cfo@himaya-group-finance.com",
        "subject": "URGENT: Wire Transfer Needed Today - Confidential",
        "html": """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;padding:20px;color:#333;">
<p>Hi Adnan,</p>
<p>I need your urgent assistance with a confidential wire transfer that must be completed today.</p>
<p>We are finalizing a strategic acquisition and I need you to initiate a transfer of <strong>$247,500 USD</strong> to our escrow account before the market closes.</p>
<p><strong>Wire Details:</strong></p>
<ul>
  <li>Bank: Emirates NBD</li>
  <li>Account Name: Gulf Capital Holdings LLC</li>
  <li>IBAN: AE070260001015107062303</li>
  <li>SWIFT: EBILAEAD</li>
  <li>Reference: ACQ-2026-0414-CONF</li>
</ul>
<p>This is highly confidential — please do not discuss with other team members or use company email for follow-ups. Reply to this personal email only.</p>
<p>I am currently in board meetings and cannot take calls. Please confirm by email once done.</p>
<p>Best regards,<br/>
<strong>Khalid Al-Mansoor</strong><br/>
Chief Financial Officer<br/>
Himaya Technologies Group</p>
<p style="font-size:10px;color:#999;">This message is intended only for the named recipient and is confidential.</p>
</body>
</html>""",
        "text": "Hi Adnan, I need your urgent assistance with a confidential wire transfer of $247,500 USD today for a strategic acquisition. Please transfer to Gulf Capital Holdings LLC, IBAN: AE070260001015107062303, SWIFT: EBILAEAD. Do not discuss with others. - Khalid Al-Mansoor, CFO"
    },
    {
        "label": "Flavor 3: Malware Delivery (DocuSign / Document Phishing)",
        "from_display": "DocuSign eSignature Notifications",
        "from_address": VERIFIED_SENDER,  # SES requires verified sender
        "reply_to": "noreply@docusign-secure-portal.net",
        "subject": "Complete Document Signing - Contract Awaiting Your Signature",
        "html": """<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px;">
<div style="max-width:600px;margin:0 auto;background:white;border-radius:8px;border:1px solid #ddd;">
  <div style="background:#1a5276;padding:20px;text-align:center;">
    <p style="color:white;font-size:22px;font-weight:bold;margin:0;">DocuSign</p>
  </div>
  <div style="padding:30px;">
    <p style="color:#666;">Adnan Ahmed has been requested to review and sign the following document:</p>
    <div style="background:#f8f9fa;border:1px solid #dee2e6;border-radius:4px;padding:15px;margin:20px 0;">
      <p style="margin:0;font-size:14px;"><strong>Document:</strong> Himaya_Partnership_Agreement_Q2_2026.docm</p>
      <p style="margin:5px 0 0;font-size:12px;color:#666;">Expires: April 15, 2026 | Document ID: DS-8847632-2026</p>
    </div>
    <div style="text-align:center;margin:25px 0;">
      <a href="http://docusign-secure-portal.net/sign?doc=DS-8847632&recipient=adnanahmed&token=kX9mP2nQr7sT" 
         style="background:#f59e0b;color:white;padding:12px 30px;text-decoration:none;border-radius:4px;font-weight:bold;display:inline-block;">
        Review &amp; Sign Document
      </a>
    </div>
    <p style="font-size:11px;color:#999;text-align:center;">
      Note: The document contains macros that must be enabled to display properly.<br/>
      When prompted, click "Enable Content" to view the full agreement.
    </p>
    <hr style="border:none;border-top:1px solid #eee;"/>
    <p style="font-size:11px;color:#999;">DocuSign Envelope ID: 8847632-ABCD-2026. Do Not Share This Email. 
    <a href="#">Unsubscribe</a> | <a href="#">Privacy Policy</a></p>
  </div>
</div>
</body>
</html>""",
        "text": "You have a document awaiting your signature: Himaya_Partnership_Agreement_Q2_2026.docm. Sign at http://docusign-secure-portal.net/sign?doc=DS-8847632&recipient=adnanahmed&token=kX9mP2nQr7sT - Note: Enable macros to view content."
    }
]


def send_phishing_email(ses_client, email_def: dict) -> dict:
    """Send a single phishing test email via SES raw send."""
    msg = MIMEMultipart('alternative')
    msg['Subject'] = email_def['subject']
    # Use verified sender address but set display name to look like attacker
    msg['From'] = f"{email_def['from_display']} <{email_def['from_address']}>"
    msg['To'] = TARGET
    msg['Reply-To'] = email_def['reply_to']
    # Add X-Helios-Test header so we can identify these in logs
    msg['X-Helios-Test'] = 'phishing-simulation-2026-04-14'
    # Spoof the X-Originating-IP to look like a foreign server
    msg['X-Originating-IP'] = '91.108.4.227'  # Telegram Russia DC — known malicious range
    
    # Attach parts
    part1 = MIMEText(email_def['text'], 'plain')
    part2 = MIMEText(email_def['html'], 'html')
    msg.attach(part1)
    msg.attach(part2)
    
    try:
        response = ses_client.send_raw_email(
            Source=email_def['from_address'],
            Destinations=[TARGET],
            RawMessage={'Data': msg.as_string()}
        )
        return {"success": True, "message_id": response['MessageId'], "label": email_def['label']}
    except Exception as e:
        return {"success": False, "error": str(e), "label": email_def['label']}


if __name__ == "__main__":
    print(f"🎣 Helios Phishing Test — Sending 3 emails to: {TARGET}")
    print("=" * 60)
    
    ses = boto3.client('ses', region_name=SES_REGION)
    
    results = []
    for i, email_def in enumerate(PHISHING_EMAILS, 1):
        print(f"\n[{i}/3] Sending: {email_def['label']}")
        print(f"       From display: {email_def['from_display']}")
        print(f"       Subject: {email_def['subject'][:60]}...")
        
        result = send_phishing_email(ses, email_def)
        results.append(result)
        
        if result['success']:
            print(f"       ✅ Sent! MessageId: {result['message_id']}")
        else:
            print(f"       ❌ Failed: {result['error']}")
    
    print("\n" + "=" * 60)
    success_count = sum(1 for r in results if r['success'])
    print(f"\n📊 Results: {success_count}/3 emails sent successfully")
    print(f"\n⏱  Delta-sync runs every ~60s. Check Helios threat queue in ~2-3 minutes.")
    print(f"   Expected: All 3 should score HIGH RISK and be QUARANTINED by auto-triage.")
    print(f"\n🔍 Things to validate:")
    print(f"   1. Threats appear in /threats page with high risk scores")
    print(f"   2. Auto-triage quarantines them (status=quarantined)")
    print(f"   3. Emails physically moved to Junk/Helios-Quarantine in Outlook")
    print(f"   4. Neo4j shows 'no prior sender-recipient relationship'")
    print(f"   5. Dashboard risk score updates to reflect new threats")
