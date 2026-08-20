"""
Milder end-to-end test — designed to LAND IN THE INBOX (not EOP Junk) while
still tripping Himaya's URL/credential-harvest detection.

Differences vs send_detonation_test.py:
  - NO attachments (malicious PDF / encrypted zip are the biggest EOP triggers).
  - NO spoofed X-Originating-IP / lookalike Reply-To headers.
  - Business-looking subject/body from the SES-authenticated himaya.ai domain
    (good SPF/DKIM => better Inbox placement).
  - Keeps ONE credential-harvesting login link that Himaya detonates
    (Chromium detects input[type=password]) so it should still score HIGH.

Target defaults to the M365 mailbox. Override with DETON_TEST_TARGET.
Run: python3 scripts/send_inbox_test.py
"""
import os
import subprocess
import tempfile
import base64 as _b64
import json as _json
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

TARGET = os.getenv("DETON_TEST_TARGET", "adnanahmed@sana085.onmicrosoft.com")
# Sender is overridable so M365/EOP tests can use an alternate SES-verified domain
# (e.g. attacker-sim.himaya.ai) when the usual himaya.ai sender is being junked.
SENDER = os.getenv("DETON_TEST_SENDER", "helios-test-attacker@himaya.ai")
SES_REGION = "us-east-1"

# Credential-harvesting login form (real page with a password field) — Himaya's
# Chromium URL detonation flags input[type=password] as credential harvesting.
LOGIN_FORM_URL = "https://the-internet.herokuapp.com/login"

HTML = f"""<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;color:#333;line-height:1.5;">
<p>Hi Adnan,</p>
<p>Here is the shared <strong>Q3 payroll summary</strong> you requested. For
security, the document is behind our staff portal &mdash; please sign in to view it:</p>
<p><a href="{LOGIN_FORM_URL}">Open the staff portal &rarr;</a></p>
<p>Let me know if you have any trouble accessing it.</p>
<p>Best regards,<br>Finance Team</p>
</body></html>"""

TEXT = (
    "Hi Adnan, here is the shared Q3 payroll summary you requested. "
    f"Please sign in to view it: {LOGIN_FORM_URL} — Finance Team"
)


def main():
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Shared: Q3 payroll summary"
    msg["From"] = f"Finance Team <{SENDER}>"
    msg["To"] = TARGET
    msg["X-Helios-Test"] = "inbox-mild-2026"
    msg.attach(MIMEText(TEXT, "plain"))
    msg.attach(MIMEText(HTML, "html"))

    b64 = _b64.b64encode(msg.as_string().encode()).decode()
    raw_json_path = os.path.join(tempfile.mkdtemp(prefix="mild_eml_"), "raw.json")
    with open(raw_json_path, "w") as f:
        _json.dump({"Data": b64}, f)

    out = subprocess.run(
        ["aws", "ses", "send-raw-email", "--region", SES_REGION,
         "--source", SENDER, "--destinations", TARGET,
         "--raw-message", f"file://{raw_json_path}"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(f"SEND FAILED (rc={out.returncode})\nSTDOUT={out.stdout}\nSTDERR={out.stderr}")
        raise SystemExit(1)
    print(f"SENT to {TARGET} | {out.stdout.strip()}")
    print(f"  url: {LOGIN_FORM_URL}  (no attachments; mild subject for Inbox placement)")


if __name__ == "__main__":
    main()
