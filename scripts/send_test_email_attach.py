"""
SES raw-email sender WITH a file attachment, for end-to-end pipeline testing.

The attachment is BENIGN — its only purpose is to carry a "dangerous" file
extension (e.g. .docm) so Himaya's reputation layer flags a hard IOC
(suspicious_attachments), which is the realistic signal a malware-bearing email
would produce. No EICAR / no real malware is used, so provider AV won't strip it.

Usage:
  python3 scripts/send_test_email_attach.py --to adnan@himaya.ai \
      --from "IT Helpdesk <helios-test-attacker@himaya.ai>" \
      --subject "PHISH w/ payload" --html '<p>See attached invoice</p>' \
      --attach-name invoice_scan.docm
"""
import argparse
import base64
import json
import os
import subprocess
import tempfile
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders

SES_REGION = os.getenv("SES_REGION", "us-east-1")

# A minimal, benign OOXML-ish blob. Not a real macro; just bytes so the file is
# non-empty and carries the flagged extension. Sandbox oletools may note it's
# not a valid OLE file — that's fine; the extension-based hard IOC is the signal.
_BENIGN_BLOB = b"PK\x03\x04 himaya-benign-test-attachment (no macro, no payload) " * 8


def send(sender: str, to: str, subject: str, html: str, attach_name: str) -> str:
    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to

    alt = MIMEMultipart("alternative")
    import re
    alt.attach(MIMEText(re.sub("<[^>]+>", " ", html), "plain"))
    alt.attach(MIMEText(html, "html"))
    msg.attach(alt)

    part = MIMEBase("application", "octet-stream")
    part.set_payload(_BENIGN_BLOB)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{attach_name}"')
    msg.attach(part)

    b64 = base64.b64encode(msg.as_string().encode()).decode()
    p = os.path.join(tempfile.mkdtemp(prefix="test_eml_att_"), "raw.json")
    with open(p, "w") as f:
        json.dump({"Data": b64}, f)
    src_addr = sender.split("<")[-1].strip(">") if "<" in sender else sender
    out = subprocess.run(
        ["aws", "ses", "send-raw-email", "--region", SES_REGION,
         "--source", src_addr, "--destinations", to,
         "--raw-message", f"file://{p}"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise SystemExit(f"SEND FAILED to {to}: {out.stderr or out.stdout}")
    return out.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", required=True)
    ap.add_argument("--from", dest="sender", required=True)
    ap.add_argument("--subject", required=True)
    ap.add_argument("--html", required=True)
    ap.add_argument("--attach-name", default="invoice_scan.docm")
    a = ap.parse_args()
    res = send(a.sender, a.to, a.subject, a.html, a.attach_name)
    print(f"SENT -> {a.to} | {a.subject} | attach={a.attach_name} | {res}")


if __name__ == "__main__":
    main()
