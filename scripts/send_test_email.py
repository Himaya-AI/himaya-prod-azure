"""
Flexible SES test-email sender (uses send-raw-email + base64 MIME so links,
quotes and commas in the HTML body work — the aws --message shorthand does not).

Usage:
  python3 scripts/send_test_email.py --to adnan@himaya.ai \
      --from "IT Helpdesk <it-helpdesk@attacker-sim.himaya.ai>" \
      --subject "08192154-PHISH verify your mailbox" \
      --html '<p>...<a href="https://x/login">verify</a></p>'

Only SES-verified identities may be used as --from.
"""
import argparse
import base64
import json
import os
import subprocess
import tempfile
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SES_REGION = os.getenv("SES_REGION", "us-east-1")


def send(sender: str, to: str, subject: str, html: str, text: str | None = None) -> str:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    msg.attach(MIMEText(text or _strip(html), "plain"))
    msg.attach(MIMEText(html, "html"))
    b64 = base64.b64encode(msg.as_string().encode()).decode()
    p = os.path.join(tempfile.mkdtemp(prefix="test_eml_"), "raw.json")
    with open(p, "w") as f:
        json.dump({"Data": b64}, f)
    # Extract the bare address for --source
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


def _strip(html: str) -> str:
    import re
    return re.sub("<[^>]+>", " ", html)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", required=True)
    ap.add_argument("--from", dest="sender", required=True)
    ap.add_argument("--subject", required=True)
    ap.add_argument("--html", required=True)
    a = ap.parse_args()
    res = send(a.sender, a.to, a.subject, a.html)
    print(f"SENT -> {a.to} | {a.subject} | {res}")


if __name__ == "__main__":
    main()
