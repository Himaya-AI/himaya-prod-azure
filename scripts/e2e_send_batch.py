"""
End-to-end pipeline test sender. Sends a set of BENIGN security-awareness test
simulation emails (standard phishing-simulation patterns — no real malware and
no live credential capture; links point at non-resolving sim domains) to the
given recipient so we can verify ingestion -> auto-triage -> provider action.

Usage:
  python3 scripts/e2e_send_batch.py --to adnan@himaya.ai --tag GML
"""
import argparse
import datetime as _dt
import sys

sys.path.insert(0, ".")
from scripts.send_test_email import send  # noqa: E402


def build_cases(ts: str, tag: str):
    return [
        {
            "name": "PHISH->QUARANTINE",
            "sender": "IT Helpdesk <helios-test-attacker@himaya.ai>",
            "subject": f"{ts}-{tag}-PHISH Action required: verify your Microsoft 365 password",
            "html": (
                "<p>Dear user,</p>"
                "<p>Your mailbox password expires <b>today</b>. To avoid losing "
                "access you must reverify immediately.</p>"
                '<p><a href="http://microsoft-365-verify.security-alert.win/login?u=adnan">'
                "Reverify your account now</a></p>"
                "<p>Failure to act will suspend your account within 24 hours.</p>"
                "<p>IT Helpdesk</p>"
            ),
        },
        {
            "name": "SPAM->MARK_AS_SPAM",
            "sender": "Mega Deals <helios-test-attacker@himaya.ai>",
            "subject": f"{ts}-{tag}-SPAM You WON a 1000 dollar gift card - claim now",
            "html": (
                "<p>CONGRATULATIONS!!!</p>"
                "<p>You have been selected to receive a <b>1000 dollar Amazon gift "
                "card</b>. Limited time only!</p>"
                '<p><a href="http://cheap-deals-now.biz/claim">CLICK HERE TO CLAIM</a></p>'
                "<p>Unsubscribe | 100% free | act fast</p>"
            ),
        },
        {
            "name": "BEC->ESCALATE",
            "sender": "Adnan Ahmed - CEO <adnan.heliostest@gmail.com>",
            "subject": f"{ts}-{tag}-SUS Quick task - are you available?",
            "html": (
                "<p>Hi,</p>"
                "<p>I am in back-to-back meetings and need you to handle an urgent "
                "vendor payment discreetly. Are you at your desk? Reply and I will "
                "send the wire details.</p>"
                "<p>Sent from my iPhone</p>"
            ),
        },
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--to", required=True)
    ap.add_argument("--tag", default="GML")
    ap.add_argument("--ts", default=None)
    a = ap.parse_args()
    ts = a.ts or _dt.datetime.now().strftime("%H%M%S")
    print(f"RUN_TS={ts} TAG={a.tag} TO={a.to}")
    for c in build_cases(ts, a.tag):
        try:
            mid = send(c["sender"], a.to, c["subject"], c["html"])
            print(f"SENT [{c['name']}] subj='{c['subject']}' -> {mid}")
        except SystemExit as e:
            print(f"FAILED [{c['name']}]: {e}")
    print("BATCH DONE")


if __name__ == "__main__":
    main()
