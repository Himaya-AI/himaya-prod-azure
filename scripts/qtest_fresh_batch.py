"""
Fresh quarantine/release test batch. Sends BENIGN security-awareness test
simulation emails (standard phishing-sim patterns — no real malware, no live
credential capture; links point at non-resolving sim domains) plus a few
obvious spam samples, so we can verify:

  1. attack mail  -> classified malicious -> quarantined  (test RELEASE)
  2. spam mail     -> classified spam                       (test MANUAL RELEASE)

Scenarios are intentionally different from e2e_send_batch.py so the queue
doesn't dedupe against earlier runs.

Usage:
  python3 scripts/qtest_fresh_batch.py --to adnan@himaya.ai --tag GML
  python3 scripts/qtest_fresh_batch.py --to AdnanAhmed@sana085.onmicrosoft.com --tag OL
"""
import argparse
import datetime as _dt
import sys

sys.path.insert(0, ".")
from scripts.send_test_email import send  # noqa: E402

# One verified SES sending identity, varied display names.
FROM_ATTACK = "helios-test-attacker@himaya.ai"


def build_attack(ts: str, tag: str):
    """One attack per vendor, distinct between Outlook and Gmail runs."""
    if tag.upper().startswith("OL"):
        # Outlook: DocuSign-style credential phishing
        return {
            "name": "PHISH->QUARANTINE (DocuSign)",
            "sender": f"DocuSign <{FROM_ATTACK}>",
            "subject": f"{ts}-{tag}-PHISH Completed: You have a document to sign",
            "html": (
                "<p>Hello,</p>"
                "<p><b>Adnan Ahmed</b> has sent you a document to review and "
                "electronically sign.</p>"
                '<p><a href="http://docusign-secure-view.account-verify.win/doc?id=8842">'
                "REVIEW DOCUMENT</a></p>"
                "<p>This document will expire in 48 hours. Do not share this email.</p>"
                "<p>&copy; DocuSign Inc.</p>"
            ),
        }
    # Gmail: fake DHL parcel-delivery phishing
    return {
        "name": "PHISH->QUARANTINE (DHL)",
        "sender": f"DHL Express <{FROM_ATTACK}>",
        "subject": f"{ts}-{tag}-PHISH Your parcel is on hold - customs fee required",
        "html": (
            "<p>Dear Customer,</p>"
            "<p>Your parcel <b>#DHL-772140-KSA</b> could not be delivered due to "
            "an unpaid customs fee of <b>SAR 21.50</b>.</p>"
            '<p><a href="http://dhl-redelivery.parcel-fee-pay.win/track?p=772140">'
            "Pay the fee and reschedule delivery</a></p>"
            "<p>Your package will be returned to sender within 3 days if unpaid.</p>"
            "<p>DHL Express Customer Service</p>"
        ),
    }


def build_spam(ts: str, tag: str):
    """2-3 obvious spam samples per vendor for manual-release testing."""
    return [
        {
            "name": "SPAM-crypto",
            "sender": f"Crypto Rewards <{FROM_ATTACK}>",
            "subject": f"{ts}-{tag}-SPAM Claim your 0.5 BTC bonus before midnight",
            "html": (
                "<p>Congratulations trader!</p>"
                "<p>Your wallet qualifies for a <b>0.5 BTC welcome bonus</b>. "
                "This exclusive offer ends at midnight.</p>"
                '<p><a href="http://free-btc-bonus-claim.biz/go">CLAIM YOUR BONUS</a></p>'
                "<p>Unsubscribe | Terms apply | Act now</p>"
            ),
        },
        {
            "name": "SPAM-seo",
            "sender": f"Growth Marketing <{FROM_ATTACK}>",
            "subject": f"{ts}-{tag}-SPAM Rank #1 on Google - 70% OFF this week only",
            "html": (
                "<p>Hi there,</p>"
                "<p>We can get your website to the <b>#1 spot on Google</b> in 30 "
                "days. Limited slots at <b>70% OFF</b>!</p>"
                '<p><a href="http://cheap-seo-boost.biz/order">Order your SEO package</a></p>'
                "<p>Reply STOP to unsubscribe.</p>"
            ),
        },
        {
            "name": "SPAM-giftcard",
            "sender": f"Rewards Center <{FROM_ATTACK}>",
            "subject": f"{ts}-{tag}-SPAM You've been selected for a $500 IKEA gift card",
            "html": (
                "<p>Dear valued customer,</p>"
                "<p>You have been randomly selected to receive a <b>$500 IKEA gift "
                "card</b>. Complete a short survey to claim.</p>"
                '<p><a href="http://reward-survey-claim.biz/ikea">Start the survey</a></p>'
                "<p>100% free | No purchase necessary | Unsubscribe</p>"
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

    cases = [build_attack(ts, a.tag)] + build_spam(ts, a.tag)
    for c in cases:
        try:
            mid = send(c["sender"], a.to, c["subject"], c["html"])
            print(f"SENT [{c['name']}] subj='{c['subject']}' -> {mid}")
        except SystemExit as e:
            print(f"FAILED [{c['name']}]: {e}")
    print("BATCH DONE")


if __name__ == "__main__":
    main()
