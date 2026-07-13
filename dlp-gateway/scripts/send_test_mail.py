#!/usr/bin/env python3
"""Send a test message into the local DLP gateway."""

from __future__ import annotations

import argparse
import smtplib
from email.message import EmailMessage


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--from-addr", default="alice@example.test")
    parser.add_argument("--to-addr", default="bob@external.test")
    parser.add_argument("--subject", default="DLP gateway local test")
    args = parser.parse_args()

    msg = EmailMessage()
    msg["From"] = args.from_addr
    msg["To"] = args.to_addr
    msg["Subject"] = args.subject
    msg["X-Himaya-Org-Id"] = "should-be-stripped"
    msg.set_content(
        "Hello from the local DLP gateway test.\n"
        "This body should arrive intact in MailHog.\n"
    )

    with smtplib.SMTP(args.host, args.port, timeout=20) as client:
        refused = client.send_message(msg)
        print(f"sent ok refused={refused}")


if __name__ == "__main__":
    main()
