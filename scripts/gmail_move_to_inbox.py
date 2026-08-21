"""
Move Gmail messages matching a query OUT of SPAM and INTO the INBOX, so the
Himaya delta-sync (which scans inbox mail via `after:` search that excludes spam)
will ingest them. Used only to run controlled end-to-end tests when Gmail's own
spam filter intercepts a simulated-phishing test email before Himaya sees it.

Auth: GOOGLE_SERVICE_ACCOUNT_B64 (service-account JSON, domain-wide delegation).

Usage:
  python scripts/gmail_move_to_inbox.py --user adnan@himaya.ai --query "GTEST-BEC"
"""
import argparse
import base64
import json
import os
import sys
import time

import httpx

GMAIL = "https://gmail.googleapis.com/gmail/v1"


def _sa_headers(subject_email: str) -> dict:
    from google.oauth2 import service_account
    import google.auth.transport.requests as ga_requests

    sa_info = json.loads(base64.b64decode(os.environ["GOOGLE_SERVICE_ACCOUNT_B64"]).decode())
    creds = service_account.Credentials.from_service_account_info(
        sa_info, scopes=["https://mail.google.com/"]
    ).with_subject(subject_email)
    creds.refresh(ga_requests.Request())
    return {"Authorization": f"Bearer {creds.token}"}


def _req(client: httpx.Client, method: str, url: str, **kw):
    for attempt in range(1, 8):
        r = client.request(method, url, **kw)
        if r.status_code != 429:
            return r
        time.sleep(2 * attempt)
    return r


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--user", required=True)
    ap.add_argument("--query", required=True)
    ap.add_argument("--limit", type=int, default=5)
    a = ap.parse_args()

    headers = _sa_headers(a.user)
    with httpx.Client(timeout=30) as c:
        lst = _req(
            c, "GET", f"{GMAIL}/users/{a.user}/messages",
            headers=headers,
            params={"maxResults": a.limit, "includeSpamTrash": "true", "q": a.query},
        )
        lst.raise_for_status()
        msgs = lst.json().get("messages", []) or []
        if not msgs:
            print(f"No messages matching {a.query!r} for {a.user}")
            return
        for m in msgs:
            mid = m["id"]
            meta = _req(
                c, "GET", f"{GMAIL}/users/{a.user}/messages/{mid}",
                headers=headers,
                params={"format": "metadata", "metadataHeaders": ["Subject"]},
            )
            labels = meta.json().get("labelIds", []) if meta.status_code == 200 else []
            subj = ""
            for h in (meta.json().get("payload", {}) or {}).get("headers", []):
                if h.get("name", "").lower() == "subject":
                    subj = h.get("value", "")
            r = _req(
                c, "POST", f"{GMAIL}/users/{a.user}/messages/{mid}/modify",
                headers={**headers, "Content-Type": "application/json"},
                json={"removeLabelIds": ["SPAM", "TRASH"], "addLabelIds": ["INBOX", "UNREAD"]},
            )
            print(f"[{r.status_code}] moved {mid} -> INBOX (was {labels}) | {subj[:50]!r}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"MOVE ERROR: {type(e).__name__}: {e}")
        sys.exit(1)
