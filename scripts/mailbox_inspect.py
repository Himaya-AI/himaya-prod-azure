"""
Mailbox inspector — read-only verification of Himaya's provider-side actions.

Shows, for a given mailbox, the most recent messages and WHERE they actually
live (Gmail: INBOX / SPAM / CATEGORY_* / Himaya-Quarantine / Himaya-Suspicious
labels; M365: which folder + Outlook categories). Use it to confirm that a
quarantine/spam/escalate action really moved/labelled the message on the
provider side.

Auth (same creds as prod, supplied via env — never hard-coded):
  GOOGLE_SERVICE_ACCOUNT_B64   base64 of the service-account JSON (Gmail DWD)
  M365_CLIENT_ID / M365_CLIENT_SECRET / M365_TENANT_ID   (Graph app-only)

Usage:
  python scripts/mailbox_inspect.py --provider gmail --user adnan@himaya.ai [--query "Q3 payroll"] [--limit 15]
  python scripts/mailbox_inspect.py --provider m365  --user AdnanAhmed@sana085.onmicrosoft.com [--limit 15]
"""
import argparse
import base64
import json
import os
import sys

import time

import httpx

GMAIL = "https://gmail.googleapis.com/gmail/v1"
GRAPH = "https://graph.microsoft.com/v1.0"


def _get(client: httpx.Client, url: str, **kw):
    """GET with backoff on Gmail 429 (mailbox is heavily rate-limited)."""
    for attempt in range(1, 7):
        r = client.get(url, **kw)
        if r.status_code != 429:
            return r
        time.sleep(2 * attempt)
    return r


def _sa_headers(subject_email: str) -> dict:
    from google.oauth2 import service_account
    import google.auth.transport.requests as ga_requests

    sa_b64 = os.environ["GOOGLE_SERVICE_ACCOUNT_B64"]
    sa_info = json.loads(base64.b64decode(sa_b64).decode())
    scopes = ["https://mail.google.com/"]
    creds = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
    creds = creds.with_subject(subject_email)
    creds.refresh(ga_requests.Request())
    return {"Authorization": f"Bearer {creds.token}"}


def inspect_gmail(user: str, query: str | None, limit: int) -> None:
    headers = _sa_headers(user)
    with httpx.Client(timeout=30) as c:
        # id -> label name map
        lbl = _get(c, f"{GMAIL}/users/{user}/labels", headers=headers)
        lbl.raise_for_status()
        id2name = {l["id"]: l["name"] for l in lbl.json().get("labels", [])}

        params = {"maxResults": limit, "includeSpamTrash": "true"}
        if query:
            params["q"] = query
        lst = _get(c, f"{GMAIL}/users/{user}/messages", headers=headers, params=params)
        lst.raise_for_status()
        msgs = lst.json().get("messages", []) or []
        print(f"\n=== GMAIL {user} — {len(msgs)} recent message(s) "
              f"{'matching ' + repr(query) if query else '(incl. spam/trash)'} ===")
        for m in msgs:
            meta = _get(
                c,
                f"{GMAIL}/users/{user}/messages/{m['id']}",
                headers=headers,
                params={"format": "metadata", "metadataHeaders": ["Subject", "From", "Date"]},
            )
            if meta.status_code != 200:
                continue
            j = meta.json()
            labels = [id2name.get(x, x) for x in j.get("labelIds", [])]
            hdrs = {h["name"].lower(): h["value"] for h in j.get("payload", {}).get("headers", [])}
            # Highlight the placement that matters
            placement = []
            for key in ("INBOX", "SPAM", "TRASH"):
                if key in labels:
                    placement.append(key)
            himaya = [x for x in labels if x.startswith("Himaya-") or x.startswith("Helios-")]
            cats = [x for x in labels if x.startswith("CATEGORY_")]
            print(f"  [{','.join(placement) or 'none':11}] "
                  f"himaya={himaya or '-'} cat={cats or '-'} "
                  f"| {hdrs.get('subject','')[:48]!r} <- {hdrs.get('from','')[:34]}")


def _m365_token() -> str:
    tenant = os.getenv("M365_TENANT_ID", "common")
    if tenant == "common":
        # client-credentials needs a concrete tenant; the protected tenant here
        tenant = os.getenv("M365_TENANT_OVERRIDE", "sana085.onmicrosoft.com")
    r = httpx.post(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "client_id": os.environ["M365_CLIENT_ID"],
            "client_secret": os.environ["M365_CLIENT_SECRET"],
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def inspect_m365(user: str, limit: int) -> None:
    token = _m365_token()
    headers = {"Authorization": f"Bearer {token}"}
    with httpx.Client(timeout=30) as c:
        # folder id -> name (include hidden so Himaya-Quarantine shows)
        folders = {}
        fr = c.get(
            f"{GRAPH}/users/{user}/mailFolders",
            headers=headers,
            params={"$top": 100, "includeHiddenFolders": "true"},
        )
        if fr.status_code == 200:
            for f in fr.json().get("value", []):
                folders[f["id"]] = f.get("displayName", "?")
        print(f"\n=== M365 {user} — folders: {sorted(set(folders.values()))} ===")
        mr = c.get(
            f"{GRAPH}/users/{user}/messages",
            headers=headers,
            params={"$top": limit, "$select": "subject,from,parentFolderId,categories,receivedDateTime",
                    "$orderby": "receivedDateTime desc"},
        )
        if mr.status_code != 200:
            print(f"  messages fetch failed: {mr.status_code} {mr.text[:200]}")
            return
        for m in mr.json().get("value", []):
            folder = folders.get(m.get("parentFolderId"), m.get("parentFolderId", "?"))
            frm = (m.get("from", {}) or {}).get("emailAddress", {}).get("address", "")
            print(f"  [{folder:20}] cats={m.get('categories') or '-'} "
                  f"| {(m.get('subject') or '')[:48]!r} <- {frm[:34]}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", required=True, choices=["gmail", "m365"])
    ap.add_argument("--user", required=True)
    ap.add_argument("--query", default=None)
    ap.add_argument("--limit", type=int, default=15)
    a = ap.parse_args()
    try:
        if a.provider == "gmail":
            inspect_gmail(a.user, a.query, a.limit)
        else:
            inspect_m365(a.user, a.limit)
    except Exception as e:
        print(f"INSPECT ERROR: {type(e).__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
