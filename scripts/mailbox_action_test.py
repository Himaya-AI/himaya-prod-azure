"""
Mailbox ACTION tester — verifies Himaya's provider-side actions actually work,
decoupled from AI scoring and (flaky) inbound spam delivery.

For Gmail it exercises the *exact* Gmail API operations the backend uses in
`backend/services/quarantine_service.py` and `mailbox_capture_service.py`:

  quarantine  : get/create hidden 'Himaya-Quarantine' label, add it + remove INBOX
  suspicious  : get/create 'Himaya-Suspicious' label, add it (email stays in INBOX)
  spam        : add SPAM label, remove INBOX
  hardcapture : fetch raw MIME (format=raw), DELETE the message permanently,
                then re-insert it (reinject) to prove the full round-trip works

Every action is run against ONE target message (matched by --query) and then
RESTORED, so the mailbox is left as it was found. hardcapture proves the
mail.google.com scope grants permanent-delete + insert.

Auth (same creds as prod, via env):
  GOOGLE_SERVICE_ACCOUNT_B64   base64 of the service-account JSON (Gmail DWD)

Usage:
  python scripts/mailbox_action_test.py --user adnan@himaya.ai --query "ACTION-TEST" \
      --actions quarantine,suspicious,spam,hardcapture
"""
import argparse
import base64
import os
import sys
import time

import httpx

# Reuse auth + backoff helpers from the inspector.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mailbox_inspect import GMAIL, GRAPH, _get, _m365_token, _sa_headers  # noqa: E402

QUAR_LABEL = "Himaya-Quarantine"
SUSP_LABEL = "Himaya-Suspicious"


def _post(client: httpx.Client, url: str, **kw):
    for attempt in range(1, 7):
        r = client.post(url, **kw)
        if r.status_code != 429:
            return r
        time.sleep(2 * attempt)
    return r


def _get_or_create_label(c, user, headers, name, hidden):
    lbl = _get(c, f"{GMAIL}/users/{user}/labels", headers=headers)
    lbl.raise_for_status()
    for l in lbl.json().get("labels", []):
        if l["name"] == name:
            return l["id"]
    body = {
        "name": name,
        "labelListVisibility": "labelHide" if hidden else "labelShow",
        "messageListVisibility": "hide" if hidden else "show",
    }
    r = _post(c, f"{GMAIL}/users/{user}/labels", headers=headers, json=body)
    r.raise_for_status()
    return r.json()["id"]


def _labels_of(c, user, headers, msg_id):
    r = _get(c, f"{GMAIL}/users/{user}/messages/{msg_id}",
             headers=headers, params={"format": "minimal"})
    r.raise_for_status()
    return set(r.json().get("labelIds", []))


def _modify(c, user, headers, msg_id, add=None, remove=None):
    body = {"addLabelIds": add or [], "removeLabelIds": remove or []}
    r = _post(c, f"{GMAIL}/users/{user}/messages/{msg_id}/modify",
              headers=headers, json=body)
    r.raise_for_status()
    return r.json()


def find_target(c, user, headers, query):
    r = _get(c, f"{GMAIL}/users/{user}/messages", headers=headers,
             params={"q": query, "maxResults": 1, "includeSpamTrash": "true"})
    r.raise_for_status()
    msgs = r.json().get("messages", []) or []
    if not msgs:
        return None
    return msgs[0]["id"]


def act_quarantine(c, user, headers, msg_id):
    print("  [quarantine] applying hidden label + removing INBOX ...")
    lid = _get_or_create_label(c, user, headers, QUAR_LABEL, hidden=True)
    _modify(c, user, headers, msg_id, add=[lid], remove=["INBOX"])
    labels = _labels_of(c, user, headers, msg_id)
    ok = lid in labels and "INBOX" not in labels
    print(f"    -> labels now: {sorted(labels)}  PASS={ok}")
    # restore
    _modify(c, user, headers, msg_id, add=["INBOX"], remove=[lid])
    print("    restored to INBOX")
    return ok


def act_suspicious(c, user, headers, msg_id):
    print("  [suspicious] applying Himaya-Suspicious label (stays in INBOX) ...")
    lid = _get_or_create_label(c, user, headers, SUSP_LABEL, hidden=False)
    _modify(c, user, headers, msg_id, add=[lid])
    labels = _labels_of(c, user, headers, msg_id)
    ok = lid in labels and "INBOX" in labels
    print(f"    -> labels now: {sorted(labels)}  PASS={ok}")
    _modify(c, user, headers, msg_id, remove=[lid])
    print("    removed suspicious label")
    return ok


def act_spam(c, user, headers, msg_id):
    print("  [spam] adding SPAM + removing INBOX ...")
    _modify(c, user, headers, msg_id, add=["SPAM"], remove=["INBOX"])
    labels = _labels_of(c, user, headers, msg_id)
    ok = "SPAM" in labels and "INBOX" not in labels
    print(f"    -> labels now: {sorted(labels)}  PASS={ok}")
    _modify(c, user, headers, msg_id, add=["INBOX"], remove=["SPAM"])
    print("    restored to INBOX")
    return ok


def act_hardcapture(c, user, headers, msg_id):
    print("  [hardcapture] fetch raw MIME -> permanent DELETE -> reinject ...")
    raw = _get(c, f"{GMAIL}/users/{user}/messages/{msg_id}",
               headers=headers, params={"format": "raw"})
    raw.raise_for_status()
    raw_b64 = raw.json()["raw"]
    size = len(base64.urlsafe_b64decode(raw_b64 + "=" * (-len(raw_b64) % 4)))
    print(f"    fetched raw MIME ({size} bytes)")

    d = c.delete(f"{GMAIL}/users/{user}/messages/{msg_id}", headers=headers)
    gone = d.status_code in (204, 200)
    verify = _get(c, f"{GMAIL}/users/{user}/messages/{msg_id}",
                  headers=headers, params={"format": "minimal"})
    gone = gone and verify.status_code == 404
    print(f"    deleted (status={d.status_code}); re-GET status={verify.status_code}  DELETED={gone}")

    ins = _post(c, f"{GMAIL}/users/{user}/messages",
                headers=headers,
                params={"internalDateSource": "dateHeader"},
                json={"raw": raw_b64, "labelIds": ["INBOX", "UNREAD"]})
    reinjected = ins.status_code == 200
    new_id = ins.json().get("id") if reinjected else None
    print(f"    reinject status={ins.status_code}  new_id={new_id}  REINJECTED={reinjected}")
    return gone and reinjected


GMAIL_ACTIONS = {
    "quarantine": act_quarantine,
    "suspicious": act_suspicious,
    "spam": act_spam,
    "hardcapture": act_hardcapture,
}


# ── M365 (Graph) actions ──────────────────────────────────────────────────────
def _m365_folder_id(c, user, headers, name, hidden):
    r = c.get(f"{GRAPH}/users/{user}/mailFolders",
              headers=headers, params={"$top": 100, "includeHiddenFolders": "true"})
    r.raise_for_status()
    for f in r.json().get("value", []):
        if f.get("displayName") == name:
            return f["id"]
    cr = _post(c, f"{GRAPH}/users/{user}/mailFolders",
               headers=headers, json={"displayName": name})
    cr.raise_for_status()
    fid = cr.json()["id"]
    if hidden:
        c.patch(f"{GRAPH}/users/{user}/mailFolders/{fid}",
                headers=headers, json={"isHidden": True})
    return fid


def _m365_parent(c, user, headers, msg_id):
    r = c.get(f"{GRAPH}/users/{user}/messages/{msg_id}",
              headers=headers, params={"$select": "parentFolderId,categories"})
    r.raise_for_status()
    j = r.json()
    return j.get("parentFolderId"), (j.get("categories") or [])


def _m365_move(c, user, headers, msg_id, dest):
    r = _post(c, f"{GRAPH}/users/{user}/messages/{msg_id}/move",
              headers=headers, json={"destinationId": dest})
    r.raise_for_status()
    return r.json().get("id", msg_id)


def m365_quarantine(c, user, headers, msg_id):
    print("  [quarantine] create/find hidden Himaya-Quarantine folder + move ...")
    fid = _m365_folder_id(c, user, headers, QUAR_LABEL, hidden=True)
    new_id = _m365_move(c, user, headers, msg_id, fid)
    parent, _ = _m365_parent(c, user, headers, new_id)
    ok = parent == fid
    print(f"    -> parentFolderId matches quarantine folder  PASS={ok}")
    restored = _m365_move(c, user, headers, new_id, "inbox")
    print("    restored to Inbox")
    return ok, restored


def m365_suspicious(c, user, headers, msg_id):
    print("  [suspicious] apply Himaya-Suspicious category (stays in Inbox) ...")
    r = c.patch(f"{GRAPH}/users/{user}/messages/{msg_id}",
                headers=headers, json={"categories": ["Himaya-Suspicious"]})
    r.raise_for_status()
    parent, cats = _m365_parent(c, user, headers, msg_id)
    ok = "Himaya-Suspicious" in cats
    print(f"    -> categories now: {cats}  PASS={ok}")
    c.patch(f"{GRAPH}/users/{user}/messages/{msg_id}", headers=headers, json={"categories": []})
    print("    cleared category")
    return ok, msg_id


def m365_junk(c, user, headers, msg_id):
    print("  [junk] move to Junk Email folder ...")
    new_id = _m365_move(c, user, headers, msg_id, "junkemail")
    parent, _ = _m365_parent(c, user, headers, new_id)
    jr = c.get(f"{GRAPH}/users/{user}/mailFolders/junkemail", headers=headers)
    junk_id = jr.json().get("id") if jr.status_code == 200 else None
    ok = parent == junk_id
    print(f"    -> in Junk Email  PASS={ok}")
    restored = _m365_move(c, user, headers, new_id, "inbox")
    print("    restored to Inbox")
    return ok, restored


def m365_hardcapture(c, user, headers, msg_id):
    print("  [hardcapture] fetch MIME -> move to Deleted + purge -> reinject ...")
    raw = c.get(f"{GRAPH}/users/{user}/messages/{msg_id}/$value", headers=headers)
    raw.raise_for_status()
    mime = raw.content
    print(f"    fetched MIME ({len(mime)} bytes)")
    del_id = _m365_move(c, user, headers, msg_id, "deleteditems")
    c.delete(f"{GRAPH}/users/{user}/messages/{del_id}", headers=headers)
    verify = c.get(f"{GRAPH}/users/{user}/messages/{del_id}", headers=headers)
    gone = verify.status_code == 404
    print(f"    purged; re-GET status={verify.status_code}  DELETED={gone}")
    cr = _post(c, f"{GRAPH}/users/{user}/messages",
               headers={**headers, "Content-Type": "text/plain"},
               content=base64.b64encode(mime))
    reinjected = cr.status_code in (200, 201)
    new_id = cr.json().get("id") if reinjected else None
    if reinjected:
        new_id = _m365_move(c, user, headers, new_id, "inbox")
    print(f"    reinject status={cr.status_code}  REINJECTED={reinjected}")
    return gone and reinjected, new_id


M365_ACTIONS = {
    "quarantine": m365_quarantine,
    "suspicious": m365_suspicious,
    "junk": m365_junk,
    "hardcapture": m365_hardcapture,
}


def find_target_m365(c, user, headers, query):
    r = c.get(f"{GRAPH}/users/{user}/messages", headers=headers,
              params={"$search": f'"{query}"', "$top": 1, "$select": "id,subject"})
    if r.status_code != 200:
        return None
    v = r.json().get("value", [])
    return v[0]["id"] if v else None


def run_gmail(args):
    headers = _sa_headers(args.user)
    results = {}
    with httpx.Client(timeout=40) as c:
        msg_id = find_target(c, args.user, headers, args.query)
        if not msg_id:
            print(f"No Gmail message for query {args.query!r} in {args.user}.")
            sys.exit(2)
        print(f"Target Gmail message id={msg_id} in {args.user}\n")
        for name in [a.strip() for a in args.actions.split(",") if a.strip()]:
            fn = GMAIL_ACTIONS.get(name)
            if not fn:
                print(f"  unknown gmail action {name!r}, skipping")
                continue
            try:
                results[name] = fn(c, args.user, headers, msg_id)
            except httpx.HTTPStatusError as e:
                print(f"    ERROR {name}: {e.response.status_code} {e.response.text[:200]}")
                results[name] = False
            print()
    return results


def run_m365(args):
    token = _m365_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    results = {}
    with httpx.Client(timeout=40) as c:
        msg_id = find_target_m365(c, args.user, headers, args.query)
        if not msg_id:
            print(f"No M365 message for query {args.query!r} in {args.user}.")
            sys.exit(2)
        print(f"Target M365 message id={msg_id} in {args.user}\n")
        for name in [a.strip() for a in args.actions.split(",") if a.strip()]:
            fn = M365_ACTIONS.get(name)
            if not fn:
                print(f"  unknown m365 action {name!r}, skipping")
                continue
            try:
                ok, msg_id = fn(c, args.user, headers, msg_id)
                results[name] = ok
            except httpx.HTTPStatusError as e:
                print(f"    ERROR {name}: {e.response.status_code} {e.response.text[:200]}")
                results[name] = False
            print()
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="gmail", choices=["gmail", "m365"])
    ap.add_argument("--user", required=True)
    ap.add_argument("--query", required=True, help="subject/body query to locate the ONE test message")
    ap.add_argument("--actions", default="quarantine,suspicious,spam,hardcapture")
    args = ap.parse_args()

    results = run_gmail(args) if args.provider == "gmail" else run_m365(args)

    print("=== ACTION TEST RESULTS ===")
    for k, v in results.items():
        print(f"  {k:12s} {'PASS' if v else 'FAIL'}")
    sys.exit(0 if results and all(results.values()) else 1)


if __name__ == "__main__":
    main()
