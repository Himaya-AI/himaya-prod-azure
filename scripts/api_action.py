"""
Call a Himaya prod API endpoint as an authenticated user by minting a short-lived
HS256 JWT (same scheme as backend.routers.auth.create_access_token). No external
JWT lib needed. Used to exercise the manual quarantine / mark-as-spam / release
UI actions exactly as the frontend does.

Usage:
  python3 scripts/api_action.py --user-id <uuid> --path /api/quarantine/<tid>/quarantine
  python3 scripts/api_action.py --user-id <uuid> --path /api/quarantine/<tid>/mark-as-spam
  python3 scripts/api_action.py --user-id <uuid> --path /api/quarantine/<tid>/release
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import time

import httpx

BASE = os.getenv("HIMAYA_API_BASE", "https://app.himaya.ai")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-in-prod")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def mint(user_id: str, org_id: str = "", role: str = "admin", ttl: int = 600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": user_id, "exp": int(time.time()) + ttl}
    if org_id:
        payload["org_id"] = org_id
    payload["role"] = role
    seg = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    sig = hmac.new(JWT_SECRET.encode(), seg.encode(), hashlib.sha256).digest()
    return f"{seg}.{_b64(sig)}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--user-id", required=True)
    ap.add_argument("--org-id", default="")
    ap.add_argument("--path", required=True)
    ap.add_argument("--method", default="POST")
    ap.add_argument("--json-body", default="", help="JSON string request body")
    a = ap.parse_args()
    tok = mint(a.user_id, a.org_id)
    kwargs = {"headers": {"Authorization": f"Bearer {tok}"}, "timeout": 60}
    if a.json_body:
        kwargs["json"] = json.loads(a.json_body)
        kwargs["headers"]["Content-Type"] = "application/json"
    r = httpx.request(a.method, f"{BASE}{a.path}", **kwargs)
    print(f"{a.method} {a.path} -> HTTP {r.status_code}")
    try:
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print(r.text[:500])


if __name__ == "__main__":
    main()
