"""One-shot integration test: sentinel-mail reputation_client → Docker reputation service."""
from __future__ import annotations

import asyncio
import json
import os
import sys


async def main() -> int:
    url = os.getenv("REPUTATION_SERVICE_URL", "")
    if not url:
        print("FAIL: REPUTATION_SERVICE_URL is not set")
        return 1

    from backend.services.reputation_client import analyze_email_reputation

    email_data = {
        "sender": "docker-test@example.com",
        "body": "See https://1evil-domain.example/phish and attachment",
        "attachments": [{"filename": "invoice.xlsm"}],
    }
    auth_results = {
        "spf": "fail",
        "dkim": "none",
        "dmarc": "fail",
        "sender_ip": "203.0.113.5",
    }

    link_result, reputation_result = await analyze_email_reputation(email_data, auth_results)

    print("REPUTATION_SERVICE_URL:", url)
    print("reputation_score:", reputation_result["reputation_score"])
    print("reputation_indicators:", reputation_result["indicators"])
    print("link_score:", link_result["link_score"])
    print("link_indicators:", link_result["indicators"])
    print("suspicious_urls:", link_result["suspicious_urls"])

    ok = True
    if reputation_result["reputation_score"] < 1:
        print("FAIL: expected non-zero reputation_score from auth signals")
        ok = False
    if link_result["link_score"] < 1:
        print("FAIL: expected non-zero link_score from URL heuristic")
        ok = False
    if "spf_fail" not in reputation_result["indicators"]:
        print("FAIL: expected spf_fail in reputation indicators")
        ok = False

    if ok:
        print("PASS: Docker integration test succeeded")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
