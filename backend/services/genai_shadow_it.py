"""
GenAI shadow-IT discovery.

Added 2026-06-23 (Adnan turn 2). The conversation around DSPM has
shifted hard toward "who is sending our data to ChatGPT / Gemini /
Copilot / Claude / Perplexity / Mistral / etc". This module surfaces
that across every signal we already collect:

  1. M365 Teams + OAuth grants  : appNames / displayNames matching
                                  a curated AI vendor list.
  2. GitHub installations       : known AI GitHub apps installed on
                                  org repos (Copilot, Cody, Codeium,
                                  Tabnine, JetBrains AI, etc.).
  3. SaaS data items            : any item_url whose host matches a
                                  known AI vendor.
  4. Audit log domain hits      : any DLP egress alert against an AI
                                  vendor host counts as evidence.

This is a *passive* discovery — no provider writes. We just join what
we already store and label rows with a `vendor` and `category`.

Public API:
  - discover(db, org_id) -> list[dict]
  - vendor_for_host(host) -> dict | None
  - KNOWN_VENDORS -> list of vendor dicts (for the UI)
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


# Each vendor entry:
#   id           - stable slug used in alerts and UI
#   name         - vendor display name
#   category     - 'chat' | 'coding' | 'image' | 'voice' | 'agent' | 'analytics'
#   hosts        - list of hostname substrings (lowercased)
#   app_keywords - list of app-name keywords for OAuth / Teams app matching
#   risk         - 'low' | 'medium' | 'high'  (default usage risk; enterprise
#                  flavours may be lower-risk but we flag them anyway)
KNOWN_VENDORS: list[dict[str, Any]] = [
    {"id": "openai-chatgpt", "name": "OpenAI ChatGPT", "category": "chat",
     "hosts": ["chat.openai.com", "chatgpt.com", "openai.com"],
     "app_keywords": ["chatgpt", "openai", "gpt-4", "gpt-5"],
     "risk": "high"},
    {"id": "anthropic-claude", "name": "Anthropic Claude", "category": "chat",
     "hosts": ["claude.ai", "anthropic.com"],
     "app_keywords": ["claude", "anthropic"],
     "risk": "medium"},
    {"id": "google-gemini", "name": "Google Gemini / Bard", "category": "chat",
     "hosts": ["gemini.google.com", "bard.google.com", "aistudio.google.com"],
     "app_keywords": ["gemini", "bard", "google ai", "duet ai"],
     "risk": "medium"},
    {"id": "microsoft-copilot", "name": "Microsoft Copilot", "category": "chat",
     "hosts": ["copilot.microsoft.com", "copilot.cloud.microsoft", "m365copilot.com"],
     "app_keywords": ["copilot", "microsoft copilot", "bing chat"],
     "risk": "medium"},
    {"id": "perplexity", "name": "Perplexity", "category": "chat",
     "hosts": ["perplexity.ai"],
     "app_keywords": ["perplexity"],
     "risk": "high"},
    {"id": "mistral", "name": "Mistral", "category": "chat",
     "hosts": ["chat.mistral.ai", "mistral.ai"],
     "app_keywords": ["mistral", "le chat"],
     "risk": "medium"},
    {"id": "deepseek", "name": "DeepSeek", "category": "chat",
     "hosts": ["chat.deepseek.com", "deepseek.com"],
     "app_keywords": ["deepseek"],
     "risk": "high"},
    {"id": "qwen", "name": "Qwen / Tongyi", "category": "chat",
     "hosts": ["chat.qwen.ai", "tongyi.aliyun.com"],
     "app_keywords": ["qwen", "tongyi"],
     "risk": "high"},
    {"id": "you", "name": "You.com", "category": "chat",
     "hosts": ["you.com"],
     "app_keywords": ["you.com", "youchat"],
     "risk": "medium"},
    {"id": "poe", "name": "Poe (Quora)", "category": "chat",
     "hosts": ["poe.com"],
     "app_keywords": ["poe"],
     "risk": "high"},
    # Coding assistants
    {"id": "github-copilot", "name": "GitHub Copilot", "category": "coding",
     "hosts": ["github.com/copilot"],
     "app_keywords": ["github copilot", "copilot for"],
     "risk": "medium"},
    {"id": "cursor", "name": "Cursor", "category": "coding",
     "hosts": ["cursor.com", "cursor.so"],
     "app_keywords": ["cursor"],
     "risk": "medium"},
    {"id": "codeium", "name": "Codeium / Windsurf", "category": "coding",
     "hosts": ["codeium.com", "windsurf.ai", "windsurf.com"],
     "app_keywords": ["codeium", "windsurf"],
     "risk": "medium"},
    {"id": "tabnine", "name": "Tabnine", "category": "coding",
     "hosts": ["tabnine.com"],
     "app_keywords": ["tabnine"],
     "risk": "medium"},
    {"id": "sourcegraph-cody", "name": "Sourcegraph Cody", "category": "coding",
     "hosts": ["sourcegraph.com"],
     "app_keywords": ["cody", "sourcegraph"],
     "risk": "medium"},
    {"id": "jetbrains-ai", "name": "JetBrains AI", "category": "coding",
     "hosts": ["jetbrains.ai"],
     "app_keywords": ["jetbrains ai"],
     "risk": "low"},
    {"id": "replit-ghostwriter", "name": "Replit Agent / Ghostwriter", "category": "coding",
     "hosts": ["replit.com"],
     "app_keywords": ["replit", "ghostwriter"],
     "risk": "medium"},
    # Productivity / agent
    {"id": "notion-ai", "name": "Notion AI", "category": "productivity",
     "hosts": ["notion.so", "notion.ai"],
     "app_keywords": ["notion ai"],
     "risk": "low"},
    {"id": "grammarly", "name": "Grammarly AI", "category": "productivity",
     "hosts": ["grammarly.com"],
     "app_keywords": ["grammarly"],
     "risk": "low"},
    {"id": "otter-ai", "name": "Otter.ai", "category": "voice",
     "hosts": ["otter.ai"],
     "app_keywords": ["otter"],
     "risk": "medium"},
    {"id": "fireflies", "name": "Fireflies.ai", "category": "voice",
     "hosts": ["fireflies.ai"],
     "app_keywords": ["fireflies"],
     "risk": "medium"},
    {"id": "rewind-ai", "name": "Rewind AI", "category": "agent",
     "hosts": ["rewind.ai"],
     "app_keywords": ["rewind"],
     "risk": "high"},
    {"id": "krisp-ai", "name": "Krisp AI", "category": "voice",
     "hosts": ["krisp.ai"],
     "app_keywords": ["krisp"],
     "risk": "low"},
    # Image / generative
    {"id": "midjourney", "name": "Midjourney", "category": "image",
     "hosts": ["midjourney.com"],
     "app_keywords": ["midjourney"],
     "risk": "medium"},
    {"id": "stability-ai", "name": "Stability AI", "category": "image",
     "hosts": ["stability.ai"],
     "app_keywords": ["stability ai", "stable diffusion"],
     "risk": "medium"},
    # Aggregators
    {"id": "huggingface", "name": "Hugging Face", "category": "agent",
     "hosts": ["huggingface.co"],
     "app_keywords": ["hugging face", "huggingface"],
     "risk": "medium"},
]


def _hostname(url: str) -> str | None:
    try:
        host = urlparse(url).hostname
        return host.lower() if host else None
    except Exception:
        return None


def vendor_for_host(host: str | None) -> dict[str, Any] | None:
    if not host:
        return None
    h = host.lower()
    for v in KNOWN_VENDORS:
        for sub in v["hosts"]:
            if sub in h:
                return v
    return None


def vendor_for_app_name(name: str | None) -> dict[str, Any] | None:
    if not name:
        return None
    n = name.lower()
    for v in KNOWN_VENDORS:
        for kw in v["app_keywords"]:
            # word-boundary match: avoid 'gptzero' matching 'gpt'
            if re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])", n):
                return v
    return None


async def discover(db: AsyncSession, org_id: str) -> list[dict[str, Any]]:
    """Return a list of GenAI usage findings across every connector."""
    findings: dict[str, dict[str, Any]] = {}

    def _bump(vendor: dict, source: str, evidence: dict):
        key = vendor["id"]
        cur = findings.get(key)
        if cur is None:
            cur = {
                "vendor_id": vendor["id"],
                "vendor": vendor["name"],
                "category": vendor["category"],
                "risk": vendor["risk"],
                "sources": [],
                "evidence_count": 0,
                "users": set(),
            }
            findings[key] = cur
        cur["evidence_count"] += 1
        if source not in cur["sources"]:
            cur["sources"].append(source)
        u = evidence.get("user")
        if u:
            cur["users"].add(u)

    # 1. saas_data_items URLs that point at a known vendor host.
    try:
        rows = (await db.execute(text(
            "SELECT item_url, owner_email, provider FROM saas_data_items "
            "WHERE org_id = CAST(:oid AS UUID) AND item_url IS NOT NULL "
            "  AND item_url <> '' LIMIT 5000"
        ), {"oid": org_id})).mappings().all()
        for r in rows:
            v = vendor_for_host(_hostname(r["item_url"]))
            if v:
                _bump(v, "saas_data_items", {
                    "user": r.get("owner_email"),
                    "provider": r.get("provider"),
                })
    except Exception as exc:
        logger.debug(f"genai_discover: saas_data_items failed: {exc}")

    # 2. teamsApps inventory (if present).
    try:
        rows = (await db.execute(text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'teams_apps' LIMIT 1"
        ))).first()
        if rows:
            apps = (await db.execute(text(
                "SELECT app_name, publisher FROM teams_apps "
                "WHERE org_id = CAST(:oid AS UUID) LIMIT 2000"
            ), {"oid": org_id})).mappings().all()
            for a in apps:
                v = vendor_for_app_name(a.get("app_name"))
                if v:
                    _bump(v, "teams_apps", {"user": a.get("publisher")})
    except Exception as exc:
        logger.debug(f"genai_discover: teams_apps failed: {exc}")

    # 3. OAuth grants table — name-based.
    try:
        oauth_rows = (await db.execute(text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'saas_oauth_apps' LIMIT 1"
        ))).first()
        if oauth_rows:
            grants = (await db.execute(text(
                "SELECT app_name, publisher, user_email FROM saas_oauth_apps "
                "WHERE org_id = CAST(:oid AS UUID) LIMIT 2000"
            ), {"oid": org_id})).mappings().all()
            for g in grants:
                v = vendor_for_app_name(g.get("app_name")) or vendor_for_app_name(g.get("publisher"))
                if v:
                    _bump(v, "oauth_grants", {"user": g.get("user_email")})
    except Exception as exc:
        logger.debug(f"genai_discover: oauth grants failed: {exc}")

    # 4. github_findings repository name hints (e.g. .cursor / .copilot
    #    files indicate a coding assistant in use).
    try:
        gh_rows = (await db.execute(text(
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_name = 'github_findings' LIMIT 1"
        ))).first()
        if gh_rows:
            gh = (await db.execute(text(
                "SELECT repository, title FROM github_findings "
                "WHERE org_id = CAST(:oid AS UUID) LIMIT 2000"
            ), {"oid": org_id})).mappings().all()
            for f in gh:
                hay = f"{(f.get('repository') or '')} {(f.get('title') or '')}"
                v = vendor_for_app_name(hay)
                if v:
                    _bump(v, "github_findings", {"user": f.get("repository")})
    except Exception as exc:
        logger.debug(f"genai_discover: github_findings failed: {exc}")

    # 5. audit_logs: any action containing the vendor host in new_value.
    try:
        audits = (await db.execute(text(
            "SELECT new_value, ip_address FROM audit_logs "
            "WHERE org_id = CAST(:oid AS UUID) "
            "  AND created_at >= NOW() - INTERVAL '30 days' "
            "LIMIT 5000"
        ), {"oid": org_id})).mappings().all()
        for a in audits:
            nv = a.get("new_value") or {}
            if isinstance(nv, str):
                try: nv = json.loads(nv)
                except Exception: nv = {}
            if not isinstance(nv, dict):
                continue
            host_candidates = [
                nv.get("host"), nv.get("destination_host"),
                _hostname(nv.get("url") or ""),
                _hostname(nv.get("resource_url") or ""),
            ]
            for h in host_candidates:
                v = vendor_for_host(h)
                if v:
                    _bump(v, "audit_logs", {"user": nv.get("user_email")})
                    break
    except Exception as exc:
        logger.debug(f"genai_discover: audit_logs failed: {exc}")

    out: list[dict[str, Any]] = []
    for f in findings.values():
        f["unique_users"] = len(f.pop("users"))
        out.append(f)
    # Sort: high risk first, then by evidence count
    risk_order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda x: (risk_order.get(x["risk"], 9), -x["evidence_count"]))
    return out
