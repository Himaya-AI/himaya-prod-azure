"""
GitHub collector — uses a Personal Access Token (or GitHub App installation token)
to enumerate organization-level security posture.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from ..types import ScanContext

logger = logging.getLogger(__name__)

GH_API = "https://api.github.com"


class GitHubCollectorConfig:
    def __init__(
        self,
        token: str,
        org: str,
        max_repos: int = 200,
    ):
        self.token = token
        self.org = org
        self.max_repos = max_repos


async def _gh_paged(token: str, url: str, max_pages: int = 5) -> dict:
    all_items: list = []
    next_url: Optional[str] = url if url.startswith("https://") else f"{GH_API}{url}"
    page = 0
    last_err: Optional[str] = None
    while next_url and page < max_pages:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.get(
                    next_url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                )
                if r.status_code >= 400:
                    last_err = f"HTTP {r.status_code}: {r.text[:200]}"
                    break
                body = r.json()
                if isinstance(body, list):
                    all_items.extend(body)
                else:
                    all_items.append(body)
                next_url = None
                link = r.headers.get("link")
                if link:
                    for part in link.split(","):
                        if 'rel="next"' in part:
                            next_url = part.split(";")[0].strip().strip("<>")
                            break
                page += 1
        except Exception as exc:
            last_err = str(exc)
            break
    return {"err": last_err, "data": all_items}


async def _gh_get(token: str, url: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                url if url.startswith("https://") else f"{GH_API}{url}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if r.status_code >= 400:
                return {"err": f"HTTP {r.status_code}: {r.text[:200]}", "data": None}
            return {"err": None, "data": r.json()}
    except Exception as exc:
        return {"err": str(exc), "data": None}


async def collect_github(ctx: ScanContext, config: Optional[GitHubCollectorConfig] = None) -> None:
    if config is None:
        s = ctx.settings
        config = GitHubCollectorConfig(
            token=s["token"],
            org=s["org"],
            max_repos=int(s.get("max_repos", 200)),
        )

    org = config.org
    token = config.token

    # Org info + security defaults
    org_info = await _gh_get(token, f"/orgs/{org}")
    ctx.add_source(["orgs", "get", org], org_info)

    # Org members + 2FA disabled list
    members_2fa = await _gh_paged(token, f"/orgs/{org}/members?filter=2fa_disabled", max_pages=3)
    ctx.add_source(["orgs", "members2faDisabled", org], members_2fa)

    members = await _gh_paged(token, f"/orgs/{org}/members?per_page=100", max_pages=5)
    ctx.add_source(["orgs", "members", org], members)

    # Outside collaborators
    collabs = await _gh_paged(token, f"/orgs/{org}/outside_collaborators?per_page=100", max_pages=3)
    ctx.add_source(["orgs", "outsideCollaborators", org], collabs)

    # Org webhooks
    hooks = await _gh_paged(token, f"/orgs/{org}/hooks?per_page=100", max_pages=2)
    ctx.add_source(["orgs", "hooks", org], hooks)

    # Org SAML / SSO sessions (best-effort — needs admin:org scope)
    saml = await _gh_get(token, f"/orgs/{org}/credential-authorizations")
    ctx.add_source(["orgs", "credentialAuthorizations", org], saml)

    # Repos
    repos = await _gh_paged(
        token, f"/orgs/{org}/repos?per_page=100&type=all",
        max_pages=max(1, config.max_repos // 100),
    )
    ctx.add_source(["repos", "list", org], repos)

    # Per-repo enrichment (branch protection, secret scanning, code scanning, dependabot)
    repo_items = (repos or {}).get("data") or []
    sem = asyncio.Semaphore(6)

    async def _enrich_repo(repo: dict) -> None:
        full = repo.get("full_name")
        default_branch = repo.get("default_branch") or "main"
        if not full:
            return
        async with sem:
            bp = await _gh_get(token, f"/repos/{full}/branches/{default_branch}/protection")
            ctx.add_source(["repos", "branchProtection", full], bp)

            vuln = await _gh_get(token, f"/repos/{full}/vulnerability-alerts")
            ctx.add_source(["repos", "vulnerabilityAlerts", full], vuln)

            secret = await _gh_get(token, f"/repos/{full}")
            ctx.add_source(["repos", "details", full], secret)

            # Code scanning alerts (best-effort)
            code = await _gh_paged(token, f"/repos/{full}/code-scanning/alerts?per_page=50", max_pages=1)
            ctx.add_source(["repos", "codeScanningAlerts", full], code)

            # Secret scanning alerts (best-effort)
            ss = await _gh_paged(token, f"/repos/{full}/secret-scanning/alerts?per_page=50", max_pages=1)
            ctx.add_source(["repos", "secretScanningAlerts", full], ss)

            # Repo collaborators (for admin count)
            collaborators = await _gh_paged(token, f"/repos/{full}/collaborators?per_page=100", max_pages=1)
            ctx.add_source(["repos", "collaborators", full], collaborators)

    if repo_items:
        # cap enrichment to avoid runaway scans
        await asyncio.gather(
            *[_enrich_repo(r) for r in repo_items[: min(len(repo_items), config.max_repos)]],
            return_exceptions=True,
        )


def make_github_collector(config: GitHubCollectorConfig):
    async def _runner(ctx: ScanContext) -> None:
        await collect_github(ctx, config)
    return _runner
