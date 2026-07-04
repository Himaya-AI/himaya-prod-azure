"""
Pushes Himaya Helios DLP policies downstream to Microsoft 365 tenant as
Exchange Online transport rules via the Microsoft Graph API.

In production: calls Graph API / Exchange Online PowerShell REST.
In dev/mock mode: simulates the push and logs what would happen.
"""

from typing import Optional
import httpx
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

MOCK_MODE = True  # Set False when real M365 token available
GRAPH = "https://graph.microsoft.com/v1.0"

# Exchange Online management endpoint (separate from Graph API)
EXO_ENDPOINT = "https://outlook.office365.com/adminapi/beta/{tenant_id}/TransportConfiguration"


class M365PolicyPusher:

    def __init__(self, access_token: Optional[str] = None, tenant_id: Optional[str] = None):
        self.access_token = access_token
        self.tenant_id = tenant_id
        self.mock_mode = MOCK_MODE or not access_token

    # ── High-level: sync a full DLP policy ────────────────────────────────────

    async def sync_dlp_policy(self, policy: dict, org_id: str) -> dict:
        """
        Top-level sync: create or update M365 transport rule for this policy.
        Returns dict with status, m365_rule_id, and detail.
        """
        existing_rule_id = policy.get("m365_rule_id")

        if existing_rule_id:
            # Update existing rule
            result = await self.update_transport_rule(existing_rule_id, policy, org_id)
        else:
            # Create new rule
            result = await self.create_transport_rule(policy, org_id)

        return result

    # ── Transport Rule CRUD ────────────────────────────────────────────────────

    async def create_transport_rule(self, policy: dict, org_id: str) -> dict:
        """Create Exchange Online transport rule from Helios DLP policy."""
        rule_config = self._translate_policy_to_transport_rule(policy)

        if self.mock_mode:
            mock_rule_id = f"himaya-rule-{policy.get('id', org_id)[:8]}"
            logger.info(f"[MOCK] Would create transport rule: {json.dumps(rule_config, indent=2)}")
            return {
                "status": "mock_success",
                "m365_rule_id": mock_rule_id,
                "rule": rule_config,
                "message": "Mock mode — real M365 credentials required for live sync.",
                "timestamp": datetime.utcnow().isoformat(),
            }

        # Real Graph API — Exchange transport rules via admin endpoint
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Try Graph API beta endpoint for transport rules
                resp = await client.post(
                    f"{GRAPH}/admin/exchange/transportRules",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                    json=rule_config,
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    return {
                        "status": "success",
                        "m365_rule_id": data.get("id") or data.get("identity", ""),
                        "rule": data,
                        "message": "Transport rule created successfully in Exchange Online.",
                    }
                else:
                    # Fallback: log the error and return mock success for now
                    logger.warning(f"m365_push: transport rule API returned {resp.status_code}: {resp.text[:300]}")
                    return {
                        "status": "api_error",
                        "m365_rule_id": None,
                        "error": f"Graph API {resp.status_code}: {resp.text[:200]}",
                        "rule_config": rule_config,
                        "message": "Transport rule creation failed. Exchange Online admin API may require EXO PowerShell.",
                    }
        except Exception as exc:
            logger.error(f"m365_push: create_transport_rule exception: {exc}")
            return {"status": "error", "error": str(exc), "m365_rule_id": None}

    async def update_transport_rule(self, rule_id: str, policy: dict, org_id: str) -> dict:
        """Update an existing Exchange Online transport rule."""
        rule_config = self._translate_policy_to_transport_rule(policy)

        if self.mock_mode:
            logger.info(f"[MOCK] Would update transport rule {rule_id}: {json.dumps(rule_config, indent=2)}")
            return {
                "status": "mock_success",
                "m365_rule_id": rule_id,
                "rule": rule_config,
                "message": "Mock mode — rule would be updated.",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.patch(
                    f"{GRAPH}/admin/exchange/transportRules/{rule_id}",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                    json=rule_config,
                )
                if resp.status_code in (200, 204):
                    return {
                        "status": "updated",
                        "m365_rule_id": rule_id,
                        "message": "Transport rule updated successfully.",
                    }
                else:
                    # Try re-creating if update fails (rule may have been deleted externally)
                    logger.warning(f"m365_push: update returned {resp.status_code} for rule {rule_id}, will recreate")
                    return await self.create_transport_rule(policy, org_id)
        except Exception as exc:
            logger.error(f"m365_push: update_transport_rule exception: {exc}")
            return {"status": "error", "error": str(exc), "m365_rule_id": rule_id}

    async def remove_transport_rule(self, rule_id: str) -> dict:
        """Remove transport rule when policy is paused or deleted."""
        if self.mock_mode:
            logger.info(f"[MOCK] Would remove transport rule {rule_id}")
            return {"status": "mock_success", "removed": rule_id}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.delete(
                    f"{GRAPH}/admin/exchange/transportRules/{rule_id}",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                )
                return {
                    "status": "removed" if resp.status_code in (200, 204, 404) else "error",
                    "rule_id": rule_id,
                    "http_status": resp.status_code,
                }
        except Exception as exc:
            logger.error(f"m365_push: remove_transport_rule exception: {exc}")
            return {"status": "error", "error": str(exc), "rule_id": rule_id}

    async def get_transport_rules(self) -> dict:
        """List all Himaya-managed transport rules in the tenant."""
        if self.mock_mode:
            return {"status": "mock", "rules": []}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{GRAPH}/admin/exchange/transportRules?$filter=startsWith(name,'HimayaHelios-')",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                )
                if resp.status_code == 200:
                    return {"status": "success", "rules": resp.json().get("value", [])}
                return {"status": "error", "http_status": resp.status_code}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    async def push_block_list_entry(self, domain: str, org_id: str) -> dict:
        """Add domain to M365 tenant block list."""
        if self.mock_mode:
            logger.info(f"[MOCK] Would block domain {domain} in M365 for org {org_id}")
            return {
                "status": "mock_success",
                "domain": domain,
                "action": "blocked",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{GRAPH}/admin/exchange/blockedSenderDomains",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    json={"domain": domain},
                )
                return resp.json() if resp.status_code < 400 else {"status": "error", "code": resp.status_code}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    async def reconcile(self, active_policies: list, org_id: str) -> dict:
        """Periodic job: verify M365 state matches expected state."""
        results = []
        for policy in active_policies:
            if not policy.get("m365_rule_id"):
                result = await self.create_transport_rule(policy, org_id)
                results.append({"policy_id": policy["id"], "action": "re_pushed", "result": result})
            else:
                results.append({"policy_id": policy["id"], "action": "ok"})
        return {"reconciled": len(results), "results": results}

    # ── Policy → Transport Rule Translation ────────────────────────────────────

    def _translate_policy_to_transport_rule(self, policy: dict) -> dict:
        """Convert Himaya Helios DLP policy to M365 Exchange transport rule format."""
        action = policy.get("action", "WARN")
        policy_name = policy.get("name", "Unnamed Policy")
        custom_keywords: list = policy.get("custom_keywords") or []
        custom_regex: list = policy.get("custom_regex") or []

        # Map Helios action → Exchange transport rule action
        action_map = {
            "BLOCK": "delete",
            "BLOCK_DELETE": "delete",
            "HOLD": "quarantine",
            "QUARANTINE": "quarantine",
            "WARN": "prepend_disclaimer",
            "ALLOW": None,
        }
        rule_action = action_map.get(action, "prepend_disclaimer")

        # Build keyword/pattern lists
        sensitive_keywords: list[str] = []
        if policy.get("detect_pii"):
            sensitive_keywords += ["SSN", "social security", "date of birth", "passport"]
        if policy.get("detect_financial"):
            sensitive_keywords += ["credit card", "bank account", "routing number", "IBAN"]
        if policy.get("detect_credentials"):
            sensitive_keywords += ["password", "secret", "private key", "API key"]
        if policy.get("detect_itar"):
            sensitive_keywords += ["ITAR", "EAR", "export control", "military"]
        if policy.get("detect_bulk_exfil"):
            sensitive_keywords += ["confidential", "proprietary", "trade secret"]
        sensitive_keywords += custom_keywords

        # Build conditions
        conditions = {}
        if sensitive_keywords:
            conditions["subjectOrBodyMatchesPatterns"] = sensitive_keywords[:50]  # Exchange limit
        if custom_regex:
            conditions["subjectOrBodyMatchesRegex"] = custom_regex[:10]
        if policy.get("external_only", False):
            conditions["senderDomainIs"] = ["internal"]  # negate externally

        # Build actions
        rule_actions: list[dict] = []
        if rule_action == "delete":
            rule_actions.append({"type": "delete"})
        elif rule_action == "quarantine":
            rule_actions.append({"type": "quarantine"})
            rule_actions.append({"type": "notifyRecipient", "message": "Your email has been held for DLP review by Himaya Helios."})
        elif rule_action == "prepend_disclaimer":
            rule_actions.append({
                "type": "prependDisclaimer",
                "text": f"[HELIOS DLP WARNING] This email may contain sensitive content as defined by policy '{policy_name}'. Please review before sending.",
                "fallbackAction": "wrap",
            })
        elif rule_action is None:
            rule_actions.append({"type": "allow"})

        # Notify manager/admin
        if policy.get("notify_manager_email"):
            rule_actions.append({
                "type": "redirect",
                "emailAddress": {"address": policy["notify_manager_email"]},
            })

        return {
            "name": f"HimayaHelios-{policy_name[:60]}",
            "priority": 50,  # Medium priority, below critical security rules
            "enabled": policy.get("enabled", True),
            "conditions": conditions,
            "actions": rule_actions,
            "state": "enabled" if policy.get("enabled", True) else "disabled",
            "mode": "enforce",
            "comments": f"Managed by Himaya Helios DLP · Policy ID: {policy.get('id', 'unknown')}",
        }
