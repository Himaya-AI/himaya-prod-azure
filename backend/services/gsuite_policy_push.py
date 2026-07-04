"""
Pushes Himaya Helios DLP policies downstream to Google Workspace tenant as
Content Compliance Rules via the Google Admin SDK.

Mirrors the M365 transport rule pattern from m365_policy_push.py.
"""

from typing import Optional
import httpx
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

MOCK_MODE = True  # Set False when real Google Admin SDK credentials available
ADMIN_SDK_BASE = "https://admin.googleapis.com"


class GSuitePolicyPusher:

    def __init__(
        self,
        access_token: Optional[str] = None,
        customer_id: Optional[str] = None,  # e.g. "my_customer" or "C0xxxxxxx"
    ):
        self.access_token = access_token
        self.customer_id = customer_id or "my_customer"
        self.mock_mode = MOCK_MODE or not access_token

    # ── High-level: sync a full DLP policy ────────────────────────────────────

    async def sync_dlp_policy(self, policy: dict, org_id: str) -> dict:
        """
        Top-level sync: create or update GSuite content compliance rule.
        Returns dict with status, gsuite_rule_id, and detail.
        """
        existing_rule_id = policy.get("gsuite_rule_id")

        if existing_rule_id:
            result = await self.update_content_compliance_rule(existing_rule_id, policy, org_id)
        else:
            result = await self.create_content_compliance_rule(policy, org_id)

        return result

    # ── Content Compliance Rule CRUD ──────────────────────────────────────────

    async def create_content_compliance_rule(self, policy: dict, org_id: str) -> dict:
        """Create Google Workspace Content Compliance Rule from Helios DLP policy."""
        rule_config = self._translate_policy_to_compliance_rule(policy)

        if self.mock_mode:
            mock_rule_id = f"himaya-gsuite-{policy.get('id', org_id)[:8]}"
            logger.info(f"[MOCK] Would create GSuite compliance rule: {json.dumps(rule_config, indent=2)}")
            return {
                "status": "mock_success",
                "gsuite_rule_id": mock_rule_id,
                "rule": rule_config,
                "message": "Mock mode — real Google Admin SDK credentials required for live sync.",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                # Google Admin SDK: Gmail Settings API for content compliance
                resp = await client.post(
                    f"{ADMIN_SDK_BASE}/admin/gmail/v1/users/{self.customer_id}/settings/contentCompliance",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                    json=rule_config,
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    rule_id = data.get("id") or data.get("name", "")
                    return {
                        "status": "success",
                        "gsuite_rule_id": rule_id,
                        "rule": data,
                        "message": "Content compliance rule created successfully in Google Workspace.",
                    }
                else:
                    logger.warning(
                        f"gsuite_push: compliance rule API returned {resp.status_code}: {resp.text[:300]}"
                    )
                    return {
                        "status": "api_error",
                        "gsuite_rule_id": None,
                        "error": f"Admin SDK {resp.status_code}: {resp.text[:200]}",
                        "rule_config": rule_config,
                        "message": (
                            "Content compliance rule creation failed. "
                            "Ensure the service account has Gmail Settings API access."
                        ),
                    }
        except Exception as exc:
            logger.error(f"gsuite_push: create_content_compliance_rule exception: {exc}")
            return {"status": "error", "error": str(exc), "gsuite_rule_id": None}

    async def update_content_compliance_rule(
        self, rule_id: str, policy: dict, org_id: str
    ) -> dict:
        """Update an existing Google Workspace content compliance rule."""
        rule_config = self._translate_policy_to_compliance_rule(policy)

        if self.mock_mode:
            logger.info(f"[MOCK] Would update GSuite compliance rule {rule_id}: {json.dumps(rule_config, indent=2)}")
            return {
                "status": "mock_success",
                "gsuite_rule_id": rule_id,
                "rule": rule_config,
                "message": "Mock mode — rule would be updated.",
                "timestamp": datetime.utcnow().isoformat(),
            }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.put(
                    f"{ADMIN_SDK_BASE}/admin/gmail/v1/users/{self.customer_id}/settings/contentCompliance/{rule_id}",
                    headers={
                        "Authorization": f"Bearer {self.access_token}",
                        "Content-Type": "application/json",
                    },
                    json=rule_config,
                )
                if resp.status_code in (200, 204):
                    return {
                        "status": "updated",
                        "gsuite_rule_id": rule_id,
                        "message": "Content compliance rule updated successfully.",
                    }
                else:
                    # Re-create if update fails
                    logger.warning(
                        f"gsuite_push: update returned {resp.status_code} for rule {rule_id}, will recreate"
                    )
                    return await self.create_content_compliance_rule(policy, org_id)
        except Exception as exc:
            logger.error(f"gsuite_push: update_content_compliance_rule exception: {exc}")
            return {"status": "error", "error": str(exc), "gsuite_rule_id": rule_id}

    async def remove_content_compliance_rule(self, rule_id: str) -> dict:
        """Remove content compliance rule when policy is paused or deleted."""
        if self.mock_mode:
            logger.info(f"[MOCK] Would remove GSuite compliance rule {rule_id}")
            return {"status": "mock_success", "removed": rule_id}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.delete(
                    f"{ADMIN_SDK_BASE}/admin/gmail/v1/users/{self.customer_id}/settings/contentCompliance/{rule_id}",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                )
                return {
                    "status": "removed" if resp.status_code in (200, 204, 404) else "error",
                    "rule_id": rule_id,
                    "http_status": resp.status_code,
                }
        except Exception as exc:
            logger.error(f"gsuite_push: remove_content_compliance_rule exception: {exc}")
            return {"status": "error", "error": str(exc), "rule_id": rule_id}

    async def get_content_compliance_rules(self) -> dict:
        """List all Himaya-managed content compliance rules in the tenant."""
        if self.mock_mode:
            return {"status": "mock", "rules": []}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"{ADMIN_SDK_BASE}/admin/gmail/v1/users/{self.customer_id}/settings/contentCompliance",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                )
                if resp.status_code == 200:
                    rules = resp.json().get("contentComplianceSettings", [])
                    # Filter to only Himaya-managed rules
                    himaya_rules = [r for r in rules if "HimayaHelios" in r.get("name", "")]
                    return {"status": "success", "rules": himaya_rules}
                return {"status": "error", "http_status": resp.status_code}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    # ── Google OAuth token acquisition ────────────────────────────────────────

    @staticmethod
    async def get_access_token_from_service_account(
        service_account_key: dict,
        scopes: list[str] | None = None,
    ) -> Optional[str]:
        """
        Obtain a Google access token from a service account JSON key.
        Requires google-auth library: pip install google-auth.
        """
        if scopes is None:
            scopes = [
                "https://www.googleapis.com/auth/admin.gmail.settings.sharing",
                "https://www.googleapis.com/auth/apps.groups.settings",
                "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                "https://www.googleapis.com/auth/admin.directory.user.readonly",
            ]
        try:
            import google.oauth2.service_account as _sa
            import google.auth.transport.requests as _gatr
            creds = _sa.Credentials.from_service_account_info(
                service_account_key, scopes=scopes
            )
            creds.refresh(_gatr.Request())
            return creds.token
        except ImportError:
            logger.warning("gsuite_push: google-auth not installed — cannot mint service account token")
            return None
        except Exception as exc:
            logger.error(f"gsuite_push: service account token failed: {exc}")
            return None

    # ── Policy → Compliance Rule Translation ──────────────────────────────────

    def _translate_policy_to_compliance_rule(self, policy: dict) -> dict:
        """Convert Himaya Helios DLP policy to Google Workspace Content Compliance Rule format."""
        action = policy.get("action", "WARN")
        policy_name = policy.get("name", "Unnamed Policy")
        custom_keywords: list = policy.get("custom_keywords") or []

        # Map Helios action → GSuite compliance rule action
        action_map = {
            "BLOCK": "REJECT",
            "BLOCK_DELETE": "REJECT",
            "HOLD": "QUARANTINE",
            "QUARANTINE": "QUARANTINE",
            "WARN": "WARN_SENDER",
            "ALLOW": "ALLOW",
        }
        rule_action = action_map.get(action, "WARN_SENDER")

        # Build expression list (word match expressions)
        expressions = []
        if policy.get("detect_pii"):
            expressions.extend([
                {"value": "SSN", "matchType": "FULL_WORD"},
                {"value": "social security number", "matchType": "CONTAINS"},
                {"value": "date of birth", "matchType": "CONTAINS"},
                {"value": "passport number", "matchType": "CONTAINS"},
            ])
        if policy.get("detect_financial"):
            expressions.extend([
                {"value": "credit card", "matchType": "CONTAINS"},
                {"value": "bank account", "matchType": "CONTAINS"},
                {"value": "routing number", "matchType": "CONTAINS"},
                {"value": "IBAN", "matchType": "FULL_WORD"},
            ])
        if policy.get("detect_credentials"):
            expressions.extend([
                {"value": "password", "matchType": "FULL_WORD"},
                {"value": "private key", "matchType": "CONTAINS"},
                {"value": "API key", "matchType": "CONTAINS"},
            ])
        if policy.get("detect_itar"):
            expressions.extend([
                {"value": "ITAR", "matchType": "FULL_WORD"},
                {"value": "export control", "matchType": "CONTAINS"},
            ])
        if policy.get("detect_bulk_exfil"):
            expressions.extend([
                {"value": "confidential", "matchType": "FULL_WORD"},
                {"value": "proprietary", "matchType": "FULL_WORD"},
            ])

        # Add custom keywords
        for kw in custom_keywords[:20]:
            expressions.append({"value": kw, "matchType": "CONTAINS"})

        # GSuite content compliance rule format
        rule = {
            "name": f"HimayaHelios-{policy_name[:60]}",
            "expressions": [
                {
                    "allExpressions": {
                        "expressions": [
                            {"headerContains": {"value": kw["value"]}}
                            if kw.get("matchType") == "FULL_WORD"
                            else {"bodyContains": {"value": kw["value"]}}
                        ]
                    }
                }
                for kw in expressions[:50]
            ] if expressions else [],
            "state": "ACTIVE" if policy.get("enabled", True) else "INACTIVE",
        }

        # Add action based on type
        if rule_action == "REJECT":
            rule["action"] = {
                "rejectMessage": (
                    f"[HELIOS DLP] This email was blocked by policy '{policy_name}' "
                    "as it may contain sensitive information."
                )
            }
        elif rule_action == "QUARANTINE":
            rule["action"] = {"quarantineMessage": {"mailRoutingAddress": policy.get("notify_manager_email", "")}}
        elif rule_action == "WARN_SENDER":
            rule["action"] = {
                "modifyMessage": {
                    "addHeaderNames": ["X-Himaya-DLP-Warning"],
                    "addHeaderValues": [f"Policy violation: {policy_name}"],
                }
            }

        return rule
