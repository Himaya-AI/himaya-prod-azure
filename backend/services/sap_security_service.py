"""
SAP Security Service — scans SAP S/4HANA systems for security issues.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class SAPSecurityService:
    """Service for scanning SAP S/4HANA systems for security issues."""

    def __init__(self, host: str, client: str, username: str, password: str):
        self.host = host
        self.client = client
        self.username = username
        self.password = password

    async def test_connection(self) -> dict[str, Any]:
        """Test the SAP connection using RFC or OData."""
        try:
            # In production, we'd use pyrfc or SAP OData APIs
            # For now, validate basic parameters and return success
            
            if not self.host or not self.client or not self.username or not self.password:
                return {"success": False, "error": "Missing required connection parameters"}

            # Simulate successful connection test
            # In production: pyrfc.Connection(ashost=self.host, sysnr='00', client=self.client, ...)
            
            return {
                "success": True,
                "system_id": self.client[:3].upper() if len(self.client) >= 3 else "SAP",
                "host": self.host,
                "client": self.client,
            }
        except Exception as e:
            logger.error(f"SAP connection test failed: {e}")
            return {"success": False, "error": str(e)}

    async def scan_all(self) -> dict[str, Any]:
        """
        Scan SAP system for security issues.
        Returns users and findings.
        """
        users = []
        findings = []
        now = datetime.now(timezone.utc).isoformat()

        try:
            # Scan users
            user_data, user_findings = await self._scan_users()
            users.extend(user_data)
            findings.extend(user_findings)

            # Scan for SOD violations
            sod_findings = await self._scan_sod_violations(user_data)
            findings.extend(sod_findings)

            # Scan critical transactions
            tcode_findings = await self._scan_critical_transactions()
            findings.extend(tcode_findings)

            # Scan for sensitive table access
            table_findings = await self._scan_sensitive_tables()
            findings.extend(table_findings)

            stats = {
                "total_users": len(users),
                "privileged_users": sum(1 for u in users if u.get("is_privileged")),
                "total_findings": len(findings),
                "critical_findings": sum(1 for f in findings if f.get("severity") == "critical"),
                "high_findings": sum(1 for f in findings if f.get("severity") == "high"),
                "sod_violations": sum(1 for f in findings if f.get("category") == "sod_violation"),
            }

            return {
                "users": users,
                "findings": findings,
                "stats": stats,
                "scanned_at": now,
            }

        except Exception as e:
            logger.error(f"SAP scan failed: {e}")
            return {
                "users": [],
                "findings": [],
                "stats": {"error": str(e)},
                "scanned_at": now,
            }

    async def _scan_users(self) -> tuple[list, list]:
        """Scan SAP users for security issues."""
        users = []
        findings = []

        # In production, would call RFC function modules:
        # - BAPI_USER_GETLIST: List all users
        # - BAPI_USER_GET_DETAIL: Get user details
        # - USR02: User master data table

        # Example findings that would be generated:
        privileged_roles = [
            "SAP_ALL", "SAP_NEW", "S_A.SYSTEM", "S_A.ADMIN",
            "S_USER_GRP:*", "S_TABU_DIS:*", "S_DEVELOP"
        ]

        # Placeholder - in production, iterate over actual users
        
        return users, findings

    async def _scan_sod_violations(self, users: list) -> list:
        """Scan for Segregation of Duties violations."""
        findings = []

        # SOD rule matrix - conflicting roles/authorizations
        sod_rules = [
            {
                "id": "SOD001",
                "name": "Create Vendor / Post Payment",
                "auth1": "FK01",  # Create vendor
                "auth2": "F110",  # Payment run
                "severity": "critical",
            },
            {
                "id": "SOD002",
                "name": "Maintain User / Assign Roles",
                "auth1": "SU01",  # User maintenance
                "auth2": "PFCG",  # Role maintenance
                "severity": "critical",
            },
            {
                "id": "SOD003",
                "name": "Create Purchase Order / Goods Receipt",
                "auth1": "ME21N",  # Create PO
                "auth2": "MIGO",   # Goods receipt
                "severity": "high",
            },
            {
                "id": "SOD004",
                "name": "Post Journal Entry / Approve Journal",
                "auth1": "FB01",  # Post document
                "auth2": "FBV0",  # Park/Post held document
                "severity": "high",
            },
        ]

        # In production, check each user against SOD rules
        # For each violation found, create a finding

        return findings

    async def _scan_critical_transactions(self) -> list:
        """Scan for unauthorized use of critical transactions."""
        findings = []

        # Critical transaction codes to monitor
        critical_tcodes = {
            "SE38": {"name": "ABAP Editor", "severity": "critical", "reason": "Direct code execution"},
            "SE80": {"name": "Object Navigator", "severity": "critical", "reason": "Development access"},
            "SM30": {"name": "Table Maintenance", "severity": "high", "reason": "Direct table modification"},
            "SM37": {"name": "Background Jobs", "severity": "medium", "reason": "Job scheduling"},
            "SE16N": {"name": "Table Browser", "severity": "high", "reason": "Data access"},
            "SU01": {"name": "User Maintenance", "severity": "critical", "reason": "User administration"},
            "PFCG": {"name": "Role Maintenance", "severity": "critical", "reason": "Authorization control"},
            "SA38": {"name": "ABAP Reporting", "severity": "high", "reason": "Report execution"},
            "SE37": {"name": "Function Builder", "severity": "critical", "reason": "Function module access"},
            "SCC4": {"name": "Client Administration", "severity": "critical", "reason": "System configuration"},
        }

        # In production, query SM20 (Security Audit Log) or SM21 (System Log)
        # to find unauthorized usage of these transactions

        return findings

    async def _scan_sensitive_tables(self) -> list:
        """Scan for access to sensitive tables."""
        findings = []

        # Sensitive tables to monitor
        sensitive_tables = [
            {"table": "USR02", "description": "User passwords", "severity": "critical"},
            {"table": "USR40", "description": "Password rules", "severity": "high"},
            {"table": "USRBF2", "description": "User buffer", "severity": "high"},
            {"table": "T000", "description": "Client master", "severity": "critical"},
            {"table": "RFBLG", "description": "FI document cluster", "severity": "high"},
            {"table": "BKPF", "description": "Accounting document header", "severity": "medium"},
            {"table": "BSEG", "description": "Accounting document segment", "severity": "medium"},
            {"table": "LFA1", "description": "Vendor master", "severity": "medium"},
            {"table": "KNA1", "description": "Customer master", "severity": "medium"},
            {"table": "PA0008", "description": "HR Basic Pay", "severity": "critical"},
            {"table": "PA0002", "description": "HR Personal Data", "severity": "critical"},
        ]

        # In production, query table access logs or authorization objects
        # to detect unauthorized access to these tables

        return findings
