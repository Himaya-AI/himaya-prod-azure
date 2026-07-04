#!/usr/bin/env python3
# Vendored from: https://github.com/Krishcalin/SSPM-Snowflake-Data-Platform
# Original license: MIT, Copyright (c) 2026 KRISH
# Integrated into Himaya as a library (CLI/report functions still present
# but unused; connector router calls SnowflakeScanner.run_all + Finding directly).
"""
Snowflake Data Platform SSPM Scanner v1.0.0
SaaS Security Posture Management scanner for Snowflake accounts.

Performs live SQL-based checks aligned with:
  CIS Snowflake Foundations Benchmark v1.0.0 (10-27-2023)

Check domains:
  - Identity and Access Management (17 checks: 1.1 - 1.17)
  - Monitoring and Alerting (9 checks: 2.1 - 2.9)
  - Networking (2 checks: 3.1 - 3.2)
  - Data Protection (11 checks: 4.1 - 4.11)

Compliance Framework Mapping (per finding):
  CIS Snowflake Foundations Benchmark v1.0.0
  NIST SP 800-53 Rev 5
  ISO/IEC 27001:2022
  SOC 2 Type II Trust Services Criteria

Authentication:
  Option 1 — Username / Password:
    --account, --user, --password
  Option 2 — Key Pair:
    --account, --user, --private-key-path [--private-key-passphrase]
  Option 3 — Externalbrowser (SSO):
    --account, --user, --authenticator externalbrowser

Required Snowflake Roles:
  ACCOUNTADMIN or a custom role with:
    - SECURITY_VIEWER on SNOWFLAKE database
    - GOVERNANCE_VIEWER on SNOWFLAKE database
    - USAGE on security integrations
    - OWNERSHIP on network policies

Usage:
  python snowflake_scanner.py \\
      --account <account_identifier> \\
      --user <username> \\
      --password <password> \\
      --role ACCOUNTADMIN

  python snowflake_scanner.py \\
      --account <account_identifier> \\
      --user <username> \\
      --private-key-path /path/to/rsa_key.p8

Env var fallback:
  SNOWFLAKE_ACCOUNT  SNOWFLAKE_USER  SNOWFLAKE_PASSWORD
  SNOWFLAKE_ROLE  SNOWFLAKE_WAREHOUSE  SNOWFLAKE_PRIVATE_KEY_PATH
  SNOWFLAKE_PRIVATE_KEY_PASSPHRASE  SNOWFLAKE_AUTHENTICATOR
"""

import os
import re
import sys
import json
import html as html_mod
import argparse
import traceback
from datetime import datetime, timezone, timedelta

try:
    import snowflake.connector
    HAS_SNOWFLAKE = True
except ImportError:
    HAS_SNOWFLAKE = False

VERSION = "1.0.0"

# ============================================================
# Severity levels & scoring weights
# ============================================================
SEVERITY_WEIGHT = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
    "INFO": 0,
}

# ============================================================
# Compliance Framework Mapping
# CIS Snowflake v1.0.0, NIST 800-53 Rev5, ISO 27001:2022, SOC 2
# ============================================================
COMPLIANCE_MAP: dict = {
    # ── Section 1: Identity and Access Management ──
    "SF-IAM-001": {"cis_snowflake": "1.1",  "nist_800_53": "IA-2, IA-8",       "iso_27001": "A.8.5",  "soc2": "CC6.1, CC6.2"},
    "SF-IAM-002": {"cis_snowflake": "1.2",  "nist_800_53": "AC-2, IA-4",       "iso_27001": "A.5.16", "soc2": "CC6.1, CC6.2"},
    "SF-IAM-003": {"cis_snowflake": "1.3",  "nist_800_53": "IA-5",             "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "SF-IAM-004": {"cis_snowflake": "1.4",  "nist_800_53": "IA-2(1), IA-2(2)", "iso_27001": "A.8.5",  "soc2": "CC6.1, CC6.2"},
    "SF-IAM-005": {"cis_snowflake": "1.5",  "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "SF-IAM-006": {"cis_snowflake": "1.6",  "nist_800_53": "IA-5(2)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "SF-IAM-007": {"cis_snowflake": "1.7",  "nist_800_53": "IA-5(1)",          "iso_27001": "A.8.5",  "soc2": "CC6.1"},
    "SF-IAM-008": {"cis_snowflake": "1.8",  "nist_800_53": "AC-2(3)",          "iso_27001": "A.5.18", "soc2": "CC6.1, CC6.2"},
    "SF-IAM-009": {"cis_snowflake": "1.9",  "nist_800_53": "AC-11, AC-12",     "iso_27001": "A.8.1",  "soc2": "CC6.1"},
    "SF-IAM-010": {"cis_snowflake": "1.10", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "SF-IAM-011": {"cis_snowflake": "1.11", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1"},
    "SF-IAM-012": {"cis_snowflake": "1.12", "nist_800_53": "AC-6",             "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "SF-IAM-013": {"cis_snowflake": "1.13", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "SF-IAM-014": {"cis_snowflake": "1.14", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "SF-IAM-015": {"cis_snowflake": "1.15", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "SF-IAM-016": {"cis_snowflake": "1.16", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    "SF-IAM-017": {"cis_snowflake": "1.17", "nist_800_53": "AC-6(5)",          "iso_27001": "A.8.2",  "soc2": "CC6.1, CC6.3"},
    # ── Section 2: Monitoring and Alerting ──
    "SF-MON-001": {"cis_snowflake": "2.1",  "nist_800_53": "AU-6, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.2, CC7.3"},
    "SF-MON-002": {"cis_snowflake": "2.2",  "nist_800_53": "AU-6, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.2, CC7.3"},
    "SF-MON-003": {"cis_snowflake": "2.3",  "nist_800_53": "AU-6, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.2, CC7.3"},
    "SF-MON-004": {"cis_snowflake": "2.4",  "nist_800_53": "AU-6, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.2, CC7.3"},
    "SF-MON-005": {"cis_snowflake": "2.5",  "nist_800_53": "AU-6, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.2, CC7.3"},
    "SF-MON-006": {"cis_snowflake": "2.6",  "nist_800_53": "AU-6, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.2, CC7.3"},
    "SF-MON-007": {"cis_snowflake": "2.7",  "nist_800_53": "AU-6, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.2, CC7.3"},
    "SF-MON-008": {"cis_snowflake": "2.8",  "nist_800_53": "AU-6, AU-12",      "iso_27001": "A.8.15", "soc2": "CC7.2, CC7.3"},
    "SF-MON-009": {"cis_snowflake": "2.9",  "nist_800_53": "SI-2, SI-5",       "iso_27001": "A.8.8",  "soc2": "CC7.1"},
    # ── Section 3: Networking ──
    "SF-NET-001": {"cis_snowflake": "3.1",  "nist_800_53": "SC-7, AC-4",       "iso_27001": "A.8.20", "soc2": "CC6.1, CC6.6"},
    "SF-NET-002": {"cis_snowflake": "3.2",  "nist_800_53": "SC-7, AC-4",       "iso_27001": "A.8.20", "soc2": "CC6.1, CC6.6"},
    # ── Section 4: Data Protection ──
    "SF-DP-001":  {"cis_snowflake": "4.1",  "nist_800_53": "SC-12, SC-28",     "iso_27001": "A.8.24", "soc2": "CC6.1, CC6.7"},
    "SF-DP-002":  {"cis_snowflake": "4.2",  "nist_800_53": "SC-12, SC-28",     "iso_27001": "A.8.24", "soc2": "CC6.1, CC6.7"},
    "SF-DP-003":  {"cis_snowflake": "4.3",  "nist_800_53": "CP-9, CP-10",      "iso_27001": "A.8.13", "soc2": "CC6.1, A1.2"},
    "SF-DP-004":  {"cis_snowflake": "4.4",  "nist_800_53": "CP-9, CP-10",      "iso_27001": "A.8.13", "soc2": "CC6.1, A1.2"},
    "SF-DP-005":  {"cis_snowflake": "4.5",  "nist_800_53": "CM-6, SC-28",      "iso_27001": "A.8.9",  "soc2": "CC6.1"},
    "SF-DP-006":  {"cis_snowflake": "4.6",  "nist_800_53": "CM-6, SC-28",      "iso_27001": "A.8.9",  "soc2": "CC6.1"},
    "SF-DP-007":  {"cis_snowflake": "4.7",  "nist_800_53": "CM-6, SC-28",      "iso_27001": "A.8.9",  "soc2": "CC6.1"},
    "SF-DP-008":  {"cis_snowflake": "4.8",  "nist_800_53": "AC-4, SC-7",       "iso_27001": "A.8.12", "soc2": "CC6.1, CC6.6"},
    "SF-DP-009":  {"cis_snowflake": "4.9",  "nist_800_53": "SC-12, SC-28",     "iso_27001": "A.8.24", "soc2": "CC6.1, CC6.7"},
    "SF-DP-010":  {"cis_snowflake": "4.10", "nist_800_53": "AC-3, AC-16",      "iso_27001": "A.8.11", "soc2": "CC6.1, CC6.4"},
    "SF-DP-011":  {"cis_snowflake": "4.11", "nist_800_53": "AC-3, AC-16",      "iso_27001": "A.8.3",  "soc2": "CC6.1, CC6.4"},
}

# ============================================================
# Colour helpers for console output
# ============================================================
_ANSI = {
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "DIM": "\033[2m",
}

def _c(text: str, *styles: str) -> str:
    """Apply ANSI styles."""
    prefix = "".join(_ANSI.get(s, "") for s in styles)
    return f"{prefix}{text}{_ANSI['RESET']}" if prefix else text

def _severity_colour(sev: str) -> str:
    return {"CRITICAL": "RED", "HIGH": "RED", "MEDIUM": "YELLOW", "LOW": "CYAN", "INFO": "BLUE"}.get(sev, "")

def _status_colour(status: str) -> str:
    return {"PASS": "GREEN", "FAIL": "RED", "WARN": "YELLOW", "SKIP": "DIM", "ERROR": "MAGENTA"}.get(status, "")


# ============================================================
# Data model
# ============================================================
class Finding:
    __slots__ = (
        "rule_id", "title", "status", "severity", "description",
        "remediation", "evidence", "cis_ref", "profile_level",
    )

    def __init__(self, rule_id: str, title: str, status: str, severity: str,
                 description: str = "", remediation: str = "", evidence: str = "",
                 cis_ref: str = "", profile_level: int = 1):
        self.rule_id = rule_id
        self.title = title
        self.status = status
        self.severity = severity
        self.description = description
        self.remediation = remediation
        self.evidence = evidence
        self.cis_ref = cis_ref
        self.profile_level = profile_level

    def to_dict(self) -> dict:
        d = {s: getattr(self, s) for s in self.__slots__}
        d["compliance"] = COMPLIANCE_MAP.get(self.rule_id, {})
        return d


# ============================================================
# Snowflake connector wrapper
# ============================================================
class SnowflakeClient:
    """Wraps snowflake-connector-python for read-only audit queries."""

    def __init__(self, account: str, user: str, password: str | None = None,
                 role: str = "ACCOUNTADMIN", warehouse: str | None = None,
                 private_key_path: str | None = None,
                 private_key_pem: str | None = None,
                 private_key_passphrase: str | None = None,
                 authenticator: str | None = None):
        self.account = account
        self.user = user
        self.password = password
        self.role = role
        self.warehouse = warehouse
        self.private_key_path = private_key_path
        # Himaya extension: accept PEM contents directly (not just a path).
        self.private_key_pem = private_key_pem
        self.private_key_passphrase = private_key_passphrase
        self.authenticator = authenticator
        self._conn = None

    def connect(self):
        params: dict = {
            "account": self.account,
            "user": self.user,
            "role": self.role,
        }
        if self.warehouse:
            params["warehouse"] = self.warehouse
        if self.authenticator:
            params["authenticator"] = self.authenticator
        if self.private_key_path or self.private_key_pem:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives import serialization
            if self.private_key_pem:
                key_bytes = self.private_key_pem.encode()
            else:
                with open(self.private_key_path, "rb") as key_file:
                    key_bytes = key_file.read()
            p_key = serialization.load_pem_private_key(
                key_bytes,
                password=self.private_key_passphrase.encode() if self.private_key_passphrase else None,
                backend=default_backend(),
            )
            pkb = p_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            params["private_key"] = pkb
        elif self.password:
            params["password"] = self.password

        self._conn = snowflake.connector.connect(**params)

    def query(self, sql: str) -> list[dict]:
        """Execute SQL and return list of dicts."""
        if not self._conn:
            raise RuntimeError("Not connected. Call connect() first.")
        cur = self._conn.cursor(snowflake.connector.DictCursor)
        try:
            cur.execute(sql)
            rows = cur.fetchall()
            # Normalize column names to uppercase
            return [{k.upper(): v for k, v in row.items()} for row in rows]
        finally:
            cur.close()

    def query_scalar(self, sql: str):
        """Execute SQL and return first column of first row, or None."""
        rows = self.query(sql)
        if rows:
            first_key = next(iter(rows[0]))
            return rows[0][first_key]
        return None

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None


# ============================================================
# Scanner engine
# ============================================================
class SnowflakeScanner:
    """CIS Snowflake Foundations Benchmark v1.0.0 scanner."""

    def __init__(self, client: SnowflakeClient, verbose: bool = False):
        self.client = client
        self.verbose = verbose
        self.findings: list[Finding] = []

    def _log(self, msg: str):
        if self.verbose:
            print(f"  {_c('[*]', 'DIM')} {msg}", file=sys.stderr)

    def _add(self, finding: Finding):
        self.findings.append(finding)

    # ----------------------------------------------------------
    # Section 1: Identity and Access Management
    # ----------------------------------------------------------

    def check_1_1_sso_configured(self):
        """1.1 Ensure single sign-on (SSO) is configured (Automated)"""
        rid, title = "SF-IAM-001", "SSO is configured for your account"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW SECURITY INTEGRATIONS;")
            rows = self.client.query(
                "SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) "
                "WHERE (\"type\" LIKE 'EXTERNAL_OAUTH%' OR \"type\" LIKE 'SAML2') "
                "AND \"enabled\" = 'true';"
            )
            if rows:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="SSO security integrations (SAML2/EXTERNAL_OAUTH) found and enabled.",
                    evidence=f"{len(rows)} SSO integration(s) found.",
                    cis_ref="1.1", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description="No enabled SSO (SAML2 or EXTERNAL_OAUTH) integrations found.",
                    remediation="Configure SSO via SAML2 or External OAuth security integration.",
                    cis_ref="1.1", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="1.1"))

    def check_1_2_scim_configured(self):
        """1.2 Ensure SCIM integration is configured (Automated)"""
        rid, title = "SF-IAM-002", "SCIM integration is configured for user provisioning"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW SECURITY INTEGRATIONS;")
            rows = self.client.query(
                "SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) "
                "WHERE (\"type\" LIKE 'SCIM%') AND \"enabled\" = 'true';"
            )
            if rows:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="SCIM integration found and enabled.",
                    evidence=f"{len(rows)} SCIM integration(s) active.",
                    cis_ref="1.2", profile_level=2))
            else:
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description="No enabled SCIM integration found for automated user provisioning.",
                    remediation="Configure SCIM integration with Okta, Azure AD, or custom IdP.",
                    cis_ref="1.2", profile_level=2))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.2"))

    def check_1_3_sso_users_no_password(self):
        """1.3 Ensure Snowflake password is unset for SSO users (Manual)"""
        rid, title = "SF-IAM-003", "Snowflake password is unset for SSO users"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT NAME, HAS_PASSWORD "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.USERS "
                "WHERE HAS_PASSWORD = TRUE "
                "AND DELETED_ON IS NULL "
                "AND DISABLED = 'false';"
            )
            if rows:
                names = [r["NAME"] for r in rows[:10]]
                self._add(Finding(rid, title, "WARN", "MEDIUM",
                    description=f"{len(rows)} active user(s) have passwords set. "
                                "Verify these are not SSO users (manual check required).",
                    evidence=f"Users with passwords: {', '.join(names)}" + (" ..." if len(rows) > 10 else ""),
                    remediation="For SSO users: ALTER USER <username> SET PASSWORD = NULL;",
                    cis_ref="1.3", profile_level=1))
            else:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="No active users have passwords set.",
                    cis_ref="1.3", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.3"))

    def check_1_4_mfa_enabled(self):
        """1.4 Ensure MFA is on for all human users with passwords (Automated)"""
        rid, title = "SF-IAM-004", "MFA is enabled for all password-authenticated users"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT NAME, EXT_AUTHN_DUO AS MFA_ENABLED "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.USERS "
                "WHERE DELETED_ON IS NULL "
                "AND DISABLED = 'false' "
                "AND HAS_PASSWORD = TRUE "
                "AND (EXT_AUTHN_DUO = FALSE OR EXT_AUTHN_DUO IS NULL);"
            )
            if rows:
                names = [r["NAME"] for r in rows[:10]]
                self._add(Finding(rid, title, "FAIL", "CRITICAL",
                    description=f"{len(rows)} user(s) with passwords lack MFA enrollment.",
                    evidence=f"Users without MFA: {', '.join(names)}" + (" ..." if len(rows) > 10 else ""),
                    remediation="Each user must enroll in MFA via Snowsight Profile settings.",
                    cis_ref="1.4", profile_level=1))
            else:
                self._add(Finding(rid, title, "PASS", "CRITICAL",
                    description="All password-authenticated users have MFA enabled.",
                    cis_ref="1.4", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "CRITICAL", evidence=str(e), cis_ref="1.4"))

    def check_1_5_password_policy(self):
        """1.5 Ensure minimum password length is >= 14 (Automated)"""
        rid, title = "SF-IAM-005", "Minimum password length is set to 14+ characters"
        self._log(f"Checking {rid}: {title}")
        try:
            # Check account-level password policy
            acct_rows = self.client.query(
                "WITH PWDS_WITH_MIN_LEN AS ( "
                "  SELECT ID FROM SNOWFLAKE.ACCOUNT_USAGE.PASSWORD_POLICIES "
                "  WHERE PASSWORD_MIN_LENGTH >= 14 AND DELETED IS NULL "
                ") "
                "SELECT A.* FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A "
                "LEFT JOIN PWDS_WITH_MIN_LEN AS B ON A.POLICY_ID = B.ID "
                "WHERE A.REF_ENTITY_DOMAIN = 'ACCOUNT' "
                "AND A.POLICY_KIND = 'PASSWORD_POLICY' "
                "AND A.POLICY_STATUS = 'ACTIVE' "
                "AND B.ID IS NOT NULL;"
            )
            # Check user-level overrides with weaker policies
            user_overrides = self.client.query(
                "WITH PWDS_WITH_MIN_LEN AS ( "
                "  SELECT ID FROM SNOWFLAKE.ACCOUNT_USAGE.PASSWORD_POLICIES "
                "  WHERE PASSWORD_MIN_LENGTH >= 14 AND DELETED IS NULL "
                ") "
                "SELECT A.* FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A "
                "LEFT JOIN PWDS_WITH_MIN_LEN AS B ON A.POLICY_ID = B.ID "
                "WHERE A.REF_ENTITY_DOMAIN = 'USER' "
                "AND A.POLICY_STATUS = 'ACTIVE' "
                "AND B.ID IS NULL;"
            )
            if acct_rows and not user_overrides:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="Account-level password policy enforces >= 14 character minimum.",
                    cis_ref="1.5", profile_level=1))
            elif not acct_rows:
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description="No account-level password policy enforcing 14+ character minimum found.",
                    remediation="CREATE PASSWORD POLICY my_policy PASSWORD_MIN_LENGTH=14; "
                                "ALTER ACCOUNT SET PASSWORD POLICY my_policy;",
                    cis_ref="1.5", profile_level=1))
            else:
                names = [r.get("REF_ENTITY_NAME", "unknown") for r in user_overrides[:5]]
                self._add(Finding(rid, title, "WARN", "HIGH",
                    description=f"{len(user_overrides)} user-level password policy override(s) "
                                "with weaker settings found.",
                    evidence=f"Users with weaker policies: {', '.join(names)}",
                    cis_ref="1.5", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="1.5"))

    def check_1_6_service_accounts_keypair(self):
        """1.6 Ensure service accounts use key pair authentication (Automated)"""
        rid, title = "SF-IAM-006", "Service accounts use key pair authentication"
        self._log(f"Checking {rid}: {title}")
        try:
            # Check for users tagged as service accounts without key pair auth
            rows = self.client.query(
                "SELECT TR.OBJECT_NAME "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES TR "
                "LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS U ON TR.OBJECT_NAME = U.NAME "
                "WHERE TR.TAG_NAME = 'ACCOUNT_TYPE' "
                "AND TR.TAG_VALUE = 'service' "
                "AND TR.DOMAIN = 'USER' "
                "AND U.DELETED_ON IS NULL "
                "AND (U.HAS_PASSWORD = TRUE OR U.HAS_RSA_PUBLIC_KEY = FALSE);"
            )
            if not rows:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="All tagged service accounts use key pair auth without passwords.",
                    cis_ref="1.6", profile_level=1))
            else:
                names = [r["OBJECT_NAME"] for r in rows[:10]]
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description=f"{len(rows)} service account(s) lack key pair auth or have passwords.",
                    evidence=f"Non-compliant service accounts: {', '.join(names)}",
                    remediation="ALTER USER <svc> SET RSA_PUBLIC_KEY='...'; "
                                "ALTER USER <svc> SET PASSWORD = NULL;",
                    cis_ref="1.6", profile_level=1))
        except Exception as e:
            # Tag may not exist — degrade gracefully
            if "does not exist" in str(e).lower() or "Object does not exist" in str(e):
                self._add(Finding(rid, title, "SKIP", "HIGH",
                    description="ACCOUNT_TYPE tag not found. Service accounts are not tagged. "
                                "Cannot distinguish service accounts from human users.",
                    remediation="Tag service accounts: ALTER USER <svc> SET TAG ACCOUNT_TYPE='service';",
                    cis_ref="1.6", profile_level=1))
            else:
                self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="1.6"))

    def check_1_7_keypair_rotation(self):
        """1.7 Ensure authentication key pairs rotated every 180 days (Automated)"""
        rid, title = "SF-IAM-007", "Authentication key pairs are rotated every 180 days"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "WITH FILTERED_QUERY_HISTORY AS ( "
                "  SELECT END_TIME AS SET_TIME, "
                "    UPPER(REGEXP_SUBSTR(QUERY_TEXT, 'USER\\\\s+\"?([\\\\w]+)\"?', 1, 1, 'i', 1)) AS PROCESSED_USERNAME, "
                "    QUERY_TEXT "
                "  FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
                "  WHERE EXECUTION_STATUS = 'SUCCESS' "
                "    AND QUERY_TYPE IN ('ALTER_USER', 'CREATE_USER') "
                "    AND TO_DATE(END_TIME) < DATEADD(day, -180, CURRENT_DATE()) "
                "    AND (QUERY_TEXT ILIKE '%rsa_public_key%' OR QUERY_TEXT ILIKE '%rsa_public_key_2%') "
                "), "
                "EXTRACTED_KEYS AS ( "
                "  SELECT SET_TIME, PROCESSED_USERNAME, "
                "    CASE "
                "      WHEN POSITION('rsa_public_key' IN LOWER(QUERY_TEXT)) > 0 THEN 'rsa_public_key' "
                "      WHEN POSITION('rsa_public_key_2' IN LOWER(QUERY_TEXT)) > 0 THEN 'rsa_public_key_2' "
                "      ELSE NULL END AS RSA_KEY_NAME "
                "  FROM FILTERED_QUERY_HISTORY "
                "  WHERE POSITION('rsa_public_key' IN LOWER(QUERY_TEXT)) > 0 "
                "    OR POSITION('rsa_public_key_2' IN LOWER(QUERY_TEXT)) > 0 "
                "), "
                "RECENT_KEYS AS ( "
                "  SELECT EK.SET_TIME, EK.PROCESSED_USERNAME AS USERNAME, "
                "    EK.RSA_KEY_NAME AS RSA_PUBLIC_KEY, "
                "    ROW_NUMBER() OVER (PARTITION BY EK.PROCESSED_USERNAME, EK.RSA_KEY_NAME "
                "                       ORDER BY EK.SET_TIME DESC) AS RNUM "
                "  FROM EXTRACTED_KEYS EK "
                "  INNER JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AU ON EK.PROCESSED_USERNAME = AU.NAME "
                "  WHERE AU.DELETED_ON IS NULL AND AU.DISABLED = FALSE "
                "    AND EK.RSA_KEY_NAME IS NOT NULL "
                ") "
                "SELECT SET_TIME, USERNAME, RSA_PUBLIC_KEY FROM RECENT_KEYS WHERE RNUM = 1;"
            )
            if rows:
                names = [r["USERNAME"] for r in rows[:10]]
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"{len(rows)} user(s) have key pairs older than 180 days.",
                    evidence=f"Stale key users: {', '.join(names)}",
                    remediation="Rotate RSA key pairs. See Snowflake key pair rotation docs.",
                    cis_ref="1.7", profile_level=1))
            else:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="No key pairs older than 180 days detected (within 360-day query history).",
                    cis_ref="1.7", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.7"))

    def check_1_8_inactive_users(self):
        """1.8 Ensure users inactive 90+ days are disabled (Automated)"""
        rid, title = "SF-IAM-008", "Users inactive for 90+ days are disabled"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW USERS;")
            rows = self.client.query(
                "SELECT \"name\", \"disabled\", \"last_success_login\" "
                "FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) "
                "WHERE \"disabled\" = 'false' "
                "AND (\"last_success_login\" < DATEADD(day, -90, CURRENT_TIMESTAMP()) "
                "     OR \"last_success_login\" IS NULL);"
            )
            if rows:
                names = [r.get("name", r.get("NAME", "?")) for r in rows[:10]]
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"{len(rows)} active user(s) have not logged in for 90+ days.",
                    evidence=f"Inactive users: {', '.join(names)}" + (" ..." if len(rows) > 10 else ""),
                    remediation="ALTER USER <user_name> SET DISABLED = true;",
                    cis_ref="1.8", profile_level=1))
            else:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="All active users have logged in within the last 90 days.",
                    cis_ref="1.8", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.8"))

    def check_1_9_session_timeout(self):
        """1.9 Ensure idle session timeout <= 15 min for ACCOUNTADMIN/SECURITYADMIN (Automated)"""
        rid, title = "SF-IAM-009", "Idle session timeout <= 15 min for privileged roles"
        self._log(f"Checking {rid}: {title}")
        try:
            # Check user-level session policies for privileged users
            rows = self.client.query(
                "WITH PRIV_USERS AS ( "
                "  SELECT DISTINCT GRANTEE_NAME "
                "  FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS "
                "  WHERE DELETED_ON IS NULL "
                "    AND ROLE IN ('ACCOUNTADMIN','SECURITYADMIN') "
                "), "
                "POLICY_REFS AS ( "
                "  SELECT * "
                "  FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A "
                "  LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSION_POLICIES AS B "
                "    ON A.POLICY_ID = B.ID "
                "  WHERE A.POLICY_KIND = 'SESSION_POLICY' "
                "    AND A.POLICY_STATUS = 'ACTIVE' "
                "    AND A.REF_ENTITY_DOMAIN = 'USER' "
                "    AND B.DELETED IS NULL "
                "    AND B.SESSION_IDLE_TIMEOUT_MINS <= 15 "
                ") "
                "SELECT A.* FROM PRIV_USERS AS A "
                "LEFT JOIN POLICY_REFS AS B ON A.GRANTEE_NAME = B.REF_ENTITY_NAME "
                "WHERE B.POLICY_ID IS NULL;"
            )
            # Also check account-level session policy
            acct_policy = self.client.query(
                "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES AS A "
                "LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSION_POLICIES AS B "
                "  ON A.POLICY_ID = B.ID "
                "WHERE A.POLICY_KIND = 'SESSION_POLICY' "
                "  AND A.POLICY_STATUS = 'ACTIVE' "
                "  AND A.REF_ENTITY_DOMAIN = 'ACCOUNT' "
                "  AND B.DELETED IS NULL "
                "  AND B.SESSION_IDLE_TIMEOUT_MINS <= 15;"
            )
            if not rows or acct_policy:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="Privileged users have idle session timeout <= 15 minutes.",
                    cis_ref="1.9", profile_level=1))
            else:
                names = [r.get("GRANTEE_NAME", "?") for r in rows[:10]]
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description=f"{len(rows)} privileged user(s) lack a session policy with <= 15 min timeout.",
                    evidence=f"Users without policy: {', '.join(names)}",
                    remediation="CREATE SESSION POLICY sp_priv SESSION_IDLE_TIMEOUT_MINS=15, "
                                "SESSION_UI_IDLE_TIMEOUT_MINS=15; "
                                "ALTER USER <user> SET SESSION POLICY sp_priv;",
                    cis_ref="1.9", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="1.9"))

    def check_1_10_limit_admin_users(self):
        """1.10 Limit ACCOUNTADMIN and SECURITYADMIN users (Automated)"""
        rid, title = "SF-IAM-010", "ACCOUNTADMIN and SECURITYADMIN users are limited"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT DISTINCT A.GRANTEE_NAME AS NAME, A.ROLE "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS AS A "
                "LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AS B "
                "  ON A.GRANTEE_NAME = B.NAME "
                "WHERE A.ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN') "
                "  AND A.DELETED_ON IS NULL "
                "  AND B.DELETED_ON IS NULL "
                "  AND B.DISABLED = 'false' "
                "ORDER BY A.ROLE;"
            )
            count = len(rows)
            if 2 <= count <= 10:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description=f"{count} users have ACCOUNTADMIN/SECURITYADMIN (within 2-10 range).",
                    evidence=f"Admin users: {', '.join(r['NAME'] for r in rows)}",
                    cis_ref="1.10", profile_level=1))
            elif count < 2:
                self._add(Finding(rid, title, "WARN", "HIGH",
                    description=f"Only {count} admin user(s). Risk of losing account access.",
                    remediation="Ensure at least 2 users have ACCOUNTADMIN for redundancy.",
                    cis_ref="1.10", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description=f"{count} users have ACCOUNTADMIN/SECURITYADMIN (exceeds recommended 10).",
                    evidence=f"Admin users: {', '.join(r['NAME'] for r in rows[:15])}",
                    remediation="REVOKE ROLE ACCOUNTADMIN FROM USER <username>;",
                    cis_ref="1.10", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="1.10"))

    def check_1_11_accountadmin_email(self):
        """1.11 Ensure ACCOUNTADMIN users have email addresses (Automated)"""
        rid, title = "SF-IAM-011", "All ACCOUNTADMIN users have email addresses assigned"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT DISTINCT A.GRANTEE_NAME AS NAME, B.EMAIL "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS AS A "
                "LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS AS B "
                "  ON A.GRANTEE_NAME = B.NAME "
                "WHERE A.ROLE = 'ACCOUNTADMIN' "
                "  AND A.DELETED_ON IS NULL "
                "  AND B.EMAIL IS NULL "
                "  AND B.DELETED_ON IS NULL "
                "  AND B.DISABLED = 'false';"
            )
            if not rows:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="All ACCOUNTADMIN users have email addresses set.",
                    cis_ref="1.11", profile_level=1))
            else:
                names = [r["NAME"] for r in rows]
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"{len(rows)} ACCOUNTADMIN user(s) lack email addresses.",
                    evidence=f"Users without email: {', '.join(names)}",
                    remediation="ALTER USER <username> SET EMAIL = '<email>';",
                    cis_ref="1.11", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.11"))

    def check_1_12_no_admin_default_role(self):
        """1.12 Ensure no users have ACCOUNTADMIN/SECURITYADMIN as default role (Automated)"""
        rid, title = "SF-IAM-012", "No users have ACCOUNTADMIN/SECURITYADMIN as default role"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT NAME, DEFAULT_ROLE "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.USERS "
                "WHERE DEFAULT_ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN') "
                "  AND DELETED_ON IS NULL "
                "  AND DISABLED = 'false';"
            )
            if not rows:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="No users have ACCOUNTADMIN/SECURITYADMIN as default role.",
                    cis_ref="1.12", profile_level=1))
            else:
                detail = [f"{r['NAME']}({r['DEFAULT_ROLE']})" for r in rows]
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description=f"{len(rows)} user(s) have admin roles as default.",
                    evidence=f"Users: {', '.join(detail)}",
                    remediation="ALTER USER <user> SET DEFAULT_ROLE = <less_privileged_role>;",
                    cis_ref="1.12", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="1.12"))

    def check_1_13_admin_not_granted_custom(self):
        """1.13 Ensure ACCOUNTADMIN/SECURITYADMIN not granted to custom roles (Automated)"""
        rid, title = "SF-IAM-013", "ACCOUNTADMIN/SECURITYADMIN not granted to custom roles"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT GRANTEE_NAME AS CUSTOM_ROLE, "
                "  PRIVILEGE AS GRANTED_PRIVILEGE, "
                "  NAME AS GRANTED_ROLE "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
                "WHERE GRANTED_ON = 'ROLE' "
                "  AND NAME IN ('ACCOUNTADMIN','SECURITYADMIN') "
                "  AND DELETED_ON IS NULL;"
            )
            # Expected: only ACCOUNTADMIN inheriting SECURITYADMIN
            unexpected = [r for r in rows if not (
                r.get("CUSTOM_ROLE") == "ACCOUNTADMIN" and r.get("GRANTED_ROLE") == "SECURITYADMIN"
            )]
            if not unexpected:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="ACCOUNTADMIN/SECURITYADMIN not granted to custom roles.",
                    cis_ref="1.13", profile_level=1))
            else:
                detail = [f"{r.get('CUSTOM_ROLE')} <- {r.get('GRANTED_ROLE')}" for r in unexpected]
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description=f"Admin roles granted to custom roles.",
                    evidence=f"Grants: {', '.join(detail)}",
                    remediation="REVOKE ROLE ACCOUNTADMIN FROM ROLE <custom_role>;",
                    cis_ref="1.13", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="1.13"))

    def check_1_14_tasks_not_owned_by_admin(self):
        """1.14 Ensure tasks are not owned by ACCOUNTADMIN/SECURITYADMIN (Automated)"""
        rid, title = "SF-IAM-014", "Tasks are not owned by ACCOUNTADMIN/SECURITYADMIN"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT NAME, GRANTEE_NAME AS ROLE_NAME "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
                "WHERE GRANTED_ON = 'TASK' "
                "  AND DELETED_ON IS NULL "
                "  AND GRANTED_TO = 'ROLE' "
                "  AND PRIVILEGE = 'OWNERSHIP' "
                "  AND GRANTEE_NAME IN ('ACCOUNTADMIN', 'SECURITYADMIN');"
            )
            if not rows:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="No tasks are owned by ACCOUNTADMIN/SECURITYADMIN.",
                    cis_ref="1.14", profile_level=1))
            else:
                detail = [f"{r['NAME']}({r['ROLE_NAME']})" for r in rows[:10]]
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"{len(rows)} task(s) owned by admin roles.",
                    evidence=f"Tasks: {', '.join(detail)}",
                    remediation="GRANT OWNERSHIP ON TASK <task> TO ROLE <custom_role>;",
                    cis_ref="1.14", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.14"))

    def check_1_15_tasks_not_run_as_admin(self):
        """1.15 Ensure tasks don't run with ACCOUNTADMIN/SECURITYADMIN privileges (Automated)"""
        rid, title = "SF-IAM-015", "Tasks do not run with ACCOUNTADMIN/SECURITYADMIN privileges"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT NAME, GRANTEE_NAME AS ROLE_NAME, PRIVILEGE "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
                "WHERE GRANTED_ON = 'TASK' "
                "  AND DELETED_ON IS NULL "
                "  AND GRANTED_TO = 'ROLE' "
                "  AND GRANTEE_NAME IN ('ACCOUNTADMIN', 'SECURITYADMIN');"
            )
            if not rows:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="No tasks have privileges granted to admin roles.",
                    cis_ref="1.15", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"{len(rows)} task privilege(s) granted to admin roles.",
                    remediation="REVOKE ALL PRIVILEGES ON TASK <task> FROM ROLE ACCOUNTADMIN;",
                    cis_ref="1.15", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.15"))

    def check_1_16_procedures_not_owned_by_admin(self):
        """1.16 Ensure stored procedures not owned by admin roles (Automated)"""
        rid, title = "SF-IAM-016", "Stored procedures not owned by ACCOUNTADMIN/SECURITYADMIN"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT PROCEDURE_NAME, PROCEDURE_OWNER "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.PROCEDURES "
                "WHERE DELETED IS NULL "
                "  AND PROCEDURE_OWNER IN ('ACCOUNTADMIN','SECURITYADMIN');"
            )
            if not rows:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="No stored procedures owned by admin roles.",
                    cis_ref="1.16", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"{len(rows)} stored procedure(s) owned by admin roles.",
                    evidence=f"Procedures: {', '.join(r['PROCEDURE_NAME'] for r in rows[:10])}",
                    remediation="GRANT OWNERSHIP ON PROCEDURE <proc> TO ROLE <custom_role>;",
                    cis_ref="1.16", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.16"))

    def check_1_17_procedures_not_run_as_admin(self):
        """1.17 Ensure stored procedures don't run with admin privileges (Automated)"""
        rid, title = "SF-IAM-017", "Stored procedures do not run with admin privileges"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT NAME AS STORED_PROCEDURE_NAME, GRANTEE_NAME AS ROLE_NAME "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
                "WHERE GRANTED_ON = 'PROCEDURE' "
                "  AND DELETED_ON IS NULL "
                "  AND GRANTED_TO = 'ROLE' "
                "  AND GRANTEE_NAME IN ('ACCOUNTADMIN', 'SECURITYADMIN');"
            )
            if not rows:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="No stored procedures have privileges granted to admin roles.",
                    cis_ref="1.17", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"{len(rows)} stored procedure privilege(s) granted to admin roles.",
                    remediation="REVOKE ALL PRIVILEGES ON PROCEDURE <proc> FROM ROLE ACCOUNTADMIN;",
                    cis_ref="1.17", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="1.17"))

    # ----------------------------------------------------------
    # Section 2: Monitoring and Alerting
    # ----------------------------------------------------------

    def _check_monitoring_query(self, rid: str, title: str, severity: str,
                                query: str, desc_pass: str, desc_fail: str,
                                remediation: str, cis_ref: str):
        """Generic monitoring check: run query, PASS if rows exist, WARN otherwise."""
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(query)
            if rows:
                self._add(Finding(rid, title, "PASS", severity,
                    description=desc_pass,
                    evidence=f"{len(rows)} relevant event(s) found in query history.",
                    cis_ref=cis_ref, profile_level=1))
            else:
                self._add(Finding(rid, title, "WARN", severity,
                    description=desc_fail,
                    remediation=remediation,
                    cis_ref=cis_ref, profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", severity, evidence=str(e), cis_ref=cis_ref))

    def check_2_1_monitor_admin_grants(self):
        """2.1 Ensure monitoring for ACCOUNTADMIN/SECURITYADMIN role grants"""
        self._check_monitoring_query(
            "SF-MON-001",
            "Monitoring exists for admin role grants",
            "HIGH",
            "SELECT * FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES "
            "WHERE NAME IN ('ACCOUNTADMIN','SECURITYADMIN') "
            "AND CREATED_ON >= DATEADD(day, -30, CURRENT_TIMESTAMP()) LIMIT 5;",
            "Admin role grant events found in the last 30 days (monitoring data available).",
            "No recent admin role grant events found. Ensure monitoring/alerting is configured.",
            "Create a scheduled task to alert on new ACCOUNTADMIN/SECURITYADMIN grants.",
            "2.1",
        )

    def check_2_2_monitor_manage_grants(self):
        """2.2 Ensure monitoring for MANAGE GRANTS privilege grants"""
        self._check_monitoring_query(
            "SF-MON-002",
            "Monitoring exists for MANAGE GRANTS privilege grants",
            "HIGH",
            "SELECT END_TIME, QUERY_TYPE, QUERY_TEXT, USER_NAME, ROLE_NAME "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            "WHERE EXECUTION_STATUS = 'SUCCESS' "
            "  AND QUERY_TYPE = 'GRANT' "
            "  AND REGEXP_INSTR(QUERY_TEXT, 'manage\\\\s*grants', 1, 1, 0, 'i') > 0 "
            "  AND END_TIME >= DATEADD(day, -30, CURRENT_TIMESTAMP()) "
            "ORDER BY END_TIME DESC LIMIT 5;",
            "MANAGE GRANTS events found in recent query history.",
            "No MANAGE GRANTS events found. Ensure monitoring is configured.",
            "Create monitoring task to alert on MANAGE GRANTS privilege changes.",
            "2.2",
        )

    def check_2_3_monitor_password_signin_sso(self):
        """2.3 Ensure monitoring for password sign-ins of SSO users"""
        self._check_monitoring_query(
            "SF-MON-003",
            "Monitoring exists for password sign-ins of SSO users",
            "MEDIUM",
            "SELECT EVENT_TIMESTAMP, USER_NAME, CLIENT_IP, "
            "  FIRST_AUTHENTICATION_FACTOR, SECOND_AUTHENTICATION_FACTOR "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
            "WHERE FIRST_AUTHENTICATION_FACTOR = 'PASSWORD' "
            "  AND EVENT_TIMESTAMP >= DATEADD(day, -7, CURRENT_TIMESTAMP()) "
            "ORDER BY EVENT_TIMESTAMP DESC LIMIT 5;",
            "Password sign-in events found. Review if any belong to SSO users.",
            "No recent password sign-in events. Monitoring data may be available.",
            "Create monitoring task to detect password sign-ins when SSO is configured.",
            "2.3",
        )

    def check_2_4_monitor_password_no_mfa(self):
        """2.4 Ensure monitoring for password sign-in without MFA"""
        self._check_monitoring_query(
            "SF-MON-004",
            "Monitoring exists for password sign-in without MFA",
            "HIGH",
            "SELECT EVENT_TIMESTAMP, USER_NAME, CLIENT_IP "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
            "WHERE FIRST_AUTHENTICATION_FACTOR = 'PASSWORD' "
            "  AND SECOND_AUTHENTICATION_FACTOR IS NULL "
            "  AND EVENT_TIMESTAMP >= DATEADD(day, -7, CURRENT_TIMESTAMP()) "
            "ORDER BY EVENT_TIMESTAMP DESC LIMIT 5;",
            "Password sign-ins without MFA detected. Alert should be configured.",
            "No recent password-only sign-ins found.",
            "Create monitoring task to alert on password sign-ins without MFA.",
            "2.4",
        )

    def check_2_5_monitor_security_integrations(self):
        """2.5 Ensure monitoring for security integration changes"""
        self._check_monitoring_query(
            "SF-MON-005",
            "Monitoring exists for security integration changes",
            "HIGH",
            "SELECT END_TIME, QUERY_TYPE, QUERY_TEXT, USER_NAME, ROLE_NAME "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            "WHERE EXECUTION_STATUS = 'SUCCESS' "
            "  AND QUERY_TYPE IN ('CREATE', 'ALTER', 'DROP') "
            "  AND QUERY_TEXT ILIKE '%security integration%' "
            "  AND END_TIME >= DATEADD(day, -30, CURRENT_TIMESTAMP()) "
            "ORDER BY END_TIME DESC LIMIT 5;",
            "Security integration change events found in query history.",
            "No security integration changes detected. Ensure monitoring is active.",
            "Create monitoring task to alert on CREATE/ALTER/DROP security integrations.",
            "2.5",
        )

    def check_2_6_monitor_network_policies(self):
        """2.6 Ensure monitoring for network policy changes"""
        self._check_monitoring_query(
            "SF-MON-006",
            "Monitoring exists for network policy changes",
            "HIGH",
            "SELECT END_TIME, QUERY_TYPE, QUERY_TEXT, USER_NAME "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            "WHERE EXECUTION_STATUS = 'SUCCESS' "
            "  AND (QUERY_TYPE IN ('CREATE_NETWORK_POLICY','ALTER_NETWORK_POLICY','DROP_NETWORK_POLICY') "
            "       OR (QUERY_TEXT ILIKE '%set%network_policy%' "
            "           OR QUERY_TEXT ILIKE '%unset%network_policy%')) "
            "  AND END_TIME >= DATEADD(day, -30, CURRENT_TIMESTAMP()) "
            "ORDER BY END_TIME DESC LIMIT 5;",
            "Network policy change events found.",
            "No recent network policy changes detected. Ensure monitoring is active.",
            "Create monitoring task to alert on network policy changes.",
            "2.6",
        )

    def check_2_7_monitor_scim_token(self):
        """2.7 Ensure monitoring for SCIM token creation"""
        self._check_monitoring_query(
            "SF-MON-007",
            "Monitoring exists for SCIM token creation",
            "MEDIUM",
            "SELECT END_TIME, QUERY_TEXT, USER_NAME "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            "WHERE EXECUTION_STATUS = 'SUCCESS' "
            "  AND QUERY_TYPE = 'SELECT' "
            "  AND REGEXP_INSTR(QUERY_TEXT, 'system\\\\\\$generate_scim_access_token', 1, 1, 0, 'i') > 0 "
            "  AND END_TIME >= DATEADD(day, -90, CURRENT_TIMESTAMP()) "
            "ORDER BY END_TIME DESC LIMIT 5;",
            "SCIM token generation events found.",
            "No SCIM token creation detected. Ensure monitoring is configured.",
            "Create monitoring task to alert on SCIM access token generation.",
            "2.7",
        )

    def check_2_8_monitor_share_exposures(self):
        """2.8 Ensure monitoring for new share exposures"""
        self._check_monitoring_query(
            "SF-MON-008",
            "Monitoring exists for new share exposures",
            "HIGH",
            "SELECT END_TIME, QUERY_TEXT, USER_NAME "
            "FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY "
            "WHERE EXECUTION_STATUS = 'SUCCESS' "
            "  AND QUERY_TYPE = 'ALTER' "
            "  AND REGEXP_INSTR(QUERY_TEXT, "
            "      '^alter\\\\s*share.*(add|set)\\\\s*accounts\\\\s*=', 1, 1, 0, 'is') > 0 "
            "  AND END_TIME >= DATEADD(day, -30, CURRENT_TIMESTAMP()) "
            "ORDER BY END_TIME DESC LIMIT 5;",
            "Share exposure events found.",
            "No recent share exposures detected. Ensure monitoring is active.",
            "Create monitoring task to alert on ALTER SHARE ... ADD/SET ACCOUNTS.",
            "2.8",
        )

    def check_2_9_monitor_unsupported_drivers(self):
        """2.9 Ensure monitoring for unsupported client drivers"""
        rid, title = "SF-MON-009", "Monitoring exists for unsupported client drivers"
        self._log(f"Checking {rid}: {title}")
        try:
            rows = self.client.query(
                "SELECT CREATED_ON, USER_NAME, "
                "  CLIENT_APPLICATION_ID, CLIENT_APPLICATION_VERSION "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.SESSIONS "
                "WHERE CREATED_ON >= DATEADD(day, -30, CURRENT_TIMESTAMP()) "
                "LIMIT 5;"
            )
            if rows:
                self._add(Finding(rid, title, "PASS", "LOW",
                    description="Session data available for monitoring client driver versions.",
                    evidence=f"Sample: {rows[0].get('CLIENT_APPLICATION_ID', 'N/A')} "
                             f"v{rows[0].get('CLIENT_APPLICATION_VERSION', 'N/A')}",
                    cis_ref="2.9", profile_level=2))
            else:
                self._add(Finding(rid, title, "WARN", "LOW",
                    description="No session data available for client version monitoring.",
                    remediation="Monitor SNOWFLAKE.ACCOUNT_USAGE.SESSIONS for unsupported client versions.",
                    cis_ref="2.9", profile_level=2))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "LOW", evidence=str(e), cis_ref="2.9"))

    # ----------------------------------------------------------
    # Section 3: Networking
    # ----------------------------------------------------------

    def check_3_1_account_network_policy(self):
        """3.1 Ensure account-level network policy configured (Manual)"""
        rid, title = "SF-NET-001", "Account-level network policy is configured"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;")
            rows = self.client.query(
                "SELECT \"value\" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) "
                "WHERE \"value\" IS NOT NULL AND \"value\" != '';"
            )
            if rows:
                policy_name = rows[0].get("value", rows[0].get("VALUE", ""))
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description=f"Account-level network policy '{policy_name}' is configured.",
                    evidence=f"Policy: {policy_name}",
                    cis_ref="3.1", profile_level=2))
            else:
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description="No account-level network policy configured. "
                                "Access is allowed from any IP address.",
                    remediation="CREATE NETWORK POLICY <policy> ALLOWED_IP_LIST=('...'); "
                                "ALTER ACCOUNT SET NETWORK_POLICY = <policy>;",
                    cis_ref="3.1", profile_level=2))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="3.1"))

    def check_3_2_service_account_network_policy(self):
        """3.2 Ensure user-level network policies for service accounts (Manual)"""
        rid, title = "SF-NET-002", "User-level network policies configured for service accounts"
        self._log(f"Checking {rid}: {title}")
        try:
            svc_users = self.client.query(
                "SELECT TR.OBJECT_NAME "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES TR "
                "LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS U "
                "  ON TR.OBJECT_NAME = U.NAME "
                "WHERE TR.TAG_NAME = 'ACCOUNT_TYPE' "
                "  AND TR.TAG_VALUE = 'service' "
                "  AND TR.DOMAIN = 'USER' "
                "  AND U.DELETED_ON IS NULL;"
            )
            if not svc_users:
                self._add(Finding(rid, title, "SKIP", "MEDIUM",
                    description="No tagged service accounts found. Cannot verify network policies.",
                    remediation="Tag service accounts and apply user-level network policies.",
                    cis_ref="3.2", profile_level=1))
                return
            # For each service account, check if network policy exists
            # (Cannot run SHOW PARAMETERS FOR USER dynamically easily, so check policy refs)
            policy_refs = self.client.query(
                "SELECT REF_ENTITY_NAME "
                "FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES "
                "WHERE POLICY_KIND = 'NETWORK_POLICY' "
                "  AND REF_ENTITY_DOMAIN = 'USER' "
                "  AND POLICY_STATUS = 'ACTIVE';"
            )
            policy_users = {r.get("REF_ENTITY_NAME", "") for r in policy_refs}
            missing = [u["OBJECT_NAME"] for u in svc_users if u["OBJECT_NAME"] not in policy_users]
            if not missing:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="All tagged service accounts have user-level network policies.",
                    cis_ref="3.2", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"{len(missing)} service account(s) lack user-level network policies.",
                    evidence=f"Missing policy: {', '.join(missing[:10])}",
                    remediation="ALTER USER <svc> SET NETWORK_POLICY = <policy>;",
                    cis_ref="3.2", profile_level=1))
        except Exception as e:
            if "does not exist" in str(e).lower():
                self._add(Finding(rid, title, "SKIP", "MEDIUM",
                    description="ACCOUNT_TYPE tag not found. Cannot identify service accounts.",
                    cis_ref="3.2", profile_level=1))
            else:
                self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="3.2"))

    # ----------------------------------------------------------
    # Section 4: Data Protection
    # ----------------------------------------------------------

    def check_4_1_periodic_rekeying(self):
        """4.1 Ensure yearly rekeying is enabled (Automated)"""
        rid, title = "SF-DP-001", "Periodic data rekeying is enabled"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW PARAMETERS LIKE 'PERIODIC_DATA_REKEYING' IN ACCOUNT;")
            rows = self.client.query(
                "SELECT \"value\" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            val = rows[0].get("value", rows[0].get("VALUE", "")) if rows else ""
            if str(val).lower() == "true":
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="Periodic data rekeying is enabled.",
                    cis_ref="4.1", profile_level=2))
            else:
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description="Periodic data rekeying is disabled.",
                    remediation="ALTER ACCOUNT SET PERIODIC_DATA_REKEYING = true;",
                    cis_ref="4.1", profile_level=2))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="4.1"))

    def check_4_2_encryption_key_size(self):
        """4.2 Ensure AES encryption key size is 256 bits (Automated)"""
        rid, title = "SF-DP-002", "AES encryption key size is set to 256 bits"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW PARAMETERS LIKE 'CLIENT_ENCRYPTION_KEY_SIZE' IN ACCOUNT;")
            rows = self.client.query(
                "SELECT \"value\" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            val = rows[0].get("value", rows[0].get("VALUE", "")) if rows else ""
            if str(val) == "256":
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description="Client encryption key size is 256 bits.",
                    cis_ref="4.2", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "MEDIUM",
                    description=f"Client encryption key size is {val} (expected 256).",
                    remediation="ALTER ACCOUNT SET CLIENT_ENCRYPTION_KEY_SIZE = 256;",
                    cis_ref="4.2", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="4.2"))

    def check_4_3_data_retention_critical(self):
        """4.3 Ensure DATA_RETENTION_TIME_IN_DAYS is 90 for critical data (Manual)"""
        rid, title = "SF-DP-003", "Data retention is set to 90 days for critical data"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW PARAMETERS LIKE 'DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT;")
            rows = self.client.query(
                "SELECT \"value\" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            val = int(rows[0].get("value", rows[0].get("VALUE", 1))) if rows else 1
            if val >= 90:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description=f"Account-level data retention is {val} days (>= 90).",
                    cis_ref="4.3", profile_level=2))
            else:
                self._add(Finding(rid, title, "WARN", "MEDIUM",
                    description=f"Account-level data retention is {val} days. "
                                "Manual check needed for critical data tables.",
                    remediation="ALTER TABLE <table> SET DATA_RETENTION_TIME_IN_DAYS = 90;",
                    cis_ref="4.3", profile_level=2))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="4.3"))

    def check_4_4_min_data_retention(self):
        """4.4 Ensure MIN_DATA_RETENTION_TIME_IN_DAYS >= 7 (Automated)"""
        rid, title = "SF-DP-004", "MIN_DATA_RETENTION_TIME_IN_DAYS is set to 7 or higher"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW PARAMETERS LIKE 'MIN_DATA_RETENTION_TIME_IN_DAYS' IN ACCOUNT;")
            rows = self.client.query(
                "SELECT \"value\" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            val = int(rows[0].get("value", rows[0].get("VALUE", 0))) if rows else 0
            if val >= 7:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description=f"MIN_DATA_RETENTION_TIME_IN_DAYS = {val} (>= 7).",
                    cis_ref="4.4", profile_level=2))
            else:
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description=f"MIN_DATA_RETENTION_TIME_IN_DAYS = {val} (should be >= 7).",
                    remediation="ALTER ACCOUNT SET MIN_DATA_RETENTION_TIME_IN_DAYS = 7;",
                    cis_ref="4.4", profile_level=2))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="4.4"))

    def check_4_5_require_storage_integration_creation(self):
        """4.5 Ensure REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION is true (Automated)"""
        rid, title = "SF-DP-005", "Storage integration required for stage creation"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query(
                "SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION' IN ACCOUNT;"
            )
            rows = self.client.query(
                "SELECT \"value\" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            val = rows[0].get("value", rows[0].get("VALUE", "")) if rows else ""
            if str(val).lower() == "true":
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="Storage integration is required for stage creation.",
                    cis_ref="4.5", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description="Storage integration is NOT required for stage creation.",
                    remediation="ALTER ACCOUNT SET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_CREATION = true;",
                    cis_ref="4.5", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="4.5"))

    def check_4_6_require_storage_integration_operation(self):
        """4.6 Ensure REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION is true (Automated)"""
        rid, title = "SF-DP-006", "Storage integration required for stage operations"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query(
                "SHOW PARAMETERS LIKE 'REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION' IN ACCOUNT;"
            )
            rows = self.client.query(
                "SELECT \"value\" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            val = rows[0].get("value", rows[0].get("VALUE", "")) if rows else ""
            if str(val).lower() == "true":
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="Storage integration is required for stage operations.",
                    cis_ref="4.6", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description="Storage integration is NOT required for stage operations.",
                    remediation="ALTER ACCOUNT SET REQUIRE_STORAGE_INTEGRATION_FOR_STAGE_OPERATION = true;",
                    cis_ref="4.6", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="4.6"))

    def check_4_7_external_stages_storage_integration(self):
        """4.7 Ensure all external stages have storage integrations (Automated)"""
        rid, title = "SF-DP-007", "All external stages have storage integrations"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW STAGES;")
            rows = self.client.query(
                "SELECT \"name\", \"type\", \"storage_integration\" "
                "FROM TABLE(RESULT_SCAN(LAST_QUERY_ID())) "
                "WHERE \"type\" = 'EXTERNAL' "
                "  AND (\"storage_integration\" IS NULL OR \"storage_integration\" = '');"
            )
            if not rows:
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="All external stages have storage integrations configured.",
                    cis_ref="4.7", profile_level=1))
            else:
                names = [r.get("name", r.get("NAME", "?")) for r in rows[:10]]
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description=f"{len(rows)} external stage(s) lack storage integrations.",
                    evidence=f"Stages: {', '.join(names)}",
                    remediation="ALTER STAGE <stage> SET STORAGE_INTEGRATION = <integration>;",
                    cis_ref="4.7", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="4.7"))

    def check_4_8_prevent_unload_inline_url(self):
        """4.8 Ensure PREVENT_UNLOAD_TO_INLINE_URL is true (Automated)"""
        rid, title = "SF-DP-008", "PREVENT_UNLOAD_TO_INLINE_URL is set to true"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW PARAMETERS LIKE 'PREVENT_UNLOAD_TO_INLINE_URL' IN ACCOUNT;")
            rows = self.client.query(
                "SELECT \"value\" FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            val = rows[0].get("value", rows[0].get("VALUE", "")) if rows else ""
            if str(val).lower() == "true":
                self._add(Finding(rid, title, "PASS", "HIGH",
                    description="PREVENT_UNLOAD_TO_INLINE_URL is enabled.",
                    cis_ref="4.8", profile_level=1))
            else:
                self._add(Finding(rid, title, "FAIL", "HIGH",
                    description="PREVENT_UNLOAD_TO_INLINE_URL is disabled. Data exfiltration risk.",
                    remediation="ALTER ACCOUNT SET PREVENT_UNLOAD_TO_INLINE_URL = true;",
                    cis_ref="4.8", profile_level=1))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "HIGH", evidence=str(e), cis_ref="4.8"))

    def check_4_9_tri_secret_secure(self):
        """4.9 Ensure Tri-Secret Secure is enabled (Manual)"""
        rid, title = "SF-DP-009", "Tri-Secret Secure is enabled"
        self._log(f"Checking {rid}: {title}")
        # Tri-Secret Secure cannot be verified via SQL — manual check required
        self._add(Finding(rid, title, "WARN", "MEDIUM",
            description="Tri-Secret Secure status cannot be verified programmatically. "
                        "Manual verification required via Snowflake Support.",
            remediation="Contact Snowflake Support to enable Tri-Secret Secure "
                        "(Business Critical Edition or higher required).",
            cis_ref="4.9", profile_level=2))

    def check_4_10_data_masking(self):
        """4.10 Ensure data masking is enabled for sensitive data (Manual)"""
        rid, title = "SF-DP-010", "Data masking policies are configured for sensitive data"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW MASKING POLICIES IN ACCOUNT;")
            rows = self.client.query(
                "SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            if rows:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description=f"{len(rows)} masking policy(ies) configured.",
                    evidence=f"Policies found: {len(rows)}",
                    cis_ref="4.10", profile_level=2))
            else:
                self._add(Finding(rid, title, "WARN", "MEDIUM",
                    description="No masking policies found. Sensitive data may be unprotected.",
                    remediation="Create and apply masking policies for columns with sensitive data.",
                    cis_ref="4.10", profile_level=2))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="4.10"))

    def check_4_11_row_access_policies(self):
        """4.11 Ensure row-access policies are configured (Manual)"""
        rid, title = "SF-DP-011", "Row-access policies are configured for sensitive data"
        self._log(f"Checking {rid}: {title}")
        try:
            self.client.query("SHOW ROW ACCESS POLICIES IN ACCOUNT;")
            rows = self.client.query(
                "SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()));"
            )
            if rows:
                self._add(Finding(rid, title, "PASS", "MEDIUM",
                    description=f"{len(rows)} row access policy(ies) configured.",
                    evidence=f"Policies found: {len(rows)}",
                    cis_ref="4.11", profile_level=2))
            else:
                self._add(Finding(rid, title, "WARN", "MEDIUM",
                    description="No row access policies found.",
                    remediation="Create and apply row access policies for tables with restricted rows.",
                    cis_ref="4.11", profile_level=2))
        except Exception as e:
            self._add(Finding(rid, title, "ERROR", "MEDIUM", evidence=str(e), cis_ref="4.11"))

    # ----------------------------------------------------------
    # Run all checks
    # ----------------------------------------------------------

    def run_all(self):
        """Execute all CIS Snowflake Foundations Benchmark checks."""
        checks = [
            # Section 1: Identity and Access Management
            self.check_1_1_sso_configured,
            self.check_1_2_scim_configured,
            self.check_1_3_sso_users_no_password,
            self.check_1_4_mfa_enabled,
            self.check_1_5_password_policy,
            self.check_1_6_service_accounts_keypair,
            self.check_1_7_keypair_rotation,
            self.check_1_8_inactive_users,
            self.check_1_9_session_timeout,
            self.check_1_10_limit_admin_users,
            self.check_1_11_accountadmin_email,
            self.check_1_12_no_admin_default_role,
            self.check_1_13_admin_not_granted_custom,
            self.check_1_14_tasks_not_owned_by_admin,
            self.check_1_15_tasks_not_run_as_admin,
            self.check_1_16_procedures_not_owned_by_admin,
            self.check_1_17_procedures_not_run_as_admin,
            # Section 2: Monitoring and Alerting
            self.check_2_1_monitor_admin_grants,
            self.check_2_2_monitor_manage_grants,
            self.check_2_3_monitor_password_signin_sso,
            self.check_2_4_monitor_password_no_mfa,
            self.check_2_5_monitor_security_integrations,
            self.check_2_6_monitor_network_policies,
            self.check_2_7_monitor_scim_token,
            self.check_2_8_monitor_share_exposures,
            self.check_2_9_monitor_unsupported_drivers,
            # Section 3: Networking
            self.check_3_1_account_network_policy,
            self.check_3_2_service_account_network_policy,
            # Section 4: Data Protection
            self.check_4_1_periodic_rekeying,
            self.check_4_2_encryption_key_size,
            self.check_4_3_data_retention_critical,
            self.check_4_4_min_data_retention,
            self.check_4_5_require_storage_integration_creation,
            self.check_4_6_require_storage_integration_operation,
            self.check_4_7_external_stages_storage_integration,
            self.check_4_8_prevent_unload_inline_url,
            self.check_4_9_tri_secret_secure,
            self.check_4_10_data_masking,
            self.check_4_11_row_access_policies,
        ]
        for check_fn in checks:
            try:
                check_fn()
            except Exception:
                traceback.print_exc()


# ============================================================
# Scoring engine
# ============================================================
def compute_score(findings: list[Finding]) -> dict:
    """Compute severity-weighted posture score (0-100)."""
    max_pts = earned = 0
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0, "ERROR": 0}
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        w = SEVERITY_WEIGHT.get(f.severity, 0)
        if f.status in ("SKIP", "ERROR"):
            continue
        max_pts += w
        if f.status == "PASS":
            earned += w
        elif f.status == "WARN":
            earned += w * 0.5

    score = round((earned / max_pts) * 100, 1) if max_pts > 0 else 0.0
    has_critical_fail = any(f.status == "FAIL" and f.severity == "CRITICAL" for f in findings)

    return {
        "score": score,
        "max_points": max_pts,
        "earned_points": earned,
        "total_checks": len(findings),
        "counts": counts,
        "severity_counts": sev_counts,
        "has_critical_fail": has_critical_fail,
        "grade": _grade(score),
    }

def _grade(score: float) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


# ============================================================
# Console report
# ============================================================
def print_console_report(findings: list[Finding], score_data: dict, account: str):
    """Pretty-print findings to the console."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print()
    print(_c("=" * 72, "BOLD"))
    print(_c("  Snowflake SSPM Scanner — CIS Snowflake Foundations Benchmark v1.0.0", "BOLD", "CYAN"))
    print(_c(f"  Account: {account}  |  Scanned: {ts}", "DIM"))
    print(_c("=" * 72, "BOLD"))
    print()

    # Group by section
    sections = {
        "SF-IAM": "1. Identity and Access Management",
        "SF-MON": "2. Monitoring and Alerting",
        "SF-NET": "3. Networking",
        "SF-DP":  "4. Data Protection",
    }
    for prefix, heading in sections.items():
        sec_findings = [f for f in findings if f.rule_id.startswith(prefix)]
        if not sec_findings:
            continue
        print(_c(f"  {heading}", "BOLD"))
        print(_c("  " + "-" * 68, "DIM"))
        for f in sec_findings:
            status_str = _c(f"[{f.status:5s}]", _status_colour(f.status), "BOLD")
            sev_str = _c(f"({f.severity})", _severity_colour(f.severity))
            print(f"  {status_str} {sev_str} {f.rule_id} — {f.title}")
            if f.status in ("FAIL", "ERROR", "WARN") and f.description:
                print(f"           {_c(f.description, 'DIM')}")
        print()

    # Score summary
    sd = score_data
    grade_colour = {"A": "GREEN", "B": "GREEN", "C": "YELLOW", "D": "YELLOW", "F": "RED"}.get(sd["grade"], "")
    print(_c("  Score Summary", "BOLD"))
    print(_c("  " + "-" * 68, "DIM"))
    print(f"  Posture Score : {_c(f'{sd["score"]}%', grade_colour, 'BOLD')}  "
          f"Grade: {_c(sd['grade'], grade_colour, 'BOLD')}")
    c = sd["counts"]
    print(f"  Pass: {_c(str(c['PASS']), 'GREEN')}  "
          f"Fail: {_c(str(c['FAIL']), 'RED')}  "
          f"Warn: {_c(str(c['WARN']), 'YELLOW')}  "
          f"Skip: {c['SKIP']}  Error: {c['ERROR']}")
    if sd["has_critical_fail"]:
        print(f"  {_c('!! CRITICAL failures detected !!', 'RED', 'BOLD')}")
    print(_c("=" * 72, "BOLD"))
    print()


# ============================================================
# JSON report
# ============================================================
def write_json_report(findings: list[Finding], score_data: dict,
                      account: str, path: str):
    report = {
        "scanner": "Snowflake SSPM Scanner",
        "version": VERSION,
        "benchmark": "CIS Snowflake Foundations Benchmark v1.0.0",
        "account": account,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "score": score_data,
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)


# ============================================================
# HTML report
# ============================================================
def write_html_report(findings: list[Finding], score_data: dict,
                      account: str, path: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sd = score_data
    esc = html_mod.escape

    status_bg = {
        "PASS": "#2ecc71", "FAIL": "#e74c3c", "WARN": "#f39c12",
        "SKIP": "#95a5a6", "ERROR": "#9b59b6",
    }
    sev_bg = {
        "CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f",
        "LOW": "#3498db", "INFO": "#95a5a6",
    }

    rows_html = ""
    for f in findings:
        comp = COMPLIANCE_MAP.get(f.rule_id, {})
        comp_str = " | ".join(f"{k}: {v}" for k, v in comp.items()) if comp else "—"
        rows_html += (
            f'<tr>'
            f'<td><span class="badge" style="background:{status_bg.get(f.status, "#666")}">'
            f'{esc(f.status)}</span></td>'
            f'<td><span class="badge" style="background:{sev_bg.get(f.severity, "#666")}">'
            f'{esc(f.severity)}</span></td>'
            f'<td>{esc(f.rule_id)}</td>'
            f'<td>{esc(f.title)}</td>'
            f'<td class="desc">{esc(f.description)}</td>'
            f'<td class="desc">{esc(f.remediation)}</td>'
            f'<td class="desc">{esc(f.evidence)}</td>'
            f'<td>{esc(f.cis_ref)}</td>'
            f'<td class="desc" style="font-size:0.75em">{esc(comp_str)}</td>'
            f'</tr>\n'
        )

    grade_color = {"A": "#2ecc71", "B": "#2ecc71", "C": "#f39c12", "D": "#f39c12", "F": "#e74c3c"}.get(sd["grade"], "#fff")
    c = sd["counts"]

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Snowflake SSPM Report — {esc(account)}</title>
<style>
  :root {{ --bg: #0f1923; --card: #162536; --text: #e0e6ed; --accent: #29b5e8; --border: #1e3a52; }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'Segoe UI',system-ui,-apple-system,sans-serif; background:var(--bg);
          color:var(--text); line-height:1.6; }}
  .container {{ max-width:1400px; margin:0 auto; padding:20px; }}
  h1 {{ color:var(--accent); font-size:1.6em; margin-bottom:4px; }}
  .subtitle {{ color:#7f8c9b; font-size:0.9em; margin-bottom:24px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:16px; margin-bottom:24px; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:16px;
           text-align:center; }}
  .card .num {{ font-size:2em; font-weight:700; }}
  .card .lbl {{ font-size:0.8em; color:#7f8c9b; text-transform:uppercase; letter-spacing:1px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card); border-radius:10px; overflow:hidden; }}
  th {{ background:#1a3044; color:var(--accent); padding:10px 8px; text-align:left; font-size:0.8em;
       text-transform:uppercase; letter-spacing:0.5px; position:sticky; top:0; }}
  td {{ padding:8px; border-bottom:1px solid var(--border); font-size:0.85em; vertical-align:top; }}
  tr:hover {{ background:#1a3044; }}
  .badge {{ padding:2px 8px; border-radius:4px; color:#fff; font-size:0.75em; font-weight:600; }}
  .desc {{ max-width:280px; word-wrap:break-word; }}
  .footer {{ text-align:center; color:#4a5568; font-size:0.75em; margin-top:32px; padding:16px; }}
  a {{ color:var(--accent); }}
</style>
</head>
<body>
<div class="container">
  <h1>Snowflake SSPM Security Report</h1>
  <div class="subtitle">
    Account: <strong>{esc(account)}</strong> &nbsp;|&nbsp; Scanned: {esc(ts)} &nbsp;|&nbsp;
    Benchmark: CIS Snowflake Foundations v1.0.0 &nbsp;|&nbsp; Scanner v{VERSION}
  </div>
  <div class="cards">
    <div class="card"><div class="num" style="color:{grade_color}">{sd['score']}%</div><div class="lbl">Posture Score ({sd['grade']})</div></div>
    <div class="card"><div class="num">{sd['total_checks']}</div><div class="lbl">Total Checks</div></div>
    <div class="card"><div class="num" style="color:#2ecc71">{c['PASS']}</div><div class="lbl">Pass</div></div>
    <div class="card"><div class="num" style="color:#e74c3c">{c['FAIL']}</div><div class="lbl">Fail</div></div>
    <div class="card"><div class="num" style="color:#f39c12">{c['WARN']}</div><div class="lbl">Warn</div></div>
    <div class="card"><div class="num" style="color:#95a5a6">{c['SKIP']}</div><div class="lbl">Skip</div></div>
  </div>
  <table>
    <thead><tr>
      <th>Status</th><th>Severity</th><th>Rule ID</th><th>Title</th>
      <th>Description</th><th>Remediation</th><th>Evidence</th><th>CIS Ref</th><th>Compliance</th>
    </tr></thead>
    <tbody>{rows_html}</tbody>
  </table>
  <div class="footer">
    Generated by Snowflake SSPM Scanner v{VERSION} &nbsp;|&nbsp;
    CIS Snowflake Foundations Benchmark v1.0.0
  </div>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_content)


# ============================================================
# CLI
# ============================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="snowflake_scanner",
        description="Snowflake SSPM Scanner — CIS Snowflake Foundations Benchmark v1.0.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python snowflake_scanner.py --account xy12345.us-east-1 --user admin --password $PASS\n"
            "  python snowflake_scanner.py --account xy12345 --user admin --private-key-path key.p8\n"
            "  python snowflake_scanner.py --account xy12345 --user admin --authenticator externalbrowser\n"
        ),
    )
    # Connection
    g = p.add_argument_group("Connection")
    g.add_argument("--account", default=os.environ.get("SNOWFLAKE_ACCOUNT"),
                   help="Snowflake account identifier (env: SNOWFLAKE_ACCOUNT)")
    g.add_argument("--user", default=os.environ.get("SNOWFLAKE_USER"),
                   help="Snowflake username (env: SNOWFLAKE_USER)")
    g.add_argument("--password", default=os.environ.get("SNOWFLAKE_PASSWORD"),
                   help="Snowflake password (env: SNOWFLAKE_PASSWORD)")
    g.add_argument("--role", default=os.environ.get("SNOWFLAKE_ROLE", "ACCOUNTADMIN"),
                   help="Snowflake role (default: ACCOUNTADMIN)")
    g.add_argument("--warehouse", default=os.environ.get("SNOWFLAKE_WAREHOUSE"),
                   help="Snowflake warehouse (env: SNOWFLAKE_WAREHOUSE)")
    g.add_argument("--private-key-path", default=os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH"),
                   help="Path to RSA private key (env: SNOWFLAKE_PRIVATE_KEY_PATH)")
    g.add_argument("--private-key-passphrase",
                   default=os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE"),
                   help="Passphrase for private key (env: SNOWFLAKE_PRIVATE_KEY_PASSPHRASE)")
    g.add_argument("--authenticator", default=os.environ.get("SNOWFLAKE_AUTHENTICATOR"),
                   help="Authenticator type: externalbrowser, snowflake (default)")
    # Output
    o = p.add_argument_group("Output")
    o.add_argument("--json", dest="json_path", metavar="FILE",
                   help="Write JSON report to FILE")
    o.add_argument("--html", dest="html_path", metavar="FILE",
                   help="Write HTML report to FILE")
    o.add_argument("--min-score", type=float, default=0,
                   help="Exit 1 if score is below this threshold (default: 0)")
    o.add_argument("-v", "--verbose", action="store_true",
                   help="Show check-by-check progress")
    o.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate
    if not HAS_SNOWFLAKE:
        print("ERROR: snowflake-connector-python is required.\n"
              "  pip install snowflake-connector-python", file=sys.stderr)
        sys.exit(2)

    if not args.account or not args.user:
        parser.error("--account and --user are required (or set env vars)")

    if not args.password and not args.private_key_path and not args.authenticator:
        parser.error("One of --password, --private-key-path, or --authenticator is required")

    # Connect
    client = SnowflakeClient(
        account=args.account,
        user=args.user,
        password=args.password,
        role=args.role,
        warehouse=args.warehouse,
        private_key_path=args.private_key_path,
        private_key_passphrase=args.private_key_passphrase,
        authenticator=args.authenticator,
    )

    print(f"\n{_c('[*]', 'CYAN')} Connecting to Snowflake account: {args.account} ...")
    try:
        client.connect()
    except Exception as e:
        print(f"{_c('[!]', 'RED')} Connection failed: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"{_c('[+]', 'GREEN')} Connected as {args.user} with role {args.role}")

    # Scan
    scanner = SnowflakeScanner(client, verbose=args.verbose)
    print(f"{_c('[*]', 'CYAN')} Running CIS Snowflake Foundations Benchmark v1.0.0 checks ...")
    scanner.run_all()

    # Score
    score_data = compute_score(scanner.findings)

    # Output
    print_console_report(scanner.findings, score_data, args.account)

    if args.json_path:
        write_json_report(scanner.findings, score_data, args.account, args.json_path)
        print(f"{_c('[+]', 'GREEN')} JSON report: {args.json_path}")

    if args.html_path:
        write_html_report(scanner.findings, score_data, args.account, args.html_path)
        print(f"{_c('[+]', 'GREEN')} HTML report: {args.html_path}")

    # Cleanup
    client.close()

    # Exit code
    if score_data["has_critical_fail"] or score_data["score"] < args.min_score:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
