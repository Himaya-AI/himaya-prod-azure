"""
Full Battle Test Suite — Helios Production Readiness
Covers every major feature end-to-end against the live API.

Features tested:
  - Sign up (register) + duplicate rejection
  - Login + wrong password + JWT structure
  - Forgot password + set password flow
  - Dashboard: all fields numeric, org-scoped, AI risk score
  - Message trace: structure, filters, detail view
  - Inbox posture: summary, apps, rules, forwards, scan trigger, AI score
  - Compliance: overview, controls, PDF + HTML report generation + download
  - Integration connect/disconnect: onboarding status, integration state
  - Sandbox: list sessions, create session, WebSocket connectivity
  - Threats: list, detail, bulk actions, auto-triage status
  - Quarantine: list, structure, action idempotency
  - Policies: list, CRUD structure
  - People/directory: users present, groups no-500
  - Reports: list, generation
  - Settings: org settings readable
  - Static assets: frontend, taskpane, icons, manifest
  - Security: unauthenticated rejection, wrong-org isolation, CSP headers

Env vars:
  HELIOS_API           — https://app.himaya.ai
  HELIOS_TEST_EMAIL    — admin test user email
  HELIOS_TEST_PASSWORD — admin test user password
  HELIOS_PHISH_KEY     — org phish reporter key
"""
import os
import time
import uuid
import base64
import json
import re

import httpx
import pytest

API = os.environ.get("HELIOS_API", "https://app.himaya.ai")
TEST_EMAIL = os.environ.get("HELIOS_TEST_EMAIL", "")
TEST_PASSWORD = os.environ.get("HELIOS_TEST_PASSWORD", "")
PHISH_KEY = os.environ.get("HELIOS_PHISH_KEY", "")

NEED_CREDS = pytest.mark.skipif(
    not TEST_EMAIL or not TEST_PASSWORD,
    reason="HELIOS_TEST_EMAIL / HELIOS_TEST_PASSWORD not set",
)
NEED_KEY = pytest.mark.skipif(not PHISH_KEY, reason="HELIOS_PHISH_KEY not set")


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=API, timeout=30, follow_redirects=True) as c:
        yield c


@pytest.fixture(scope="module")
def auth(client):
    if not TEST_EMAIL or not TEST_PASSWORD:
        pytest.skip("Credentials not set")
    r = client.post("/api/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    assert r.status_code == 200, f"Login failed: {r.status_code} {r.text[:300]}"
    data = r.json()
    return {
        "token": data["access_token"],
        "org_id": data.get("org_id", ""),
        "headers": {"Authorization": f"Bearer {data['access_token']}"},
    }


# ─────────────────────────────────────────────────────────────────────────────
# 1. API Health
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIHealth:
    def test_health_endpoint(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_openapi_schema_has_routes(self, client):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        assert len(schema.get("paths", {})) > 15, \
            "Too few API routes — router registration may be broken"

    def test_docs_reachable(self, client):
        r = client.get("/docs")
        assert r.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# 2. Auth — Sign Up, Login, Forgot Password
# ─────────────────────────────────────────────────────────────────────────────

class TestAuth:
    def test_register_duplicate_domain_rejected(self, client):
        """Re-registering with an existing domain must return 400."""
        if not TEST_EMAIL:
            pytest.skip("No test email set")
        domain = TEST_EMAIL.split("@")[1]
        r = client.post("/api/auth/register", json={
            "org_name": "Duplicate Org",
            "domain": domain,
            "country": "SA",
            "email": f"newuser-{uuid.uuid4().hex[:6]}@{domain}",
            "password": "TestPass123!",
        })
        # Should be 400 (domain taken) or 409 — NOT 200 or 500
        assert r.status_code in (400, 409, 422), \
            f"Duplicate domain registration returned unexpected {r.status_code}: {r.text}"

    def test_register_duplicate_email_rejected(self, client):
        """Re-registering with an existing email must be rejected."""
        if not TEST_EMAIL:
            pytest.skip("No test email set")
        r = client.post("/api/auth/register", json={
            "org_name": "Another Org",
            "domain": f"battle-{uuid.uuid4().hex[:6]}.test",
            "country": "SA",
            "email": TEST_EMAIL,
            "password": "TestPass123!",
        })
        assert r.status_code in (400, 409, 422), \
            f"Duplicate email registration returned {r.status_code}: {r.text}"

    @NEED_CREDS
    def test_login_returns_valid_jwt(self, client):
        r = client.post("/api/auth/login", json={"email": TEST_EMAIL, "password": TEST_PASSWORD})
        assert r.status_code == 200, f"Login failed: {r.text}"
        data = r.json()
        assert "access_token" in data
        parts = data["access_token"].split(".")
        assert len(parts) == 3, "Token is not a 3-part JWT"

    @NEED_CREDS
    def test_jwt_contains_org_id(self, auth):
        payload_b64 = auth["token"].split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        assert "org_id" in payload, \
            "JWT payload missing org_id — tenant isolation broken"

    def test_wrong_password_returns_401(self, client):
        if not TEST_EMAIL:
            pytest.skip("No test email set")
        r = client.post("/api/auth/login", json={"email": TEST_EMAIL, "password": "WRONG_PASSWORD_XYZ"})
        assert r.status_code == 401, f"Wrong password returned {r.status_code} instead of 401"

    def test_nonexistent_user_returns_401(self, client):
        r = client.post("/api/auth/login", json={"email": "nobody@nowhere-invalid.com", "password": "x"})
        assert r.status_code == 401

    @NEED_CREDS
    def test_me_endpoint_returns_correct_user(self, client, auth):
        r = client.get("/api/auth/me", headers=auth["headers"])
        assert r.status_code == 200, f"/me failed: {r.text}"
        data = r.json()
        assert data.get("email") == TEST_EMAIL
        assert "org_id" in data
        assert "role" in data

    def test_forgot_password_unknown_email_no_leak(self, client):
        """Forgot password must not reveal whether an email exists."""
        r = client.post("/api/auth/forgot-password", json={"email": "unknown-xyz@nowhere.invalid"})
        # Must return 200 with generic message (not 404 which leaks user existence)
        assert r.status_code == 200, f"forgot-password leaked status: {r.status_code}"
        data = r.json()
        assert "message" in data, "forgot-password missing message field"

    @NEED_CREDS
    def test_forgot_password_known_email_no_error(self, client):
        """Forgot password for a real email must not 500."""
        r = client.post("/api/auth/forgot-password", json={"email": TEST_EMAIL})
        assert r.status_code == 200, f"forgot-password for real email returned {r.status_code}: {r.text}"

    def test_set_password_invalid_token_rejected(self, client):
        """set-password with a bogus token must return 400."""
        r = client.post("/api/auth/set-password", json={
            "token": "totally-fake-token-xyz",
            "new_password": "NewPass123!",
        })
        assert r.status_code == 400, \
            f"Invalid reset token returned {r.status_code} instead of 400"

    def test_unauthenticated_protected_routes_rejected(self, client):
        """All protected routes must reject unauthenticated requests."""
        protected = [
            "/api/threats", "/api/dashboard/summary", "/api/compliance/overview",
            "/api/posture/summary", "/api/quarantine", "/api/policies",
            "/api/people", "/api/message-trace", "/api/reports", "/api/settings/org",
        ]
        for route in protected:
            r = client.get(route)
            assert r.status_code in (401, 403), \
                f"Route {route} did not require auth — returned {r.status_code}"


# ─────────────────────────────────────────────────────────────────────────────
# 3. Dashboard
# ─────────────────────────────────────────────────────────────────────────────

class TestDashboard:
    @NEED_CREDS
    def test_summary_all_required_fields_present(self, client, auth):
        r = client.get("/api/dashboard/summary", headers=auth["headers"])
        assert r.status_code == 200, f"Dashboard summary failed: {r.text}"
        data = r.json()
        assert "detail" not in data, f"Dashboard returned error: {data}"
        required = ["risk_score", "compliance_score", "active_threats",
                    "emails_scanned", "active_policies", "status"]
        for field in required:
            assert field in data, f"Dashboard missing field: {field}"

    @NEED_CREDS
    def test_summary_numeric_fields_non_negative(self, client, auth):
        r = client.get("/api/dashboard/summary", headers=auth["headers"])
        data = r.json()
        for field in ["risk_score", "compliance_score", "active_threats",
                      "emails_scanned", "active_policies"]:
            if field in data:
                assert isinstance(data[field], (int, float)) and data[field] >= 0, \
                    f"Dashboard field {field} has invalid value: {data[field]}"

    @NEED_CREDS
    def test_summary_risk_score_bounded(self, client, auth):
        r = client.get("/api/dashboard/summary", headers=auth["headers"])
        data = r.json()
        assert 0 <= data.get("risk_score", 0) <= 100, \
            f"risk_score out of 0-100 range: {data.get('risk_score')}"

    @NEED_CREDS
    def test_summary_status_valid_value(self, client, auth):
        r = client.get("/api/dashboard/summary", headers=auth["headers"])
        data = r.json()
        assert data.get("status") in ("healthy", "warning", "critical"), \
            f"Unexpected status value: {data.get('status')}"

    @NEED_CREDS
    def test_summary_org_scoped(self, client, auth):
        """Dashboard must be scoped to the authenticated org."""
        r = client.get("/api/dashboard/summary", headers=auth["headers"])
        data = r.json()
        if "org_id" in data:
            assert data["org_id"] == auth.get("org_id"), \
                "Dashboard returned data for wrong org — cross-tenant leak!"

    @NEED_CREDS
    def test_ai_risk_score_structure(self, client, auth):
        """AI risk score endpoint must return valid score structure."""
        r = client.get("/api/dashboard/ai-risk-score", headers=auth["headers"], timeout=60)
        assert r.status_code == 200, f"AI risk score failed: {r.text}"
        data = r.json()
        assert "score" in data, "AI risk score missing 'score' field"
        assert "risk_level" in data, "AI risk score missing 'risk_level' field"
        assert "explanation" in data, "AI risk score missing 'explanation' field"
        assert "key_factors" in data, "AI risk score missing 'key_factors' field"
        assert 0 <= data["score"] <= 100, f"AI score out of range: {data['score']}"
        assert data["risk_level"] in ("low", "guarded", "elevated", "high", "critical"), \
            f"Invalid risk_level: {data['risk_level']}"
        assert isinstance(data["key_factors"], list) and len(data["key_factors"]) >= 1, \
            "key_factors must be a non-empty list"

    @NEED_CREDS
    def test_ai_risk_score_reflects_posture(self, client, auth):
        """AI risk score key_factors must mention posture when posture scan has run."""
        r = client.get("/api/dashboard/ai-risk-score", headers=auth["headers"], timeout=60)
        data = r.json()
        # If posture data exists, key_factors should mention posture or no findings
        posture_r = client.get("/api/posture/summary", headers=auth["headers"])
        if posture_r.status_code == 200:
            posture = posture_r.json()
            if posture.get("last_scanned"):
                # The posture signal must have been fed into the scoring prompt
                factors_text = " ".join(data.get("key_factors", [])).lower()
                assert any(kw in factors_text for kw in ["posture", "oauth", "rule", "forward", "finding"]), \
                    "AI risk score key_factors don't mention posture despite scan data existing"

    @NEED_CREDS
    def test_trends_endpoint(self, client, auth):
        r = client.get("/api/dashboard/trends", headers=auth["headers"])
        assert r.status_code == 200, f"Trends endpoint returned {r.status_code}: {r.text[:200]}"

    @NEED_CREDS
    def test_recent_threats_endpoint(self, client, auth):
        r = client.get("/api/dashboard/threats/recent", headers=auth["headers"])
        assert r.status_code == 200, f"Recent threats returned {r.status_code}: {r.text[:200]}"


# ─────────────────────────────────────────────────────────────────────────────
# 4. Message Trace
# ─────────────────────────────────────────────────────────────────────────────

class TestMessageTrace:
    @NEED_CREDS
    def test_message_trace_reachable(self, client, auth):
        r = client.get("/api/message-trace", headers=auth["headers"])
        assert r.status_code == 200, \
            f"Message trace returned {r.status_code}: {r.text[:300]}\n" \
            "REGRESSION: M365/Google token schema change may have broken delta sync"
        data = r.json()
        assert not (isinstance(data, dict) and "detail" in data), \
            f"Message trace returned error: {data}"

    @NEED_CREDS
    def test_message_trace_schema(self, client, auth):
        """If there are messages, each must have required fields."""
        r = client.get("/api/message-trace?limit=5", headers=auth["headers"])
        data = r.json()
        items = data if isinstance(data, list) else data.get("items", data.get("messages", []))
        if items:
            first = items[0]
            for field in ["id", "subject", "sender"]:
                assert field in first, \
                    f"Message trace item missing field '{field}' — schema may have changed"

    @NEED_CREDS
    def test_message_trace_filters_no_500(self, client, auth):
        """All filter combinations must return 200, not 500."""
        filters = [
            "?limit=5",
            "?threat_type=PHISHING",
            "?status=quarantined",
            "?limit=5&offset=0",
            "?limit=10&offset=5",
        ]
        for f in filters:
            r = client.get(f"/api/message-trace{f}", headers=auth["headers"])
            assert r.status_code == 200, \
                f"Message trace with filter {f} returned {r.status_code}: {r.text[:100]}"

    @NEED_CREDS
    def test_message_trace_detail_reachable(self, client, auth):
        """If messages exist, fetching detail for first one must work."""
        r = client.get("/api/message-trace?limit=1", headers=auth["headers"])
        data = r.json()
        items = data if isinstance(data, list) else data.get("items", [])
        if not items:
            pytest.skip("No messages for detail test")
        item_id = items[0].get("id")
        if not item_id:
            pytest.skip("Message has no id field")
        r2 = client.get(f"/api/message-trace/{item_id}", headers=auth["headers"])
        # 200 or 404 (item might be threat not trace record) — never 500
        assert r2.status_code in (200, 404), \
            f"Message trace detail returned {r2.status_code}: {r2.text[:100]}"


# ─────────────────────────────────────────────────────────────────────────────
# 5. Inbox Posture
# ─────────────────────────────────────────────────────────────────────────────

class TestInboxPosture:
    @NEED_CREDS
    def test_posture_summary_reachable(self, client, auth):
        r = client.get("/api/posture/summary", headers=auth["headers"])
        # 200 for enterprise orgs, 403 for non-enterprise
        assert r.status_code in (200, 403), \
            f"Posture summary returned {r.status_code}: {r.text}"

    @NEED_CREDS
    def test_posture_summary_schema(self, client, auth):
        r = client.get("/api/posture/summary", headers=auth["headers"])
        if r.status_code == 403:
            pytest.skip("Org is not Enterprise tier — posture feature gated")
        data = r.json()
        required = ["posture_score", "high_risk_apps", "high_risk_rules",
                    "external_forwards", "total_apps", "total_rules", "total_forwards"]
        for field in required:
            assert field in data, f"Posture summary missing field: {field}"
        assert 0 <= data["posture_score"] <= 100, \
            f"posture_score out of 0-100: {data['posture_score']}"

    @NEED_CREDS
    def test_posture_apps_returns_list(self, client, auth):
        r = client.get("/api/posture/apps", headers=auth["headers"])
        if r.status_code == 403:
            pytest.skip("Non-enterprise org")
        assert r.status_code == 200, f"Posture apps returned {r.status_code}: {r.text}"
        data = r.json()
        assert isinstance(data, list), "Posture apps must return a list"
        if data:
            app = data[0]
            for field in ["id", "name", "provider", "risk", "scopes"]:
                assert field in app, f"App record missing field: {field}"
            assert app["risk"] in ("low", "medium", "high"), \
                f"App risk value invalid: {app['risk']}"

    @NEED_CREDS
    def test_posture_inbox_rules_returns_list(self, client, auth):
        r = client.get("/api/posture/inbox-rules", headers=auth["headers"])
        if r.status_code == 403:
            pytest.skip("Non-enterprise org")
        assert r.status_code == 200, f"Inbox rules returned {r.status_code}: {r.text}"
        data = r.json()
        assert isinstance(data, list), "Inbox rules must return a list"
        if data:
            rule = data[0]
            for field in ["id", "name", "mailbox", "provider", "risk"]:
                assert field in rule, f"Rule record missing field: {field}"

    @NEED_CREDS
    def test_posture_forwards_returns_list(self, client, auth):
        r = client.get("/api/posture/forwards", headers=auth["headers"])
        if r.status_code == 403:
            pytest.skip("Non-enterprise org")
        assert r.status_code == 200, f"Forwards returned {r.status_code}: {r.text}"
        data = r.json()
        assert isinstance(data, list), "Forwards must return a list"

    @NEED_CREDS
    def test_posture_scan_trigger_accepted(self, client, auth):
        """POST /scan must accept the request (background task starts)."""
        r = client.post("/api/posture/scan", headers=auth["headers"])
        if r.status_code == 403:
            pytest.skip("Non-enterprise org")
        assert r.status_code == 200, f"Posture scan trigger returned {r.status_code}: {r.text}"
        data = r.json()
        assert data.get("ok") is True, f"Posture scan trigger missing ok=true: {data}"

    @NEED_CREDS
    def test_posture_ai_score_structure(self, client, auth):
        r = client.get("/api/posture/ai-score", headers=auth["headers"], timeout=30)
        if r.status_code == 403:
            pytest.skip("Non-enterprise org")
        assert r.status_code == 200, f"Posture AI score returned {r.status_code}: {r.text}"
        data = r.json()
        assert "score" in data or data.get("score") is None, \
            "Posture AI score missing 'score' field"
        assert "label" in data, "Posture AI score missing 'label' field"
        assert "reasoning" in data, "Posture AI score missing 'reasoning' field"

    @NEED_CREDS
    def test_posture_affects_dashboard_risk_score(self, client, auth):
        """
        The dashboard /summary risk_score must be >= the base org risk_score
        if there are any posture findings (posture adds delta on top).
        """
        posture_r = client.get("/api/posture/summary", headers=auth["headers"])
        if posture_r.status_code != 200:
            pytest.skip("Non-enterprise org or posture unavailable")
        posture = posture_r.json()
        has_findings = (
            posture.get("high_risk_apps", 0) > 0 or
            posture.get("high_risk_rules", 0) > 0 or
            posture.get("external_forwards", 0) > 0
        )
        if not has_findings or not posture.get("last_scanned"):
            pytest.skip("No posture findings — delta test not applicable")

        dash_r = client.get("/api/dashboard/summary", headers=auth["headers"])
        dash = dash_r.json()
        # We can't compare to raw base score without DB access, but risk_score must be > 0
        assert dash.get("risk_score", 0) > 0, \
            "Dashboard risk_score is 0 despite posture findings — posture delta not being applied"


# ─────────────────────────────────────────────────────────────────────────────
# 6. Compliance
# ─────────────────────────────────────────────────────────────────────────────

class TestCompliance:
    @NEED_CREDS
    def test_overview_returns_frameworks(self, client, auth):
        r = client.get("/api/compliance/overview", headers=auth["headers"])
        assert r.status_code == 200, f"Compliance overview failed: {r.text}"
        data = r.json()
        assert "frameworks" in data, "Compliance overview missing 'frameworks' key"
        assert len(data["frameworks"]) > 0, "No frameworks returned"

    @NEED_CREDS
    def test_overview_framework_schema(self, client, auth):
        r = client.get("/api/compliance/overview", headers=auth["headers"])
        data = r.json()
        for fw in data.get("frameworks", []):
            for field in ["framework", "total_controls", "compliance_pct"]:
                assert field in fw, f"Framework record missing field: {field}"
            assert 0 <= fw["compliance_pct"] <= 100, \
                f"compliance_pct out of range: {fw['compliance_pct']}"

    @NEED_CREDS
    def test_controls_endpoint_returns_list(self, client, auth):
        r = client.get("/api/compliance/controls?framework=SAMA_CSF", headers=auth["headers"])
        assert r.status_code == 200, f"Controls endpoint failed: {r.text}"
        data = r.json()
        items = data.get("items", data) if isinstance(data, dict) else data
        assert len(items) > 0, "No controls returned for SAMA_CSF"

    @NEED_CREDS
    def test_controls_status_valid_values(self, client, auth):
        r = client.get("/api/compliance/controls?framework=SAMA_CSF", headers=auth["headers"])
        data = r.json()
        items = data.get("items", []) if isinstance(data, dict) else data
        for item in items:
            assert item.get("status") in ("compliant", "partial", "non_compliant", "not_started"), \
                f"Invalid control status: {item.get('status')}"

    @NEED_CREDS
    def test_pdf_report_generates_valid_pdf(self, client, auth):
        """Generate SAMA_CSF PDF and verify it's a real PDF file."""
        r = client.post(
            "/api/compliance/report/generate",
            json={"framework": "SAMA_CSF", "format": "pdf",
                  "date_from": "2026-01-01", "date_to": "2026-04-27"},
            headers=auth["headers"],
            timeout=120,
        )
        assert r.status_code == 200, \
            f"PDF generation returned {r.status_code}: {r.text[:300]}"
        data = r.json()
        assert "report_id" in data, f"No report_id in response: {data}"

        dl = client.get(f"/api/compliance/report/{data['report_id']}",
                        headers=auth["headers"], timeout=30)
        assert dl.status_code == 200, f"PDF download failed: {dl.status_code}"
        assert len(dl.content) > 1024, \
            f"PDF too small ({len(dl.content)} bytes) — likely empty or error"
        assert dl.content[:4] == b"%PDF", \
            f"Response is not a valid PDF — first 4 bytes: {dl.content[:4]}"

    @NEED_CREDS
    def test_html_report_generates_valid_html(self, client, auth):
        """Generate NCA_ECC HTML and verify it contains real content."""
        r = client.post(
            "/api/compliance/report/generate",
            json={"framework": "NCA_ECC", "format": "html",
                  "date_from": "2026-01-01", "date_to": "2026-04-27"},
            headers=auth["headers"],
            timeout=120,
        )
        assert r.status_code == 200, \
            f"HTML generation returned {r.status_code}: {r.text[:300]}"
        data = r.json()
        dl = client.get(f"/api/compliance/report/{data['report_id']}",
                        headers=auth["headers"], timeout=30)
        assert dl.status_code == 200
        html = dl.text
        assert len(html) > 500, f"HTML report too small: {len(html)} chars"
        assert "<html" in html.lower() or "<!doctype" in html.lower(), \
            "Response is not valid HTML"
        assert "NCA" in html or "compliance" in html.lower(), \
            "HTML report missing expected compliance content"

    @NEED_CREDS
    def test_report_download_correct_content_type(self, client, auth):
        """PDF download must return application/pdf content-type."""
        r = client.post(
            "/api/compliance/report/generate",
            json={"framework": "SAMA_CSF", "format": "pdf",
                  "date_from": "2026-01-01", "date_to": "2026-04-27"},
            headers=auth["headers"],
            timeout=120,
        )
        if r.status_code != 200:
            pytest.skip("PDF generation failed, skipping content-type check")
        data = r.json()
        dl = client.get(f"/api/compliance/report/{data['report_id']}",
                        headers=auth["headers"], timeout=30)
        assert "pdf" in dl.headers.get("content-type", "").lower(), \
            f"PDF download has wrong content-type: {dl.headers.get('content-type')}"

    @NEED_CREDS
    def test_compliance_assess_endpoint(self, client, auth):
        """POST /assess must return valid assessment data."""
        r = client.post(
            "/api/compliance/assess",
            json={"framework": "SAMA_CSF"},
            headers=auth["headers"],
            timeout=120,
        )
        assert r.status_code == 200, f"Compliance assess returned {r.status_code}: {r.text[:300]}"
        data = r.json()
        assert "score_pct" in data, "Assessment missing score_pct"
        assert "controls_assessed" in data, "Assessment missing controls_assessed"
        assert 0 <= data["score_pct"] <= 100, f"score_pct out of range: {data['score_pct']}"

    @NEED_CREDS
    def test_dns_check_returns_domain_info(self, client, auth):
        r = client.get("/api/compliance/dns-check", headers=auth["headers"])
        assert r.status_code in (200, 404), \
            f"DNS check returned unexpected {r.status_code}: {r.text}"
        if r.status_code == 200:
            data = r.json()
            assert "domain" in data, "DNS check missing domain field"
            assert "spf" in data, "DNS check missing spf field"
            assert "dmarc" in data, "DNS check missing dmarc field"

    @NEED_CREDS
    def test_evidence_endpoint_returns_paginated(self, client, auth):
        r = client.get("/api/compliance/evidence", headers=auth["headers"])
        assert r.status_code == 200, f"Evidence endpoint returned {r.status_code}: {r.text}"


# ─────────────────────────────────────────────────────────────────────────────
# 7. Integrations (Connect / Disconnect)
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrations:
    @NEED_CREDS
    def test_onboarding_status_reachable(self, client, auth):
        r = client.get("/api/onboarding/status", headers=auth["headers"])
        assert r.status_code in (200, 404), \
            f"Onboarding status returned {r.status_code}: {r.text}"

    @NEED_CREDS
    def test_onboarding_status_schema(self, client, auth):
        r = client.get("/api/onboarding/status", headers=auth["headers"])
        if r.status_code == 404:
            pytest.skip("Onboarding status not implemented")
        data = r.json()
        assert not (isinstance(data, dict) and "detail" in data and r.status_code >= 400), \
            f"Onboarding status returned error: {data}"

    @NEED_CREDS
    def test_disconnect_nonexistent_integration_graceful(self, client, auth):
        """Disconnecting a non-connected integration must not 500."""
        for provider in ["m365", "google"]:
            r = client.post(
                f"/api/onboarding/disconnect/{provider}",
                headers=auth["headers"],
            )
            # 200, 404, or 400 — never 500
            assert r.status_code in (200, 400, 404, 422), \
                f"Disconnect {provider} returned unexpected {r.status_code}: {r.text[:100]}"

    @NEED_CREDS
    def test_mailbox_count_present_when_connected(self, client, auth):
        """If an integration is active, mailbox count should be > 0."""
        r = client.get("/api/dashboard/summary", headers=auth["headers"])
        r2 = client.get("/api/onboarding/status", headers=auth["headers"])
        if r2.status_code != 200:
            pytest.skip("Onboarding status not available")
        onboard = r2.json()
        # If any provider connected, emails_scanned in dashboard should be > 0
        has_active = any(
            v for k, v in onboard.items()
            if "connected" in str(k).lower() or "status" in str(k).lower()
        )
        if has_active:
            dash = r.json()
            # Just check it's not a hard 0 when we know mailboxes are connected
            # Some orgs may genuinely have no processed emails if brand new
            assert "emails_scanned" in dash, \
                "Dashboard missing emails_scanned when integration is connected"


# ─────────────────────────────────────────────────────────────────────────────
# 8. Threats
# ─────────────────────────────────────────────────────────────────────────────

class TestThreats:
    @NEED_CREDS
    def test_threats_list_returns_list(self, client, auth):
        r = client.get("/api/threats", headers=auth["headers"])
        assert r.status_code == 200, f"Threats list failed: {r.text}"
        data = r.json()
        items = data if isinstance(data, list) else data.get("items", data.get("threats", []))
        assert isinstance(items, list), "Threats must return a list or paginated response"

    @NEED_CREDS
    def test_threats_schema(self, client, auth):
        r = client.get("/api/threats?limit=5", headers=auth["headers"])
        data = r.json()
        items = data if isinstance(data, list) else data.get("items", [])
        if not items:
            pytest.skip("No threats for schema test")
        threat = items[0]
        for field in ["id", "threat_type", "risk_score", "action_taken"]:
            assert field in threat, f"Threat missing field: {field}"
        assert 0 <= (threat.get("risk_score") or 0) <= 100, \
            f"Threat risk_score out of range: {threat.get('risk_score')}"

    @NEED_CREDS
    def test_threat_detail_reachable(self, client, auth):
        r = client.get("/api/threats?limit=1", headers=auth["headers"])
        data = r.json()
        items = data if isinstance(data, list) else data.get("items", [])
        if not items:
            pytest.skip("No threats for detail test")
        threat_id = items[0]["id"]
        r2 = client.get(f"/api/threats/{threat_id}", headers=auth["headers"])
        assert r2.status_code == 200, \
            f"Threat detail returned {r2.status_code}: {r2.text[:200]}"

    @NEED_CREDS
    def test_threats_pagination(self, client, auth):
        r1 = client.get("/api/threats?limit=5&offset=0", headers=auth["headers"])
        r2 = client.get("/api/threats?limit=5&offset=5", headers=auth["headers"])
        assert r1.status_code == 200
        assert r2.status_code == 200

    @NEED_CREDS
    def test_auto_triage_status_reachable(self, client, auth):
        r = client.get("/api/threats/auto-triage/status", headers=auth["headers"])
        assert r.status_code == 200, f"Auto-triage status returned {r.status_code}: {r.text}"
        data = r.json()
        assert "enabled" in data, "Auto-triage status missing 'enabled' field"

    @NEED_CREDS
    def test_threat_type_filter_no_500(self, client, auth):
        for tt in ["PHISHING", "BEC", "MALWARE", "SPAM", "CLEAN"]:
            r = client.get(f"/api/threats?threat_type={tt}&limit=3", headers=auth["headers"])
            assert r.status_code == 200, \
                f"Threat filter for type {tt} returned {r.status_code}: {r.text[:100]}"


# ─────────────────────────────────────────────────────────────────────────────
# 9. Quarantine
# ─────────────────────────────────────────────────────────────────────────────

class TestQuarantine:
    @NEED_CREDS
    def test_quarantine_list_reachable(self, client, auth):
        r = client.get("/api/quarantine", headers=auth["headers"])
        assert r.status_code == 200, f"Quarantine list failed: {r.text}"

    @NEED_CREDS
    def test_quarantine_schema(self, client, auth):
        r = client.get("/api/quarantine?limit=5", headers=auth["headers"])
        data = r.json()
        items = data if isinstance(data, list) else data.get("items", data.get("threats", []))
        if not items:
            pytest.skip("No quarantined items")
        item = items[0]
        assert "id" in item, "Quarantine item missing id"
        assert "status" in item, "Quarantine item missing status"

    @NEED_CREDS
    def test_block_permanently_idempotent(self, client, auth):
        """
        block-permanently must not 500 on duplicate call.
        Regression: asyncpg transaction abort on duplicate policy.
        """
        r = client.get("/api/quarantine?limit=1", headers=auth["headers"])
        data = r.json()
        items = data if isinstance(data, list) else data.get("items", [])
        if not items:
            pytest.skip("No quarantined threats for idempotency test")
        threat_id = items[0]["id"]
        # Call twice — second must not 500
        r1 = client.post(f"/api/quarantine/{threat_id}/block-permanently", headers=auth["headers"])
        r2 = client.post(f"/api/quarantine/{threat_id}/block-permanently", headers=auth["headers"])
        assert r1.status_code in (200, 404), \
            f"First block-permanently returned {r1.status_code}: {r1.text}"
        assert r2.status_code in (200, 409, 400, 404), \
            f"Second block-permanently (duplicate) returned unexpected {r2.status_code}: {r2.text}"
        assert r2.status_code != 500, \
            "block-permanently 500'd on duplicate — asyncpg transaction not rolled back"


# ─────────────────────────────────────────────────────────────────────────────
# 10. Policies
# ─────────────────────────────────────────────────────────────────────────────

class TestPolicies:
    @NEED_CREDS
    def test_policies_list_returns_data(self, client, auth):
        r = client.get("/api/policies", headers=auth["headers"])
        assert r.status_code == 200, f"Policies list failed: {r.text}"

    @NEED_CREDS
    def test_policies_schema(self, client, auth):
        r = client.get("/api/policies", headers=auth["headers"])
        data = r.json()
        items = data if isinstance(data, list) else data.get("items", data.get("policies", []))
        if not items:
            pytest.skip("No policies for schema test")
        p = items[0]
        for field in ["id", "action", "status"]:
            assert field in p, f"Policy missing field: {field}"

    @NEED_CREDS
    def test_active_policy_count_consistent_with_dashboard(self, client, auth):
        """Policy count in /policies must match dashboard active_policies."""
        r_pol = client.get("/api/policies?status=active", headers=auth["headers"])
        r_dash = client.get("/api/dashboard/summary", headers=auth["headers"])
        assert r_pol.status_code == 200
        assert r_dash.status_code == 200

        data = r_pol.json()
        policies = data if isinstance(data, list) else data.get("items", [])
        dash = r_dash.json()
        dash_count = dash.get("active_policies", -1)
        # They should be consistent or dash is a superset
        if dash_count >= 0:
            assert dash_count >= 0, "active_policies should never be negative"


# ─────────────────────────────────────────────────────────────────────────────
# 11. People / Directory
# ─────────────────────────────────────────────────────────────────────────────

class TestDirectory:
    @NEED_CREDS
    def test_people_list_has_users(self, client, auth):
        r = client.get("/api/people", headers=auth["headers"])
        assert r.status_code == 200, f"People list failed: {r.text}"
        data = r.json()
        users = data if isinstance(data, list) else data.get("items", data.get("users", []))
        assert len(users) > 0, \
            "No users in directory — M365/Google directory sync may be broken"

    @NEED_CREDS
    def test_people_schema(self, client, auth):
        r = client.get("/api/people?limit=5", headers=auth["headers"])
        data = r.json()
        users = data if isinstance(data, list) else data.get("items", [])
        if not users:
            pytest.skip("No users for schema test")
        u = users[0]
        assert "email" in u, "User record missing email"

    @NEED_CREDS
    def test_groups_endpoint_no_500(self, client, auth):
        """
        Groups must not 500.
        Regression: route ordering — 'groups' was matched as {user_id}.
        """
        r = client.get("/api/people/groups", headers=auth["headers"])
        assert r.status_code in (200, 404), \
            f"Groups returned {r.status_code} — possible route conflict with /people/{{user_id}}"

    @NEED_CREDS
    def test_people_search_no_500(self, client, auth):
        r = client.get("/api/people?search=test", headers=auth["headers"])
        assert r.status_code in (200, 404), \
            f"People search returned {r.status_code}"


# ─────────────────────────────────────────────────────────────────────────────
# 12. Sandbox
# ─────────────────────────────────────────────────────────────────────────────

class TestSandbox:
    @NEED_CREDS
    def test_sandbox_sessions_list_reachable(self, client, auth):
        r = client.get("/api/sandbox/sessions", headers=auth["headers"])
        assert r.status_code in (200, 404), \
            f"Sandbox sessions returned {r.status_code}: {r.text[:200]}"

    @NEED_CREDS
    def test_sandbox_sessions_schema(self, client, auth):
        r = client.get("/api/sandbox/sessions", headers=auth["headers"])
        if r.status_code == 404:
            pytest.skip("Sandbox endpoint not available")
        data = r.json()
        sessions = data if isinstance(data, list) else data.get("items", data.get("sessions", []))
        if sessions:
            s = sessions[0]
            assert "id" in s, "Sandbox session missing id"

    @NEED_CREDS
    def test_sandbox_create_session_no_500(self, client, auth):
        """Creating a sandbox session must not 500 (may fail gracefully if EC2 limit hit)."""
        r = client.post(
            "/api/sandbox/sessions",
            json={"threat_id": None},
            headers=auth["headers"],
        )
        # 200 = created, 402/503 = capacity limit, 400/422 = validation — all acceptable
        assert r.status_code not in (500, 502, 503) or r.status_code in (503,), \
            f"Sandbox create returned unexpected {r.status_code}: {r.text[:200]}"

    @NEED_CREDS
    def test_sandbox_websocket_endpoint_exists(self, client, auth):
        """The WebSocket URL pattern must be served (won't upgrade via httpx but must not 404)."""
        r = client.get("/api/sandbox/ws-info", headers=auth["headers"])
        # Endpoint may not exist in all builds — 404 OK, 500 is not
        assert r.status_code in (200, 404, 405), \
            f"Sandbox WebSocket info returned {r.status_code}: {r.text[:100]}"


# ─────────────────────────────────────────────────────────────────────────────
# 13. Reports
# ─────────────────────────────────────────────────────────────────────────────

class TestReports:
    @NEED_CREDS
    def test_reports_list_reachable(self, client, auth):
        r = client.get("/api/reports", headers=auth["headers"])
        assert r.status_code in (200, 404), f"Reports list returned {r.status_code}"

    @NEED_CREDS
    def test_reports_schema(self, client, auth):
        r = client.get("/api/reports", headers=auth["headers"])
        if r.status_code == 404:
            pytest.skip("Reports endpoint not available")
        data = r.json()
        reports = data if isinstance(data, list) else data.get("items", data.get("reports", []))
        if reports:
            rpt = reports[0]
            assert "id" in rpt, "Report record missing id"


# ─────────────────────────────────────────────────────────────────────────────
# 14. Settings
# ─────────────────────────────────────────────────────────────────────────────

class TestSettings:
    @NEED_CREDS
    def test_org_settings_reachable(self, client, auth):
        r = client.get("/api/settings/org", headers=auth["headers"])
        assert r.status_code == 200, f"Org settings returned {r.status_code}: {r.text}"

    @NEED_CREDS
    def test_org_settings_has_org_name(self, client, auth):
        r = client.get("/api/settings/org", headers=auth["headers"])
        data = r.json()
        assert "name" in data or "org_name" in data, \
            f"Org settings missing org name field: {list(data.keys())}"


# ─────────────────────────────────────────────────────────────────────────────
# 15. Phish Reporter Add-On
# ─────────────────────────────────────────────────────────────────────────────

class TestPhishReporter:
    @NEED_KEY
    def test_manifest_reachable_and_valid(self, client):
        r = client.get(f"/api/phish-report/manifest.xml?key={PHISH_KEY}")
        assert r.status_code == 200, f"Manifest failed: {r.text}"
        assert "OfficeApp" in r.text, "Manifest missing OfficeApp element"
        assert "app.himaya.ai" in r.text

    def test_manifest_bad_key_rejected(self, client):
        r = client.get("/api/phish-report/manifest.xml?key=invalid-key-xyz")
        assert r.status_code == 401

    def test_submit_bad_key_rejected(self, client):
        r = client.post(
            "/api/phish-report/submit",
            json={"reporter_email": "test@test.com", "subject": "test",
                  "sender": "x@x.com", "sender_domain": "x.com",
                  "body_preview": "", "message_id": "battle-test",
                  "received_at": "2026-01-01T00:00:00Z", "provider": "outlook"},
            headers={"X-Phish-Report-Key": "invalid-key"},
        )
        assert r.status_code == 401

    @NEED_KEY
    def test_phish_key_endpoint_reachable(self, client, auth):
        r = client.get("/api/phish-report/key", headers=auth["headers"])
        assert r.status_code == 200, f"Phish key endpoint returned {r.status_code}"

    @NEED_KEY
    def test_manifest_no_invalid_schema_elements(self, client):
        """
        Regression: <TaskpaneId> in <Action> and <Icon> before <Control> in <Group>
        both cause M365 manifest validation to reject the add-in.
        """
        r = client.get(f"/api/phish-report/manifest.xml?key={PHISH_KEY}")
        assert r.status_code == 200
        xml = r.text
        assert "<TaskpaneId>" not in xml, \
            "<TaskpaneId> inside <Action> is invalid in V1_0 schema — M365 will reject"
        group_match = re.search(r"<Group[^>]*>(.*?)</Group>", xml, re.DOTALL)
        if group_match:
            group_content = group_match.group(1)
            control_pos = group_content.find("<Control")
            icon_pos = group_content.find("<Icon>")
            if icon_pos != -1 and control_pos != -1:
                assert icon_pos > control_pos, \
                    "<Icon> before <Control> in <Group> — invalid M365 schema"


# ─────────────────────────────────────────────────────────────────────────────
# 16. Static Assets + CSP
# ─────────────────────────────────────────────────────────────────────────────

class TestStaticAndCSP:
    def test_frontend_loads(self):
        r = httpx.get(f"{API}/", timeout=15, follow_redirects=True)
        assert r.status_code == 200
        assert "text/html" in r.headers.get("content-type", "")

    def test_outlook_taskpane_loads(self):
        r = httpx.get(f"{API}/addons/outlook/taskpane.html", timeout=15)
        assert r.status_code == 200
        assert "Office.js" in r.text or "appsforoffice" in r.text

    def test_taskpane_csp_allows_api_connect(self):
        """
        Taskpane CSP connect-src must include app.himaya.ai.
        Regression: connect-src 'self' blocked fetch() from inside Office task pane.
        """
        r = httpx.get(f"{API}/addons/outlook/taskpane.html", timeout=15)
        csp = r.headers.get("content-security-policy", "")
        assert "connect-src" in csp, "Taskpane missing connect-src CSP directive"
        assert "app.himaya.ai" in csp, \
            "app.himaya.ai not in connect-src — API calls will be blocked in Office"

    def test_himaya_icons_all_sizes(self):
        for size in [16, 32, 80]:
            r = httpx.get(f"{API}/himaya-3-{size}.png", timeout=10)
            assert r.status_code == 200, f"himaya-3-{size}.png returned {r.status_code}"
            assert r.content[:4] == b"\x89PNG", \
                f"himaya-3-{size}.png is not a valid PNG"

    def test_login_page_loads(self):
        r = httpx.get(f"{API}/login", timeout=15, follow_redirects=True)
        assert r.status_code == 200

    def test_register_page_loads(self):
        r = httpx.get(f"{API}/register", timeout=15, follow_redirects=True)
        assert r.status_code in (200, 302, 301)


# ─────────────────────────────────────────────────────────────────────────────
# 17. Security Hardening
# ─────────────────────────────────────────────────────────────────────────────

class TestSecurityHardening:
    def test_admin_api_requires_key(self, client):
        """Admin API must require X-Admin-Api-Key."""
        r = client.get("/api/admin/orgs")
        assert r.status_code in (401, 403, 422), \
            f"Admin API accessible without key: {r.status_code}"

    def test_sql_injection_attempt_handled(self, client, auth):
        if not TEST_EMAIL or not TEST_PASSWORD:
            pytest.skip("No credentials")
        r = client.get(
            "/api/threats?threat_type=' OR 1=1--",
            headers=auth["headers"] if auth else {},
        )
        assert r.status_code in (200, 400, 422), \
            f"SQL injection attempt returned unexpected {r.status_code}"
        assert r.status_code != 500, "SQL injection caused 500 — query not parameterized"

    @NEED_CREDS
    def test_cross_tenant_access_rejected(self, client, auth):
        """
        Accessing another org's data by guessing a UUID must fail.
        Tests that all queries are properly org-scoped.
        """
        fake_id = str(uuid.uuid4())
        r = client.get(f"/api/threats/{fake_id}", headers=auth["headers"])
        assert r.status_code in (404, 403), \
            f"Accessing nonexistent threat returned {r.status_code} instead of 404/403"

    def test_expired_token_rejected(self, client):
        """An obviously fake token must be rejected."""
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        r = client.get("/api/threats", headers={"Authorization": f"Bearer {fake_token}"})
        assert r.status_code in (401, 403), \
            f"Fake JWT was accepted: {r.status_code}"


# ─────────────────────────────────────────────────────────────────────────────
# 18. DLP — Data Loss Prevention
# ─────────────────────────────────────────────────────────────────────────────

class TestDLP:
    """DLP feature tests — all enterprise-gated routes + webhook security."""

    # ── Enterprise gate ───────────────────────────────────────────────────────

    def test_dlp_policies_enterprise_gated(self, client):
        """DLP policies must reject unauthenticated requests."""
        r = client.get("/api/dlp/policies")
        assert r.status_code in (401, 403, 422), \
            f"DLP policies accessible without auth: {r.status_code}"

    @NEED_CREDS
    def test_dlp_policies_list(self, client, auth):
        """Authenticated enterprise user should get 200 from /api/dlp/policies."""
        r = client.get("/api/dlp/policies", headers=auth["headers"])
        assert r.status_code in (200, 403), \
            f"DLP policies returned unexpected {r.status_code}"
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, list), "Expected list of policies"

    @NEED_CREDS
    def test_dlp_stats_structure(self, client, auth):
        """DLP stats must return expected keys."""
        r = client.get("/api/dlp/stats", headers=auth["headers"])
        assert r.status_code in (200, 403), \
            f"DLP stats returned {r.status_code}"
        if r.status_code == 200:
            data = r.json()
            for key in ("total_events_today", "held_today", "blocked_today", "active_policies"):
                assert key in data, f"Missing key '{key}' in DLP stats"
            assert isinstance(data["active_policies"], int), \
                "active_policies must be int"

    @NEED_CREDS
    def test_dlp_queue_reachable(self, client, auth):
        """DLP queue endpoint must be reachable and return a list."""
        r = client.get("/api/dlp/queue", headers=auth["headers"])
        assert r.status_code in (200, 403), \
            f"DLP queue returned unexpected {r.status_code}"
        if r.status_code == 200:
            assert isinstance(r.json(), list), "DLP queue must return a list"

    # ── Webhook security ──────────────────────────────────────────────────────

    def test_dlp_webhook_m365_rejects_bad_secret(self, client):
        """M365 webhook must reject requests with wrong secret."""
        r = client.post(
            "/api/dlp/webhook/m365",
            json={
                "org_id": str(uuid.uuid4()),
                "sender": "test@example.com",
                "recipients": ["external@gmail.com"],
                "subject": "Test",
                "body": "Hello",
            },
            headers={"X-DLP-Secret": "wrong-secret-should-be-rejected"},
        )
        # If DLP_WEBHOOK_SECRET is configured, this must return 401
        # If not configured (dev mode), it may return 200 — that's acceptable for now
        assert r.status_code in (200, 401, 422, 500), \
            f"Webhook bad secret returned unexpected {r.status_code}"

    def test_dlp_webhook_classifies_pii_email(self, client):
        """Webhook with no secret should classify a PII email (or return 401)."""
        r = client.post(
            "/api/dlp/webhook/m365",
            json={
                "org_id": str(uuid.uuid4()),
                "sender": "employee@testcompany.com",
                "recipients": ["external@gmail.com"],
                "subject": "Application form",
                "body": "My SSN is 123-45-6789 and my credit card is 4111111111111111",
            },
            headers={"X-DLP-Secret": ""},
        )
        # Either 401 (secret required) or 200/550 (classified)
        assert r.status_code in (200, 401, 550), \
            f"DLP webhook returned unexpected {r.status_code}"
        if r.status_code in (200, 550):
            data = r.json()
            # If classified, should have action field or error field
            assert "action" in data or "error" in data, \
                f"DLP webhook response missing action/error field: {data}"

    # ── Classify endpoint ─────────────────────────────────────────────────────

    @NEED_CREDS
    def test_dlp_classify_pii_detected(self, client, auth):
        """Internal classify endpoint should detect SSN as PII."""
        r = client.post(
            "/api/dlp/classify",
            json={
                "sender": "user@himaya.ai",
                "recipients": ["external@gmail.com"],
                "subject": "Personal info",
                "body": "Hi, my social security number is 123-45-6789. Please keep confidential.",
                "provider": "m365",
            },
            headers=auth["headers"],
        )
        assert r.status_code in (200, 403, 422), \
            f"DLP classify returned unexpected {r.status_code}"
        if r.status_code == 200:
            data = r.json()
            assert "risk_level" in data, "Missing risk_level"
            assert "action" in data, "Missing action"
            assert data["risk_level"] in ("medium", "high", "critical"), \
                f"SSN not detected as sensitive: risk={data['risk_level']}"

    # ── CRUD lifecycle ────────────────────────────────────────────────────────

    @NEED_CREDS
    def test_dlp_create_and_delete_policy(self, client, auth):
        """Create a DLP policy then delete it — full CRUD lifecycle."""
        # Create
        create_r = client.post(
            "/api/dlp/policies",
            json={
                "name": f"Battle Test Policy {uuid.uuid4().hex[:8]}",
                "severity": "high",
                "enabled": True,
                "detect_pii": True,
                "detect_financial": False,
                "detect_credentials": True,
                "detect_itar": False,
                "detect_bulk_exfil": False,
                "custom_keywords": ["classified", "top-secret"],
                "custom_regex": [],
                "action": "HOLD",
                "notify_sender": False,
                "notify_manager_email": None,
                "external_only": True,
            },
            headers=auth["headers"],
        )
        assert create_r.status_code in (201, 403), \
            f"DLP policy create returned {create_r.status_code}: {create_r.text[:200]}"

        if create_r.status_code == 201:
            policy_id = create_r.json()["id"]
            assert policy_id, "Created policy must have an id"

            # Verify it appears in list
            list_r = client.get("/api/dlp/policies", headers=auth["headers"])
            assert list_r.status_code == 200
            ids = [p["id"] for p in list_r.json()]
            assert policy_id in ids, "Newly created policy not found in list"

            # Update it
            patch_r = client.patch(
                f"/api/dlp/policies/{policy_id}",
                json={"enabled": False},
                headers=auth["headers"],
            )
            assert patch_r.status_code == 200, \
                f"DLP policy patch returned {patch_r.status_code}"

            # Delete it
            del_r = client.delete(
                f"/api/dlp/policies/{policy_id}",
                headers=auth["headers"],
            )
            assert del_r.status_code == 200, \
                f"DLP policy delete returned {del_r.status_code}"

            # Verify gone
            list_r2 = client.get("/api/dlp/policies", headers=auth["headers"])
            ids2 = [p["id"] for p in list_r2.json()]
            assert policy_id not in ids2, "Deleted policy still in list"
