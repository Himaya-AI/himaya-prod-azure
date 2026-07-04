"""Smoke tests for the rev 374 toxic rules:
- sharepoint_anyone_link_sensitive (M365 confidential file shared externally)
- external_owner_confidential (M365 file owned by outsider)
- stale_sensitive_data (sensitive file untouched 365d+)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.services import toxic_combinations as tc


class _FakeMappings:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return _FakeMappings(self._rows)


class _StubDB:
    """Routes execute() responses based on substring match in the SQL."""

    def __init__(self, plan):
        # plan: list of (sql_substring, rows). First match wins.
        self.plan = plan
        self.executed: list[str] = []

    async def execute(self, stmt, params=None):
        sql = str(stmt)
        self.executed.append(sql)
        for needle, rows in self.plan:
            if needle in sql:
                return _FakeResult(rows)
        return _FakeResult([])


def test_new_rules_registered():
    rule_ids = {r.rule_id for r, _ in tc.RULES}
    for rid in (
        "sharepoint_anyone_link_sensitive",
        "external_owner_confidential",
        "stale_sensitive_data",
    ):
        assert rid in rule_ids, f"missing rule {rid!r}"


@pytest.mark.asyncio
async def test_sharepoint_anyone_link_rule_emits_critical_for_highly_confidential():
    db = _StubDB([
        ("FROM saas_data_items", [
            {
                "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "provider": "sharepoint",
                "item_id": "doc-1",
                "item_name": "Q1_Payroll_Confidential.xlsx",
                "item_url": "https://contoso.sharepoint.com/Doc.xlsx",
                "owner_email": "hr@contoso.com",
                "classification_label": "highly_confidential",
                "classification_categories": ["pii", "financial"],
                "sharing_scope": "public",
                "last_modified_at": datetime.now(timezone.utc),
            }
        ]),
    ])
    matches = await tc._rule_sharepoint_anyone_link_sensitive(
        "00000000-0000-0000-0000-000000000000", db
    )
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "sharepoint_anyone_link_sensitive"
    assert m.severity == "critical"
    assert "Payroll" in m.title
    assert "Anyone with the link" in m.description
    assert any("Categories: pii" in f for f in m.factors)
    assert m.resources[0]["provider"] == "sharepoint"


@pytest.mark.asyncio
async def test_sharepoint_external_scope_is_high_not_critical():
    db = _StubDB([
        ("FROM saas_data_items", [
            {
                "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "provider": "onedrive",
                "item_id": "doc-2",
                "item_name": "Customer_PII.csv",
                "item_url": "https://contoso-my.sharepoint.com/x.csv",
                "owner_email": "sales@contoso.com",
                "classification_label": "confidential",
                "classification_categories": ["pii"],
                "sharing_scope": "external",
                "last_modified_at": datetime.now(timezone.utc),
            }
        ]),
    ])
    matches = await tc._rule_sharepoint_anyone_link_sensitive(
        "00000000-0000-0000-0000-000000000000", db
    )
    assert len(matches) == 1
    assert matches[0].severity == "high"
    assert "External user(s)" in matches[0].description


@pytest.mark.asyncio
async def test_stale_sensitive_data_rule_reports_days_stale():
    sixteen_months_ago = datetime.now(timezone.utc) - timedelta(days=500)
    db = _StubDB([
        ("FROM saas_data_items", [
            {
                "id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
                "provider": "sharepoint",
                "item_name": "Old_Contracts_2024.zip",
                "item_url": None,
                "owner_email": "legal@contoso.com",
                "classification_label": "highly_confidential",
                "classification_categories": ["pii", "financial"],
                "last_modified_at": sixteen_months_ago,
                "days_stale": 500.0,
            }
        ]),
    ])
    matches = await tc._rule_stale_sensitive_data(
        "00000000-0000-0000-0000-000000000000", db
    )
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "stale_sensitive_data"
    assert m.severity == "high"  # highly_confidential bumps to high
    assert "500d untouched" in m.title
    assert "500 days" in m.description
    assert any("Days since modified: 500" in f for f in m.factors)


@pytest.mark.asyncio
async def test_stale_sensitive_data_confidential_is_medium():
    db = _StubDB([
        ("FROM saas_data_items", [
            {
                "id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
                "provider": "teams",
                "item_name": "OldPlan.docx",
                "item_url": None,
                "owner_email": "owner@contoso.com",
                "classification_label": "confidential",
                "classification_categories": ["financial"],
                "last_modified_at": datetime.now(timezone.utc) - timedelta(days=400),
                "days_stale": 400.0,
            }
        ]),
    ])
    matches = await tc._rule_stale_sensitive_data(
        "00000000-0000-0000-0000-000000000000", db
    )
    assert matches[0].severity == "medium"


@pytest.mark.asyncio
async def test_external_owner_confidential_skips_when_no_domains():
    # When the org has no users, we can't decide what "external" means;
    # rule must safely return [].
    db = _StubDB([
        ("FROM users", []),
        ("FROM saas_data_items", [
            {  # This row should never be reached
                "id": "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
                "provider": "sharepoint",
                "item_name": "X",
                "item_url": None,
                "owner_email": "stranger@evil.com",
                "classification_label": "highly_confidential",
                "classification_categories": ["pii"],
                "sharing_scope": "org",
                "last_modified_at": datetime.now(timezone.utc),
            }
        ]),
    ])
    matches = await tc._rule_external_owner_confidential(
        "00000000-0000-0000-0000-000000000000", db
    )
    assert matches == []


@pytest.mark.asyncio
async def test_external_owner_confidential_emits_when_owner_outside_domain():
    db = _StubDB([
        ("FROM users", [{"d": "contoso.com"}]),
        ("FROM saas_data_items", [
            {
                "id": "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "provider": "sharepoint",
                "item_name": "Sensitive_Deal_Memo.docx",
                "item_url": "https://contoso.sharepoint.com/x.docx",
                "owner_email": "guest@partner.com",
                "classification_label": "highly_confidential",
                "classification_categories": ["financial", "customer_data"],
                "sharing_scope": "org",
                "last_modified_at": datetime.now(timezone.utc),
            }
        ]),
    ])
    matches = await tc._rule_external_owner_confidential(
        "00000000-0000-0000-0000-000000000000", db
    )
    assert len(matches) == 1
    m = matches[0]
    assert m.severity == "critical"
    assert "guest@partner.com" in m.description
    assert any("guest@partner.com" in f for f in m.factors)


@pytest.mark.asyncio
async def test_anyone_link_rule_returns_empty_when_no_matches():
    db = _StubDB([
        ("FROM saas_data_items", []),
    ])
    matches = await tc._rule_sharepoint_anyone_link_sensitive(
        "00000000-0000-0000-0000-000000000000", db
    )
    assert matches == []


@pytest.mark.asyncio
async def test_fingerprints_are_stable_across_calls():
    """Re-running the same rule on the same data must produce identical
    fingerprints so the upsert is idempotent.
    """
    rows = [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "provider": "sharepoint",
            "item_id": "doc-1",
            "item_name": "X.docx",
            "item_url": None,
            "owner_email": "a@b.com",
            "classification_label": "confidential",
            "classification_categories": ["pii"],
            "sharing_scope": "public",
            "last_modified_at": datetime.now(timezone.utc),
        }
    ]
    db1 = _StubDB([("FROM saas_data_items", rows)])
    db2 = _StubDB([("FROM saas_data_items", rows)])
    m1 = await tc._rule_sharepoint_anyone_link_sensitive("o", db1)
    m2 = await tc._rule_sharepoint_anyone_link_sensitive("o", db2)
    assert m1[0].fingerprint == m2[0].fingerprint
