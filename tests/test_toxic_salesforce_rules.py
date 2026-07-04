"""
Smoke tests for the Salesforce toxic-combination rules.

Exercises the rule registration shape and the per-rule SQL signature
without spinning up a real Postgres instance. We use a stub that
records executed SQL and returns canned MappingResults so we can
assert the rule emits the right ToxicMatch shape.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

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
    def __init__(self, rows_by_table):
        self._rows_by_table = rows_by_table
        self.executed: list[str] = []

    async def execute(self, stmt, params=None):
        sql = str(stmt)
        self.executed.append(sql)
        if "salesforce_objects" in sql:
            return _FakeResult(self._rows_by_table.get("salesforce_objects", []))
        if "salesforce_findings" in sql:
            return _FakeResult(self._rows_by_table.get("salesforce_findings", []))
        return _FakeResult([])


def test_salesforce_rules_registered():
    sf_rule_ids = {
        r.rule_id for r, _ in tc.RULES if r.rule_id.startswith("salesforce_")
    }
    assert sf_rule_ids == {
        "salesforce_guest_custom_object",
        "salesforce_guest_pii_object",
        "salesforce_api_anonymous_enum",
    }


@pytest.mark.asyncio
async def test_guest_custom_object_rule_emits_critical_match():
    db = _StubDB({
        "salesforce_objects": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "sobject_name": "Customer_Wallet__c",
                "sample_record_id": "a0B5g0000012345",
                "discovered_at": None,
                "connection_id": "22222222-2222-2222-2222-222222222222",
            }
        ]
    })
    matches = await tc._rule_salesforce_guest_custom_object("00000000-0000-0000-0000-000000000000", db)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "salesforce_guest_custom_object"
    assert m.severity == "critical"
    assert "Customer_Wallet__c" in m.title
    assert any("Custom object" in f for f in m.factors)
    assert m.primary_keys and m.primary_keys[0].startswith("sfdc:")


@pytest.mark.asyncio
async def test_guest_pii_object_rule_emits_critical_match_for_user_sobject():
    db = _StubDB({
        "salesforce_objects": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "sobject_name": "User",
                "sample_record_id": "0055g0000012345",
                "connection_id": "22222222-2222-2222-2222-222222222222",
            }
        ]
    })
    matches = await tc._rule_salesforce_guest_pii_object("00000000-0000-0000-0000-000000000000", db)
    assert len(matches) == 1
    m = matches[0]
    assert m.severity == "critical"
    assert "User" in m.title


@pytest.mark.asyncio
async def test_api_anonymous_enum_rule_inherits_severity():
    db = _StubDB({
        "salesforce_findings": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "finding_id": "sf-api-001-abc",
                "severity": "critical",
                "title": "Anonymous REST sObjects enumeration possible",
                "description": "GET /services/data/v60.0/sobjects returned 200.",
                "connection_id": "22222222-2222-2222-2222-222222222222",
                "metadata": {},
                "sobject_name": None,
            }
        ]
    })
    matches = await tc._rule_salesforce_api_anonymous_enum("00000000-0000-0000-0000-000000000000", db)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "salesforce_api_anonymous_enum"
    assert m.severity == "critical"
    assert "Anonymous" in m.title


@pytest.mark.asyncio
async def test_rules_return_empty_when_table_missing():
    class _ErrorDB:
        async def execute(self, *args, **kwargs):
            raise RuntimeError("relation does not exist")

    db = _ErrorDB()
    for fn in (
        tc._rule_salesforce_guest_custom_object,
        tc._rule_salesforce_guest_pii_object,
        tc._rule_salesforce_api_anonymous_enum,
    ):
        out = await fn("00000000-0000-0000-0000-000000000000", db)
        assert out == []
