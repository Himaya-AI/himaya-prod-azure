"""Verify the SQL CASE built by `_label_case_sql` maps the cross-cloud DLP
worker's risk_level vocabulary (low|medium|high|critical) into the
sensitivity-label vocabulary the frontend expects
(public|internal|confidential|highly_confidential).

Adnan 2026-06-22: the prior UNION coalesced metadata->>'dlp_risk_level'
straight into `classification_label`, so AWS / Databricks / GCP /
Salesforce rows surfaced as "high"/"low" — which the frontend
LABEL_BG map and "isConfidential" filter never matched, leaving them
unlabelled in Data Inventory and invisible to Sensitive Exposure.
"""
from __future__ import annotations

import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir))

from backend.routers.saas_security import _label_case_sql  # noqa: E402


def _ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def test_pass_through_canonical_label_branch_present():
    sql = _ws(_label_case_sql())
    assert (
        "WHEN metadata->>'dlp_risk_level' IN "
        "('public','internal','confidential','highly_confidential') "
        "THEN metadata->>'dlp_risk_level'"
    ) in sql


def test_critical_or_high_with_pii_becomes_highly_confidential():
    sql = _ws(_label_case_sql())
    assert "WHEN metadata->>'dlp_risk_level' IN ('critical','high')" in sql
    assert "(metadata->'dlp_categories')::jsonb ?|" in sql
    # All seven sensitive tokens included
    for tok in ("pii", "phi", "pci", "credentials", "secrets",
                "customer_data", "financial"):
        assert f"'{tok}'" in sql
    assert "THEN 'highly_confidential'" in sql


def test_medium_or_high_without_pii_becomes_confidential():
    sql = _ws(_label_case_sql())
    assert (
        "WHEN metadata->>'dlp_risk_level' IN ('critical','high','medium') "
        "THEN 'confidential'"
    ) in sql


def test_low_becomes_internal_by_default():
    sql = _ws(_label_case_sql())
    assert (
        "WHEN metadata->>'dlp_risk_level' = 'low' THEN 'internal'"
    ) in sql


def test_aws_low_with_public_access_becomes_public():
    sql = _ws(_label_case_sql(
        low_extra=("WHEN metadata->>'dlp_risk_level' = 'low' "
                   "AND public_access THEN 'public'"),
        default_extra=("WHEN public_access THEN 'public' "
                       "WHEN encryption_enabled THEN 'confidential'"),
    ))
    assert (
        "WHEN metadata->>'dlp_risk_level' = 'low' AND public_access "
        "THEN 'public'"
    ) in sql


def test_aws_unclassified_falls_back_to_public_or_encrypted():
    sql = _ws(_label_case_sql(
        low_extra=("WHEN metadata->>'dlp_risk_level' = 'low' "
                   "AND public_access THEN 'public'"),
        default_extra=("WHEN public_access THEN 'public' "
                       "WHEN encryption_enabled THEN 'confidential'"),
    ))
    assert "WHEN public_access THEN 'public'" in sql
    assert "WHEN encryption_enabled THEN 'confidential'" in sql
    assert sql.rstrip().endswith("ELSE 'internal' END")


def test_databricks_default_extra_uses_has_secrets():
    sql = _ws(_label_case_sql(default_extra="WHEN has_secrets THEN 'confidential'"))
    assert "WHEN has_secrets THEN 'confidential'" in sql
    assert sql.rstrip().endswith("ELSE 'internal' END")


def test_does_not_emit_raw_risk_level_as_label_for_high_low_medium_critical():
    """Regression guard: the bug was COALESCE(metadata->>'dlp_risk_level', ...)
    which dumped 'high'/'low'/'critical'/'medium' into the label column.
    The new CASE must never use the bare metadata->>'dlp_risk_level' as
    the THEN value for a high/medium/low/critical branch — only for the
    canonical-label pass-through branch.
    """
    sql = _ws(_label_case_sql())
    # The only branch that returns the raw value is the pass-through for
    # already-canonical labels. Make sure there's no `THEN metadata->>...`
    # after a 'critical'/'high'/'medium'/'low' guard.
    bad_patterns = [
        "IN ('critical','high','medium') THEN metadata",
        "IN ('critical','high') THEN metadata",
        "= 'low' THEN metadata",
        "= 'medium' THEN metadata",
        "= 'high' THEN metadata",
        "= 'critical' THEN metadata",
    ]
    for pat in bad_patterns:
        assert pat not in sql, f"regression: SQL contains {pat!r}"


def test_all_four_known_outputs_are_emitted():
    """Make sure every label the frontend LABEL_BG map knows about can be
    produced by at least one branch."""
    sql = _ws(_label_case_sql(
        low_extra=("WHEN metadata->>'dlp_risk_level' = 'low' "
                   "AND public_access THEN 'public'"),
        default_extra=("WHEN public_access THEN 'public' "
                       "WHEN encryption_enabled THEN 'confidential'"),
    ))
    for label in ("public", "internal", "confidential", "highly_confidential"):
        assert f"'{label}'" in sql, f"label {label!r} never produced"
