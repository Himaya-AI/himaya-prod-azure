"""Unit tests for the pure helpers in backend.services.permission_diff.

Database-bound paths (snapshot_all / compute_diff / run_and_alert) are
covered by integration tests against a Docker Postgres in CI. Here we
test the severity matrix + rollback hint mapping so a refactor of
either can't silently regress.
"""
from __future__ import annotations

from backend.services.permission_diff import (
    SOURCES,
    SEVERITY_RULES,
    _rollback_hint,
    _severity_for,
)


def test_public_access_flip_to_true_is_critical():
    assert _severity_for("public_access", False, True) == "critical"


def test_public_access_flip_to_false_is_low():
    assert _severity_for("public_access", True, False) == "low"


def test_encryption_disabled_is_high():
    assert _severity_for("encryption_enabled", True, False) == "high"


def test_sharing_scope_private_to_public_is_critical():
    assert _severity_for("sharing_scope", "private", "public") == "critical"


def test_sharing_scope_private_to_external_is_high():
    assert _severity_for("sharing_scope", "private", "external") == "high"


def test_sharing_scope_external_to_private_is_low_tightening():
    assert _severity_for("sharing_scope", "external", "private") == "low"


def test_unknown_change_defaults_to_medium():
    assert _severity_for("color", "red", "blue") == "medium"


def test_databricks_workspace_made_public_is_critical():
    assert _severity_for("is_public", False, True) == "critical"


def test_rollback_hint_for_aws_public_access_uses_put_public_access_block():
    hint = _rollback_hint("aws_resources", "public_access", "my-bucket", True)
    assert "put-public-access-block" in hint
    assert "my-bucket" in hint


def test_rollback_hint_for_aws_encryption_uses_put_bucket_encryption():
    hint = _rollback_hint("aws_resources", "encryption_enabled", "my-bucket", False)
    assert "put-bucket-encryption" in hint
    assert "AES256" in hint


def test_rollback_hint_for_gcp_uses_gcloud_storage():
    hint = _rollback_hint("gcp_resources", "public_access", "my-gcs-bucket", True)
    assert "gcloud storage" in hint
    assert "my-gcs-bucket" in hint


def test_rollback_hint_for_azure_uses_az_storage():
    hint = _rollback_hint("azure_resources", "public_access", "myacct", True)
    assert "az storage account update" in hint
    assert "myacct" in hint


def test_rollback_hint_for_m365_mentions_sharepoint():
    hint = _rollback_hint("saas_data_items", "sharing_scope", "Plans.xlsx", "public")
    assert "SharePoint" in hint or "OneDrive" in hint


def test_rollback_hint_falls_back_to_generic_review():
    hint = _rollback_hint("unknown_table", "weird_field", "X", "Y")
    assert "Review" in hint


def test_every_watched_field_has_a_source():
    """Every watched field in SOURCES should map to a column in fields."""
    for src in SOURCES:
        for w in src["watch"]:
            assert w in src["fields"], (
                f"watch field {w!r} for {src['table']} is not in fields"
            )


def test_severity_matrix_covers_acl_loosening_directions():
    """Every loosening direction we care about should be at least HIGH."""
    must_be_high_or_critical = [
        ("public_access", False, True),
        ("is_public", False, True),
        ("encryption_enabled", True, False),
        ("sharing_scope", "private", "public"),
        ("sharing_scope", "org", "public"),
        ("sharing_scope", "org", "external"),
    ]
    for triple in must_be_high_or_critical:
        sev = SEVERITY_RULES.get(triple)
        assert sev in ("critical", "high"), (
            f"loosening {triple} should be high/critical, got {sev}"
        )
