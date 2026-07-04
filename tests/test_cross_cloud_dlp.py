"""
Unit tests for the cross-cloud heuristic DLP classifier.
Focuses on the pure-Python `_classify_heuristic` so we cover the
risk/category logic without a DB.
"""
from __future__ import annotations

from backend.services.cross_cloud_dlp import _classify_heuristic


def test_credentials_hit_high_risk():
    cats, risk = _classify_heuristic({
        "name": "prod-app-secret",
        "resource_type": "secret",
        "public_access": False,
        "encryption_enabled": True,
    })
    assert "credentials" in cats
    assert risk in ("high", "critical")


def test_public_pii_bucket_critical():
    cats, risk = _classify_heuristic({
        "name": "customer-data-public",
        "resource_type": "s3_bucket",
        "public_access": True,
        "encryption_enabled": False,
    })
    assert "pii" in cats
    assert risk == "critical"


def test_logs_bucket_low_risk_when_private_encrypted():
    cats, risk = _classify_heuristic({
        "name": "cloudtrail-access-logs",
        "resource_type": "s3_bucket",
        "public_access": False,
        "encryption_enabled": True,
    })
    assert "logs" in cats
    assert risk == "low"


def test_fallback_resource_type_storage():
    cats, _risk = _classify_heuristic({
        "name": "random-bucket-42",
        "resource_type": "storage_bucket",
    })
    assert cats == ["storage"]


def test_fallback_resource_type_notebook():
    cats, _risk = _classify_heuristic({
        "name": "team-notebook",
        "resource_type": "databricks_notebook",
    })
    assert cats == ["analytics"]


def test_unencrypted_pii_high_even_when_private():
    cats, risk = _classify_heuristic({
        "name": "employee-payroll-db",
        "resource_type": "rds_instance",
        "public_access": False,
        "encryption_enabled": False,
    })
    assert "pii" in cats or "financial" in cats
    assert risk == "high"


def test_marketing_static_low_risk():
    cats, risk = _classify_heuristic({
        "name": "marketing-website-static",
        "resource_type": "s3_bucket",
        "public_access": True,
        "encryption_enabled": False,
    })
    assert "public_data" in cats
    assert risk == "low"


def test_tags_contribute_to_categorisation():
    cats, _risk = _classify_heuristic({
        "name": "anonymised-bucket",
        "resource_type": "s3_bucket",
        "tags": {"DataClassification": "PII", "Owner": "hr@acme.com"},
    })
    assert "pii" in cats
