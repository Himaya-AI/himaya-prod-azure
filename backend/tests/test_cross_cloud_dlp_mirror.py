"""Unit tests for the cross-cloud DLP -> dspm_findings mirror mapping.

The actual mirror writes to Postgres and is integration-tested; here we
verify the pure helpers used to drive it: the table->cloud map and the
risk->severity map. A regression in either of these would silently
hide entire connectors from the Sensitive Data Discovery panel.
"""
from __future__ import annotations

from backend.services.cross_cloud_dlp import (
    CONNECTOR_TABLES,
    _RISK_TO_SEVERITY,
    _TABLE_TO_CLOUD,
)


def test_every_connector_table_has_a_cloud_mapping():
    """If we classify a table but don't know its cloud key, the mirror
    silently drops the row. Force CONNECTOR_TABLES <-> _TABLE_TO_CLOUD
    to stay in sync."""
    classified_tables = {cfg["table"] for cfg in CONNECTOR_TABLES}
    mapped_tables = set(_TABLE_TO_CLOUD.keys())
    missing = classified_tables - mapped_tables
    assert not missing, (
        f"Tables classified by cross_cloud_dlp but not mapped to a "
        f"dspm_findings.cloud key: {missing}"
    )


def test_cloud_mapping_covers_all_competitive_connectors():
    """The 'cloud' column drives the Sensitive Data Discovery filter
    dropdown. Lose one of these and that connector disappears."""
    required = {
        "databricks", "gcp", "azure", "oracle",
        "github", "snowflake", "sap", "salesforce",
    }
    present = set(_TABLE_TO_CLOUD.values())
    missing = required - present
    assert not missing, f"Missing cloud values in _TABLE_TO_CLOUD: {missing}"


def test_risk_severity_translation_is_lossless():
    """Every heuristic-emitted risk level must map to a dspm_findings
    severity. Otherwise we'd write rows with severity=None and the
    panel would refuse to render them."""
    for risk in ("low", "medium", "high", "critical"):
        assert _RISK_TO_SEVERITY[risk] in (
            "info", "low", "medium", "high", "critical"
        )


def test_cloud_values_are_lowercase_and_url_safe():
    """The cloud value is also a URL query param. Spaces / mixed case
    break the inventory filter."""
    import re
    for cloud in _TABLE_TO_CLOUD.values():
        assert cloud == cloud.lower()
        assert re.match(r"^[a-z0-9_-]+$", cloud), f"bad cloud {cloud!r}"
