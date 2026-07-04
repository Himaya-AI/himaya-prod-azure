"""Unit tests for backend.services.cross_region_access.

Added 2026-06-23 with the cross-region access detector. We don't hit
a database here — we test the pure helpers (`_countries_for_region`,
region map coverage, EU expansion) so the detector's regional-residency
matrix can't silently regress.
"""
from __future__ import annotations

import pytest

from backend.services.cross_region_access import (
    EU_COUNTRIES,
    REGION_TO_COUNTRIES,
    _countries_for_region,
)


def test_eu_countries_includes_known_member_states():
    for code in ("DE", "FR", "IE", "ES", "NL", "SE"):
        assert code in EU_COUNTRIES


def test_eu_countries_excludes_uk_and_ch():
    # UK left the EU; CH was never in. Both must be handled explicitly
    # by region mapping, not via EU_COUNTRIES.
    assert "GB" not in EU_COUNTRIES
    assert "CH" not in EU_COUNTRIES


def test_aws_eu_west_2_is_uk_only():
    countries = _countries_for_region("eu-west-2")
    assert countries == {"GB"}


def test_aws_eu_central_1_covers_eu_and_includes_germany():
    countries = _countries_for_region("eu-central-1")
    assert "DE" in countries
    assert countries >= EU_COUNTRIES


def test_azure_uksouth_is_uk_only():
    countries = _countries_for_region("uksouth")
    assert countries == {"GB"}


def test_azure_swiss_region_includes_ch_and_eu():
    countries = _countries_for_region("switzerlandnorth")
    assert "CH" in countries
    assert "DE" in countries  # member of the broader EU residency set


def test_gcp_asia_south1_is_india():
    assert _countries_for_region("asia-south1") == {"IN"}


def test_aws_me_central_1_is_uae():
    assert _countries_for_region("me-central-1") == {"AE"}


def test_aws_il_central_1_is_israel():
    assert _countries_for_region("il-central-1") == {"IL"}


def test_unknown_region_returns_empty_set():
    """Empty set means 'don't enforce' so we never false-positive."""
    assert _countries_for_region("on-mars-1") == set()
    assert _countries_for_region("") == set()
    assert _countries_for_region(None) == set()


def test_region_lookup_is_case_insensitive():
    assert _countries_for_region("US-EAST-1") == {"US"}
    assert _countries_for_region("WestEurope") >= EU_COUNTRIES


def test_loose_match_strips_prefix():
    """Some callers (cross-cloud joins) prefix the region with the cloud."""
    assert _countries_for_region("gcp:us-central1") == {"US"}
    assert _countries_for_region("aws:eu-west-2") == {"GB"}


def test_region_map_has_no_obvious_typos():
    # Every region key should be lowercase + only ASCII letters/digits/dashes/underscores.
    import re
    for key in REGION_TO_COUNTRIES:
        assert key == key.lower(), f"region {key!r} is not lowercase"
        assert re.match(r"^[a-z0-9_-]+$", key), f"region {key!r} has odd chars"
        countries = REGION_TO_COUNTRIES[key]
        assert isinstance(countries, set) and len(countries) > 0
        for c in countries:
            assert len(c) == 2 and c.isupper(), f"region {key} has bad country {c!r}"


def test_all_major_clouds_have_at_least_one_region():
    keys = set(REGION_TO_COUNTRIES.keys())
    # AWS
    assert any(k.startswith("us-east") or k.startswith("eu-") for k in keys)
    # GCP
    assert any(k.startswith("europe-") or k.startswith("asia-") for k in keys)
    # Azure
    assert any(k in {"eastus", "westeurope", "uksouth"} for k in keys)
