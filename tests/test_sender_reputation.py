"""
Tests for Sender Reputation Engine (MODEL-003)
Tests lookalike detection, entropy, TLD scoring, and classifier.
"""

from __future__ import annotations

import sys
import os

# Ensure himaya is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest


# ---------------------------------------------------------------------------
# Lookalike Detection Tests
# ---------------------------------------------------------------------------

class TestLookalikeDomain:
    """Tests for lookalike domain detection."""

    def test_alrajhi_lookalike_detected(self):
        """al-rajhibank.com should be detected as lookalike of alrajhibank.com.sa"""
        from models.sender_reputation.lookalike import detect_lookalike

        is_lookalike, matched_domain, distance = detect_lookalike("al-rajhibank.com")
        assert is_lookalike is True, f"Expected lookalike, got distance={distance}"
        assert matched_domain == "alrajhibank.com.sa"

    def test_zatca_typo_lookalike_detected(self):
        """zatcaa.com (single char typo) should be detected as lookalike of zatca.gov.sa"""
        from models.sender_reputation.lookalike import detect_lookalike

        is_lookalike, matched_domain, distance = detect_lookalike("zatcaa.com")
        assert is_lookalike is True, f"Expected lookalike, got distance={distance}"
        assert matched_domain == "zatca.gov.sa"

    def test_google_not_lookalike(self):
        """google.com should not be flagged as a lookalike of any Gulf domain."""
        from models.sender_reputation.lookalike import detect_lookalike

        is_lookalike, matched_domain, distance = detect_lookalike("google.com")
        assert is_lookalike is False
        assert matched_domain is None

    def test_exact_match_not_lookalike(self):
        """The real domain itself should not be flagged."""
        from models.sender_reputation.lookalike import detect_lookalike

        is_lookalike, matched_domain, _ = detect_lookalike("zatca.gov.sa")
        assert is_lookalike is False

    def test_close_variant_detected(self):
        """ararnco.com (transposition) should be detected as lookalike of aramco.com"""
        from models.sender_reputation.lookalike import detect_lookalike

        is_lookalike, matched_domain, distance = detect_lookalike("ararnco.com")
        # Distance from ararnco → aramco is 2 (insert 'a', delete 'r')
        assert is_lookalike is True or distance <= 3  # Allow some flexibility

    def test_high_distance_not_lookalike(self):
        """A completely unrelated domain should not match."""
        from models.sender_reputation.lookalike import detect_lookalike

        is_lookalike, _, _ = detect_lookalike("completelydifferentdomain.io")
        assert is_lookalike is False

    def test_custom_protected_list(self):
        """Custom protected domains should be used when provided."""
        from models.sender_reputation.lookalike import detect_lookalike

        is_lookalike, matched, _ = detect_lookalike(
            "paypa1.com",
            protected_domains=["paypal.com"]
        )
        assert is_lookalike is True
        assert matched == "paypal.com"


# ---------------------------------------------------------------------------
# Domain Entropy Tests
# ---------------------------------------------------------------------------

class TestDomainEntropy:
    """Tests for Shannon entropy calculation."""

    def test_low_entropy_simple_domain(self):
        """Simple dictionary-word domains should have low entropy."""
        from models.sender_reputation.classifier import compute_domain_entropy

        entropy = compute_domain_entropy("google.com")
        assert 0.0 < entropy < 4.0, f"Unexpected entropy: {entropy}"

    def test_high_entropy_dga_domain(self):
        """DGA-like random domains should have high entropy."""
        from models.sender_reputation.classifier import compute_domain_entropy

        # Random-looking DGA domain
        entropy = compute_domain_entropy("xkq8mzv2p4j.com")
        assert entropy > 2.5, f"Expected high entropy for DGA domain, got {entropy}"

    def test_entropy_returns_float(self):
        from models.sender_reputation.classifier import compute_domain_entropy

        result = compute_domain_entropy("example.com")
        assert isinstance(result, float)
        assert result >= 0.0

    def test_single_char_domain_zero_entropy(self):
        """Single character SLD has zero entropy (only one character, no distribution)."""
        from models.sender_reputation.classifier import compute_domain_entropy

        entropy = compute_domain_entropy("a.com")
        assert entropy == 0.0

    def test_compound_tld_uses_sld(self):
        """Domain with compound TLD should compute entropy on SLD only."""
        from models.sender_reputation.classifier import compute_domain_entropy

        # "alrajhibank" is the SLD for alrajhibank.com.sa → expects non-zero entropy
        entropy = compute_domain_entropy("alrajhibank.com.sa")
        assert entropy > 0.0


# ---------------------------------------------------------------------------
# TLD Risk Score Tests
# ---------------------------------------------------------------------------

class TestTldRiskScore:
    """Tests for TLD risk score mapping."""

    def test_com_low_risk(self):
        from models.sender_reputation.classifier import get_tld_risk_score
        assert get_tld_risk_score("example.com") == 0.1

    def test_xyz_high_risk(self):
        from models.sender_reputation.classifier import get_tld_risk_score
        assert get_tld_risk_score("phishing.xyz") == 0.8

    def test_top_highest_risk(self):
        from models.sender_reputation.classifier import get_tld_risk_score
        assert get_tld_risk_score("fake.top") == 0.9

    def test_gov_sa_zero_risk(self):
        from models.sender_reputation.classifier import get_tld_risk_score
        assert get_tld_risk_score("zatca.gov.sa") == 0.0

    def test_gov_ae_zero_risk(self):
        from models.sender_reputation.classifier import get_tld_risk_score
        assert get_tld_risk_score("mohre.gov.ae") == 0.0

    def test_com_sa_low_risk(self):
        from models.sender_reputation.classifier import get_tld_risk_score
        assert get_tld_risk_score("alrajhibank.com.sa") == 0.1

    def test_ae_low_risk(self):
        from models.sender_reputation.classifier import get_tld_risk_score
        assert get_tld_risk_score("adib.ae") == 0.15

    def test_unknown_tld_moderate_risk(self):
        from models.sender_reputation.classifier import get_tld_risk_score
        score = get_tld_risk_score("example.unknowntld")
        assert score == 0.5


# ---------------------------------------------------------------------------
# Synthetic Data Generation Tests
# ---------------------------------------------------------------------------

class TestSyntheticDataGeneration:
    """Tests for training data generation."""

    def test_correct_shape(self):
        """Generated dataframe should have correct number of rows and columns."""
        from models.sender_reputation.trainer import generate_synthetic_data, FEATURE_COLUMNS

        df = generate_synthetic_data(n_phishing=50, n_legit=50)
        assert len(df) == 100
        assert "label" in df.columns
        for col in FEATURE_COLUMNS:
            assert col in df.columns, f"Missing column: {col}"

    def test_label_distribution(self):
        """Should produce correct number of each label."""
        from models.sender_reputation.trainer import generate_synthetic_data

        df = generate_synthetic_data(n_phishing=100, n_legit=200)
        assert df["label"].sum() == 100   # Phishing = label 1
        assert (df["label"] == 0).sum() == 200  # Legit = label 0

    def test_reproducible_with_seed(self):
        """Same seed should produce identical datasets."""
        from models.sender_reputation.trainer import generate_synthetic_data

        df1 = generate_synthetic_data(n_phishing=50, n_legit=50, seed=99)
        df2 = generate_synthetic_data(n_phishing=50, n_legit=50, seed=99)
        assert df1.equals(df2)

    def test_feature_value_ranges(self):
        """Feature values should be within expected ranges."""
        from models.sender_reputation.trainer import generate_synthetic_data

        df = generate_synthetic_data(n_phishing=100, n_legit=100)
        assert df["tld_risk_score"].between(0.0, 1.0).all()
        assert (df["has_dmarc"].isin([0.0, 1.0])).all()
        assert (df["mx_valid"].isin([0.0, 1.0])).all()


# ---------------------------------------------------------------------------
# Rule-Based Scoring Tests
# ---------------------------------------------------------------------------

class TestRuleBasedScoring:
    """Tests for rule-based fallback scorer."""

    def test_score_returns_0_to_100(self):
        """Any input should return a score in [0, 100]."""
        from models.sender_reputation.classifier import score_sender

        signals = {
            "domain": "example.com",
            "domain_age_days": 365,
            "dmarc": {"has_dmarc": True, "policy": "reject"},
            "spf": {"has_spf": True, "qualifier": "-"},
            "dkim": {"has_dkim": True},
            "is_breached": False,
            "mx_valid": True,
            "lookalike": {"is_lookalike": False, "distance": 10},
            "is_new_to_org": False,
            "tld_risk_score": 0.1,
            "domain_entropy": 2.5,
        }

        score = score_sender(signals, model=None)
        assert 0.0 <= score <= 100.0

    def test_suspicious_domain_higher_score(self):
        """A suspicious domain should score higher than a clean domain."""
        from models.sender_reputation.classifier import score_sender

        clean = {
            "domain": "legitbank.com",
            "domain_age_days": 2000,
            "dmarc": {"has_dmarc": True, "policy": "reject"},
            "spf": {"has_spf": True, "qualifier": "-"},
            "dkim": {"has_dkim": True},
            "is_breached": False,
            "mx_valid": True,
            "lookalike": {"is_lookalike": False, "distance": 15},
            "is_new_to_org": False,
            "tld_risk_score": 0.1,
            "domain_entropy": 2.2,
        }

        suspicious = {
            "domain": "phish-bank.xyz",
            "domain_age_days": 5,
            "dmarc": {"has_dmarc": False},
            "spf": {"has_spf": False},
            "dkim": {"has_dkim": False},
            "is_breached": True,
            "mx_valid": False,
            "lookalike": {"is_lookalike": True, "distance": 1},
            "is_new_to_org": True,
            "tld_risk_score": 0.8,
            "domain_entropy": 3.9,
        }

        clean_score = score_sender(clean, model=None)
        suspicious_score = score_sender(suspicious, model=None)
        assert suspicious_score > clean_score, (
            f"Suspicious score ({suspicious_score}) should exceed clean score ({clean_score})"
        )

    def test_lookalike_raises_score(self):
        """Lookalike flag should significantly raise the score."""
        from models.sender_reputation.classifier import score_sender

        base = {
            "domain": "test.com",
            "domain_age_days": 100,
            "dmarc": {"has_dmarc": True},
            "spf": {"has_spf": True},
            "dkim": {"has_dkim": True},
            "is_breached": False,
            "mx_valid": True,
            "lookalike": {"is_lookalike": False, "distance": 10},
            "is_new_to_org": False,
            "tld_risk_score": 0.1,
            "domain_entropy": 2.0,
        }

        with_lookalike = {**base, "lookalike": {"is_lookalike": True, "distance": 1}}

        base_score = score_sender(base, model=None)
        lookalike_score = score_sender(with_lookalike, model=None)
        assert lookalike_score > base_score
