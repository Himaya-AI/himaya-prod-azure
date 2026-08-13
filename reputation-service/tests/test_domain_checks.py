from app.core.domain_checks import (
	detect_homoglyph_domain,
	detect_punycode_domain,
	detect_tranco_rank,
)


def test_detect_punycode_domain_matches_xn_labels():
	result = detect_punycode_domain("xn--pple-43d.com")

	assert result.check == "punycode_domain"
	assert result.matched is True
	assert "punycode_domain" in result.indicators
	assert result.details["host"] == "xn--pple-43d.com"
	assert result.details["punycode_labels"] == ["xn--pple-43d"]


def test_detect_punycode_domain_no_match_for_ascii_domain():
	result = detect_punycode_domain("support.microsoft.com")

	assert result.check == "punycode_domain"
	assert result.matched is False
	assert result.indicators == []
	assert result.details["punycode_labels"] == []


def test_detect_homoglyph_domain_reports_confusable_signals():
	result = detect_homoglyph_domain("аррӏе.com")

	assert result.check == "homoglyph_domain"
	if result.details.get("dependency_missing") == "confusable_homoglyphs":
		assert result.matched is False
		assert result.indicators == []
	else:
		assert result.matched is True
		assert any(ind.startswith("homoglyph_") for ind in result.indicators)
	assert result.details["host"] == "аррӏе.com"


def test_detect_homoglyph_domain_no_match_for_plain_ascii_domain():
	result = detect_homoglyph_domain("apple.com")

	assert result.check == "homoglyph_domain"
	assert result.matched is False
	assert result.indicators == []


def test_detect_tranco_rank_matches_exact_domain():
	ranks = {"www.google.com": 14, "google.com": 1}
	result = detect_tranco_rank("www.google.com", rank_index=ranks)

	assert result.check == "tranco_rank"
	assert result.matched is True
	assert result.details["rank"] == 14
	assert result.details["matched_domain"] == "www.google.com"
	assert result.details["rank_source"] == "exact_domain"


def test_detect_tranco_rank_falls_back_to_etld_plus_one():
	ranks = {"microsoft.com": 6}
	result = detect_tranco_rank("support.microsoft.com", rank_index=ranks)

	assert result.check == "tranco_rank"
	assert result.matched is True
	assert result.details["rank"] == 6
	assert result.details["matched_domain"] == "microsoft.com"
	assert result.details["rank_source"] == "etld_plus_one"
	assert "tranco_rank_etld_fallback" in result.indicators