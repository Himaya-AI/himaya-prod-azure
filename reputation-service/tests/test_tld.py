from app.core.tld import TldService


def test_tld_service_extracts_email_domain_parts():
    service = TldService()

    result = service.analyze("account-security-noreply@accountprotection.microsoft.com")

    assert result.valid_format is True
    assert result.domain == "accountprotection.microsoft.com"
    assert result.root_domain == "microsoft.com"
    assert result.subdomain == "accountprotection"
    assert result.tld == "com"
    assert result.valid_tld is True
    assert result.public_domain is True


def test_tld_service_extracts_nested_subdomains():
    service = TldService()

    result = service.analyze("https://mail.security.example.co.uk/path")

    assert result.valid_format is True
    assert result.domain == "mail.security.example.co.uk"
    assert result.root_domain == "example.co.uk"
    assert result.subdomain == "mail.security"
    assert result.tld == "co.uk"
    assert result.valid_tld is True
    assert result.public_domain is True


def test_tld_service_rejects_non_host_values():
    service = TldService()

    result = service.analyze("not-a-domain")

    assert result.valid_format is False
    assert result.domain == "not-a-domain"
    assert result.root_domain is None
    assert result.subdomain is None
    assert result.tld is None
    assert result.valid_tld is False
    assert result.public_domain is False