"""Regression tests for Reply-To organizational-domain handling.

Production incident: legitimate ESP bulk mail was scored content=100 / SPAM
because the Reply-To check compared full hostnames as strings, so
updates.linear.app -> linear.app looked like a cross-domain mismatch.
"""
import pytest

from backend.services.email_processor import (
    _registrable_domain,
    _same_organizational_domain,
)


@pytest.mark.parametrize("host,expected", [
    ("linear.app",           "linear.app"),
    ("updates.linear.app",   "linear.app"),
    ("engage.canva.com",     "canva.com"),
    ("mail.hiive.com",       "hiive.com"),
    ("a.b.c.example.com",    "example.com"),
    ("example.co.uk",        "example.co.uk"),
    ("mail.example.co.uk",   "example.co.uk"),
    ("deep.mail.example.co.uk", "example.co.uk"),
    ("bank.com.sa",          "bank.com.sa"),
    ("mail.bank.com.sa",     "bank.com.sa"),
    ("localhost",            "localhost"),
    ("",                     ""),
    ("EXAMPLE.COM.",         "example.com"),
])
def test_registrable_domain(host, expected):
    assert _registrable_domain(host) == expected


@pytest.mark.parametrize("sender,reply_to", [
    ("updates.linear.app", "linear.app"),
    ("engage.canva.com",   "canva.com"),
    ("mail.hiive.com",     "hiive.com"),
    ("mail.example.co.uk", "example.co.uk"),
    ("a.example.com",      "b.example.com"),
])
def test_same_org_suppresses_mismatch(sender, reply_to):
    """The exact false positives seen in production must be same-org."""
    assert _same_organizational_domain(sender, reply_to) is True


@pytest.mark.parametrize("sender,reply_to", [
    ("acme.com",            "gmail.com"),
    ("acme.com",            "acme-payments.com"),
    ("acme.com",            "acme.co"),
    ("microsoft.com",       "micros0ft.com"),
    ("example.co.uk",       "example2.co.uk"),
    ("bank.com.sa",         "bank.com"),
])
def test_cross_org_still_flagged(sender, reply_to):
    """Genuine BEC / lookalike reply-to must still count as a mismatch."""
    assert _same_organizational_domain(sender, reply_to) is False


def test_public_suffix_alone_is_not_shared_org():
    """Two unrelated domains under the same multi-part suffix must not match."""
    assert _same_organizational_domain("alpha.co.uk", "beta.co.uk") is False
    assert _same_organizational_domain("a.com.sa", "b.com.sa") is False


def test_lookalike_regex_ignores_plain_net_and_org():
    """.net/.org are ordinary TLDs and must not earn a lookalike penalty,
    while .co (typo of .com) and digit/hyphen runs still do."""
    import re

    from backend.services import email_processor as ep
    src = ep.__file__
    with open(src, encoding="utf-8") as fh:
        assert r"|\.net$|\.org$" not in fh.read()

    pattern = r'[0-9]{2,}|[-_]{2,}|\.co$'
    assert re.search(pattern, "charity.org") is None
    assert re.search(pattern, "provider.net") is None
    assert re.search(pattern, "acme.co") is not None
    assert re.search(pattern, "acme12.com") is not None
    assert re.search(pattern, "acme--pay.com") is not None
