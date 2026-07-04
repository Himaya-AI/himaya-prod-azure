from app.api.schemas import EntityType, ReputationEntity
from app.core.normalizer import build_ti_cache_key, normalize_entity

def test_normalizes_url_and_removes_tracking_params():
    entity = ReputationEntity(
        type=EntityType.url,
        value="HTTPS://Example.COM/login/?utm_source=x&token=abc&fbclid=123",
    )

    normalized = normalize_entity(entity)

    assert normalized.normalized_value == "https://example.com/login?token=abc"
    assert normalized.entity_key.startswith("rep:v1:url:")
    assert normalized.related_domain == "example.com"


def test_http_and_https_urls_share_cache_key():
    http_entity = ReputationEntity(type=EntityType.url, value="http://Example.COM/path")
    https_entity = ReputationEntity(type=EntityType.url, value="https://example.com/path")

    http_normalized = normalize_entity(http_entity)
    https_normalized = normalize_entity(https_entity)

    assert http_normalized.normalized_value == https_normalized.normalized_value
    assert http_normalized.entity_key == https_normalized.entity_key


def test_sender_lookup_uses_domain_for_sources():
    entity = ReputationEntity(type=EntityType.sender, value="CEO@Fake-Bank.COM")

    normalized = normalize_entity(entity)

    assert normalized.normalized_value == "ceo@fake-bank.com"
    assert normalized.lookup_type == EntityType.domain
    assert normalized.lookup_value == "fake-bank.com"


def test_sender_ti_cache_key_reuses_domain_entry():
    sender = normalize_entity(
        ReputationEntity(type=EntityType.sender, value="user@shared-cache.test")
    )
    domain = normalize_entity(
        ReputationEntity(type=EntityType.domain, value="shared-cache.test")
    )

    assert build_ti_cache_key(sender) == build_ti_cache_key(domain)
    assert build_ti_cache_key(sender) == domain.entity_key


def test_file_hash_is_canonicalized():
    entity = ReputationEntity(type=EntityType.file, value="A" * 64)

    normalized = normalize_entity(entity)

    assert normalized.normalized_value == "a" * 64
    assert normalized.entity_key.startswith("rep:v1:file:")


def test_ip_is_canonicalized():
    entity = ReputationEntity(type=EntityType.ip, value=" 203.0.113.5 ")

    normalized = normalize_entity(entity)

    assert normalized.normalized_value == "203.0.113.5"
    assert normalized.lookup_type == EntityType.ip
    assert normalized.entity_key.startswith("rep:v1:ip:")
