from app.api.schemas import EntityType
from app.config.settings import load_settings
from app.sources.registry import load_source_registry


def test_registry_filters_unconfigured_api_sources(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("ALIENVAULT_OTX_API_KEY", raising=False)

    registry = load_source_registry(load_settings())

    file_sources = registry.for_entity(EntityType.file)
    ip_sources = registry.for_entity(EntityType.ip)
    url_sources = registry.for_entity(EntityType.url)

    assert file_sources == []
    assert any(source.name == "ioc_feeds" for source in ip_sources)
    assert any(source.name == "ioc_feeds" for source in url_sources)
    assert any(source.name == "dns" for source in registry.for_entity(EntityType.domain))
    assert all(source.name != "virustotal" for source in registry.for_entity(EntityType.domain))
    assert all(source.name != "alienvault" for source in registry.for_entity(EntityType.domain))
