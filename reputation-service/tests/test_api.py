from fastapi.testclient import TestClient

from app.main import app


def test_lookup_returns_explainable_result_without_external_api_calls():
    payload = {
        "entities": [
            {
                "type": "file",
                "value": "a" * 64,
                "hash_type": "sha256",
                "context": {"filename": "invoice.xlsm"},
            }
        ]
    }

    with TestClient(app) as client:
        response = client.post("/api/v1/reputation/lookup", json=payload)

    assert response.status_code == 200
    body = response.json()
    result = body["results"][0]
    assert result["verdict"] == "suspicious"
    assert result["score"] == 20
    assert result["cache_hit"] is False
    assert result["indicators"] == ["dangerous_attachment_extension:.xlsm"]
    assert "summary" in result


def test_invalid_file_hash_returns_422():
    payload = {
        "entities": [
            {
                "type": "file",
                "value": "not-a-hash",
                "hash_type": "sha256",
            }
        ]
    }

    with TestClient(app) as client:
        response = client.post("/api/v1/reputation/lookup", json=payload)

    assert response.status_code == 422


def test_invalid_ip_returns_422():
    payload = {"entities": [{"type": "ip", "value": "not-an-ip"}]}

    with TestClient(app) as client:
        response = client.post("/api/v1/reputation/lookup", json=payload)

    assert response.status_code == 422


def test_digit_prefix_url_heuristic_scores_suspicious():
    payload = {"entities": [{"type": "url", "value": "https://1evil-domain.example/path"}]}

    with TestClient(app) as client:
        response = client.post("/api/v1/reputation/lookup", json=payload)

    assert response.status_code == 200
    result = response.json()["results"][0]
    assert "suspicious_url_digit_prefix" in result["indicators"]
    assert result["verdict"] == "suspicious"


def test_sender_context_is_reapplied_on_cached_threat_intel():
    sender = "cache-context-test@example.com"
    base_payload = {"entities": [{"type": "sender", "value": sender}]}
    auth_payload = {
        "entities": [
            {
                "type": "sender",
                "value": sender,
                "context": {"auth_results": {"spf": "fail", "dkim": "pass", "dmarc": "pass"}},
            }
        ]
    }

    with TestClient(app) as client:
        first = client.post("/api/v1/reputation/lookup", json=base_payload)
        second = client.post("/api/v1/reputation/lookup", json=auth_payload)

    assert first.status_code == 200
    assert second.status_code == 200
    first_result = first.json()["results"][0]
    second_result = second.json()["results"][0]
    assert first_result["cache_hit"] is False
    assert second_result["cache_hit"] is True
    assert "spf_fail" in second_result["indicators"]
    assert second_result["score"] > first_result["score"]


def test_domain_lookup_warms_sender_threat_intel_cache():
    domain = "shared-ti-cache.example"
    sender = f"user@{domain}"

    with TestClient(app) as client:
        domain_response = client.post(
            "/api/v1/reputation/lookup",
            json={"entities": [{"type": "domain", "value": domain}]},
        )
        sender_response = client.post(
            "/api/v1/reputation/lookup",
            json={"entities": [{"type": "sender", "value": sender}]},
        )

    assert domain_response.status_code == 200
    assert sender_response.status_code == 200
    assert domain_response.json()["results"][0]["cache_hit"] is False
    assert sender_response.json()["results"][0]["cache_hit"] is True


def test_health_lists_configured_sources():
    with TestClient(app) as client:
        response = client.get("/api/v1/reputation/health")

    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "helios-reputation-service"
    source_names = {source["name"] for source in body["sources"]}
    assert {"virustotal", "alienvault", "whois", "ioc_feeds", "dns", "urlscan", "malwarebazaar"}.issubset(source_names)

