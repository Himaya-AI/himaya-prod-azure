"""
Unit tests for the Salesforce SALSA-inspired scanner.

We exercise the individual probe functions against an httpx
AsyncClient that we point at an httpx MockTransport, so the test
suite stays fully offline and deterministic.
"""
from __future__ import annotations

import json

import httpx
import pytest

from backend.services import salesforce_scanner as scanner


def _client_for_handler(handler):
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(
        transport=transport, base_url="https://acme.lightning.force.com",
        timeout=5,
    )


@pytest.mark.asyncio
async def test_probe_aura_root_present_when_lightning():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path in ("/aura", "/aura/auraFW"):
            return httpx.Response(200, text="while(1);/*{\"actions\":[]}*/")
        return httpx.Response(404)

    async with _client_for_handler(handler) as client:
        present, snippet = await scanner._probe_aura_root(
            client, "https://acme.lightning.force.com"
        )
    assert present is True
    assert "while" in snippet.lower()


@pytest.mark.asyncio
async def test_probe_aura_root_absent_when_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    async with _client_for_handler(handler) as client:
        present, snippet = await scanner._probe_aura_root(
            client, "https://acme.lightning.force.com"
        )
    assert present is False
    assert snippet == ""


@pytest.mark.asyncio
async def test_probe_rest_sobjects_returns_exposure_when_open():
    payload = {
        "sobjects": [
            {"name": "Account"},
            {"name": "Contact"},
            {"name": "Custom__c"},
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/services/data/v60.0/sobjects/":
            return httpx.Response(200, json=payload)
        return httpx.Response(404)

    async with _client_for_handler(handler) as client:
        exposed, names, status = await scanner._probe_rest_sobjects_anon(
            client, "https://acme.lightning.force.com"
        )
    assert exposed is True
    assert status == 200
    assert "Account" in names
    assert "Custom__c" in names


@pytest.mark.asyncio
async def test_probe_rest_sobjects_returns_no_exposure_when_401():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "auth"})

    async with _client_for_handler(handler) as client:
        exposed, names, status = await scanner._probe_rest_sobjects_anon(
            client, "https://acme.lightning.force.com"
        )
    assert exposed is False
    assert names == []
    assert status == 401


@pytest.mark.asyncio
async def test_probe_soap_partner_detects_fault_response():
    fault_xml = (
        '<?xml version="1.0"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soapenv:Body><soapenv:Fault>'
        '<faultcode>soapenv:Client</faultcode>'
        '<faultstring>No SOAPAction header</faultstring>'
        '</soapenv:Fault></soapenv:Body></soapenv:Envelope>'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/services/Soap/c/60.0":
            return httpx.Response(500, text=fault_xml,
                                  headers={"Content-Type": "text/xml"})
        return httpx.Response(404)

    async with _client_for_handler(handler) as client:
        reachable = await scanner._probe_soap_partner(
            client, "https://acme.lightning.force.com"
        )
    assert reachable is True


@pytest.mark.asyncio
async def test_probe_soap_partner_negative_when_404():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    async with _client_for_handler(handler) as client:
        reachable = await scanner._probe_soap_partner(
            client, "https://acme.lightning.force.com"
        )
    assert reachable is False


@pytest.mark.asyncio
async def test_probe_aura_sobject_detects_guest_read():
    record_body = '{"records":[{"Id":"001000000ABCDEF"}]}'

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/aura":
            return httpx.Response(200, text=record_body,
                                  headers={"Content-Type": "application/json"})
        return httpx.Response(404)

    async with _client_for_handler(handler) as client:
        ok, sample = await scanner._probe_aura_sobject(
            client, "https://acme.lightning.force.com", "Account"
        )
    assert ok is True
    assert sample == "001000000ABCDEF"


@pytest.mark.asyncio
async def test_probe_aura_sobject_no_match_when_no_id_pattern():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/aura":
            return httpx.Response(200, text="<html>access denied</html>")
        return httpx.Response(404)

    async with _client_for_handler(handler) as client:
        ok, sample = await scanner._probe_aura_sobject(
            client, "https://acme.lightning.force.com", "Account"
        )
    assert ok is False
    assert sample is None


def test_short_truncates_payload():
    assert scanner._short("hello", 10) == "hello"
    assert scanner._short("x" * 1000, 5).startswith("xxxxx")
    assert scanner._short(None) == ""
