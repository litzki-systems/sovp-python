# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

import pytest

import sovp.resolver as resolver


class _FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class _FakeRdata:
    def __init__(self, strings):
        self.strings = strings


def test_resolve_dns_pubkey_concatenates_split_txt_chunks(monkeypatch):
    """
    Regression: RFC 1035 allows a single TXT RDATA to be split across
    multiple <character-string> chunks. resolve_dns_pubkey() must
    concatenate them before matching v=SOVP1, not evaluate each chunk
    independently (which would fail to find the "k=" parameter whenever
    the split falls before it). See draft Section "DNS TXT Record Format
    and Resolution", and sovp-engine's equivalent join()-based parser.
    """
    chunks = [b"v=SOVP1; k=", b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="]
    fake_answers = [_FakeRdata(chunks)]

    monkeypatch.setattr(resolver.dns.resolver, "resolve", lambda name, rtype: fake_answers)

    key = resolver.resolve_dns_pubkey("example.com")

    assert key == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def test_validate_domain_rejects_malformed_integrity_proof_without_crashing(monkeypatch):
    """
    Regression test: a remote document with a non-dict `integrity_proof`
    (e.g. None, list, string) must fail closed (psi_core = 0), not raise
    AttributeError out of validate_domain(). See core.py's identical guard
    for verify_identity().
    """
    document = {
        "domain": "evil.example",
        "integrity_proof": None,
    }

    monkeypatch.setattr(resolver, "fetch_identity_document", lambda domain, timeout=10: document)
    monkeypatch.setattr(resolver, "resolve_dns_pubkey", lambda domain: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

    result = resolver.validate_domain("evil.example")

    assert result["psi_core"] == 0


def test_fetch_identity_document_rejects_oversized_response(monkeypatch):
    """
    draft-litzki-sovp-04 "Resource Limits for Unverified Documents": a
    verifier parses sovp-identity.json before Psi_core is known, so an
    oversized document from an unauthenticated sender must be rejected
    before it is trusted with any further processing (previously this used
    resp.json(), which has no size limit).
    """
    import json as _json

    oversized_text = _json.dumps({"pad": "x" * 70000})
    monkeypatch.setattr(
        resolver.requests, "get", lambda url, timeout, headers: _FakeResponse(200, oversized_text)
    )

    with pytest.raises(resolver.SOVPResolverError, match="resource limit"):
        resolver.fetch_identity_document("evil.example")


def test_fetch_identity_document_rejects_duplicate_keys(monkeypatch):
    monkeypatch.setattr(
        resolver.requests, "get", lambda url, timeout, headers: _FakeResponse(200, '{"a":1,"a":2}')
    )

    with pytest.raises(resolver.SOVPResolverError, match="resource limit"):
        resolver.fetch_identity_document("evil.example")


def test_fetch_identity_document_still_returns_a_well_formed_document(monkeypatch):
    import json as _json

    good_text = _json.dumps({"@context": "x", "entity": {"uid": "y"}})
    monkeypatch.setattr(
        resolver.requests, "get", lambda url, timeout, headers: _FakeResponse(200, good_text)
    )

    doc = resolver.fetch_identity_document("good.example")

    assert doc == _json.loads(good_text)
