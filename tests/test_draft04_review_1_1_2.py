# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for the Draft 04 conformance review of release 1.1.1.

Each test names the draft-litzki-sovp-04 rule it checks. Every case passed
verification in 1.1.1 and is rejected from 1.1.2 on.
"""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

import sovp.resolver as resolver
from sovp import core
from sovp.core import (
    DRAFT_OUTCOMES,
    generate_keypair,
    sign_identity,
    verify_identity_detail,
)
from sovp.document_safety import (
    UnverifiedDocumentLimitError,
    parse_unverified_sovp_document,
)

HOST = "example.org"


def _ts(delta_seconds=0):
    return (
        datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")


def _document(**overrides):
    document = {
        "@context": "https://litzki-systems.com/protocol/v2.0",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:review-1-1-2",
            "canonical_url": f"https://{HOST}",
            "verification_method": "Ed25519",
        },
        "freshness": {"created": _ts(-10), "expiresAt": _ts(86400)},
    }
    document.update(overrides)
    return document


def _signed(priv, document):
    signature = sign_identity(priv, document)
    return {**document, "integrity_proof": {"signature": signature}}, signature


def _verify(document, **kwargs):
    priv, pub = generate_keypair()
    signed, signature = _signed(priv, document)
    return verify_identity_detail(signed, signature, pub, expected_host=HOST, **kwargs)


def test_baseline_document_verifies():
    assert _verify(_document()) == (True, "ok")


# Section 6.2 step 1: unsupported @context, @type or verification_method.

@pytest.mark.parametrize(
    "overrides",
    [
        {"@type": "Something"},
        {"@context": "https://evil.example/v9"},
        {"@context": "https://litzki-systems.com/protocol/v2.0/extra"},
    ],
)
def test_unsupported_schema_members_are_document_invalid(overrides):
    assert _verify(_document(**overrides)) == (False, "document_invalid")


def test_missing_context_is_document_invalid():
    document = _document()
    del document["@context"]
    assert _verify(document) == (False, "document_invalid")


def test_unsupported_verification_method_is_document_invalid():
    document = _document()
    document["entity"]["verification_method"] = "RSA"
    assert _verify(document) == (False, "document_invalid")


def test_v1_4_documents_remain_supported():
    """Section 9.4: a verifier MAY keep supporting earlier schema versions."""
    document = _document(**{"@context": "https://litzki-systems.com/protocol/v1.4"})
    del document["freshness"]
    assert _verify(document) == (True, "ok")


# Sections 5 and 9.4 item 1: UTC with a literal Z, no fractional seconds.

@pytest.mark.parametrize(
    "created",
    [
        "2026-10-23T12:00:00+00:00",
        "2026-10-23T14:00:00+02:00",
        "2026-10-23T12:00:00.123Z",
        "2026-10-23 12:00:00Z",
        "2026-10-23",
    ],
)
def test_freshness_timestamps_must_be_strict_utc(created):
    document = _document(freshness={"created": created, "expiresAt": _ts(86400)})
    ok, reason = _verify(document)
    assert ok is False
    assert DRAFT_OUTCOMES[reason] == "document_invalid"


# Section 9.4 item 4: no allowance after expiresAt.

def test_document_expired_thirty_seconds_ago_is_stale():
    document = _document(freshness={"created": _ts(-3600), "expiresAt": _ts(-30)})
    assert _verify(document) == (False, "expired")


# Section 9.4 item 3: now - W <= created, without clock skew on the past side.

def test_issuance_window_has_no_skew_on_the_past_side():
    document = _document(freshness={"created": _ts(-630), "expiresAt": _ts(86400)})
    assert _verify(document, check_timestamp=True) == (False, "issuance_window")


# Section 5: signature is standard Base64 of exactly 64 octets.

@pytest.mark.parametrize("suffix", ["!!", "\n", " "])
def test_signature_with_extra_characters_is_rejected(suffix):
    priv, pub = generate_keypair()
    signed, signature = _signed(priv, _document())
    assert verify_identity_detail(signed, signature + suffix, pub, expected_host=HOST) == (
        False,
        "signature",
    )


def test_signature_in_base64url_is_rejected():
    priv, pub = generate_keypair()
    signed, signature = _signed(priv, _document())
    url_safe = base64.urlsafe_b64encode(base64.b64decode(signature)).decode().rstrip("=")
    assert verify_identity_detail(signed, url_safe, pub, expected_host=HOST)[0] is False


# Section 6.2: fixed order. Host binding (step 3) comes before key resolution
# (step 4), so a wrong host is reported even when DNS has no key.

def test_host_mismatch_is_reported_before_dns_is_queried(monkeypatch):
    priv, _pub = generate_keypair()
    document = _document()
    document["entity"]["canonical_url"] = "https://other.example"
    signed, _ = _signed(priv, document)
    monkeypatch.setattr(resolver, "fetch_identity_document", lambda domain, timeout=10: signed)

    def no_dns(*args, **kwargs):
        raise AssertionError("DNS must not be queried after a host mismatch")

    monkeypatch.setattr(resolver, "resolve_dns_pubkeys", no_dns)
    result = resolver.validate_domain(HOST)
    assert (result["psi_core"], result["reason"], result["outcome"]) == (
        0,
        "host_mismatch",
        "host_mismatch",
    )


def test_unsupported_type_is_reported_before_dns_is_queried(monkeypatch):
    priv, _pub = generate_keypair()
    signed, _ = _signed(priv, _document(**{"@type": "Something"}))
    monkeypatch.setattr(resolver, "fetch_identity_document", lambda domain, timeout=10: signed)
    monkeypatch.setattr(resolver, "resolve_dns_pubkeys", lambda *a, **k: pytest.fail("DNS queried"))
    result = resolver.validate_domain(HOST)
    assert result["outcome"] == "document_invalid"


# Section 6.2: a document retrieved from an IP literal is never verified.

@pytest.mark.parametrize("host", ["93.184.216.34", "2001:db8::1", "[2001:db8::1]", "127.0.0.1"])
def test_ip_literals_are_refused_before_any_retrieval(monkeypatch, host):
    monkeypatch.setattr(resolver.requests, "get", lambda *a, **k: pytest.fail("network used"))
    with pytest.raises(resolver.SOVPResolverError):
        resolver.validate_domain(host)


@pytest.mark.parametrize("host", ["example.org:8443", "https://example.org", "example.org/path", ""])
def test_hosts_with_port_scheme_or_path_are_refused(host):
    with pytest.raises(resolver.SOVPResolverError):
        resolver.normalize_retrieval_host(host)


def test_retrieval_host_is_normalized():
    assert resolver.normalize_retrieval_host("Example.ORG.") == "example.org"


# Section 6.2 step 1: a document that is not a JSON object is document_invalid.

class _Response:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self.content = body.encode("utf-8") if isinstance(body, str) else body

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        pass


@pytest.mark.parametrize("body", ["[1, 2, 3]", '"text"', "42", "null"])
def test_non_object_documents_are_rejected(monkeypatch, body):
    monkeypatch.setattr(resolver.requests, "get", lambda url, **kw: _Response(200, body))
    with pytest.raises(resolver.SOVPResolverError, match="not a JSON object"):
        resolver.fetch_identity_document(HOST)


def test_non_utf8_documents_are_rejected(monkeypatch):
    monkeypatch.setattr(resolver.requests, "get", lambda url, **kw: _Response(200, b'{"a": "\xff"}'))
    with pytest.raises(resolver.SOVPResolverError, match="UTF-8"):
        resolver.fetch_identity_document(HOST)


# Section 9.9: redirects are not followed.

def test_redirects_are_not_followed(monkeypatch):
    seen = []

    def fake_get(url, **kwargs):
        seen.append(kwargs.get("allow_redirects"))
        return _Response(302, "")

    monkeypatch.setattr(resolver.requests, "get", fake_get)
    with pytest.raises(resolver.SOVPResolverError, match="HTTP 302"):
        resolver.fetch_identity_document(HOST)
    assert seen == [False]


# Section 9.8: the size limit applies before the whole body is read.

def test_oversized_body_is_rejected_while_reading(monkeypatch):
    body = json.dumps({"pad": "x" * 70000})
    monkeypatch.setattr(resolver.requests, "get", lambda url, **kw: _Response(200, body))
    with pytest.raises(resolver.SOVPResolverError, match="resource limit"):
        resolver.fetch_identity_document(HOST)


# Section 9.8: malformed input is a clean limit error, never a crash.

@pytest.mark.parametrize(
    "text",
    ['{"a": -}', '{"a": 01}', '{"a": 1.}', '{"a": .5}', '{"a": 1e}', '{"a": "\\x"}', '{"a": "\\u12"}'],
)
def test_malformed_json_is_a_limit_error(text):
    with pytest.raises(UnverifiedDocumentLimitError):
        parse_unverified_sovp_document(text)


def test_valid_numbers_still_parse():
    assert parse_unverified_sovp_document('{"a": -0.5e+3, "b": 0, "c": 10}') == {
        "a": -500.0,
        "b": 0,
        "c": 10,
    }


# DNS: a TXT record that is not UTF-8 is ignored, not a crash.

def test_non_utf8_txt_record_is_ignored(monkeypatch):
    _priv, pub = generate_keypair()

    class _Rdata:
        def __init__(self, strings):
            self.strings = strings

    answers = [_Rdata([b"\xff\xfe"]), _Rdata([f"v=SOVP1; k={pub}".encode()])]
    monkeypatch.setattr(resolver.dns.resolver, "resolve", lambda name, rtype: answers)
    assert resolver.resolve_dns_pubkeys(HOST) == [pub]


# Table 3: every reason code maps to a draft outcome name.

def test_every_reason_has_a_draft_outcome():
    reasons = {v for k, v in vars(core).items() if k.startswith("REASON_")}
    assert reasons == set(DRAFT_OUTCOMES)
    assert set(DRAFT_OUTCOMES.values()) <= {
        "verified",
        "document_invalid",
        "host_mismatch",
        "key_unresolved",
        "invalid_signature",
        "stale",
    }
