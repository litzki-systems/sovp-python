# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

import base64
from datetime import datetime, timedelta, timezone

import pytest

from sovp import core, resolver
from sovp.core import generate_identity_document, generate_keypair, sign_identity, verify_identity


def _v2_document(canonical_url="https://example.com", **extra):
    now = datetime(2026, 10, 8, 1, 0, 0, tzinfo=timezone.utc)
    document = {
        "@context": "https://litzki-systems.com/protocol/v2.0",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:draft-04-test",
            "canonical_url": canonical_url,
            "verification_method": "Ed25519",
        },
        "freshness": {
            "created": "2026-10-08T00:59:50Z",
            "nonce": "draft-04-test-nonce",
            "expiresAt": "2026-10-08T02:00:00Z",
        },
        **extra,
    }
    return document, now


def _sign_document(private_key_b64, document):
    signature = sign_identity(private_key_b64, document)
    return {
        **document,
        "integrity_proof": {
            "signature": signature,
            "public_key_ref": "dns:txt:_sovp.example.com",
        },
    }, signature


def _freeze_core(now):
    original = core.datetime

    class FrozenDatetime(original):
        @classmethod
        def now(cls, tz=None):
            return now

    core.datetime = FrozenDatetime
    return original


def test_v2_freshness_future_clock_skew_boundary():
    priv, pub = generate_keypair()
    document, _ = _v2_document()
    document["freshness"]["created"] = "2026-10-08T01:00:59Z"
    document, signature = _sign_document(priv, document)

    original = _freeze_core(datetime(2026, 10, 8, 1, 0, 0, tzinfo=timezone.utc))
    try:
        assert verify_identity(document, signature, pub) is True
    finally:
        core.datetime = original


def test_v2_freshness_future_clock_skew_exceeded():
    priv, pub = generate_keypair()
    document, _ = _v2_document()
    document["freshness"]["created"] = "2026-10-08T01:01:01Z"
    document, signature = _sign_document(priv, document)

    original = _freeze_core(datetime(2026, 10, 8, 1, 0, 0, tzinfo=timezone.utc))
    try:
        assert verify_identity(document, signature, pub) is False
    finally:
        core.datetime = original


def test_v2_freshness_expiry_clock_skew_boundary():
    priv, pub = generate_keypair()
    document, _ = _v2_document()
    document["freshness"]["created"] = "2026-10-08T00:58:50Z"
    document["freshness"]["expiresAt"] = "2026-10-08T00:59:01Z"
    document, signature = _sign_document(priv, document)

    original = _freeze_core(datetime(2026, 10, 8, 1, 0, 0, tzinfo=timezone.utc))
    try:
        assert verify_identity(document, signature, pub) is True
    finally:
        core.datetime = original


def test_v2_freshness_expiry_clock_skew_exceeded():
    priv, pub = generate_keypair()
    document, _ = _v2_document()
    document["freshness"]["expiresAt"] = "2026-10-08T00:58:59Z"
    document, signature = _sign_document(priv, document)

    original = _freeze_core(datetime(2026, 10, 8, 1, 0, 0, tzinfo=timezone.utc))
    try:
        assert verify_identity(document, signature, pub) is False
    finally:
        core.datetime = original


def test_v2_issuance_window_clock_skew_boundary():
    priv, pub = generate_keypair()
    document, _ = _v2_document()
    document["freshness"]["created"] = "2026-10-08T00:49:00Z"
    document["freshness"]["expiresAt"] = "2026-10-08T02:00:00Z"
    document, signature = _sign_document(priv, document)

    original = _freeze_core(datetime(2026, 10, 8, 1, 0, 0, tzinfo=timezone.utc))
    try:
        assert verify_identity(document, signature, pub, check_timestamp=True) is True
    finally:
        core.datetime = original


def test_v2_issuance_window_rejects_beyond_clock_skew():
    priv, pub = generate_keypair()
    document, _ = _v2_document()
    document["freshness"]["created"] = "2026-10-08T00:48:59Z"
    document["freshness"]["expiresAt"] = "2026-10-08T02:00:00Z"
    document, signature = _sign_document(priv, document)

    original = _freeze_core(datetime(2026, 10, 8, 1, 0, 0, tzinfo=timezone.utc))
    try:
        assert verify_identity(document, signature, pub, check_timestamp=True) is False
    finally:
        core.datetime = original


def test_unknown_top_level_members_are_in_signed_scope():
    priv, pub = generate_keypair()
    document = generate_identity_document(
        private_key_b64=priv,
        entity_uid="urn:sovp:signed-extension-test",
        canonical_url="https://example.com",
        nonce="signed-extension-test",
        expires_at="2026-12-31T23:59:59Z",
    )
    document["vendor_extension"] = {"mode": "example"}
    signature = sign_identity(
        priv,
        {key: value for key, value in document.items()
         if key not in ("integrity_proof", "contentAddress", "scan")},
    )
    document["integrity_proof"]["signature"] = signature

    assert verify_identity(document, signature, pub) is True

    tampered = {
        **document,
        "vendor_extension": {"mode": "tampered"},
    }
    assert verify_identity(tampered, signature, pub) is False


def test_content_address_is_outside_signed_scope():
    priv, pub = generate_keypair()
    document = generate_identity_document(
        private_key_b64=priv,
        entity_uid="urn:sovp:content-address-test",
        canonical_url="https://example.com",
        nonce="content-address-test",
        expires_at="2026-12-31T23:59:59Z",
    )
    signature = document["integrity_proof"]["signature"]

    document["contentAddress"]["digest"] = "00" * 32
    assert verify_identity(document, signature, pub) is True


def test_scan_is_outside_signed_scope():
    priv, pub = generate_keypair()
    document = generate_identity_document(
        private_key_b64=priv,
        entity_uid="urn:sovp:scan-scope-test",
        canonical_url="https://example.com",
        scan={"verdict": "CERTIFIED", "score": 92},
    )
    signature = document["integrity_proof"]["signature"]

    document["scan"]["score"] = 1
    assert verify_identity(document, signature, pub) is True


def test_host_binding_normalizes_case_and_trailing_dot():
    priv, pub = generate_keypair()
    document = generate_identity_document(
        private_key_b64=priv,
        entity_uid="urn:sovp:host-test",
        canonical_url="https://Example.COM./resource",
    )
    signature = document["integrity_proof"]["signature"]

    assert verify_identity(
        document,
        signature,
        pub,
        expected_host="EXAMPLE.com.",
    ) is True


def test_host_binding_rejects_different_host():
    priv, pub = generate_keypair()
    document = generate_identity_document(
        private_key_b64=priv,
        entity_uid="urn:sovp:host-test",
        canonical_url="https://example.com",
    )
    signature = document["integrity_proof"]["signature"]

    assert verify_identity(
        document,
        signature,
        pub,
        expected_host="attacker.example",
    ) is False


def test_public_key_reference_uses_dns_hostname_without_port():
    priv, _ = generate_keypair()
    document = generate_identity_document(
        private_key_b64=priv,
        entity_uid="urn:sovp:port-test",
        canonical_url="https://example.com:8443/path",
    )

    assert document["integrity_proof"]["public_key_ref"] == "dns:txt:_sovp.example.com"


def test_dns_parser_requires_exact_sovp1_syntax(monkeypatch):
    class FakeRdata:
        def __init__(self, value):
            self.strings = [value.encode("utf-8")]

    records = [
        FakeRdata("v=SOVP10; k=" + base64.b64encode(b"a" * 32).decode()),
        FakeRdata("v=SOVP1; k=" + base64.b64encode(b"b" * 32).decode() + "; extra=x"),
        FakeRdata("v=SOVP1; k=" + base64.b64encode(b"c" * 32).decode()),
    ]
    monkeypatch.setattr(
        resolver.dns.resolver,
        "resolve",
        lambda name, rtype: records,
    )

    keys = resolver.resolve_dns_pubkeys("example.com")
    assert keys == [base64.b64encode(b"c" * 32).decode()]


@pytest.mark.parametrize(
    "record",
    [
        "v=SOVP10; k=" + base64.b64encode(b"a" * 32).decode(),
        "v=SOVP1",
        "v=SOVP1; k=",
        "v=SOVP1; k=invalid",
        "v=SOVP1; k=" + base64.b64encode(b"a" * 31).decode(),
        "v=SOVP1; k=" + base64.b64encode(b"a" * 32).decode() + "; k=" + base64.b64encode(b"b" * 32).decode(),
    ],
)
def test_dns_parser_rejects_invalid_sovp_records(monkeypatch, record):
    class FakeRdata:
        def __init__(self, value):
            self.strings = [value.encode("utf-8")]

    monkeypatch.setattr(
        resolver.dns.resolver,
        "resolve",
        lambda name, rtype: [FakeRdata(record)],
    )

    with pytest.raises(resolver.SOVPResolverError):
        resolver.resolve_dns_pubkeys("example.com")
