# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

import sovp.resolver as resolver


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
