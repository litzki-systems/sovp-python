# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

import sovp.resolver as resolver


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
