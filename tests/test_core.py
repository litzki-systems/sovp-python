# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

import pytest
from datetime import datetime, timezone, timedelta
from sovp.core import generate_keypair, sign_identity, verify_identity, generate_identity_document


def test_keypair_generation():
    """
    Tests Ed25519 keypair generation.
    Ensures both private and public keys are returned as base64 encoded strings.
    """
    priv, pub = generate_keypair()
    assert priv is not None
    assert pub is not None
    assert isinstance(priv, str)
    assert isinstance(pub, str)


def test_sign_and_verify_identity():
    """
    Validates the core resonance proof (Psi_core).
    Tests successful verification (Psi_core = 1) and tamper resistance (Psi_core = 0).
    Uses the nested entity structure from draft Section 4.
    """
    priv, pub = generate_keypair()

    # Payload conforming to draft Section 4 schema (non-proof fields only)
    identity_metadata = {
        "@context": "https://litzki-systems.com/protocol/v1.4",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:test-vector-01",
            "canonical_url": "https://test.litzki-systems.com",
            "verification_method": "Ed25519"
        }
    }

    signature = sign_identity(priv, identity_metadata)
    assert signature is not None

    # Positive test: Psi_core = 1
    is_valid = verify_identity(identity_metadata, signature, pub)
    assert is_valid is True

    # Negative test: tampered canonical_url → Psi_core = 0
    tampered_metadata = {
        "@context": "https://litzki-systems.com/protocol/v1.4",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:test-vector-01",
            "canonical_url": "https://malicious-actor.org",
            "verification_method": "Ed25519"
        }
    }
    is_invalid = verify_identity(tampered_metadata, signature, pub)
    assert is_invalid is False


def test_integrity_proof_excluded_from_signing():
    """
    Verifies that integrity_proof is stripped from the signed scope per draft Section 4 MUST:
    "Implementations MUST canonicalize only the non-proof fields of M."

    Passing the full document (with integrity_proof) to sign_identity or
    verify_identity must produce the same result as passing only the non-proof fields.
    """
    priv, pub = generate_keypair()

    non_proof_fields = {
        "@context": "https://litzki-systems.com/protocol/v1.4",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:test-exclusion-01",
            "canonical_url": "https://test.litzki-systems.com",
            "verification_method": "Ed25519"
        }
    }

    # Sign using only the non-proof fields
    signature = sign_identity(priv, non_proof_fields)

    # Full document including integrity_proof
    full_document = {
        **non_proof_fields,
        "integrity_proof": {
            "signature": signature,
            "created": "2026-01-01T00:00:00Z",
            "public_key_ref": "dns:txt:_sovp.test.litzki-systems.com",
            "nonce": "unique-nonce-abc"
        }
    }

    # Verifying the full document must succeed (proof fields are stripped internally)
    assert verify_identity(full_document, signature, pub) is True

    # Verifying non-proof fields alone must also succeed
    assert verify_identity(non_proof_fields, signature, pub) is True

    # Signing the full document must produce the same signature as signing non-proof fields
    signature_from_full = sign_identity(priv, full_document)
    assert verify_identity(non_proof_fields, signature_from_full, pub) is True


def test_timestamp_validation_rejects_stale():
    """
    Verifies that stale created timestamps are rejected per draft Section 7.2 SHOULD:
    "Validating Agents SHOULD reject signatures with a timestamp older than 600 seconds."
    """
    priv, pub = generate_keypair()

    metadata = {
        "@context": "https://litzki-systems.com/protocol/v1.4",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:test-timestamp-01",
            "canonical_url": "https://test.litzki-systems.com",
            "verification_method": "Ed25519"
        }
    }

    signature = sign_identity(priv, metadata)

    # Stale document: created timestamp is one hour in the past
    stale_document = {
        **metadata,
        "integrity_proof": {
            "signature": signature,
            "created": "2020-01-01T00:00:00Z",
            "public_key_ref": "dns:txt:_sovp.test.litzki-systems.com"
        }
    }

    # Without timestamp check: should still pass cryptographic verification
    assert verify_identity(stale_document, signature, pub, check_timestamp=False) is True

    # With timestamp check enabled: must be rejected as stale
    assert verify_identity(stale_document, signature, pub, check_timestamp=True) is False


def test_timestamp_validation_accepts_fresh():
    """
    Verifies that a fresh created timestamp passes validation per draft Section 7.2.
    """
    priv, pub = generate_keypair()

    metadata = {
        "@context": "https://litzki-systems.com/protocol/v1.4",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:test-timestamp-02",
            "canonical_url": "https://test.litzki-systems.com",
            "verification_method": "Ed25519"
        }
    }

    signature = sign_identity(priv, metadata)

    # Fresh document: created timestamp is 10 seconds ago
    fresh_created = (datetime.now(timezone.utc) - timedelta(seconds=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    fresh_document = {
        **metadata,
        "integrity_proof": {
            "signature": signature,
            "created": fresh_created,
            "public_key_ref": "dns:txt:_sovp.test.litzki-systems.com"
        }
    }

    assert verify_identity(fresh_document, signature, pub, check_timestamp=True) is True


def test_verify_rejects_wrong_key():
    """Ensures Psi_core = 0 when the wrong public key is supplied."""
    priv, pub = generate_keypair()
    _, wrong_pub = generate_keypair()

    metadata = {
        "@context": "https://litzki-systems.com/protocol/v1.4",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:test-wrongkey-01",
            "canonical_url": "https://test.litzki-systems.com",
            "verification_method": "Ed25519"
        }
    }

    signature = sign_identity(priv, metadata)
    assert verify_identity(metadata, signature, wrong_pub) is False


def test_verify_rejects_malformed_inputs():
    """Ensures malformed base64 inputs return False rather than raising exceptions."""
    priv, pub = generate_keypair()
    metadata = {
        "@context": "https://litzki-systems.com/protocol/v1.4",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": "urn:sovp:test-malformed-01",
            "canonical_url": "https://test.litzki-systems.com",
            "verification_method": "Ed25519"
        }
    }
    signature = sign_identity(priv, metadata)

    assert verify_identity(metadata, "not-valid-base64!!!", pub) is False
    assert verify_identity(metadata, signature, "not-valid-base64!!!") is False


def test_generate_identity_document_no_scan():
    """
    Verifies generate_identity_document() produces a valid, verifiable document
    with the correct structure and no scan key when scan is omitted.
    """
    priv, pub = generate_keypair()
    doc = generate_identity_document(
        private_key_b64=priv,
        entity_uid="urn:sovp:test-gendoc-01",
        canonical_url="https://test.litzki-systems.com",
    )

    assert doc["@type"] == "SovereignIdentity"
    assert "scan" not in doc
    assert "integrity_proof" in doc

    signature = doc["integrity_proof"]["signature"]
    assert verify_identity(doc, signature, pub) is True


def test_generate_identity_document_with_scan():
    """
    Verifies generate_identity_document() appends the scan object outside the
    signed scope. verify_identity() must still pass (scan excluded from signing).
    """
    priv, pub = generate_keypair()
    scan_data = {"verdict": "CERTIFIED"}
    doc = generate_identity_document(
        private_key_b64=priv,
        entity_uid="urn:sovp:test-gendoc-02",
        canonical_url="https://test.litzki-systems.com",
        scan=scan_data,
    )

    assert "scan" in doc
    assert doc["scan"] == {"verdict": "CERTIFIED"}

    signature = doc["integrity_proof"]["signature"]
    assert verify_identity(doc, signature, pub) is True
