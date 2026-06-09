# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

# SOVP RFC Test Vector Set 1 — do not modify
# Generated 2026-06-09 against sovp-python 1.0.1 / draft-litzki-sovp-02
# Any conforming SOVP implementation must produce Psi_core = 1 for VECTOR_1.

from datetime import datetime, timezone, timedelta
from sovp.core import verify_identity

# --- Fixed keypair (Test Vector Set 1) ---
VECTOR_1_PRIVATE_KEY = "1r6vlmMZDA2vEtvsK+RSdyffROOQiyfFJlmHbm9c85w="
VECTOR_1_PUBLIC_KEY  = "T9rvGE4izpy57b8slLvcgi5m8NliXnoofUYHqUCBOqM="
VECTOR_1_SIGNATURE   = (
    "QAtcj4bJlPrUWLyunU0laoPhgVYh+Fgud0b8m6VtqIvpW5hmFumLxF+"
    "DpBDsvP0YzxeZp6InKb7sHxcZjrWQBg=="
)

# One-byte corruption of VECTOR_1_SIGNATURE (first byte XOR 0xFF).
VECTOR_1_TAMPERED_SIGNATURE = (
    "vwtcj4bJlPrUWLyunU0laoPhgVYh+Fgud0b8m6VtqIvpW5hmFumLxF+"
    "DpBDsvP0YzxeZp6InKb7sHxcZjrWQBg=="
)

# A distinct public key that does not correspond to VECTOR_1_PRIVATE_KEY.
VECTOR_1_WRONG_PUBLIC_KEY = "smKOwfBSZ62HzfGWG6RwoCGkhgH6bXKgPWUc4xRvDCU="

# Canonical document for Test Vector 1.
# integrity_proof.signature must equal VECTOR_1_SIGNATURE when verified
# against the non-proof fields using VECTOR_1_PUBLIC_KEY.
VECTOR_1_DOCUMENT = {
    "@context": "https://litzki-systems.com/protocol/v1.4",
    "@type": "SovereignIdentity",
    "entity": {
        "uid": "urn:sovp:test-entity-1",
        "canonical_url": "https://example.com",
        "verification_method": "Ed25519",
    },
    "integrity_proof": {
        "signature": VECTOR_1_SIGNATURE,
        "created": "2026-01-01T00:00:00Z",
        "public_key_ref": "dns:txt:_sovp.example.com",
    },
}


def test_vector_1_valid():
    """Psi_core = 1: valid document, valid signature, correct public key."""
    result = verify_identity(VECTOR_1_DOCUMENT, VECTOR_1_SIGNATURE, VECTOR_1_PUBLIC_KEY)
    assert result is True


def test_vector_2_tampered_url():
    """Psi_core = 0: canonical_url tampered → JCS digest changes → signature invalid."""
    tampered = {
        **VECTOR_1_DOCUMENT,
        "entity": {
            **VECTOR_1_DOCUMENT["entity"],
            "canonical_url": "https://attacker.com",
        },
    }
    result = verify_identity(tampered, VECTOR_1_SIGNATURE, VECTOR_1_PUBLIC_KEY)
    assert result is False


def test_vector_3_tampered_signature():
    """Psi_core = 0: first byte of signature XOR 0xFF → Ed25519 reject."""
    result = verify_identity(
        VECTOR_1_DOCUMENT, VECTOR_1_TAMPERED_SIGNATURE, VECTOR_1_PUBLIC_KEY
    )
    assert result is False


def test_vector_4_wrong_pubkey():
    """Psi_core = 0: correct document and signature, but wrong public key."""
    result = verify_identity(
        VECTOR_1_DOCUMENT, VECTOR_1_SIGNATURE, VECTOR_1_WRONG_PUBLIC_KEY
    )
    assert result is False


def test_vector_5_timestamp_valid():
    """Psi_core = 1: check_timestamp=True, created = now − 10s (within 600s window)."""
    fresh_created = (
        datetime.now(timezone.utc) - timedelta(seconds=10)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = {
        **VECTOR_1_DOCUMENT,
        "integrity_proof": {
            **VECTOR_1_DOCUMENT["integrity_proof"],
            "created": fresh_created,
        },
    }
    result = verify_identity(
        doc, VECTOR_1_SIGNATURE, VECTOR_1_PUBLIC_KEY, check_timestamp=True
    )
    assert result is True


def test_vector_6_timestamp_expired():
    """Psi_core = 0: check_timestamp=True, created = now − 700s (exceeds 600s window)."""
    stale_created = (
        datetime.now(timezone.utc) - timedelta(seconds=700)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    doc = {
        **VECTOR_1_DOCUMENT,
        "integrity_proof": {
            **VECTOR_1_DOCUMENT["integrity_proof"],
            "created": stale_created,
        },
    }
    result = verify_identity(
        doc, VECTOR_1_SIGNATURE, VECTOR_1_PUBLIC_KEY, check_timestamp=True
    )
    assert result is False
