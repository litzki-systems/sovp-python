# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

# SOVP RFC Test Vector Set 1 — do not modify
# Generated 2026-06-09 against sovp-python 1.0.1 / draft-litzki-sovp-03
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


# --- Fixed keypair (Test Vector Set 2 — schema v2.0 "freshness" object) ---
# Generated 2026-09-16 against sovp-python (post-freshness-migration) /
# draft-litzki-sovp-04, using sovp.core.generate_identity_document +
# sign_identity directly (not fabricated). Covers the schema v2.0 case where
# created/nonce/expiresAt live in a signed "freshness" object instead of the
# unsigned integrity_proof (see Vector Set 1, which stays v1.4 and unmodified
# by design — it is the fixed legacy-schema regression vector).
VECTOR_2_PRIVATE_KEY = "/Tp1tRJ/wlUUHYDsO7C1rR0XAsAg4hHmLC0xQKkdmHQ="
VECTOR_2_PUBLIC_KEY  = "Roc8V4AnfbRjW35aagwwuHJhc7hPQZl7ooncY+HdM+s="
VECTOR_2_SIGNATURE   = (
    "Th2wr122ikRicemrC5bITXHri5glqNqfkPosCjLBjXLIdO2UStZm5j7SmJ0j1xuEYAPOc9Wt"
    "JW4blsceuCVCBg=="
)

# One-byte corruption of VECTOR_2_SIGNATURE (first byte XOR 0xFF).
VECTOR_2_TAMPERED_SIGNATURE = (
    "sR2wr122ikRicemrC5bITXHri5glqNqfkPosCjLBjXLIdO2UStZm5j7SmJ0j1xuEYAPOc9Wt"
    "JW4blsceuCVCBg=="
)

# A distinct public key that does not correspond to VECTOR_2_PRIVATE_KEY.
VECTOR_2_WRONG_PUBLIC_KEY = "RYVkYPO0CymHmHNYfjw3a9baEyWH40fnEzrgY/rMA5M="

# Canonical document for Test Vector 2. freshness is INSIDE the signed scope
# (unlike integrity_proof.created in Vector Set 1) — tampering with any
# freshness field must invalidate the signature.
VECTOR_2_DOCUMENT = {
    "@context": "https://litzki-systems.com/protocol/v2.0",
    "@type": "SovereignIdentity",
    "entity": {
        "uid": "urn:sovp:test-entity-2",
        "canonical_url": "https://example.org",
        "verification_method": "Ed25519",
    },
    "freshness": {
        "created": "2026-06-01T12:00:00Z",
        "nonce": "fixed-test-nonce-v2-0001",
        "expiresAt": "2026-12-01T00:00:00Z",
    },
    "contentAddress": {
        "alg": "sha256",
        "digest": "33465a2bb2d7885afd9dd8890ac9eafd48a98e16bb75cd2be4ebedf2763ae2b5",
    },
    "integrity_proof": {
        "signature": VECTOR_2_SIGNATURE,
        "public_key_ref": "dns:txt:_sovp.example.org",
    },
}


def test_vector_2_1_valid():
    """Psi_core = 1: v2.0 document with freshness object, valid signature."""
    result = verify_identity(VECTOR_2_DOCUMENT, VECTOR_2_SIGNATURE, VECTOR_2_PUBLIC_KEY)
    assert result is True


def test_vector_2_2_tampered_freshness_created():
    """Psi_core = 0: freshness.created tampered → freshness is in signed
    scope for v2.0, so the JCS digest changes and the signature is invalid.
    This is the exact bug the v2.0 migration fixes (created was previously
    forgeable inside the unsigned integrity_proof)."""
    tampered = {
        **VECTOR_2_DOCUMENT,
        "freshness": {
            **VECTOR_2_DOCUMENT["freshness"],
            "created": "2099-01-01T00:00:00Z",
        },
    }
    result = verify_identity(tampered, VECTOR_2_SIGNATURE, VECTOR_2_PUBLIC_KEY)
    assert result is False


def test_vector_2_3_tampered_expires_at():
    """Psi_core = 0: freshness.expiresAt tampered → signature invalid.
    This is the practically more important bug fixed by the migration:
    expiresAt was previously forgeable without breaking the signature."""
    tampered = {
        **VECTOR_2_DOCUMENT,
        "freshness": {
            **VECTOR_2_DOCUMENT["freshness"],
            "expiresAt": "2099-01-01T00:00:00Z",
        },
    }
    result = verify_identity(tampered, VECTOR_2_SIGNATURE, VECTOR_2_PUBLIC_KEY)
    assert result is False


def test_vector_2_4_tampered_signature():
    """Psi_core = 0: first byte of signature XOR 0xFF → Ed25519 reject."""
    result = verify_identity(
        VECTOR_2_DOCUMENT, VECTOR_2_TAMPERED_SIGNATURE, VECTOR_2_PUBLIC_KEY
    )
    assert result is False


def test_vector_2_5_wrong_pubkey():
    """Psi_core = 0: correct document and signature, but wrong public key."""
    result = verify_identity(
        VECTOR_2_DOCUMENT, VECTOR_2_SIGNATURE, VECTOR_2_WRONG_PUBLIC_KEY
    )
    assert result is False


def test_vector_2_6_timestamp_valid():
    """Psi_core = 1: check_timestamp=True reads freshness.created (not
    integrity_proof.created) for v2.0 documents."""
    fresh_created = (
        datetime.now(timezone.utc) - timedelta(seconds=10)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    from sovp.core import generate_identity_document, sign_identity

    doc = {
        **VECTOR_2_DOCUMENT,
        "freshness": {
            **VECTOR_2_DOCUMENT["freshness"],
            "created": fresh_created,
        },
    }
    non_proof = {
        k: v for k, v in doc.items()
        if k not in ("integrity_proof", "scan", "contentAddress")
    }
    sig = sign_identity(VECTOR_2_PRIVATE_KEY, non_proof)
    doc["integrity_proof"] = {**doc["integrity_proof"], "signature": sig}

    result = verify_identity(
        doc, sig, VECTOR_2_PUBLIC_KEY, check_timestamp=True
    )
    assert result is True


def test_vector_2_7_timestamp_expired():
    """Psi_core = 0: check_timestamp=True, freshness.created = now − 700s
    (exceeds 600s window)."""
    stale_created = (
        datetime.now(timezone.utc) - timedelta(seconds=700)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    from sovp.core import sign_identity

    doc = {
        **VECTOR_2_DOCUMENT,
        "freshness": {
            **VECTOR_2_DOCUMENT["freshness"],
            "created": stale_created,
        },
    }
    non_proof = {
        k: v for k, v in doc.items()
        if k not in ("integrity_proof", "scan", "contentAddress")
    }
    sig = sign_identity(VECTOR_2_PRIVATE_KEY, non_proof)
    doc["integrity_proof"] = {**doc["integrity_proof"], "signature": sig}

    result = verify_identity(
        doc, sig, VECTOR_2_PUBLIC_KEY, check_timestamp=True
    )
    assert result is False
