# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

import base64
import jcs
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair() -> tuple[str, str]:
    """
    Generates a new Ed25519 keypair for sovereign identity validation.

    Returns:
        tuple[str, str]: A tuple containing the base64 encoded private key
        and public key.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return base64.b64encode(priv_bytes).decode('utf-8'), base64.b64encode(pub_bytes).decode('utf-8')


def sign_identity(private_key_b64: str, identity_metadata: dict) -> str:
    """
    Signs the canonicalized identity metadata using the Ed25519 private key.
    The metadata is canonicalized according to RFC 8785 (JCS) before signing.

    Per draft Section 4, the integrity_proof field is always stripped before
    canonicalization. Callers MAY pass the full document or the non-proof
    subset; the result is identical.

    Args:
        private_key_b64 (str): The base64 encoded Ed25519 private key.
        identity_metadata (dict): The identity payload (full document or
            non-proof fields only).

    Returns:
        str: The base64 encoded Ed25519 signature.
    """
    priv_bytes = base64.b64decode(private_key_b64)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

    # Per draft Section 4 MUST: "Implementations MUST canonicalize only the
    # non-proof fields of M when computing or verifying JCS(M)."
    payload = {k: v for k, v in identity_metadata.items() if k != "integrity_proof"}
    canonical_data = jcs.canonicalize(payload)
    signature = private_key.sign(canonical_data)
    return base64.b64encode(signature).decode('utf-8')


def verify_identity(
    identity_metadata: dict,
    signature_b64: str,
    public_key_b64: str,
    check_timestamp: bool = False,
    max_age_seconds: int = 600,
) -> bool:
    """
    Deterministically verifies the cryptographic alignment (Psi_core resonance).

    Per draft Section 3: Psi_core = Verify(K_pub, sigma, JCS(M)).
    Ed25519 pure mode (RFC 8032) is used; no external pre-hash is applied.

    Per draft Section 4 MUST: integrity_proof is stripped before
    canonicalization, so callers MAY pass the full document or the non-proof
    subset; the result is identical.

    Per draft Section 7.2 SHOULD: when check_timestamp is True, rejects any
    document whose integrity_proof.created timestamp is older than
    max_age_seconds (default 600).

    Args:
        identity_metadata (dict): The identity payload (full document or
            non-proof fields only).
        signature_b64 (str): The base64 encoded signature.
        public_key_b64 (str): The base64 encoded Ed25519 public key.
        check_timestamp (bool): When True, enforce the 600-second validity
            window on the integrity_proof.created field (draft Section 7.2).
        max_age_seconds (int): Maximum acceptable age of the created timestamp
            in seconds. Default: 600 (per draft Section 7.2).

    Returns:
        bool: True if the signature is valid (Psi_core = 1), False otherwise
        (Psi_core = 0).
    """
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(signature_b64)

        # Per draft Section 4 MUST: canonicalize only the non-proof fields.
        payload = {k: v for k, v in identity_metadata.items() if k != "integrity_proof"}
        canonical_data = jcs.canonicalize(payload)
        public_key.verify(sig_bytes, canonical_data)

        # Per draft Section 7.2 SHOULD: reject stale timestamps.
        if check_timestamp:
            proof = identity_metadata.get("integrity_proof", {})
            created_str = proof.get("created")
            if created_str is not None:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                age = datetime.now(timezone.utc) - created
                if age > timedelta(seconds=max_age_seconds):
                    return False

        return True

    except (InvalidSignature, ValueError, TypeError):
        return False
