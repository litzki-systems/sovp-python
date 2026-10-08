# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import hashlib
import jcs
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse

# Top-level keys that are always excluded from the signed scope.
# Per draft Section 4: integrity_proof is excluded because the signature
# cannot cover itself. Per draft V02 item 10: vendor extension objects
# (e.g. scan) MUST NOT be included in the signed scope.
_OUT_OF_SCOPE_KEYS = frozenset({"integrity_proof", "scan", "contentAddress"})
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
    payload = {k: v for k, v in identity_metadata.items() if k not in _OUT_OF_SCOPE_KEYS}
    canonical_data = jcs.canonicalize(payload)
    signature = private_key.sign(canonical_data)
    return base64.b64encode(signature).decode('utf-8')


def _is_v2_document(identity_metadata: dict) -> bool:
    context = identity_metadata.get("@context")
    return isinstance(context, str) and "/v2.0" in context


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone information")
    return parsed.astimezone(timezone.utc)


def _validate_freshness(
    identity_metadata: dict,
    check_timestamp: bool,
    max_age_seconds: int,
    clock_skew_seconds: int = 60,
) -> None:
    freshness = identity_metadata.get("freshness")

    if _is_v2_document(identity_metadata):
        if not isinstance(freshness, dict):
            raise ValueError("v2.0 documents require a freshness object")

        created_str = freshness.get("created")
        expires_at_str = freshness.get("expiresAt")
        if created_str is None or expires_at_str is None:
            raise ValueError(
                "v2.0 documents require freshness.created and freshness.expiresAt"
            )

        created = _parse_timestamp(created_str)
        expires_at = _parse_timestamp(expires_at_str)

        if expires_at <= created:
            raise ValueError("freshness.expiresAt must be later than freshness.created")

        now = datetime.now(timezone.utc)
        if now < created - timedelta(seconds=clock_skew_seconds):
            raise ValueError("freshness.created is too far in the future")
        if now > expires_at + timedelta(seconds=clock_skew_seconds):
            raise ValueError("freshness.expiresAt has expired")

        if check_timestamp and now > created + timedelta(
            seconds=max_age_seconds + clock_skew_seconds
        ):
            raise ValueError("freshness.created is outside the issuance window")
        return

    if check_timestamp:
        created_str = None
        if isinstance(freshness, dict):
            created_str = freshness.get("created")
        if created_str is None:
            proof = identity_metadata.get("integrity_proof", {})
            if isinstance(proof, dict):
                created_str = proof.get("created")
        if created_str is None:
            raise ValueError("created timestamp is required when timestamp checking is enabled")

        created = _parse_timestamp(created_str)
        now = datetime.now(timezone.utc)
        if now < created - timedelta(seconds=clock_skew_seconds):
            raise ValueError("created timestamp is too far in the future")
        if now > created + timedelta(seconds=max_age_seconds + clock_skew_seconds):
            raise ValueError("created timestamp is outside the issuance window")


def verify_identity(
    identity_metadata: dict,
    signature_b64: str,
    public_key_b64: str,
    check_timestamp: bool = False,
    max_age_seconds: int = 600,
    expected_host: str | None = None,
) -> bool:
    """
    Verify an SOVP identity document signature and Draft 04 bindings.

    Schema v2.0 requires freshness.created and freshness.expiresAt. The
    freshness fields are signed; expiresAt is always enforced, while the
    created issuance window is enforced when check_timestamp is True.

    When expected_host is supplied, entity.canonical_url MUST resolve to the
    same host, normalized to lower case with a trailing dot removed.
    """
    try:
        if expected_host is not None:
            entity = identity_metadata.get("entity")
            canonical_url = (
                entity.get("canonical_url") if isinstance(entity, dict) else None
            )
            if not isinstance(canonical_url, str):
                return False
            parsed = urlparse(canonical_url)
            if not parsed.hostname:
                return False
            actual_host = parsed.hostname.rstrip(".").lower()
            wanted_host = expected_host.rstrip(".").lower()
            if actual_host != wanted_host:
                return False

        pub_bytes = base64.b64decode(public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(signature_b64)

        payload = {
            k: v for k, v in identity_metadata.items()
            if k not in _OUT_OF_SCOPE_KEYS
        }
        canonical_data = jcs.canonicalize(payload)
        public_key.verify(sig_bytes, canonical_data)

        _validate_freshness(
            identity_metadata,
            check_timestamp=check_timestamp,
            max_age_seconds=max_age_seconds,
        )
        return True

    except (InvalidSignature, ValueError, TypeError, AttributeError):
        return False



def generate_identity_document(
    private_key_b64: str,
    entity_uid: str,
    canonical_url: str,
    scan: dict | None = None,
    nonce: str | None = None,
    expires_at: str | None = None,
    context_version: str = "v2.0",
) -> dict:
    """
    Builds, signs, and returns a complete sovp-identity.json document.

    The non-proof fields are canonicalized and signed per draft Section 4.
    Schema v2.0+: created/expiresAt/nonce live in a "freshness" object that
    IS part of the signed scope (schema < v2.0 kept them in integrity_proof,
    which is excluded from the signed scope and therefore forgeable without
    invalidating the signature). The scan object (if provided) is appended
    after integrity_proof and is excluded from the signed scope — consistent
    with draft V02 item 10: vendor extension objects MUST NOT be included in
    the signed scope.

    Args:
        private_key_b64 (str): Base64 encoded Ed25519 private key.
        entity_uid (str): The entity UID (e.g. "urn:sovp:example").
        canonical_url (str): The canonical URL of the publishing entity.
        scan (dict | None): Optional vendor extension object appended outside
            the signed scope. Omitted from the document when None.
        nonce (str | None): Replay-protection nonce. A uuid4 is generated
            when None.
        expires_at (str | None): ISO-8601 expiry timestamp for
            freshness.expiresAt. Omitted from the document when None.
        context_version (str): Context version string. Default: "v2.0".

    Returns:
        dict: The complete signed sovp-identity.json document.
    """
    domain = urlparse(canonical_url).netloc
    public_key_ref = f"dns:txt:_sovp.{domain}"
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    resolved_nonce = nonce if nonce is not None else str(uuid.uuid4())
    resolved_expires_at = expires_at
    if resolved_expires_at is None:
        resolved_expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    freshness = {
        "created": created,
        "nonce": resolved_nonce,
        "expiresAt": resolved_expires_at,
    }

    # Non-proof payload — the only fields covered by the signature.
    non_proof = {
        "@context": f"https://litzki-systems.com/protocol/{context_version}",
        "@type": "SovereignIdentity",
        "entity": {
            "uid": entity_uid,
            "canonical_url": canonical_url,
            "verification_method": "Ed25519",
        },
        "freshness": freshness,
    }

    canonical_data = jcs.canonicalize(non_proof)
    signature = sign_identity(private_key_b64, non_proof)
    digest = hashlib.sha256(canonical_data).hexdigest()

    document = {
        **non_proof,
        "contentAddress": {
            "alg": "sha256",
            "digest": digest,
        },
        "integrity_proof": {
            "signature": signature,
            "public_key_ref": public_key_ref,
        },
    }

    # Vendor extension: appended after proof, excluded from signed scope.
    if scan is not None:
        document["scan"] = scan

    return document
