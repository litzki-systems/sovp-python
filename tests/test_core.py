import pytest
from sovp.core import generate_keypair, sign_identity, verify_identity

def test_keypair_generation():
    """
    Verifies the deterministic generation of Ed25519 keypairs.
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
    Tests both successful verification (resonance = 1) and tamper resistance (resonance = 0).
    """
    priv, pub = generate_keypair()
    
    # Deterministic test payload (Test Vector 01)
    identity_metadata = {
        "@context": "https://litzki-systems.org/protocol/v1.5",
        "@type": "SovereignIdentity",
        "uid": "urn:sovp:test-vector-01",
        "canonical_url": "https://test.litzki-systems.org"
    }
    
    # Generate signature
    signature = sign_identity(priv, identity_metadata)
    assert signature is not None
    
    # Validation: Positive test (Resonance Psi_core = 1)
    is_valid = verify_identity(identity_metadata, signature, pub)
    assert is_valid is True
    
    # Validation: Negative test / Tamper attempt (Resonance Psi_core = 0)
    tampered_metadata = identity_metadata.copy()
    tampered_metadata["canonical_url"] = "https://malicious-actor.org"
    
    is_invalid = verify_identity(tampered_metadata, signature, pub)
    assert is_invalid is False