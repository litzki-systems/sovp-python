import hashlib
import base64
import canonicaljson
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
    The metadata is formatted according to RFC 8785 (JCS) and pre-hashed with SHA-512.
    
    Args:
        private_key_b64 (str): The base64 encoded Ed25519 private key.
        identity_metadata (dict): The identity payload to be signed.
        
    Returns:
        str: The base64 encoded Ed25519 signature.
    """
    priv_bytes = base64.b64decode(private_key_b64)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
    
    canonical_data = canonicaljson.encode_canonical_json(identity_metadata)
    digest = hashlib.sha512(canonical_data).digest()
    
    signature = private_key.sign(digest)
    return base64.b64encode(signature).decode('utf-8')

def verify_identity(identity_metadata: dict, signature_b64: str, public_key_b64: str) -> bool:
    """
    Deterministically verifies the cryptographic alignment (Psi_core resonance).
    
    Args:
        identity_metadata (dict): The original identity payload.
        signature_b64 (str): The base64 encoded signature.
        public_key_b64 (str): The base64 encoded Ed25519 public key.
        
    Returns:
        bool: True if the signature is valid (Psi_core = 1), False otherwise (Psi_core = 0).
    """
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        sig_bytes = base64.b64decode(signature_b64)
        
        canonical_data = canonicaljson.encode_canonical_json(identity_metadata)
        digest = hashlib.sha512(canonical_data).digest()
        
        public_key.verify(sig_bytes, digest)
        return True
        
    except (InvalidSignature, ValueError, TypeError):
        return False