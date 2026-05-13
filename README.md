# sovp-python

Reference implementation of the **Sovereign Validation Protocol (SOVP)** in Python.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/Status-Patent_Pending-orange.svg)](https://litzki-systems.com/sovp)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--litzki--sovp--05-lightgrey.svg)](https://litzki-systems.com/sovp)

---

## What is SOVP?

SOVP is a protocol that allows LLMs and autonomous agents to verify the authenticity of a data source **before ingesting it**. It answers one question deterministically: does this data originate from the declared entity, and has it been tampered with?

It does **not** validate the semantic accuracy or truthfulness of content. It validates identity and integrity only.

The core validation function is:

```
Psi_core = Verify(K_pub, sigma, H(JCS(M)))
```

Where `Psi_core = 1` means the source is cryptographically verified. `Psi_core = 0` means ingestion is blocked.

---

## How is this different from DANE or DIDs?

| | SOVP | DANE | W3C DIDs |
|---|---|---|---|
| **Target** | Agentic / LLM ingestion pipelines | TLS certificate validation | Decentralized identity |
| **Layer** | Layer 0 (infrastructure ingress) | Transport layer | Application layer |
| **Trigger** | Pre-ingestion, before body parsing | TLS handshake | On-demand resolution |
| **DNS anchor** | `_sovp` TXT record | `_dane` TLSA record | DID document |
| **Primary use case** | AI agent trust verification | Email/TLS authentication | General identity |

SOVP is scoped specifically to the pre-ingestion validation problem in agentic architectures.

---

## Installation

```bash
git clone https://github.com/litzki-systems/sovp-python.git
cd sovp-python
pip install -e .
```

This installs the `sovp` CLI and the `sovp.core` library. Dependencies (`cryptography`, `canonicaljson`) are declared in `pyproject.toml` and resolved automatically.

---

## Usage

The current implementation exposes three functions in `sovp.core` and three matching CLI commands.

### Python API

#### Generate a key pair

```python
from sovp.core import generate_keypair

private_key_b64, public_key_b64 = generate_keypair()
print(public_key_b64)   # publish this in your DNS TXT record
print(private_key_b64)  # keep this secret
```

#### Sign an identity payload

```python
from sovp.core import sign_identity
import json

# Fields to sign — do NOT include integrity_proof here
metadata = {
    "@context": "https://litzki-systems.com/protocol/v1.5",
    "@type": "SovereignIdentity",
    "uid": "urn:sovp:your-entity-id",
    "canonical_url": "https://yourdomain.com"
}

signature = sign_identity(private_key_b64, metadata)

# Embed the signature before publishing
signed_payload = {
    **metadata,
    "integrity_proof": {
        "signature": signature,
        "created": "2026-01-01T00:00:00Z",
        "public_key_ref": "dns:txt:_sovp.yourdomain.tld"
    }
}

# Write to /.well-known/sovp-identity.json on your server
with open("sovp-identity.json", "w") as f:
    json.dump(signed_payload, f, indent=2)
```

> **Note:** Sign only the fields that form the canonical identity. Do not include `integrity_proof` in the signed payload — the signature cannot cover itself.

#### Verify a signature (Psi_core)

```python
from sovp.core import verify_identity

# Use the same fields that were signed (excluding integrity_proof)
metadata = {
    "@context": "https://litzki-systems.com/protocol/v1.5",
    "@type": "SovereignIdentity",
    "uid": "urn:sovp:your-entity-id",
    "canonical_url": "https://yourdomain.com"
}

psi_core = verify_identity(metadata, signature, public_key_b64)

if psi_core:
    print("Psi_core = 1: Verified. Proceed with ingestion.")
else:
    print("Psi_core = 0: Verification failed. Ingestion blocked.")
```

### CLI

```bash
# Generate a keypair
sovp generate-keypair

# Sign a JSON payload file
sovp sign --payload test_payload.json --privkey <base64-private-key>

# Verify a signature
sovp verify --payload test_payload.json --sig <base64-signature> --pubkey <base64-public-key>
```

---

## Technical Foundation

- **Cryptography:** Ed25519 (RFC 8032)
- **Canonicalization:** JSON Canonicalization Scheme / JCS (RFC 8785)
- **Hashing:** SHA-512 digest of the canonical payload passed as the message to Ed25519 `sign()` / `verify()`
- **Key distribution:** DNS TXT record at `_sovp.yourdomain.tld` (see DNS Setup below)
- **Replay protection:** `created` timestamp + optional `nonce` in `integrity_proof` — field parsing is not yet validated by this library (see Roadmap)

Full protocol specification: [IETF Internet-Draft draft-litzki-sovp-05](https://litzki-systems.com/sovp) *(draft prepared, not yet submitted to IETF)*

---

## The sovp-identity.json Schema

```json
{
  "@context": "https://litzki-systems.com/protocol/v1.5",
  "@type": "SovereignIdentity",
  "entity": {
    "uid": "urn:sovp:your-entity-id",
    "canonical_url": "https://yourdomain.com",
    "verification_method": "Ed25519"
  },
  "integrity_proof": {
    "signature": "<Ed25519 signature, base64>",
    "created": "2026-03-19T10:00:00Z",
    "public_key_ref": "dns:txt:_sovp.yourdomain.tld",
    "nonce": "optional-unique-string"
  }
}
```

Place this file at `https://yourdomain.com/.well-known/sovp-identity.json`.

> **Important:** Sign only the fields **outside** `integrity_proof`. The `integrity_proof` block must not be included in the signed data.

---

## DNS Setup

Add a TXT record to your DNS zone:

```
_sovp.yourdomain.tld  IN  TXT  "v=SOVP1; k=<your-Ed25519-public-key-base64>"
```

Recommended TTL: 300 seconds (per draft Section 6.1).  
DNSSEC is recommended for the `_sovp` zone.

> **Note:** Automatic DNS resolution and key retrieval are not yet implemented in this library. Keys must currently be supplied directly to `verify_identity()`. See Roadmap.

---

## Roadmap

The following features are defined in the protocol draft but not yet implemented in this library:

| Feature | Description |
|---|---|
| `SOVPIdentity` class | High-level key management: `SOVPIdentity.generate()`, `.public_key_b64`, `.private_key_b64` |
| `SOVPSigner` class | High-level signing: `SOVPSigner(private_key_b64).sign(metadata)` |
| `SOVPValidator` class | End-to-end validator: `SOVPValidator().verify(url)` returning result with `.psi_core` and `.reason` |
| DNS resolution | Automatic retrieval of public key from `_sovp.<domain>` TXT record |
| HTTP fetch | Automatic fetch and parsing of `/.well-known/sovp-identity.json` |
| Replay protection | Validation of `created` timestamp and `nonce` fields in `integrity_proof` |
| RFC conformance test vectors | Fixed-input/output vectors for cross-implementation interoperability testing |

---

## Status

| Component | Status |
|---|---|
| `sovp.core` library (`generate_keypair`, `sign_identity`, `verify_identity`) | Implemented |
| CLI (`generate-keypair`, `sign`, `verify`) | Implemented |
| High-level class API (`SOVPIdentity`, `SOVPSigner`, `SOVPValidator`) | Not yet implemented — see Roadmap |
| DNS + HTTP resolution in `SOVPValidator` | Not yet implemented — see Roadmap |
| Replay protection (timestamp / nonce validation) | Not yet implemented — see Roadmap |
| Test vectors (RFC conformance) | Not yet implemented — see Roadmap |
| IETF Internet-Draft | draft-litzki-sovp-05 (prepared, not yet submitted) |
| U.S. Provisional Patent | Filed — No. 64/005,737 |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

The SOVP protocol specification and ZWAP architecture are intellectual property of Litzki Systems LLC. Patent pending.

---

## Developed by

[Litzki Systems LLC](https://litzki-systems.com)  
St. Petersburg, FL, USA · Operating from Mexico City  
[info@litzki-systems.com](mailto:info@litzki-systems.com)

Development of this reference implementation was assisted by
[Claude Code](https://claude.ai/code) (Anthropic).
