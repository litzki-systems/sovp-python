# sovp-python

Reference implementation of the **Sovereign Validation Protocol (SOVP)** in Python.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Status](https://img.shields.io/badge/Status-Patent_Pending-orange.svg)](https://litzki-systems.com/sovp)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--litzki--sovp--05-blue.svg)](https://litzki-systems.com/sovp)

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
pip install cryptography canonicaljson
```

---

## Usage

### Generate a key pair

```python
from sovp import SOVPIdentity

identity = SOVPIdentity.generate()
print(identity.public_key_b64)   # publish this in your DNS TXT record
print(identity.private_key_b64)  # keep this secret
```

### Sign an identity payload

```python
from sovp import SOVPSigner
import json

metadata = {
    "@context": "https://litzki.systems/protocol/v1.5",
    "@type": "SovereignIdentity",
    "entity": {
        "uid": "urn:sovp:your-entity-id",
        "canonical_url": "https://yourdomain.com",
        "verification_method": "Ed25519"
    }
}

signer = SOVPSigner(private_key_b64=identity.private_key_b64)
signed_payload = signer.sign(metadata)

# Write to /.well-known/sovp-identity.json on your server
with open("sovp-identity.json", "w") as f:
    json.dump(signed_payload, f, indent=2)
```

### Verify a source (Psi_core)

```python
from sovp import SOVPValidator

validator = SOVPValidator()

# Resolves DNS TXT record, fetches sovp-identity.json, runs Ed25519 verification
result = validator.verify("https://yourdomain.com")

if result.psi_core == 1:
    print("Verified. Proceed with ingestion.")
else:
    print("Verification failed. Ingestion blocked.")
    print(result.reason)
```

---

## Technical Foundation

- **Cryptography:** Ed25519 (RFC 8032)
- **Canonicalization:** JSON Canonicalization Scheme / JCS (RFC 8785)
- **Hashing:** SHA-512 (RFC 6234) as pre-hash for Ed25519
- **Key distribution:** DNS TXT record at `_sovp.yourdomain.tld` or `X-SOVP-Identity` HTTP header
- **Replay protection:** `created` timestamp + optional nonce in `integrity_proof`

Full protocol specification: [IETF Internet-Draft draft-litzki-sovp-05](https://litzki-systems.com/sovp)

---

## The sovp-identity.json Schema

```json
{
  "@context": "https://litzki.systems/protocol/v1.5",
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

---

## DNS Setup

Add a TXT record to your DNS zone:

```
_sovp.yourdomain.tld  IN  TXT  "v=SOVP1; k=<your-Ed25519-public-key-base64>"
```

Recommended TTL: 300 seconds (per draft Section 6.1).  
DNSSEC is recommended for the `_sovp` zone.

---

## Status

| Component | Status |
|---|---|
| Python core library | In development (target: KW 12 / 2026) |
| CLI tool | In development |
| Test vectors (RFC conformance) | In development |
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
