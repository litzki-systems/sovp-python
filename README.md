# sovp-python

**sovp-python** is the reference implementation of the [Sovereign Validation Protocol (SOVP)](https://litzki-systems.com/sovp) — a pre-ingestion verification protocol that lets LLMs and autonomous agents cryptographically confirm the identity and integrity of a data source before parsing it. It exists because existing mechanisms (DANE, DIDs, TLS) operate at the wrong layer for agentic pipelines: SOVP sits at Layer 0, before the body is read. To get started: clone the repo and run `pip install -e .` — this exposes both a `sovp.core` Python API and a `sovp` CLI with three commands.

> **Protocol specification:** [draft-litzki-sovp-05](https://litzki-systems.com/sovp) — IETF Internet-Draft (prepared, submission pending)

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--litzki--sovp--05-lightgrey.svg)](https://litzki-systems.com/sovp)
[![Status](https://img.shields.io/badge/Status-Patent_Pending-orange.svg)](https://litzki-systems.com/sovp)

---

## What SOVP does

SOVP answers one question deterministically: does this data originate from the declared entity, and has it been tampered with?

It does **not** validate semantic accuracy or truthfulness. It validates identity and integrity only.

```
Psi_core = Verify(K_pub, sigma, H(JCS(M)))
```

`Psi_core = 1` — source verified, proceed with ingestion.  
`Psi_core = 0` — verification failed, ingestion blocked.

---

## How is this different from DANE or DIDs?

| | SOVP | DANE | W3C DIDs |
|---|---|---|---|
| **Target** | Agentic / LLM ingestion pipelines | TLS certificate validation | Decentralized identity |
| **Layer** | Layer 0 (pre-ingestion) | Transport layer | Application layer |
| **Trigger** | Before body parsing | TLS handshake | On-demand resolution |
| **DNS anchor** | `_sovp` TXT record | `_dane` TLSA record | DID document |

---

## Installation

```bash
git clone https://github.com/litzki-systems/sovp-python.git
cd sovp-python
pip install -e .
```

This installs the `sovp` CLI and the `sovp.core` library. Dependencies (`cryptography`, `canonicaljson`) are declared in `pyproject.toml`.

---

## Usage

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

metadata = {
    "@context": "https://litzki-systems.com/protocol/v1.5",
    "@type": "SovereignIdentity",
    "uid": "urn:sovp:your-entity-id",
    "canonical_url": "https://yourdomain.com"
}

signature = sign_identity(private_key_b64, metadata)

signed_payload = {
    **metadata,
    "integrity_proof": {
        "signature": signature,
        "created": "2026-01-01T00:00:00Z",
        "public_key_ref": "dns:txt:_sovp.yourdomain.tld"
    }
}

with open("sovp-identity.json", "w") as f:
    json.dump(signed_payload, f, indent=2)
```

> Sign only the fields outside `integrity_proof`. The signature cannot cover itself.

#### Verify (Psi_core)

```python
from sovp.core import verify_identity

psi_core = verify_identity(metadata, signature, public_key_b64)

if psi_core:
    print("Psi_core = 1: Verified.")
else:
    print("Psi_core = 0: Ingestion blocked.")
```

### CLI

```bash
sovp generate-keypair
sovp sign   --payload test_payload.json --privkey <base64-private-key>
sovp verify --payload test_payload.json --sig <base64-signature> --pubkey <base64-public-key>
```

---

## Technical foundation

| Primitive | Specification |
|---|---|
| Signatures | Ed25519 (RFC 8032) |
| Canonicalization | JSON Canonicalization Scheme / JCS (RFC 8785) |
| Hashing | Ed25519 pure mode — `sign(JCS(M))`, no pre-hash |
| Key distribution | DNS TXT at `_sovp.yourdomain.tld` |
| Replay protection | `created` + optional `nonce` in `integrity_proof` (parsing not yet validated — see Roadmap) |

---

## The sovp-identity.json schema

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

Serve this file at `https://yourdomain.com/.well-known/sovp-identity.json`.

---

## DNS setup

```
_sovp.yourdomain.tld  IN  TXT  "v=SOVP1; k=<your-Ed25519-public-key-base64>"
```

Recommended TTL: 300 seconds (per draft Section 6.1). DNSSEC recommended for the `_sovp` zone.

> Automatic DNS resolution is not yet implemented. Keys must be supplied directly to `verify_identity()`. See Roadmap.

---

## Roadmap

| Feature | Status |
|---|---|
| `sovp.core` library (`generate_keypair`, `sign_identity`, `verify_identity`) | Implemented |
| CLI (`generate-keypair`, `sign`, `verify`) | Implemented |
| `SOVPIdentity` / `SOVPSigner` / `SOVPValidator` class API | Not yet implemented |
| DNS + HTTP resolution in `SOVPValidator` | Not yet implemented |
| Replay protection (timestamp / nonce validation) | Not yet implemented |
| RFC conformance test vectors | Not yet implemented |
| IETF Internet-Draft | draft-litzki-sovp-05 (prepared, submission pending) |
| U.S. Provisional Patent | Filed — No. 64/005,737 |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

The SOVP protocol specification is intellectual property of Litzki Systems LLC. Patent pending.

---

[Litzki Systems LLC](https://litzki-systems.com) · St. Petersburg, FL · [info@litzki-systems.com](mailto:info@litzki-systems.com)
