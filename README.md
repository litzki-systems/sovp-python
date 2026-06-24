# sovp-python

**sovp-python** is the reference implementation of the [Sovereign Validation Protocol (SOVP)](https://litzki-systems.com/sovp) — a pre-ingestion verification protocol that lets LLMs and autonomous agents cryptographically confirm the identity and integrity of a data source before parsing it. It exists because existing mechanisms (DANE, DIDs, TLS) operate at the wrong layer for agentic pipelines: SOVP sits at Layer 0, before the body is read. To get started: clone the repo and run `pip install -e .` — this exposes both a `sovp.core` Python API and a `sovp` CLI with three commands.

> **Protocol specification:** [draft-litzki-sovp-03](https://datatracker.ietf.org/doc/draft-litzki-sovp/) — IETF Internet-Draft

[![CI](https://github.com/litzki-systems/sovp-python/actions/workflows/ci.yml/badge.svg)](https://github.com/litzki-systems/sovp-python/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--litzki--sovp--03-lightgrey.svg)](https://datatracker.ietf.org/doc/draft-litzki-sovp/)
[![Status](https://img.shields.io/badge/Status-Patent_Pending-orange.svg)](https://litzki-systems.com/sovp)

---

## What SOVP does

SOVP answers one question deterministically: does this data originate from the declared entity, and has it been tampered with?

It does **not** validate semantic accuracy or truthfulness. It validates identity and integrity only.

```
Psi_core = Verify(K_pub, sigma, JCS(M))
```

`Psi_core = 1` — source verified, proceed with ingestion.  
`Psi_core = 0` — verification failed, ingestion blocked.

> **Scope of this reference implementation:** This library provides Ed25519 signing and verification primitives for SOVP identity documents. Full protocol execution — including DNS TXT record resolution, HTTP retrieval of `/.well-known/sovp-identity.json`, and Mode B gateway behavior — is implementation-defined and not included in this package.

---

## Position in the agentic trust stack

SOVP is the infrastructure attestation layer inside a broader agentic trust stack. The four layers, from discovery to runtime:

| Layer | Concern | Mechanism |
|---|---|---|
| **Discovery** | Is the source findable and routable? | DNS, service registries, `ai-catalog.json` |
| **Install safety** | Is the artifact what it claims to be before execution? | `contentAddress` digest (SHA-256 over JCS bytes), SOVP `trustManifest` type |
| **Infrastructure trust** | Does the serving entity control the domain and key? | SOVP `sovp-identity.json`, `_sovp` DNS TXT, Ed25519 proof |
| **Runtime governance** | Is the agent permitted to act on this data in this context? | Policy engines, capability tokens, audit logs |

SOVP operates at **layers 2 and 3**. If you arrived here from [ards-project/ard-spec issue #41](https://github.com/ards-project/ard-spec/issues/41): the `trustManifest` type in an `ai-catalog.json` entry maps to layer 2 — it binds a catalog entry's `contentAddress` digest to an independently verifiable infrastructure attestation, so a consuming agent can confirm the entry was produced by the declared entity before acting on it.

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
pip install sovp
```

For development, clone the repo instead:

```bash
git clone https://github.com/litzki-systems/sovp-python.git
cd sovp-python
pip install -e .
```

This installs the `sovp` CLI and the `sovp.core` library. Dependencies (`cryptography`, `canonicaljson`) are declared in `pyproject.toml`.

---

## End-to-end example

The fastest way to see SOVP in action — generate a keypair, sign an identity document, verify it, and watch tamper detection fire:

```python
from sovp.core import generate_keypair, generate_identity_document, verify_identity

# 1. Generate keys — publish public_key_b64 in your DNS TXT record
private_key_b64, public_key_b64 = generate_keypair()

# 2. Build and sign — serve this JSON at /.well-known/sovp-identity.json
document = generate_identity_document(
    private_key_b64=private_key_b64,
    entity_uid="urn:sovp:example-entity",
    canonical_url="https://example.com",
)

# 3. Verify (Psi_core)
signature = document["integrity_proof"]["signature"]
psi_core = verify_identity(document, signature, public_key_b64)
print("Psi_core =", 1 if psi_core else 0)   # → 1

# 4. Tamper detection
document["entity"]["canonical_url"] = "https://attacker.com"
psi_core = verify_identity(document, signature, public_key_b64)
print("Psi_core =", 1 if psi_core else 0)   # → 0  (blocked)
```

A runnable version with annotated output is in [`examples/end_to_end.py`](examples/end_to_end.py):

```bash
python examples/end_to_end.py
```

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

# Non-proof fields only — integrity_proof is always excluded from the signed scope
# (draft-litzki-sovp-03, Section 4 MUST). sign_identity() will strip it automatically if present.
metadata = {
    "@context": "https://litzki-systems.com/protocol/v1.4",
    "@type": "SovereignIdentity",
    "entity": {
        "uid": "urn:sovp:your-entity-id",
        "canonical_url": "https://yourdomain.com",
        "verification_method": "Ed25519"
    }
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

> `sign_identity()` always strips `integrity_proof` before canonicalizing, so
> callers may pass the full document or only the non-proof fields — the result
> is identical. The signature cannot cover itself.

#### Verify (Psi_core)

```python
from sovp.core import verify_identity

# Pass the full document or the non-proof subset — both work identically.
# Enable check_timestamp=True to enforce the 600-second validity window
# (draft Section 7.2 SHOULD).
psi_core = verify_identity(signed_payload, signature, public_key_b64, check_timestamp=True)

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
| Hashing | Ed25519 pure mode (RFC 8032) — `sign(JCS(M))`, no external pre-hash applied |
| Key distribution | DNS TXT at `_sovp.yourdomain.tld` |
| Replay protection | `created` timestamp validation (600 s window, `check_timestamp=True`); nonce deduplication not yet implemented — see Roadmap |

---

## The sovp-identity.json schema

```json
{
  "@context": "https://litzki-systems.com/protocol/v1.4",
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
  },
  "contentAddress": {
    "digest": "sha256:<hex-encoded SHA-256 over JCS-canonical bytes of the non-proof fields>"
  },
  "parameters": {
    "entropy_threshold": 0.12,
    "determinism_score": 0.98
  }
}
```

> **`contentAddress` (optional, draft-litzki-sovp-03 Section 4):** `contentAddress.digest` is a SHA-256 hash computed over the JCS-canonical representation of all non-proof, non-`contentAddress` fields. A verifier independently recomputes it as `sha256(JCS(doc_without_proof_and_contentAddress))` and compares the hex string. This lets downstream consumers (e.g. an `ai-catalog.json` entry) bind a catalog record to the exact document bytes without re-running the Ed25519 signature check. **`contentAddress` is excluded from the Ed25519 signed scope** — it is computed after signing, from the same byte range the signature covers.

> **Note:** `parameters` is non-normative and MUST NOT be used for trust
> decisions (draft Section 4). It is excluded from the signed scope.

Serve this file at `https://yourdomain.com/.well-known/sovp-identity.json`.

---

## DNS setup

```
_sovp.yourdomain.tld  IN  TXT  "v=SOVP1; k=<your-Ed25519-public-key-base64>"
```

Recommended TTL: 300 seconds (per draft Section 6.1). DNSSEC recommended for the `_sovp` zone.

> Automatic DNS resolution is not yet implemented. Keys must be supplied directly to `verify_identity()`. See Roadmap.

---

## Live validation example

To validate a live production domain (requires DNS + network access):

```bash
python examples/validate_live.py
```

This runs the full pipeline against `litzki-systems.com`: DNS TXT resolution, HTTP fetch of `/.well-known/sovp-identity.json`, and Ed25519 verification.

Expected output:
```
SOVP Live Validation — litzki-systems.com
Domain:          litzki-systems.com
Psi_core:        1
Public key ref:  dns:txt:_sovp.litzki-systems.com
Entity UID:      urn:sovp:litzki-systems.com
Canonical URL:   https://litzki-systems.com
Result: VERIFIED — identity and integrity confirmed.
```

---

## Roadmap

| Feature | Status |
|---|---|
| `sovp.core` primitives (`generate_keypair`, `sign_identity`, `verify_identity`) | Implemented |
| `sovp.core` document builder (`generate_identity_document`) | Implemented |
| CLI (`generate-keypair`, `sign`, `verify`) | Implemented |
| Replay protection — timestamp validation (`check_timestamp=True`) | Implemented |
| Replay protection — nonce deduplication | Planned |
| DNS + HTTP resolution in `SOVPValidator` | Implemented — see `sovp.resolver` |
| RFC conformance test vectors | Implemented — see `tests/test_vectors.py` |
| `SOVPIdentity` / `SOVPSigner` / `SOVPValidator` class API | Planned |
| IETF Internet-Draft | [draft-litzki-sovp-03](https://datatracker.ietf.org/doc/draft-litzki-sovp/) — active (updated 2026-06-09) |
| ARD `trustManifest` type registration | In progress — [ards-project/ard-spec #41](https://github.com/ards-project/ard-spec/issues/41) |
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
