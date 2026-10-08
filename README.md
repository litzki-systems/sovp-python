# sovp-python

**sovp-python** is the reference implementation of the [Sovereign Validation Protocol (SOVP)](https://litzki-systems.com/sovp), a pre-ingestion verification protocol for validating a signed identity document before its contents are ingested. SOVP verifies that the document was signed by the party controlling an Ed25519 public key published for the document host in DNS. It operates at Layer 0, before the document body is ingested. To get started: clone the repo and run `pip install -e .`. This exposes the `sovp.core` Python API and the `sovp` CLI.

> **Protocol specification:** [draft-litzki-sovp](https://datatracker.ietf.org/doc/draft-litzki-sovp/) — IETF Internet-Draft

[![CI](https://github.com/litzki-systems/sovp-python/actions/workflows/ci.yml/badge.svg)](https://github.com/litzki-systems/sovp-python/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![IETF Draft](https://img.shields.io/badge/IETF-draft--litzki--sovp-lightgrey.svg)](https://datatracker.ietf.org/doc/draft-litzki-sovp/)
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

> **Scope of this reference implementation:** This library provides Ed25519 signing and verification primitives for SOVP identity documents, plus DNS TXT record resolution and HTTP retrieval of `sovp-identity.json` via `sovp.resolver` (`resolve_dns_pubkey()`, `fetch_identity_document()`, `validate_domain()`). Mode B gateway behavior — an active, caching relay rather than a one-shot check — is implementation-defined and not included in this package.

---

## Protocol scope

SOVP defines a narrow cryptographic validation boundary at Layer 0. The core verification function is:

`Psi_core = Verify(K_pub, sigma, JCS(M))`

where the public key is resolved from the host's `_sovp` DNS TXT records. For schema v2.0, the signed document also carries freshness data, including `created` and `expiresAt`. The reference resolver validates the document against the expected host and applies the v2.0 freshness rules.

SOVP establishes that the signed document is attributable to the party controlling the DNS-published Ed25519 key. Optional instance binding can associate a signed document with an expected instance identifier. Instance binding does not establish that a process is running as that instance.

SOVP does not establish legal identity, semantic accuracy or truthfulness, security posture, configuration or hardening state, runtime behavior, requester authorization, or permission to perform an action. Those properties require separate evidence and policy mechanisms. SOVP claims should therefore be composed with other systems only through explicit, separately defined evidence and claim semantics.

`contentAddress` provides an unsigned SHA-256 content identity over the same JCS representation used for the signature. It supports content consistency and downstream binding. It does not provide authenticity and must not be used as a substitute for signature verification.

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

This installs the `sovp` CLI and the `sovp.core` library. Dependencies (`cryptography`, `jcs`, `dnspython`, `requests`) are declared in `pyproject.toml`.

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
psi_core = verify_identity(
    document,
    signature,
    public_key_b64,
    expected_host="example.com",
)
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
from sovp.core import generate_identity_document
import json

# Schema v2.0 (current default): created/nonce/expiresAt live in a signed
# "freshness" object, not in the unsigned integrity_proof. Use this helper
# rather than assembling the document by hand — see "Low-level signing
# primitive" below for what it does internally.
signed_payload = generate_identity_document(
    private_key_b64,
    entity_uid="urn:sovp:your-entity-id",
    canonical_url="https://yourdomain.com",
)

with open("sovp-identity.json", "w") as f:
    json.dump(signed_payload, f, indent=2)
```

#### Low-level signing primitive

`generate_identity_document()` above is built on `sign_identity()`, the raw Ed25519-over-JCS primitive with no schema opinion of its own — shown here for anyone assembling a document shape by hand:

```python
from sovp.core import sign_identity

# Non-proof fields only — integrity_proof is always excluded from the signed scope
# (draft Section 4 MUST). sign_identity() will strip it automatically if present.
metadata = {
    "@context": "https://litzki-systems.com/protocol/v2.0",
    "@type": "SovereignIdentity",
    "entity": {
        "uid": "urn:sovp:your-entity-id",
        "canonical_url": "https://yourdomain.com",
        "verification_method": "Ed25519"
    },
    "freshness": {
        "created": "2026-01-01T00:00:00Z",
        "expiresAt": "2026-04-01T00:00:00Z"
    }
}

signature = sign_identity(private_key_b64, metadata)

signed_payload = {
    **metadata,
    "integrity_proof": {
        "signature": signature,
        "public_key_ref": "dns:txt:_sovp.yourdomain.tld"
    }
}
```

> `sign_identity()` always strips `integrity_proof` before canonicalizing, so
> callers may pass the full document or only the non-proof fields — the result
> is identical. The signature cannot cover itself.

#### Verify (Psi_core)

```python
from sovp.core import verify_identity

# Pass the full document or the non-proof subset — both work identically.
# Enable check_timestamp=True to enforce the 600-second issuance window
# defined by Draft 04 Section 7.2.
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
| Freshness | Signed `freshness.created` and `freshness.expiresAt` validation; the reference resolver applies the 600 s issuance window when timestamp checking is enabled |

---

## The sovp-identity.json schema

```json
{
  "@context": "https://litzki-systems.com/protocol/v2.0",
  "@type": "SovereignIdentity",
  "entity": {
    "uid": "urn:sovp:your-entity-id",
    "canonical_url": "https://yourdomain.com",
    "verification_method": "Ed25519"
  },
  "freshness": {
    "created": "2026-03-19T10:00:00Z",
    "nonce": "optional-unique-string",
    "expiresAt": "2026-06-17T10:00:00Z"
  },
  "integrity_proof": {
    "signature": "<Ed25519 signature, base64>",
    "public_key_ref": "dns:txt:_sovp.yourdomain.tld"
  },
  "contentAddress": {
    "alg": "sha256",
    "digest": "<hex-encoded SHA-256 over JCS-canonical bytes of the non-proof fields>"
  }
}
```

> **`freshness` (schema v2.0):** `created`, `nonce`, and `expiresAt` live in
> this object, which IS part of the signed scope — unlike schema v1.4, where
> these three fields sat inside `integrity_proof` and were therefore
> forgeable without invalidating the signature (`integrity_proof` itself is
> excluded from the signed scope). A v1.4 document's `expiresAt` in
> particular could be pushed arbitrarily into the future by anyone able to
> modify the served file, without breaking the signature. `verify_identity()`
> reads `freshness.created` first and falls back to the unsigned
> `integrity_proof.created` only for documents that predate this change.

> **`contentAddress` (optional, draft Section 4):** `contentAddress.digest` is a SHA-256 hash computed over the JCS-canonical representation of all non-proof, non-`contentAddress` fields. A verifier independently recomputes it as `sha256(JCS(doc_without_proof_and_contentAddress))` and compares the hex string. This lets downstream consumers (e.g. an `ai-catalog.json` entry) bind a catalog record to the exact document bytes without re-running the Ed25519 signature check. **`contentAddress` is excluded from the Ed25519 signed scope** — it is computed after signing, from the same byte range the signature covers.

Serve this file at `https://yourdomain.com/.well-known/sovp-identity.json`.

---

## DNS setup

```
_sovp.yourdomain.tld  IN  TXT  "v=SOVP1; k=<your-Ed25519-public-key-base64>"
```

Recommended TTL: 300 seconds (per draft Section 6.1). DNSSEC recommended for the `_sovp` zone.

> Automatic DNS resolution is implemented in `sovp.resolver.resolve_dns_pubkey()` (see "Live validation example" below and the Roadmap). `verify_identity()` itself remains a pure function and still expects the key to be supplied directly; `sovp.resolver` is what resolves it from DNS on the caller's behalf.

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
| `contentAddress` digest (SHA-256 over JCS bytes) | Implemented |
| DNS + HTTP resolution in `SOVPValidator` | Implemented — see `sovp.resolver` |
| RFC conformance test vectors | Implemented — see `tests/test_vectors.py` |
| Live validation (`validate_live.py`) | Implemented |
| AgenTrust Marketplace integration | Implemented — see [sovp-agentrust-bridge](https://github.com/litzki-systems/sovp-agentrust-bridge) |
| Reference identity-endpoint deployment (Cloudflare Worker) | Implemented — see `workers/sovp-identity`; deployment requires a fresh Draft 04 document and matching DNS key |
| Replay protection — nonce deduplication | Planned |
| `SOVPIdentity` / `SOVPSigner` / `SOVPValidator` class API | Planned |
| IETF Internet-Draft | [draft-litzki-sovp](https://datatracker.ietf.org/doc/draft-litzki-sovp/) — active |
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
