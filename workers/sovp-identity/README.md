# SOVP Identity Worker

Cloudflare Worker reference deployment for a Draft 04 SOVP identity endpoint.

The worker serves a pre-signed schema v2.0 `sovp-identity.json` document at
`/.well-known/sovp-identity.json` and `/sovp-identity.json`. The signed document
is supplied through the Cloudflare secret `SOVP_IDENTITY_JSON`, so the repository
contains no private signing key and no stale static signature.

## What this demonstrates

* Schema v2.0 with signed `freshness.created` and `freshness.expiresAt`
* Ed25519 signature over the JCS canonicalized signed scope
* `contentAddress` as an optional unsigned content identity
* DNS TXT reference format: `v=SOVP1; k=<raw-Ed25519-public-key-base64>`
* Serving host validation against `entity.canonical_url`
* The well-known endpoint defined by Draft 04

The worker does not generate or verify the Ed25519 signature. Signature generation
belongs to the publisher. Generate the document with the reference implementation,
publish its public key in DNS, and provide the complete signed JSON document to the
worker as a secret.

## Prepare a Draft 04 document

Use `sovp-python` to generate a fresh v2.0 document:

```python
from sovp.core import generate_keypair, generate_identity_document
import json

private_key_b64, public_key_b64 = generate_keypair()

document = generate_identity_document(
    private_key_b64=private_key_b64,
    entity_uid="urn:sovp:yourdomain.com",
    canonical_url="https://yourdomain.com",
)

print(json.dumps(document, indent=2))
print("Publish this public key in DNS:", public_key_b64)
```

Publish the returned public key under:

```
_sovp.yourdomain.com  IN  TXT  "v=SOVP1; k=<public_key_b64>"
```

The DNS key and the document signature must come from the same keypair.

## Configure the Worker

Store the complete generated JSON document as a Cloudflare Worker secret:

```bash
wrangler secret put SOVP_IDENTITY_JSON
```

Then deploy:

```bash
wrangler deploy
```

Generate a fresh document before its signed freshness window expires and update
the secret as part of the deployment process.

## Verification

The repository reference resolver verifies:

1. the well-known document retrieval,
2. the DNS-published Ed25519 key,
3. the serving-host binding,
4. the v2.0 freshness fields,
5. the Ed25519 signature over the JCS signed scope.

Run the live validation example with:

```bash
python examples/validate_live.py
```

## Protocol specification

[draft-litzki-sovp](https://datatracker.ietf.org/doc/draft-litzki-sovp/)
