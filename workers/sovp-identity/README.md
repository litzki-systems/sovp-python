# SOVP Identity Worker

Cloudflare Worker reference deployment for a spec-compliant SOVP identity endpoint.

Serves `/.well-known/sovp-identity.json` and `/sovp-identity.json` with the correct
headers and a `SovereignIdentity` document signed per draft-litzki-sovp-02 Section 4.

## What this demonstrates

- How to serve a spec-compliant `sovp-identity.json` at the well-known URI
- Ed25519 signature over JCS-canonicalized non-proof fields (RFC 8785)
- DNS TXT record reference format: `v=SOVP1; k=<raw-Ed25519-base64>`

## Signing

The document embedded in `index.mjs` was signed using `sovp.core.sign_identity()`:

```python
from sovp.core import generate_keypair, generate_identity_document
private_key_b64, public_key_b64 = generate_keypair()
document = generate_identity_document(
    private_key_b64=private_key_b64,
    entity_uid="urn:sovp:yourdomain.com",
    canonical_url="https://yourdomain.com",
)
```

Publish `public_key_b64` in your DNS TXT record:
_sovp.yourdomain.com  IN  TXT  "v=SOVP1; k=<public_key_b64>"

## Deploy

```bash
npm install -g wrangler
wrangler deploy
```

## Protocol specification

[draft-litzki-sovp-02](https://datatracker.ietf.org/doc/draft-litzki-sovp/)
