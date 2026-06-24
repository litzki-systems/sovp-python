#!/usr/bin/env python3
# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0
#
# Shows how a SOVP v1 entry looks inside an ai-catalog.json trustManifest.
# This is the pattern being proposed in ards-project/ard-spec issue #41.
#
# Run: python examples/ard_trust_manifest.py

import hashlib
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sovp.core import generate_keypair, generate_identity_document, verify_identity

try:
    from canonicaljson import encode_canonical_json
except ImportError:
    print("Install canonicaljson: pip install canonicaljson", file=sys.stderr)
    sys.exit(1)

print("=== SOVP ARD trustManifest Example ===\n")

# ── Step 1: Produce a signed sovp-identity.json ────────────────────────────────
private_key_b64, public_key_b64 = generate_keypair()

document = generate_identity_document(
    private_key_b64=private_key_b64,
    entity_uid="urn:sovp:example-publisher",
    canonical_url="https://publisher.example",
)

# ── Step 2: Compute contentAddress over the non-proof, non-contentAddress fields
#
# The digest covers the same byte range that the Ed25519 signature covers:
# JCS(document minus integrity_proof minus contentAddress).
# This lets a catalog consumer verify content identity without re-running Ed25519.
signed_fields = {k: v for k, v in document.items()
                 if k not in ("integrity_proof", "contentAddress")}
canonical_bytes = encode_canonical_json(signed_fields)
digest_hex = hashlib.sha256(canonical_bytes).hexdigest()

document["contentAddress"] = {"digest": f"sha256:{digest_hex}"}

print("sovp-identity.json (with contentAddress):")
print(json.dumps(document, indent=2))
print()

# ── Step 3: Build the ai-catalog.json entry (trustManifest type) ───────────────
#
# This is the structure an ARD-compliant catalog producer emits.
# The `contentAddress` here matches the one inside the SOVP document,
# giving downstream agents a single hash to pin before fetching the full
# identity document.
catalog_entry = {
    "schemaVersion": "ard/1.0",
    "type": "trustManifest",
    "uri": "https://publisher.example/.well-known/sovp-identity.json",
    "contentAddress": {
        "digest": f"sha256:{digest_hex}"
    },
    "sovp": {
        "draftVersion": "draft-litzki-sovp-03",
        "entityUid": document["entity"]["uid"],
        "canonicalUrl": document["entity"]["canonical_url"],
        "publicKeyRef": document["integrity_proof"]["public_key_ref"]
    }
}

print("ai-catalog.json entry (trustManifest):")
print(json.dumps(catalog_entry, indent=2))
print()

# ── Step 4: Consuming agent verifies the chain ─────────────────────────────────
#
# 1. Fetch the SOVP document from catalog_entry["uri"].
# 2. Recompute the digest and compare to catalog_entry["contentAddress"]["digest"].
# 3. Run SOVP Psi_core check to confirm infrastructure trust.

fetched_doc = document  # in production: HTTP GET catalog_entry["uri"]

recomputed_fields = {k: v for k, v in fetched_doc.items()
                     if k not in ("integrity_proof", "contentAddress")}
recomputed_bytes = encode_canonical_json(recomputed_fields)
recomputed_digest = "sha256:" + hashlib.sha256(recomputed_bytes).hexdigest()

digest_ok = recomputed_digest == catalog_entry["contentAddress"]["digest"]
print(f"contentAddress match : {'PASS' if digest_ok else 'FAIL'}")

signature = fetched_doc["integrity_proof"]["signature"]
psi_core = verify_identity(fetched_doc, signature, public_key_b64)
print(f"Psi_core             : {'1  VERIFIED' if psi_core else '0  BLOCKED'}")

assert digest_ok and psi_core, "Chain verification failed."
print("\n=== Done — full trustManifest chain verified ===")
