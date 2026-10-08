#!/usr/bin/env python3
# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0
#
# Shows how a SOVP v2.0 identity document can be referenced from an
# ai-catalog.json trustManifest entry.
#
# Run: python examples/ard_trust_manifest.py

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import jcs

from sovp.core import generate_keypair, generate_identity_document, verify_identity

print("=== SOVP ARD trustManifest Example ===\n")

# Step 1: Produce a signed schema v2.0 sovp-identity.json document.
private_key_b64, public_key_b64 = generate_keypair()

document = generate_identity_document(
    private_key_b64=private_key_b64,
    entity_uid="urn:sovp:example-publisher",
    canonical_url="https://publisher.example",
)

digest_hex = document["contentAddress"]["digest"]

print("sovp-identity.json:")
print(json.dumps(document, indent=2))
print()

# Step 2: Build an ai-catalog.json reference.
catalog_entry = {
    "schemaVersion": "ard/1.0",
    "type": "trustManifest",
    "uri": "https://publisher.example/.well-known/sovp-identity.json",
    "contentAddress": {
        "alg": "sha256",
        "digest": digest_hex,
    },
    "sovp": {
        "draftVersion": "draft-litzki-sovp-04",
        "entityUid": document["entity"]["uid"],
        "canonicalUrl": document["entity"]["canonical_url"],
        "publicKeyRef": document["integrity_proof"]["public_key_ref"],
    },
}

print("ai-catalog.json entry (trustManifest):")
print(json.dumps(catalog_entry, indent=2))
print()

# Step 3: The consuming agent recomputes the unsigned content identity.
fetched_doc = document

recomputed_fields = {
    key: value
    for key, value in fetched_doc.items()
    if key not in ("integrity_proof", "contentAddress", "scan")
}
recomputed_bytes = jcs.canonicalize(recomputed_fields)
recomputed_digest = hashlib.sha256(recomputed_bytes).hexdigest()

digest_ok = recomputed_digest == catalog_entry["contentAddress"]["digest"]
print(f"contentAddress match : {'PASS' if digest_ok else 'FAIL'}")

# Step 4: Verify the signed document and its host binding.
signature = fetched_doc["integrity_proof"]["signature"]
psi_core = verify_identity(
    fetched_doc,
    signature,
    public_key_b64,
    expected_host="publisher.example",
)
print(f"Psi_core             : {'1  VERIFIED' if psi_core else '0  BLOCKED'}")

assert digest_ok and psi_core, "Draft 04 verification chain failed."
print("\n=== Done — trustManifest reference verified ===")
