#!/usr/bin/env python3
# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end SOVP walkthrough: generate keys, sign an identity document,
# verify it, and confirm that tampering is detected.
#
# Run: python examples/end_to_end.py

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sovp.core import generate_keypair, generate_identity_document, verify_identity

print("=== SOVP End-to-End Example ===\n")

# ── Step 1: Generate an Ed25519 keypair ────────────────────────────────────────
private_key_b64, public_key_b64 = generate_keypair()
print(f"Public key  : {public_key_b64}")
print(f"Private key : {private_key_b64[:20]}...  (keep secret)\n")

# Publish public_key_b64 in DNS:
#   _sovp.yourdomain.tld  IN  TXT  "v=SOVP1; k=<public_key_b64>"

# ── Step 2: Build and sign a sovp-identity.json document ──────────────────────
document = generate_identity_document(
    private_key_b64=private_key_b64,
    entity_uid="urn:sovp:example-entity",
    canonical_url="https://example.com",
)
print("Signed sovp-identity.json:")
print(json.dumps(document, indent=2))
print()

# Serve this at: https://example.com/.well-known/sovp-identity.json

# ── Step 3: Verify — Psi_core resonance check ─────────────────────────────────
signature = document["integrity_proof"]["signature"]

psi_core = verify_identity(document, signature, public_key_b64)
print(f"Psi_core = {'1 ✓  Verified — ingestion may proceed.' if psi_core else '0 ✗  Blocked.'}")
assert psi_core, "Verification should pass for an unmodified document."

# ── Step 4: Tamper detection ───────────────────────────────────────────────────
tampered = json.loads(json.dumps(document))
tampered["entity"]["canonical_url"] = "https://attacker.com"

psi_tampered = verify_identity(tampered, signature, public_key_b64)
print(f"Psi_core = {'1' if psi_tampered else '0 ✗  Tamper detected — ingestion blocked.'}")
assert not psi_tampered, "Verification should fail after tampering."

print("\n=== Done ===")
