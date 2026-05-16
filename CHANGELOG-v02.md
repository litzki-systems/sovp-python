# SOVP Draft V02 — Planned Changes

Status: Pending first IETF feedback. Items below are confirmed for inclusion in draft-litzki-sovp-02.

## 1. Section 7.2 — Remove stale "not yet implemented" note
Current text: "timestamp and nonce validation are not yet implemented in the reference implementation and are planned for a future release."
Problem: Timestamp validation is now implemented via check_timestamp=True in verify_identity().
Fix: Remove the note. Replace with: "Timestamp validation is implemented in the reference implementation via the check_timestamp parameter of verify_identity(). Nonce-based deduplication remains a future work item."

## 2. Section 4 — Resolve @context version (v1.4 vs v1.5)
Problem: Draft shows v1.4; reference implementation used v1.5. Tests realigned to v1.4 for now.
Fix: Confirm canonical version. Update draft and implementation to single consistent value. Define versioning policy (what a context version bump implies).

## 3. Section 6 / New sub-section — DNS TXT Record Format (normative)
Problem: Section 9.1 registers the _sovp DNS label but specifies no TXT record value format. README uses v=SOVP1; k=<base64> non-normatively.
Fix: Add normative sub-section: "A DNS TXT record for SOVP MUST use the format: v=SOVP1; k=<public-key-base64> where <public-key-base64> is the standard (RFC 4648) base64 encoding of the 32-byte Ed25519 public key."

## 4. Section 9.2 — SOVP-Identity Header Value Syntax (normative)
Problem: Header name is registered but value syntax is completely unspecified.
Fix: Add: "The value of the SOVP-Identity header MUST be the standard (RFC 4648) base64 encoding of the 32-byte Ed25519 public key. Example: SOVP-Identity: <base64-encoded-32-byte-public-key>"

## 5. Section 3 — Public Key Encoding (normative)
Problem: K_pub is referenced in the formula but no encoding format is defined.
Fix: Add: "Ed25519 public keys MUST be encoded using standard base64 (RFC 4648 Section 4) when represented in DNS TXT records or HTTP headers. The encoded key MUST represent exactly 32 bytes of raw Ed25519 public key material."

## 6. Section 3 — Pure Mode Clarification Note
Problem: The Psi_core formula could be misread as implying an external pre-hash.
Fix: Add note: "Ed25519 in pure mode (RFC 8032 Section 5.1) applies SHA-512 internally. Implementations MUST NOT apply any external hash function to JCS(M) before passing it to the Ed25519 sign or verify operation."

## 7. Section 7 — New Section 7.3.1: Origin Binding Enforcement (MUST)
Problem: Nothing in the draft prevents a key from _sovp.attacker.com verifying a document claiming canonical_url of a different domain.
Fix: Add Section 7.3.1: "A Validating Agent performing full protocol execution MUST verify that the domain from which the public key was retrieved matches the domain serving the sovp-identity.json artifact. Mismatched domains MUST result in Psi_core = 0."

## 8. Section 3 or Appendix — RFC 8785 Library Compliance Note
Problem: Non-RFC-8785 libraries (e.g. Matrix canonical JSON) produce different output for floating-point values.
Fix: Add: "Implementations MUST use an RFC 8785-compliant JCS library. Floating-point numbers MUST be serialized per RFC 8785 Section 3.2.2. Non-compliant canonical JSON libraries MUST NOT be used."

## 9. Introduction or Appendix — Reference Implementation Scope Statement
Problem: The Python reference implementation provides signing/verification primitives only. DNS resolution, HTTP retrieval, and Mode B gateway behavior are absent but not disclosed in the draft.
Fix: Add: "The reference implementation provides signing and verification primitives only. Full protocol execution including DNS resolution and HTTP retrieval is implementation-defined."
