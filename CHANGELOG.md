# Changelog

All notable changes to the sovp Python package are documented here.
Protocol specification: [draft-litzki-sovp-03](https://datatracker.ietf.org/doc/draft-litzki-sovp/)

## [Unreleased]

### Fixed
- `sovp/core.py` — `verify_identity()` no longer fails open when `integrity_proof.created` is missing; with `check_timestamp=True` a missing `created` is now a rejection (Psi_core = 0), closing a replay bypass of draft Section 7.2
- `sovp/core.py` — `verify_identity()` no longer raises `AttributeError` when `integrity_proof` is a non-dict value (attacker-controlled since it's excluded from the signed payload); now returns `False` per the documented `bool`-only contract

## [1.0.5] — 2026-08-29

### Fixed
- `pyproject.toml` — capped the unpinned `cryptography` dependency to `>=38.0.0,!=40.0.0,!=40.0.1,<42`. A global `pip install sovp` on a server also running `certbot`/`pyOpenSSL` (OS-packaged) could pull a `cryptography` release newer than pyOpenSSL supports, shadow the OS-packaged version, and break certbot with `AttributeError: module 'lib' has no attribute 'GEN_EMAIL'`. The cap matches the range pyOpenSSL 23.x (Ubuntu 24.04's apt version) actually declares support for.

## [1.0.4] — 2026-07-09

### Fixed
- Packaging: `sovp` source modules are now included in the built wheel
  (`[tool.setuptools.packages.find] include = ["sovp*"]`), so `pip install sovp`
  ships the importable `sovp.core`, `sovp.cli`, and `sovp.resolver` modules.

## [1.0.3] — 2026-06-09

### Added
- `workers/sovp-identity/` — Cloudflare Worker reference deployment for spec-compliant SOVP identity endpoint
- `workers/sovp-identity/README.md` — deployment guide with signing instructions

### Fixed
- `sovp-bridge.mjs` — spec-compliant Ed25519 signing in identity document (draft-litzki-sovp-02 Section 4). Signature now covers JCS-canonicalized non-proof fields, not certification token payload
- `sovp-bridge.mjs` — `canonicalize` default import fixed (`.default` instead of named destructuring)
- `sovp-identity-worker/index.mjs` — deployed new spec-compliant document, Psi_core = 1 confirmed end-to-end against litzki-systems.com
- DNS TXT record updated to `v=SOVP1; k=<raw-Ed25519-base64>` format per draft Section 6.1

## [1.0.2] — 2026-06-09

### Added
- `sovp/resolver.py` — full DNS TXT resolution (`_sovp.{domain}`) and HTTP fetch
  (`/.well-known/sovp-identity.json`) pipeline
- `validate_domain()` — single-call full validation: fetch + resolve + verify
- `fetch_identity_document()` — HTTP fetch with fallback path
- `resolve_dns_pubkey()` — DNS TXT resolution, parses `v=SOVP1; k=<base64>` format
- `SOVPResolverError` — resolver-specific exception class
- `tests/test_vectors.py` — RFC conformance test vectors (6 vectors, deterministic)
- `dnspython` and `requests` added as package dependencies

## [1.0.1] — 2026-06-09

### Fixed
- IETF Draft version references in README updated to `draft-litzki-sovp-02`
- `pyproject.toml` version corrected from `0.1.0-alpha` to `1.0.1`
- `readme = "README.md"` added to `pyproject.toml` — PyPI now renders full documentation
- Parameter count corrected to 268+ across all references

## [1.0.0] — 2026-06-01

### Added
- Initial release
- `sovp.core` primitives: `generate_keypair()`, `sign_identity()`, `verify_identity()`
- `generate_identity_document()` — builds complete `sovp-identity.json`
- CLI: `sovp generate-keypair`, `sovp sign`, `sovp verify`
- Replay protection via timestamp validation (`check_timestamp=True`, 600s window)
- Apache 2.0 license
