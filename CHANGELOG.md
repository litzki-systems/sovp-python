# Changelog

All notable changes to the sovp Python package are documented here.
Protocol specification: [draft-litzki-sovp-04](https://datatracker.ietf.org/doc/draft-litzki-sovp/)

## [1.1.1] — 2026-10-09

External review of the published surface (report V11) found that the documented
live-validation path could not succeed against any real deployment, including
the reference deployment. This release fixes that and the documentation defects
found alongside it. No wire format, no schema and no signed scope changed.

### Fixed
- `sovp/resolver.py` — `validate_domain()` passed `check_timestamp=True`
  unconditionally, which enforced the issuance window of draft Section 9.4
  (default `W = 600 s`) against `freshness.created`. A statically published
  `.well-known` document is re-signed on its validity cycle, not per request,
  so the window could never be satisfied: `validate_domain("litzki-systems.com")`
  returned `psi_core = 0` for a correctly signed, unexpired document. The
  window is now opt-in via a new `check_timestamp` parameter, default `False`.
  `freshness.expiresAt` is still always enforced, as is host binding.
- `sovp/core.py` — `generate_identity_document()` defaulted
  `freshness.expiresAt` to `created + 1 hour`, while its own docstring (and
  draft Section 10) stated that `expiresAt` was omitted unless the caller
  supplied it. Both statements were wrong. The default is now
  `created + DEFAULT_VALIDITY_DAYS` (90 days), matching what the production
  deployments publish, and the docstring says so.
- `README.md` — the "Live validation example" told the reader to run
  `python examples/validate_live.py`, a file the PyPI distribution does not
  contain, and printed an expected output with `Psi_core: 1` (actually `0`,
  see above) and `Entity UID: urn:sovp:litzki-systems.com` (actually
  `urn:sovp:litzki-systems-llc`). The section is now a three-line example over
  the installed API with its real output, and it says that `examples/` lives in
  the repository only.
- `README.md` — two dead draft cross-references: the issuance window was cited
  as "Section 7.2", which does not exist in revision 04 (Section 7 has no
  subsections); it is Section 9.4. The 300-second DNS TTL recommendation was
  cited as Section 6.1; it is Section 9.3. The 1.1.0 changelog entry carried
  the same wrong number and is corrected in place.

### Added
- `sovp/core.py` — `verify_identity_detail()`, returning
  `(verified, reason)`. `verify_identity()` keeps its boolean contract and is
  now a thin wrapper around it.
- `sovp/resolver.py` — `validate_domain()` returns a `reason` field naming the
  first failed check: `ok`, `host_mismatch`, `signature`, `freshness_missing`,
  `freshness_invalid`, `created_in_future`, `expired`, `issuance_window`,
  `no_key`. A silent `0` could not distinguish an expired document from a
  forged one.
- `sovp/core.py` — `DEFAULT_VALIDITY_DAYS = 90` and the `REASON_*` constants,
  both exported from the `sovp` package.
- `tests/` — seven tests: the two-day-old document that must verify by default
  (the regression this release exists for), the window when explicitly
  requested, `reason` for expiry vs. signature vs. host mismatch, the 90-day
  default and an explicit override, and `verify_identity_detail()`'s reason
  codes. 80 tests pass.

### Changed
- `pyproject.toml` — `requires-python = ">=3.9"` declared; the README badge
  claimed 3.9+ but the metadata named no floor.
- `README.md` — Roadmap: the ARD `trustManifest` registration is "Proposed —
  open issue", not "In progress"; the live-validation row names
  `validate_domain()` instead of the unshipped example file.

## [1.1.0] — 2026-10-09

### Added
- `sovp/core.py` — `generate_identity_document()` now signs a `freshness` object (`created`, `nonce`, `expiresAt`) as part of the Ed25519-signed scope; default `context_version` changed from `"v1.4"` to `"v2.0"`. Previously these fields lived inside the unsigned `integrity_proof` and were forgeable without invalidating the signature — same weakness as the already-documented `expiresAt` forgeability in `sovp-engine`'s scanner. Closes the replay-protection gap described in `draft-litzki-sovp-04`.
- `tests/test_vectors.py` — Test Vector Set 2 (schema v2.0, real generated+verified signatures) covering the new `freshness` object, including tamper rejection for `freshness.created`/`freshness.expiresAt`. Test Vector Set 1 (v1.4, locked) is unchanged.
- `sovp/document_safety.py` — `parse_unverified_sovp_document()`, a minimal JSON parser enforcing draft-litzki-sovp-04's "Resource Limits for Unverified Documents": rejects a document larger than 64 KiB, nested deeper than 16 levels, or containing a duplicate member name in any object, before the document is trusted with any further processing.

### Changed
- `pyproject.toml` — the `cryptography` bound stays at `>=38.0.0,!=40.0.0,!=40.0.1,<42`. It matches the `Requires-Dist` line of the OS-packaged pyOpenSSL 23.2.0 on Ubuntu 24.04, which `certbot` imports. A global `pip install sovp` with a higher bound shadows that version and breaks certificate renewal. The library itself runs on newer `cryptography` releases; the bound protects the system install.
- `CHANGELOG.md` — the 1.0.1 entry referenced a parameter count. It now states that the parameter count references were aligned with the protocol specification.
- `README.md` — the introduction names `pip install sovp` as the normal installation route and keeps the editable clone for development.
- `sovp/core.py` — `verify_identity()`'s `check_timestamp` path now reads `freshness.created` first and falls back to the unsigned `integrity_proof.created` only for documents whose `@context` predates v2.0; this fallback affects timestamp freshness checking only, never signature verification.
- `README.md` — schema example and "Replay protection" table row updated to the v2.0/`freshness` shape; added an explicit callout that the tamper-resistance guarantee is new as of v2.0 and did not hold under v1.4.
- `README.md` — `contentAddress` example corrected from the stale prefixed `"sha256:<hex>"` single-field form to the shape `generate_identity_document()` actually ships: `{"alg": "sha256", "digest": "<hex>"}`.
- `README.md` — removed the `parameters` (`entropy_threshold`/`determinism_score`) field from the schema example; it does not exist in any reference implementation (`sovp-python`, `sovp-engine`, or the Cloudflare Worker) and was never anything other than an illustrative artifact. Found while reconciling `draft-litzki-sovp-04` against the running implementations — the draft's own schema example had the same field, removed there too.
- `sovp/core.py` — Draft 04 host binding is enforced through `expected_host`; v2.0 freshness remains signed and expiry is always validated. Generated DNS key references use the URL hostname, excluding ports and normalizing trailing dots and case.
- `sovp/resolver.py` — DNS TXT parsing now accepts only the exact `v=SOVP1; k=<base64>` record shape and requires a valid 32-byte Ed25519 public key. Legacy endpoint fallback remains restricted to HTTP 404.
- `examples/` — live validation, end-to-end verification, and the ARD trustManifest example now identify Draft 04 explicitly and demonstrate v2.0 host binding and the current `contentAddress` shape.
- `workers/sovp-identity/` — the reference worker now serves a publisher-supplied, pre-signed Draft 04 v2.0 document from a Cloudflare secret instead of embedding a stale v1.4 artifact.

### Fixed
- `tests/test_vectors.py` — `contentAddress.digest` in Test Vector Set 2 was wrong. The vector shipped `33465a2b…3ae2b5`; the correct value over `sha256(JCS(signed scope))` is `d00c6db5…30b460`. No test read the field, so the vector and the specification drifted apart unnoticed.
- `sovp/core.py` — `verify_identity()` no longer fails open when `integrity_proof.created` is missing; with `check_timestamp=True` a missing `created` is now a rejection (Psi_core = 0), closing a replay bypass of draft Section 9.4
- `sovp/core.py` — `verify_identity()` no longer raises `AttributeError` when `integrity_proof` is a non-dict value (attacker-controlled since it's excluded from the signed payload); now returns `False` per the documented `bool`-only contract
- `sovp/resolver.py` — `fetch_identity_document()` used `resp.json()` (== `json.loads()`) to parse a remote, not-yet-signature-checked document, with no size, depth, or duplicate-key limit. Now parses via `parse_unverified_sovp_document()`.

### Tests
- `tests/test_vectors.py` — two tests now recompute `contentAddress.digest` from Test Vector Set 2 itself and assert that a change inside the signed scope changes the recomputed digest. This keeps the vector and the specification from drifting apart again.
- Added Draft 04 conformance coverage for freshness clock-skew boundaries, the 600-second issuance window, signed unknown top-level members, unsigned `contentAddress` and `scan` extensions, host normalization, URL ports, and exact DNS TXT syntax.

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
- Parameter count references in the documentation aligned with the protocol specification

## [1.0.0] — 2026-06-01

### Added
- Initial release
- `sovp.core` primitives: `generate_keypair()`, `sign_identity()`, `verify_identity()`
- `generate_identity_document()` — builds complete `sovp-identity.json`
- CLI: `sovp generate-keypair`, `sovp sign`, `sovp verify`
- Replay protection via timestamp validation (`check_timestamp=True`, 600s window)
- Apache 2.0 license
