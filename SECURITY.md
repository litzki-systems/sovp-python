# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a Vulnerability

To report a security vulnerability in the SOVP reference implementation or
protocol specification, please email:

**security@litzki-systems.com**

Do not open a public GitHub issue for security vulnerabilities.

We will acknowledge receipt within 72 hours and aim to resolve confirmed
vulnerabilities within 30 days. We will coordinate disclosure timing with
the reporter.

## Scope

This policy covers:
- The `sovp` Python package (`sovp.core`, `sovp.resolver`, `sovp.cli`)
- The SOVP protocol specification (`draft-litzki-sovp-03`)

This policy does not cover third-party dependencies. Please report
vulnerabilities in `cryptography`, `dnspython`, or `requests` to their
respective maintainers.

## Cryptographic Foundations

SOVP uses Ed25519 (RFC 8032) for signatures and RFC 8785 JCS for
canonicalization. Known limitations and threat model are documented in
the Security Considerations section of `draft-litzki-sovp-03`.
