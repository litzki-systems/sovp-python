# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import binascii

import dns.exception
import dns.resolver
import requests

from .core import (
    REASON_NO_KEY,
    REASON_SIGNATURE,
    verify_identity,  # noqa: F401  re-exported: callers import it from sovp.resolver
    verify_identity_detail,
)
from .document_safety import (
    UnverifiedDocumentLimitError,
    parse_unverified_sovp_document,
)


class SOVPResolverError(Exception):
    pass


def fetch_identity_document(domain: str, timeout: int = 10) -> dict:
    """
    Fetch the SOVP identity document.

    The well-known endpoint is authoritative. The legacy path is used only
    when the well-known endpoint returns HTTP 404.
    """
    primary_url = f"https://{domain}/.well-known/sovp-identity.json"
    fallback_url = f"https://{domain}/sovp-identity.json"
    headers = {"User-Agent": "sovp-resolver/1.1.1"}

    try:
        resp = requests.get(primary_url, timeout=timeout, headers=headers)
    except requests.RequestException as exc:
        raise SOVPResolverError(f"failed to retrieve {primary_url}: {exc}") from exc

    url = primary_url
    if resp.status_code == 404:
        url = fallback_url
        try:
            resp = requests.get(fallback_url, timeout=timeout, headers=headers)
        except requests.RequestException as exc:
            raise SOVPResolverError(f"failed to retrieve {fallback_url}: {exc}") from exc

    if resp.status_code != 200:
        raise SOVPResolverError(
            f"identity document returned HTTP {resp.status_code} at {url}"
        )

    try:
        return parse_unverified_sovp_document(resp.text)
    except UnverifiedDocumentLimitError as exc:
        raise SOVPResolverError(
            f"resource limit violated at {url}: {exc}"
        ) from exc


def _parse_sovp_txt_record(record: str) -> str | None:
    """
    Parse the exact Draft 04 DNS TXT syntax.

    A matching record consists of exactly:
        v=SOVP1; k=<standard-base64-Ed25519-public-key>
    """
    parts = [part.strip() for part in record.split(";")]
    if len(parts) != 2 or parts[0] != "v=SOVP1" or not parts[1].startswith("k="):
        return None

    key_b64 = parts[1][2:]
    if not key_b64:
        return None

    try:
        key_bytes = base64.b64decode(key_b64, validate=True)
    except (binascii.Error, ValueError):
        return None

    if len(key_bytes) != 32:
        return None

    return key_b64


def resolve_dns_pubkeys(domain: str, max_keys: int = 4) -> list[str]:
    """
    Resolve _sovp.{domain} TXT records.

    All matching v=SOVP1 records form an unordered key set for rotation.
    At most max_keys candidates are returned.
    """
    if max_keys < 1:
        raise ValueError("max_keys must be at least 1")

    txt_name = f"_sovp.{domain}"

    try:
        answers = dns.resolver.resolve(txt_name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        raise SOVPResolverError(
            f"DNS TXT record not found for {txt_name}: {exc}"
        ) from exc
    except dns.resolver.Timeout as exc:
        raise SOVPResolverError(
            f"DNS resolution timed out for {txt_name}: {exc}"
        ) from exc
    except dns.exception.DNSException as exc:
        raise SOVPResolverError(
            f"DNS resolution failed for {txt_name}: {exc}"
        ) from exc

    keys: list[str] = []
    for rdata in answers:
        record = "".join(
            chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
            for chunk in rdata.strings
        )
        key = _parse_sovp_txt_record(record)
        if key is None:
            continue
        keys.append(key)
        if len(keys) >= max_keys:
            break

    if not keys:
        raise SOVPResolverError(
            f"No valid SOVP1 TXT record found at {txt_name}. "
            "Expected format: v=SOVP1; k=<Ed25519-public-key-base64>"
        )
    return keys


def resolve_dns_pubkey(domain: str) -> str:
    """
    Resolve _sovp.{domain} TXT record and return one public key.

    This helper is retained for callers that need one display/reference key.
    Validation uses resolve_dns_pubkeys() so key rotation remains supported.
    """
    return resolve_dns_pubkeys(domain, max_keys=1)[0]


def validate_domain(
    domain: str,
    timeout: int = 10,
    check_timestamp: bool = False,
) -> dict:
    """
    Execute the reference validation pipeline.

    The document is retrieved first, the DNS key set is resolved, and each
    published candidate key is tested until one verifies the signed document.
    Host binding and the v2.0 freshness rules, including freshness.expiresAt,
    are enforced by verify_identity_detail().

    check_timestamp enables the issuance window of draft Section 9.4 (default
    W = 600 s) against freshness.created. It is False by default: a statically
    published .well-known document is re-signed on a validity cycle, not per
    request, so it cannot satisfy a 600-second window. Section 9.4 permits a
    longer W by local policy; callers that verify challenge-bound documents
    pass check_timestamp=True.

    Returns a dict with domain, psi_core (1 or 0), reason, document and
    public_key_ref. reason names the first failed check as one of the
    core.REASON_* constants, and is "ok" when psi_core is 1.
    """
    document = fetch_identity_document(domain, timeout=timeout)
    candidate_keys = resolve_dns_pubkeys(domain)

    proof = document.get("integrity_proof", {})
    signature_b64 = proof.get("signature", "") if isinstance(proof, dict) else ""

    psi_core = 0
    reason = REASON_NO_KEY
    for public_key_b64 in candidate_keys:
        verified, candidate_reason = verify_identity_detail(
            document,
            signature_b64,
            public_key_b64,
            check_timestamp=check_timestamp,
            expected_host=domain,
        )
        if verified:
            psi_core = 1
            reason = candidate_reason
            break
        # Report the most specific failure across the published key set: a
        # freshness or host failure says more than "none of the keys matched".
        if reason == REASON_NO_KEY or (
            reason == REASON_SIGNATURE and candidate_reason != REASON_SIGNATURE
        ):
            reason = candidate_reason

    return {
        "domain": domain,
        "psi_core": psi_core,
        "reason": reason,
        "document": document,
        "public_key_ref": f"dns:txt:_sovp.{domain}",
    }
