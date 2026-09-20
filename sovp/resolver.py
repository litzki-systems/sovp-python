# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import requests
import dns.resolver
import dns.exception

from .core import verify_identity
from .document_safety import parse_unverified_sovp_document, UnverifiedDocumentLimitError


class SOVPResolverError(Exception):
    pass


def fetch_identity_document(domain: str, timeout: int = 10) -> dict:
    """
    Fetch /.well-known/sovp-identity.json from domain.
    Primary: https://{domain}/.well-known/sovp-identity.json
    Fallback: https://{domain}/sovp-identity.json
    Raises SOVPResolverError on HTTP error or JSON parse failure.
    Returns parsed dict.
    """
    primary_url = f"https://{domain}/.well-known/sovp-identity.json"
    fallback_url = f"https://{domain}/sovp-identity.json"
    headers = {"User-Agent": "sovp-resolver/1.0.1"}

    for url in (primary_url, fallback_url):
        try:
            resp = requests.get(url, timeout=timeout, headers=headers)
            if resp.status_code == 200:
                # draft-litzki-sovp-04 "Resource Limits for Unverified
                # Documents": Psi_core is not known yet at this point, so
                # resp.json() (== json.loads(), no size/depth/duplicate-key
                # limit) is not used here.
                try:
                    return parse_unverified_sovp_document(resp.text)
                except UnverifiedDocumentLimitError as exc:
                    raise SOVPResolverError(
                        f"resource limit violated at {url}: {exc}"
                    ) from exc
        except requests.RequestException:
            continue

    raise SOVPResolverError(
        f"sovp-identity.json not reachable at {primary_url} or {fallback_url}"
    )


def resolve_dns_pubkeys(domain: str, max_keys: int = 4) -> list[str]:
    """
    Resolve _sovp.{domain} TXT records, returning every matching
    v=SOVP1; k=<base64> key as an unordered set (draft-litzki-sovp-04
    "Multiple _sovp TXT records", key-rotation support), capped at
    max_keys. Raises SOVPResolverError if no record matches or DNS
    resolution fails.
    """
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
        # RFC 1035 allows a single TXT RDATA to hold multiple
        # <character-string> chunks; per draft Section "DNS TXT Record
        # Format and Resolution", they MUST be concatenated before parsing.
        record = "".join(
            chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
            for chunk in rdata.strings
        )
        if not record.startswith("v=SOVP1"):
            continue
        for part in record.split(";"):
            part = part.strip()
            if part.startswith("k="):
                keys.append(part[2:].strip())
                break
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
    Resolve _sovp.{domain} TXT record and return a single public key.
    Kept for callers that only want one display/reference key, not a
    verification decision; see resolve_dns_pubkeys() for the full,
    rotation-aware set. Returns the first matching key.
    """
    return resolve_dns_pubkeys(domain, max_keys=1)[0]


def validate_domain(domain: str, timeout: int = 10) -> dict:
    """
    Full pipeline:
    1. fetch_identity_document(domain)
    2. resolve_dns_pubkeys(domain) — every published v=SOVP1 key
    3. verify_identity(document, signature, pubkey) against each, in order,
       accepting on the first that verifies (draft-litzki-sovp-04 "Multiple
       _sovp TXT records", key-rotation support)
    Returns {
        "domain": domain,
        "psi_core": 1 or 0,
        "document": dict,
        "public_key_ref": "dns:txt:_sovp.{domain}"
    }
    """
    document = fetch_identity_document(domain, timeout=timeout)
    candidate_keys = resolve_dns_pubkeys(domain)

    proof = document.get("integrity_proof", {})
    signature_b64 = proof.get("signature", "") if isinstance(proof, dict) else ""

    psi_core = 0
    for public_key_b64 in candidate_keys:
        if verify_identity(document, signature_b64, public_key_b64):
            psi_core = 1
            break

    return {
        "domain": domain,
        "psi_core": psi_core,
        "document": document,
        "public_key_ref": f"dns:txt:_sovp.{domain}",
    }
