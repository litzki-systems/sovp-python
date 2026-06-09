# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import requests
import dns.resolver
import dns.exception

from .core import verify_identity


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
                try:
                    return resp.json()
                except ValueError as exc:
                    raise SOVPResolverError(
                        f"JSON parse failure at {url}: {exc}"
                    ) from exc
        except requests.RequestException:
            continue

    raise SOVPResolverError(
        f"sovp-identity.json not reachable at {primary_url} or {fallback_url}"
    )


def resolve_dns_pubkey(domain: str) -> str:
    """
    Resolve _sovp.{domain} TXT record.
    Parse v=SOVP1; k=<base64> format.
    Returns public key as base64 string.
    Raises SOVPResolverError if record not found or malformed.
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

    for rdata in answers:
        for txt_string in rdata.strings:
            record = (
                txt_string.decode("utf-8")
                if isinstance(txt_string, bytes)
                else txt_string
            )
            if not record.startswith("v=SOVP1"):
                continue
            for part in record.split(";"):
                part = part.strip()
                if part.startswith("k="):
                    return part[2:].strip()

    raise SOVPResolverError(
        f"No valid SOVP1 TXT record found at {txt_name}. "
        "Expected format: v=SOVP1; k=<Ed25519-public-key-base64>"
    )


def validate_domain(domain: str, timeout: int = 10) -> dict:
    """
    Full pipeline:
    1. fetch_identity_document(domain)
    2. resolve_dns_pubkey(domain)
    3. verify_identity(document, signature, pubkey)
    Returns {
        "domain": domain,
        "psi_core": 1 or 0,
        "document": dict,
        "public_key_ref": "dns:txt:_sovp.{domain}"
    }
    """
    document = fetch_identity_document(domain, timeout=timeout)
    public_key_b64 = resolve_dns_pubkey(domain)

    proof = document.get("integrity_proof", {})
    signature_b64 = proof.get("signature", "")

    psi_core = 1 if verify_identity(document, signature_b64, public_key_b64) else 0

    return {
        "domain": domain,
        "psi_core": psi_core,
        "document": document,
        "public_key_ref": f"dns:txt:_sovp.{domain}",
    }
