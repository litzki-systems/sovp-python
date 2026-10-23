# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import binascii
import ipaddress

import dns.exception
import dns.resolver
import requests

from .core import (
    DRAFT_OUTCOMES,
    REASON_NO_KEY,
    REASON_SIGNATURE,
    document_shape_reason,
    verify_identity,  # noqa: F401  re-exported: callers import it from sovp.resolver
    verify_identity_detail,
)
from .document_safety import (
    MAX_UNVERIFIED_DOCUMENT_BYTES,
    UnverifiedDocumentLimitError,
    parse_unverified_sovp_document,
)


class SOVPResolverError(Exception):
    pass


USER_AGENT = "sovp-resolver/1.1.2"


def normalize_retrieval_host(domain: str) -> str:
    """
    Return the retrieval host of draft Section 6.2: lowercase, no trailing dot.

    Raises SOVPResolverError for an IP literal (the draft forbids verifying a
    document retrieved from one), for a host with a port, scheme, path or
    whitespace, and for an empty host.
    """
    if not isinstance(domain, str):
        raise SOVPResolverError("domain must be a string")
    host = domain.strip().rstrip(".").lower()
    if not host:
        raise SOVPResolverError(f"invalid host {domain!r}")
    if any(ch in host for ch in "/:@?#[] \t"):
        raise SOVPResolverError(
            f"invalid host {domain!r}: give a bare host name without scheme, port or path"
        )
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SOVPResolverError(
            f"refusing IP literal {domain!r}: draft Section 6.2 forbids verifying "
            "a document retrieved from an IP address"
        )
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise SOVPResolverError(f"invalid host {domain!r}: {exc}") from exc


def _get(url: str, timeout: int):
    try:
        # Draft Section 9.9: do not follow redirects. A 3xx answer is a
        # retrieval failure like any other status except 200 and 404.
        return requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=False,
            stream=True,
        )
    except requests.RequestException as exc:
        raise SOVPResolverError(f"failed to retrieve {url}: {exc}") from exc


def _read_body(resp, url: str) -> bytes:
    """Read at most the size limit plus one octet, after content decoding."""
    body = b""
    try:
        for chunk in resp.iter_content(chunk_size=8192):
            body += chunk
            if len(body) > MAX_UNVERIFIED_DOCUMENT_BYTES:
                raise SOVPResolverError(
                    f"resource limit violated at {url}: document exceeds "
                    f"{MAX_UNVERIFIED_DOCUMENT_BYTES} bytes"
                )
    except requests.RequestException as exc:
        raise SOVPResolverError(f"failed to read {url}: {exc}") from exc
    finally:
        resp.close()
    return body


def fetch_identity_document(domain: str, timeout: int = 10) -> dict:
    """
    Fetch the SOVP identity document.

    The well-known endpoint is authoritative. The legacy path is used only
    when the well-known endpoint returns HTTP 404. Redirects are not
    followed. The body is read under the size limit of draft Section 9.8,
    decoded as UTF-8 and parsed under the depth and duplicate-member limits;
    a document that is not a JSON object is rejected.
    """
    host = normalize_retrieval_host(domain)
    primary_url = f"https://{host}/.well-known/sovp-identity.json"
    fallback_url = f"https://{host}/sovp-identity.json"

    resp = _get(primary_url, timeout)
    url = primary_url
    if resp.status_code == 404:
        resp.close()
        url = fallback_url
        resp = _get(fallback_url, timeout)

    if resp.status_code != 200:
        resp.close()
        raise SOVPResolverError(
            f"identity document returned HTTP {resp.status_code} at {url}"
        )

    body = _read_body(resp, url)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SOVPResolverError(f"document at {url} is not valid UTF-8") from exc

    try:
        document = parse_unverified_sovp_document(text)
    except UnverifiedDocumentLimitError as exc:
        raise SOVPResolverError(
            f"resource limit violated at {url}: {exc}"
        ) from exc
    if not isinstance(document, dict):
        raise SOVPResolverError(f"document at {url} is not a JSON object")
    return document


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

    txt_name = f"_sovp.{normalize_retrieval_host(domain)}"

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
        try:
            record = "".join(
                chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
                for chunk in rdata.strings
            )
        except UnicodeDecodeError:
            continue  # cannot be a v=SOVP1 record; ignored like any other
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

    Checks follow the order of draft Section 6.2: retrieval and document
    shape, host binding, key resolution, signature, freshness. A failure in
    the document or host binding is reported before DNS is queried.

    Returns a dict with domain, psi_core (1 or 0), reason, outcome, document
    and public_key_ref. reason names the first failed check as one of the
    core.REASON_* constants, and is "ok" when psi_core is 1. outcome is the
    same result under the outcome names of draft Section 6.2, Table 3.
    Retrieval failures (evidence_missing) and key resolution failures
    (key_unresolved) raise SOVPResolverError.
    """
    domain = normalize_retrieval_host(domain)
    document = fetch_identity_document(domain, timeout=timeout)

    shape_reason = document_shape_reason(document, expected_host=domain)
    if shape_reason is not None:
        return {
            "domain": domain,
            "psi_core": 0,
            "reason": shape_reason,
            "outcome": DRAFT_OUTCOMES[shape_reason],
            "document": document,
            "public_key_ref": f"dns:txt:_sovp.{domain}",
        }

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
        "outcome": DRAFT_OUTCOMES[reason],
        "document": document,
        "public_key_ref": f"dns:txt:_sovp.{domain}",
    }
