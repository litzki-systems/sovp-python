# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

"""Resource limits for unverified SOVP documents.

draft-litzki-sovp-04, Security Considerations, "Resource Limits for
Unverified Documents": a verifier parses sovp-identity.json before
Psi_core is known, so a document MUST be rejected before canonicalization
if it is larger than 64 KiB, nested deeper than 16 levels, or contains
duplicate member names in any object.

json.loads() alone does not enforce any of this: it silently keeps the
last of a duplicate key and has no depth limit (a sufficiently deep
document instead risks a RecursionError deep inside the interpreter,
which is not a clean, catchable rejection). This module re-implements a
minimal JSON parser that enforces both limits while parsing, before an
attacker-controlled document is trusted with any further processing.
"""

from __future__ import annotations

import json

MAX_UNVERIFIED_DOCUMENT_BYTES = 64 * 1024
MAX_UNVERIFIED_DOCUMENT_DEPTH = 16


class UnverifiedDocumentLimitError(ValueError):
    pass


def parse_unverified_sovp_document(
    text: str,
    max_bytes: int = MAX_UNVERIFIED_DOCUMENT_BYTES,
    max_depth: int = MAX_UNVERIFIED_DOCUMENT_DEPTH,
):
    """Parse an untrusted SOVP document under size/depth/duplicate-key limits.

    Raises UnverifiedDocumentLimitError if any limit is violated, or if the
    text is not well-formed JSON. Returns the parsed value otherwise (same
    shape json.loads() would return, since object pairs are inserted via a
    plain dict in traversal order).
    """
    byte_length = len(text.encode("utf-8"))
    if byte_length > max_bytes:
        raise UnverifiedDocumentLimitError(
            f"document exceeds {max_bytes} bytes ({byte_length})"
        )

    pos = 0
    n = len(text)

    def fail(msg: str):
        raise UnverifiedDocumentLimitError(f"{msg} at offset {pos}")

    def skip_ws():
        nonlocal pos
        while pos < n and text[pos] in " \t\n\r":
            pos += 1

    def parse_value(depth: int):
        nonlocal pos
        if depth > max_depth:
            fail(f"nesting exceeds {max_depth} levels")
        skip_ws()
        if pos >= n:
            fail("unexpected end of input")
        c = text[pos]
        if c == "{":
            return parse_object(depth)
        if c == "[":
            return parse_array(depth)
        if c == '"':
            return parse_string()
        if c == "t":
            expect_literal("true")
            return True
        if c == "f":
            expect_literal("false")
            return False
        if c == "n":
            expect_literal("null")
            return None
        if c == "-" or c.isdigit():
            return parse_number()
        fail(f"unexpected token {c!r}")

    def expect_literal(lit: str):
        nonlocal pos
        if text[pos:pos + len(lit)] != lit:
            fail(f"expected literal {lit}")
        pos += len(lit)

    def parse_number():
        nonlocal pos
        start = pos
        if text[pos] == "-":
            pos += 1
        while pos < n and text[pos].isdigit():
            pos += 1
        if pos < n and text[pos] == ".":
            pos += 1
            while pos < n and text[pos].isdigit():
                pos += 1
        if pos < n and text[pos] in "eE":
            pos += 1
            if pos < n and text[pos] in "+-":
                pos += 1
            while pos < n and text[pos].isdigit():
                pos += 1
        token = text[start:pos]
        return float(token) if any(ch in token for ch in ".eE") else int(token)

    def parse_string():
        nonlocal pos
        if text[pos] != '"':
            fail("expected string")
        start = pos
        pos += 1
        while pos < n:
            c = text[pos]
            if c == "\\":
                pos += 2
                continue
            if c == '"':
                pos += 1
                break
            pos += 1
        if pos > n or text[pos - 1] != '"':
            fail("unterminated string")
        # Delegate escape-sequence decoding to json.loads on the isolated
        # string literal rather than re-implementing it by hand.
        return json.loads(text[start:pos])

    def parse_object(depth: int):
        nonlocal pos
        pos += 1  # consume '{'
        obj = {}
        seen_keys = set()
        skip_ws()
        if pos < n and text[pos] == "}":
            pos += 1
            return obj
        while True:
            skip_ws()
            if pos >= n or text[pos] != '"':
                fail("expected string key")
            key = parse_string()
            if key in seen_keys:
                fail(f'duplicate member name "{key}"')
            seen_keys.add(key)
            skip_ws()
            if pos >= n or text[pos] != ":":
                fail("expected ':'")
            pos += 1
            obj[key] = parse_value(depth + 1)
            skip_ws()
            if pos < n and text[pos] == ",":
                pos += 1
                continue
            if pos < n and text[pos] == "}":
                pos += 1
                break
            fail("expected ',' or '}'")
        return obj

    def parse_array(depth: int):
        nonlocal pos
        pos += 1  # consume '['
        arr = []
        skip_ws()
        if pos < n and text[pos] == "]":
            pos += 1
            return arr
        while True:
            arr.append(parse_value(depth + 1))
            skip_ws()
            if pos < n and text[pos] == ",":
                pos += 1
                continue
            if pos < n and text[pos] == "]":
                pos += 1
                break
            fail("expected ',' or ']'")
        return arr

    result = parse_value(1)
    skip_ws()
    if pos != n:
        fail("trailing content after JSON value")
    return result
