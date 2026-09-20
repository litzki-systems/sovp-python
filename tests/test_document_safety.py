# Copyright (c) 2026 Litzki Systems LLC
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

from sovp.document_safety import (
    parse_unverified_sovp_document,
    UnverifiedDocumentLimitError,
    MAX_UNVERIFIED_DOCUMENT_BYTES,
    MAX_UNVERIFIED_DOCUMENT_DEPTH,
)

# Coverage for draft-litzki-sovp-04 Security Considerations, "Resource Limits
# for Unverified Documents": a verifier parses sovp-identity.json before
# Psi_core is known, so plain json.loads() is not enough on its own — it
# silently keeps the last of a duplicate member name and has no depth limit.


def test_parses_an_ordinary_document_identically_to_json_loads():
    doc = {
        "@context": "https://litzki-systems.com/protocol/v2.0",
        "entity": {"uid": "x"},
        "freshness": {"created": "now"},
        "list": [1, 2, {"a": "é"}],
    }
    text = json.dumps(doc)
    assert parse_unverified_sovp_document(text) == json.loads(text)


def test_rejects_a_document_larger_than_the_byte_limit():
    text = json.dumps({"pad": "x" * MAX_UNVERIFIED_DOCUMENT_BYTES})
    with pytest.raises(UnverifiedDocumentLimitError):
        parse_unverified_sovp_document(text)


def test_accepts_a_small_document_well_under_the_byte_limit():
    text = json.dumps({"a": "x" * 100})
    parse_unverified_sovp_document(text)  # must not raise


def test_rejects_a_duplicate_member_name_within_the_same_object():
    with pytest.raises(UnverifiedDocumentLimitError, match='duplicate member name "a"'):
        parse_unverified_sovp_document('{"a":1,"b":2,"a":3}')


def test_allows_the_same_key_name_reused_in_different_objects():
    text = json.dumps({"outer": {"id": 1}, "other": {"id": 2}})
    parse_unverified_sovp_document(text)  # must not raise


def test_rejects_nesting_deeper_than_the_depth_limit():
    deep = 0
    for _ in range(MAX_UNVERIFIED_DOCUMENT_DEPTH + 1):
        deep = {"n": deep}
    with pytest.raises(UnverifiedDocumentLimitError):
        parse_unverified_sovp_document(json.dumps(deep))


def test_accepts_nesting_exactly_at_the_depth_limit():
    at_limit = 0
    for _ in range(MAX_UNVERIFIED_DOCUMENT_DEPTH - 1):
        at_limit = {"n": at_limit}
    parse_unverified_sovp_document(json.dumps(at_limit))  # must not raise


def test_rejects_duplicate_keys_nested_inside_an_array_of_objects():
    with pytest.raises(UnverifiedDocumentLimitError, match='duplicate member name "a"'):
        parse_unverified_sovp_document('{"items":[{"a":1,"a":2}]}')


def test_rejects_malformed_json_the_same_way_json_loads_would():
    with pytest.raises(UnverifiedDocumentLimitError):
        parse_unverified_sovp_document('{"a":')


def test_correctly_parses_escaped_quotes_and_backslashes_inside_strings():
    text = json.dumps({"s": 'a "quoted" \\ value with \n newline'})
    assert parse_unverified_sovp_document(text) == json.loads(text)
