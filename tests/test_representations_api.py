"""Regression tests for ``POST /representations/select``.

Covers response key resolution (exact / ``nXX`` case-insensitive /
``default``), request Content-Type matching (wildcard specificity and the
declared-parameter containment rule, charset case-insensitivity), RFC 7231
Accept negotiation (most-specific-range weight, q=0 exclusion, wildcard
specificity and the declaration-order stable tie-break), request bodies and
responses reached through local ``$ref`` chains (3.0 sibling ignore vs 3.1
nearest-first merge, schema and Example Object $refs, path item $refs,
dangling / external / circular chains), the returned JSON Pointers and
normalized media types, 400 envelope validation, 406 / 415 selection
failures, and the non-mutation / no-partial-result guarantees.
"""

from __future__ import annotations

import copy
import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def make_doc(
    *,
    openapi="3.0.3",
    request_content=None,
    request_body_extra=None,
    request_body=None,
    responses=None,
    components=None,
    path_item_extra=None,
    path_item=None,
):
    operation: dict = {}
    if path_item is not None:
        item = copy.deepcopy(path_item)
    else:
        if request_body is not None:
            operation["requestBody"] = copy.deepcopy(request_body)
        elif request_content is not None:
            body = {"content": copy.deepcopy(request_content)}
            if request_body_extra:
                body.update(copy.deepcopy(request_body_extra))
            operation["requestBody"] = body
        operation["responses"] = (
            copy.deepcopy(responses)
            if responses is not None
            else {"200": {"description": "ok"}}
        )
        item = {"post": operation}
        if path_item_extra:
            item.update(copy.deepcopy(path_item_extra))
    doc = {
        "openapi": openapi,
        "info": {"title": "T", "version": "1"},
        "paths": {"/pets": item},
    }
    if components is not None:
        doc["components"] = copy.deepcopy(components)
    return doc


def select(doc, **over):
    body = {
        "document": doc,
        "selector": "POST /pets",
        "content_type": None,
        "accept": None,
        "status_code": 200,
    }
    body.update(over)
    return client.post("/representations/select", json=body)


JSON = "application/json"


# --------------------------------------------------------------------------- #
# Happy path: pointers, normalized media types, schema/example payload
# --------------------------------------------------------------------------- #


def test_basic_request_and_response_selection():
    doc = make_doc(
        request_content={
            "application/json; charset=utf-8": {
                "schema": {"$ref": "#/components/schemas/Pet"},
                "example": {"name": "Rex"},
                "examples": {
                    "sample": {"summary": "s", "value": {"name": "Sam"}},
                },
            },
        },
        responses={
            "200": {
                "description": "ok",
                "content": {"application/json": {"schema": {"type": "object"}}},
            }
        },
        components={"schemas": {"Pet": {"type": "object", "properties": {
            "name": {"type": "string"}}}}},
    )
    r = select(
        doc,
        content_type="application/json; charset=UTF-8; version=2",
        accept="application/json",
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["operation_pointer"] == "/paths/~1pets/post"

    req = body["request"]
    assert req["required"] is False
    rep = req["representation"]
    assert rep["media_type"] == "application/json; charset=utf-8"
    assert rep["offered_media_type"] == "application/json; charset=utf-8; version=2"
    assert rep["pointer"] == (
        "/paths/~1pets/post/requestBody/content/"
        "application~1json; charset=utf-8"
    )
    assert rep["content_pointer"] == "/paths/~1pets/post/requestBody/content"
    assert rep["schema_pointer"] == "/components/schemas/Pet"
    assert rep["schema"] == {"type": "object", "properties": {
        "name": {"type": "string"}}}
    assert rep["example"] == {"name": "Rex"}
    assert rep["example_pointer"].endswith("/example")
    assert rep["examples"][0]["name"] == "sample"
    assert rep["examples"][0]["value"] == {"name": "Sam"}
    assert rep["examples"][0]["value_pointer"] == (
        rep["pointer"] + "/examples/sample/value"
    )

    resp = body["response"]
    assert resp["key"] == "200" and resp["match"] == "exact"
    assert resp["status_code"] == 200
    assert resp["representation"]["media_type"] == "application/json"
    assert resp["representation"]["weight"] == 1.0


def test_normalized_media_type_sorts_parameters_and_lowercases_range():
    doc = make_doc(request_content={
        "Application/JSON; B=2; a=1": {"schema": {"type": "object"}}})
    r = select(doc, content_type="application/json; a=1; b=2; extra=x")
    assert r.status_code == 200, r.text
    rep = r.json()["request"]["representation"]
    assert rep["media_type"] == "application/json; a=1; b=2"


def test_no_request_body_and_no_content_type_gives_null_request():
    doc = make_doc()
    r = select(doc)
    assert r.status_code == 200
    assert r.json()["request"] is None


def test_response_without_content_gives_null_representation_even_with_accept():
    doc = make_doc(responses={"204": {"description": "empty"}})
    r = select(doc, status_code=204, accept="image/png")
    assert r.status_code == 200
    data = r.json()
    assert data["response"]["key"] == "204"
    assert data["response"]["representation"] is None


# --------------------------------------------------------------------------- #
# Response key selection
# --------------------------------------------------------------------------- #


def test_response_key_exact_wildcard_default_order():
    responses = {
        "201": {"description": "created"},
        "2XX": {"description": "twoxx", "content": {"application/json": {}}},
        "default": {"description": "fallback"},
    }
    doc = make_doc(responses=responses)
    # exact wins over wildcard
    r = select(doc, status_code=201)
    assert r.json()["response"]["match"] == "exact"
    # wildcard (case-insensitive key/status) wins over default
    r = select(doc, status_code="250")
    assert r.json()["response"]["key"] == "2XX"
    assert r.json()["response"]["match"] == "wildcard"
    r = select(doc, status_code=404)
    assert r.json()["response"]["key"] == "default"
    assert r.json()["response"]["match"] == "default"


def test_missing_response_is_422_with_status_code():
    doc = make_doc(responses={"200": {"description": "ok"}})
    r = select(doc, status_code=404)
    assert r.status_code == 422
    errors = r.json()["errors"]
    assert len(errors) == 1
    assert errors[0]["code"] == "missing_response"
    assert errors[0]["status_code"] == 404


# --------------------------------------------------------------------------- #
# Request Content-Type matching
# --------------------------------------------------------------------------- #


def test_request_content_type_parameter_containment():
    doc = make_doc(request_content={
        "application/json; version=2": {"schema": {"type": "object"}},
        "application/json": {"schema": {"type": "string"}},
    })
    # wire satisfies the parameterized declaration: it is more specific
    r = select(doc, content_type="application/json; version=2; charset=utf-8")
    assert r.status_code == 200
    assert r.json()["request"]["representation"]["media_type"] == (
        "application/json; version=2")
    # wire does not satisfy version=2: falls back to the plain declaration
    r = select(doc, content_type="application/json; version=1")
    assert r.json()["request"]["representation"]["media_type"] == "application/json"


def test_request_content_type_parameter_names_case_insensitive_charset_value():
    doc = make_doc(request_content={
        "application/json; charset=utf-8": {"schema": {"type": "string"}}})
    r = select(doc, content_type="application/json; CHARSET=UTF-8")
    assert r.status_code == 200
    r = select(doc, content_type="application/json; charset=ascii")
    assert r.status_code == 415


def test_request_content_type_wildcard_declarations_specificity_and_order():
    # Declared wildcards are unusual but accepted; concrete beats type/*.
    doc = make_doc(request_content={
        "*/*": {"schema": {"type": "string"}},
        "application/*": {"schema": {"type": "integer"}},
        "application/json": {"schema": {"type": "object"}},
    })
    r = select(doc, content_type="application/json")
    assert r.json()["request"]["representation"]["media_type"] == "application/json"
    r = select(doc, content_type="application/xml")
    assert r.json()["request"]["representation"]["media_type"] == "application/*"
    r = select(doc, content_type="text/plain")
    assert r.json()["request"]["representation"]["media_type"] == "*/*"


def test_request_content_type_no_match_is_415_with_supported_list():
    doc = make_doc(request_content={
        "application/json": {"schema": {}},
        "application/xml": {"schema": {}},
    })
    r = select(doc, content_type="image/png")
    assert r.status_code == 415
    body = r.json()
    assert body["error"] == "unsupported_media_type"
    assert body["offered_media_type"] == "image/png"
    assert body["supported_media_types"] == ["application/json", "application/xml"]
    assert body["content_pointer"].endswith("/content")


def test_content_type_on_bodyless_operation_is_415():
    doc = make_doc()
    r = select(doc, content_type="application/json")
    assert r.status_code == 415
    assert r.json()["supported_media_types"] == []


def test_empty_content_map_is_415_when_content_type_present():
    doc = make_doc(request_body={"required": True, "content": {}})
    r = select(doc, content_type="application/json")
    assert r.status_code == 415
    assert r.json()["supported_media_types"] == []


# --------------------------------------------------------------------------- #
# Accept negotiation
# --------------------------------------------------------------------------- #


def test_accept_highest_weight_wins():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {},
        "application/xml": {},
    }}})
    r = select(doc, accept="application/json;q=0.1, application/xml;q=0.9")
    rep = r.json()["response"]["representation"]
    assert rep["media_type"] == "application/xml"
    assert rep["weight"] == 0.9
    assert rep["accepted_media_range"] == "application/xml"


def test_accept_most_specific_range_supplies_weight():
    # Broad range likes everything, concrete range dislikes json: json must
    # take the concrete q=0 and lose, even though */* gives q=1.
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {},
        "text/plain": {},
    }}})
    r = select(doc, accept="*/*;q=1, application/json;q=0")
    assert r.status_code == 200
    assert r.json()["response"]["representation"]["media_type"] == "text/plain"


def test_accept_q_zero_excludes_otherwise_matching_type():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {},
    }}})
    r = select(doc, accept="application/json;q=0")
    assert r.status_code == 406
    assert r.json()["supported_media_types"] == ["application/json"]


def test_accept_wildcards_lose_to_concrete_at_equal_weight():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {},
        "text/plain": {},
    }}})
    r = select(doc, accept="*/*;q=0.5, text/*;q=0.5, text/plain;q=0.5")
    assert r.json()["response"]["representation"]["media_type"] == "text/plain"
    r = select(doc, accept="text/*;q=0.5, */*;q=0.5")
    assert r.json()["response"]["representation"]["media_type"] == "text/plain"


def test_accept_equal_weight_keeps_declaration_order():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/vnd.a+json": {},
        "application/json": {},
    }}})
    r = select(doc, accept="application/*;q=0.5")
    assert r.json()["response"]["representation"]["media_type"] == (
        "application/vnd.a+json")
    # swapping Accept range order must not change the contract-order verdict
    r = select(doc, accept="application/*")
    assert r.json()["response"]["representation"]["media_type"] == (
        "application/vnd.a+json")


def test_accept_equal_specificity_ranges_use_highest_q():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {},
        "application/xml": {},
    }}})
    # Two equally specific concrete ranges for json: the higher q wins,
    # regardless of their order in the header.
    r = select(doc, accept="application/json;q=0.2, application/json;q=0.8, application/xml;q=0.5")
    rep = r.json()["response"]["representation"]
    assert rep["media_type"] == "application/json"
    assert rep["weight"] == 0.8
    assert rep["accepted_media_range"] == "application/json"
    r = select(doc, accept="application/json;q=0.8, application/json;q=0.2, application/xml;q=0.9")
    rep = r.json()["response"]["representation"]
    assert rep["media_type"] == "application/xml"


def test_accept_no_match_is_406_with_accept_echo():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {}}}})
    r = select(doc, accept="image/*, text/plain;q=0.2")
    assert r.status_code == 406
    body = r.json()
    assert body["error"] == "not_acceptable"
    assert body["accept"] == "image/*, text/plain;q=0.2"
    assert body["supported_media_types"] == ["application/json"]


def test_missing_accept_is_wildcard():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {}}}})
    r = select(doc, accept=None)
    assert r.status_code == 200
    rep = r.json()["response"]["representation"]
    assert rep["media_type"] == "application/json"
    assert rep["weight"] == 1.0
    assert rep["accepted_media_range"] == "*/*"


def test_accept_parameter_must_be_present_on_declared_type():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "text/html; level=1": {},
        "text/html": {},
    }}})
    # Only the level=1 declaration satisfies the parameterized range.
    r = select(doc, accept="text/html; level=1")
    assert r.json()["response"]["representation"]["media_type"] == (
        "text/html; level=1")
    # A bare range matches both bare and parameterized candidates; equal
    # weight/range specificity then prefers the more specific (parameterized)
    # server type, with contract declaration order as the final tie-break.
    r = select(doc, accept="text/html")
    assert r.json()["response"]["representation"]["media_type"] == (
        "text/html; level=1")


# --------------------------------------------------------------------------- #
# $ref resolution: 3.0 ignore siblings vs 3.1 nearest-first merge
# --------------------------------------------------------------------------- #


def test_request_body_ref_30_ignores_siblings():
    doc = make_doc(
        request_body={
            "$ref": "#/components/requestBodies/B",
            "content": {"application/xml": {"schema": {"type": "string"}}},
        },
        responses={"200": {"description": "ok"}},
        components={"requestBodies": {"B": {"content": {
            "application/json": {"schema": {"type": "object"}}}}}},
    )
    r = select(doc, content_type="application/json")
    assert r.status_code == 200
    assert r.json()["request"]["representation"]["media_type"] == "application/json"
    r = select(doc, content_type="application/xml")
    assert r.status_code == 415  # sibling content ignored in 3.0


def test_request_body_ref_31_merges_siblings_nearest_first():
    doc = make_doc(
        openapi="3.1.0",
        request_body={
            "$ref": "#/components/requestBodies/B",
            "content": {"application/xml": {"schema": {"type": "string"}}},
        },
        components={"requestBodies": {"B": {"content": {
            "application/json": {"schema": {"type": "object"}}}}}},
    )
    r = select(doc, content_type="application/xml")
    assert r.status_code == 200
    assert r.json()["request"]["representation"]["media_type"] == "application/xml"
    # content is one member: the nearest layer's value wins wholesale
    r = select(doc, content_type="application/json")
    assert r.status_code == 415


def test_response_ref_merge_differs_by_version_and_content_pointer():
    components = {"responses": {"R": {
        "description": "base",
        "content": {"application/json": {}}}}}
    doc = make_doc(
        openapi="3.1.0",
        responses={"200": {
            "$ref": "#/components/responses/R",
            "content": {"text/plain": {}}}},
        components=components,
    )
    r = select(doc, accept="text/plain")
    assert r.status_code == 200
    assert r.json()["response"]["representation"]["media_type"] == "text/plain"
    # the content map came from the sibling layer at the occurrence
    assert r.json()["response"]["representation"]["content_pointer"] == (
        "/paths/~1pets/post/responses/200/content")

    doc["openapi"] = "3.0.3"
    r = select(doc, accept="text/plain")
    assert r.status_code == 406
    r = select(doc, accept="application/json")
    assert r.status_code == 200
    assert r.json()["response"]["representation"]["content_pointer"] == (
        "/components/responses/R/content")


def test_schema_ref_followed_and_31_siblings_merged():
    doc = make_doc(
        openapi="3.1.0",
        request_content={"application/json": {"schema": {
            "$ref": "#/components/schemas/B", "description": "near"}}},
        components={"schemas": {"B": {"type": "object", "title": "T"}}},
    )
    r = select(doc, content_type="application/json")
    rep = r.json()["request"]["representation"]
    assert rep["schema"] == {"type": "object", "title": "T",
                             "description": "near"}
    assert rep["schema_pointer"] == "/components/schemas/B"


def test_schema_ref_30_ignores_siblings():
    doc = make_doc(
        request_content={"application/json": {"schema": {
            "$ref": "#/components/schemas/B", "description": "near"}}},
        components={"schemas": {"B": {"type": "object"}}},
    )
    r = select(doc, content_type="application/json")
    assert r.json()["request"]["representation"]["schema"] == {"type": "object"}


def test_boolean_schema_passes_through():
    doc = make_doc(
        openapi="3.1.0",
        request_content={"application/json": {"schema": False}},
    )
    r = select(doc, content_type="application/json")
    rep = r.json()["request"]["representation"]
    assert rep["schema"] is False
    assert rep["schema_pointer"].endswith("/schema")


def test_example_ref_resolved_with_value_pointer_and_external_value_surfaced():
    doc = make_doc(
        request_content={"application/json": {
            "schema": {"type": "object"},
            "examples": {
                "a": {"$ref": "#/components/examples/E"},
                "b": {"summary": "ext", "externalValue": "https://x/e.json"},
            },
        }},
        components={"examples": {"E": {"summary": "S", "value": {"k": 1}}}},
    )
    r = select(doc, content_type="application/json")
    examples = {
        e["name"]: e
        for e in r.json()["request"]["representation"]["examples"]
    }
    assert examples["a"]["value"] == {"k": 1}
    assert examples["a"]["value_pointer"] == "/components/examples/E/value"
    assert examples["a"]["pointer"].endswith("/examples/a")
    assert examples["b"]["external_value"] == "https://x/e.json"
    assert examples["b"]["external_value_pointer"].endswith("/externalValue")
    assert examples["b"]["value"] is None
    assert examples["b"]["value_pointer"] is None


def test_path_item_ref_31_provides_operation():
    doc = make_doc(
        openapi="3.1.0",
        path_item={"$ref": "#/components/pathItems/P"},
        components={"pathItems": {"P": {"post": {
            "responses": {"200": {"description": "ok",
                                  "content": {"application/json": {}}}}}}}},
    )
    r = select(doc)
    assert r.status_code == 200, r.text
    assert r.json()["operation_pointer"] == "/paths/~1pets/post"
    assert r.json()["response"]["representation"]["media_type"] == "application/json"


# --------------------------------------------------------------------------- #
# Reference / structural failures -> 422 (no partial result)
# --------------------------------------------------------------------------- #


def test_dangling_request_body_ref_is_422():
    doc = make_doc(request_body={"$ref": "#/components/requestBodies/Missing"})
    r = select(doc, content_type="application/json")
    assert r.status_code == 422
    errors = r.json()["errors"]
    assert errors[0]["code"] == "unresolvable_reference"
    assert errors[0]["pointer"] == "/paths/~1pets/post/requestBody"
    assert errors[0]["ref"] == "#/components/requestBodies/Missing"


def test_external_request_body_ref_is_422():
    doc = make_doc(request_body={"$ref": "https://example.com/b.json#/B"})
    r = select(doc, content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "unresolvable_reference"


def test_circular_request_body_chain_is_422():
    doc = make_doc(
        request_body={"$ref": "#/components/requestBodies/A"},
        components={"requestBodies": {
            "A": {"$ref": "#/components/requestBodies/B"},
            "B": {"$ref": "#/components/requestBodies/A"}}},
    )
    r = select(doc, content_type="application/json")
    assert r.status_code == 422
    assert "circular" in r.json()["errors"][0]["error"]


def test_dangling_schema_ref_only_fails_when_representation_selected():
    doc = make_doc(request_content={"application/json": {
        "schema": {"$ref": "#/components/schemas/Nope"}}})
    # no Content-Type: no representation chosen, the bad schema is not reached
    assert select(doc).status_code == 200
    r = select(doc, content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["pointer"].endswith(
        "/content/application~1json/schema")


def test_dangling_example_ref_is_422():
    doc = make_doc(request_content={"application/json": {
        "examples": {"a": {"$ref": "#/components/examples/Missing"}}}})
    r = select(doc, content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["pointer"].endswith("/examples/a")


def test_malformed_containers_are_422():
    doc = make_doc(responses={"200": {"description": "ok"}})
    doc["paths"]["/pets"]["post"]["responses"] = []
    r = select(doc)
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_response"

    doc2 = make_doc(request_content={"application/json": "not-an-object"})
    r = select(doc2, content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_media_type"

    doc3 = make_doc(request_body={"content": []})
    r = select(doc3, content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_media_type"

    doc4 = make_doc(request_content={"application/json": {}, "not-a-media-type": {}})
    r = select(doc4, content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_media_type"


def test_errors_sorted_and_no_partial_result():
    doc = make_doc(request_body={"$ref": "#/components/requestBodies/Missing"})
    r = select(doc, content_type="application/json")
    assert r.status_code == 422
    body = r.json()
    assert "operation_pointer" not in body
    assert body["errors"] == sorted(
        body["errors"],
        key=lambda e: (e["code"], e.get("pointer", ""), e.get("ref", ""),
                       e.get("error", "")),
    )


# --------------------------------------------------------------------------- #
# 400 envelopes
# --------------------------------------------------------------------------- #


def test_bad_document_shape_is_400():
    r = client.post("/representations/select", json={
        "document": {"openapi": "2.0", "paths": {}},
        "selector": "POST /pets", "status_code": 200})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_openapi_document"


def test_bad_selector_is_400():
    doc = make_doc()
    for selector in ["GET /pets", "POST /nope", "garbage", "POST"]:
        r = client.post("/representations/select", json={
            "document": doc, "selector": selector, "status_code": 200})
        assert r.status_code == 400, selector
        assert r.json()["error"] == "invalid_selector"
    # A non-string selector fails pydantic validation (422), not routing.
    r = client.post("/representations/select", json={
        "document": doc, "selector": 7, "status_code": 200})
    assert r.status_code == 422


def test_malformed_content_type_is_400():
    doc = make_doc(request_content={"application/json": {}})
    for value in [
        "application/",
        "*/json",
        "*/*",
        "application/json, text/plain",
        "application/json;q=0.5",
        "application//json",
        "no spaces allowed",
        "application/json; charset",
    ]:
        r = select(doc, content_type=value)
        assert r.status_code == 400, value
        assert r.json()["error"] == "invalid_representation_request"
    # A non-string field fails pydantic validation with the default 422.
    assert select(doc, content_type=123).status_code == 422


def test_malformed_accept_is_400():
    doc = make_doc()
    for value in [
        "application/json;q=2",
        "application/json;q=-1",
        "application/json;q=abc",
        "application/json;q=0.1234",
        "application//json",
        "*/json",
    ]:
        r = select(doc, accept=value)
        assert r.status_code == 400, value
    assert select(doc, accept=9).status_code == 422


def test_valid_q_forms_accepted():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {}}}})
    for value in ["application/json;q=1", "application/json;q=0.123",
                  "application/json; q=0.5", "application/json;Q=0.7"]:
        r = select(doc, accept=value)
        assert r.status_code == 200, value
    # q=0 is syntactically valid but excludes the only representation -> 406
    r = select(doc, accept="application/json;q=0")
    assert r.status_code == 406


def test_malformed_status_code_is_400():
    doc = make_doc()
    for value in [99, 600, "200x", "2XX", "20"]:
        r = client.post("/representations/select", json={
            "document": doc, "selector": "POST /pets", "status_code": value})
        assert r.status_code == 400, (value, r.status_code)
    # a null required field fails pydantic validation with 422
    r = client.post("/representations/select", json={
        "document": doc, "selector": "POST /pets", "status_code": None})
    assert r.status_code == 422
    # a JSON boolean is coerced to 1 by pydantic's lax int mode, then
    # rejected by the 100..599 range check as a regular 400 envelope error
    r = client.post("/representations/select", json={
        "document": doc, "selector": "POST /pets", "status_code": True})
    assert r.status_code == 400


def test_blank_header_strings_treated_as_absent():
    doc = make_doc(responses={"200": {"description": "ok", "content": {
        "application/json": {}}}})
    r = select(doc, content_type="   ", accept="  ")
    assert r.status_code == 200
    assert r.json()["request"] is None


# --------------------------------------------------------------------------- #
# Precedence and non-mutation
# --------------------------------------------------------------------------- #


def test_415_takes_precedence_over_406():
    # Both sides unmatched: 415 (request) is reported.
    doc = make_doc(
        request_content={"application/json": {}},
        responses={"200": {"description": "ok", "content": {"text/plain": {}}}},
    )
    r = select(doc, content_type="image/png", accept="image/png")
    assert r.status_code == 415


def test_422_takes_precedence_over_negotiation_failures():
    doc = make_doc(request_body={"$ref": "#/components/requestBodies/Missing"})
    r = select(doc, content_type="image/png", accept="image/png")
    assert r.status_code == 422


def test_input_document_is_not_modified():
    doc = make_doc(
        request_content={"application/json": {
            "schema": {"$ref": "#/components/schemas/P"},
            "examples": {"a": {"$ref": "#/components/examples/E"}}}},
        components={
            "schemas": {"P": {"type": "object"}},
            "examples": {"E": {"value": {"x": 1}}},
        },
    )
    snapshot = json.dumps(doc, sort_keys=True)
    r = select(doc, content_type="application/json", accept="application/json")
    assert r.status_code == 200
    assert json.dumps(doc, sort_keys=True) == snapshot

    # returned payloads are detached copies
    rep = r.json()["request"]["representation"]
    rep["schema"]["mutated"] = True
    rep["examples"][0]["value"]["y"] = 2
    assert json.dumps(doc, sort_keys=True) == snapshot


def test_response_is_stable_across_key_insertion_order():
    def doc_with(first):
        media = {
            first: {},
        }
        other = "application/xml" if first == "application/json" else "application/json"
        media[other] = {}
        return make_doc(responses={"200": {"description": "ok",
                                          "content": media}})

    r1 = select(doc_with("application/json"), accept="*/*;q=0.5")
    r2 = select(doc_with("application/xml"), accept="*/*;q=0.5")
    # declaration order differs, so the winners differ; but each is the
    # first-declared member and never depends on Accept range ordering
    assert r1.json()["response"]["representation"]["media_type"] == "application/json"
    assert r2.json()["response"]["representation"]["media_type"] == "application/xml"
