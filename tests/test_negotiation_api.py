"""Regression tests for ``POST /representations/select``.

Covers: response-key selection (exact / case-insensitive ``nXX`` /
default, int and string status codes), request Content-Type matching
(parameter containment, wildcard specificity, declaration order,
concrete-type enforcement), response Accept negotiation (RFC 9110
most-specific range, q weights, ``q=0``, missing/empty Accept,
parameter containment), bodyless requests/responses, local ``$ref``
resolution of requestBody / Response / Example objects (multi-hop,
OpenAPI 3.0 sibling ignore vs 3.1 sibling merge, dangling / external /
non-object / circular), schema/example extraction with source JSON
Pointers, 400 envelope validation, 406/415 precedence, the no-partial-
result guarantee and input non-mutation.
"""

from __future__ import annotations

import copy

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #


def make_doc(
    *,
    openapi="3.0.3",
    request_body=None,
    responses=None,
    components=None,
    path_item_extra=None,
    operation_extra=None,
    path="/pets",
    method="post",
):
    operation: dict = {}
    if request_body is not None:
        operation["requestBody"] = request_body
    operation["responses"] = (
        responses
        if responses is not None
        else {"200": {"description": "ok"}}
    )
    if operation_extra:
        operation.update(operation_extra)
    item = {method: operation}
    if path_item_extra:
        item.update(path_item_extra)
    doc = {
        "openapi": openapi,
        "info": {"title": "Pet", "version": "1.0"},
        "paths": {path: item},
    }
    if components is not None:
        doc["components"] = components
    return doc


def call(doc, *, selector="POST /pets", status_code=200,
         request_content_type=None, accept=None, extra=None):
    payload = {
        "document": doc,
        "selector": selector,
        "status_code": status_code,
    }
    if request_content_type is not None:
        payload["request_content_type"] = request_content_type
    if accept is not None:
        payload["accept"] = accept
    if extra:
        payload.update(extra)
    return client.post("/representations/select", json=payload)


def simple_body(*media_types, required=True):
    content = {}
    for index, media in enumerate(media_types):
        content[media] = {"schema": {"type": "object", "x-index": index}}
    return {"required": required, "content": content}


def simple_response(*media_types, code="200", description="ok"):
    content = {}
    for index, media in enumerate(media_types):
        content[media] = {"schema": {"type": "object", "x-index": index}}
    return {code: {"description": description, "content": content}}


# --------------------------------------------------------------------------- #
# Basic happy path
# --------------------------------------------------------------------------- #


def test_basic_selection_returns_pointers_and_schema():
    doc = make_doc(
        request_body=simple_body("application/json"),
        responses=simple_response("application/json", "application/xml"),
    )
    r = call(
        doc,
        request_content_type="application/json",
        accept="application/xml",
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["operation_pointer"] == "/paths/~1pets/post"
    req = body["request"]
    assert req["present"] is True
    assert req["required"] is True
    assert req["content_type"] == "application/json"
    assert req["declared_media_type"] == "application/json"
    assert req["media_type"] == "application/json"
    assert req["media_type_pointer"] == (
        "/paths/~1pets/post/requestBody/content/application~1json"
    )
    assert req["schema"] == {"type": "object", "x-index": 0}
    assert req["schema_pointer"].endswith(
        "/requestBody/content/application~1json/schema"
    )
    resp = body["response"]
    assert resp["present"] is True
    assert resp["status_code"] == 200
    assert resp["key"] == "200"
    assert resp["match"] == "exact"
    assert resp["declared_media_type"] == "application/xml"
    assert resp["media_type"] == "application/xml"
    assert resp["schema_pointer"].endswith(
        "/responses/200/content/application~1xml/schema"
    )


def test_defaults_when_headers_absent():
    doc = make_doc(
        request_body={"required": False, "content": {"application/json": {}}},
        responses=simple_response("application/json"),
    )
    r = call(doc)
    assert r.status_code == 200, r.text
    body = r.json()
    # Optional body without Content-Type -> no request representation.
    assert body["request"] is None
    # Missing Accept -> first declared representation.
    assert body["response"]["declared_media_type"] == "application/json"


def test_get_operation_without_request_body_ignores_content_type():
    doc = make_doc(method="get", responses={"204": {"description": "no content"}})
    r = call(doc, selector="GET /pets", status_code=204,
             request_content_type="application/json")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["request"] is None
    resp = body["response"]
    assert resp["present"] is False
    assert resp["key"] == "204"
    assert resp["media_type"] is None
    assert resp["examples"] == []


def test_method_case_insensitive_selector():
    doc = make_doc(method="post")
    r = call(doc, selector="post /pets")
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# Response-key selection
# --------------------------------------------------------------------------- #


def test_exact_beats_wildcard_and_default():
    responses = {
        "200": {"description": "exact", "content": {"application/json": {}}},
        "2XX": {"description": "wild", "content": {"application/xml": {}}},
        "default": {"description": "def", "content": {"text/plain": {}}},
    }
    doc = make_doc(responses=responses)
    r = call(doc, status_code=200, accept="*/*")
    body = r.json()
    assert body["response"]["key"] == "200"
    assert body["response"]["match"] == "exact"


def test_wildcard_case_insensitive():
    responses = {
        "200": {"description": "ok"},
        "4xx": {"description": "client err",
                "content": {"application/problem+json": {"schema": {"type": "object"}}}},
    }
    doc = make_doc(responses=responses)
    r = call(doc, status_code=404, accept="*/*")
    assert r.status_code == 200
    body = r.json()
    assert body["response"]["key"] == "4xx"
    assert body["response"]["match"] == "wildcard"
    assert body["response"]["declared_media_type"] == "application/problem+json"
    assert body["response"]["status_code"] == 404


def test_wildcard_digit_classes_1xx_3xx_5xx():
    for code, wanted in ((101, "1XX"), (302, "3xx"), (503, "5XX")):
        responses = {wanted: {"description": "x",
                              "content": {"application/json": {}}}}
        doc = make_doc(responses=responses)
        r = call(doc, status_code=code, accept="*/*")
        assert r.status_code == 200, (code, r.text)
        assert r.json()["response"]["match"] == "wildcard"


def test_default_fallback():
    responses = {"default": {"description": "def",
                             "content": {"application/json": {}}}}
    doc = make_doc(responses=responses)
    r = call(doc, status_code=418, accept="*/*")
    assert r.status_code == 200
    body = r.json()
    assert body["response"]["key"] == "default"
    assert body["response"]["match"] == "default"


def test_string_status_code_accepted_and_normalized():
    doc = make_doc(responses=simple_response("application/json"))
    r = call(doc, status_code="200")
    assert r.status_code == 200
    assert r.json()["response"]["status_code"] == 200


def test_no_matching_response_is_422():
    doc = make_doc(responses={"200": {"description": "ok"}})
    r = call(doc, status_code=404)
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "negotiation_failed"
    assert body["errors"][0]["code"] == "response_not_declared"
    assert body["errors"][0]["status_code"] == 404


def test_status_code_validation():
    doc = make_doc()
    for bad in (99, 600, -1, "2xx", "abc", 200.5):
        r = call(doc, status_code=bad)
        assert r.status_code == 400, (bad, r.status_code)
        assert r.json()["error"] == "invalid_negotiation_request"


def test_bool_status_code_rejected():
    doc = make_doc()
    r = call(doc, status_code=True)
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Request Content-Type matching
# --------------------------------------------------------------------------- #


def test_request_exact_match_with_extra_parameter():
    doc = make_doc(request_body=simple_body("application/json"))
    r = call(doc, request_content_type="application/json; charset=utf-8")
    assert r.status_code == 200, r.text
    req = r.json()["request"]
    assert req["declared_media_type"] == "application/json"
    assert req["content_type"] == "application/json; charset=utf-8"


def test_request_declared_parameter_must_be_satisfied():
    doc = make_doc(request_body=simple_body("application/json; version=1"))
    # Request missing the required parameter -> no containment.
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 415
    # ...but when supplied (exact value, name case-insensitive) it matches.
    r2 = call(doc, request_content_type="application/JSON; VERSION=1; charset=utf-8")
    assert r2.status_code == 200
    assert r2.json()["request"]["media_type"] == "application/json; version=1"
    assert r2.json()["request"]["content_type"] == (
        "application/json; charset=utf-8; version=1"
    )


def test_request_parameter_value_is_case_sensitive():
    doc = make_doc(request_body=simple_body("application/json; version=1"))
    r = call(doc, request_content_type="application/json; version=2")
    assert r.status_code == 415


def test_request_wildcard_subtype_matches():
    doc = make_doc(request_body=simple_body("application/*"))
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 200
    assert r.json()["request"]["declared_media_type"] == "application/*"


def test_request_specificity_more_concrete_declaration_wins():
    doc = make_doc(
        request_body={
            "required": True,
            "content": {
                "application/*": {"schema": {"type": "object", "x": "wild"}},
                "application/json": {"schema": {"type": "object", "x": "exact"}},
            },
        }
    )
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 200
    assert r.json()["request"]["declared_media_type"] == "application/json"


def test_request_specificity_parameters_break_type_tie():
    doc = make_doc(
        request_body={
            "required": True,
            "content": {
                "application/json": {"schema": {"x": "bare"}},
                "application/json; version=1": {"schema": {"x": "v1"}},
            },
        }
    )
    r = call(doc, request_content_type="application/json; version=1")
    assert r.status_code == 200
    assert r.json()["request"]["declared_media_type"] == (
        "application/json; version=1"
    )
    # A plain request without version matches the bare declaration.
    r2 = call(doc, request_content_type="application/json")
    assert r2.json()["request"]["declared_media_type"] == "application/json"


def test_equal_specificity_uses_declaration_order():
    # Same wildcard level / parameter count -> first declared wins.
    content = {
        "text/*": {"schema": {"x": "text"}},
        "application/*": {"schema": {"x": "app"}},
    }
    doc = make_doc(request_body={"required": True, "content": content})
    r = call(doc, request_content_type="text/plain")
    assert r.json()["request"]["declared_media_type"] == "text/*"
    r2 = call(doc, request_content_type="application/xml")
    assert r2.json()["request"]["declared_media_type"] == "application/*"


def test_content_type_wildcard_is_a_bad_request():
    doc = make_doc(request_body=simple_body("application/json"))
    r = call(doc, request_content_type="*/*")
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_negotiation_request"


def test_malformed_content_type_is_400():
    doc = make_doc(request_body=simple_body("application/json"))
    for bad in ("", "application", "application/", "application/json; q",
                "application/json; =1", "app lication/json"):
        r = call(doc, request_content_type=bad)
        assert r.status_code == 400, (bad, r.text)


def test_required_body_missing_content_type_is_415():
    doc = make_doc(request_body=simple_body("application/json", required=True))
    r = call(doc)
    assert r.status_code == 415
    assert r.json()["supported"] == ["application/json"]


def test_unsupported_content_type_is_415_with_supported_list():
    doc = make_doc(request_body=simple_body("application/json", "application/xml"))
    r = call(doc, request_content_type="text/plain")
    assert r.status_code == 415
    body = r.json()
    assert body["error"] == "unsupported_media_type"
    assert body["request_content_type"] == "text/plain"
    assert body["supported"] == ["application/json", "application/xml"]


def test_empty_request_content_map_is_415():
    doc = make_doc(request_body={"required": True, "content": {}})
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 415


# --------------------------------------------------------------------------- #
# Accept negotiation
# --------------------------------------------------------------------------- #


def test_accept_q_weights_select_highest():
    doc = make_doc(
        responses=simple_response("application/json", "application/xml")
    )
    r = call(
        doc,
        accept="application/json;q=0.2, application/xml;q=0.8",
    )
    assert r.status_code == 200
    assert r.json()["response"]["declared_media_type"] == "application/xml"


def test_accept_most_specific_range_assigns_q():
    # text/*;q=0.1 is less specific than text/html;q=0.9.
    doc = make_doc(responses=simple_response("text/html"))
    r = call(doc, accept="text/*;q=0.1, text/html;q=0.9")
    assert r.json()["response"]["declared_media_type"] == "text/html"

    # The q comes from the specific text/html range even though it is
    # listed before a wider wildcard with a *higher* q: specificity of
    # the assigning range decides, not ordering vs. weight.
    r2 = call(doc, accept="text/html;q=0.1, text/*;q=0.9, */*;q=0.9")
    assert r2.json()["response"]["declared_media_type"] == "text/html"


def test_accept_equal_q_uses_declaration_order():
    doc = make_doc(
        responses=simple_response("application/json", "application/xml")
    )
    r = call(doc, accept="application/*")
    assert r.json()["response"]["declared_media_type"] == "application/json"
    r2 = call(doc, accept="*/*")
    assert r2.json()["response"]["declared_media_type"] == "application/json"


def test_accept_parameters_must_be_satisfied():
    doc = make_doc(
        responses={
            "200": {
                "description": "ok",
                "content": {
                    "application/json; version=1": {"schema": {"x": 1}},
                    "application/json; version=2": {"schema": {"x": 2}},
                },
            }
        }
    )
    r = call(doc, accept="application/json; version=2")
    assert r.status_code == 200
    assert r.json()["response"]["media_type"] == "application/json; version=2"
    # Representation may carry extra parameters the range does not require.
    r2 = call(
        make_doc(
            responses={
                "200": {
                    "description": "ok",
                    "content": {"application/json; version=1; charset=utf-8": {}},
                }
            }
        ),
        accept="application/json; version=1",
    )
    assert r2.status_code == 200
    assert r2.json()["response"]["media_type"] == (
        "application/json; charset=utf-8; version=1"
    )


def test_accept_q_zero_excludes():
    doc = make_doc(
        responses=simple_response("application/json", "application/xml")
    )
    r = call(doc, accept="application/json;q=0, application/xml;q=0.5")
    assert r.status_code == 200
    assert r.json()["response"]["declared_media_type"] == "application/xml"

    r2 = call(doc, accept="*/*;q=0")
    assert r2.status_code == 406


def test_empty_accept_header_rejects_everything():
    doc = make_doc(responses=simple_response("application/json"))
    r = call(doc, accept="")
    assert r.status_code == 406
    body = r.json()
    assert body["error"] == "not_acceptable"
    assert body["available"] == ["application/json"]


def test_no_acceptable_representation_is_406():
    doc = make_doc(responses=simple_response("application/json"))
    r = call(doc, accept="text/plain")
    assert r.status_code == 406
    assert r.json()["available"] == ["application/json"]


def test_bodyless_response_ignores_accept():
    # A 204 response has no content; Accept can never make it 406.
    doc = make_doc(responses={"204": {"description": "no content"}})
    r = call(doc, status_code=204, accept="text/plain")
    assert r.status_code == 200
    assert r.json()["response"]["present"] is False


def test_malformed_accept_is_400():
    doc = make_doc(responses=simple_response("application/json"))
    for bad in ("text/plain;q=maybe", "text/plain;q=2", "text/plain;q=0.1234",
                "*/json", "text/", ",,", "text/plain; q"):
        r = call(doc, accept=bad)
        assert r.status_code == 400, (bad, r.text)


def test_accept_whitespace_and_casing():
    doc = make_doc(responses=simple_response("application/json"))
    r = call(doc, accept=" Application/JSON ; Q=0.8 , */*;q=0.1 ")
    assert r.status_code == 200
    assert r.json()["response"]["declared_media_type"] == "application/json"


def test_accept_quoted_q_is_extension_parameter_not_weight():
    # q="0" is a quoted extension parameter named q; per RFC 9110 the
    # weight production has no quotes, so application/json keeps q=1 and
    # the representation is still selectable (parameter 'q' simply must
    # be present on the concrete type with that value; a contract type
    # without a q parameter fails that range, which is expected).
    doc = make_doc(responses=simple_response("application/json"))
    r = call(doc, accept='application/json;q="0"')
    assert r.status_code == 406
    # A declared representation carrying that exact extension parameter
    # satisfies the range at the implicit default weight.
    doc2 = make_doc(
        responses={
            "200": {
                "description": "ok",
                "content": {'application/json;q=0': {}},
            }
        }
    )
    r2 = call(doc2, accept='application/json;q="0"')
    assert r2.status_code == 200


def test_accept_structured_suffix_strict():
    # Wildcard token matching is whole-token only; "*+json" does not
    # substring-match "vnd.api+json".
    doc = make_doc(responses=simple_response("application/vnd.api+json"))
    r = call(doc, accept="application/*+json")
    assert r.status_code == 406
    r2 = call(doc, accept="application/vnd.api+json")
    assert r2.status_code == 200


def test_accept_q_value_formats():
    doc = make_doc(responses=simple_response("application/json"))
    for valid in ("application/json;q=1", "application/json;q=1.0",
                  "application/json;q=0.123", "application/json;q=1.000"):
        r = call(doc, accept=valid)
        assert r.status_code == 200, valid
    for invalid in ("application/json;q=0.", "application/json;q=1.001",
                    "application/json;q=0.1234"):
        r = call(doc, accept=invalid)
        assert r.status_code == 400, invalid


# --------------------------------------------------------------------------- #
# Examples extraction
# --------------------------------------------------------------------------- #


def test_inline_example_and_named_examples_extracted():
    components = {
        "examples": {
            "cat": {
                "summary": "A cat",
                "value": {"name": "Milo"},
            }
        }
    }
    doc = make_doc(
        responses={
            "200": {
                "description": "ok",
                "content": {
                    "application/json": {
                        "schema": {"type": "object"},
                        "example": {"name": "Rex"},
                        "examples": {
                            "dog": {"value": {"name": "Rex"}},
                            "cat": {"$ref": "#/components/examples/cat"},
                        },
                    }
                },
            }
        },
        components=components,
    )
    r = call(doc)
    assert r.status_code == 200, r.text
    rep = r.json()["response"]
    assert rep["example"] == {"name": "Rex"}
    assert rep["example_pointer"].endswith(
        "/responses/200/content/application~1json/example"
    )
    names = {item["name"]: item for item in rep["examples"]}
    assert set(names) == {"dog", "cat"}
    assert names["cat"]["value"] == {"name": "Milo"}
    assert names["cat"]["value_pointer"] == "/components/examples/cat/value"
    assert names["cat"]["pointer"] == (
        "/paths/~1pets/post/responses/200/content/application~1json/examples/cat"
    )
    assert names["cat"]["summary"] == "A cat"
    assert names["dog"]["value_pointer"].endswith("/examples/dog/value")


def test_example_without_value_has_null_value():
    doc = make_doc(
        responses={
            "200": {
                "description": "ok",
                "content": {
                    "application/json": {
                        "examples": {"empty": {"summary": "no value"}}
                    }
                },
            }
        }
    )
    r = call(doc)
    item = r.json()["response"]["examples"][0]
    assert item["name"] == "empty"
    assert item["value"] is None
    assert item["value_pointer"] is None


def test_external_value_example_is_422():
    doc = make_doc(
        responses={
            "200": {
                "description": "ok",
                "content": {
                    "application/json": {
                        "examples": {"ext": {"externalValue": "https://x/e.json"}}
                    }
                },
            }
        }
    )
    r = call(doc)
    assert r.status_code == 422
    err = r.json()["errors"][0]
    assert err["code"] == "unsupported_reference"
    assert err["ref"] == "https://x/e.json"
    assert err["pointer"].endswith("/externalValue")


# --------------------------------------------------------------------------- #
# $ref resolution: requestBody / Response / Path Item
# --------------------------------------------------------------------------- #


def test_request_body_ref_30_ignores_siblings():
    components = {
        "requestBodies": {
            "PetBody": {
                "required": True,
                "content": {
                    "application/json": {"schema": {"type": "object", "x": "ref"}}
                },
            }
        }
    }
    # 3.0: sibling keys next to $ref are ignored.
    inline_sibling = {
        "$ref": "#/components/requestBodies/PetBody",
        "required": False,
        "content": {"text/plain": {}},
    }
    doc = make_doc(request_body=inline_sibling, components=components)
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 200, r.text
    req = r.json()["request"]
    assert req["required"] is True
    assert req["declared_media_type"] == "application/json"
    # text/plain comes from an ignored sibling -> 415.
    r2 = call(doc, request_content_type="text/plain")
    assert r2.status_code == 415


def test_request_body_ref_31_merges_siblings():
    components = {
        "requestBodies": {
            "PetBody": {
                "content": {"application/json": {"schema": {"x": "ref"}}}
            }
        }
    }
    inline_sibling = {
        "$ref": "#/components/requestBodies/PetBody",
        "required": True,
    }
    doc = make_doc(
        openapi="3.1.0", request_body=inline_sibling, components=components
    )
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 200
    assert r.json()["request"]["required"] is True


def test_response_ref_and_31_content_sibling_merge():
    components = {
        "responses": {
            "Generic": {
                "description": "generic",
                "content": {"application/json": {"schema": {"x": "json"}}},
            }
        }
    }
    inline = {
        "200": {
            "$ref": "#/components/responses/Generic",
            "content": {"application/xml": {"schema": {"x": "xml"}}},
        }
    }
    doc = make_doc(openapi="3.1.0", responses=inline, components=components)
    # OpenAPI 3.1 sibling merge: the sibling 'content' member as a whole
    # overrides the referenced object's 'content' (nearest-layer wins), so
    # only application/xml survives; the merged pointer follows the layer
    # that declares each surviving member.
    r = call(doc, accept="application/xml")
    assert r.status_code == 200
    assert r.json()["response"]["declared_media_type"] == "application/xml"
    r2 = call(doc, accept="application/json")
    assert r2.status_code == 406
    assert r.json()["response"]["media_type_pointer"] == (
        "/paths/~1pets/post/responses/200/content/application~1xml"
    )
    # 'description' is not overridden, so it keeps the terminal layer pointer.
    # (It is exercised implicitly by a successful resolution.)

    # 3.0 ignores siblings: xml is not available.
    doc30 = make_doc(openapi="3.0.3", responses=inline, components=components)
    r3 = call(doc30, accept="application/xml")
    assert r3.status_code == 406
    r4 = call(doc30, accept="application/json")
    assert r4.status_code == 200
    assert r4.json()["response"]["media_type_pointer"] == (
        "/components/responses/Generic/content/application~1json"
    )


def test_response_ref_31_merges_distinct_sibling_members():
    # A sibling member that the terminal target lacks is added; an existing
    # member is overridden whole.
    components = {
        "responses": {
            "Generic": {
                "description": "generic",
                "content": {"application/json": {"schema": {"x": "json"}}},
            }
        }
    }
    inline = {
        "200": {
            "$ref": "#/components/responses/Generic",
            "headers": {"X-Trace": {"schema": {"type": "string"}}},
        }
    }
    doc = make_doc(openapi="3.1.0", responses=inline, components=components)
    r = call(doc, accept="application/json")
    assert r.status_code == 200
    assert r.json()["response"]["media_type_pointer"] == (
        "/components/responses/Generic/content/application~1json"
    )


def test_path_level_ref_provides_operation():
    components = {
        "pathItems": {
            "Pets": {
                "post": {
                    "responses": {
                        "200": {
                            "description": "ok",
                            "content": {"application/json": {}},
                        }
                    }
                }
            }
        }
    }
    doc = make_doc(
        openapi="3.1.0",
        path_item_extra={"$ref": "#/components/pathItems/Pets"},
        components=components,
    )
    r = call(doc)
    assert r.status_code == 200, r.text
    assert r.json()["operation_pointer"] == "/paths/~1pets/post"


def test_multi_hop_ref_chain():
    components = {
        "responses": {
            "A": {"$ref": "#/components/responses/B"},
            "B": {"$ref": "#/components/responses/C"},
            "C": {"description": "c", "content": {"application/json": {}}},
        }
    }
    doc = make_doc(
        responses={"200": {"$ref": "#/components/responses/A"}},
        components=components,
    )
    r = call(doc)
    assert r.status_code == 200
    assert r.json()["response"]["declared_media_type"] == "application/json"


def test_dangling_request_body_ref_is_422():
    doc = make_doc(
        request_body={"$ref": "#/components/requestBodies/Missing",
                      "content": {"application/json": {}}}
    )
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 422
    err = r.json()["errors"][0]
    assert err["code"] == "unresolvable_reference"
    assert err["ref"] == "#/components/requestBodies/Missing"
    assert err["pointer"] == (
        "/paths/~1pets/post/requestBody"
    )


def test_external_response_ref_is_422():
    doc = make_doc(
        responses={"200": {"$ref": "https://example.com/resp.json#/R"}}
    )
    r = call(doc)
    assert r.status_code == 422
    err = r.json()["errors"][0]
    assert err["code"] == "unresolvable_reference"
    assert err["ref"].startswith("https://")


def test_circular_response_ref_is_422():
    components = {
        "responses": {
            "A": {"$ref": "#/components/responses/B"},
            "B": {"$ref": "#/components/responses/A"},
        }
    }
    doc = make_doc(
        responses={"200": {"$ref": "#/components/responses/A"}},
        components=components,
    )
    r = call(doc)
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "unresolvable_reference"


def test_ref_target_non_object_is_422():
    components = {"requestBodies": {"Body": "not-an-object"}}
    doc = make_doc(
        request_body={"$ref": "#/components/requestBodies/Body",
                      "content": {"application/json": {}}},
        components=components,
    )
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "unresolvable_reference"


def test_dangling_named_example_ref_is_422_and_no_partial_result():
    doc = make_doc(
        responses={
            "200": {
                "description": "ok",
                "content": {
                    "application/json": {
                        "examples": {"gone": {"$ref": "#/components/examples/Gone"}}
                    }
                },
            }
        }
    )
    r = call(doc)
    assert r.status_code == 422
    body = r.json()
    assert body["error"] == "negotiation_failed"
    assert "request" not in body and "response" not in body
    err = body["errors"][0]
    assert err["code"] == "unresolvable_reference"
    assert err["ref"] == "#/components/examples/Gone"


def test_schema_inner_refs_are_returned_verbatim_not_traversed():
    # A dangling $ref *inside* the schema must NOT be followed; schema is
    # returned as declared.
    doc = make_doc(
        responses={
            "200": {
                "description": "ok",
                "content": {
                    "application/json": {
                        "schema": {"$ref": "#/components/schemas/Missing"}
                    }
                },
            }
        }
    )
    r = call(doc)
    assert r.status_code == 200
    assert r.json()["response"]["schema"] == {
        "$ref": "#/components/schemas/Missing"
    }


# --------------------------------------------------------------------------- #
# Structure validation (422 contract errors)
# --------------------------------------------------------------------------- #


def test_operation_without_responses_is_422():
    doc = make_doc(operation_extra={"responses": None})
    r = call(doc)
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_operation"


def test_request_body_without_content_is_422():
    doc = make_doc(request_body={"required": True})
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_operation"


def test_malformed_declared_media_type_is_422():
    doc = make_doc(
        request_body={"required": True, "content": {"not a media type": {}}}
    )
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_media_type"


def test_media_node_not_object_is_422():
    doc = make_doc(
        request_body={"required": True, "content": {"application/json": "x"}}
    )
    r = call(doc, request_content_type="application/json")
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_operation"


def test_examples_container_not_object_is_422():
    doc = make_doc(
        responses={
            "200": {
                "description": "ok",
                "content": {"application/json": {"examples": ["a"]}},
            }
        }
    )
    r = call(doc)
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_operation"


# --------------------------------------------------------------------------- #
# Error precedence / envelope / non-mutation
# --------------------------------------------------------------------------- #


def test_415_takes_precedence_over_406():
    doc = make_doc(
        request_body=simple_body("application/json"),
        responses=simple_response("application/json"),
    )
    r = call(
        doc,
        request_content_type="text/plain",
        accept="text/plain",
    )
    assert r.status_code == 415


def test_contract_422_takes_precedence_over_negotiation_errors():
    # Dangling response ref must be 422 even though headers would 415/406.
    doc = make_doc(
        request_body=simple_body("application/json"),
        responses={"200": {"$ref": "#/components/responses/Missing"}},
    )
    r = call(doc, request_content_type="text/plain", accept="text/plain")
    assert r.status_code == 422


def test_invalid_document_shape_is_400():
    doc = make_doc()
    del doc["openapi"]
    r = call(doc)
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_openapi_document"


def test_unknown_path_and_method_are_400():
    doc = make_doc()
    r = call(doc, selector="POST /nope")
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_selector"
    r2 = call(doc, selector="DELETE /pets")
    assert r2.status_code == 400


def test_malformed_selector_is_400():
    doc = make_doc()
    for bad in ("GET", "GET/pets", "nonsense", "WAT /pets"):
        r = call(doc, selector=bad)
        assert r.status_code == 400, bad


def test_non_string_header_fields_are_400():
    doc = make_doc()
    r = call(doc, extra={"request_content_type": 123})
    assert r.status_code == 400
    r = call(doc, extra={"accept": ["application/json"]})
    assert r.status_code == 400


def test_input_is_not_modified():
    doc = make_doc(
        request_body=simple_body("application/json"),
        responses=simple_response("application/json"),
    )
    snapshot = copy.deepcopy(doc)
    r = call(
        doc,
        request_content_type="application/json; charset=utf-8",
        accept="application/json;q=0.5, */*;q=0.1",
    )
    assert r.status_code == 200
    assert doc == snapshot


def test_415_and_406_contain_no_half_baked_representations():
    doc = make_doc(
        request_body=simple_body("application/json"),
        responses=simple_response("application/json"),
    )
    for status, kwargs in (
        (415, {"request_content_type": "text/plain", "accept": "*/*"}),
        (406, {"request_content_type": "application/json", "accept": "text/plain"}),
    ):
        r = call(doc, **kwargs)
        assert r.status_code == status
        assert "request" not in r.json()
        assert "response" not in r.json()


def test_json_pointer_escaping_in_media_key():
    weird = "application/vnd.example+json"
    doc = make_doc(responses=simple_response(weird))
    r = call(doc)
    pointer = r.json()["response"]["media_type_pointer"]
    assert "/content/" in pointer
    # No raw '/' from the media type token leaks into the pointer.
    assert pointer == (
        "/paths/~1pets/post/responses/200/content/"
        "application~1vnd.example+json"
    )


# --------------------------------------------------------------------------- #
# Extra edge cases
# --------------------------------------------------------------------------- #


def test_optional_body_dangling_ref_is_still_422_even_without_content_type():
    # Contract errors are resolved before the 415 negotiation even though
    # the body is optional and no Content-Type was sent.
    doc = make_doc(
        request_body={
            "required": False,
            "$ref": "#/components/requestBodies/Missing",
        }
    )
    r = call(doc)
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "unresolvable_reference"


def test_response_value_not_object_is_422():
    doc = make_doc(responses={"200": "nope"})
    r = call(doc)
    assert r.status_code == 422
    assert r.json()["errors"][0]["code"] == "invalid_operation"


def test_request_31_sibling_content_pointer_points_at_override_layer():
    components = {
        "requestBodies": {
            "B": {"content": {"application/json": {"schema": {"x": 1}}}}
        }
    }
    inline = {
        "required": True,
        "$ref": "#/components/requestBodies/B",
        "content": {"application/xml": {"schema": {"x": 2}}},
    }
    doc = make_doc(openapi="3.1.0", request_body=inline, components=components)
    r = call(doc, request_content_type="application/xml")
    assert r.status_code == 200
    rep = r.json()["request"]
    assert rep["declared_media_type"] == "application/xml"
    assert rep["media_type_pointer"] == (
        "/paths/~1pets/post/requestBody/content/application~1xml"
    )


def test_request_wildcard_star_star_with_parameters():
    doc = make_doc(
        request_body={
            "required": True,
            "content": {
                "*/*": {"schema": {"x": "anything"}},
                "text/*": {"schema": {"x": "text"}},
            },
        }
    )
    r = call(doc, request_content_type="image/png")
    assert r.status_code == 200
    assert r.json()["request"]["declared_media_type"] == "*/*"
    r2 = call(doc, request_content_type="text/csv")
    assert r2.json()["request"]["declared_media_type"] == "text/*"


def test_accept_multiple_ranges_parameter_specificity_drives_q():
    # application/json (q .9, no params) vs application/json;version=2 (q .1):
    # the parameterized range is more specific but only APPLIES to a
    # representation carrying version=2; a bare json producer takes .9.
    doc = make_doc(responses=simple_response("application/json"))
    r = call(doc, accept="application/json;q=0.9, application/json;version=2;q=0.1")
    assert r.status_code == 200
    assert r.json()["response"]["declared_media_type"] == "application/json"


def test_406_on_wildcard_response_code_when_none_acceptable():
    doc = make_doc(
        responses={"4XX": {"description": "err",
                           "content": {"application/problem+json": {}}}}
    )
    r = call(doc, status_code=404, accept="text/html")
    assert r.status_code == 406
    body = r.json()
    assert body["available"] == ["application/problem+json"]


def test_default_response_bodyless_does_not_406():
    doc = make_doc(responses={"default": {"description": "nothing"}})
    r = call(doc, status_code=500, accept="application/json")
    assert r.status_code == 200
    resp = r.json()["response"]
    assert resp["key"] == "default"
    assert resp["match"] == "default"
    assert resp["present"] is False
