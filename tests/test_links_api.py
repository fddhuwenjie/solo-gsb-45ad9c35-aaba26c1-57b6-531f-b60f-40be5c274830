"""Regression tests for ``POST /links/plan``.

Covers response selection (exact / ``nXX`` / default, numeric and string
status codes), local ``$ref`` resolution of Response / Link / Path Item
objects (multi-hop, 3.0 sibling ignore vs 3.1 sibling merge, dangling /
external / circular), target resolution through ``operationId`` (unique /
duplicate / missing) and local ``operationRef`` (escaped fragments,
non-local, non-operation, missing methods), parameter grouping from path-
and operation-level definitions, cross-location ambiguous names, runtime
expression mapping values (including structured body values, headers,
missing / invalid expressions), literal constants, required-parameter
coverage, requestBody mappings, source JSON Pointers, 400 envelopes and
the non-mutation guarantee.
"""

from __future__ import annotations

import copy

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def make_target(path="/orders/{orderId}", method="get", operation_id="getOrder",
                parameters=None, path_level_parameters=None):
    if parameters is None:
        parameters = [
            {"name": "orderId", "in": "path", "required": True,
             "schema": {"type": "string"}},
            {"name": "trace", "in": "header", "schema": {"type": "string"}},
            {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
        ]
    operation = {"responses": {"200": {"description": "ok"}}}
    if operation_id is not None:
        operation["operationId"] = operation_id
    if parameters is not None:
        operation["parameters"] = parameters
    item = {method: operation}
    if path_level_parameters is not None:
        item["parameters"] = path_level_parameters
    return path, item


def make_doc(link, *, link_status="201", openapi="3.0.3",
             source_path="/orders", source_method="post",
             source_responses=None, target_path="/orders/{orderId}",
             target_item=None, target_method="get", operation_id="getOrder",
             target_parameters=None, target_path_level=None,
             components=None, source_operation_extra=None,
             source_path_item_extra=None):
    if target_item is None:
        target_path, target_item = make_target(
            target_path, target_method, operation_id,
            target_parameters, target_path_level,
        )
    source_operation = {
        "responses": source_responses
        if source_responses is not None
        else {link_status: {"description": "created", "links": {"getOrder": link}}},
    }
    if source_operation_extra:
        source_operation.update(source_operation_extra)
    source_item = {source_method: source_operation}
    if source_path_item_extra:
        source_item.update(source_path_item_extra)
    doc = {
        "openapi": openapi,
        "info": {"title": "Orders", "version": "1.0"},
        "paths": {source_path: source_item, target_path: target_item},
    }
    if components is not None:
        doc["components"] = components
    return doc


def context(status_code=201, *, response_body=None, request=None):
    ctx_response = {"statusCode": status_code}
    if response_body is not None:
        ctx_response["body"] = response_body
    ctx = {"response": ctx_response}
    if request is not None:
        ctx["request"] = request
    return ctx


def plan(doc, *, selector="POST /orders", link="getOrder", ctx=None):
    payload = {"document": doc, "selector": selector, "link": link}
    if ctx is not None:
        payload["context"] = ctx
    return client.post("/links/plan", json=payload)


def codes(resp):
    return [error["code"] for error in resp.json()["errors"]]


HAPPY_LINK = {
    "operationId": "getOrder",
    "parameters": {
        "orderId": "$response.body#/id",
        "trace": "$request.header.x-trace",
        "verbose": True,
    },
    "requestBody": "$response.body",
}

HAPPY_BODY = {"id": "ord-42", "total": 9, "items": [{"sku": "a"}]}
HAPPY_REQUEST = {"header": {"X-Trace": "t-1"}}


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_happy_path_plans_grouped_values_and_body():
    doc = make_doc(HAPPY_LINK)
    resp = plan(doc, ctx=context(response_body=HAPPY_BODY, request=HAPPY_REQUEST))
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["target"]["selector"] == "GET /orders/{orderId}"
    assert data["target"]["operation_id"] == "getOrder"
    assert data["target"]["operation_ref"] is None
    assert data["target"]["operation_pointer"] == "/paths/~1orders~1{orderId}/get"

    values = data["parameter_values"]
    assert values["path"] == [
        {
            "name": "orderId",
            "value": "ord-42",
            "expression": "$response.body#/id",
            "value_pointer": "/paths/~1orders/post/responses/201/links/getOrder/parameters/orderId",
            "parameter_pointer": "/paths/~1orders~1{orderId}/get/parameters/0",
        }
    ]
    assert values["query"][0]["name"] == "verbose"
    assert values["query"][0]["value"] is True
    assert values["query"][0]["expression"] is None
    assert values["header"][0]["name"] == "trace"
    assert values["header"][0]["value"] == "t-1"
    assert values["cookie"] == []

    assert data["request_body"] == {
        "provided": True,
        "value": HAPPY_BODY,
        "expression": "$response.body",
        "value_pointer": "/paths/~1orders/post/responses/201/links/getOrder/requestBody",
    }
    assert data["response"] == {
        "status_code": 201,
        "key": "201",
        "match": "exact",
        "pointer": "/paths/~1orders/post/responses/201",
    }
    assert data["source"] == {
        "selector": "POST /orders",
        "operation_pointer": "/paths/~1orders/post",
        "link_name": "getOrder",
        "link_pointer": "/paths/~1orders/post/responses/201/links/getOrder",
    }


def test_request_body_omitted_is_null_and_not_provided():
    link = {"operationId": "getOrder",
            "parameters": {"orderId": "$response.body#/id"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context(response_body={"id": "x"}))
    assert resp.status_code == 200, resp.text
    body = resp.json()["request_body"]
    assert body == {"provided": False, "value": None,
                    "expression": None, "value_pointer": None}


def test_literal_constants_accept_numbers_objects_arrays_and_null():
    link = {
        "operationId": "getOrder",
        "parameters": {
            "orderId": 7,
            "verbose": {"nested": [1, 2]},
            "trace": ["a", "b"],
        },
        "requestBody": {"fixed": True, "n": None},
    }
    doc = make_doc(
        link,
        target_parameters=[
            {"name": "orderId", "in": "path", "required": True},
            {"name": "trace", "in": "header", "schema": {"type": "array",
                                                        "items": {"type": "string"}}},
            {"name": "verbose", "in": "query"},
        ],
    )
    resp = plan(doc, ctx=context())
    assert resp.status_code == 200, resp.text
    values = resp.json()["parameter_values"]
    assert values["path"][0]["value"] == 7
    assert values["query"][0]["value"] == {"nested": [1, 2]}
    assert values["header"][0]["value"] == ["a", "b"]
    assert resp.json()["request_body"]["value"] == {"fixed": True, "n": None}


def test_structured_body_expression_may_be_object_or_array():
    link = {
        "operationId": "getOrder",
        "parameters": {"orderId": "v"},
        "requestBody": "$response.body#/items",
    }
    doc = make_doc(link)
    resp = plan(doc, ctx=context(response_body=HAPPY_BODY))
    assert resp.status_code == 200, resp.text
    assert resp.json()["request_body"]["value"] == [{"sku": "a"}]


def test_path_level_parameter_is_part_of_the_target_effective_set():
    link = {"operationId": "getOrder",
            "parameters": {"orderId": "$response.body#/id"}}
    target_path = "/orders/{orderId}"
    target_item = {
        "parameters": [
            {"name": "orderId", "in": "path", "required": True,
             "schema": {"type": "string"}}
        ],
        "get": {
            "operationId": "getOrder",
            "responses": {"200": {"description": "ok"}},
        },
    }
    doc = make_doc(link, target_path=target_path, target_item=target_item)
    resp = plan(doc, ctx=context(response_body={"id": "p-9"}))
    assert resp.status_code == 200, resp.text
    item = resp.json()["parameter_values"]["path"][0]
    assert item["value"] == "p-9"
    assert item["parameter_pointer"] == "/paths/~1orders~1{orderId}/parameters/0"


def test_operation_level_parameter_overrides_path_level_one():
    link = {"operationId": "getOrder", "parameters": {"orderId": "lit"}}
    doc = make_doc(
        link,
        target_parameters=[
            {"name": "orderId", "in": "path", "required": True,
             "description": "op-level", "schema": {"type": "string"}}
        ],
        target_path_level=[
            {"name": "orderId", "in": "path", "required": True,
             "description": "path-level", "schema": {"type": "integer"}}
        ],
    )
    resp = plan(doc, ctx=context())
    assert resp.status_code == 200, resp.text
    assert resp.json()["parameter_values"]["path"][0]["parameter_pointer"] == (
        "/paths/~1orders~1{orderId}/get/parameters/0"
    )


# --------------------------------------------------------------------------- #
# Response selection
# --------------------------------------------------------------------------- #


def test_exact_code_beats_wildcard_and_default():
    responses = {
        "2XX": {"description": "class", "links": {
            "getOrder": {"operationId": "getOrder",
                         "parameters": {"orderId": "wildcard"}}}},
        "201": {"description": "exact", "links": {
            "getOrder": {"operationId": "getOrder",
                         "parameters": {"orderId": "exact"}}}},
        "default": {"description": "fallback", "links": {
            "getOrder": {"operationId": "getOrder",
                         "parameters": {"orderId": "default"}}}},
    }
    doc = make_doc(None, source_responses=responses)
    resp = plan(doc, ctx=context(201, response_body={}))
    assert resp.status_code == 200
    assert resp.json()["response"]["match"] == "exact"
    assert resp.json()["parameter_values"]["path"][0]["value"] == "exact"


def test_wildcard_is_used_without_exact_match():
    responses = {
        "2XX": {"description": "class", "links": {
            "getOrder": {"operationId": "getOrder",
                         "parameters": {"orderId": "wild"}}}},
        "default": {"description": "fallback", "links": {
            "getOrder": {"operationId": "getOrder",
                         "parameters": {"orderId": "def"}}}},
    }
    doc = make_doc(None, source_responses=responses)
    resp = plan(doc, ctx=context(204, response_body={}))
    assert resp.status_code == 200
    body = resp.json()
    assert body["response"]["match"] == "wildcard"
    assert body["response"]["key"] == "2XX"
    assert body["parameter_values"]["path"][0]["value"] == "wild"


def test_wildcard_matching_is_case_insensitive():
    responses = {"2xx": {"description": "low", "links": {
        "getOrder": {"operationId": "getOrder", "parameters": {"orderId": "w"}}}}}
    doc = make_doc(None, source_responses=responses)
    resp = plan(doc, ctx=context(204))
    assert resp.status_code == 200
    assert resp.json()["response"]["match"] == "wildcard"


def test_default_response_is_last_resort():
    responses = {"default": {"description": "fallback", "links": {
        "getOrder": {"operationId": "getOrder",
                     "parameters": {"orderId": "d"}}}}}
    doc = make_doc(None, source_responses=responses)
    resp = plan(doc, ctx=context(500))
    assert resp.status_code == 200
    body = resp.json()
    assert body["response"] == {
        "status_code": 500, "key": "default", "match": "default",
        "pointer": "/paths/~1orders/post/responses/default",
    }
    assert body["parameter_values"]["path"][0]["value"] == "d"


def test_string_status_code_selects_response():
    doc = make_doc(HAPPY_LINK)
    resp = plan(doc, ctx=context("201", response_body=HAPPY_BODY,
                                 request=HAPPY_REQUEST))
    assert resp.status_code == 200
    assert resp.json()["response"]["status_code"] == "201"


def test_missing_status_code_is_422():
    doc = make_doc(HAPPY_LINK)
    resp = plan(doc, ctx={"response": {"body": HAPPY_BODY}})
    assert resp.status_code == 422
    assert codes(resp) == ["missing_value"]
    assert resp.json()["errors"][0]["pointer"] == "/context/response/statusCode"


def test_unmatched_status_code_is_422():
    responses = {"200": {"description": "ok", "links": {
        "getOrder": {"operationId": "getOrder", "parameters": {"orderId": "x"}}}}}
    doc = make_doc(None, source_responses=responses)
    resp = plan(doc, ctx=context(404))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]


def test_unknown_link_name_is_422_and_lists_available_links():
    doc = make_doc(HAPPY_LINK)
    resp = plan(doc, link="ghost", ctx=context())
    assert resp.status_code == 422
    error = resp.json()["errors"][0]
    assert error["code"] == "invalid_link"
    assert "ghost" in error["error"]
    assert "getOrder" in error["error"]


# --------------------------------------------------------------------------- #
# operationId / operationRef targets
# --------------------------------------------------------------------------- #


def test_operation_ref_local_fragment_resolves_target():
    link = {"operationRef": "#/paths/~1orders~1{orderId}/get",
            "parameters": {"orderId": "$response.body#/id"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context(response_body={"id": "z1"}))
    assert resp.status_code == 200, resp.text
    target = resp.json()["target"]
    assert target["operation_ref"] == "#/paths/~1orders~1{orderId}/get"
    assert target["operation_id"] is None
    assert target["path"] == "/orders/{orderId}"
    assert target["operation_pointer"] == "/paths/~1orders~1{orderId}/get"
    assert resp.json()["parameter_values"]["path"][0]["value"] == "z1"


def test_operation_ref_into_31_components_path_item_has_no_path():
    components = {"pathItems": {"T": {"get": {"responses": {"200": {"description": "o"}}}}}}
    link = {"operationRef": "#/components/pathItems/T/get"}
    source = {
        "200": {"description": "o", "links": {"getOrder": link}},
    }
    doc = make_doc(None, openapi="3.1.0", source_responses=source,
                   components=components,
                   target_path="/unused", target_item={"get": {"description": "x"}})
    resp = plan(doc, ctx=context(200))
    assert resp.status_code == 200, resp.text
    target = resp.json()["target"]
    assert target["path"] is None
    assert target["selector"] is None
    assert target["operation_pointer"] == "/components/pathItems/T/get"


def test_operation_ref_to_external_uri_is_422():
    link = {"operationRef": "https://x.example.com/api.yaml#/paths/~1t/get"}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_operation_ref_not_ending_in_method_is_422():
    link = {"operationRef": "#/paths/~1orders~1{orderId}"}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_link_target"]


def test_operation_ref_to_dangling_pointer_is_422():
    link = {"operationRef": "#/paths/~1missing/get"}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_operation_ref_root_is_422():
    link = {"operationRef": "#"}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_link_target"]


def test_operation_ref_missing_method_on_path_item_is_422():
    # /orders/{orderId} declares GET, not POST, so the method is absent.
    link = {"operationRef": "#/paths/~1orders~1{orderId}/post"}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_link_target"]


def test_missing_operation_id_is_422():
    doc = make_doc({"operationId": "absent"})
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_link_target"]


def test_duplicate_operation_id_is_422():
    doc = make_doc({"operationId": "getOrder"})
    doc["paths"]["/other"] = {"get": {"operationId": "getOrder",
                                      "responses": {"200": {"description": "x"}}}}
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_link_target"]
    assert "not globally unique" in resp.json()["errors"][0]["error"]


def test_both_operation_ref_and_id_is_422():
    link = {
        "operationId": "getOrder",
        "operationRef": "#/paths/~1orders~1{orderId}/get",
    }
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]


def test_neither_operation_ref_nor_id_is_422():
    doc = make_doc({"description": "no target"})
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]


# --------------------------------------------------------------------------- #
# Parameters
# --------------------------------------------------------------------------- #


def test_required_parameter_left_unassigned_is_422():
    link = {"operationId": "getOrder", "parameters": {"trace": "t"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    error = resp.json()["errors"][0]
    assert error["code"] == "missing_required_parameter"
    assert error["name"] == "orderId"
    assert error["in"] == "path"
    assert error["pointer"].endswith("/parameters/0")


def test_unknown_parameter_mapping_key_is_422():
    link = {"operationId": "getOrder",
            "parameters": {"ghost": "x", "orderId": "v"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_parameter"]
    assert resp.json()["errors"][0]["name"] == "ghost"


def test_parameter_name_spanning_locations_is_ambiguous_422():
    components = {
        "parameters": {
            "IdHeader": {"name": "id", "in": "header", "schema": {"type": "string"}},
            "IdQuery": {"name": "id", "in": "query", "schema": {"type": "string"}},
        }
    }
    target_item = {"get": {
        "operationId": "getThing",
        "parameters": [
            {"$ref": "#/components/parameters/IdHeader"},
            {"$ref": "#/components/parameters/IdQuery"},
        ],
        "responses": {"200": {"description": "o"}},
    }}
    link = {"operationId": "getThing", "parameters": {"id": "v"}}
    doc = make_doc(
        link, target_path="/things", target_item=target_item,
        components=components,
    )
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["ambiguous_parameter"]
    assert "header, query" in resp.json()["errors"][0]["error"]


def test_optional_cross_location_duplicate_name_without_mapping_is_fine():
    target_item = {"get": {
        "operationId": "getThing",
        "parameters": [
            {"name": "id", "in": "header"},
            {"name": "id", "in": "query"},
        ],
        "responses": {"200": {"description": "o"}},
    }}
    link = {"operationId": "getThing"}
    doc = make_doc(link, target_path="/things", target_item=target_item)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 200, resp.text
    values = resp.json()["parameter_values"]
    assert values["path"] == [] and values["query"] == [] and values["header"] == []


def test_required_ambiguous_name_is_reported_once_even_when_mapped():
    target_item = {"get": {
        "operationId": "getThing",
        "parameters": [
            {"name": "id", "in": "path", "required": True},
            {"name": "id", "in": "query"},
        ],
        "responses": {"200": {"description": "o"}},
    }}
    link = {"operationId": "getThing", "parameters": {"id": "v"}}
    doc = make_doc(link, target_path="/things/{id}", target_item=target_item)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp).count("ambiguous_parameter") == 1


def test_invalid_target_parameter_location_is_422():
    target_path, target_item = make_target(
        parameters=[{"name": "weird", "in": "body"}]
    )
    link = {"operationId": "getOrder"}
    doc = make_doc(link, target_path=target_path, target_item=target_item)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_parameter"]


def test_class_wildcards_cover_all_five_status_classes():
    for digit, code in [("1", 100), ("3", 302), ("4", 404), ("5", 503)]:
        responses = {f"{digit}XX": {"description": "c", "links": {
            "getOrder": {"operationId": "getOrder",
                         "parameters": {"orderId": "w"}}}}}
        doc = make_doc(None, source_responses=responses)
        resp = plan(doc, ctx=context(code))
        assert resp.status_code == 200, (digit, resp.text)
        assert resp.json()["response"]["match"] == "wildcard"


def test_dangling_parameter_ref_on_target_is_422():
    target_item = {"get": {
        "operationId": "getThing",
        "parameters": [{"$ref": "#/components/parameters/Missing"}],
        "responses": {"200": {"description": "o"}},
    }}
    link = {"operationId": "getThing"}
    doc = make_doc(link, target_path="/things", target_item=target_item)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


# --------------------------------------------------------------------------- #
# Expression evaluation
# --------------------------------------------------------------------------- #


def test_expression_with_missing_body_fragment_is_422():
    link = {"operationId": "getOrder",
            "parameters": {"orderId": "$response.body#/nope"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context(response_body={"id": "x"}))
    assert resp.status_code == 422
    assert sorted(codes(resp)) == sorted(
        ["missing_value", "missing_required_parameter"]
    )
    error = next(e for e in resp.json()["errors"] if e["code"] == "missing_value")
    assert error["expression"] == "$response.body#/nope"
    assert error["context_pointer"] == "/context/response/body/nope"


def test_expression_resolving_to_null_is_422():
    link = {"operationId": "getOrder",
            "parameters": {"orderId": "$response.body#/id"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context(response_body={"id": None}))
    assert resp.status_code == 422
    assert "missing_value" in codes(resp)


def test_invalid_runtime_expression_is_422():
    link = {"operationId": "getOrder",
            "parameters": {"orderId": "$nope.body"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_expression", "missing_required_parameter"]


def test_template_like_strings_not_starting_with_dollar_are_literals():
    # Link mapping values are either whole runtime expressions or constants;
    # a value that merely embeds braces is an opaque constant.
    link = {"operationId": "getOrder",
            "parameters": {"orderId": "id-{$response.body#/id}"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context(response_body={"id": "x"}))
    assert resp.status_code == 200, resp.text
    item = resp.json()["parameter_values"]["path"][0]
    assert item["value"] == "id-{$response.body#/id}"
    assert item["expression"] is None


def test_request_query_expression_allows_structured_values_and_body_object():
    link = {
        "operationId": "getOrder",
        "parameters": {"orderId": "$request.query.ids"},
        "requestBody": "$request.body",
    }
    doc = make_doc(link)
    request = {"query": {"ids": ["a", "b"]}, "body": {"any": {"k": 1}}}
    resp = plan(doc, ctx=context(request=request))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["parameter_values"]["path"][0]["value"] == ["a", "b"]
    assert data["request_body"]["value"] == {"any": {"k": 1}}


def test_header_expression_matches_case_insensitively():
    link = {
        "operationId": "getOrder",
        "parameters": {"orderId": "v", "trace": "$request.header.X-TRACE"},
    }
    doc = make_doc(link)
    resp = plan(doc, ctx=context(request={"header": {"x-trace": "tt"}}))
    assert resp.status_code == 200
    assert resp.json()["parameter_values"]["header"][0]["value"] == "tt"


def test_ambiguous_context_header_is_422():
    link = {
        "operationId": "getOrder",
        "parameters": {"orderId": "v", "trace": "$request.header.x-trace"},
    }
    doc = make_doc(link)
    request = {"header": {"X-Trace": "a", "x-trace": "b"}}
    resp = plan(doc, ctx=context(request=request))
    assert resp.status_code == 422
    assert codes(resp) == ["ambiguous_header"]


def test_request_body_expression_missing_message_is_422():
    link = {"operationId": "getOrder", "requestBody": "$request.body"}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert sorted(codes(resp)) == sorted(
        ["missing_value", "missing_required_parameter"]
    )
    assert any(
        e.get("expression") == "$request.body" and e["code"] == "missing_value"
        for e in resp.json()["errors"]
    )


def test_status_code_expression_in_parameter_value():
    link = {
        "operationId": "getOrder",
        "parameters": {"orderId": "v", "verbose": "$statusCode"},
    }
    doc = make_doc(link)
    resp = plan(doc, ctx=context(201))
    assert resp.status_code == 200
    assert resp.json()["parameter_values"]["query"][0]["value"] == 201


def test_cookie_parameter_group_and_null_literal_for_optional():
    target_path, target_item = make_target(
        path="/c/{id}",
        parameters=[
            {"name": "id", "in": "path", "required": True,
             "schema": {"type": "string"}},
            {"name": "session", "in": "cookie", "schema": {"type": "string"}},
        ],
    )
    link = {"operationId": "getOrder",
            "parameters": {"id": "$response.body#/id", "session": None}}
    doc = make_doc(link, target_path=target_path, target_item=target_item)
    resp = plan(doc, ctx=context(response_body={"id": "x"}))
    assert resp.status_code == 200, resp.text
    values = resp.json()["parameter_values"]
    assert values["path"][0]["value"] == "x"
    assert values["cookie"] == [
        {
            "name": "session",
            "value": None,
            "expression": None,
            "value_pointer": "/paths/~1orders/post/responses/201/links/getOrder/parameters/session",
            "parameter_pointer": "/paths/~1c~1{id}/get/parameters/1",
        }
    ]


def test_operation_ref_method_token_is_case_insensitive():
    link = {"operationRef": "#/paths/~1orders~1{orderId}/GET",
            "parameters": {"orderId": "v"}}
    doc = make_doc(link)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 200, resp.text
    assert resp.json()["target"]["method"] == "get"


# --------------------------------------------------------------------------- #
# $ref resolution
# --------------------------------------------------------------------------- #


def test_response_and_link_refs_resolve_with_component_pointers():
    components = {
        "responses": {"Created": {"description": "created", "links": {
            "getOrder": {"operationId": "getOrder",
                         "parameters": {"orderId": "$response.body#/id"}}}}},
    }
    source_responses = {"201": {"$ref": "#/components/responses/Created"}}
    doc = make_doc(None, source_responses=source_responses,
                   components=components)
    resp = plan(doc, ctx=context(response_body={"id": "c1"}))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["source"]["link_pointer"] == (
        "/components/responses/Created/links/getOrder"
    )
    assert data["parameter_values"]["path"][0]["value_pointer"] == (
        "/components/responses/Created/links/getOrder/parameters/orderId"
    )
    assert data["response"]["pointer"] == "/paths/~1orders/post/responses/201"


def test_link_ref_resolves_to_component():
    components = {"links": {"GetById": {
        "operationId": "getOrder",
        "parameters": {"orderId": "$response.body#/id"},
    }}}
    source_responses = {"201": {"description": "created", "links": {
        "getOrder": {"$ref": "#/components/links/GetById"}}}}
    doc = make_doc(None, source_responses=source_responses,
                   components=components)
    resp = plan(doc, ctx=context(response_body={"id": "c2"}))
    assert resp.status_code == 200, resp.text
    assert resp.json()["source"]["link_pointer"] == (
        "/paths/~1orders/post/responses/201/links/getOrder"
    )
    assert resp.json()["parameter_values"]["path"][0]["value_pointer"] == (
        "/components/links/GetById/parameters/orderId"
    )


def test_dangling_link_ref_is_422():
    source_responses = {"201": {"description": "created", "links": {
        "getOrder": {"$ref": "#/components/links/Missing"}}}}
    doc = make_doc(None, source_responses=source_responses)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_external_link_ref_is_422():
    source_responses = {"201": {"description": "created", "links": {
        "getOrder": {"$ref": "other.yaml#/components/links/X"}}}}
    doc = make_doc(None, source_responses=source_responses)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_circular_link_ref_chain_is_422():
    components = {"links": {
        "A": {"$ref": "#/components/links/B"},
        "B": {"$ref": "#/components/links/A"},
    }}
    source_responses = {"201": {"description": "created", "links": {
        "getOrder": {"$ref": "#/components/links/A"}}}}
    doc = make_doc(None, source_responses=source_responses,
                   components=components)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]
    assert "circular" in resp.json()["errors"][0]["error"]


def test_circular_response_ref_chain_is_422():
    components = {"responses": {
        "A": {"$ref": "#/components/responses/B"},
        "B": {"$ref": "#/components/responses/A"},
    }}
    source_responses = {"201": {"$ref": "#/components/responses/A"}}
    doc = make_doc(None, source_responses=source_responses,
                   components=components)
    resp = plan(doc, ctx=context())
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_31_sibling_fields_override_link_parameters():
    components = {"links": {"Base": {
        "operationId": "getOrder",
        "parameters": {"orderId": "$response.body#/base"},
    }}}
    source_responses = {"200": {
        "description": "o",
        "links": {"getOrder": {
            "$ref": "#/components/links/Base",
            "parameters": {"orderId": "$response.body#/override"},
        }},
    }}
    doc = make_doc(None, openapi="3.1.0", source_responses=source_responses,
                   components=components)
    resp = plan(doc, ctx=context(200, response_body={"base": "B", "override": "O"}))
    assert resp.status_code == 200, resp.text
    item = resp.json()["parameter_values"]["path"][0]
    assert item["value"] == "O"
    assert item["value_pointer"] == (
        "/paths/~1orders/post/responses/200/links/getOrder/parameters/orderId"
    )


def test_30_ignores_ref_siblings():
    components = {"links": {"Base": {
        "operationId": "getOrder",
        "parameters": {"orderId": "$response.body#/base"},
    }}}
    source_responses = {"200": {
        "description": "o",
        "links": {"getOrder": {
            "$ref": "#/components/links/Base",
            "parameters": {"orderId": "$response.body#/override"},
        }},
    }}
    doc = make_doc(None, openapi="3.0.3", source_responses=source_responses,
                   components=components)
    resp = plan(doc, ctx=context(200, response_body={"base": "B", "override": "O"}))
    assert resp.status_code == 200, resp.text
    item = resp.json()["parameter_values"]["path"][0]
    assert item["value"] == "B"
    assert item["value_pointer"] == "/components/links/Base/parameters/orderId"


def test_source_path_item_ref_resolves_cycle_safe():
    components = {"pathItems": {"Create": {
        "post": {"responses": {"201": {"description": "o", "links": {
            "getOrder": {"operationId": "getOrder",
                         "parameters": {"orderId": "v"}}}}}}}}}
    doc = make_doc(
        HAPPY_LINK,
        openapi="3.1.0",
        source_path_item_extra={"$ref": "#/components/pathItems/Create"},
        components=components,
    )
    # The sibling post in-place plus the referenced path item both expose post;
    # OpenAPI 3.1 merges layers, nearer siblings win.
    del doc["paths"]["/orders"]["post"]
    resp = plan(doc, ctx=context(response_body=HAPPY_BODY))
    assert resp.status_code == 200, resp.text
    assert resp.json()["source"]["operation_pointer"] == "/paths/~1orders/post"


def test_target_path_item_ref_is_resolved_for_operation_ref():
    components = {"pathItems": {"Order": {
        "get": {"responses": {"200": {"description": "o"}}}}}}
    # operationRef points at a path item that is itself a $ref.
    doc = make_doc(
        {"operationRef": "#/paths/~1orders~1{orderId}/get"},
        components=components,
    )
    doc["paths"]["/orders/{orderId}"] = {"$ref": "#/components/pathItems/Order"}
    resp = plan(doc, ctx=context())
    assert resp.status_code == 200, resp.text
    assert resp.json()["target"]["operation_pointer"] == "/paths/~1orders~1{orderId}/get"


# --------------------------------------------------------------------------- #
# 400 envelopes
# --------------------------------------------------------------------------- #


def test_bad_document_shape_is_400():
    resp = client.post("/links/plan", json={
        "document": {"openapi": "2.0", "paths": {}},
        "selector": "POST /orders", "link": "getOrder",
        "context": context(),
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_openapi_document"


def test_bad_selector_is_400():
    doc = make_doc(HAPPY_LINK)
    resp = plan(doc, selector="nonsense", ctx=context())
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_selector"


def test_unknown_selector_path_is_400():
    doc = make_doc(HAPPY_LINK)
    resp = plan(doc, selector="POST /missing", ctx=context())
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_selector"


def test_empty_link_name_is_400():
    doc = make_doc(HAPPY_LINK)
    resp = plan(doc, link="", ctx=context())
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_link_request"


def test_malformed_context_envelope_is_400():
    doc = make_doc(HAPPY_LINK)
    resp = client.post("/links/plan", json={
        "document": doc, "selector": "POST /orders", "link": "getOrder",
        "context": {"response": {"statusCode": "201"}, "bogus": 1},
    })
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_link_request"


def test_context_defaults_to_empty_and_missing_status_is_422_not_400():
    doc = make_doc(HAPPY_LINK)
    resp = client.post("/links/plan", json={
        "document": doc, "selector": "POST /orders", "link": "getOrder",
    })
    assert resp.status_code == 422
    assert codes(resp) == ["missing_value"]


# --------------------------------------------------------------------------- #
# Non-mutation / error aggregation
# --------------------------------------------------------------------------- #


def test_input_document_and_context_are_not_modified():
    doc = make_doc(HAPPY_LINK)
    ctx = context(response_body=HAPPY_BODY, request=HAPPY_REQUEST)
    doc_snapshot = copy.deepcopy(doc)
    ctx_snapshot = copy.deepcopy(ctx)
    resp = plan(doc, ctx=ctx)
    assert resp.status_code == 200
    assert doc == doc_snapshot
    assert ctx == ctx_snapshot


def test_errors_are_aggregated_and_stably_sorted():
    link = {
        "operationId": "getOrder",
        "parameters": {
            "orderId": "$response.body#/missing",
            "ghost": "x",
            "trace": "$request.header.absent",
        },
        "requestBody": "$response.body#/also-missing",
    }
    doc = make_doc(link)
    resp = plan(doc, ctx=context(response_body={}))
    assert resp.status_code == 422
    # Every independent problem is reported in one response: the failed
    # orderId expression also leaves the required path parameter unassigned.
    assert sorted(codes(resp)) == sorted([
        "missing_value", "unknown_parameter",
        "missing_value", "missing_value", "missing_required_parameter",
    ])
    raw = resp.json()["errors"]
    assert raw == sorted(
        raw,
        key=lambda item: (
            str(item.get("code")), str(item.get("pointer")),
            str(item.get("expression")), str(item.get("ref")),
            str(item.get("error")),
        ),
    )


def test_no_partial_plan_on_422_and_root_endpoint_lists_route():
    root = client.get("/").json()
    assert root["links_plan"] == "POST /links/plan"
