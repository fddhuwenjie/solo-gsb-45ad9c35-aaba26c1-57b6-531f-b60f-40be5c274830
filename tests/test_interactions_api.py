"""Regression tests for ``POST /interactions/graph``.

Covers contract and callback node identity (occurrence pointers for
``paths`` operations, declaration pointers for callback operations,
shared components Path Items), link edges via local ``operationRef``
(paths targets, ``components/pathItems`` targets, escaped fragments,
non-method / missing-method targets) and globally unique
``operationId``, callback edges via local Callback Object / Path Item
``$ref`` chains, OpenAPI 3.0 sibling ignore vs 3.1 nearest-wins merge,
duplicate ``operationId`` detection (even when unused by any link),
dangling / external / circular references, malformed containers,
all-errors-at-once 422 aggregation without a partial graph, stable
pointer sorting and the non-mutation guarantee.
"""

from __future__ import annotations

import copy

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


def make_doc(*, openapi="3.0.3", link=None, links=None, callback=None,
             callbacks=None, source_responses=None, source_operation_extra=None,
             extra_paths=None, components=None):
    target = {
        "get": {
            "operationId": "getOrder",
            "responses": {"200": {"description": "ok"}},
        }
    }
    if source_responses is None:
        source_responses = {"201": {"description": "created"}}
        if link is not None or links is not None:
            source_responses["201"]["links"] = (
                links if links is not None else {"fetchOrder": link}
            )
    source_operation = {
        "operationId": "createOrder",
        "responses": source_responses,
    }
    if callback is not None or callbacks is not None:
        source_operation["callbacks"] = (
            callbacks if callbacks is not None else {"onShipped": callback}
        )
    if source_operation_extra:
        source_operation.update(source_operation_extra)
    paths = {
        "/orders": {"post": source_operation},
        "/orders/{orderId}": target,
    }
    if extra_paths:
        paths.update(extra_paths)
    doc = {
        "openapi": openapi,
        "info": {"title": "Orders", "version": "1.0"},
        "paths": paths,
    }
    if components is not None:
        doc["components"] = components
    return doc


def graph(doc):
    return client.post("/interactions/graph", json={"document": doc})


def codes(resp):
    return [error["code"] for error in resp.json()["errors"]]


def nodes_by_id(resp):
    return {node["id"]: node for node in resp.json()["nodes"]}


SOURCE = "/paths/~1orders/post"
TARGET = "/paths/~1orders~1{orderId}/get"
CALLBACK_EXPR = "{$request.body#/callbackUrl}"
CALLBACK_EXPR_ESCAPED = "{$request.body#~1callbackUrl}"
CALLBACK_POINTER = f"{SOURCE}/callbacks/onShipped/{CALLBACK_EXPR_ESCAPED}"
CALLBACK_NODE = f"{CALLBACK_POINTER}/post"


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


def test_happy_path_link_and_callback():
    resp = graph(
        make_doc(
            link={"operationId": "getOrder"},
            callback={CALLBACK_EXPR: {"post": {"responses": {"200": {"description": "ok"}}}}},
        )
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 3
    assert body["edge_count"] == 2

    nodes = nodes_by_id(resp)
    assert nodes[SOURCE] == {
        "id": SOURCE,
        "kind": "operation",
        "method": "post",
        "path": "/orders",
        "operation_id": "createOrder",
    }
    assert nodes[TARGET] == {
        "id": TARGET,
        "kind": "operation",
        "method": "get",
        "path": "/orders/{orderId}",
        "operation_id": "getOrder",
    }
    assert nodes[CALLBACK_NODE] == {
        "id": CALLBACK_NODE,
        "kind": "callback",
        "method": "post",
        "path": None,
        "operation_id": None,
    }

    edges = body["edges"]
    assert edges[0] == {
        "kind": "callback",
        "name": "onShipped",
        "pointer": CALLBACK_POINTER,
        "source": SOURCE,
        "target": CALLBACK_NODE,
        "method": "post",
        "response_key": None,
        "callback_url": CALLBACK_EXPR,
    }
    assert edges[1] == {
        "kind": "link",
        "name": "fetchOrder",
        "pointer": f"{SOURCE}/responses/201/links/fetchOrder",
        "source": SOURCE,
        "target": TARGET,
        "method": "get",
        "response_key": "201",
        "callback_url": None,
    }


def test_no_links_no_callbacks_yields_nodes_only():
    resp = graph(make_doc())
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 2
    assert body["edge_count"] == 0
    assert body["edges"] == []
    assert [node["id"] for node in body["nodes"]] == [SOURCE, TARGET]


def test_empty_paths_yields_empty_graph():
    resp = graph({"openapi": "3.0.3", "info": {"title": "t", "version": "1"}, "paths": {}})
    assert resp.status_code == 200
    assert resp.json() == {"node_count": 0, "edge_count": 0, "nodes": [], "edges": []}


def test_link_via_operation_ref():
    resp = graph(make_doc(link={"operationRef": "#/paths/~1orders~1{orderId}/get"}))
    assert resp.status_code == 200
    (edge,) = resp.json()["edges"]
    assert edge["kind"] == "link"
    assert edge["target"] == TARGET
    assert edge["method"] == "get"


def test_link_operation_ref_to_components_path_item():
    doc = make_doc(
        openapi="3.1.0",
        link={"operationRef": "#/components/pathItems/Order/get"},
        components={
            "pathItems": {
                "Order": {
                    "get": {
                        "operationId": "getOrder",
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    nodes = nodes_by_id(resp)
    reusable = nodes["/components/pathItems/Order/get"]
    assert reusable["kind"] == "operation"
    assert reusable["path"] is None
    assert reusable["operation_id"] == "getOrder"
    (edge,) = resp.json()["edges"]
    assert edge["target"] == "/components/pathItems/Order/get"


def test_link_operation_ref_escaped_path_tokens():
    doc = make_doc(
        link={"operationRef": "#/paths/~1tilde~0path/get"},
        extra_paths={
            "/tilde~path": {
                "get": {"operationId": "tilde", "responses": {"200": {"description": "ok"}}}
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    nodes = nodes_by_id(resp)
    assert nodes["/paths/~1tilde~0path/get"]["path"] == "/tilde~path"
    (edge,) = resp.json()["edges"]
    assert edge["target"] == "/paths/~1tilde~0path/get"


def test_every_response_key_produces_an_edge():
    resp = graph(
        make_doc(
            source_responses={
                "201": {
                    "description": "created",
                    "links": {"exact": {"operationId": "getOrder"}},
                },
                "2XX": {
                    "description": "wildcard",
                    "links": {"wild": {"operationId": "getOrder"}},
                },
                "default": {
                    "description": "fallback",
                    "links": {"fallback": {"operationId": "getOrder"}},
                },
            }
        )
    )
    assert resp.status_code == 200
    edges = resp.json()["edges"]
    assert [edge["response_key"] for edge in edges] == ["201", "2XX", "default"]
    assert [edge["name"] for edge in edges] == ["exact", "wild", "fallback"]
    assert all(edge["target"] == TARGET for edge in edges)


def test_multiple_links_to_same_target_keep_their_sources():
    resp = graph(
        make_doc(
            links={
                "first": {"operationId": "getOrder"},
                "second": {"operationRef": "#/paths/~1orders~1{orderId}/get"},
            }
        )
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["edge_count"] == 2
    pointers = [edge["pointer"] for edge in body["edges"]]
    assert pointers == [
        f"{SOURCE}/responses/201/links/first",
        f"{SOURCE}/responses/201/links/second",
    ]
    assert all(edge["target"] == TARGET for edge in body["edges"])


def test_callback_path_item_with_multiple_methods():
    resp = graph(
        make_doc(
            callback={
                CALLBACK_EXPR: {
                    "post": {"responses": {"200": {"description": "ok"}}},
                    "put": {"operationId": "hookPut", "responses": {"200": {"description": "ok"}}},
                }
            }
        )
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["edge_count"] == 2
    edges = body["edges"]
    assert [edge["pointer"] for edge in edges] == [CALLBACK_POINTER, CALLBACK_POINTER]
    assert [edge["method"] for edge in edges] == ["post", "put"]
    assert [edge["target"] for edge in edges] == [
        f"{CALLBACK_POINTER}/post",
        f"{CALLBACK_POINTER}/put",
    ]
    nodes = nodes_by_id(resp)
    assert nodes[f"{CALLBACK_POINTER}/put"]["operation_id"] == "hookPut"


def test_callback_operations_are_not_edge_sources():
    resp = graph(
        make_doc(
            callback={
                CALLBACK_EXPR: {
                    "post": {
                        "operationId": "hook",
                        "responses": {
                            "200": {
                                "description": "ok",
                                "links": {"nested": {"operationId": "getOrder"}},
                            }
                        },
                        "callbacks": {
                            "nested": {"https://hooks.example/x": {"post": {"responses": {"200": {"description": "ok"}}}}}
                        },
                    }
                }
            }
        )
    )
    assert resp.status_code == 200
    body = resp.json()
    # Only the callback edge from the paths operation exists; the callback
    # operation's own links/callbacks are not traversed.
    assert body["edge_count"] == 1
    assert body["edges"][0]["kind"] == "callback"
    assert body["edges"][0]["source"] == SOURCE


# --------------------------------------------------------------------------- #
# $ref resolution and 3.0 / 3.1 sibling semantics
# --------------------------------------------------------------------------- #


def test_response_and_link_component_refs():
    doc = make_doc(
        source_responses={"201": {"$ref": "#/components/responses/Created"}},
        components={
            "responses": {
                "Created": {
                    "description": "created",
                    "links": {"fetchOrder": {"$ref": "#/components/links/Fetch"}},
                }
            },
            "links": {"Fetch": {"operationId": "getOrder"}},
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    (edge,) = resp.json()["edges"]
    # The edge source pointer is the link entry occurrence: the links map
    # physically lives in the referenced component response.
    assert edge["pointer"] == "/components/responses/Created/links/fetchOrder"
    assert edge["target"] == TARGET


def test_callback_object_and_path_item_component_refs():
    doc = make_doc(
        openapi="3.1.0",
        callback={"$ref": "#/components/callbacks/Shipped"},
        components={
            "callbacks": {
                "Shipped": {
                    CALLBACK_EXPR: {"$ref": "#/components/pathItems/Shipment"}
                }
            },
            "pathItems": {
                "Shipment": {
                    "post": {
                        "operationId": "notify",
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    nodes = nodes_by_id(resp)
    shared = nodes["/components/pathItems/Shipment/post"]
    assert shared["kind"] == "callback"
    assert shared["path"] is None
    assert shared["operation_id"] == "notify"
    (edge,) = resp.json()["edges"]
    # The expression pointer follows the Callback Object $ref to the component.
    assert edge["pointer"] == f"/components/callbacks/Shipped/{CALLBACK_EXPR_ESCAPED}"
    assert edge["target"] == "/components/pathItems/Shipment/post"
    assert edge["callback_url"] == CALLBACK_EXPR


def test_shared_components_path_item_yields_one_node_two_edges():
    shared_callback = {"{$url}": {"$ref": "#/components/pathItems/Shared"}}
    doc = make_doc(
        openapi="3.1.0",
        callback=shared_callback,
        extra_paths={
            "/orders2": {
                "post": {
                    "operationId": "createOrder2",
                    "responses": {"201": {"description": "created"}},
                    "callbacks": {"onShipped": shared_callback},
                }
            }
        },
        components={
            "pathItems": {
                "Shared": {"post": {"responses": {"200": {"description": "ok"}}}}
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 4  # three operations + one shared callback node
    assert body["edge_count"] == 2
    targets = {edge["target"] for edge in body["edges"]}
    assert targets == {"/components/pathItems/Shared/post"}
    sources = sorted(edge["source"] for edge in body["edges"])
    assert sources == ["/paths/~1orders/post", "/paths/~1orders2/post"]


def test_30_ignores_link_ref_siblings():
    doc = make_doc(
        openapi="3.0.3",
        link={"$ref": "#/components/links/Fetch", "operationId": "otherOp"},
        extra_paths={
            "/other": {
                "get": {"operationId": "otherOp", "responses": {"200": {"description": "ok"}}}
            }
        },
        components={"links": {"Fetch": {"operationId": "getOrder"}}},
    )
    resp = graph(doc)
    assert resp.status_code == 200
    (edge,) = resp.json()["edges"]
    assert edge["target"] == TARGET  # the sibling operationId is ignored


def test_31_link_ref_sibling_overrides():
    doc = make_doc(
        openapi="3.1.0",
        link={"$ref": "#/components/links/Fetch", "operationId": "otherOp"},
        extra_paths={
            "/other": {
                "get": {"operationId": "otherOp", "responses": {"200": {"description": "ok"}}}
            }
        },
        components={"links": {"Fetch": {"operationId": "getOrder"}}},
    )
    resp = graph(doc)
    assert resp.status_code == 200
    (edge,) = resp.json()["edges"]
    assert edge["target"] == "/paths/~1other/get"  # nearest sibling wins


def test_30_ignores_callback_ref_siblings():
    doc = make_doc(
        openapi="3.0.3",
        callback={
            "$ref": "#/components/callbacks/Base",
            "{$request.body#/extraUrl}": {"put": {"responses": {"200": {"description": "ok"}}}},
        },
        components={
            "callbacks": {
                "Base": {
                    "https://hooks.example/ship": {
                        "post": {"responses": {"200": {"description": "ok"}}}
                    }
                }
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    edges = resp.json()["edges"]
    assert len(edges) == 1  # only the component's expression survives
    assert edges[0]["callback_url"] == "https://hooks.example/ship"
    assert edges[0]["target"] == "/components/callbacks/Base/https:~1~1hooks.example~1ship/post"


def test_31_merges_callback_ref_siblings():
    doc = make_doc(
        openapi="3.1.0",
        callback={
            "$ref": "#/components/callbacks/Base",
            "{$request.body#/extraUrl}": {"put": {"responses": {"200": {"description": "ok"}}}},
        },
        components={
            "callbacks": {
                "Base": {
                    "https://hooks.example/ship": {
                        "post": {"responses": {"200": {"description": "ok"}}}
                    }
                }
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    edges = resp.json()["edges"]
    assert len(edges) == 2
    assert edges[0]["pointer"] == "/components/callbacks/Base/https:~1~1hooks.example~1ship"
    assert edges[0]["target"] == "/components/callbacks/Base/https:~1~1hooks.example~1ship/post"
    assert edges[1]["pointer"] == f"{SOURCE}/callbacks/onShipped/{{$request.body#~1extraUrl}}"
    assert edges[1]["method"] == "put"
    assert edges[1]["callback_url"] == "{$request.body#/extraUrl}"


def test_31_path_item_ref_sibling_method_overrides():
    doc = make_doc(
        openapi="3.1.0",
        callback={
            CALLBACK_EXPR: {
                "$ref": "#/components/pathItems/Base",
                "post": {"operationId": "override", "responses": {"200": {"description": "ok"}}},
            }
        },
        components={
            "pathItems": {
                "Base": {"post": {"operationId": "base", "responses": {"200": {"description": "ok"}}}}
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    nodes = nodes_by_id(resp)
    # The sibling 'post' wins and is declared at the expression occurrence.
    node = nodes[f"{CALLBACK_POINTER}/post"]
    assert node["operation_id"] == "override"
    assert "/components/pathItems/Base/post" not in nodes


def test_path_item_ref_mounted_under_paths():
    doc = make_doc(
        openapi="3.1.0",
        link={"operationId": "getOrder"},
        extra_paths={"/mounted": {"$ref": "#/components/pathItems/Mounted"}},
        components={
            "pathItems": {
                "Mounted": {
                    "get": {
                        "operationId": "mountedGet",
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    nodes = nodes_by_id(resp)
    # Mounted operations are addressed at their /paths occurrence.
    assert nodes["/paths/~1mounted/get"]["path"] == "/mounted"
    assert nodes["/paths/~1mounted/get"]["operation_id"] == "mountedGet"


def test_operation_ref_into_refed_path_item():
    doc = make_doc(
        openapi="3.1.0",
        link={"operationRef": "#/paths/~1mounted/get"},
        extra_paths={"/mounted": {"$ref": "#/components/pathItems/Mounted"}},
        components={
            "pathItems": {
                "Mounted": {
                    "get": {
                        "operationId": "mountedGet",
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 200
    (edge,) = resp.json()["edges"]
    assert edge["target"] == "/paths/~1mounted/get"


# --------------------------------------------------------------------------- #
# Target resolution failures
# --------------------------------------------------------------------------- #


def test_duplicate_operation_id_rejected_even_when_unused():
    doc = make_doc(
        extra_paths={
            "/copy": {
                "get": {"operationId": "getOrder", "responses": {"200": {"description": "ok"}}}
            }
        }
    )
    resp = graph(doc)
    assert resp.status_code == 422
    assert codes(resp) == ["duplicate_operation_id"]
    (error,) = resp.json()["errors"]
    assert error["operation_id"] == "getOrder"
    assert error["pointers"] == ["/paths/~1copy/get", TARGET]
    assert "nodes" not in resp.json()
    assert "edges" not in resp.json()


def test_link_to_duplicate_operation_id_reports_both():
    doc = make_doc(
        link={"operationId": "getOrder"},
        extra_paths={
            "/copy": {
                "get": {"operationId": "getOrder", "responses": {"200": {"description": "ok"}}}
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 422
    assert codes(resp) == ["duplicate_operation_id", "unknown_link_target"]
    target_error = resp.json()["errors"][1]
    assert target_error["pointer"].endswith("/operationId")
    assert "not globally unique" in target_error["error"]


def test_link_to_unknown_operation_id():
    resp = graph(make_doc(link={"operationId": "missing"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_link_target"]
    error = resp.json()["errors"][0]
    assert error["operation_id"] == "missing"
    assert error["pointer"] == f"{SOURCE}/responses/201/links/fetchOrder/operationId"


def test_link_with_both_operation_ref_and_id():
    resp = graph(
        make_doc(
            link={
                "operationRef": "#/paths/~1orders~1{orderId}/get",
                "operationId": "getOrder",
            }
        )
    )
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]
    assert "not both" in resp.json()["errors"][0]["error"]


def test_link_with_neither_operation_ref_nor_id():
    resp = graph(make_doc(link={"parameters": {"orderId": "$response.body#/id"}}))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]
    assert "exactly one" in resp.json()["errors"][0]["error"]


def test_link_with_non_string_operation_id():
    resp = graph(make_doc(link={"operationId": 42}))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]


def test_external_operation_ref_rejected():
    resp = graph(make_doc(link={"operationRef": "https://example.com/api#/paths/~1x/get"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_operation_ref_not_ending_in_method():
    resp = graph(make_doc(link={"operationRef": "#/paths/~1orders~1{orderId}"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_link_target"]
    assert "HTTP" in resp.json()["errors"][0]["error"]


def test_operation_ref_method_not_declared():
    resp = graph(make_doc(link={"operationRef": "#/paths/~1orders~1{orderId}/delete"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unknown_link_target"]
    assert "DELETE" in resp.json()["errors"][0]["error"]


def test_operation_ref_dangling_pointer():
    resp = graph(make_doc(link={"operationRef": "#/paths/~1missing/get"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


# --------------------------------------------------------------------------- #
# Reference failures across every resolvable position
# --------------------------------------------------------------------------- #


def test_dangling_path_item_ref():
    doc = make_doc()
    doc["paths"]["/orders"] = {"$ref": "#/components/pathItems/Missing"}
    resp = graph(doc)
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]
    assert resp.json()["errors"][0]["pointer"] == "/paths/~1orders"


def test_external_path_item_ref():
    doc = make_doc()
    doc["paths"]["/orders"] = {"$ref": "https://example.com/paths.yaml#/Orders"}
    resp = graph(doc)
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_dangling_response_ref():
    resp = graph(make_doc(source_responses={"201": {"$ref": "#/components/responses/Missing"}}))
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]
    assert resp.json()["errors"][0]["pointer"] == f"{SOURCE}/responses/201"


def test_dangling_link_ref():
    resp = graph(make_doc(link={"$ref": "#/components/links/Missing"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_dangling_callback_ref():
    resp = graph(make_doc(callback={"$ref": "#/components/callbacks/Missing"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_dangling_callback_path_item_ref():
    resp = graph(make_doc(callback={CALLBACK_EXPR: {"$ref": "#/components/pathItems/Missing"}}))
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]
    assert resp.json()["errors"][0]["pointer"] == CALLBACK_POINTER


def test_external_callback_ref():
    resp = graph(make_doc(callback={"$ref": "https://example.com/cb.yaml#/Hook"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


def test_circular_callback_ref():
    doc = make_doc(
        callback={"$ref": "#/components/callbacks/A"},
        components={
            "callbacks": {
                "A": {"$ref": "#/components/callbacks/B"},
                "B": {"$ref": "#/components/callbacks/A"},
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]
    assert "circular reference detected" in resp.json()["errors"][0]["error"]


def test_root_ref_rejected():
    resp = graph(make_doc(callback={"$ref": "#"}))
    assert resp.status_code == 422
    assert codes(resp) == ["unresolvable_reference"]


# --------------------------------------------------------------------------- #
# Malformed containers (all collected, no partial graph)
# --------------------------------------------------------------------------- #


def test_path_item_must_be_an_object():
    doc = make_doc()
    doc["paths"]["/orders"] = "not-a-path-item"
    resp = graph(doc)
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_operation"]
    assert resp.json()["errors"][0]["pointer"] == "/paths/~1orders"


def test_operation_must_be_an_object():
    doc = make_doc()
    doc["paths"]["/orders"]["post"] = "not-an-operation"
    resp = graph(doc)
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_operation"]
    assert resp.json()["errors"][0]["pointer"] == SOURCE


def test_responses_must_be_an_object():
    resp = graph(make_doc(source_responses=["201"]))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_operation"]
    assert resp.json()["errors"][0]["pointer"] == f"{SOURCE}/responses"


def test_response_must_be_an_object():
    resp = graph(make_doc(source_responses={"201": "nope"}))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]


def test_links_must_be_an_object():
    resp = graph(make_doc(source_responses={"201": {"description": "c", "links": []}}))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]
    assert resp.json()["errors"][0]["pointer"] == f"{SOURCE}/responses/201/links"


def test_link_must_be_an_object():
    resp = graph(make_doc(link="nope"))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_link"]


def test_callbacks_must_be_an_object():
    resp = graph(make_doc(callbacks=[]))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_callback"]
    assert resp.json()["errors"][0]["pointer"] == f"{SOURCE}/callbacks"


def test_callback_value_must_be_an_object():
    resp = graph(make_doc(callback="nope"))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_callback"]


def test_callback_expression_value_must_be_a_path_item():
    resp = graph(make_doc(callback={CALLBACK_EXPR: "nope"}))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_callback"]
    assert resp.json()["errors"][0]["pointer"] == CALLBACK_POINTER


def test_callback_operation_must_be_an_object():
    resp = graph(make_doc(callback={CALLBACK_EXPR: {"post": "nope"}}))
    assert resp.status_code == 422
    assert codes(resp) == ["invalid_callback"]
    assert resp.json()["errors"][0]["pointer"] == CALLBACK_NODE


def test_all_errors_are_aggregated_and_sorted():
    doc = make_doc(
        link={"operationId": "missing"},
        callback={CALLBACK_EXPR: {"$ref": "#/components/pathItems/Missing"}},
        extra_paths={
            "/copy": {
                "get": {"operationId": "getOrder", "responses": {"200": {"description": "ok"}}}
            }
        },
    )
    resp = graph(doc)
    assert resp.status_code == 422
    assert codes(resp) == [
        "duplicate_operation_id",
        "unknown_link_target",
        "unresolvable_reference",
    ]
    body = resp.json()
    assert body["error"] == "interaction_graph_failed"
    assert "nodes" not in body and "edges" not in body


# --------------------------------------------------------------------------- #
# Envelope, sorting and immutability
# --------------------------------------------------------------------------- #


def test_non_object_document_is_rejected():
    # A non-object document never reaches the handler: the request model
    # requires a JSON object and FastAPI answers its own 422.
    resp = client.post("/interactions/graph", json={"document": "not-an-object"})
    assert resp.status_code == 422


def test_non_3x_document_returns_400():
    resp = graph({"openapi": "2.0", "paths": {}})
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_openapi_document"


def test_missing_paths_returns_400():
    resp = graph({"openapi": "3.0.3", "info": {"title": "t", "version": "1"}})
    assert resp.status_code == 400


def test_nodes_and_edges_are_sorted_by_pointer():
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/zebra": {
                "post": {
                    "operationId": "z",
                    "responses": {
                        "200": {
                            "description": "ok",
                            "links": {"toB": {"operationId": "b"}, "toA": {"operationId": "a"}},
                        }
                    },
                    "callbacks": {
                        "cb": {"https://hooks.example/z": {"post": {"responses": {"200": {"description": "ok"}}}}}
                    },
                }
            },
            "/alpha": {
                "get": {"operationId": "a", "responses": {"200": {"description": "ok"}}}
            },
            "/mid": {
                "get": {"operationId": "b", "responses": {"200": {"description": "ok"}}}
            },
        },
    }
    resp = graph(doc)
    assert resp.status_code == 200
    body = resp.json()
    node_ids = [node["id"] for node in body["nodes"]]
    assert node_ids == sorted(node_ids)
    edge_keys = [
        (edge["pointer"], edge["kind"], edge["source"], edge["target"], edge["method"], edge["name"])
        for edge in body["edges"]
    ]
    assert edge_keys == sorted(edge_keys)
    assert [edge["name"] for edge in body["edges"] if edge["kind"] == "link"] == ["toA", "toB"]


def test_declared_method_key_case_is_preserved_in_node_id():
    doc = make_doc()
    doc["paths"]["/orders/{orderId}"] = {
        "GET": {"operationId": "getOrder", "responses": {"200": {"description": "ok"}}}
    }
    resp = graph(doc)
    assert resp.status_code == 200
    node = nodes_by_id(resp)["/paths/~1orders~1{orderId}/GET"]
    assert node["method"] == "get"


def test_input_document_is_not_modified():
    doc = make_doc(
        link={"operationId": "getOrder"},
        callback={CALLBACK_EXPR: {"post": {"responses": {"200": {"description": "ok"}}}}},
        components={"links": {"Unused": {"operationId": "getOrder"}}},
    )
    snapshot = copy.deepcopy(doc)
    resp = graph(doc)
    assert resp.status_code == 200
    assert doc == snapshot


def test_root_listing_mentions_the_endpoint():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["interactions_graph"] == "POST /interactions/graph"
