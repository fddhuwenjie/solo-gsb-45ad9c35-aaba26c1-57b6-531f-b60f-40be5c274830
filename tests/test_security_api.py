"""Regression tests for ``POST /security/plan``.

Covers operation-level vs root-level security (OR between requirement
items, AND within one item, explicit ``security: []`` for anonymous),
cycle-safe local Security Scheme Object ``$ref`` chains (3.0 siblings
ignored / 3.1 siblings merged), apiKey/http/oauth2/openIdConnect
definition and scope validation, fewest-scheme selection with canonical
JSON tie-break, injection location descriptions with source JSON
Pointers, 200-with-missing for unsatisfiable operations, 422 for
dangling/external/circular references and illegal definitions, 400 for
document/selector/grant envelope errors, secret non-disclosure and
non-mutation.
"""

from __future__ import annotations

import copy

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def make_doc(security=None, *, security_schemes=None, root_security=None,
             openapi="3.0.3", path_item=None):
    operation = {"responses": {"200": {"description": "ok"}}}
    if security is not None:
        operation["security"] = security
    item = {"get": operation}
    if path_item is not None:
        item = path_item
    doc = {
        "openapi": openapi,
        "info": {"title": "Sec API", "version": "1.0"},
        "paths": {"/things": item},
    }
    if root_security is not None:
        doc["security"] = root_security
    if security_schemes is not None:
        doc["components"] = {"securitySchemes": security_schemes}
    return doc


def plan(doc, selector="GET /things", granted=None):
    payload = {"document": doc, "selector": selector}
    if granted is not None:
        payload["granted"] = granted
    return client.post("/security/plan", json=payload)


APIKEY_HEADER = {"type": "apiKey", "in": "header", "name": "X-Api-Key"}
APIKEY_QUERY = {"type": "apiKey", "in": "query", "name": "api_key"}
APIKEY_COOKIE = {"type": "apiKey", "in": "cookie", "name": "session"}
HTTP_BASIC = {"type": "http", "scheme": "basic"}
HTTP_BEARER = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
HTTP_DIGEST = {"type": "http", "scheme": "digest"}
OAUTH2 = {
    "type": "oauth2",
    "flows": {
        "implicit": {
            "authorizationUrl": "https://id.example.com/authorize",
            "scopes": {"read": "read things", "write": "write things"},
        },
        "clientCredentials": {
            "tokenUrl": "https://id.example.com/token",
            "scopes": {"admin": "administer things"},
        },
    },
}
OIDC = {"type": "openIdConnect", "openIdConnectUrl": "https://id.example.com/.well-known/openid-configuration"}


# --------------------------------------------------------------------------- #
# Anonymous
# --------------------------------------------------------------------------- #

def test_empty_operation_security_is_anonymous():
    resp = plan(make_doc(security=[]))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["anonymous"] is True
    assert body["satisfiable"] is True
    assert body["inherited"] is False
    assert body["selected"] == {
        "requirement": {},
        "requirement_pointer": None,
        "scheme_count": 0,
        "plan": [],
    }
    assert body["alternatives"] == []


def test_no_security_anywhere_is_anonymous():
    resp = plan(make_doc())
    assert resp.status_code == 200
    body = resp.json()
    assert body["anonymous"] is True
    assert body["satisfiable"] is True
    assert body["security_pointer"] is None


def test_empty_root_security_is_anonymous_when_inherited():
    resp = plan(make_doc(root_security=[]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["anonymous"] is True
    assert body["inherited"] is True
    # The empty array is explicitly declared at the root.
    assert body["security_pointer"] == "/security"


# --------------------------------------------------------------------------- #
# Inheritance and override
# --------------------------------------------------------------------------- #

def test_operation_without_security_inherits_root():
    doc = make_doc(root_security=[{"h": []}], security_schemes={"h": APIKEY_HEADER})
    resp = plan(doc, granted={"h": []})
    assert resp.status_code == 200
    body = resp.json()
    assert body["inherited"] is True
    assert body["security_pointer"] == "/security"
    assert body["selected"]["plan"][0]["scheme"] == "h"


def test_operation_security_overrides_root_entirely():
    doc = make_doc(
        root_security=[{"rootOnly": []}],
        security=[{"opOnly": []}],
        security_schemes={
            "rootOnly": APIKEY_HEADER,
            "opOnly": {"type": "apiKey", "in": "query", "name": "q"},
        },
    )
    resp = plan(doc, granted={"rootOnly": [], "opOnly": []})
    assert resp.status_code == 200
    body = resp.json()
    assert body["inherited"] is False
    assert body["security_pointer"] == "/paths/~1things/get/security"
    assert len(body["alternatives"]) == 1
    assert body["selected"]["plan"][0]["scheme"] == "opOnly"


def test_operation_empty_security_overrides_root_with_anonymous():
    doc = make_doc(
        root_security=[{"rootOnly": []}],
        security=[],
        security_schemes={"rootOnly": APIKEY_HEADER},
    )
    resp = plan(doc)
    assert resp.status_code == 200
    body = resp.json()
    assert body["anonymous"] is True
    assert body["inherited"] is False
    assert body["security_pointer"] == "/paths/~1things/get/security"


# --------------------------------------------------------------------------- #
# Injection locations
# --------------------------------------------------------------------------- #

def test_apikey_header_injection():
    doc = make_doc(security=[{"h": []}], security_schemes={"h": APIKEY_HEADER})
    resp = plan(doc, granted={"h": []})
    entry = resp.json()["selected"]["plan"][0]
    assert entry["location"] == "header"
    assert entry["parameter_name"] == "X-Api-Key"
    assert "header 'X-Api-Key'" in entry["injection"]
    assert entry["source_pointer"] == "/components/securitySchemes/h"
    assert entry["requirement_pointer"] == "/paths/~1things/get/security/0"


def test_apikey_query_injection():
    doc = make_doc(security=[{"q": []}], security_schemes={"q": APIKEY_QUERY})
    entry = plan(doc, granted={"q": []}).json()["selected"]["plan"][0]
    assert entry["location"] == "query"
    assert entry["parameter_name"] == "api_key"
    assert "query parameter 'api_key'" in entry["injection"]


def test_apikey_cookie_injection():
    doc = make_doc(security=[{"c": []}], security_schemes={"c": APIKEY_COOKIE})
    entry = plan(doc, granted={"c": []}).json()["selected"]["plan"][0]
    assert entry["location"] == "cookie"
    assert entry["parameter_name"] == "session"
    assert "Cookie" in entry["injection"] and "session=<key>" in entry["injection"]


def test_http_basic_injection():
    doc = make_doc(security=[{"b": []}], security_schemes={"b": HTTP_BASIC})
    entry = plan(doc, granted={"b": []}).json()["selected"]["plan"][0]
    assert entry["location"] == "header"
    assert entry["parameter_name"] == "Authorization"
    assert entry["http_scheme"] == "basic"
    assert entry["injection"].startswith("send HTTP Basic")


def test_http_bearer_injection_with_format():
    doc = make_doc(security=[{"b": []}], security_schemes={"b": HTTP_BEARER})
    entry = plan(doc, granted={"b": []}).json()["selected"]["plan"][0]
    assert entry["parameter_name"] == "Authorization"
    assert entry["http_scheme"] == "bearer"
    assert "'Bearer <token>'" in entry["injection"]
    assert "JWT" in entry["injection"]


def test_http_other_scheme_injection():
    doc = make_doc(security=[{"d": []}], security_schemes={"d": HTTP_DIGEST})
    entry = plan(doc, granted={"d": []}).json()["selected"]["plan"][0]
    assert "'digest <token>'" in entry["injection"]


def test_oauth2_and_oidc_use_authorization_bearer():
    for name, scheme in (("o", OAUTH2), ("id", OIDC)):
        doc = make_doc(security=[{name: []}], security_schemes={name: scheme})
        entry = plan(doc, granted={name: []}).json()["selected"]["plan"][0]
        assert entry["location"] == "header"
        assert entry["parameter_name"] == "Authorization"
        assert "'Bearer <token>'" in entry["injection"]


# --------------------------------------------------------------------------- #
# OR / AND semantics and selection
# --------------------------------------------------------------------------- #

def test_or_alternatives_first_satisfiable_wins():
    doc = make_doc(
        security=[{"a": []}, {"b": []}],
        security_schemes={"a": APIKEY_QUERY, "b": APIKEY_HEADER},
    )
    body = plan(doc, granted={"b": []}).json()
    assert body["satisfiable"] is True
    assert body["selected"]["plan"][0]["scheme"] == "b"
    assert [item["satisfiable"] for item in body["alternatives"]] == [False, True]


def test_and_within_one_requirement_needs_every_scheme():
    doc = make_doc(
        security=[{"a": [], "b": []}],
        security_schemes={"a": APIKEY_QUERY, "b": APIKEY_HEADER},
    )
    body = plan(doc, granted={"a": []}).json()
    assert body["satisfiable"] is False
    assert body["selected"] is None
    missing = body["alternatives"][0]["missing"]
    assert len(missing) == 1
    assert missing[0]["scheme"] == "b"

    body = plan(doc, granted={"a": [], "b": []}).json()
    assert body["satisfiable"] is True
    assert body["selected"]["scheme_count"] == 2


def test_fewest_schemes_alternative_is_selected():
    doc = make_doc(
        security=[{"a": [], "b": []}, {"c": []}],
        security_schemes={
            "a": APIKEY_QUERY, "b": APIKEY_HEADER, "c": HTTP_BASIC,
        },
    )
    body = plan(doc, granted={"a": [], "b": [], "c": []}).json()
    assert body["selected"]["scheme_count"] == 1
    assert body["selected"]["plan"][0]["scheme"] == "c"


def test_tie_break_is_canonical_json_ordering():
    doc = make_doc(
        security=[{"zkey": []}, {"akey": []}],
        security_schemes={"zkey": APIKEY_QUERY, "akey": HTTP_BASIC},
    )
    body = plan(doc, granted={"zkey": [], "akey": []}).json()
    # Canonical JSON {"akey":[]} < {"zkey":[]}.
    assert body["selected"]["plan"][0]["scheme"] == "akey"
    assert body["selected"]["requirement_pointer"] == "/paths/~1things/get/security/1"


def test_selection_is_input_key_order_independent():
    schemes = {"zkey": APIKEY_QUERY, "akey": HTTP_BASIC}
    doc1 = make_doc(security=[{"zkey": []}, {"akey": []}], security_schemes=schemes)
    doc2 = make_doc(security=[{"akey": []}, {"zkey": []}], security_schemes=schemes)
    b1 = plan(doc1, granted={"zkey": [], "akey": []}).json()
    b2 = plan(doc2, granted={"akey": [], "zkey": []}).json()
    assert b1["selected"]["requirement"] == b2["selected"]["requirement"] == {"akey": []}


def test_and_plan_entries_are_sorted_by_scheme_name():
    doc = make_doc(
        security=[{"z": [], "a": [], "m": []}],
        security_schemes={
            "z": APIKEY_QUERY, "a": APIKEY_HEADER, "m": HTTP_BASIC,
        },
    )
    entries = plan(doc, granted={"z": [], "a": [], "m": []}).json()["selected"]["plan"]
    assert [e["scheme"] for e in entries] == ["a", "m", "z"]


# --------------------------------------------------------------------------- #
# OAuth scopes
# --------------------------------------------------------------------------- #

def test_oauth2_scope_satisfied():
    doc = make_doc(security=[{"o": ["read", "write"]}], security_schemes={"o": OAUTH2})
    body = plan(doc, granted={"o": ["write", "read", "extra"]}).json()
    assert body["satisfiable"] is True
    entry = body["selected"]["plan"][0]
    assert entry["required_scopes"] == ["read", "write"]


def test_oauth2_missing_scope_keeps_200_and_lists_scope():
    doc = make_doc(security=[{"o": ["read", "admin"]}], security_schemes={"o": OAUTH2})
    resp = plan(doc, granted={"o": ["read"]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["satisfiable"] is False
    missing = body["alternatives"][0]["missing"]
    assert [(m["scheme"], m.get("scope")) for m in missing] == [("o", "admin")]
    assert missing[0]["requirement_pointer"] == "/paths/~1things/get/security/0/o"
    assert missing[0]["source_pointer"] == "/components/securitySchemes/o"


def test_missing_credential_is_reported_once_even_with_scopes():
    doc = make_doc(security=[{"o": ["read"]}], security_schemes={"o": OAUTH2})
    body = plan(doc, granted={}).json()
    missing = body["alternatives"][0]["missing"]
    assert len(missing) == 1
    assert "scope" not in missing[0]
    assert "no credential granted" in missing[0]["error"]


def test_openidconnect_scopes_are_not_validated_against_a_list():
    doc = make_doc(security=[{"id": ["any-runtime-scope"]}], security_schemes={"id": OIDC})
    body = plan(doc, granted={"id": ["any-runtime-scope"]}).json()
    assert body["satisfiable"] is True


# --------------------------------------------------------------------------- #
# Local $ref resolution
# --------------------------------------------------------------------------- #

def test_scheme_defined_behind_single_local_ref():
    doc = make_doc(
        security=[{"rk": []}],
        security_schemes={
            "rk": {"$ref": "#/components/securitySchemes/basic"},
            "basic": HTTP_BASIC,
        },
    )
    body = plan(doc, granted={"rk": []}).json()
    entry = body["selected"]["plan"][0]
    assert entry["type"] == "http"
    assert entry["http_scheme"] == "basic"
    # Source pointer follows the chain to the definition.
    assert entry["source_pointer"] == "/components/securitySchemes/basic"


def test_scheme_defined_behind_multi_hop_ref():
    doc = make_doc(
        security=[{"rk": []}],
        security_schemes={
            "rk": {"$ref": "#/components/securitySchemes/mid"},
            "mid": {"$ref": "#/components/securitySchemes/basic"},
            "basic": HTTP_BASIC,
        },
    )
    entry = plan(doc, granted={"rk": []}).json()["selected"]["plan"][0]
    assert entry["source_pointer"] == "/components/securitySchemes/basic"


def test_openapi_30_ref_siblings_are_ignored():
    doc = make_doc(
        openapi="3.0.3",
        security=[{"rk": []}],
        security_schemes={
            "rk": {
                "$ref": "#/components/securitySchemes/basic",
                "scheme": "bearer",
            },
            "basic": HTTP_BASIC,
        },
    )
    entry = plan(doc, granted={"rk": []}).json()["selected"]["plan"][0]
    assert entry["http_scheme"] == "basic"


def test_openapi_31_ref_siblings_override_target():
    doc = make_doc(
        openapi="3.1.0",
        security=[{"rk": []}],
        security_schemes={
            "rk": {
                "$ref": "#/components/securitySchemes/b",
                "bearerFormat": "JWT",
            },
            "b": {"type": "http", "scheme": "bearer"},
        },
    )
    entry = plan(doc, granted={"rk": []}).json()["selected"]["plan"][0]
    assert entry["http_scheme"] == "bearer"
    assert "JWT" in entry["injection"]


def test_circular_scheme_ref_is_422():
    doc = make_doc(
        security=[{"rk": []}],
        security_schemes={
            "rk": {"$ref": "#/components/securitySchemes/other"},
            "other": {"$ref": "#/components/securitySchemes/rk"},
        },
    )
    resp = plan(doc)
    assert resp.status_code == 422
    errors = resp.json()["errors"]
    assert any(
        e["code"] == "unresolvable_reference"
        and "circular" in e["error"]
        and e["pointer"] == "/components/securitySchemes/rk"
        and e["ref"] == "#/components/securitySchemes/other"
        for e in errors
    )


def test_external_scheme_ref_is_422():
    doc = make_doc(
        security=[{"rk": []}],
        security_schemes={
            "rk": {"$ref": "https://ext.example.com/schemes.json#/S"},
        },
    )
    resp = plan(doc)
    assert resp.status_code == 422
    error = resp.json()["errors"][0]
    assert error["code"] == "unresolvable_reference"
    assert error["ref"] == "https://ext.example.com/schemes.json#/S"
    assert error["pointer"] == "/components/securitySchemes/rk"


def test_dangling_scheme_ref_is_422():
    doc = make_doc(
        security=[{"rk": []}],
        security_schemes={"rk": {"$ref": "#/components/securitySchemes/missing"}},
    )
    resp = plan(doc)
    assert resp.status_code == 422
    error = resp.json()["errors"][0]
    assert error["code"] == "unresolvable_reference"
    assert "missing" in error["error"]
    assert error["pointer"] == "/components/securitySchemes/rk"


def test_root_ref_target_is_422():
    doc = make_doc(
        security=[{"rk": []}],
        security_schemes={"rk": {"$ref": "#"}},
    )
    resp = plan(doc)
    assert resp.status_code == 422
    assert resp.json()["errors"][0]["code"] == "unresolvable_reference"


def test_ref_to_non_object_is_422():
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "X", "version": "1"},
        "paths": {"/things": {"get": {"responses": {"200": {"description": "ok"}},
                                    "security": [{"rk": []}]}}},
        "components": {"securitySchemes": {
            "rk": {"$ref": "#/info/version"},
        }},
    }
    resp = plan(doc)
    assert resp.status_code == 422
    assert "object" in resp.json()["errors"][0]["error"]


# --------------------------------------------------------------------------- #
# Definition validation (422)
# --------------------------------------------------------------------------- #

def test_undefined_scheme_name_is_422():
    doc = make_doc(security=[{"ghost": []}], security_schemes={})
    resp = plan(doc)
    assert resp.status_code == 422
    error = resp.json()["errors"][0]
    assert error["code"] == "unresolvable_reference"
    assert error["pointer"] == "/paths/~1things/get/security/0/ghost"


def test_missing_securitySchemes_section_is_422():
    doc = make_doc(security=[{"h": []}])
    resp = plan(doc)
    assert resp.status_code == 422
    assert resp.json()["errors"][0]["code"] == "unresolvable_reference"


def test_invalid_scheme_type_is_422():
    doc = make_doc(
        security=[{"h": []}],
        security_schemes={"h": {"type": "mutualTLS"}},
    )
    resp = plan(doc)
    assert resp.status_code == 422
    error = resp.json()["errors"][0]
    assert error["pointer"] == "/components/securitySchemes/h/type"


def test_apikey_requires_name_and_in():
    cases = [
        {"type": "apiKey", "in": "header"},
        {"type": "apiKey", "name": "x"},
        {"type": "apiKey", "name": "x", "in": "path"},
        {"type": "apiKey", "name": "", "in": "header"},
    ]
    for scheme in cases:
        doc = make_doc(security=[{"h": []}], security_schemes={"h": scheme})
        resp = plan(doc)
        assert resp.status_code == 422, scheme
        assert all(e["code"] == "invalid_security_definition"
                   for e in resp.json()["errors"])


def test_http_requires_scheme():
    doc = make_doc(
        security=[{"h": []}],
        security_schemes={"h": {"type": "http", "bearerFormat": 123}},
    )
    resp = plan(doc)
    assert resp.status_code == 422
    pointers = {e["pointer"] for e in resp.json()["errors"]}
    assert "/components/securitySchemes/h/scheme" in pointers
    assert "/components/securitySchemes/h/bearerFormat" in pointers


def test_oauth2_requires_flows_with_urls_and_scope_map():
    bad_flows = [
        None,
        {},
        {"implicit": {"scopes": {"read": ""}}},
        {"password": {"scopes": {"read": ""}}},
        {"clientCredentials": {"scopes": {"read": ""}}},
        {"authorizationCode": {"scopes": {"read": ""}}},
        {"authorizationCode": {"authorizationUrl": "https://a", "scopes": {"read": ""}}},
        {"bogusFlow": {}},
        {"implicit": {"authorizationUrl": "https://a", "scopes": {"read": 7}}},
    ]
    for flows in bad_flows:
        doc = make_doc(
            security=[{"o": []}],
            security_schemes={"o": {"type": "oauth2", "flows": flows}},
        )
        resp = plan(doc)
        assert resp.status_code == 422, flows


def test_valid_oauth2_flow_shapes_pass():
    for flow_name, extra in (
        ("implicit", {"authorizationUrl": "https://a"}),
        ("password", {"tokenUrl": "https://t"}),
        ("clientCredentials", {"tokenUrl": "https://t"}),
        ("authorizationCode", {"authorizationUrl": "https://a", "tokenUrl": "https://t"}),
    ):
        scheme = {"type": "oauth2",
                  "flows": {flow_name: dict(extra, scopes={})}}
        doc = make_doc(security=[{"o": []}], security_schemes={"o": scheme})
        resp = plan(doc, granted={"o": []})
        assert resp.status_code == 200, flow_name


def test_openidconnect_requires_url():
    for url in (None, "", 42):
        doc = make_doc(
            security=[{"id": []}],
            security_schemes={"id": {"type": "openIdConnect",
                                     "openIdConnectUrl": url}},
        )
        resp = plan(doc)
        assert resp.status_code == 422


def test_scopeless_scheme_must_have_empty_requirement_scopes():
    doc = make_doc(
        security=[{"h": ["read"]}],
        security_schemes={"h": APIKEY_HEADER},
    )
    resp = plan(doc)
    assert resp.status_code == 422
    error = resp.json()["errors"][0]
    assert error["pointer"] == "/paths/~1things/get/security/0/h"


def test_oauth2_required_scope_must_be_declared_by_a_flow():
    doc = make_doc(security=[{"o": ["ghost"]}], security_schemes={"o": OAUTH2})
    resp = plan(doc)
    assert resp.status_code == 422
    error = resp.json()["errors"][0]
    assert error["pointer"] == "/paths/~1things/get/security/0/o"
    assert "ghost" in error["error"]


def test_malformed_security_structures_are_422():
    schemes = {"h": APIKEY_HEADER}
    # security not an array
    doc = make_doc(security={"h": []}, security_schemes=schemes)
    resp = plan(doc)
    assert resp.status_code == 422
    assert resp.json()["errors"][0]["pointer"] == "/paths/~1things/get/security"

    # requirement item not an object
    doc = make_doc(security=[42], security_schemes=schemes)
    resp = plan(doc)
    assert resp.status_code == 422
    assert resp.json()["errors"][0]["pointer"] == "/paths/~1things/get/security/0"

    # scopes not an array of strings
    doc = make_doc(security=[{"h": "read"}], security_schemes=schemes)
    resp = plan(doc)
    assert resp.status_code == 422
    assert resp.json()["errors"][0]["pointer"] == "/paths/~1things/get/security/0/h"

    doc = make_doc(security=[{"h": [1]}], security_schemes=schemes)
    assert plan(doc).status_code == 422

    # scheme node not an object
    doc = make_doc(security=[{"h": []}], security_schemes={"h": "scalar"})
    assert plan(doc).status_code == 422


def test_errors_from_several_alternatives_are_all_reported_sorted():
    doc = make_doc(
        security=[{"bad1": []}, {"bad2": []}],
        security_schemes={
            "bad1": {"type": "apiKey", "in": "header"},
            "bad2": {"type": "nope"},
        },
    )
    resp = plan(doc)
    assert resp.status_code == 422
    pointers = [e["pointer"] for e in resp.json()["errors"]]
    assert pointers == sorted(pointers)
    assert len(pointers) >= 2


# --------------------------------------------------------------------------- #
# 400 request errors
# --------------------------------------------------------------------------- #

def test_bad_document_shape_is_400():
    resp = client.post(
        "/security/plan",
        json={"document": {"openapi": "2.0", "paths": {}}, "selector": "GET /things"},
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_openapi_document"


def test_malformed_selector_is_400():
    doc = make_doc()
    for selector in ("BOGUS", "get", "GETT /x"):
        resp = plan(doc, selector=selector)
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_selector"


def test_unknown_path_and_method_are_400():
    doc = make_doc()
    assert plan(doc, selector="GET /missing").status_code == 400
    assert plan(doc, selector="DELETE /things").status_code == 400


def test_selector_method_is_case_insensitive():
    doc = make_doc(security=[], )
    assert plan(doc, selector="get /things").status_code == 200
    assert plan(doc, selector="GeT /things").status_code == 200


def test_bad_granted_envelope_is_400():
    doc = make_doc(security=[{"h": []}], security_schemes={"h": APIKEY_HEADER})
    for granted in ("nope", ["h"], {"h": "read"}, {"h": [1]}, {"": []}):
        resp = plan(doc, granted=granted)
        assert resp.status_code == 400, granted
        assert resp.json()["error"] == "invalid_granted_credentials"


def test_operation_supplied_by_31_path_item_ref():
    doc = {
        "openapi": "3.1.0",
        "info": {"title": "X", "version": "1"},
        "paths": {"/things": {"$ref": "#/components/pathItems/T"}},
        "components": {
            "pathItems": {"T": {"get": {"responses": {"200": {"description": "ok"}},
                                       "security": []}}},
        },
    }
    resp = plan(doc)
    assert resp.status_code == 200
    assert resp.json()["anonymous"] is True


# --------------------------------------------------------------------------- #
# Security / determinism guarantees
# --------------------------------------------------------------------------- #

def test_no_secret_values_are_accepted_or_echoed():
    doc = make_doc(security=[{"h": []}], security_schemes={"h": HTTP_BEARER})
    secret = "pat-SECRET-value-1234567890"
    # A caller that mistakes 'granted' for a credential store still gets no
    # echo of the value in a 200 response...
    resp = plan(doc, granted={"h": [secret]})
    assert resp.status_code == 200
    assert secret not in resp.text
    # ...nor in a 400 envelope error.
    resp = plan(doc, granted={"h": secret})
    assert resp.status_code == 400
    assert secret not in resp.text


def test_request_objects_are_not_mutated():
    doc = make_doc(
        security=[{"o": ["read"]}],
        security_schemes={"o": OAUTH2},
    )
    payload = {"document": doc, "selector": "get /things",
               "granted": {"o": ["read", "read", "zzz"]}}
    snapshot = copy.deepcopy(payload)
    resp = client.post("/security/plan", json=payload)
    assert resp.status_code == 200
    assert payload == snapshot


def test_duplicate_granted_scopes_and_key_order_do_not_matter():
    doc = make_doc(security=[{"o": ["read"]}], security_schemes={"o": OAUTH2})
    b1 = plan(doc, granted={"o": ["read", "read"]}).json()
    b2 = plan(doc, granted={"o": ["read"]}).json()
    assert b1["satisfiable"] == b2["satisfiable"] is True


def test_operation_pointer_escapes_path_tokens():
    doc = {
        "openapi": "3.0.3",
        "info": {"title": "X", "version": "1"},
        "paths": {"/pets/{petId}": {"get": {"responses": {"200": {"description": "ok"}},
                                           "security": []}}},
    }
    body = plan(doc, selector="GET /pets/{petId}").json()
    assert body["operation_pointer"] == "/paths/~1pets~1{petId}/get"


def test_root_service_listing_advertises_endpoint():
    root = client.get("/").json()
    assert root["security_plan"] == "POST /security/plan"
