"""Protected-operation security plan resolution (``POST /security/plan``).

Given an OpenAPI 3.x document, one ``METHOD /path`` operation selector and
the caller's available credential inventory (security scheme names plus the
granted OAuth scopes -- never the secret values), this module computes a
concrete plan for how to authenticate the operation during joint debugging:

* the operation-level ``security`` array overrides the root-level one;
  an explicit ``security: []`` (or the absence of any requirement) means
  the operation is anonymous;
* the requirement objects inside a security array are alternatives (OR),
  while the schemes named inside one requirement object must all be
  satisfied simultaneously (AND);
* local Security Scheme Object ``$ref`` chains are resolved cycle-safe,
  honoring OpenAPI 3.1 sibling fields;
* apiKey / http / oauth2 / openIdConnect definitions and the scopes they
  require are validated against the specification;
* the plan picks the satisfiable alternative that needs the fewest
  schemes, breaking ties by canonical (sorted-key) JSON ordering;
* when no alternative is satisfiable, the operation is still answered
  with HTTP 200 and every missing scheme/scope is listed per alternative.

Dangling / external references and illegal scheme or requirement
definitions are structural contract problems and produce HTTP 422. The
service never asks for, stores or echoes secret values.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from .refresolver import (
    MAX_REF_CHAIN,
    RefResolver,
    UnresolvableReferenceError,
    is_local_ref,
    parse_local_ref,
)
from .slicer import HTTP_METHODS, parse_selector

# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class SecurityPlanError(Exception):
    """Base class for security plan failures."""


class InvalidDocumentError(SecurityPlanError):
    """The submitted document is not a recognizable OpenAPI 3.x doc (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class InvalidSelectorError(SecurityPlanError):
    """The selector is malformed (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class InvalidGrantError(SecurityPlanError):
    """The granted-credentials envelope is malformed (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class SecurityDefinitionError(SecurityPlanError):
    """One or more security definitions are illegal (HTTP 422)."""

    def __init__(self, errors: List[Dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(
            "; ".join(f"{e['code']} @ {e.get('pointer', '')}" for e in errors)
        )


# --------------------------------------------------------------------------- #
# JSON Pointer helpers (RFC 6901)
# --------------------------------------------------------------------------- #


def escape_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def pointer_join(base: str, token: Any) -> str:
    return base + "/" + escape_token(str(token))


# --------------------------------------------------------------------------- #
# Local $ref chain resolution (cycle-safe, OpenAPI 3.1 sibling semantics)
# --------------------------------------------------------------------------- #


def _reference_error(pointer: str, ref: str, message: str) -> Dict[str, Any]:
    return {
        "code": "unresolvable_reference",
        "pointer": pointer,
        "ref": ref,
        "error": message,
    }


def _follow_chain(
    doc: Dict[str, Any], node: Any, node_pointer: str
) -> Tuple[Optional[List[Tuple[Dict[str, Any], str]]], Optional[Dict[str, Any]]]:
    """Follow the local ``$ref`` chain starting at *node*.

    Returns ``(layers, error)``; each layer is ``(node, pointer)`` from the
    referencing occurrence through to the terminal non-reference object.
    """
    resolver = RefResolver(doc)
    layers: List[Tuple[Dict[str, Any], str]] = []
    current = node
    current_pointer = node_pointer
    seen: Dict[str, int] = {}
    refs: List[str] = []

    while isinstance(current, dict) and isinstance(current.get("$ref"), str):
        ref = current["$ref"]
        if not is_local_ref(ref):
            return None, _reference_error(
                current_pointer,
                ref,
                f"unsupported non-local reference '{ref}': only document-local "
                "references of the form '#/...' are supported",
            )
        target_pointer = parse_local_ref(ref)
        if target_pointer == "":
            return None, _reference_error(
                current_pointer,
                ref,
                f"reference '{ref}' targets the document root; a Security "
                "Scheme Object reference must point to a specific object "
                "location",
            )
        if target_pointer in seen:
            loop_start = seen[target_pointer]
            loop = refs[loop_start:] + [ref]
            return None, _reference_error(
                current_pointer,
                ref,
                "circular reference detected: " + " -> ".join(loop),
            )
        if len(refs) >= MAX_REF_CHAIN:
            return None, _reference_error(
                current_pointer,
                ref,
                f"reference chain exceeds the maximum depth of "
                f"{MAX_REF_CHAIN} links (last reference: {ref})",
            )
        seen[target_pointer] = len(refs)
        refs.append(ref)
        try:
            target = resolver.pointer(target_pointer)
        except UnresolvableReferenceError as exc:
            return None, _reference_error(current_pointer, exc.ref, str(exc))
        if not isinstance(target, dict):
            return None, _reference_error(
                current_pointer,
                ref,
                f"reference '{ref}' does not target an object",
            )
        layers.append((current, current_pointer))
        current = target
        current_pointer = target_pointer

    if not isinstance(current, dict):
        return None, {
            "code": "invalid_security_definition",
            "pointer": current_pointer,
            "error": "security scheme node must be an object",
        }

    layers.append((current, current_pointer))
    return layers, None


def _build_effective(
    layers: List[Tuple[Dict[str, Any], str]], merge_siblings: bool
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Build the effective object from a resolved chain.

    Returns ``(object, key_provenance)``; *key_provenance* maps each member
    to the JSON Pointer of the layer it came from. OpenAPI 3.0 uses the
    terminal target verbatim (siblings of ``$ref`` ignored); OpenAPI 3.1
    overlays sibling fields from the terminal target back toward the
    occurrence, so nearer siblings win.
    """
    if not merge_siblings:
        terminal, terminal_pointer = layers[-1]
        return dict(terminal), {key: terminal_pointer for key in terminal}

    merged: Dict[str, Any] = {}
    provenance: Dict[str, str] = {}
    for layer_node, layer_pointer in reversed(layers):
        for key, value in layer_node.items():
            if key == "$ref":
                continue
            merged[key] = value
            provenance[key] = layer_pointer
    return merged, provenance


# --------------------------------------------------------------------------- #
# Document shape / operation lookup
# --------------------------------------------------------------------------- #


def _validate_shape(doc: Any) -> List[str]:
    if not isinstance(doc, dict):
        return ["document must be a JSON object"]
    messages: List[str] = []
    version = doc.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        messages.append(
            "document.openapi must be a version string starting with '3.' "
            f"(OpenAPI 3.x), got {version!r}"
        )
    if not isinstance(doc.get("paths"), dict):
        messages.append("document.paths must be an object")
    return messages


def _resolve_path_item(
    doc: Dict[str, Any], raw_item: Any, item_pointer: str, is31: bool
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Resolve the effective operation path item, cycle-safe."""
    if not isinstance(raw_item, dict):
        return None, {
            "code": "invalid_security_definition",
            "pointer": item_pointer,
            "error": "path item must be an object",
        }
    if not isinstance(raw_item.get("$ref"), str):
        return raw_item, None
    layers, error = _follow_chain(doc, raw_item, item_pointer)
    if error is not None:
        return None, error
    effective, _provenance = _build_effective(layers, is31)
    return effective, None


# --------------------------------------------------------------------------- #
# Security Scheme Object validation
# --------------------------------------------------------------------------- #

_FLOW_KEYS = ("implicit", "password", "clientCredentials", "authorizationCode")
_APIKEY_LOCATIONS = ("header", "query", "cookie")
_SCHEME_TYPES = ("apiKey", "http", "oauth2", "openIdConnect")


def _definition_error(pointer: str, message: str) -> Dict[str, Any]:
    return {
        "code": "invalid_security_definition",
        "pointer": pointer,
        "error": message,
    }


def _validate_flows(flows: Any, scheme_pointer: str) -> List[Dict[str, Any]]:
    errors: List[Dict[str, Any]] = []
    flows_pointer = pointer_join(scheme_pointer, "flows")
    if not isinstance(flows, dict):
        return [
            _definition_error(
                flows_pointer,
                "an oauth2 security scheme requires an object 'flows'",
            )
        ]
    known_flows = [name for name in flows if name in _FLOW_KEYS]
    if not known_flows:
        return [
            _definition_error(
                flows_pointer,
                "an oauth2 security scheme requires at least one of "
                "'implicit'/'password'/'clientCredentials'/"
                "'authorizationCode'",
            )
        ]
    for flow_name in flows:
        flow_pointer = pointer_join(flows_pointer, flow_name)
        if flow_name not in _FLOW_KEYS:
            errors.append(
                _definition_error(
                    flow_pointer,
                    f"unknown oauth2 flow {flow_name!r}; expected one of "
                    "'implicit'/'password'/'clientCredentials'/"
                    "'authorizationCode'",
                )
            )
            continue
        flow = flows[flow_name]
        if not isinstance(flow, dict):
            errors.append(
                _definition_error(flow_pointer, "oauth2 flow must be an object")
            )
            continue
        if flow_name == "implicit":
            url = flow.get("authorizationUrl")
            if not isinstance(url, str) or not url:
                errors.append(
                    _definition_error(
                        pointer_join(flow_pointer, "authorizationUrl"),
                        "the 'implicit' oauth2 flow requires a non-empty "
                        "string 'authorizationUrl'",
                    )
                )
        if flow_name in ("password", "clientCredentials"):
            url = flow.get("tokenUrl")
            if not isinstance(url, str) or not url:
                errors.append(
                    _definition_error(
                        pointer_join(flow_pointer, "tokenUrl"),
                        f"the {flow_name!r} oauth2 flow requires a non-empty "
                        "string 'tokenUrl'",
                    )
                )
        if flow_name == "authorizationCode":
            for field in ("authorizationUrl", "tokenUrl"):
                url = flow.get(field)
                if not isinstance(url, str) or not url:
                    errors.append(
                        _definition_error(
                            pointer_join(flow_pointer, field),
                            "the 'authorizationCode' oauth2 flow requires a "
                            f"non-empty string {field!r}",
                        )
                    )
        refresh = flow.get("refreshUrl")
        if refresh is not None and not isinstance(refresh, str):
            errors.append(
                _definition_error(
                    pointer_join(flow_pointer, "refreshUrl"),
                    "'refreshUrl' must be a string when present",
                )
            )
        scopes = flow.get("scopes")
        if not isinstance(scopes, dict) or not all(
            isinstance(scope_name, str) and isinstance(description, str)
            for scope_name, description in scopes.items()
        ):
            errors.append(
                _definition_error(
                    pointer_join(flow_pointer, "scopes"),
                    "oauth2 flow 'scopes' must be an object mapping scope "
                    "name strings to description strings",
                )
            )
    return errors


def _validate_scheme(
    scheme: Dict[str, Any], scheme_pointer: str
) -> List[Dict[str, Any]]:
    """Validate one effective Security Scheme Object definition."""
    errors: List[Dict[str, Any]] = []
    scheme_type = scheme.get("type")
    if not isinstance(scheme_type, str) or not scheme_type:
        errors.append(
            _definition_error(
                pointer_join(scheme_pointer, "type"),
                "security scheme requires a non-empty string 'type'; expected "
                "one of 'apiKey'/'http'/'oauth2'/'openIdConnect'",
            )
        )
        return errors
    if scheme_type not in _SCHEME_TYPES:
        errors.append(
            _definition_error(
                pointer_join(scheme_pointer, "type"),
                f"unsupported security scheme type {scheme_type!r}; expected "
                "one of 'apiKey'/'http'/'oauth2'/'openIdConnect'",
            )
        )
        return errors

    if scheme_type == "apiKey":
        name = scheme.get("name")
        if not isinstance(name, str) or not name:
            errors.append(
                _definition_error(
                    pointer_join(scheme_pointer, "name"),
                    "an apiKey security scheme requires a non-empty string "
                    "'name' (the header/query/cookie parameter name)",
                )
            )
        location = scheme.get("in")
        if location not in _APIKEY_LOCATIONS:
            errors.append(
                _definition_error(
                    pointer_join(scheme_pointer, "in"),
                    "an apiKey security scheme requires 'in' to be one of "
                    "'header'/'query'/'cookie'",
                )
            )
    elif scheme_type == "http":
        http_scheme = scheme.get("scheme")
        if not isinstance(http_scheme, str) or not http_scheme:
            errors.append(
                _definition_error(
                    pointer_join(scheme_pointer, "scheme"),
                    "an http security scheme requires a non-empty string "
                    "'scheme' (an HTTP Authentication scheme, e.g. 'basic' "
                    "or 'bearer')",
                )
            )
        bearer_format = scheme.get("bearerFormat")
        if bearer_format is not None and not isinstance(bearer_format, str):
            errors.append(
                _definition_error(
                    pointer_join(scheme_pointer, "bearerFormat"),
                    "'bearerFormat' must be a string when present",
                )
            )
    elif scheme_type == "oauth2":
        errors.extend(_validate_flows(scheme.get("flows"), scheme_pointer))
    else:  # openIdConnect
        url = scheme.get("openIdConnectUrl")
        if not isinstance(url, str) or not url:
            errors.append(
                _definition_error(
                    pointer_join(scheme_pointer, "openIdConnectUrl"),
                    "an openIdConnect security scheme requires a non-empty "
                    "string 'openIdConnectUrl'",
                )
            )
    return errors


def _oauth2_declared_scopes(scheme: Dict[str, Any]) -> set:
    """Union of scope names declared across every oauth2 flow."""
    scopes: set = set()
    flows = scheme.get("flows")
    if isinstance(flows, dict):
        for flow in flows.values():
            if isinstance(flow, dict) and isinstance(flow.get("scopes"), dict):
                scopes.update(flow["scopes"])
    return scopes


# --------------------------------------------------------------------------- #
# Plan building
# --------------------------------------------------------------------------- #


class ResolvedScheme:
    """One security scheme resolved for the selected operation."""

    __slots__ = (
        "name",
        "scheme",
        "scheme_pointer",
        "requirement_pointer",
        "required_scopes",
    )

    def __init__(
        self,
        name: str,
        scheme: Dict[str, Any],
        scheme_pointer: str,
        requirement_pointer: str,
        required_scopes: List[str],
    ) -> None:
        self.name = name
        self.scheme = scheme
        self.scheme_pointer = scheme_pointer
        self.requirement_pointer = requirement_pointer
        self.required_scopes = required_scopes


def _sorted_errors(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    def key(item: Dict[str, Any]):
        return (
            str(item.get("code")),
            str(item.get("pointer") or ""),
            str(item.get("ref") or ""),
            str(item.get("error") or ""),
        )

    # Deduplicate identical structural reports while keeping stable order.
    deduped: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
    for item in errors:
        deduped.setdefault(
            (
                str(item.get("code")),
                str(item.get("pointer") or ""),
                str(item.get("ref") or ""),
                str(item.get("error") or ""),
            ),
            item,
        )
    return sorted(deduped.values(), key=key)


def _scheme_plan_entry(
    resolved: ResolvedScheme, granted: Dict[str, List[str]]
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Build one selected scheme's injection plan entry.

    Returns ``(entry, missing_credentials, missing_scopes)``.
    """
    scheme = resolved.scheme
    scheme_type = scheme["type"]
    entry: Dict[str, Any] = {
        "scheme": resolved.name,
        "type": scheme_type,
        "required_scopes": list(resolved.required_scopes),
        "source_pointer": resolved.scheme_pointer,
        "requirement_pointer": resolved.requirement_pointer,
    }

    missing_credentials: List[Dict[str, Any]] = []
    missing_scopes: List[Dict[str, Any]] = []

    if scheme_type == "apiKey":
        location = scheme["in"]
        param_name = scheme["name"]
        entry["location"] = location
        entry["parameter_name"] = param_name
        if location == "header":
            entry["injection"] = (
                f"send the API key in the HTTP header {param_name!r}"
            )
        elif location == "query":
            entry["injection"] = (
                f"send the API key as the query parameter {param_name!r}"
            )
        else:
            entry["injection"] = (
                f"send the API key as the Cookie {param_name!r} "
                f"('{param_name}=<key>' in the Cookie header)"
            )
    elif scheme_type == "http":
        http_scheme = scheme["scheme"]
        entry["location"] = "header"
        entry["parameter_name"] = "Authorization"
        entry["http_scheme"] = http_scheme
        label = http_scheme.lower()
        if label == "basic":
            entry["injection"] = (
                "send HTTP Basic credentials in the 'Authorization' header "
                "as 'Basic <base64(user:password)>'"
            )
        elif label == "bearer":
            bearer_format = scheme.get("bearerFormat")
            entry["injection"] = (
                "send the bearer token in the 'Authorization' header as "
                "'Bearer <token>'"
                + (f" (declared bearerFormat: {bearer_format})" if bearer_format else "")
            )
        else:
            entry["injection"] = (
                f"send {http_scheme!r} credentials in the 'Authorization' "
                f"header as '{http_scheme} <token>'"
            )
    elif scheme_type == "oauth2":
        entry["location"] = "header"
        entry["parameter_name"] = "Authorization"
        entry["injection"] = (
            "send the OAuth 2.0 access token in the 'Authorization' header "
            "as 'Bearer <token>' carrying the required scopes"
        )
    else:  # openIdConnect
        entry["location"] = "header"
        entry["parameter_name"] = "Authorization"
        entry["injection"] = (
            "discover the OpenID Connect provider at 'openIdConnectUrl' and "
            "send the resulting access token in the 'Authorization' header "
            "as 'Bearer <token>'"
        )

    if resolved.name not in granted:
        missing_credentials.append(
            {
                "scheme": resolved.name,
                "type": scheme_type,
                "source_pointer": resolved.scheme_pointer,
                "requirement_pointer": resolved.requirement_pointer,
                "error": (
                    f"no credential granted for security scheme "
                    f"{resolved.name!r} ({scheme_type})"
                ),
            }
        )
    elif resolved.required_scopes:
        held = set(granted[resolved.name])
        absent = [scope for scope in resolved.required_scopes if scope not in held]
        for scope in absent:
            missing_scopes.append(
                {
                    "scheme": resolved.name,
                    "type": scheme_type,
                    "scope": scope,
                    "source_pointer": resolved.scheme_pointer,
                    "requirement_pointer": pointer_join(
                        resolved.requirement_pointer, resolved.name
                    ),
                    "error": (
                        f"granted credential for {resolved.name!r} is missing "
                        f"the required scope {scope!r}"
                    ),
                }
            )

    return entry, missing_credentials, missing_scopes


def _missing_key(item: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(item.get("scheme")),
        str(item.get("scope") or ""),
        str(item.get("error") or ""),
    )


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def plan_security(
    doc: Any, selector: Any, granted: Any
) -> Dict[str, Any]:
    """Compute the security plan for the selected operation.

    :raises InvalidDocumentError: *doc* is not OpenAPI 3.x.
    :raises InvalidSelectorError: the selector is malformed/unknown (400).
    :raises InvalidGrantError: *granted* is malformed (400).
    :raises SecurityDefinitionError: illegal security definitions (422).
    """
    shape_errors = _validate_shape(doc)
    if shape_errors:
        raise InvalidDocumentError(shape_errors)

    parsed = parse_selector(selector)
    if parsed is None:
        raise InvalidSelectorError(
            [
                f"malformed selector {selector!r}: expected 'METHOD /path' "
                "(e.g. 'GET /pets')"
            ]
        )
    method, path = parsed
    if path not in doc["paths"]:
        raise InvalidSelectorError([f"{method.upper()} {path}: path is not declared"])

    # Validate the granted-credentials envelope up front (request error, 400).
    normalized_grant: Dict[str, List[str]] = {}
    if granted is None:
        granted = {}
    if not isinstance(granted, dict):
        raise InvalidGrantError(
            ["granted must be an object mapping security scheme names to "
             "granted scope name arrays"]
        )
    for scheme_name in sorted(granted, key=str):
        scopes = granted[scheme_name]
        if not isinstance(scheme_name, str) or not scheme_name:
            raise InvalidGrantError(
                ["granted security scheme names must be non-empty strings"]
            )
        if not isinstance(scopes, list) or not all(
            isinstance(scope, str) for scope in scopes
        ):
            raise InvalidGrantError(
                [
                    f"granted.{scheme_name} must be an array of granted scope "
                    "name strings (use an empty array for schemes without "
                    "scopes, such as apiKey/http)"
                ]
            )
        # Deduplicate while keeping stable sorted output; scope sets are
        # unordered, so the response must not depend on input order.
        normalized_grant[scheme_name] = sorted(set(scopes))

    is31 = str(doc.get("openapi", "")).startswith(("3.1", "3.2"))
    path_pointer = pointer_join("/paths", path)
    path_item, item_error = _resolve_path_item(
        doc, doc["paths"][path], path_pointer, is31
    )
    if item_error is not None:
        raise SecurityDefinitionError(_sorted_errors([item_error]))

    method_keys = {
        key.lower(): key for key in path_item if key.lower() in HTTP_METHODS
    }
    if method not in method_keys:
        raise InvalidSelectorError(
            [f"{method.upper()} {path}: operation is not declared"]
        )
    operation_key = method_keys[method]
    operation_pointer = pointer_join(path_pointer, operation_key)
    operation = path_item[operation_key]
    if not isinstance(operation, dict):
        raise SecurityDefinitionError(
            _sorted_errors(
                [
                    {
                        "code": "invalid_security_definition",
                        "pointer": operation_pointer,
                        "error": "operation must be an object",
                    }
                ]
            )
        )

    # Effective security: operation-level overrides root-level entirely.
    if "security" in operation:
        security = operation["security"]
        security_pointer = pointer_join(operation_pointer, "security")
        inherited = False
    else:
        security = doc.get("security")
        security_pointer = "/security"
        inherited = security is not None
    if security is None:
        # No requirement anywhere: the operation is anonymous.
        security = []
        security_pointer = None

    # --------------------------------------------------------------- #
    # Structural validation of the effective security array (422)
    # --------------------------------------------------------------- #
    errors: List[Dict[str, Any]] = []
    alternatives: List[List[ResolvedScheme]] = []

    if not isinstance(security, list):
        errors.append(
            _definition_error(
                security_pointer,
                "'security' must be an array of Security Requirement "
                "Objects ([] means anonymous)",
            )
        )
        raise SecurityDefinitionError(_sorted_errors(errors))

    schemes_section = (
        doc.get("components", {}).get("securitySchemes")
        if isinstance(doc.get("components"), dict)
        else None
    )
    if not isinstance(schemes_section, dict):
        schemes_section = None

    for alt_index, requirement in enumerate(security):
        requirement_pointer = pointer_join(security_pointer, alt_index)
        if not isinstance(requirement, dict):
            errors.append(
                _definition_error(
                    requirement_pointer,
                    "each security array item must be a Security Requirement "
                    "Object mapping scheme names to required scope arrays",
                )
            )
            continue

        resolved_alternative: List[ResolvedScheme] = []
        for scheme_name in sorted(requirement):
            required_scopes = requirement[scheme_name]
            scope_pointer = pointer_join(requirement_pointer, scheme_name)
            if not isinstance(required_scopes, list) or not all(
                isinstance(scope, str) for scope in required_scopes
            ):
                errors.append(
                    _definition_error(
                        scope_pointer,
                        "the required scopes of a security requirement must "
                        "be an array of scope name strings (use [] for "
                        "schemes without scopes)",
                    )
                )
                continue

            if schemes_section is None or scheme_name not in schemes_section:
                errors.append(
                    {
                        "code": "unresolvable_reference",
                        "pointer": scope_pointer,
                        "error": (
                            f"security requirement names undefined scheme "
                            f"{scheme_name!r}: no such "
                            "'components/securitySchemes' entry"
                        ),
                    }
                )
                continue

            raw_scheme = schemes_section[scheme_name]
            scheme_occurrence = pointer_join(
                "/components/securitySchemes", scheme_name
            )
            if not isinstance(raw_scheme, dict):
                errors.append(
                    _definition_error(
                        scheme_occurrence,
                        f"security scheme {scheme_name!r} must be an object",
                    )
                )
                continue

            layers, chain_error = _follow_chain(
                doc, raw_scheme, scheme_occurrence
            )
            if chain_error is not None:
                errors.append(chain_error)
                continue

            effective_scheme, _key_provenance = _build_effective(layers, is31)
            definition_pointer = layers[-1][1]
            errors.extend(_validate_scheme(effective_scheme, definition_pointer))

            scheme_type = effective_scheme.get("type")
            # Scope/requirement consistency:
            #   apiKey/http never carry scopes in a requirement;
            #   oauth2 may only require scopes declared by some flow;
            #   openIdConnect scopes are discovery-time and unconstrained.
            if scheme_type == "apiKey" or scheme_type == "http":
                if required_scopes:
                    errors.append(
                        _definition_error(
                            scope_pointer,
                            f"{scheme_type} security scheme {scheme_name!r} "
                            "must use an empty required-scope array; scopes "
                            "apply only to oauth2/openIdConnect",
                        )
                    )
            elif scheme_type == "oauth2":
                declared = _oauth2_declared_scopes(effective_scheme)
                for scope in required_scopes:
                    if scope not in declared:
                        errors.append(
                            _definition_error(
                                scope_pointer,
                                f"required scope {scope!r} is not declared by "
                                f"any flow of oauth2 scheme {scheme_name!r}",
                            )
                        )

            # Register the alternative regardless of the definition-level
            # errors collected above: if any structural error exists the
            # whole request is rejected with 422 before a plan is built.
            resolved_alternative.append(
                ResolvedScheme(
                    scheme_name,
                    effective_scheme,
                    definition_pointer,
                    requirement_pointer,
                    sorted(required_scopes),
                )
            )
        alternatives.append(resolved_alternative)

    if errors:
        raise SecurityDefinitionError(_sorted_errors(errors))

    # --------------------------------------------------------------- #
    # Evaluate each alternative against the granted credential inventory
    # --------------------------------------------------------------- #
    alternative_reports: List[Dict[str, Any]] = []
    satisfiable_reports: List[Tuple[int, Dict[str, Any]]] = []

    for alt_index, resolved_alternative in enumerate(alternatives):
        requirement = security[alt_index]
        requirement_pointer = pointer_join(security_pointer, alt_index)
        plan: List[Dict[str, Any]] = []
        missing_credentials: List[Dict[str, Any]] = []
        missing_scopes: List[Dict[str, Any]] = []
        for resolved in resolved_alternative:
            entry, cred_errors, scope_errors = _scheme_plan_entry(
                resolved, normalized_grant
            )
            plan.append(entry)
            missing_credentials.extend(cred_errors)
            missing_scopes.extend(scope_errors)

        plan.sort(key=lambda item: item["scheme"])
        missing_credentials.sort(key=_missing_key)
        missing_scopes.sort(key=_missing_key)
        missing = missing_credentials + missing_scopes

        report = {
            "requirement": requirement,
            "requirement_pointer": requirement_pointer,
            "satisfiable": not missing,
            "scheme_count": len(resolved_alternative),
            "plan": plan,
            "missing": missing,
        }
        alternative_reports.append(report)
        if not missing:
            satisfiable_reports.append((alt_index, report))

    anonymous = security == []
    if anonymous:
        selected: Optional[Dict[str, Any]] = {
            "requirement": {},
            "requirement_pointer": None,
            "scheme_count": 0,
            "plan": [],
        }
        satisfiable = True
    elif satisfiable_reports:
        # Fewest schemes wins; ties are broken by canonical JSON ordering of
        # the requirement object (sorted keys, compact separators).
        def canonical(requirement: Any) -> str:
            return json.dumps(
                requirement, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False,
            )

        selected_index, selected_report = min(
            satisfiable_reports,
            key=lambda pair: (
                pair[1]["scheme_count"],
                canonical(pair[1]["requirement"]),
                pair[0],
            ),
        )
        selected = {
            "requirement": selected_report["requirement"],
            "requirement_pointer": selected_report["requirement_pointer"],
            "scheme_count": selected_report["scheme_count"],
            "plan": selected_report["plan"],
        }
        satisfiable = True
    else:
        selected = None
        satisfiable = False

    return {
        "operation_pointer": operation_pointer,
        "security_pointer": security_pointer,
        "inherited": inherited,
        "anonymous": anonymous,
        "satisfiable": satisfiable,
        "selected": selected,
        "alternatives": alternative_reports,
    }
