"""Follow-up call planning from an OpenAPI Link Object (``POST /links/plan``).

Given an OpenAPI 3.x document, a source ``METHOD /path`` operation selector,
the name of one link declared by one of the source responses and the
concrete request/response runtime context, produce the plan for the next
HTTP call the link describes: the target operation, parameter values
grouped by ``path`` / ``query`` / ``header`` / ``cookie`` and the request
body, each annotated with its source JSON Pointer.

Response selection runs in the OpenAPI order: the exact status code, then
the class wildcard ``nXX`` (case-insensitive), then ``default``. Response,
Link and target Path Item local ``$ref`` chains are resolved cycle-safe;
OpenAPI 3.1 merges ``$ref`` sibling fields while 3.0 ignores them.

A Link Object must identify its target with exactly one of a local
``operationRef`` fragment (``#/...`` ending in an HTTP method) or a
globally unique ``operationId``. ``parameters`` keys match **target
parameter names**; the same name declared in several parameter locations
is ambiguous. Mapping values and ``requestBody`` that are strings
beginning with ``$`` are evaluated as complete runtime expressions
(``$url`` / ``$method`` / ``$statusCode`` / ``$request.*`` /
``$response.*``, body fragments via RFC 6901 JSON Pointer); every other
JSON value is a literal constant. Unlike URL interpolation, expression
results may be arrays or objects.

Missing expression values, unknown or ambiguous targets and parameter
names, unset required target parameters and external / dangling /
circular references are all collected and rejected with HTTP 422. The
input document and context are never modified and no partial plan is
returned.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote

from .callbacks import (
    MISSING,
    _build_effective,
    _evaluate,
    _follow_chain,
    _navigate_body,
    _normalize_context,
    _parse_expression,
    _sorted_errors,
    _valid_pointer_syntax,
    escape_token,
    pointer_join,
)
from .materializer import GROUPS, Parameter, _resolve_occurrences
from .refresolver import (
    RefResolver,
    UnresolvableReferenceError,
    _decode_token,
    is_local_ref,
)
from .slicer import HTTP_METHODS, parse_selector


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class LinkPlanError(Exception):
    """Base class for link planning failures."""


class InvalidDocumentError(LinkPlanError):
    """The submitted document is not a recognizable OpenAPI 3.x doc (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class InvalidSelectorError(LinkPlanError):
    """The selector is malformed or unknown (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class InvalidLinkRequestError(LinkPlanError):
    """The request envelope (link name / context) is malformed (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class LinkPlanningError(LinkPlanError):
    """One or more semantic link planning problems (HTTP 422)."""

    def __init__(self, errors: List[Dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(
            "; ".join(f"{e['code']} @ {e.get('pointer', '')}" for e in errors)
        )


# --------------------------------------------------------------------------- #
# Document shape / source operation lookup
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


def _resolve_object_member(
    doc: Dict[str, Any],
    raw: Any,
    occurrence_pointer: str,
    is31: bool,
    *,
    kind: str,
) -> Tuple[
    Optional[Dict[str, Any]],
    Optional[Dict[str, str]],
    Optional[str],
    Optional[Dict[str, Any]],
]:
    """Resolve an inline or ``$ref``'d object (Response / Link / Path Item).

    Returns ``(node, provenance, effective_pointer, error)``. For an inline
    object the effective pointer is its occurrence pointer and provenance is
    ``None``; for a referenced object the effective pointer follows the chain
    to its terminal location and provenance maps each member key to the
    layer that declares it (OpenAPI 3.1 sibling merging).
    """
    if not isinstance(raw, dict):
        return None, None, None, {
            "code": "invalid_link",
            "pointer": occurrence_pointer,
            "error": f"{kind} must be an object",
        }
    if not isinstance(raw.get("$ref"), str):
        return raw, None, occurrence_pointer, None

    layers, error = _follow_chain(doc, raw, occurrence_pointer)
    if error is not None:
        return None, None, None, error
    effective, provenance = _build_effective(layers, is31)
    terminal_pointer = layers[-1][1]
    return effective, provenance, terminal_pointer, None


def _resolve_path_item(
    doc: Dict[str, Any], raw_item: Any, item_pointer: str, is31: bool
) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[Dict[str, Any]]]:
    """Resolve a Path Item Object through its own local ``$ref`` chain."""
    if not isinstance(raw_item, dict):
        return None, None, {
            "code": "invalid_link",
            "pointer": item_pointer,
            "error": "path item must be an object",
        }
    if not isinstance(raw_item.get("$ref"), str):
        return raw_item, item_pointer, None
    layers, error = _follow_chain(doc, raw_item, item_pointer)
    if error is not None:
        return None, None, error
    effective, _provenance = _build_effective(layers, is31)
    return effective, item_pointer, None


def _member_pointer(
    key: str, base_pointer: str, provenance: Optional[Dict[str, str]]
) -> str:
    """JSON Pointer of an effective member, following a resolved chain."""
    if provenance is None or key not in provenance:
        return pointer_join(base_pointer, key)
    return pointer_join(provenance[key], key)


# --------------------------------------------------------------------------- #
# Response selection
# --------------------------------------------------------------------------- #


def _select_response_key(
    responses: Dict[str, Any], status_code: Any
) -> Tuple[Optional[str], Optional[str]]:
    """Pick the response key in OpenAPI order: exact, ``nXX``, ``default``.

    Returns ``(key, reason)`` where *reason* is ``"exact"`` / ``"wildcard"``
    / ``"default"``; ``(None, None)`` when nothing matches.
    """
    status_text = str(status_code)

    if status_text in responses:
        return status_text, "exact"

    wildcard: Optional[str] = None
    if status_text[:1].isdigit():
        wanted = status_text[0].lower() + "xx"
        for key in responses:
            if isinstance(key, str) and key.lower() == wanted:
                wildcard = key
                break
    if wildcard is not None:
        return wildcard, "wildcard"

    if "default" in responses:
        return "default", "default"
    return None, None


# --------------------------------------------------------------------------- #
# Target resolution
# --------------------------------------------------------------------------- #


def _decode_pointer(pointer: str) -> Optional[List[str]]:
    """Split a JSON Pointer into its decoded tokens, or ``None`` if invalid."""
    if not pointer.startswith("/") or not _valid_pointer_syntax(pointer):
        return None
    return [
        _decode_token(raw) for raw in pointer.split("/")[1:]
    ]


def _resolve_operation_ref(
    doc: Dict[str, Any], operation_ref: Any, link_pointer: str, is31: bool
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Resolve a local ``operationRef`` fragment to its target operation."""
    ref_pointer = link_pointer + "/operationRef"
    if not isinstance(operation_ref, str) or not operation_ref:
        return None, {
            "code": "invalid_link",
            "pointer": ref_pointer,
            "error": "operationRef must be a non-empty local JSON Pointer string",
        }
    if not is_local_ref(operation_ref):
        return None, {
            "code": "unresolvable_reference",
            "pointer": ref_pointer,
            "ref": operation_ref,
            "error": (
                f"unsupported non-local operationRef '{operation_ref}': only "
                "document-local references of the form '#/...' are supported"
            ),
        }

    fragment = operation_ref.split("#", 1)[1]
    tokens = _decode_pointer(fragment)
    if tokens is None:
        return None, {
            "code": "unknown_link_target",
            "pointer": ref_pointer,
            "ref": operation_ref,
            "error": "operationRef is not a valid JSON Pointer",
        }
    if len(tokens) < 2:
        return None, {
            "code": "unknown_link_target",
            "pointer": ref_pointer,
            "ref": operation_ref,
            "error": (
                "operationRef must point to an operation, i.e. a Path Item "
                "location followed by an HTTP method"
            ),
        }

    method_token = tokens[-1]
    method = method_token.lower()
    if method not in HTTP_METHODS:
        return None, {
            "code": "unknown_link_target",
            "pointer": ref_pointer,
            "ref": operation_ref,
            "error": (
                f"operationRef '{operation_ref}' does not end in an HTTP "
                "method (get/put/post/delete/options/head/patch/trace)"
            ),
        }
    parent_tokens = tokens[:-1]
    parent_pointer = "".join("/" + escape_token(token) for token in parent_tokens)

    try:
        parent = RefResolver(doc).pointer(parent_pointer)
    except UnresolvableReferenceError as exc:
        return None, {
            "code": "unresolvable_reference",
            "pointer": ref_pointer,
            "ref": operation_ref,
            "error": str(exc),
        }

    path_item, _item_pointer, item_error = _resolve_path_item(
        doc, parent, parent_pointer, is31
    )
    if item_error is not None:
        item_error["pointer"] = ref_pointer
        item_error["ref"] = operation_ref
        return None, item_error
    if not isinstance(path_item, dict):
        return None, {
            "code": "unknown_link_target",
            "pointer": ref_pointer,
            "ref": operation_ref,
            "error": "operationRef does not point to an operation of a Path Item Object",
        }

    method_keys = {key.lower(): key for key in path_item if key.lower() in HTTP_METHODS}
    if method not in method_keys:
        return None, {
            "code": "unknown_link_target",
            "pointer": ref_pointer,
            "ref": operation_ref,
            "error": (
                f"operationRef '{operation_ref}' points at a Path Item that "
                f"does not declare {method.upper()}"
            ),
        }
    operation_key = method_keys[method]
    operation = path_item[operation_key]
    if not isinstance(operation, dict):
        return None, {
            "code": "unknown_link_target",
            "pointer": pointer_join(parent_pointer, operation_key),
            "ref": operation_ref,
            "error": "operationRef target must be an Operation Object",
        }

    # Only references into #/paths carry a concrete URL path; components
    # Path Items (OpenAPI 3.1) are reusable templates without one.
    target_path = tokens[1] if len(tokens) >= 2 and tokens[0] == "paths" else None
    target = {
        "kind": "operationRef",
        "operation_ref": operation_ref,
        "operation_id": None,
        "method": method,
        "path": target_path,
        "pointer": pointer_join(parent_pointer, operation_key),
        "path_item_pointer": parent_pointer,
        "path_item": path_item,
        "operation": operation,
    }
    return target, None


def _build_operation_index(
    doc: Dict[str, Any], is31: bool
) -> Tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """Index every paths-item operation by its ``operationId``."""
    index: Dict[str, List[Dict[str, Any]]] = {}
    errors: List[Dict[str, Any]] = []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return index, errors

    for path, raw_item in paths.items():
        path_pointer = pointer_join("/paths", path)
        path_item, _item_pointer, item_error = _resolve_path_item(
            doc, raw_item, path_pointer, is31
        )
        if item_error is not None:
            errors.append(item_error)
            continue
        if not isinstance(path_item, dict):
            continue
        for key, operation in path_item.items():
            if key.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                continue
            index.setdefault(operation_id, []).append(
                {
                    "method": key.lower(),
                    "path": path,
                    "pointer": pointer_join(path_pointer, key),
                    "path_item_pointer": path_pointer,
                    "path_item": path_item,
                    "operation": operation,
                }
            )
    return index, errors


def _resolve_operation_id(
    doc: Dict[str, Any], operation_id: Any, link_pointer: str, is31: bool
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Resolve a globally unique ``operationId`` to its target operation."""
    id_pointer = link_pointer + "/operationId"
    if not isinstance(operation_id, str) or not operation_id:
        return None, {
            "code": "invalid_link",
            "pointer": id_pointer,
            "error": "operationId must be a non-empty string",
        }

    index, index_errors = _build_operation_index(doc, is31)
    if index_errors:
        return None, index_errors[0]

    matches = index.get(operation_id, [])
    if not matches:
        return None, {
            "code": "unknown_link_target",
            "pointer": id_pointer,
            "operation_id": operation_id,
            "error": (
                f"no operation declares operationId {operation_id!r}; the "
                "identifier must resolve to exactly one operation"
            ),
        }
    if len(matches) > 1:
        pointers = ", ".join(sorted(match["pointer"] for match in matches))
        return None, {
            "code": "unknown_link_target",
            "pointer": id_pointer,
            "operation_id": operation_id,
            "error": (
                f"operationId {operation_id!r} is not globally unique; it is "
                f"declared by {len(matches)} operations ({pointers})"
            ),
        }

    match = matches[0]
    target = {
        "kind": "operationId",
        "operation_ref": None,
        "operation_id": operation_id,
        "method": match["method"],
        "path": match["path"],
        "pointer": match["pointer"],
        "path_item_pointer": match["path_item_pointer"],
        "path_item": match["path_item"],
        "operation": match["operation"],
    }
    return target, None


# --------------------------------------------------------------------------- #
# Target parameters
# --------------------------------------------------------------------------- #


def _collect_target_parameters(
    doc: Dict[str, Any],
    path_item: Dict[str, Any],
    operation: Dict[str, Any],
    path_item_pointer: str,
    target_pointer: str,
    is31: bool,
) -> Tuple[List[Parameter], List[Dict[str, Any]]]:
    """Merge path/operation parameters exactly like /requests/materialize."""
    errors: List[Dict[str, Any]] = []
    op_pointer = target_pointer

    path_occurrences = _resolve_occurrences(
        doc,
        path_item.get("parameters"),
        pointer_join(path_item_pointer, "parameters"),
        is31,
        errors,
    )
    op_occurrences = _resolve_occurrences(
        doc,
        operation.get("parameters"),
        pointer_join(op_pointer, "parameters"),
        is31,
        errors,
    )

    def index_level(
        occurrences: List[Tuple[Dict[str, Any], str]], level: str
    ) -> Dict[Tuple[str, str], Tuple[Dict[str, Any], str]]:
        indexed: Dict[Tuple[str, str], Tuple[Dict[str, Any], str]] = {}
        for node, pointer in occurrences:
            name = node.get("name")
            location = node.get("in")
            if not isinstance(name, str) or not name:
                errors.append(
                    {
                        "code": "invalid_parameter",
                        "pointer": pointer,
                        "error": "parameter is missing a string 'name'",
                    }
                )
                continue
            if location not in GROUPS:
                errors.append(
                    {
                        "code": "invalid_parameter",
                        "pointer": pointer,
                        "in": location if isinstance(location, str) else None,
                        "name": name,
                        "error": (
                            "parameter 'in' must be one of path/query/header/"
                            f"cookie, got {location!r}"
                        ),
                    }
                )
                continue
            key = (location, name)
            if key in indexed:
                errors.append(
                    {
                        "code": "invalid_parameter",
                        "pointer": pointer,
                        "first_pointer": indexed[key][1],
                        "in": location,
                        "name": name,
                        "error": (
                            f"duplicate {level}-level {location} parameter "
                            f"'{name}'"
                        ),
                    }
                )
                continue
            indexed[key] = (node, pointer)
        return indexed

    path_index = index_level(path_occurrences, "path")
    op_index = index_level(op_occurrences, "operation")

    effective: List[Parameter] = []
    for (location, name), (node, pointer) in path_index.items():
        if (location, name) in op_index:
            op_node, op_pointer = op_index[(location, name)]
            effective.append(Parameter(location, name, op_node, op_pointer))
        else:
            effective.append(Parameter(location, name, node, pointer))
    for (location, name), (node, pointer) in op_index.items():
        if (location, name) not in path_index:
            effective.append(Parameter(location, name, node, pointer))
    return effective, errors


# --------------------------------------------------------------------------- #
# Runtime-expression evaluation (values may be structured, unlike URLs)
# --------------------------------------------------------------------------- #


def _evaluate_value(
    descriptor: Tuple[Any, ...], context: Dict[str, Any]
) -> Dict[str, Any]:
    """Evaluate a runtime expression allowing object/array results.

    Wraps the callback evaluator (which reports object/array results for URL
    interpolation as ``non_scalar``) and fetches the structured value for
    body, path and query sources; header values are always scalar.
    """
    outcome = _evaluate(descriptor, context)
    if outcome["kind"] != "non_scalar":
        return outcome

    _, side, source, token = descriptor
    message = context.get(side) or {}
    if source == "body":
        value = _navigate_body(message.get("body"), token)
        if value is MISSING or value is None:
            return {
                "kind": "missing",
                "context_pointer": outcome["context_pointer"],
            }
        return {"kind": "value", "value": value}
    if source in ("path", "query"):
        return {"kind": "value", "value": message[source][unquote(token)]}
    # Header values are validated as scalars by the context envelope; a
    # structured result can never be sent on the wire.
    return outcome


def _resolve_mapping_value(
    raw_value: Any,
    value_pointer: str,
    context: Dict[str, Any],
) -> Tuple[bool, Any, Optional[Dict[str, Any]]]:
    """Resolve one ``parameters`` / ``requestBody`` mapping value.

    Returns ``(is_expression, value, error)``. Strings beginning with ``$``
    must be complete runtime expressions; every other JSON value is a
    literal constant (deep-copied by the caller).
    """
    if not isinstance(raw_value, str) or not raw_value.startswith("$"):
        return False, raw_value, None

    descriptor = _parse_expression(raw_value)
    if descriptor is None:
        return True, None, {
            "code": "invalid_expression",
            "pointer": value_pointer,
            "expression": raw_value,
            "error": (
                f"{raw_value!r} is not a valid complete runtime expression"
            ),
        }

    outcome = _evaluate_value(descriptor, context)
    kind = outcome["kind"]
    if kind == "missing":
        return True, None, {
            "code": "missing_value",
            "pointer": value_pointer,
            "expression": raw_value,
            "context_pointer": outcome["context_pointer"],
            "error": (
                f"runtime expression {raw_value!r} has no value in the "
                "supplied request/response context"
            ),
        }
    if kind == "ambiguous":
        return True, None, {
            "code": "ambiguous_header",
            "pointer": value_pointer,
            "expression": raw_value,
            "context_pointer": outcome["context_pointer"],
            "error": (
                "header name matches several context headers that differ "
                "only in case"
            ),
        }
    if kind == "non_scalar":
        return True, None, {
            "code": "invalid_expression",
            "pointer": value_pointer,
            "expression": raw_value,
            "context_pointer": outcome["context_pointer"],
            "error": (
                f"runtime expression {raw_value!r} resolved to a structured "
                "header value; header expressions must resolve to a scalar"
            ),
        }
    return True, outcome["value"], None


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def plan_link(
    doc: Any, selector: Any, link_name: Any, context: Any
) -> Dict[str, Any]:
    """Build the follow-up call plan for one declared link.

    :raises InvalidDocumentError: *doc* is not OpenAPI 3.x.
    :raises InvalidSelectorError: the selector is malformed/unknown (400).
    :raises InvalidLinkRequestError: *link_name* / *context* malformed (400).
    :raises LinkPlanningError: semantic problems (422), each carrying source
        JSON Pointers.
    """
    shape_errors = _validate_shape(doc)
    if shape_errors:
        raise InvalidDocumentError(shape_errors)

    parsed = parse_selector(selector)
    if parsed is None:
        raise InvalidSelectorError(
            [
                f"malformed selector {selector!r}: expected 'METHOD /path' "
                "(e.g. 'POST /orders')"
            ]
        )
    method, path = parsed
    if path not in doc["paths"]:
        raise InvalidSelectorError([f"{method.upper()} {path}: path is not declared"])

    request_errors: List[str] = []
    if not isinstance(link_name, str) or not link_name:
        request_errors.append(
            "link must be the non-empty name of a link in the selected response"
        )
    normalized_context, context_errors = _normalize_context(context)
    if context_errors:
        request_errors.extend(context_errors)
    if request_errors:
        raise InvalidLinkRequestError(request_errors)

    is31 = str(doc.get("openapi", "")).startswith(("3.1", "3.2"))
    errors: List[Dict[str, Any]] = []

    # --- Source operation --------------------------------------------------
    path_pointer = pointer_join("/paths", path)
    path_item, _item_pointer, item_error = _resolve_path_item(
        doc, doc["paths"][path], path_pointer, is31
    )
    if item_error is not None:
        raise LinkPlanningError(_sorted_errors([item_error]))

    method_keys = {key.lower(): key for key in path_item if key.lower() in HTTP_METHODS}
    if method not in method_keys:
        raise InvalidSelectorError(
            [f"{method.upper()} {path}: operation is not declared"]
        )
    operation_key = method_keys[method]
    operation = path_item[operation_key]
    operation_pointer = pointer_join(path_pointer, operation_key)
    if not isinstance(operation, dict):
        raise LinkPlanningError(
            _sorted_errors(
                [
                    {
                        "code": "invalid_link",
                        "pointer": operation_pointer,
                        "error": "operation must be an object",
                    }
                ]
            )
        )

    # --- Response selection ------------------------------------------------
    responses = operation.get("responses")
    responses_pointer = pointer_join(operation_pointer, "responses")
    if not isinstance(responses, dict):
        raise LinkPlanningError(
            _sorted_errors(
                [
                    {
                        "code": "invalid_link",
                        "pointer": responses_pointer,
                        "error": "source operation must declare a 'responses' object",
                    }
                ]
            )
        )

    response_section = normalized_context.get("response") or {}
    if "statusCode" not in response_section:
        raise LinkPlanningError(
            _sorted_errors(
                [
                    {
                        "code": "missing_value",
                        "pointer": "/context/response/statusCode",
                        "error": (
                            "context.response.statusCode is required to select "
                            "the response that declares the link"
                        ),
                    }
                ]
            )
        )
    status_code = response_section["statusCode"]
    response_key, match_reason = _select_response_key(responses, status_code)
    if response_key is None:
        raise LinkPlanningError(
            _sorted_errors(
                [
                    {
                        "code": "invalid_link",
                        "pointer": responses_pointer,
                        "status_code": status_code,
                        "error": (
                            f"no response matches status code {status_code!r}: "
                            "expected the exact code, an 'nXX' wildcard key or "
                            "'default'"
                        ),
                    }
                ]
            )
        )

    response_ref_pointer = pointer_join(responses_pointer, response_key)
    response, response_provenance, _response_effective_pointer, response_error = (
        _resolve_object_member(
            doc,
            responses[response_key],
            response_ref_pointer,
            is31,
            kind="response",
        )
    )
    if response_error is not None:
        raise LinkPlanningError(_sorted_errors([response_error]))

    links_pointer = _member_pointer("links", response_ref_pointer, response_provenance)
    links = response.get("links")
    if links is not None and not isinstance(links, dict):
        raise LinkPlanningError(
            _sorted_errors(
                [
                    {
                        "code": "invalid_link",
                        "pointer": links_pointer,
                        "error": "'links' must be an object",
                    }
                ]
            )
        )
    if links is None or link_name not in links:
        available = sorted(links) if isinstance(links, dict) else []
        raise LinkPlanningError(
            _sorted_errors(
                [
                    {
                        "code": "invalid_link",
                        "pointer": links_pointer,
                        "link": link_name,
                        "error": (
                            f"response {response_key!r} does not declare a link "
                            f"named {link_name!r}"
                            + (f"; available links: {', '.join(available)}" if available else "")
                        ),
                    }
                ]
            )
        )

    link_ref_pointer = pointer_join(links_pointer, link_name)
    link, link_provenance, _link_effective_pointer, link_error = _resolve_object_member(
        doc, links[link_name], link_ref_pointer, is31, kind="link"
    )
    if link_error is not None:
        raise LinkPlanningError(_sorted_errors([link_error]))

    def lp(member: str) -> str:
        return _member_pointer(member, link_ref_pointer, link_provenance)

    # --- Target choice: exactly one of operationRef / operationId ----------
    has_ref = "operationRef" in link
    has_id = "operationId" in link
    if has_ref and has_id:
        errors.append(
            {
                "code": "invalid_link",
                "pointer": lp("operationRef"),
                "error": (
                    "a link must identify its target with exactly one of "
                    "'operationRef' or 'operationId', not both"
                ),
            }
        )
        target = None
    elif has_ref:
        target, target_error = _resolve_operation_ref(
            doc, link["operationRef"], link_ref_pointer, is31
        )
        if target_error is not None:
            errors.append(target_error)
    elif has_id:
        target, target_error = _resolve_operation_id(
            doc, link["operationId"], link_ref_pointer, is31
        )
        if target_error is not None:
            errors.append(target_error)
    else:
        errors.append(
            {
                "code": "invalid_link",
                "pointer": link_ref_pointer,
                "error": (
                    "a link must identify its target with exactly one of "
                    "'operationRef' or 'operationId'"
                ),
            }
        )
        target = None

    # --- Target parameters -------------------------------------------------
    parameters_by_name: Dict[str, List[Parameter]] = {}
    effective_parameters: List[Parameter] = []
    if target is not None:
        effective_parameters, param_errors = _collect_target_parameters(
            doc,
            target["path_item"],
            target["operation"],
            target["path_item_pointer"],
            target["pointer"],
            is31,
        )
        errors.extend(param_errors)
        for parameter in effective_parameters:
            parameters_by_name.setdefault(parameter.name, []).append(parameter)

    ambiguous_names = {
        name for name, params in parameters_by_name.items() if len(params) > 1
    }

    mappings = link.get("parameters")
    mappings_pointer = lp("parameters")
    if mappings is not None and not isinstance(mappings, dict):
        errors.append(
            {
                "code": "invalid_link",
                "pointer": mappings_pointer,
                "error": "link 'parameters' must be an object",
            }
        )
        mappings = None

    assigned: Dict[str, Parameter] = {}
    grouped: Dict[str, Dict[str, Dict[str, Any]]] = {
        group: {} for group in GROUPS
    }
    reported_ambiguous: set = set()

    if mappings is not None and target is not None:
        for key, raw_value in mappings.items():
            value_pointer = pointer_join(mappings_pointer, key)
            if not isinstance(key, str) or not key:
                errors.append(
                    {
                        "code": "invalid_link",
                        "pointer": value_pointer,
                        "error": "parameter mapping keys must be non-empty target parameter names",
                    }
                )
                continue
            if key in ambiguous_names:
                locations = ", ".join(
                    sorted(param.location for param in parameters_by_name[key])
                )
                errors.append(
                    {
                        "code": "ambiguous_parameter",
                        "pointer": value_pointer,
                        "name": key,
                        "error": (
                            f"parameter name {key!r} is declared in multiple "
                            f"locations ({locations}); qualify the target "
                            "operation so the name is unique"
                        ),
                    }
                )
                reported_ambiguous.add(key)
                continue
            candidates = parameters_by_name.get(key)
            if not candidates:
                errors.append(
                    {
                        "code": "unknown_parameter",
                        "pointer": value_pointer,
                        "name": key,
                        "error": (
                            f"target operation declares no parameter named "
                            f"{key!r}"
                        ),
                    }
                )
                continue

            is_expression, value, value_error = _resolve_mapping_value(
                raw_value, value_pointer, normalized_context
            )
            if value_error is not None:
                errors.append(value_error)
                continue

            parameter = candidates[0]
            assigned[key] = parameter
            grouped[parameter.location][key] = {
                "value": copy.deepcopy(value),
                "expression": raw_value if is_expression else None,
                "value_pointer": value_pointer,
                "parameter_pointer": parameter.pointer,
            }

    # --- Request body ------------------------------------------------------
    request_body: Any = None
    body_pointer: Optional[str] = None
    body_expression: Optional[str] = None
    if "requestBody" in link:
        body_pointer = lp("requestBody")
        is_expression, body_value, body_error = _resolve_mapping_value(
            link["requestBody"], body_pointer, normalized_context
        )
        if body_error is not None:
            errors.append(body_error)
        else:
            request_body = copy.deepcopy(body_value)
            body_expression = link["requestBody"] if is_expression else None

    # --- Required parameter coverage --------------------------------------
    for parameter in effective_parameters:
        if parameter.name in ambiguous_names:
            continue
        if parameter.required and parameter.name not in assigned:
            errors.append(
                {
                    "code": "missing_required_parameter",
                    "pointer": parameter.pointer,
                    "in": parameter.location,
                    "name": parameter.name,
                    "error": (
                        f"required {parameter.location} parameter "
                        f"{parameter.name!r} is not assigned by the link "
                        "'parameters' map"
                    ),
                }
            )

    # A required parameter whose name spans several locations can never be
    # the target of a name-only mapping; report each such name once.
    for name in sorted(ambiguous_names):
        if (
            name in assigned
            or name in reported_ambiguous
            or not any(param.required for param in parameters_by_name[name])
        ):
            continue
        locations = ", ".join(
            sorted(param.location for param in parameters_by_name[name])
        )
        definition_pointer = next(
            param.pointer
            for param in parameters_by_name[name]
            if param.required
        )
        errors.append(
            {
                "code": "ambiguous_parameter",
                "pointer": definition_pointer,
                "name": name,
                "error": (
                    f"required parameter {name!r} is declared in multiple "
                    f"locations ({locations}); a name-only link mapping "
                    "cannot address it unambiguously"
                ),
            }
        )

    if errors:
        raise LinkPlanningError(_sorted_errors(errors))

    parameter_values = {
        group: [
            {
                "name": name,
                "value": grouped[group][name]["value"],
                "expression": grouped[group][name]["expression"],
                "value_pointer": grouped[group][name]["value_pointer"],
                "parameter_pointer": grouped[group][name]["parameter_pointer"],
            }
            for name in grouped[group]
        ]
        for group in GROUPS
    }

    return {
        "source": {
            "selector": f"{method.upper()} {path}",
            "operation_pointer": operation_pointer,
            "link_name": link_name,
            "link_pointer": link_ref_pointer,
        },
        "response": {
            "status_code": status_code,
            "key": response_key,
            "match": match_reason,
            "pointer": response_ref_pointer,
        },
        "target": {
            "selector": (
                f"{target['method'].upper()} {target['path']}"
                if target["path"] is not None
                else None
            ),
            "method": target["method"],
            "path": target["path"],
            "operation_pointer": target["pointer"],
            "operation_id": target["operation_id"],
            "operation_ref": target["operation_ref"],
        },
        "parameter_values": parameter_values,
        "request_body": {
            "provided": "requestBody" in link,
            "value": request_body,
            "expression": body_expression,
            "value_pointer": body_pointer,
        },
    }
