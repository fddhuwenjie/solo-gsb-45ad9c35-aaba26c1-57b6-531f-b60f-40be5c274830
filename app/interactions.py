"""Interaction graph of follow-up HTTP calls (``POST /interactions/graph``).

Given one OpenAPI 3.x document, walk every operation declared under
``paths`` and turn the contract relations that trigger a follow-up HTTP
call into a directed graph, meant for joint-debugging checklists:

* **Nodes** are operations. Every ``paths`` operation is a stable
  ``operation`` node keyed by its JSON Pointer; every operation declared
  inside a callback Path Item Object is a ``callback`` node keyed by the
  JSON Pointer of its *declaration* — a local ``$ref`` chain is followed
  to the terminal location, so a reusable components Path Item referenced
  from several places yields one shared node.
* **Link edges** come from Response Link Objects: every ``links`` entry
  of every declared response is resolved through its local
  ``operationRef`` fragment (``#/...`` ending in an HTTP method,
  including reusable ``components/pathItems`` Path Items) or its
  globally unique ``operationId``. The edge carries the link's source
  JSON Pointer, the response key and the target HTTP method.
* **Callback edges** come from the operation ``callbacks`` map: each
  Callback Object entry and each callback Path Item Object is resolved
  (local ``$ref`` chains, cycle-safe) and every HTTP method the Path
  Item declares produces one edge carrying the expression's source JSON
  Pointer, the callback URL template (the expression key) and the HTTP
  method.

OpenAPI 3.0 ignores ``$ref`` sibling fields; OpenAPI 3.1 merges them
with the nearest sibling winning. Dangling, external or circular
references, duplicate ``operationId`` values and link targets that
cannot be located uniquely are all collected and rejected together —
no partial graph is returned. Nodes and edges are sorted stably by JSON
Pointer, and when several declarations reach the same target each keeps
its own source edge. The input document is never modified.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .callbacks import (
    _build_effective,
    _follow_chain,
    _sorted_errors,
    pointer_join,
)
from .linkplanner import _member_pointer, _resolve_operation_ref
from .slicer import HTTP_METHODS


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class InteractionGraphError(Exception):
    """Base class for interaction graph failures."""


class InvalidDocumentError(InteractionGraphError):
    """The submitted document is not a recognizable OpenAPI 3.x doc (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class GraphBuildError(InteractionGraphError):
    """One or more semantic graph problems (HTTP 422); no partial graph."""

    def __init__(self, errors: List[Dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(
            "; ".join(f"{e['code']} @ {e.get('pointer', '')}" for e in errors)
        )


# --------------------------------------------------------------------------- #
# Document shape / shared resolution helpers
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
    """Resolve a ``paths`` item through its own local ``$ref`` chain."""
    if not isinstance(raw_item, dict):
        return None, {
            "code": "invalid_operation",
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


def _resolve_member(
    doc: Dict[str, Any],
    raw: Any,
    occurrence_pointer: str,
    is31: bool,
    *,
    code: str,
    message: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
    """Resolve an inline or ``$ref``'d object member, cycle-safe.

    Returns ``(effective, provenance, error)``. For an inline object the
    provenance is ``None``; for a referenced object it maps each member
    key to the JSON Pointer of the chain layer that declares it (OpenAPI
    3.1 sibling merging, 3.0 terminal-only).
    """
    if not isinstance(raw, dict):
        return None, None, {
            "code": code,
            "pointer": occurrence_pointer,
            "error": message,
        }
    if not isinstance(raw.get("$ref"), str):
        return raw, None, None
    layers, error = _follow_chain(doc, raw, occurrence_pointer)
    if error is not None:
        return None, None, error
    effective, provenance = _build_effective(layers, is31)
    return effective, provenance, None


def _node(
    node_id: str,
    kind: str,
    method: str,
    path: Optional[str],
    operation_id: Any,
) -> Dict[str, Any]:
    return {
        "id": node_id,
        "kind": kind,
        "method": method,
        "path": path,
        "operation_id": operation_id if isinstance(operation_id, str) else None,
    }


def _edge_sort_key(edge: Dict[str, Any]) -> Tuple[str, ...]:
    return (
        edge["pointer"],
        edge["kind"],
        edge["source"],
        edge["target"],
        edge["method"],
        edge["name"],
    )


# --------------------------------------------------------------------------- #
# Link edges
# --------------------------------------------------------------------------- #


def _resolve_link_target(
    doc: Dict[str, Any],
    link: Dict[str, Any],
    link_pointer: str,
    link_provenance: Optional[Dict[str, str]],
    operation_ids: Dict[str, List[str]],
    nodes: Dict[str, Dict[str, Any]],
    is31: bool,
) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    """Locate a link's target operation and register its node.

    Returns ``(node_id, method, error)``. The target is identified by
    exactly one of a local ``operationRef`` or a globally unique
    ``operationId``; target nodes reached through ``components`` Path
    Items are registered on demand with a ``null`` path.
    """
    has_ref = "operationRef" in link
    has_id = "operationId" in link
    if has_ref and has_id:
        return None, None, {
            "code": "invalid_link",
            "pointer": _member_pointer("operationRef", link_pointer, link_provenance),
            "error": (
                "a link must identify its target with exactly one of "
                "'operationRef' or 'operationId', not both"
            ),
        }
    if not has_ref and not has_id:
        return None, None, {
            "code": "invalid_link",
            "pointer": link_pointer,
            "error": (
                "a link must identify its target with exactly one of "
                "'operationRef' or 'operationId'"
            ),
        }

    if has_ref:
        target, error = _resolve_operation_ref(
            doc, link["operationRef"], link_pointer, is31
        )
        if error is not None:
            return None, None, error
        node_id = target["pointer"]
        if node_id not in nodes:
            nodes[node_id] = _node(
                node_id,
                "operation",
                target["method"],
                target["path"],
                target["operation"].get("operationId"),
            )
        return node_id, target["method"], None

    operation_id = link["operationId"]
    id_pointer = link_pointer + "/operationId"
    if not isinstance(operation_id, str) or not operation_id:
        return None, None, {
            "code": "invalid_link",
            "pointer": id_pointer,
            "error": "operationId must be a non-empty string",
        }
    matches = operation_ids.get(operation_id, [])
    if not matches:
        return None, None, {
            "code": "unknown_link_target",
            "pointer": id_pointer,
            "operation_id": operation_id,
            "error": (
                f"no operation declares operationId {operation_id!r}; the "
                "identifier must resolve to exactly one operation"
            ),
        }
    if len(matches) > 1:
        locations = ", ".join(sorted(matches))
        return None, None, {
            "code": "unknown_link_target",
            "pointer": id_pointer,
            "operation_id": operation_id,
            "error": (
                f"operationId {operation_id!r} is not globally unique; it "
                f"is declared by {len(matches)} operations ({locations})"
            ),
        }
    node_id = matches[0]
    return node_id, nodes[node_id]["method"], None


def _process_links(
    doc: Dict[str, Any],
    operation: Dict[str, Any],
    operation_pointer: str,
    source_id: str,
    operation_ids: Dict[str, List[str]],
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    errors: List[Dict[str, Any]],
    is31: bool,
) -> None:
    """Turn every response link of one operation into a directed edge."""
    responses = operation.get("responses")
    if responses is None:
        return
    responses_pointer = pointer_join(operation_pointer, "responses")
    if not isinstance(responses, dict):
        errors.append(
            {
                "code": "invalid_operation",
                "pointer": responses_pointer,
                "error": "'responses' must be an object",
            }
        )
        return

    for response_key, raw_response in responses.items():
        response_pointer = pointer_join(responses_pointer, response_key)
        response, response_provenance, error = _resolve_member(
            doc,
            raw_response,
            response_pointer,
            is31,
            code="invalid_link",
            message="response must be an object",
        )
        if error is not None:
            errors.append(error)
            continue

        links_pointer = _member_pointer("links", response_pointer, response_provenance)
        links = response.get("links")
        if links is None:
            continue
        if not isinstance(links, dict):
            errors.append(
                {
                    "code": "invalid_link",
                    "pointer": links_pointer,
                    "error": "'links' must be an object",
                }
            )
            continue

        for link_name, raw_link in links.items():
            link_pointer = pointer_join(links_pointer, link_name)
            link, link_provenance, error = _resolve_member(
                doc,
                raw_link,
                link_pointer,
                is31,
                code="invalid_link",
                message="link must be an object",
            )
            if error is not None:
                errors.append(error)
                continue
            target_id, target_method, error = _resolve_link_target(
                doc,
                link,
                link_pointer,
                link_provenance,
                operation_ids,
                nodes,
                is31,
            )
            if error is not None:
                errors.append(error)
                continue
            edges.append(
                {
                    "kind": "link",
                    "name": link_name,
                    "pointer": link_pointer,
                    "source": source_id,
                    "target": target_id,
                    "method": target_method,
                    "response_key": response_key,
                    "callback_url": None,
                }
            )


# --------------------------------------------------------------------------- #
# Callback edges
# --------------------------------------------------------------------------- #


def _process_callbacks(
    doc: Dict[str, Any],
    operation: Dict[str, Any],
    operation_pointer: str,
    source_id: str,
    nodes: Dict[str, Dict[str, Any]],
    edges: List[Dict[str, Any]],
    errors: List[Dict[str, Any]],
    is31: bool,
) -> None:
    """Turn every callback expression of one operation into edges."""
    callbacks = operation.get("callbacks")
    if callbacks is None:
        return
    callbacks_pointer = pointer_join(operation_pointer, "callbacks")
    if not isinstance(callbacks, dict):
        errors.append(
            {
                "code": "invalid_callback",
                "pointer": callbacks_pointer,
                "error": "'callbacks' must be an object",
            }
        )
        return

    for callback_name, callback_raw in callbacks.items():
        callback_pointer = pointer_join(callbacks_pointer, callback_name)
        callback_map, callback_provenance, error = _resolve_member(
            doc,
            callback_raw,
            callback_pointer,
            is31,
            code="invalid_callback",
            message="callback value must be a Callback Object",
        )
        if error is not None:
            errors.append(error)
            continue

        for expression_key, raw_path_item in callback_map.items():
            declaration_pointer = (
                callback_provenance[expression_key]
                if callback_provenance is not None
                else callback_pointer
            )
            expression_pointer = pointer_join(declaration_pointer, expression_key)
            path_item, item_provenance, error = _resolve_member(
                doc,
                raw_path_item,
                expression_pointer,
                is31,
                code="invalid_callback",
                message="callback expression value must be a Path Item Object",
            )
            if error is not None:
                errors.append(error)
                continue

            for key, callback_operation in path_item.items():
                if key.lower() not in HTTP_METHODS:
                    continue
                base_pointer = (
                    item_provenance[key]
                    if item_provenance is not None and key in item_provenance
                    else expression_pointer
                )
                node_pointer = pointer_join(base_pointer, key)
                if not isinstance(callback_operation, dict):
                    errors.append(
                        {
                            "code": "invalid_callback",
                            "pointer": node_pointer,
                            "error": "callback operation must be an object",
                        }
                    )
                    continue
                if node_pointer not in nodes:
                    nodes[node_pointer] = _node(
                        node_pointer,
                        "callback",
                        key.lower(),
                        None,
                        callback_operation.get("operationId"),
                    )
                edges.append(
                    {
                        "kind": "callback",
                        "name": callback_name,
                        "pointer": expression_pointer,
                        "source": source_id,
                        "target": node_pointer,
                        "method": key.lower(),
                        "response_key": None,
                        "callback_url": expression_key,
                    }
                )


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def build_interaction_graph(doc: Any) -> Dict[str, Any]:
    """Build the follow-up-call interaction graph for one document.

    Returns ``{"nodes": [...], "edges": [...]}``, both sorted stably by
    JSON Pointer.

    :raises InvalidDocumentError: *doc* is not OpenAPI 3.x (400).
    :raises GraphBuildError: semantic problems (422), each carrying
        source JSON Pointers; no partial graph is produced.
    """
    shape_errors = _validate_shape(doc)
    if shape_errors:
        raise InvalidDocumentError(shape_errors)

    is31 = str(doc.get("openapi", "")).startswith(("3.1", "3.2"))
    errors: List[Dict[str, Any]] = []
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    # Pass 1: contract operation nodes and the global operationId index.
    operations: List[Tuple[Dict[str, Any], str]] = []
    operation_ids: Dict[str, List[str]] = {}
    for path, raw_item in doc["paths"].items():
        path_pointer = pointer_join("/paths", path)
        path_item, item_error = _resolve_path_item(doc, raw_item, path_pointer, is31)
        if item_error is not None:
            errors.append(item_error)
            continue
        for key, operation in path_item.items():
            if key.lower() not in HTTP_METHODS:
                continue
            operation_pointer = pointer_join(path_pointer, key)
            if not isinstance(operation, dict):
                errors.append(
                    {
                        "code": "invalid_operation",
                        "pointer": operation_pointer,
                        "error": "operation must be an object",
                    }
                )
                continue
            nodes[operation_pointer] = _node(
                operation_pointer,
                "operation",
                key.lower(),
                path,
                operation.get("operationId"),
            )
            operations.append((operation, operation_pointer))
            operation_id = operation.get("operationId")
            if isinstance(operation_id, str) and operation_id:
                operation_ids.setdefault(operation_id, []).append(operation_pointer)

    # Duplicate operationIds poison every operationId-based lookup, so
    # they are reported even when no link references them.
    for operation_id in sorted(operation_ids):
        locations = sorted(operation_ids[operation_id])
        if len(locations) < 2:
            continue
        errors.append(
            {
                "code": "duplicate_operation_id",
                "pointer": locations[0],
                "operation_id": operation_id,
                "pointers": locations,
                "error": (
                    f"operationId {operation_id!r} is declared by "
                    f"{len(locations)} operations ({', '.join(locations)}); "
                    "operationIds must be globally unique"
                ),
            }
        )

    # Pass 2: edges, now that the operationId index is complete.
    for operation, operation_pointer in operations:
        _process_links(
            doc,
            operation,
            operation_pointer,
            operation_pointer,
            operation_ids,
            nodes,
            edges,
            errors,
            is31,
        )
        _process_callbacks(
            doc,
            operation,
            operation_pointer,
            operation_pointer,
            nodes,
            edges,
            errors,
            is31,
        )

    if errors:
        raise GraphBuildError(_sorted_errors(errors))

    return {
        "nodes": [nodes[node_id] for node_id in sorted(nodes)],
        "edges": sorted(edges, key=_edge_sort_key),
    }
