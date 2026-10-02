"""HTTP content negotiation for one OpenAPI operation (``POST /representations``).

Given an OpenAPI 3.x document, a ``METHOD /path`` operation selector, the
real request ``Content-Type`` / ``Accept`` header values and a response
status code, pick exactly one request representation (from
``requestBody.content``) and one response representation (from the
``responses`` member selected exact -> ``nXX`` -> ``default``) following
RFC 9110 content negotiation.

Media-type matching:

* the ``type`` / ``subtype`` slots match case-insensitively, the
  wildcard ``*`` matching everything in that slot;
* a media type can carry parameters (e.g. ``version=2``): every
  non-``q`` parameter required by a negotiable range must be present on
  the concrete type with the same value (parameter names are
  case-insensitive, values case-sensitive);
* request side: the request ``Content-Type`` is a concrete type (no
  wildcards), so the declared content map is searched for the most
  specific containing type (fewer wildcards wins, then more equal
  parameters, then declaration order) -- a concrete request may carry
  extra parameters a declaration does not restrict;
* response side: every declared representation is scored against the
  ``Accept`` header: the quality value comes from the **most specific**
  applicable range (exact type/subtype beats ``type/*`` beats ``*/*``,
  with matching parameters increasing specificity), and the
  representation with the highest ``q`` wins; ties are broken by
  declaration order. A missing ``Accept`` header means ``*/*;q=1``;
  ``q=0`` ranges are never selectable and an empty ``Accept`` header
  rejects everything.

``requestBody`` / Response Object local ``$ref`` chains are resolved
cycle-safe: OpenAPI 3.1 merges ``$ref`` sibling fields (nearest wins),
OpenAPI 3.0 ignores them. Media-type ``schema`` is returned verbatim
(references preserved); inline ``example`` and resolved
``examples.<name>`` entries are returned with their source JSON Pointer.
``externalValue`` and external / dangling / circular references on the
selected representations are rejected with HTTP 422. No match on the
request side is 415, no match on the response side is 406; no partial
result is ever returned and the input is never modified.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

from .callbacks import (
    _build_effective,
    pointer_join,
)
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


class NegotiationError(Exception):
    """Base class for representation negotiation failures."""


class InvalidDocumentError(NegotiationError):
    """The submitted document is not a recognizable OpenAPI 3.x doc (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class InvalidSelectorError(NegotiationError):
    """The selector is malformed or unknown (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class InvalidNegotiationRequestError(NegotiationError):
    """The request envelope (headers / status code) is malformed (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class UnsupportedRequestMediaTypeError(NegotiationError):
    """The request Content-Type matches no declared representation (415)."""

    def __init__(self, content_type: Optional[str], supported: List[str]) -> None:
        self.content_type = content_type
        self.supported = supported
        super().__init__(f"unsupported request media type {content_type!r}")


class NotAcceptableError(NegotiationError):
    """The Accept header matches no declared representation (406)."""

    def __init__(self, accept: Optional[str], available: List[str]) -> None:
        self.accept = accept
        self.available = available
        super().__init__(f"no response representation matches Accept {accept!r}")


class NegotiationContractError(NegotiationError):
    """A contract-level structure/reference problem on the selected path (422)."""

    def __init__(self, errors: List[Dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(
            "; ".join(f"{e['code']} @ {e.get('pointer', '')}" for e in errors)
        )


# --------------------------------------------------------------------------- #
# Media type parsing (RFC 9110 section 8.3 / 12.5.1)
# --------------------------------------------------------------------------- #


# Whitespace bytes (OWS); quoted-string / token follow RFC 9110 / RFC 9110.
def _is_token_char(char: str) -> bool:
    return char in (
        "!#$%&'*+-.^_`|~"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
    )


class MediaTypeParseError(ValueError):
    """A media type / Accept header value cannot be parsed."""


def _read_token(text: str, index: int) -> Tuple[str, int]:
    start = index
    while index < len(text) and _is_token_char(text[index]):
        index += 1
    if index == start:
        raise MediaTypeParseError("expected a token")
    return text[start:index], index


def _skip_ows(text: str, index: int) -> int:
    while index < len(text) and text[index] in " \t":
        index += 1
    return index


def _read_quoted_string(text: str, index: int) -> Tuple[str, int]:
    # Assumes text[index] == '"'.
    index += 1
    chars: List[str] = []
    while index < len(text):
        char = text[index]
        if char == '"':
            return "".join(chars), index + 1
        if char == "\\":
            index += 1
            if index >= len(text):
                raise MediaTypeParseError("unterminated quoted string")
            chars.append(text[index])
        elif ord(char) <= 0x1F or ord(char) == 0x7F:
            raise MediaTypeParseError("control character in quoted string")
        else:
            chars.append(char)
        index += 1
    raise MediaTypeParseError("unterminated quoted string")


def _read_parameter_value(text: str, index: int) -> Tuple[str, bool, int]:
    if index < len(text) and text[index] == '"':
        value, index = _read_quoted_string(text, index)
        return value, True, index
    value, index = _read_token(text, index)
    return value, False, index


def _parse_parameters(
    text: str, index: int
) -> Tuple[Dict[str, str], "set[str]", int]:
    """Parse ``; name=value`` pairs.

    Returns ``(parameters, quoted_names, new_index)``. Parameter names
    are lower-cased; *quoted_names* records parameters whose value was a
    quoted string (so a quoted ``q="0.5"`` is an extension parameter
    rather than the Accept weight, whose ABNF forbids quotes).
    Duplicate names are an error (ambiguous media type).
    """
    parameters: Dict[str, str] = {}
    quoted: set = set()
    while index < len(text):
        index = _skip_ows(text, index)
        if index >= len(text) or text[index] != ";":
            raise MediaTypeParseError("expected ';' before the next parameter")
        index += 1
        index = _skip_ows(text, index)
        name, index = _read_token(text, index)
        name = name.lower()
        index = _skip_ows(text, index)
        if index >= len(text) or text[index] != "=":
            raise MediaTypeParseError(f"parameter {name!r} is missing its value")
        index += 1
        index = _skip_ows(text, index)
        value, was_quoted, index = _read_parameter_value(text, index)
        if name in parameters:
            raise MediaTypeParseError(f"duplicate media-type parameter {name!r}")
        parameters[name] = value
        if was_quoted:
            quoted.add(name)
        index = _skip_ows(text, index)
    return parameters, quoted, index


def parse_media_type(text: str) -> Dict[str, Any]:
    """Parse one concrete media type (used for request Content-Type).

    Wildcards are rejected: an on-the-wire Content-Type must identify a
    concrete type. Returns ``{"type", "subtype", "parameters", "raw"}``.
    """
    if not isinstance(text, str) or not text:
        raise MediaTypeParseError("media type must be a non-empty string")
    index = 0
    try:
        type_, index = _read_token(text, index)
        if index >= len(text) or text[index] != "/":
            raise MediaTypeParseError("expected '/' after the type")
        index += 1
        subtype, index = _read_token(text, index)
        index = _skip_ows(text, index)
        parameters, _quoted, index = _parse_parameters(text, index)
        if index != len(text):
            raise MediaTypeParseError("unexpected trailing characters")
    except MediaTypeParseError as exc:
        raise MediaTypeParseError(f"invalid media type {text!r}: {exc}") from None

    type_l, subtype_l = type_.lower(), subtype.lower()
    if type_l == "*" or subtype_l == "*":
        raise MediaTypeParseError(
            f"invalid media type {text!r}: a Content-Type must be concrete "
            "(wildcards are only valid in Accept ranges)"
        )
    return {
        "type": type_l,
        "subtype": subtype_l,
        "parameters": parameters,
        "raw": text,
    }


def _parse_media_range(text: str) -> Dict[str, Any]:
    """Parse one Accept media range, including its ``q`` weight.

    Returns ``{"type", "subtype", "parameters", "q"}`` with ``q`` in
    ``0..1``. Quoted ``q`` (``q="0.5"``) is a regular extension
    parameter, not the weight.
    """
    index = 0
    try:
        type_, index = _read_token(text, index)
        if index >= len(text) or text[index] != "/":
            raise MediaTypeParseError("expected '/' after the type")
        index += 1
        subtype, index = _read_token(text, index)
        index = _skip_ows(text, index)
        parameters, quoted, index = _parse_parameters(text, index)
        if index != len(text):
            raise MediaTypeParseError("unexpected trailing characters")
    except MediaTypeParseError as exc:
        raise MediaTypeParseError(f"invalid Accept range {text!r}: {exc}") from None

    type_l, subtype_l = type_.lower(), subtype.lower()
    if type_l == "*" and subtype_l != "*":
        raise MediaTypeParseError(
            f"invalid Accept range {text!r}: '*' type requires '*' subtype"
        )

    qvalue = 1.0
    if "q" in parameters and "q" not in quoted:
        raw_q = parameters["q"]
        if not _is_valid_qvalue(raw_q):
            raise MediaTypeParseError(
                f"invalid Accept range {text!r}: q value {raw_q!r} must be a "
                "number between 0 and 1 with at most three decimal digits"
            )
        qvalue = float(raw_q)
        del parameters["q"]
    return {
        "type": type_l,
        "subtype": subtype_l,
        "parameters": parameters,
        "q": qvalue,
    }


def _is_valid_qvalue(raw: str) -> bool:
    if raw in ("0", "1"):
        return True
    if raw == "0." or raw == "1.":
        return False
    if raw.startswith("0.") and raw[2:].isdigit() and len(raw) - 2 <= 3:
        return True
    if raw.startswith("1.") and raw[2:].isdigit() and len(raw) - 2 <= 3:
        # RFC grammar allows 1.000 but not 1.001.
        return set(raw[2:]) <= {"0"}
    return False


def parse_accept(header: Optional[str]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse an Accept header into ordered media ranges.

    Returns ``(ranges, errors)``. A missing header yields the single
    wildcard range ``*/*;q=1``; an *empty* header is a deliberate
    rejection of every representation and therefore yields an empty
    range list (RFC 9110: an empty field value means "nothing is
    acceptable" for content negotiation purposes).
    """
    if header is None:
        return [
            {"type": "*", "subtype": "*", "parameters": {}, "q": 1.0}
        ], []
    if not isinstance(header, str):
        return [], ["accept must be a string when provided"]

    trimmed = header.strip(" \t")
    if trimmed == "":
        return [], []

    ranges: List[Dict[str, Any]] = []
    errors: List[str] = []
    for piece in _split_accept(trimmed):
        item = piece.strip(" \t")
        if item == "":
            errors.append(
                f"invalid Accept header {header!r}: empty media range between commas"
            )
            continue
        try:
            ranges.append(_parse_media_range(item))
        except MediaTypeParseError as exc:
            errors.append(str(exc))
    return ranges, errors


def _split_accept(text: str) -> List[str]:
    """Split an Accept header on top-level commas (respecting quotes)."""
    parts: List[str] = []
    start = 0
    quoted = False
    for index, char in enumerate(text):
        if quoted:
            if char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == ",":
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def canonical_media_type(
    type_: str, subtype: str, parameters: Dict[str, str]
) -> str:
    """Render a media type with lower-cased type/subtype and sorted params."""
    base = f"{type_.lower()}/{subtype.lower()}"
    suffix = "".join(
        f"; {name}={_render_param_value(parameters[name])}"
        for name in sorted(parameters)
    )
    return base + suffix


def _render_param_value(value: str) -> str:
    """Quote a parameter value only when it is not a bare token."""
    if all(_is_token_char(char) for char in value) and value != "":
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


# --------------------------------------------------------------------------- #
# Matching and selection
# --------------------------------------------------------------------------- #


def _types_match(range_type: str, range_subtype: str, concrete: Dict[str, Any]) -> bool:
    if range_type != "*" and range_type != concrete["type"]:
        return False
    if range_subtype != "*" and range_subtype != concrete["subtype"]:
        return False
    return True


def _range_parameters_satisfied(
    range_parameters: Dict[str, str], concrete_parameters: Dict[str, str]
) -> bool:
    """Every parameter required by the range must be present with equal value.

    Parameter names are case-insensitive (already lower-cased by the
    parser); values are case-sensitive. The concrete type may carry
    additional parameters the range does not mention.
    """
    for name, value in range_parameters.items():
        if concrete_parameters.get(name) != value:
            return False
    return True


def _specificity(range_: Dict[str, Any], concrete: Dict[str, Any]) -> Tuple[int, int]:
    """Most-specific-match key for two applicable ranges.

    RFC 9110: the most specific range assigns the quality value.
    Specificity rises with the number of non-wildcard type slots and the
    number of parameters that matched the concrete type.
    """
    type_slots = (range_["type"] != "*") + (range_["subtype"] != "*")
    matched_params = sum(
        1
        for name in range_["parameters"]
        if name in concrete["parameters"]
        and concrete["parameters"][name] == range_["parameters"][name]
    )
    return type_slots, matched_params


def select_request_media_type(
    content: Dict[str, Any], requested: Dict[str, Any]
) -> Optional[str]:
    """Pick one declared request media-type key for a concrete Content-Type.

    Containment rule: every parameter declared on the contract media
    type must be present on the request type with the same value; the
    request type may carry extra parameters. Among all matches the most
    specific wins (fewer wildcards, more equal parameters); remaining
    ties follow declaration order.
    """
    best_key: Optional[str] = None
    best_score: Optional[Tuple[int, int]] = None
    for key in content:
        try:
            declared = _parse_declared_media_type(key)
        except MediaTypeParseError:
            continue
        if not _types_match(declared["type"], declared["subtype"], requested):
            continue
        if not _range_parameters_satisfied(
            declared["parameters"], requested["parameters"]
        ):
            continue
        type_slots = (declared["type"] != "*") + (
            declared["subtype"] != "*"
        )
        equal_params = sum(
            1
            for name, value in declared["parameters"].items()
            if requested["parameters"].get(name) == value
        )
        score = (type_slots, equal_params)
        if best_score is None or score > best_score:
            best_score = score
            best_key = key
    return best_key


def _parse_declared_media_type(key: Any) -> Dict[str, Any]:
    """Parse a contract content-map key (may legitimately be ``*/*``)."""
    if not isinstance(key, str) or not key:
        raise MediaTypeParseError("media type must be a non-empty string")
    index = 0
    try:
        type_, index = _read_token(key, index)
        if index >= len(key) or key[index] != "/":
            raise MediaTypeParseError("expected '/' after the type")
        index += 1
        subtype, index = _read_token(key, index)
        index = _skip_ows(key, index)
        parameters, _quoted, index = _parse_parameters(key, index)
        if index != len(key):
            raise MediaTypeParseError("unexpected trailing characters")
    except MediaTypeParseError as exc:
        raise MediaTypeParseError(f"invalid media type {key!r}: {exc}") from None
    type_l, subtype_l = type_.lower(), subtype.lower()
    if type_l == "*" and subtype_l != "*":
        raise MediaTypeParseError(
            f"invalid media type {key!r}: '*' type requires '*' subtype"
        )
    return {"type": type_l, "subtype": subtype_l, "parameters": parameters}


def quality_for(
    concrete: Dict[str, Any], ranges: List[Dict[str, Any]]
) -> Optional[float]:
    """Return the quality assigned to *concrete* by parsed Accept *ranges*.

    The most specific applicable range decides (RFC 9110 12.5.2); when
    several ranges are equally specific the first declared one wins.
    Returns ``None`` when no range applies (treated like ``q=0``).
    """
    best_q: Optional[float] = None
    best_spec: Optional[Tuple[int, int]] = None
    for range_ in ranges:
        if not _types_match(range_["type"], range_["subtype"], concrete):
            continue
        if not _range_parameters_satisfied(
            range_["parameters"], concrete["parameters"]
        ):
            continue
        spec = _specificity(range_, concrete)
        if best_spec is None or spec > best_spec:
            best_spec = spec
            best_q = range_["q"]
    return best_q


def select_response_media_type(
    content: Dict[str, Any], ranges: List[Dict[str, Any]]
) -> Optional[str]:
    """Pick one declared response media-type key for parsed Accept ranges.

    Each declared representation is scored with :func:`quality_for`;
    the highest ``q > 0`` wins, ties broken by declaration order.
    """
    if not ranges:
        return None
    best_key: Optional[str] = None
    best_q = 0.0
    for key in content:
        try:
            declared = _parse_declared_media_type(key)
        except MediaTypeParseError:
            continue
        qvalue = quality_for(declared, ranges)
        if qvalue is None or qvalue <= 0.0:
            continue
        if best_key is None or qvalue > best_q:
            best_q = qvalue
            best_key = key
    return best_key


# --------------------------------------------------------------------------- #
# Response-key selection (exact -> nXX -> default)
# --------------------------------------------------------------------------- #


def normalize_status_code(raw: Any) -> Tuple[Optional[int], Optional[str]]:
    """Validate the requested response status code.

    Accepts an integer (100..599) or a digit string of the same range.
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        return None, "status_code must be an integer (100..599) or a digit string"
    text = str(raw)
    if not text.isdigit():
        return None, f"status_code {raw!r} must consist of digits only"
    code = int(text)
    if not 100 <= code <= 599:
        return None, f"status_code {code} must be between 100 and 599"
    return code, None


def select_response_key(
    responses: Dict[str, Any], code: int
) -> Tuple[Optional[str], Optional[str]]:
    """Pick the response key: exact, class wildcard ``nXX``, then default."""
    text = str(code)
    if text in responses:
        return text, "exact"
    wanted = text[0] + "XX"
    for key in responses:
        if isinstance(key, str) and key.lower() == wanted.lower():
            return key, "wildcard"
    if "default" in responses:
        return "default", "default"
    return None, None


# --------------------------------------------------------------------------- #
# Object resolution (requestBody / Response with 3.0/3.1 $ref semantics)
# --------------------------------------------------------------------------- #


def _contract_error(
    code: str, pointer: str, error: str, **extra: Any
) -> Dict[str, Any]:
    item: Dict[str, Any] = {"code": code, "pointer": pointer, "error": error}
    item.update(extra)
    return item


def _follow_object_chain(
    doc: Dict[str, Any], node: Any, node_pointer: str
) -> Tuple[Optional[List[Tuple[Dict[str, Any], str]]], Optional[Dict[str, Any]]]:
    """Follow the local ``$ref`` chain of a requestBody / Response / Example.

    Mirrors :func:`app.callbacks._follow_chain` but reports contract-layer
    error codes for this endpoint. Returns ``(layers, error)``; each layer
    is ``(node, pointer)`` from the occurrence through the terminal
    non-reference object.
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
            return None, _contract_error(
                "unresolvable_reference",
                current_pointer,
                f"unsupported non-local reference '{ref}': only document-local "
                "references of the form '#/...' are supported",
                ref=ref,
            )
        target_pointer = parse_local_ref(ref)
        if target_pointer == "":
            return None, _contract_error(
                "unresolvable_reference",
                current_pointer,
                f"reference '{ref}' targets the document root; requestBody / "
                "response references must point to a specific object",
                ref=ref,
            )
        if target_pointer in seen:
            loop_start = seen[target_pointer]
            loop = refs[loop_start:] + [ref]
            return None, _contract_error(
                "unresolvable_reference",
                current_pointer,
                "circular reference detected: " + " -> ".join(loop),
                ref=ref,
            )
        if len(refs) >= MAX_REF_CHAIN:
            return None, _contract_error(
                "unresolvable_reference",
                current_pointer,
                f"reference chain exceeds the maximum depth of "
                f"{MAX_REF_CHAIN} links (last reference: {ref})",
                ref=ref,
            )
        seen[target_pointer] = len(refs)
        refs.append(ref)
        try:
            target = resolver.pointer(target_pointer)
        except UnresolvableReferenceError as exc:
            return None, _contract_error(
                "unresolvable_reference",
                current_pointer,
                str(exc),
                ref=ref,
            )
        if not isinstance(target, dict):
            return None, _contract_error(
                "unresolvable_reference",
                current_pointer,
                f"reference '{ref}' does not target an object",
                ref=ref,
            )
        layers.append((current, current_pointer))
        current = target
        current_pointer = target_pointer

    if not isinstance(current, dict):
        return None, _contract_error(
            "invalid_operation", current_pointer, "referenced node must be an object"
        )

    layers.append((current, current_pointer))
    return layers, None


def _resolve_referenced_object(
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
    """Resolve an inline or ``$ref``'d requestBody / Response object."""
    if not isinstance(raw, dict):
        return None, None, None, _contract_error(
            "invalid_operation",
            occurrence_pointer,
            f"{kind} must be an object",
        )
    if not isinstance(raw.get("$ref"), str):
        return raw, None, occurrence_pointer, None

    layers, error = _follow_object_chain(doc, raw, occurrence_pointer)
    if error is not None:
        return None, None, None, error
    effective, provenance = _build_effective(layers, is31)
    terminal_pointer = layers[-1][1]
    return effective, provenance, terminal_pointer, None


def _member_pointer(
    key: str, base_pointer: str, provenance: Optional[Dict[str, str]]
) -> str:
    if provenance is None or key not in provenance:
        return pointer_join(base_pointer, key)
    return pointer_join(provenance[key], key)


# --------------------------------------------------------------------------- #
# Representation detail extraction
# --------------------------------------------------------------------------- #


def _extract_representation(
    doc: Dict[str, Any],
    content: Dict[str, Any],
    media_key: str,
    content_pointer: str,
    is31: bool,
    errors: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Build the representation result for the selected media type."""
    media_pointer = pointer_join(content_pointer, media_key)
    media_node = content[media_key]
    if not isinstance(media_node, dict):
        errors.append(
            _contract_error(
                "invalid_operation",
                media_pointer,
                f"media type object for {media_key!r} must be an object",
            )
        )
        return None

    try:
        parsed = _parse_declared_media_type(media_key)
        media_type = canonical_media_type(
            parsed["type"], parsed["subtype"], parsed["parameters"]
        )
    except MediaTypeParseError as exc:
        errors.append(
            _contract_error(
                "invalid_media_type", media_pointer, str(exc)
            )
        )
        return None

    representation: Dict[str, Any] = {
        "media_type": media_type,
        "media_type_pointer": media_pointer,
        "schema": None,
        "schema_pointer": None,
        "example": None,
        "example_pointer": None,
        "examples": [],
    }

    if "schema" in media_node:
        schema_node = media_node["schema"]
        representation["schema"] = copy.deepcopy(schema_node)
        representation["schema_pointer"] = media_pointer + "/schema"

    if "example" in media_node:
        representation["example"] = copy.deepcopy(media_node["example"])
        representation["example_pointer"] = media_pointer + "/example"

    examples = media_node.get("examples")
    if examples is not None:
        if not isinstance(examples, dict):
            errors.append(
                _contract_error(
                    "invalid_operation",
                    media_pointer + "/examples",
                    "'examples' must be an object",
                )
            )
        else:
            examples_pointer = media_pointer + "/examples"
            for name in examples:
                entry_pointer = pointer_join(examples_pointer, name)
                entry, provenance, _terminal, ref_error = (
                    _resolve_referenced_object(
                        doc,
                        examples[name],
                        entry_pointer,
                        is31,
                        kind="example",
                    )
                )
                if ref_error is not None:
                    errors.append(ref_error)
                    continue
                if not isinstance(entry, dict):
                    errors.append(
                        _contract_error(
                            "invalid_example",
                            entry_pointer,
                            "examples map entry must resolve to an Example Object",
                        )
                    )
                    continue
                if isinstance(entry.get("externalValue"), str):
                    errors.append(
                        _contract_error(
                            "unsupported_reference",
                            _member_pointer(
                                "externalValue", entry_pointer, provenance
                            ),
                            f"externalValue {entry['externalValue']!r} cannot be "
                            "fetched; examples must be embedded or use a local "
                            "$ref",
                            ref=entry["externalValue"],
                        )
                    )
                    continue
                value_pointer: Optional[str] = None
                value = None
                if "value" in entry:
                    value_pointer = _member_pointer(
                        "value", entry_pointer, provenance
                    )
                    value = copy.deepcopy(entry["value"])
                representation["examples"].append(
                    {
                        "name": name,
                        "pointer": entry_pointer,
                        "value": value,
                        "value_pointer": value_pointer,
                        "summary": entry.get("summary"),
                        "description": entry.get("description"),
                    }
                )

    # Stable output for named examples regardless of input key order.
    representation["examples"].sort(key=lambda item: item["name"])
    return representation


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def negotiate_representations(
    doc: Any,
    selector: Any,
    request_content_type: Any,
    accept: Any,
    status_code: Any,
) -> Dict[str, Any]:
    """Select exactly one request and one response representation.

    :raises InvalidDocumentError: *doc* is not OpenAPI 3.x (400).
    :raises InvalidSelectorError: the selector is malformed/unknown (400).
    :raises InvalidNegotiationRequestError: header/status envelope bad (400).
    :raises NegotiationContractError: selected-path contract problems (422).
    :raises UnsupportedRequestMediaTypeError: 415.
    :raises NotAcceptableError: 406.
    """
    # --- Document shape ----------------------------------------------------
    if not isinstance(doc, dict):
        raise InvalidDocumentError(["document must be a JSON object"])
    shape_messages: List[str] = []
    version = doc.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        shape_messages.append(
            "document.openapi must be a version string starting with '3.' "
            f"(OpenAPI 3.x), got {version!r}"
        )
    if not isinstance(doc.get("paths"), dict):
        shape_messages.append("document.paths must be an object")
    if shape_messages:
        raise InvalidDocumentError(shape_messages)

    parsed_selector = parse_selector(selector)
    if parsed_selector is None:
        raise InvalidSelectorError(
            [
                f"malformed selector {selector!r}: expected 'METHOD /path' "
                "(e.g. 'POST /pets')"
            ]
        )
    method, path = parsed_selector
    if path not in doc["paths"]:
        raise InvalidSelectorError([f"{method.upper()} {path}: path is not declared"])

    # --- Envelope validation (400) ----------------------------------------
    envelope_messages: List[str] = []
    code, code_error = normalize_status_code(status_code)
    if code_error is not None:
        envelope_messages.append(code_error)

    if request_content_type is not None and not isinstance(
        request_content_type, str
    ):
        envelope_messages.append("request_content_type must be a string when provided")
    if accept is not None and not isinstance(accept, str):
        envelope_messages.append("accept must be a string when provided")

    requested_media: Optional[Dict[str, Any]] = None
    if isinstance(request_content_type, str):
        try:
            requested_media = parse_media_type(request_content_type)
        except MediaTypeParseError as exc:
            envelope_messages.append(str(exc))

    # Missing Accept means the client accepts everything ('*/*;q=1').
    accept_ranges: List[Dict[str, Any]] = [
        {"type": "*", "subtype": "*", "parameters": {}, "q": 1.0}
    ]
    if isinstance(accept, str):
        accept_ranges, accept_errors = parse_accept(accept)
        envelope_messages.extend(accept_errors)

    if envelope_messages:
        raise InvalidNegotiationRequestError(envelope_messages)
    assert code is not None  # validated above

    is31 = str(version).startswith(("3.1", "3.2"))
    errors: List[Dict[str, Any]] = []

    # --- Locate the operation (path-level $ref included) -------------------
    path_pointer = pointer_join("/paths", path)
    path_item, _item_pointer, item_error = _resolve_path_item(
        doc, doc["paths"][path], path_pointer, is31
    )
    if item_error is not None:
        raise NegotiationContractError(_sorted_errors([item_error]))
    if not isinstance(path_item, dict):
        raise NegotiationContractError(
            _sorted_errors(
                [_contract_error("invalid_operation", path_pointer, "path item must be an object")]
            )
        )

    method_keys = {
        key.lower(): key for key in path_item if key.lower() in HTTP_METHODS
    }
    if method not in method_keys:
        raise InvalidSelectorError(
            [f"{method.upper()} {path}: operation is not declared"]
        )
    operation_key = method_keys[method]
    operation = path_item[operation_key]
    operation_pointer = pointer_join(path_pointer, operation_key)
    if not isinstance(operation, dict):
        raise NegotiationContractError(
            _sorted_errors(
                [
                    _contract_error(
                        "invalid_operation",
                        operation_pointer,
                        "operation must be an object",
                    )
                ]
            )
        )

    # --- Request body resolution ------------------------------------------
    request_result: Optional[Dict[str, Any]] = None
    request_content: Optional[Dict[str, Any]] = None
    request_content_pointer: Optional[str] = None
    request_required = False

    raw_body = operation.get("requestBody")
    if raw_body is not None:
        body_pointer = pointer_join(operation_pointer, "requestBody")
        request_body, body_provenance, _body_terminal, body_error = (
            _resolve_referenced_object(
                doc, raw_body, body_pointer, is31, kind="requestBody"
            )
        )
        if body_error is not None:
            errors.append(body_error)
        else:
            content_member_pointer = _member_pointer(
                "content", body_pointer, body_provenance
            )
            request_required = bool(request_body.get("required"))
            body_content = request_body.get("content")
            if "content" not in request_body:
                errors.append(
                    _contract_error(
                        "invalid_operation",
                        content_member_pointer,
                        "requestBody must declare a 'content' object",
                    )
                )
            elif not isinstance(body_content, dict):
                errors.append(
                    _contract_error(
                        "invalid_operation",
                        content_member_pointer,
                        "requestBody 'content' must be an object",
                    )
                )
            else:
                request_content = body_content
                request_content_pointer = content_member_pointer
                for key, node in body_content.items():
                    if not isinstance(key, str):
                        errors.append(
                            _contract_error(
                                "invalid_media_type",
                                content_member_pointer,
                                "requestBody content keys must be media type strings",
                            )
                        )
                    elif not isinstance(node, dict):
                        errors.append(
                            _contract_error(
                                "invalid_operation",
                                pointer_join(content_member_pointer, key),
                                f"media type object for {key!r} must be an object",
                            )
                        )
                    else:
                        try:
                            _parse_declared_media_type(key)
                        except MediaTypeParseError as exc:
                            errors.append(
                                _contract_error(
                                    "invalid_media_type",
                                    pointer_join(content_member_pointer, key),
                                    str(exc),
                                )
                            )

    # --- Response resolution -----------------------------------------------
    responses_pointer = pointer_join(operation_pointer, "responses")
    responses = operation.get("responses")
    response_content: Optional[Dict[str, Any]] = None
    response_content_pointer: Optional[str] = None
    response_key: Optional[str] = None
    response_match: Optional[str] = None

    if not isinstance(responses, dict) or not responses:
        errors.append(
            _contract_error(
                "invalid_operation",
                responses_pointer,
                "operation must declare a non-empty 'responses' object",
            )
        )
    else:
        response_key, response_match = select_response_key(responses, code)
        if response_key is None:
            errors.append(
                _contract_error(
                    "response_not_declared",
                    responses_pointer,
                    f"no response matches status code {code}: expected the "
                    "exact code, an 'nXX' wildcard key or 'default'",
                    status_code=code,
                )
            )
        else:
            response_ref_pointer = pointer_join(responses_pointer, response_key)
            response, response_provenance, _terminal_pointer, resp_error = (
                _resolve_referenced_object(
                    doc,
                    responses[response_key],
                    response_ref_pointer,
                    is31,
                    kind="response",
                )
            )
            if resp_error is not None:
                errors.append(resp_error)
            else:
                response_content = response.get("content")
                if response_content is not None and not isinstance(
                    response_content, dict
                ):
                    errors.append(
                        _contract_error(
                            "invalid_operation",
                            _member_pointer(
                                "content", response_ref_pointer, response_provenance
                            ),
                            "response 'content' must be an object",
                        )
                    )
                    response_content = None
                elif isinstance(response_content, dict):
                    response_content_pointer = _member_pointer(
                        "content", response_ref_pointer, response_provenance
                    )
                    for key, node in response_content.items():
                        if not isinstance(key, str):
                            errors.append(
                                _contract_error(
                                    "invalid_media_type",
                                    response_content_pointer,
                                    "response content keys must be media type strings",
                                )
                            )
                        elif not isinstance(node, dict):
                            errors.append(
                                _contract_error(
                                    "invalid_operation",
                                    pointer_join(response_content_pointer, key),
                                    f"media type object for {key!r} must be an object",
                                )
                            )
                        else:
                            try:
                                _parse_declared_media_type(key)
                            except MediaTypeParseError as exc:
                                errors.append(
                                    _contract_error(
                                        "invalid_media_type",
                                        pointer_join(response_content_pointer, key),
                                        str(exc),
                                    )
                                )

    if errors:
        raise NegotiationContractError(_sorted_errors(errors))

    # --- Request representation negotiation --------------------------------
    if request_content is not None:
        supported = list(request_content)
        if requested_media is None:
            if request_required:
                raise UnsupportedRequestMediaTypeError(None, supported)
            # Optional body, no Content-Type sent: no request representation.
            request_result = None
        else:
            chosen_key = select_request_media_type(request_content, requested_media)
            if chosen_key is None:
                raise UnsupportedRequestMediaTypeError(
                    request_content_type, supported
                )
            req_errors: List[Dict[str, Any]] = []
            request_rep = _extract_representation(
                doc,
                request_content,
                chosen_key,
                request_content_pointer,
                is31,
                req_errors,
            )
            if request_rep is None or req_errors:
                raise NegotiationContractError(_sorted_errors(req_errors))
            request_result = {
                "present": True,
                "required": request_required,
                "content_type": canonical_media_type(
                    requested_media["type"],
                    requested_media["subtype"],
                    requested_media["parameters"],
                ),
                "declared_media_type": chosen_key,
                **request_rep,
            }
    else:
        # No requestBody declared: a Content-Type on a bodiless operation is
        # simply ignored (nothing for the server to parse).
        request_result = None

    # --- Response representation negotiation -------------------------------
    response_result: Dict[str, Any]
    if response_content is not None:
        available = list(response_content)
        chosen_key = select_response_media_type(response_content, accept_ranges)
        if chosen_key is None:
            # Missing Accept header yields the implicit */* range, so this
            # branch is reached only when nothing matches (or Accept was an
            # explicit empty / q=0 rejection).
            raise NotAcceptableError(accept, available)
        rep_errors: List[Dict[str, Any]] = []
        response_rep = _extract_representation(
            doc,
            response_content,
            chosen_key,
            response_content_pointer,
            is31,
            rep_errors,
        )
        if response_rep is None or rep_errors:
            raise NegotiationContractError(_sorted_errors(rep_errors))
        response_result = {
            "present": True,
            "status_code": code,
            "key": response_key,
            "match": response_match,
            "response_pointer": pointer_join(responses_pointer, response_key),
            "declared_media_type": chosen_key,
            **response_rep,
        }
    else:
        # Bodyless response (e.g. 204): no content to negotiate.
        response_result = {
            "present": False,
            "status_code": code,
            "key": response_key,
            "match": response_match,
            "response_pointer": pointer_join(responses_pointer, response_key),
            "media_type": None,
            "media_type_pointer": None,
            "schema": None,
            "schema_pointer": None,
            "example": None,
            "example_pointer": None,
            "examples": [],
        }

    return {
        "operation_pointer": operation_pointer,
        "request": request_result,
        "response": response_result,
    }


def _resolve_path_item(
    doc: Dict[str, Any], raw_item: Any, item_pointer: str, is31: bool
) -> Tuple[Optional[Dict[str, Any]], Optional[str], Optional[Dict[str, Any]]]:
    """Resolve a Path Item Object through its own local ``$ref`` chain."""
    if not isinstance(raw_item, dict):
        return None, None, _contract_error(
            "invalid_operation", item_pointer, "path item must be an object"
        )
    if not isinstance(raw_item.get("$ref"), str):
        return raw_item, item_pointer, None
    layers, error = _follow_object_chain(doc, raw_item, item_pointer)
    if error is not None:
        return None, None, error
    effective, _provenance = _build_effective(layers, is31)
    return effective, item_pointer, None


def _sorted_errors(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stable, order-independent ordering of collected contract errors."""
    return sorted(
        errors,
        key=lambda error: (
            str(error.get("code", "")),
            str(error.get("pointer", "")),
            str(error.get("ref", "")),
            str(error.get("error", "")),
        ),
    )
