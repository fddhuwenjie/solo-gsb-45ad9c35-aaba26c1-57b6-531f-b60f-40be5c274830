"""HTTP-driven OpenAPI representation selection (``POST /representations/select``).

Given an OpenAPI 3.x document, one ``METHOD /path`` operation selector and
the *real* HTTP headers of a joint-debugging call (the request
``Content-Type``, the request ``Accept`` list and the concrete response
status code), select the unique request and response representations:

* the response key is resolved in OpenAPI order -- exact status code, then
  the class wildcard ``nXX`` (case-insensitive), then ``default``;
* a request ``Content-Type`` matches a declared media type when its media
  range is covered and **every declared media-type parameter is present on
  the wire with an equal value** (the wire value may carry extra
  parameters; ``charset`` values compare case-insensitively);
* response negotiation honors RFC 7231: the most specific matching Accept
  media range supplies the weight (``q``), wildcard ranges lose to
  concrete ones, ``q=0`` excludes a representation, and ties are decided
  by contract declaration order (the result never depends on JSON key
  order beyond the declared order);
* local ``$ref`` chains on request bodies / responses (and their schema
  and Example Object members) are resolved cycle-safe; OpenAPI 3.0 ignores
  ``$ref`` siblings while 3.1 merges them nearest-first.

A request ``Content-Type`` that matches nothing is rejected with HTTP
**415**; an ``Accept`` list that matches nothing is rejected with
**406**. Contract problems (dangling / external / circular references,
malformed containers, an undeclared status code) are rejected with
**422**. No partial result is ever returned and the input objects are
never modified.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .callbacks import _build_effective, _follow_chain, pointer_join
from .linkplanner import _member_pointer, _resolve_object_member, _resolve_path_item
from .slicer import HTTP_METHODS, parse_selector


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class RepresentationError(Exception):
    """Base class for representation-selection failures."""


class InvalidDocumentError(RepresentationError):
    """The submitted document is not a recognizable OpenAPI 3.x doc (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class InvalidSelectorError(RepresentationError):
    """The selector is malformed or unknown (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class InvalidRepresentationRequestError(RepresentationError):
    """The envelope (headers / status code) is malformed (400)."""

    def __init__(self, messages: List[str]) -> None:
        self.messages = messages
        super().__init__("; ".join(messages))


class ReferenceOrStructureError(RepresentationError):
    """One or more contract-level problems (HTTP 422)."""

    def __init__(self, errors: List[Dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(
            "; ".join(f"{e['code']} @ {e.get('pointer', '')}" for e in errors)
        )


class UnsupportedMediaTypeError(RepresentationError):
    """The request Content-Type matches no declared media type (HTTP 415)."""

    def __init__(
        self,
        message: str,
        content_pointer: str,
        supported: List[str],
        offered: Optional[str],
    ) -> None:
        self.message = message
        self.content_pointer = content_pointer
        self.supported = supported
        self.offered = offered
        super().__init__(message)


class NotAcceptableError(RepresentationError):
    """The Accept list matches no declared response media type (HTTP 406)."""

    def __init__(
        self,
        message: str,
        content_pointer: str,
        supported: List[str],
        accept: Optional[str],
    ) -> None:
        self.message = message
        self.content_pointer = content_pointer
        self.supported = supported
        self.accept = accept
        super().__init__(message)


# --------------------------------------------------------------------------- #
# Media type / Accept parsing (RFC 7230 token / quoted-string, RFC 7231 q)
# --------------------------------------------------------------------------- #


_TCHAR = frozenset(
    "!#$%&'*+-.^_`|~"
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
)


@dataclass(frozen=True)
class MediaRange:
    """One parsed media range (a Content-Type entry or one Accept entry)."""

    type: str  # lower-cased; "*" for the wildcard type
    subtype: str  # lower-cased; "*" for the wildcard subtype
    params: Dict[str, str]  # lower-cased name -> canonical value
    q: float = 1.0  # Accept weight (always 1.0 for Content-Type)

    @property
    def range_rank(self) -> int:
        """Wildcard specificity: concrete type > type/* > */*."""
        if self.type != "*" and self.subtype != "*":
            return 3
        if self.type != "*":
            return 2
        return 1

    def canonical(self, *, include_q: bool = False) -> str:
        """Stable textual form: lower-cased range, parameters sorted by name.

        The wire value of every parameter is preserved verbatim (except
        ``charset``, whose value names a character set and is case-insensitive,
        so it is rendered lower-cased for a stable normalization).
        """
        text = f"{self.type}/{self.subtype}"
        for name in sorted(self.params):
            value = self.params[name].lower() if name == "charset" else self.params[name]
            text += f"; {name}={value}"
        if include_q and self.q != 1.0:
            text += f";q={_format_q(self.q)}"
        return text


def _format_q(value: float) -> str:
    text = ("%.3f" % value).rstrip("0").rstrip(".")
    return text or "0"


def _parse_quoted_value(text: str) -> Optional[str]:
    """Parse an RFC 7230 quoted-string (without surrounding quotes)."""
    result: List[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 1
            if index >= len(text) or text[index] in {"\r", "\n"}:
                return None
            result.append(text[index])
        elif char in {"\r", "\n", '"'}:
            return None
        else:
            result.append(char)
        index += 1
    return "".join(result)


def _split_semicolons(text: str) -> Optional[List[str]]:
    """Split on semicolons that are not inside a quoted string."""
    parts: List[str] = []
    start = 0
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            if quoted and index > 0 and text[index - 1] == "\\":
                pass  # escaped quote, handled as part of the value
            else:
                quoted = not quoted
        elif char == ";" and not quoted:
            parts.append(text[start:index])
            start = index + 1
        index += 1
    if quoted:
        return None
    parts.append(text[start:])
    return parts


def _parse_parameter(raw: str) -> Optional[Tuple[str, str]]:
    """Parse one ``name=value`` media-type parameter."""
    if "=" not in raw:
        return None
    name, raw_value = raw.split("=", 1)
    name = name.strip()
    if not name or any(char not in _TCHAR for char in name):
        return None
    raw_value = raw_value.strip()
    if len(raw_value) >= 2 and raw_value[0] == '"' and raw_value[-1] == '"':
        value = _parse_quoted_value(raw_value[1:-1])
        if value is None:
            return None
    else:
        value = raw_value
        if not value or any(char not in _TCHAR for char in value):
            return None
    return name.lower(), value


def _parse_media_ranges(
    header: str, *, allow_wildcards: bool
) -> Tuple[Optional[List[MediaRange]], Optional[str]]:
    """Parse a Content-Type (single range, no wildcards) or Accept header."""
    pieces = [piece.strip() for piece in header.split(",")]
    if any(piece == "" for piece in pieces):
        return None, "empty media range in header value"

    ranges: List[MediaRange] = []
    for piece in pieces:
        segments = _split_semicolons(piece)
        if segments is None:
            return None, f"unterminated quoted string in {piece!r}"
        main = segments[0].strip()
        if main.count("/") != 1:
            return None, f"malformed media type {piece!r}: expected 'type/subtype'"
        type_text, subtype_text = (part.strip() for part in main.split("/", 1))
        if not type_text or not subtype_text:
            return None, f"malformed media type {piece!r}: empty type or subtype"

        def valid_token(token: str) -> bool:
            return bool(token) and all(char in _TCHAR for char in token)

        type_is_wild = type_text == "*"
        subtype_is_wild = subtype_text == "*"
        if not ((type_is_wild or valid_token(type_text)) and (
            subtype_is_wild or valid_token(subtype_text)
        )):
            return None, f"malformed media type {piece!r}: illegal type or subtype token"
        if not allow_wildcards and (type_is_wild or subtype_is_wild):
            return None, (
                f"malformed media type {piece!r}: Content-Type must be a concrete "
                "media type, not a wildcard"
            )
        if type_is_wild and not subtype_is_wild:
            return None, f"malformed media type {piece!r}: '*/subtype' is not allowed"

        params: Dict[str, str] = {}
        q_value: Optional[float] = None
        for raw_param in segments[1:]:
            parsed = _parse_parameter(raw_param)
            if parsed is None:
                return None, f"malformed media-type parameter {raw_param!r} in {piece!r}"
            name, value = parsed
            name_lower = name.lower()
            if name_lower in params:
                return None, f"duplicate media-type parameter {name!r} in {piece!r}"
            if name_lower == "q":
                if not allow_wildcards:
                    return None, (
                        f"malformed Content-Type {piece!r}: the 'q' parameter only "
                        "belongs on Accept media ranges"
                    )
                if not _valid_q(value):
                    return None, f"invalid Accept weight q={value!r} in {piece!r}"
                q_value = float(value)
                continue
            # Charset names are case-insensitive (they identify a coded
            # character set); normalize them like the type/subtype tokens.
            if name_lower == "charset":
                value = value.lower()
            params[name_lower] = value

        ranges.append(
            MediaRange(
                type=type_text.lower(),
                subtype=subtype_text.lower(),
                params=params,
                q=1.0 if q_value is None else q_value,
            )
        )
    return ranges, None


def _valid_q(text: str) -> bool:
    if text == "0" or text == "1":
        return True
    if "." not in text:
        return False
    whole, fraction = text.split(".", 1)
    if whole == "0" and fraction.isdigit() and 1 <= len(fraction) <= 3:
        return True
    if whole == "1" and 1 <= len(fraction) <= 3 and set(fraction) == {"0"}:
        return True
    return False


def normalize_declared_media_type(raw_key: Any) -> str:
    """Canonical form of a declared content-map key; lenient fallback."""
    text = str(raw_key).strip()
    parsed, error = _parse_media_ranges(text, allow_wildcards=True)
    if error is not None or not parsed:
        return text
    return parsed[0].canonical()


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def _range_covers(
    range_type: str,
    range_subtype: str,
    concrete_type: str,
    concrete_subtype: str,
) -> bool:
    if range_type == "*":
        return True
    if range_type != concrete_type:
        return False
    if range_subtype == "*":
        return True
    return range_subtype == concrete_subtype


def _params_satisfied(required: Dict[str, str], offered: Dict[str, str]) -> bool:
    """Every *required* parameter must be present on *offered* with equal value.

    ``charset`` values are case-insensitive (they name a character encoding);
    every other parameter value is compared verbatim. Extra parameters on the
    offered side are allowed.
    """
    for name, value in required.items():
        present = offered.get(name)
        if present is None:
            return False
        if name == "charset":
            if present.lower() != value.lower():
                return False
        elif present != value:
            return False
    return True


@dataclass
class Candidate:
    """One declared Media Type Object entry with a parsed range."""

    key: str
    parsed: Optional[MediaRange]  # None when the declared key is malformed
    media_type: str
    node: Dict[str, Any]
    pointer: str
    order: int


def _parse_declared(key: Any) -> Optional[MediaRange]:
    text = str(key).strip()
    parsed, error = _parse_media_ranges(text, allow_wildcards=True)
    if error is not None:
        return None
    return parsed[0] if parsed else None


def select_request_representation(
    candidates: List[Candidate], offered: MediaRange
) -> Optional[Candidate]:
    """Pick the unique declared media type for a concrete Content-Type.

    Precedence: range specificity (concrete > ``type/*`` > ``*/*``), then
    the number of declared parameters the wire value satisfies, then the
    contract declaration order.
    """
    best: Optional[Candidate] = None
    best_score: Optional[Tuple[int, int]] = None
    for candidate in candidates:
        parsed = candidate.parsed
        if parsed is None:
            continue
        if not _range_covers(parsed.type, parsed.subtype, offered.type, offered.subtype):
            continue
        if not _params_satisfied(parsed.params, offered.params):
            continue
        score = (parsed.range_rank, len(parsed.params))
        if best_score is None or score > best_score:
            best, best_score = candidate, score
    return best


def select_response_representation(
    candidates: List[Candidate], accept_ranges: List[MediaRange]
) -> Optional[Tuple[Candidate, MediaRange]]:
    """Pick the unique declared media type honoring an Accept list.

    Each candidate takes its weight from the **most specific** Accept range
    that covers it (a near concrete range overrides a broader one regardless
    of its q); among equally specific covering ranges the highest q applies.
    Candidates only covered by ``q=0`` ranges are excluded. The winner
    maximizes weight, then matched-range specificity, then the candidate's
    own specificity; equal scores keep declaration order.
    """
    best: Optional[Candidate] = None
    best_range: Optional[MediaRange] = None
    best_score: Optional[Tuple[float, int, int, int, int]] = None

    for candidate in candidates:
        parsed = candidate.parsed
        if parsed is None:
            continue

        # A candidate takes its weight from the most specific Accept range
        # covering it; specificity overrides weight (so a concrete
        # 'application/json;q=0' wins over '*/*;q=1'). Among ranges of equal
        # specificity (e.g. duplicate concrete ranges), the highest q applies
        # and the first occurrence breaks the remaining tie.
        matched: Optional[MediaRange] = None
        matched_specificity: Optional[Tuple[int, int]] = None
        matched_q: Optional[float] = None
        for accepted in accept_ranges:
            if not _range_covers(
                accepted.type, accepted.subtype, parsed.type, parsed.subtype
            ):
                continue
            if not _params_satisfied(accepted.params, parsed.params):
                continue
            specificity = (accepted.range_rank, len(accepted.params))
            if matched_specificity is None or specificity > matched_specificity:
                matched, matched_specificity, matched_q = (
                    accepted, specificity, accepted.q)
            elif specificity == matched_specificity and accepted.q > matched_q:
                matched, matched_q = accepted, accepted.q
        if matched is None or matched_q == 0.0:
            continue

        score = (
            matched_q,
            matched_specificity[0],
            matched_specificity[1],
            parsed.range_rank,
            len(parsed.params),
        )
        if best_score is None or score > best_score:
            best, best_range, best_score = candidate, matched, score
    if best is None or best_range is None:
        return None
    return best, best_range


# --------------------------------------------------------------------------- #
# Response key selection
# --------------------------------------------------------------------------- #


def _select_response_key(
    responses: Dict[str, Any], status_text: str
) -> Tuple[Optional[str], Optional[str]]:
    """Exact status code, then ``nXX`` wildcard (case-insensitive), then default."""
    if status_text in responses:
        return status_text, "exact"
    wildcard: Optional[str] = None
    wanted = status_text[0].lower() + "xx"
    for key in responses:
        if isinstance(key, str) and len(key) == 3 and key.lower() == wanted:
            wildcard = key
            break
    if wildcard is not None:
        return wildcard, "wildcard"
    if "default" in responses:
        return "default", "default"
    return None, None


# --------------------------------------------------------------------------- #
# Resolved-object helpers
# --------------------------------------------------------------------------- #


def _sorted_errors(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        errors,
        key=lambda e: (
            str(e.get("code", "")),
            str(e.get("pointer", "")),
            str(e.get("ref", "")),
            str(e.get("error", "")),
        ),
    )


def _resolve_contract_object(
    doc: Dict[str, Any],
    raw: Any,
    occurrence_pointer: str,
    is31: bool,
    *,
    kind: str,
) -> Tuple[
    Optional[Dict[str, Any]],
    Optional[Dict[str, str]],
    Optional[Dict[str, Any]],
]:
    """Resolve an inline or ``$ref``'d request body / response object."""
    if not isinstance(raw, dict):
        return None, None, {
            "code": f"invalid_{kind}",
            "pointer": occurrence_pointer,
            "error": f"{kind} must be an object",
        }
    if not isinstance(raw.get("$ref"), str):
        return raw, None, None
    layers, error = _follow_chain(doc, raw, occurrence_pointer)
    if error is not None:
        return None, None, error
    effective, provenance = _build_effective(layers, is31)
    if not isinstance(effective, dict):  # defensive: _follow_chain guarantees dict
        return None, None, {
            "code": f"invalid_{kind}",
            "pointer": occurrence_pointer,
            "error": f"{kind} reference must target an object",
        }
    return effective, provenance, None


def _resolve_schema(
    doc: Dict[str, Any],
    raw_schema: Any,
    schema_pointer: str,
    is31: bool,
) -> Tuple[Any, str, Optional[Dict[str, Any]]]:
    """Return (deep-copied schema value, physical pointer, error).

    A schema that is itself a local ``$ref`` chain is followed to its
    terminal component (3.0 ignores siblings, 3.1 merges them); plain inline
    schemas (and 3.1 boolean schemas) are copied as declared.
    """
    if not isinstance(raw_schema, dict) or not isinstance(raw_schema.get("$ref"), str):
        return copy.deepcopy(raw_schema), schema_pointer, None

    layers, error = _follow_chain(doc, raw_schema, schema_pointer)
    if error is not None:
        return None, schema_pointer, error
    effective, _provenance = _build_effective(layers, is31)
    terminal_pointer = layers[-1][1]
    return copy.deepcopy(effective), terminal_pointer, None


def _resolve_example_entry(
    doc: Dict[str, Any],
    raw_entry: Any,
    entry_pointer: str,
    is31: bool,
    name: str,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """Resolve one ``examples.<name>`` entry through its local ``$ref`` chain."""
    effective, provenance, _effective_pointer, error = _resolve_object_member(
        doc, raw_entry, entry_pointer, is31, kind="example"
    )
    if error is not None:
        return None, error

    def member_pointer(member: str) -> Optional[str]:
        if member not in effective:
            return None
        return _member_pointer(member, entry_pointer, provenance)

    return {
        "name": name,
        "pointer": entry_pointer,
        "summary": copy.deepcopy(effective.get("summary")) if "summary" in effective else None,
        "description": (
            copy.deepcopy(effective.get("description"))
            if "description" in effective
            else None
        ),
        "value": copy.deepcopy(effective.get("value")) if "value" in effective else None,
        "value_pointer": member_pointer("value"),
        "external_value": (
            copy.deepcopy(effective.get("externalValue"))
            if "externalValue" in effective
            else None
        ),
        "external_value_pointer": member_pointer("externalValue"),
    }, None


def _build_representation(
    doc: Dict[str, Any],
    candidate: Candidate,
    content_pointer: str,
    is31: bool,
    errors: List[Dict[str, Any]],
    *,
    offered: Optional[MediaRange] = None,
    accepted: Optional[MediaRange] = None,
) -> Dict[str, Any]:
    """Assemble the stable response object for one selected Media Type Object."""
    media = candidate.node
    media_pointer = candidate.pointer

    schema: Any = None
    schema_pointer: Optional[str] = None
    if "schema" in media:
        schema_pointer = pointer_join(media_pointer, "schema")
        schema, schema_pointer, schema_error = _resolve_schema(
            doc, media["schema"], schema_pointer, is31
        )
        if schema_error is not None:
            errors.append(schema_error)

    example: Any = None
    example_pointer: Optional[str] = None
    if "example" in media:
        example_pointer = pointer_join(media_pointer, "example")
        example = copy.deepcopy(media["example"])

    examples: List[Dict[str, Any]] = []
    raw_examples = media.get("examples")
    if raw_examples is not None:
        examples_pointer = pointer_join(media_pointer, "examples")
        if not isinstance(raw_examples, dict):
            errors.append(
                {
                    "code": "invalid_media_type",
                    "pointer": examples_pointer,
                    "error": "'examples' must be an object",
                }
            )
        else:
            for name, raw_entry in raw_examples.items():
                entry_pointer = pointer_join(examples_pointer, str(name))
                resolved, example_error = _resolve_example_entry(
                    doc, raw_entry, entry_pointer, is31, str(name)
                )
                if example_error is not None:
                    errors.append(example_error)
                else:
                    examples.append(resolved)

    return {
        "content_pointer": content_pointer,
        "pointer": media_pointer,
        "media_type": candidate.media_type,
        "offered_media_type": offered.canonical() if offered is not None else None,
        "accepted_media_range": (
            accepted.canonical() if accepted is not None else None
        ),
        "weight": accepted.q if accepted is not None else None,
        "schema": schema,
        "schema_pointer": schema_pointer,
        "example": example,
        "example_pointer": example_pointer,
        "examples": examples,
    }


# --------------------------------------------------------------------------- #
# Content collection
# --------------------------------------------------------------------------- #


def _collect_candidates(
    content: Any, content_pointer: str
) -> Tuple[Optional[List[Candidate]], Optional[Dict[str, Any]]]:
    if not isinstance(content, dict):
        return None, {
            "code": "invalid_media_type",
            "pointer": content_pointer,
            "error": "'content' must be an object mapping media types to Media Type Objects",
        }
    candidates: List[Candidate] = []
    for order, (key, media_node) in enumerate(content.items()):
        media_pointer = pointer_join(content_pointer, str(key))
        if not isinstance(media_node, dict):
            return None, {
                "code": "invalid_media_type",
                "pointer": media_pointer,
                "error": "Media Type Object must be an object",
            }
        parsed = _parse_declared(key)
        if parsed is None:
            return None, {
                "code": "invalid_media_type",
                "pointer": media_pointer,
                "error": (
                    f"content map key {str(key)!r} is not a valid media type "
                    "(expected 'type/subtype' with RFC 7230 parameters)"
                ),
            }
        candidates.append(
            Candidate(
                key=str(key),
                parsed=parsed,
                media_type=normalize_declared_media_type(key),
                node=media_node,
                pointer=media_pointer,
                order=order,
            )
        )
    return candidates, None


def _normalized_supported(candidates: List[Candidate]) -> List[str]:
    seen: set = set()
    supported: List[str] = []
    for candidate in candidates:
        if candidate.media_type not in seen:
            seen.add(candidate.media_type)
            supported.append(candidate.media_type)
    return supported


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def select_representations(
    doc: Any,
    selector: Any,
    content_type: Any,
    accept: Any,
    status_code: Any,
) -> Dict[str, Any]:
    """Select the request and response representations for one HTTP call.

    :raises InvalidDocumentError: *doc* is not OpenAPI 3.x.
    :raises InvalidSelectorError: the selector is malformed/unknown (400).
    :raises InvalidRepresentationRequestError: headers/status malformed (400).
    :raises ReferenceOrStructureError: contract-level problems (422).
    :raises UnsupportedMediaTypeError: request Content-Type unmatched (415).
    :raises NotAcceptableError: Accept list unmatched (406).
    """
    # --- Request envelope validation (400) ---------------------------------
    shape_errors: List[str] = []
    if not isinstance(doc, dict):
        shape_errors.append("document must be a JSON object")
    else:
        version = doc.get("openapi")
        if not isinstance(version, str) or not version.startswith("3."):
            shape_errors.append(
                "document.openapi must be a version string starting with '3.' "
                f"(OpenAPI 3.x), got {version!r}"
            )
        if not isinstance(doc.get("paths"), dict):
            shape_errors.append("document.paths must be an object")
    if shape_errors:
        raise InvalidDocumentError(shape_errors)

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

    envelope_errors: List[str] = []
    offered: Optional[MediaRange] = None
    accept_ranges: List[MediaRange] = [MediaRange("*", "*", {}, 1.0)]
    accept_header: Optional[str] = None

    if content_type is not None:
        if not isinstance(content_type, str):
            envelope_errors.append("content_type must be a string when provided")
        elif content_type.strip():
            parsed_ct, ct_error = _parse_media_ranges(
                content_type.strip(), allow_wildcards=False
            )
            if ct_error is not None:
                envelope_errors.append(f"invalid Content-Type header: {ct_error}")
            elif len(parsed_ct) != 1:
                envelope_errors.append(
                    "invalid Content-Type header: exactly one media type is allowed"
                )
            else:
                offered = parsed_ct[0]

    if accept is not None:
        if not isinstance(accept, str):
            envelope_errors.append("accept must be a string when provided")
        elif accept.strip():
            accept_header = accept.strip()
            parsed_accept, accept_error = _parse_media_ranges(
                accept_header, allow_wildcards=True
            )
            if accept_error is not None:
                envelope_errors.append(f"invalid Accept header: {accept_error}")
            else:
                accept_ranges = parsed_accept

    status_text: Optional[str] = None
    if isinstance(status_code, bool) or not isinstance(status_code, (int, str)):
        envelope_errors.append(
            "status_code must be an integer or a 3-digit string (100..599)"
        )
    else:
        status_text = str(status_code).strip()
        if not (
            len(status_text) == 3
            and status_text.isdigit()
            and status_text[0] in "12345"
        ):
            envelope_errors.append(
                f"status_code must be a concrete HTTP status code (100..599), got {status_code!r}"
            )
    if envelope_errors:
        raise InvalidRepresentationRequestError(envelope_errors)

    is31 = str(doc.get("openapi", "")).startswith(("3.1", "3.2"))
    errors: List[Dict[str, Any]] = []

    # --- Operation lookup --------------------------------------------------
    path_pointer = pointer_join("/paths", path)
    path_item, _item_pointer, item_error = _resolve_path_item(
        doc, doc["paths"][path], path_pointer, is31
    )
    if item_error is not None:
        if item_error.get("code") == "invalid_link":
            item_error = {**item_error, "code": "invalid_operation"}
        raise ReferenceOrStructureError(_sorted_errors([item_error]))

    if not isinstance(path_item, dict):
        raise ReferenceOrStructureError(
            _sorted_errors(
                [
                    {
                        "code": "invalid_operation",
                        "pointer": path_pointer,
                        "error": "path item must be an object",
                    }
                ]
            )
        )
    method_keys = {
        key.lower(): key
        for key in path_item
        if isinstance(key, str) and key.lower() in HTTP_METHODS
    }
    if method not in method_keys:
        raise InvalidSelectorError(
            [f"{method.upper()} {path}: operation is not declared"]
        )
    operation_key = method_keys[method]
    operation = path_item[operation_key]
    operation_pointer = pointer_join(path_pointer, operation_key)
    if not isinstance(operation, dict):
        raise ReferenceOrStructureError(
            _sorted_errors(
                [
                    {
                        "code": "invalid_operation",
                        "pointer": operation_pointer,
                        "error": "operation must be an object",
                    }
                ]
            )
        )

    # --- Request body ------------------------------------------------------
    request_result: Optional[Dict[str, Any]] = None
    request_candidates: Optional[List[Candidate]] = None
    request_content_pointer: Optional[str] = None
    if "requestBody" in operation:
        body_pointer = pointer_join(operation_pointer, "requestBody")
        body, body_provenance, body_error = _resolve_contract_object(
            doc,
            operation["requestBody"],
            body_pointer,
            is31,
            kind="request_body",
        )
        required = False
        content_pointer = _member_pointer("content", body_pointer, body_provenance)
        if body_error is not None:
            errors.append(body_error)
        else:
            required = bool(body.get("required", False))
            if "content" in body:
                request_content_pointer = content_pointer
                request_candidates, content_error = _collect_candidates(
                    body.get("content"), content_pointer
                )
                if content_error is not None:
                    errors.append(content_error)
                    request_candidates = None
        request_result = {
            "request_body_pointer": body_pointer,
            "required": required,
            "representation": None,
        }

    # --- Response selection ------------------------------------------------
    responses = operation.get("responses")
    responses_pointer = pointer_join(operation_pointer, "responses")
    if not isinstance(responses, dict):
        errors.append(
            {
                "code": "invalid_response",
                "pointer": responses_pointer,
                "error": "operation must declare a 'responses' object",
            }
        )
        responses = {}

    response_key, match_kind = _select_response_key(responses, status_text)
    if response_key is None:
        errors.append(
            {
                "code": "missing_response",
                "pointer": responses_pointer,
                "status_code": int(status_text),
                "error": (
                    f"no response matches status code {int(status_text)}: expected "
                    "the exact code, an 'nXX' wildcard key or 'default'"
                ),
            }
        )
        response_result = None
        response_candidates: Optional[List[Candidate]] = None
        response_content_pointer: Optional[str] = None
    else:
        response_ref_pointer = pointer_join(responses_pointer, response_key)
        response, response_provenance, response_error = _resolve_contract_object(
            doc,
            responses[response_key],
            response_ref_pointer,
            is31,
            kind="response",
        )
        response_candidates = None
        response_content_pointer = None
        if response_error is not None:
            errors.append(response_error)
        else:
            response_content_pointer = _member_pointer(
                "content", response_ref_pointer, response_provenance
            )
            if "content" in response:
                response_candidates, content_error = _collect_candidates(
                    response.get("content"), response_content_pointer
                )
                if content_error is not None:
                    errors.append(content_error)
                    response_candidates = None
        response_result = {
            "status_code": int(status_text),
            "key": response_key,
            "match": match_kind,
            "response_pointer": response_ref_pointer,
            "representation": None,
        }

    # Contract-level problems abort before any HTTP-style negotiation.
    if errors:
        raise ReferenceOrStructureError(_sorted_errors(errors))

    # --- Request negotiation ----------------------------------------------
    if request_result is not None:
        if offered is not None:
            if not request_candidates:
                raise UnsupportedMediaTypeError(
                    "the request Content-Type does not match any media type "
                    "declared by the operation requestBody",
                    request_content_pointer or "",
                    _normalized_supported(request_candidates or []),
                    offered.canonical(),
                )
            chosen = select_request_representation(request_candidates, offered)
            if chosen is None:
                raise UnsupportedMediaTypeError(
                    "the request Content-Type does not match any media type "
                    "declared by the operation requestBody",
                    request_content_pointer or "",
                    _normalized_supported(request_candidates),
                    offered.canonical(),
                )
            request_result["representation"] = _build_representation(
                doc,
                chosen,
                request_content_pointer or chosen.pointer,
                is31,
                errors,
                offered=offered,
            )
        # No Content-Type supplied: no concrete request representation is
        # selected (e.g. an empty body); null is returned as-is.
    elif offered is not None:
        # The operation declares no request body, yet the caller sends a
        # concrete Content-Type: there is nothing it can match (415).
        raise UnsupportedMediaTypeError(
            "the operation declares no request body, so the request "
            "Content-Type cannot match any media type",
            pointer_join(operation_pointer, "requestBody"),
            [],
            offered.canonical(),
        )

    # --- Response negotiation ---------------------------------------------
    if response_candidates is not None:
        chosen_response = select_response_representation(
            response_candidates, accept_ranges
        )
        if chosen_response is None:
            raise NotAcceptableError(
                "none of the response media types declared for the selected "
                "response is acceptable per the request Accept header",
                response_content_pointer or "",
                _normalized_supported(response_candidates),
                accept_header,
            )
        chosen_candidate, matched_range = chosen_response
        response_result["representation"] = _build_representation(
            doc,
            chosen_candidate,
            response_content_pointer or chosen_candidate.pointer,
            is31,
            errors,
            accepted=matched_range,
        )
    # A response without a content map has no negotiable representation;
    # Accept cannot turn that into 406.

    if errors:  # schema/example reference errors discovered while assembling
        raise ReferenceOrStructureError(_sorted_errors(errors))

    return {
        "operation_pointer": operation_pointer,
        "request": request_result,
        "response": response_result,
    }
