"""Controlled export of STIX2 objects according to data markings.

These functions let a caller share only the parts of an object whose
markings the recipient is allowed to see.  The caller passes in the exact
set of marking identifiers the recipient is cleared for; no marking registry
or clearance store is consulted by this module.

Both object level markings (``object_marking_refs``) and granular markings
(``granular_markings``) are taken into account:

* An object level marking applies to the whole object.  If any of the
  object's ``object_marking_refs`` is not in the allowed set, the entire
  object is withheld.
* A granular marking applies to the property selected by each of its
  selectors and to every value underneath that property (markings are
  inherited downwards).  A value is only exported when *all* of the
  markings which apply to it are allowed.  An unmarked value is always
  allowed.

The original object is never modified; the result is a separately built
object and re-parsing the serialized output yields an equivalent object.
"""

import copy
import json
import re

from stix2 import exceptions, registry
from stix2.markings import utils
from stix2.parsing import parse
from stix2.serialization import STIXJSONEncoder
from stix2.utils import detect_spec_version


# Selector components are either dictionary keys or ``[index]`` list
# positions, matching the selector syntax enforced by SelectorProperty.
_INDEX_COMPONENT = re.compile(r"^\[(\d+)\]$")

# Sentinel returned by the recursive filter when a value is hidden.
_HIDDEN = object()


class ControlledExportResult:
    """Outcome of a controlled export.

    Attributes:
        exportable (bool): True if an export of the object (possibly with
            some content removed) could be produced.
        stix_object: The re-parsed, filtered STIX object when
            ``exportable`` is True.  Otherwise None.
        reason (str): Human readable explanation of why the object could
            not be exported when ``exportable`` is False.  Otherwise None.
        removed_paths (list): Selector strings of the values which were
            withheld because of disallowed markings.
        disallowed_markings (list): Marking identifiers encountered on the
            object which were not part of the allowed set.
    """

    def __init__(
        self, stix_object=None, reason=None,
        removed_paths=None, disallowed_markings=None,
    ):
        self.exportable = stix_object is not None
        self.stix_object = stix_object
        self.reason = reason
        self.removed_paths = removed_paths or []
        self.disallowed_markings = disallowed_markings or []

    def __repr__(self):
        if self.exportable:
            return (
                "ControlledExportResult(exportable=True, "
                "stix_object={0!r}, removed_paths={1!r})".format(
                    self.stix_object, self.removed_paths,
                )
            )
        return (
            "ControlledExportResult(exportable=False, reason={0!r}, "
            "disallowed_markings={1!r})".format(
                self.reason, self.disallowed_markings,
            )
        )


def _parse_selector(selector):
    """Split a selector string into key (str) and index (int) components."""
    components = []
    for component in selector.split("."):
        index_match = _INDEX_COMPONENT.match(component)
        if index_match:
            components.append(int(index_match.group(1)))
        else:
            components.append(component)
    return tuple(components)


def _build_selector(components):
    """Inverse of :func:`_parse_selector`."""
    rendered = []
    for component in components:
        if isinstance(component, int):
            rendered.append("[{0}]".format(component))
        else:
            rendered.append(component)
    return ".".join(rendered)


def _has_custom_properties(data):
    """Check whether a plain STIX dictionary uses custom properties.

    Unknown object types are left to the parser's normal handling, so this
    only inspects registered types.  The 2.1 toplevel-property-extension
    case is rare in an export input; properties contributed by a registered
    extension are recognized through the extension registry.
    """
    obj_type = data.get("type")
    if not obj_type:
        return False

    try:
        spec_version = detect_spec_version(data)
    except exceptions.STIXError:
        return False

    obj_class = registry.class_for_type(obj_type, spec_version, "objects") \
        or registry.class_for_type(obj_type, spec_version, "observables")
    if obj_class is None:
        return False

    defined = set(obj_class._properties.keys())
    for ext_id, ext in (data.get("extensions") or {}).items():
        ext_class = registry.class_for_type(ext_id, spec_version, "extensions")
        if ext_class and isinstance(ext, dict) and \
                ext.get("extension_type") == "toplevel-property-extension":
            defined.update(getattr(ext_class, "_toplevel_properties", {}).keys())

    return any(key not in defined for key in data)


def _build_marking_map(granular_markings):
    """Map parsed selector paths to the sets of markings applied to them."""
    marking_map = {}
    for granular_marking in granular_markings or []:
        marking_ref = granular_marking.get("marking_ref")
        if not marking_ref:
            # Language markings are not dissemination restrictions, so they
            # do not participate in controlled export.
            continue
        for selector in granular_marking.get("selectors", []):
            path = _parse_selector(selector)
            marking_map.setdefault(path, set()).add(marking_ref)
    return marking_map


def _applied_markings(path, marking_map):
    """Return all markings that apply to ``path``.

    A marking applies when its selector equals the path or is a component
    wise prefix of it, i.e. the marking is inherited by every descendant of
    the marked property.  Matching is done on parsed component tuples, never
    on raw string prefixes, so selectors such as ``name`` and ``names`` can
    never be confused.
    """
    markings = set()
    for selector_path, selector_markings in marking_map.items():
        if path[:len(selector_path)] == selector_path:
            markings.update(selector_markings)
    return markings


def _is_exportable(path, marking_map, allowed_markings, disallowed_markings):
    """Check whether every marking on ``path`` is allowed."""
    exportable = True
    for marking in _applied_markings(path, marking_map):
        if marking not in allowed_markings:
            exportable = False
            if marking not in disallowed_markings:
                disallowed_markings.append(marking)
    return exportable


def _filter_value(
    value, path, marking_map, allowed_markings,
    removed_paths, disallowed_markings, index_maps,
):
    """Recursively filter ``value`` located at ``path``.

    Returns the filtered value, or ``_HIDDEN`` when the value (or, for
    containers, one of its required ancestors) must be withheld.
    """
    if not _is_exportable(
        path, marking_map, allowed_markings, disallowed_markings,
    ):
        removed_paths.append(_build_selector(path))
        return _HIDDEN

    if isinstance(value, dict):
        filtered = {}
        for key, child in value.items():
            child_path = path + (key,)
            child_value = _filter_value(
                child, child_path, marking_map, allowed_markings,
                removed_paths, disallowed_markings, index_maps,
            )
            if child_value is not _HIDDEN:
                filtered[key] = child_value
        return filtered

    if isinstance(value, list):
        filtered = []
        index_map = {}
        for index, child in enumerate(value):
            child_path = path + (index,)
            child_value = _filter_value(
                child, child_path, marking_map, allowed_markings,
                removed_paths, disallowed_markings, index_maps,
            )
            if child_value is _HIDDEN:
                continue
            index_map[index] = len(filtered)
            filtered.append(child_value)
        if index_map:
            # Keyed by the path addressing the list itself.  During selector
            # rewriting the index component is the last thing appended, so
            # the components in hand when an index is visited address the
            # list and can be used to look this mapping up.
            index_maps[path] = index_map
        return filtered

    return value


def _rewrite_selector(selector, removed_paths, index_maps):
    """Map a selector onto the filtered object, or None if it now dangles.

    Whether content was withheld is decided against the original selector
    components, because index rewriting can produce a path string which
    coincidentally equals the pre-removal path of a different element.
    """
    components = _parse_selector(selector)

    # A selector which exactly points at withheld content is dangling.  The
    # check uses the un-rewritten path and is an equality comparison, so
    # ancestor keys can never be mistaken for withheld leaves.
    if selector in removed_paths:
        return None

    rewritten = []
    for component in components:
        if isinstance(component, int):
            # ``rewritten`` currently addresses the list itself and is the
            # key under which the list's index mapping was stored.
            index_map = index_maps.get(tuple(rewritten))
            if index_map is None or component not in index_map:
                return None
            rewritten.append(index_map[component])
        else:
            rewritten.append(component)

    return _build_selector(tuple(rewritten))


def _filter_granular_markings(
    granular_markings, allowed_markings, removed_paths,
    index_maps, disallowed_markings,
):
    """Rebuild granular markings for the filtered object.

    Entries using disallowed markings, or whose selectors no longer point at
    exported content, are dropped.  Surviving selectors are rewritten so that
    list indices still refer to the same values after list elements were
    removed.
    """
    filtered_markings = []
    for granular_marking in granular_markings or []:
        marking_ref = granular_marking.get("marking_ref")
        if marking_ref and marking_ref not in allowed_markings:
            if marking_ref not in disallowed_markings:
                disallowed_markings.append(marking_ref)
            continue

        rewritten_selectors = []
        for selector in granular_marking.get("selectors", []):
            rewritten = _rewrite_selector(
                selector, removed_paths, index_maps,
            )
            if rewritten is not None:
                rewritten_selectors.append(rewritten)

        if not rewritten_selectors:
            continue

        entry = {"selectors": rewritten_selectors}
        if marking_ref:
            entry["marking_ref"] = marking_ref
        lang = granular_marking.get("lang")
        if lang:
            entry["lang"] = lang
        filtered_markings.append(entry)

    if not filtered_markings:
        return None
    return utils.compress_markings(filtered_markings)


def controlled_export(obj, allowed_markings):
    """Export an object containing only content cleared for the recipient.

    Args:
        obj: An SDO, SRO or SCO (or an equivalent plain dictionary).
        allowed_markings: A marking identifier or MarkingDefinition, or a
            list of them.  Only the markings given here are considered
            cleared for the recipient; the list is supplied directly by the
            caller.

    Returns:
        ControlledExportResult: The result is never None.  When the object
        can be shared, ``exportable`` is True and ``stix_object`` is a newly
        built, re-parsed STIX object containing only the allowed content.
        When withholding content would leave an invalid object (for example
        a required property was hidden), ``exportable`` is False and
        ``reason`` explains the failure; no partial object is returned.

    Note:
        The input object is never modified.  Marking identifiers used by
        language granular markings do not restrict dissemination and are
        ignored when deciding what to withhold.
    """
    allowed = set(utils.convert_to_marking_list(allowed_markings) or [])

    if isinstance(obj, dict):
        data = copy.deepcopy(obj)
        allow_custom = _has_custom_properties(data)
    else:
        # Round trip through JSON so the output cannot share any mutable
        # state with the caller's object.
        data = json.loads(json.dumps(obj, cls=STIXJSONEncoder))
        allow_custom = obj.has_custom

    object_level_markings = data.get("object_marking_refs") or []
    disallowed_object_markings = [
        marking for marking in object_level_markings
        if marking not in allowed
    ]
    if disallowed_object_markings:
        return ControlledExportResult(
            reason=(
                "Object is withheld: object level marking(s) {0} are not "
                "in the allowed set.".format(
                    ", ".join(sorted(disallowed_object_markings)),
                )
            ),
            disallowed_markings=disallowed_object_markings,
        )

    granular_markings = data.pop("granular_markings", None)
    marking_map = _build_marking_map(granular_markings)

    removed_paths = []
    disallowed_markings = []
    index_maps = {}
    filtered_data = {}
    for key, value in data.items():
        child_value = _filter_value(
            value, (key,), marking_map, allowed,
            removed_paths, disallowed_markings, index_maps,
        )
        if child_value is not _HIDDEN:
            filtered_data[key] = child_value

    rebuilt_markings = _filter_granular_markings(
        granular_markings, allowed, removed_paths,
        index_maps, disallowed_markings,
    )
    if rebuilt_markings:
        filtered_data["granular_markings"] = rebuilt_markings

    try:
        exported = parse(
            filtered_data,
            allow_custom=allow_custom,
            version=detect_spec_version(filtered_data),
        )
    except KeyError as exc:
        return ControlledExportResult(
            reason=(
                "Object cannot be exported: the filtered content is not a "
                "STIX object (missing {0!r}).".format(exc.args[0])
            ),
            removed_paths=removed_paths,
            disallowed_markings=disallowed_markings,
        )
    except exceptions.ObjectConfigurationError as exc:
        return ControlledExportResult(
            reason=(
                "Object cannot be exported: withholding the disallowed "
                "content would make it invalid. {0}".format(exc)
            ),
            removed_paths=removed_paths,
            disallowed_markings=disallowed_markings,
        )
    except exceptions.ParseError as exc:
        return ControlledExportResult(
            reason=(
                "Object cannot be exported: the filtered content could not "
                "be parsed as a valid STIX object. {0}".format(exc)
            ),
            removed_paths=removed_paths,
            disallowed_markings=disallowed_markings,
        )

    return ControlledExportResult(
        stix_object=exported,
        removed_paths=removed_paths,
        disallowed_markings=disallowed_markings,
    )
