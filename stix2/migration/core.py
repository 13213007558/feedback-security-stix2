"""Core engine for migrating STIX 2.0 observed-data content to STIX 2.1.

STIX 2.0 stores cyber observables (SCOs) inside the ``objects`` mapping of an
observed-data object, where the values reference each other through numeric
string keys.  STIX 2.1 models SCOs as standalone objects with real STIX IDs
and links them from observed-data through ``object_refs``.

The engine:

* never mutates its input (it works on deep copies),
* turns numeric local references into STIX IDs, including references nested
  inside SCO extensions such as ``archive-ext.contains_refs``,
* generates deterministic UUIDv5 IDs through the v2.1 object model, falling
  back to UUIDv4 where a reference cycle makes a deterministic ID impossible,
* preserves observation windows, counts, markings and reference topology,
* reports anything that cannot be mapped 1:1 instead of dropping it.
"""

import copy
import json
import uuid

from .. import registry
from ..exceptions import STIXError
from ..properties import ListProperty, ObjectReferenceProperty
from ..v21 import Bundle, MarkingDefinition, ObservedData
from .exceptions import MigrationError, MigrationIssue
from .mappings import (
    EXTENSION_PROPERTY_REMOVALS, SCO_PROPERTY_RENAMES,
    SCO_PROPERTY_REMOVALS, reference_property_names,
)

OBSERVED_DATA_TYPE = "observed-data"
MARKING_DEFINITION_TYPE = "marking-definition"
EXTENSIONS_PROPERTY = "extensions"

# Properties defined on a STIX 2.0 observed-data SDO.  Anything else on the
# input object is custom content and has to be opted into explicitly.
_V20_OD_PROPERTIES = {
    "type", "id", "created_by_ref", "created", "modified",
    "first_observed", "last_observed", "number_observed", "objects",
    "revoked", "labels", "external_references", "object_marking_refs",
    "granular_markings",
}


class MigrationResult(object):
    """Outcome of migrating one or more STIX 2.0 observed-data objects.

    Attributes:
        observed_data (list): The migrated STIX 2.1 observed-data objects,
            in input order.
        scos (list): Every standalone SCO referenced by the observed-data
            objects, de-duplicated by ID.  Order is deterministic and does not
            depend on input ordering.
        markings (list): STIX 2.1 marking-definition objects migrated from
            the input bundle (may be empty).
        issues (list[MigrationIssue]): Non-blocking items that need a human.
            Only populated when ``strict=False``.
        extra_objects (list): Serialized input bundle objects that were not
            observed-data or marking-definition and therefore were not
            migrated.  Only populated by :func:`migrate_bundle`.
    """

    def __init__(self):
        self.observed_data = []
        self.scos = []
        self.markings = []
        self.issues = []
        self.extra_objects = []

    @property
    def objects(self):
        """All migrated top-level objects, suitable for a STIX 2.1 bundle."""
        migrated = list(self.markings)
        migrated.extend(self.scos)
        migrated.extend(self.observed_data)
        return migrated

    def as_bundle(self, id=None):
        """Return the migrated content wrapped in a STIX 2.1 bundle."""
        return Bundle(objects=self.objects, id=id, allow_custom=True)


class _IssueCollector(object):
    """Accumulates migration problems and enforces the strict/lenient policy.

    Most problems are recoverable in lenient mode: they are collected as
    :class:`MigrationIssue` and the affected data is skipped or carried over.
    Some problems have no safe representation in STIX 2.1 at all (e.g. an
    unrecognized, non-custom property); those are ``blocking`` and raise even
    in lenient mode so data can never be silently lost.
    """

    def __init__(self, strict):
        self.strict = strict
        self.issues = []

    def report(self, code, message, observed_data_id=None, object_key=None,
               path=None, blocking=False):
        if self.strict or blocking:
            raise MigrationError("{0}: {1}".format(code, message))
        issue = MigrationIssue(
            code, message, observed_data_id, object_key, path,
        )
        if issue not in self.issues:
            self.issues.append(issue)
        return issue


def _v20_sco_class(sco_type):
    return registry.class_for_type(sco_type, "2.0", "observables")


def _v21_sco_class(sco_type):
    return registry.class_for_type(sco_type, "2.1", "observables")


def _v20_extension_class(ext_type):
    return registry.class_for_type(ext_type, "2.0", "extensions")


def _v21_extension_class(ext_type):
    return registry.class_for_type(ext_type, "2.1", "extensions")


def _is_custom_name(name):
    return name.startswith("x_") or name.startswith("X_")


def _local_ref_locations(sco_type, sco_dict):
    """Yield every local reference location in one SCO dictionary.

    Each location is a tuple ``(path, valid_types, is_list, numeric_keys)``:

    * ``path`` is the property path relative to the SCO, either
      ``"src_ref"`` or ``"extensions.archive-ext.contains_refs"``;
    * ``valid_types`` is the whitelist enforced by the v2.0 property, or
      ``None`` when unconstrained;
    * ``is_list`` tells whether the value is a list of keys;
    * ``numeric_keys`` is the referenced key (or the list of keys).

    Both top-level SCO references and references nested inside registered
    extensions are covered, because both move to full STIX IDs in 2.1.
    """
    sco_class = _v20_sco_class(sco_type)
    if sco_class is None:
        return

    for prop_name in reference_property_names(sco_class):
        if prop_name not in sco_dict:
            continue
        prop = sco_class._properties[prop_name]
        contained = prop.contained if isinstance(prop, ListProperty) else prop
        is_list = isinstance(prop, ListProperty)
        yield (
            prop_name,
            contained.valid_types,
            is_list,
            list(sco_dict[prop_name]) if is_list else sco_dict[prop_name],
        )

    extensions = sco_dict.get(EXTENSIONS_PROPERTY)
    if not isinstance(extensions, dict):
        return
    for ext_type, ext_dict in extensions.items():
        if not isinstance(ext_dict, dict):
            continue
        ext_class = _v20_extension_class(ext_type)
        if ext_class is None:
            continue
        for prop_name, prop in ext_class._properties.items():
            if prop_name not in ext_dict:
                continue
            contained = (
                prop.contained if isinstance(prop, ListProperty) else prop
            )
            if not isinstance(contained, ObjectReferenceProperty):
                continue
            is_list = isinstance(prop, ListProperty)
            path = "{0}.{1}.{2}".format(
                EXTENSIONS_PROPERTY, ext_type, prop_name,
            )
            yield (
                path,
                contained.valid_types,
                is_list,
                list(ext_dict[prop_name]) if is_list
                else ext_dict[prop_name],
            )


def _tarjan_scc(nodes, edges):
    """Return strongly connected components using Tarjan's algorithm.

    ``edges`` maps each node to the nodes it references.  Components are
    returned in reverse topological order, which is the order referenced
    components must be built first.
    """
    index_counter = [0]
    stack = []
    on_stack = set()
    indices = {}
    lowlinks = {}
    components = []

    def strongconnect(node):
        indices[node] = index_counter[0]
        lowlinks[node] = index_counter[0]
        index_counter[0] += 1
        stack.append(node)
        on_stack.add(node)

        for target in edges.get(node, ()):
            if target not in indices:
                strongconnect(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])

        if lowlinks[node] == indices[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.discard(member)
                component.append(member)
                if member == node:
                    break
            components.append(component)

    for node in nodes:
        if node not in indices:
            strongconnect(node)
    return components


def _check_unknown_properties(sco_type, sco_dict, collector, od_id, key,
                              allow_custom):
    """Preflight one SCO for properties the v2.1 model cannot represent."""
    v21_class = _v21_sco_class(sco_type)
    if v21_class is None:
        collector.report(
            "unknown-observable-type",
            "observable type '{0}' at objects['{1}'] is not defined in "
            "STIX 2.1; register a CustomObservable before migrating or "
            "handle it manually".format(sco_type, key),
            od_id, key, "type",
        )
        return

    known = set(v21_class._properties)
    renames = SCO_PROPERTY_RENAMES.get(sco_type, {})
    removals = SCO_PROPERTY_REMOVALS.get(sco_type, ())

    for prop_name in sco_dict:
        if prop_name == "type" or prop_name in known or prop_name in renames:
            continue
        if prop_name in removals:
            collector.report(
                "removed-property",
                "{0}.{1} on objects['{2}'] has no STIX 2.1 equivalent and "
                "cannot be migrated automatically".format(
                    sco_type, prop_name, key,
                ),
                od_id, key, prop_name,
            )
        elif _is_custom_name(prop_name):
            if not allow_custom:
                collector.report(
                    "custom-property",
                    "custom property {0}.{1} on objects['{2}'] is not part "
                    "of the STIX 2.1 model; re-run with allow_custom=True to "
                    "carry it over or remove it manually".format(
                        sco_type, prop_name, key,
                    ),
                    od_id, key, prop_name,
                )
        else:
            # Not an x_-prefixed extension point, so there is no spec-backed
            # way to carry the value even in lenient mode: always block.
            collector.report(
                "unknown-property",
                "property {0}.{1} on objects['{2}'] is not defined in "
                "STIX 2.1 and is not a custom (x_-prefixed) property".format(
                    sco_type, prop_name, key,
                ),
                od_id, key, prop_name, blocking=True,
            )

    extensions = sco_dict.get(EXTENSIONS_PROPERTY)
    if isinstance(extensions, dict):
        for ext_type, ext_dict in extensions.items():
            if not isinstance(ext_dict, dict):
                continue
            v21_ext_class = _v21_extension_class(ext_type)
            if v21_ext_class is None:
                if not _is_custom_name(ext_type):
                    collector.report(
                        "unknown-extension",
                        "extension '{0}' on objects['{1}'] is not defined in "
                        "STIX 2.1 and is not a custom (x_-prefixed) "
                        "extension".format(ext_type, key),
                        od_id, key,
                        "{0}.{1}".format(EXTENSIONS_PROPERTY, ext_type),
                        blocking=True,
                    )
                elif not allow_custom:
                    collector.report(
                        "unknown-extension",
                        "custom extension '{0}' on objects['{1}'] needs "
                        "allow_custom=True to be carried over".format(
                            ext_type, key,
                        ),
                        od_id, key,
                        "{0}.{1}".format(EXTENSIONS_PROPERTY, ext_type),
                    )
                continue
            ext_known = set(v21_ext_class._properties)
            for prop_name in ext_dict:
                if prop_name in ext_known:
                    continue
                if prop_name in EXTENSION_PROPERTY_REMOVALS.get(
                    ext_type, (),
                ):
                    collector.report(
                        "removed-extension-property",
                        "{0}.{1} on objects['{2}'] has no STIX 2.1 "
                        "equivalent".format(ext_type, prop_name, key),
                        od_id, key,
                        "{0}.{1}.{2}".format(
                            EXTENSIONS_PROPERTY, ext_type, prop_name,
                        ),
                    )
                elif _is_custom_name(prop_name) and not allow_custom:
                    collector.report(
                        "custom-property",
                        "custom extension property {0}.{1} on objects['{2}'] "
                        "needs allow_custom=True to be carried over".format(
                            ext_type, prop_name, key,
                        ),
                        od_id, key,
                        "{0}.{1}.{2}".format(
                            EXTENSIONS_PROPERTY, ext_type, prop_name,
                        ),
                    )
                elif not _is_custom_name(prop_name):
                    collector.report(
                        "unknown-extension-property",
                        "property {0}.{1} is not defined on the STIX 2.1 "
                        "extension and is not a custom (x_-prefixed) "
                        "property".format(ext_type, prop_name),
                        od_id, key,
                        "{0}.{1}.{2}".format(
                            EXTENSIONS_PROPERTY, ext_type, prop_name,
                        ),
                        blocking=True,
                    )


def _check_granular_markings(od_dict, collector, od_id):
    """Split v2.0 granular markings into migratable and object-scoped ones."""
    migratable = []
    for marking in od_dict.get("granular_markings", ()):
        selectors = marking.get("selectors", ())
        object_scoped = [
            selector for selector in selectors
            if selector.split(".", 1)[0] == "objects"
        ]
        if object_scoped:
            collector.report(
                "granular-marking-selector",
                "granular marking {0} uses observed-data object selector(s) "
                "{1}; STIX 2.1 has no mechanical mapping for markings scoped "
                "to the embedded 'objects' mapping, so it must be re-applied "
                "to the standalone SCOs manually".format(
                    marking.get("marking_ref"), object_scoped,
                ),
                od_id, None, "granular_markings",
            )
        else:
            migratable.append(copy.deepcopy(marking))
    return migratable


def _preflight(od_dict, collector, allow_custom):
    """Validate references and properties before constructing anything.

    Returns the local reference graph, the set of
    ``(source_key, target_key)`` pairs that must not be rewritten because
    their target is missing or has an incompatible type (lenient mode only;
    strict mode raises inside the collector), and the set of object keys that
    map to a registered STIX 2.1 SCO type.
    """
    od_id = od_dict.get("id")
    objects = od_dict.get("objects", {})
    edges = {key: [] for key in objects}
    dropped_pairs = set()
    buildable = set()

    for key, sco_dict in objects.items():
        sco_type = sco_dict.get("type")
        if _v21_sco_class(sco_type) is not None:
            buildable.add(key)
        _check_unknown_properties(
            sco_type, sco_dict, collector, od_id, key, allow_custom,
        )
        for path, valid_types, is_list, ref_keys in _local_ref_locations(
            sco_type, sco_dict,
        ):
            for target_key in ref_keys:
                if target_key not in objects:
                    collector.report(
                        "missing-reference",
                        "{0} at objects['{1}'].{2} references objects['{3}'], "
                        "which does not exist".format(
                            sco_type, key, path, target_key,
                        ),
                        od_id, key, path,
                    )
                    dropped_pairs.add((key, target_key))
                    continue
                target_type = objects[target_key].get("type")
                if valid_types and target_type not in valid_types:
                    collector.report(
                        "invalid-reference-type",
                        "objects['{0}'].{1} points at a '{2}' object but the "
                        "property only accepts {3}".format(
                            key, path, target_type, valid_types,
                        ),
                        od_id, key, path,
                    )
                    dropped_pairs.add((key, target_key))
                    continue
                edges[key].append(target_key)

    # Multiple reference properties can point at the same target; keep one
    # edge per target so cycle detection is not skewed by duplicates.
    for key in edges:
        edges[key] = list(dict.fromkeys(edges[key]))
    return edges, dropped_pairs, buildable


def _apply_renames(sco_type, sco_dict):
    renames = SCO_PROPERTY_RENAMES.get(sco_type, {})
    if not renames:
        return sco_dict
    return {
        renames.get(prop_name, prop_name): value
        for prop_name, value in sco_dict.items()
    }


def _drop_removed_properties(sco_type, sco_dict):
    removals = set(SCO_PROPERTY_REMOVALS.get(sco_type, ()))
    if removals:
        sco_dict = {
            name: value for name, value in sco_dict.items()
            if name not in removals
        }
    extensions = sco_dict.get(EXTENSIONS_PROPERTY)
    if isinstance(extensions, dict):
        new_extensions = {}
        for ext_type, ext_dict in extensions.items():
            if isinstance(ext_dict, dict):
                drop = set(EXTENSION_PROPERTY_REMOVALS.get(ext_type, ()))
                ext_dict = {
                    name: value for name, value in ext_dict.items()
                    if name not in drop
                }
            new_extensions[ext_type] = ext_dict
        sco_dict[EXTENSIONS_PROPERTY] = new_extensions
    return sco_dict


def _rewrite_refs(owner_key, sco_type, sco_dict, id_map, dropped_pairs):
    """Replace numeric local references (top-level and in extensions) with IDs.

    ``sco_dict`` has already passed through :func:`_apply_renames`, so the
    v2.0 reference locations are mapped onto their v2.1 property names (the
    reverse of the rename table is used to find them).  Numeric values that
    have no assigned ID yet -- cycle members handled via explicit UUIDv4 --
    are still rewritten because their IDs are assigned up front.
    ``dropped_pairs`` holds ``(source_key, target_key)`` pairs that failed
    preflight; those references are omitted.
    """
    v20_class = _v20_sco_class(sco_type)
    if v20_class is None:
        return sco_dict
    renames = SCO_PROPERTY_RENAMES.get(sco_type, {})
    renamed_to = {new_name: old_name for old_name, new_name in renames.items()}
    migrated = copy.deepcopy(sco_dict)

    def convert(ref_keys, is_list):
        surviving = [
            id_map[target]
            for target in ref_keys
            if target in id_map
            and (owner_key, target) not in dropped_pairs
        ]
        if not surviving:
            return None
        return list(surviving) if is_list else surviving[0]

    # Top-level references: walk the already-renamed output dictionary so the
    # property names match what the v2.1 object model expects.
    for prop_name, value in list(migrated.items()):
        v20_name = renamed_to.get(prop_name, prop_name)
        if v20_name not in reference_property_names(v20_class):
            continue
        is_list = isinstance(
            v20_class._properties[v20_name], ListProperty,
        )
        ref_keys = list(value) if is_list else [value]
        converted = convert(ref_keys, is_list)
        if converted is None:
            migrated.pop(prop_name, None)
        else:
            migrated[prop_name] = converted

    # References nested inside registered extensions.
    extensions = migrated.get(EXTENSIONS_PROPERTY)
    if not isinstance(extensions, dict):
        return migrated
    for ext_type, ext_dict in extensions.items():
        if not isinstance(ext_dict, dict):
            continue
        ext_class = _v20_extension_class(ext_type)
        if ext_class is None:
            continue
        for ext_prop, prop in ext_class._properties.items():
            if ext_prop not in ext_dict:
                continue
            contained = (
                prop.contained if isinstance(prop, ListProperty) else prop
            )
            if not isinstance(contained, ObjectReferenceProperty):
                continue
            is_list = isinstance(prop, ListProperty)
            ref_keys = (
                list(ext_dict[ext_prop]) if is_list
                else [ext_dict[ext_prop]]
            )
            converted = convert(ref_keys, is_list)
            if converted is None:
                ext_dict.pop(ext_prop, None)
            else:
                ext_dict[ext_prop] = converted
    return migrated


def _build_sco(sco_type, sco_dict, assigned_id, allow_custom, markings):
    v21_class = _v21_sco_class(sco_type)
    kwargs = copy.deepcopy(sco_dict)
    kwargs.pop("type", None)
    kwargs["id"] = assigned_id
    if markings:
        kwargs["object_marking_refs"] = sorted(
            set(kwargs.get("object_marking_refs", ())) | set(markings),
        )
    return v21_class(allow_custom=allow_custom, **kwargs)


def _migrate_observed_data(od_dict, collector, allow_custom):
    """Migrate a single v2.0 observed-data dict to v2.1 objects."""
    if od_dict.get("type") != OBSERVED_DATA_TYPE:
        raise MigrationError(
            "expected a '{0}' object, got '{1}'".format(
                OBSERVED_DATA_TYPE, od_dict.get("type"),
            ),
        )

    od_dict = copy.deepcopy(od_dict)
    od_id = od_dict.get("id")
    if not isinstance(od_dict.get("objects"), dict) or not od_dict["objects"]:
        raise MigrationError(
            "observed-data {0} must contain a non-empty 'objects' mapping".format(
                od_id or "<no id>",
            ),
        )
    objects = od_dict["objects"]

    edges, dropped_pairs, buildable = _preflight(
        od_dict, collector, allow_custom,
    )

    # Members of a non-trivial strongly connected component (including
    # self-loops) cannot get deterministic UUIDv5 IDs: their id-contributing
    # references can never be resolved inside the cycle.  The STIX 2.1 spec
    # mandates a UUIDv4 fallback for exactly this situation.
    components = _tarjan_scc(sorted(objects), edges)
    forced_v4 = set()
    for component in components:
        if len(component) > 1:
            forced_v4.update(component)
        elif component[0] in edges.get(component[0], ()):
            forced_v4.add(component[0])

    id_map = {}
    built = {}
    object_marking_refs = list(od_dict.get("object_marking_refs", ()))

    for key in forced_v4:
        sco_type = objects[key].get("type")
        id_map[key] = "{0}--{1}".format(sco_type, uuid.uuid4())
        collector.report(
            "non-deterministic-id",
            "objects['{0}'] ({1}) is part of a reference cycle; STIX 2.1 "
            "requires a UUIDv4 fallback because the UUIDv5 id-contributing "
            "references cannot be resolved inside the cycle".format(
                key, sco_type,
            ),
            od_id, key,
        )

    # Tarjan yields components in reverse topological order, so every
    # reference target already has an ID when the source is constructed.
    for component in components:
        for key in component:
            if key not in buildable or key in built:
                continue
            raw_sco = objects[key]
            sco_type = raw_sco.get("type")
            sco_dict = _apply_renames(sco_type, raw_sco)
            sco_dict = _drop_removed_properties(sco_type, sco_dict)
            sco_dict = _rewrite_refs(
                key, sco_type, sco_dict, id_map, dropped_pairs,
            )

            try:
                if key in id_map:
                    assigned_id = id_map[key]
                else:
                    v21_class = _v21_sco_class(sco_type)
                    probe_kwargs = copy.deepcopy(sco_dict)
                    probe_kwargs.pop("type", None)
                    if object_marking_refs:
                        probe_kwargs["object_marking_refs"] = sorted(
                            set(object_marking_refs),
                        )
                    probe = v21_class(
                        allow_custom=allow_custom, **probe_kwargs
                    )
                    assigned_id = probe.id
                    id_map[key] = assigned_id
                built[key] = _build_sco(
                    sco_type, sco_dict, assigned_id, allow_custom,
                    object_marking_refs,
                )
            except (STIXError, ValueError) as exc:
                # Typical cause: a lenient-mode reference removal left the
                # object without a required property, or another v2.1 object
                # constraint failed.  In strict mode the collector would
                # already have raised; here we report and skip the object
                # rather than emit something invalid.
                id_map.pop(key, None)
                collector.report(
                    "invalid-object",
                    "objects['{0}'] ({1}) cannot be built as a valid STIX "
                    "2.1 object after migration: {2}".format(
                        key, sco_type, exc,
                    ),
                    od_id, key,
                )

    migratable_markings = _check_granular_markings(
        od_dict, collector, od_id,
    )

    od_kwargs = {}
    for prop_name in (
        "id", "created_by_ref", "created", "modified", "first_observed",
        "last_observed", "number_observed", "revoked", "labels",
        "external_references", "lang", "confidence",
    ):
        if prop_name in od_dict:
            od_kwargs[prop_name] = copy.deepcopy(od_dict[prop_name])
    if object_marking_refs:
        od_kwargs["object_marking_refs"] = list(object_marking_refs)
    if migratable_markings:
        od_kwargs["granular_markings"] = migratable_markings

    for prop_name in sorted(set(od_dict) - _V20_OD_PROPERTIES):
        if allow_custom and _is_custom_name(prop_name):
            od_kwargs[prop_name] = copy.deepcopy(od_dict[prop_name])
        else:
            collector.report(
                "custom-property",
                "observed-data property '{0}' is not defined in STIX 2.1".format(
                    prop_name,
                ),
                od_id, None, prop_name,
            )

    object_refs = sorted(
        id_map[key] for key in objects if key in id_map
    )
    if not object_refs:
        # Every observable was unbuildable (reported above in lenient
        # mode).  A STIX 2.1 observed-data must reference at least one
        # object, so there is no valid output to produce.
        raise MigrationError(
            "no migratable objects remain for observed-data {0}; see the "
            "reported issues for the blocking input problems".format(
                od_id or "<no id>",
            ),
        )
    od_kwargs["object_refs"] = object_refs
    try:
        observed_data = ObservedData(
            allow_custom=allow_custom, **od_kwargs
        )
    except (STIXError, ValueError) as exc:
        # Invalid SDO-level input (e.g. missing required observation fields
        # or an inverted observation window; some v2.1 constraints raise a
        # plain ValueError).  Surface it as a migration error so callers
        # only need to catch MigrationError.
        raise MigrationError(
            "observed-data {0} is not valid STIX 2.1 content: {1}".format(
                od_id or "<no id>", exc,
            ),
        )

    return observed_data, built


def migrate_observed_data(observed_data, strict=True, allow_custom=False):
    """Migrate one STIX 2.0 observed-data object to STIX 2.1.

    Args:
        observed_data (dict or stix2.v20.ObservedData): A STIX 2.0
            observed-data object.  It is never modified.
        strict (bool): When True (the default), raise
            :class:`MigrationError` on any content that cannot be migrated
            1:1.  When False, collect such items as ``MigrationIssue`` in
            the result and keep migrating what can be migrated.
        allow_custom (bool): Carry ``x_``-prefixed custom properties,
            extensions and observable types over to STIX 2.1 instead of
            reporting them.  Non-custom unknown content is always reported.

    Returns:
        MigrationResult: The migrated observed-data and its standalone SCOs.
    """
    od_dict = _as_dict(observed_data)
    collector = _IssueCollector(strict)
    migrated_od, built_scos = _migrate_observed_data(
        od_dict, collector, allow_custom,
    )

    result = MigrationResult()
    result.observed_data = [migrated_od]
    result.issues = collector.issues
    result.scos = _dedupe_scos(built_scos.values())
    return result


def migrate_bundle(bundle, strict=True, allow_custom=False):
    """Migrate every observed-data object in a STIX 2.0 bundle.

    Marking-definition objects are migrated alongside the observed-data so
    that SCO marking references stay resolvable.  Any other bundle object is
    out of scope for this migrator and is returned unchanged in
    ``MigrationResult.extra_objects`` rather than being dropped.

    Args:
        bundle (dict or stix2.v20.Bundle): A STIX 2.0 bundle.
        strict (bool): See :func:`migrate_observed_data`.
        allow_custom (bool): See :func:`migrate_observed_data`.

    Returns:
        MigrationResult: All migrated observed-data, SCOs (de-duplicated
        across observations) and marking-definition objects.
    """
    bundle_dict = _as_dict(bundle)
    if bundle_dict.get("type") != "bundle":
        raise MigrationError(
            "expected a 'bundle' object, got '{0}'".format(
                bundle_dict.get("type"),
            ),
        )

    collector = _IssueCollector(strict)
    result = MigrationResult()
    scos_by_id = {}
    marking_ids = set()

    for item in bundle_dict.get("objects", []):
        item_dict = _as_dict(item)
        item_type = item_dict.get("type")
        if item_type == OBSERVED_DATA_TYPE:
            migrated_od, built_scos = _migrate_observed_data(
                item_dict, collector, allow_custom,
            )
            result.observed_data.append(migrated_od)
            for sco in built_scos.values():
                scos_by_id.setdefault(sco.id, sco)
            marking_ids.update(migrated_od.get("object_marking_refs", []))
        elif item_type == MARKING_DEFINITION_TYPE:
            marking = _migrate_marking_definition(item_dict, allow_custom)
            if not any(existing.id == marking.id for existing in result.markings):
                result.markings.append(marking)
        else:
            collector.report(
                "unsupported-bundle-object",
                "bundle object '{0}' of type '{1}' is outside the "
                "observed-data migration scope and was returned untouched "
                "in extra_objects".format(item_dict.get("id"), item_type),
            )
            result.extra_objects.append(copy.deepcopy(item_dict))

    _check_missing_markings(marking_ids, result.markings, collector)
    result.issues = list(collector.issues)
    result.scos = _dedupe_scos(scos_by_id.values())
    return result


def _migrate_marking_definition(marking_dict, allow_custom):
    kwargs = copy.deepcopy(marking_dict)
    kwargs.pop("type", None)
    try:
        return MarkingDefinition(allow_custom=allow_custom, **kwargs)
    except (STIXError, ValueError) as exc:
        raise MigrationError(
            "marking-definition {0} is not valid STIX 2.1 content: {1}".format(
                marking_dict.get("id") or "<no id>", exc,
            ),
        )


def _check_missing_markings(marking_ids, markings, collector):
    available = {marking.id for marking in markings}
    for marking_id in sorted(marking_ids - available):
        collector.report(
            "missing-marking-definition",
            "object_marking_refs points at {0}, but no marking-definition "
            "with that id is present in the bundle; the reference is kept "
            "but the marking object must be supplied separately".format(
                marking_id,
            ),
        )


def _dedupe_scos(scos):
    by_id = {}
    for sco in scos:
        by_id.setdefault(sco.id, sco)
    return [by_id[sco_id] for sco_id in sorted(by_id)]


def _as_dict(obj):
    if isinstance(obj, dict):
        return copy.deepcopy(obj)
    # _STIXBase objects are immutable Mappings; round-tripping through JSON
    # yields a plain, fully detached dict and also covers embedded SCOs.
    if hasattr(obj, "serialize"):
        return json.loads(obj.serialize())
    raise MigrationError(
        "unsupported input type {0}; expected a dict or STIX object".format(
            type(obj).__name__,
        ),
    )
