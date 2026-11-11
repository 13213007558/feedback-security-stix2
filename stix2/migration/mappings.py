"""Static knowledge needed to move STIX 2.0 cyber observables to STIX 2.1.

STIX 2.1 renamed a handful of SCO properties and removed a few that no longer
have a spec-defined meaning.  The renames are safe, mechanical 1:1 moves.  The
removals are *not* guessed at: the migrator reports them for human review
rather than folding the value into some unrelated property.
"""

from ..properties import ListProperty, ObjectReferenceProperty

# Properties that kept the exact same semantics but changed name in STIX 2.1.
# Keyed by SCO type: {old_name: new_name}.
SCO_PROPERTY_RENAMES = {
    "directory": {
        "created": "ctime",
        "modified": "mtime",
        "accessed": "atime",
    },
    "file": {
        "created": "ctime",
        "modified": "mtime",
        "accessed": "atime",
    },
    "network-traffic": {
        "encapsulates_by_ref": "encapsulated_by_ref",
    },
    "process": {
        "created": "created_time",
        "binary_ref": "image_ref",
    },
    "user-account": {
        "password_last_changed": "credential_last_changed",
    },
    "windows-registry-key": {
        "modified": "modified_time",
    },
}

# v2.0 properties with no STIX 2.1 equivalent on the same object.  These must
# be reported, never silently discarded.
SCO_PROPERTY_REMOVALS = {
    "file": ["is_encrypted", "encryption_algorithm", "decryption_key"],
    "process": ["name", "arguments"],
}

# Properties dropped from embedded SCO extensions between 2.0 and 2.1.
EXTENSION_PROPERTY_REMOVALS = {
    "archive-ext": ["version"],
    "raster-image-ext": ["image_compression_algorithm"],
    "socket-ext": ["protocol_family"],
}


def reference_property_names(sco_class):
    """Return the names of local object-reference properties on a v2.0 SCO.

    Local references are the numeric ``objects``-dictionary references (e.g.
    ``src_ref`` -> ``"2"``), represented by
    :class:`~stix2.properties.ObjectReferenceProperty`.  They are distinct from
    :class:`~stix2.properties.ReferenceProperty` fields such as
    ``object_marking_refs``, which point at bundle-level objects by STIX ID
    and are not part of the observed-data local scope.
    """
    names = []
    for prop_name, prop in sco_class._properties.items():
        contained = prop.contained if isinstance(prop, ListProperty) else prop
        if isinstance(contained, ObjectReferenceProperty):
            names.append(prop_name)
    return names
