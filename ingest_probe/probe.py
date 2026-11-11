"""Probe: what stix2.parse() actually guarantees under allow_custom / interoperability.

Each case is parsed with strict flags and with relaxed flags.
OK(dict)  = returned UNVALIDATED raw dict (unknown type passthrough)
OK(obj)   = returned a stix2 object (validated to some degree)
REJECT    = raised an exception
"""
import json
import stix2
from stix2 import CustomObject, CustomObservable
from stix2.properties import StringProperty, IntegerProperty

V4 = "412aba5b-75b4-4827-99f1-c62d91504e97"      # valid RFC4122 v4 UUID
ZERO = "00000000-0000-0000-0000-000000000000"     # not an RFC4122-variant UUID
EXTDEF = "extension-definition--" + V4

@CustomObject("x-acme-asset", [
    ("name", StringProperty(required=True)),
    ("risk", IntegerProperty()),
])
class Asset:
    pass

BASE_INDICATOR = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--" + V4,
    "created": "2026-01-01T00:00:00.000Z",
    "modified": "2026-01-01T00:00:00.000Z",
    "pattern": "[ipv4-addr:value = '1.2.3.4']",
    "pattern_type": "stix",
    "valid_from": "2026-01-01T00:00:00.000Z",
}

def ind(**extra):
    d = dict(BASE_INDICATOR)
    d.update(extra)
    return d

CASES = [
    # --- group 1: type resolution ---
    ("A1 builtin-clean",
     ind(), {}),
    ("A2 registered-custom-type",
     {"type": "x-acme-asset", "spec_version": "2.1",
      "id": "x-acme-asset--" + V4, "name": "gw", "risk": "HIGH"}, {}),
    ("A3 unknown-type",
     {"type": "x-acme-foobar", "id": "not-even-an-id", "anything": [1, 2]}, {}),
    ("A4 unknown-type+extdef(new-sdo)",
     {"type": "x-acme-foobar", "spec_version": "2.1",
      "extensions": {EXTDEF: {"extension_type": "new-sdo"}}}, {}),
    # --- group 2: property-level customization on a builtin type ---
    ("B1 x_-property",
     ind(x_acme_score="ninety-nine"), {}),
    ("B2 custom_properties-key",
     ind(custom_properties={"x_evil": 1}), {}),
    ("B3 unregistered-toplevel-ext",
     ind(extensions={EXTDEF: {"extension_type": "toplevel-property-extension"}},
         x_smuggled="yes"), {}),
    # --- group 3: extensions on observables ---
    ("C1 unknown-extdef-extension",
     {"type": "file", "spec_version": "2.1", "id": "file--" + V4,
      "name": "a.exe",
      "extensions": {EXTDEF: {"whatever": {"nested": "no-schema"}}}}, {}),
    ("C2 unknown-plain-extension",
     {"type": "file", "spec_version": "2.1", "id": "file--" + V4,
      "name": "a.exe",
      "extensions": {"x-acme-ext": {"whatever": 1}}}, {}),
    # --- group 4: references ---
    ("D1 ref-to-custom-type",
     ind(created_by_ref="x-acme-identity--" + V4), {}),
    ("D2 ref-to-nonexistent-builtin",
     ind(created_by_ref="identity--" + V4), {}),
    # --- group 5: identifiers / interoperability ---
    ("E1 non-rfc4122-uuid",
     ind(id="indicator--" + ZERO), {}),
    # --- group 6: required props & vocab & pattern ---
    ("F1 missing-required-pattern",
     {k: v for k, v in ind().items() if k != "pattern"}, {}),
    ("F2 openvocab-not-enforced",
     ind(pattern_type="x-acme-dsl", pattern="THIS IS NOT STIX PATTERN SYNTAX"), {}),
    # --- group 7: version selection ---
    ("G1 bogus-spec_version",
     ind(spec_version="9.9"), {}),
    ("G2 unknown-type-no-specver",
     {"type": "x-acme-foobar", "id": "x-acme-foobar--" + V4}, {}),
]

FLAG_SETS = [
    ("strict  (allow_custom=F, interop=F)", dict()),
    ("custom  (allow_custom=T, interop=F)", dict(allow_custom=True)),
    ("interop (allow_custom=F, interop=T)", dict(interoperability=True)),
    ("both    (allow_custom=T, interop=T)", dict(allow_custom=True, interoperability=True)),
]

def attempt(data, flags):
    try:
        obj = stix2.parse(json.dumps(data), **flags)
    except Exception as exc:
        return "REJECT %s" % type(exc).__name__
    if isinstance(obj, dict):
        return "OK(raw-dict, NO validation)"
    tag = "OK(%s)" % type(obj).__name__
    if getattr(obj, "has_custom", False):
        tag += "+custom"
    return tag

for name, data, _ in CASES:
    print("\n### %s" % name)
    for label, flags in FLAG_SETS:
        print("  %-38s %s" % (label, attempt(data, flags)))
