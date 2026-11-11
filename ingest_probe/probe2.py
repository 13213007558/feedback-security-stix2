"""Follow-up probes: registered custom types and reference whitelists."""
import json
import stix2
from stix2 import CustomObject
from stix2.properties import StringProperty, IntegerProperty

V4 = "412aba5b-75b4-4827-99f1-c62d91504e97"

@CustomObject("x-acme-asset", [
    ("name", StringProperty(required=True)),
    ("risk", IntegerProperty()),
])
class Asset:
    pass

CASES = [
    ("A2a registered-custom, valid values",
     {"type": "x-acme-asset", "spec_version": "2.1",
      "id": "x-acme-asset--" + V4, "name": "gw", "risk": 5}),
    ("A2b registered-custom, wrong value type",
     {"type": "x-acme-asset", "spec_version": "2.1",
      "id": "x-acme-asset--" + V4, "name": "gw", "risk": "HIGH"}),
    ("A2c registered-custom, missing required",
     {"type": "x-acme-asset", "spec_version": "2.1",
      "id": "x-acme-asset--" + V4}),
    ("D1a ref to custom type via GENERIC whitelist (report.object_refs)",
     {"type": "report", "spec_version": "2.1", "id": "report--" + V4,
      "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
      "name": "r", "published": "2026-01-01T00:00:00.000Z",
      "object_refs": ["x-acme-foobar--" + V4]}),
    ("D1b ref to custom type via SPECIFIC whitelist (created_by_ref)",
     {"type": "indicator", "spec_version": "2.1", "id": "indicator--" + V4,
      "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
      "pattern": "[ipv4-addr:value = '1.2.3.4']", "pattern_type": "stix",
      "valid_from": "2026-01-01T00:00:00.000Z",
      "created_by_ref": "x-acme-identity--" + V4}),
    ("D3 malformed ref id",
     {"type": "indicator", "spec_version": "2.1", "id": "indicator--" + V4,
      "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
      "pattern": "[ipv4-addr:value = '1.2.3.4']", "pattern_type": "stix",
      "valid_from": "2026-01-01T00:00:00.000Z",
      "created_by_ref": "identity--not-a-uuid"}),
]

FLAG_SETS = [
    ("strict ", dict()),
    ("custom ", dict(allow_custom=True)),
]

for name, data in CASES:
    print("### %s" % name)
    for label, flags in FLAG_SETS:
        try:
            obj = stix2.parse(json.dumps(data), **flags)
            res = "OK(raw-dict)" if isinstance(obj, dict) else "OK(%s)%s" % (
                type(obj).__name__, "+custom" if getattr(obj, "has_custom", False) else "")
        except Exception as exc:
            res = "REJECT %s: %s" % (type(exc).__name__, str(exc)[:90])
        print("  %-8s %s" % (label, res))
    print()
