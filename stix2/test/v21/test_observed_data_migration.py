"""Tests for the STIX 2.0 -> 2.1 observed-data migration entry point.

The assertions compare reference topology and data semantics after a full
serialize -> re-parse round trip, rather than object identity or ordering.
"""

import copy
import json
import uuid

import pytest

import stix2
from stix2.migration import (
    MigrationError, MigrationIssue, migrate_bundle,
    migrate_observed_data,
)

MARKING_ID = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
OD_ID = "observed-data--8e9b2b22-1b9e-4f09-9b33-d0d4c9f0a111"


def make_observed_data(objects, od_id=OD_ID, **extra):
    od = {
        "type": "observed-data",
        "id": od_id,
        "created": "2020-01-01T00:00:00.000Z",
        "modified": "2020-01-01T00:00:00.000Z",
        "first_observed": "2020-01-01T00:00:00.000Z",
        "last_observed": "2020-01-01T00:01:00.000Z",
        "number_observed": 3,
        "objects": objects,
    }
    od.update(extra)
    return od


def reparse(obj):
    return stix2.parse(obj.serialize(), version="2.1")


def sco_by_type(result, sco_type):
    matches = [sco for sco in result.scos if sco.type == sco_type]
    assert len(matches) == 1
    return matches[0]


# ---------------------------------------------------------------------------
# Basic graph migration and round-trip semantics
# ---------------------------------------------------------------------------

def test_basic_graph_migration_and_reparse():
    v20 = make_observed_data({
        "0": {"type": "ipv4-addr", "value": "10.0.0.1"},
        "1": {"type": "ipv4-addr", "value": "10.0.0.2"},
        "2": {
            "type": "network-traffic", "src_ref": "0", "dst_ref": "1",
            "protocols": ["tcp"], "dst_port": 443,
        },
    })

    result = migrate_observed_data(v20)

    od = reparse(result.observed_data[0])
    assert od.type == "observed-data"
    assert od.spec_version == "2.1"
    assert od.id == OD_ID
    assert od.first_observed.year == 2020
    assert od.number_observed == 3
    assert "objects" not in od
    assert set(od.object_refs) == {sco.id for sco in result.scos}

    # Every SCO round-trips and keeps its generated identity.
    reparsed_scos = [reparse(sco) for sco in result.scos]
    assert {sco.id for sco in reparsed_scos} == set(od.object_refs)

    nt = next(s for s in reparsed_scos if s.type == "network-traffic")
    ips = {s.value: s.id for s in reparsed_scos if s.type == "ipv4-addr"}
    # Reference topology preserved semantically.
    assert nt.src_ref == ips["10.0.0.1"]
    assert nt.dst_ref == ips["10.0.0.2"]
    assert nt.dst_port == 443


def test_input_is_not_mutated():
    v20 = make_observed_data({
        "0": {"type": "file", "name": "a.txt",
              "hashes": {"SHA-256": "a" * 64}},
    })
    snapshot = json.dumps(v20, sort_keys=True)

    migrate_observed_data(v20)

    assert json.dumps(v20, sort_keys=True) == snapshot


def test_accepts_parsed_v20_object_without_mutating_it():
    v20_obj = stix2.parse(
        make_observed_data({
            "0": {"type": "domain-name", "value": "a.example",
                  "resolves_to_refs": ["1"]},
            "1": {"type": "ipv4-addr", "value": "2.2.2.2"},
        }),
        version="2.0",
    )
    before = v20_obj.serialize()

    result = migrate_observed_data(v20_obj)

    assert v20_obj.serialize() == before
    dn = sco_by_type(result, "domain-name")
    ip = sco_by_type(result, "ipv4-addr")
    assert dn.resolves_to_refs == [ip.id]


# ---------------------------------------------------------------------------
# Deterministic identity and ordering independence
# ---------------------------------------------------------------------------

def test_output_order_does_not_change_identities():
    graph_a = make_observed_data({
        "0": {"type": "ipv4-addr", "value": "1.1.1.1"},
        "1": {"type": "network-traffic", "dst_ref": "0",
              "protocols": ["tcp"]},
    })
    graph_b = make_observed_data({
        "7": {"type": "network-traffic", "dst_ref": "3",
              "protocols": ["tcp"]},
        "3": {"type": "ipv4-addr", "value": "1.1.1.1"},
    })

    ids_a = {sco.id for sco in migrate_observed_data(graph_a).scos}
    ids_b = {sco.id for sco in migrate_observed_data(graph_b).scos}
    assert ids_a == ids_b

    # UUIDv5 for the id-contributing SCOs (not a random UUIDv4).
    for sco_id in ids_a:
        assert uuid.UUID(sco_id.split("--", 1)[1]).version == 5


def test_shared_reference_is_deduplicated_to_one_sco():
    v20 = make_observed_data({
        "0": {"type": "file", "name": "a.txt",
              "hashes": {"SHA-256": "a" * 64}},
        "1": {"type": "directory", "path": "/x", "contains_refs": ["0"]},
        "2": {"type": "directory", "path": "/y", "contains_refs": ["0"]},
    })

    result = migrate_observed_data(v20)

    files = [sco for sco in result.scos if sco.type == "file"]
    assert len(files) == 1
    dirs = [sco for sco in result.scos if sco.type == "directory"]
    assert {tuple(d.contains_refs) for d in dirs} == {(files[0].id,)}


def test_separate_observations_are_never_merged():
    shared_ip = {"type": "ipv4-addr", "value": "1.1.1.1"}
    bundle = {
        "type": "bundle",
        "id": "bundle--11111111-1111-4111-8111-1111111111111",
        "objects": [
            make_observed_data(
                {"0": dict(shared_ip)},
                od_id="observed-data--aaaaaaaa-1111-4111-8111-111111111111",
                number_observed=1,
            ),
            make_observed_data(
                {"0": dict(shared_ip),
                 "1": {"type": "network-traffic", "dst_ref": "0",
                       "protocols": ["tcp"]}},
                od_id="observed-data--bbbbbbbb-2222-4222-8222-222222222222",
                first_observed="2020-01-02T00:00:00.000Z",
                last_observed="2020-01-02T00:05:00.000Z",
                number_observed=4,
            ),
        ],
    }

    result = migrate_bundle(bundle)

    assert len(result.observed_data) == 2
    assert {od.id for od in result.observed_data} == {
        "observed-data--aaaaaaaa-1111-4111-8111-111111111111",
        "observed-data--bbbbbbbb-2222-4222-8222-222222222222",
    }
    # Shared SCO collapses to one identity, observations stay distinct.
    assert len(result.scos) == 2
    counts = sorted(od.number_observed for od in result.observed_data)
    assert counts == [1, 4]
    bundle_obj = stix2.parse(result.as_bundle().serialize(), version="2.1")
    assert bundle_obj.type == "bundle"


# ---------------------------------------------------------------------------
# Reference cycles
# ---------------------------------------------------------------------------

def test_two_node_cycle_uses_uuid4_and_keeps_topology():
    v20 = make_observed_data({
        "0": {"type": "ipv4-addr", "value": "9.9.9.9"},
        "1": {"type": "network-traffic", "src_ref": "0", "protocols": ["tcp"],
              "encapsulates_refs": ["2"]},
        "2": {"type": "network-traffic", "src_ref": "0", "protocols": ["udp"],
              "encapsulates_by_ref": "1"},
    })

    with pytest.raises(MigrationError):
        migrate_observed_data(v20)

    result = migrate_observed_data(v20, strict=False)
    assert {issue.code for issue in result.issues} == {"non-deterministic-id"}
    nts = [sco for sco in result.scos if sco.type == "network-traffic"]
    assert len(nts) == 2
    by_protocol = {nt.protocols[0]: nt for nt in nts}
    assert all(
        uuid.UUID(nt.id.split("--", 1)[1]).version == 4 for nt in nts
    )
    assert by_protocol["tcp"].encapsulates_refs == [by_protocol["udp"].id]
    assert by_protocol["udp"].encapsulated_by_ref == by_protocol["tcp"].id


def test_self_loop_is_reported_and_preserved():
    v20 = make_observed_data({
        "0": {"type": "directory", "path": "/loop",
              "contains_refs": ["0"]},
    })

    result = migrate_observed_data(v20, strict=False)
    assert {issue.code for issue in result.issues} == {"non-deterministic-id"}
    directory = result.scos[0]
    assert uuid.UUID(directory.id.split("--", 1)[1]).version == 4
    assert directory.contains_refs == [directory.id]


# ---------------------------------------------------------------------------
# Missing / invalid references
# ---------------------------------------------------------------------------

def test_missing_reference_is_rejected_in_strict_mode():
    v20 = make_observed_data({
        "0": {"type": "network-traffic", "dst_ref": "9",
              "protocols": ["tcp"]},
    })
    with pytest.raises(MigrationError, match="missing-reference"):
        migrate_observed_data(v20)


def test_missing_reference_is_reported_in_lenient_mode():
    v20 = make_observed_data({
        "0": {"type": "ipv4-addr", "value": "8.8.8.8"},
        "1": {"type": "network-traffic", "dst_ref": "9",
              "protocols": ["tcp"]},
    })

    result = migrate_observed_data(v20, strict=False)

    codes = {issue.code for issue in result.issues}
    assert {"missing-reference", "invalid-object"} <= codes
    surviving = [sco for sco in result.scos if sco.type == "network-traffic"]
    assert surviving == []
    od = result.observed_data[0]
    assert od.object_refs == [sco_by_type(result, "ipv4-addr").id]


def test_invalid_reference_type_is_rejected():
    v20 = make_observed_data({
        "0": {"type": "file", "name": "f"},
        "1": {"type": "network-traffic", "src_ref": "0",
              "protocols": ["tcp"]},
    })
    with pytest.raises(MigrationError, match="invalid-reference-type"):
        migrate_observed_data(v20)


def test_fully_broken_graph_raises_even_in_lenient_mode():
    v20 = make_observed_data({
        "0": {"type": "network-traffic", "dst_ref": "9",
              "protocols": ["tcp"]},
    })
    with pytest.raises(MigrationError, match="no migratable objects remain"):
        migrate_observed_data(v20, strict=False)


# ---------------------------------------------------------------------------
# Markings
# ---------------------------------------------------------------------------

def test_object_markings_propagate_to_scos_and_observed_data():
    v20 = make_observed_data(
        {"0": {"type": "ipv4-addr", "value": "5.5.5.5"}},
        object_marking_refs=[MARKING_ID],
    )

    result = migrate_observed_data(v20)

    assert list(result.scos[0].object_marking_refs) == [MARKING_ID]
    assert list(result.observed_data[0].object_marking_refs) == [MARKING_ID]


def test_bundle_migrates_marking_definitions_and_flags_missing_one():
    bundle = {
        "type": "bundle",
        "id": "bundle--22222222-2222-4222-8222-222222222222",
        "objects": [
            {
                "type": "marking-definition", "id": MARKING_ID,
                "definition_type": "statement",
                "definition": {"statement": "copyright acme"},
            },
            make_observed_data(
                {"0": {"type": "ipv4-addr", "value": "5.5.5.5"}},
                object_marking_refs=[
                    MARKING_ID,
                    "marking-definition--9f2b1c00-0000-4000-8000-000000000000",
                ],
            ),
        ],
    }

    result = migrate_bundle(bundle, strict=False)

    assert [m.id for m in result.markings] == [MARKING_ID]
    assert any(
        issue.code == "missing-marking-definition" for issue in result.issues
    )


def test_object_scoped_granular_marking_needs_manual_review():
    v20 = make_observed_data(
        {"0": {"type": "ipv4-addr", "value": "2.2.2.2"}},
        granular_markings=[
            {"marking_ref": MARKING_ID,
             "selectors": ["objects.0.value"]},
            {"marking_ref": MARKING_ID,
             "selectors": ["number_observed"]},
        ],
    )

    with pytest.raises(MigrationError, match="granular-marking-selector"):
        migrate_observed_data(v20)

    result = migrate_observed_data(v20, strict=False)
    assert any(
        issue.code == "granular-marking-selector" for issue in result.issues
    )
    # The SDO-level selector still has an equivalent and is kept.
    gm = result.observed_data[0].granular_markings
    assert [marking.selectors for marking in gm] == [["number_observed"]]


# ---------------------------------------------------------------------------
# Property renames and removals
# ---------------------------------------------------------------------------

def test_renamed_properties_are_migrated():
    v20 = make_observed_data({
        "0": {
            "type": "file", "name": "f",
            "created": "2020-01-01T00:00:00Z",
            "modified": "2020-01-02T00:00:00Z",
            "accessed": "2020-01-03T00:00:00Z",
        },
        "1": {"type": "ipv4-addr", "value": "7.7.7.7"},
        "2": {
            "type": "network-traffic", "src_ref": "1", "protocols": ["tcp"],
            "encapsulates_by_ref": "3",
        },
        "3": {"type": "network-traffic", "src_ref": "1",
              "protocols": ["udp"]},
        "4": {"type": "process", "pid": 9,
              "created": "2020-01-01T00:00:00Z", "binary_ref": "0"},
    })

    result = migrate_observed_data(v20)
    f = sco_by_type(result, "file")
    assert f.ctime.year == 2020 and f.mtime.year == 2020 and f.atime.year == 2020

    tcp = next(
        sco for sco in result.scos
        if sco.type == "network-traffic" and sco.protocols == ["tcp"]
    )
    udp = next(
        sco for sco in result.scos
        if sco.type == "network-traffic" and sco.protocols == ["udp"]
    )
    assert tcp.encapsulated_by_ref == udp.id

    proc = sco_by_type(result, "process")
    assert proc.created_time.year == 2020
    assert proc.image_ref == f.id


def test_removed_properties_are_rejected_or_reported_never_dropped_silently():
    v20 = make_observed_data({
        "0": {"type": "file", "name": "f", "is_encrypted": True},
    })
    with pytest.raises(MigrationError, match="removed-property"):
        migrate_observed_data(v20)

    result = migrate_observed_data(v20, strict=False)
    assert any(
        issue.code == "removed-property" for issue in result.issues
    )
    assert "is_encrypted" not in result.scos[0]


def test_removed_extension_property_is_flagged():
    v20 = make_observed_data({
        "0": {
            "type": "file", "name": "inner.bin",
            "hashes": {"SHA-256": "c" * 64},
        },
        "1": {
            "type": "file", "name": "a.zip",
            "extensions": {"archive-ext": {
                "contains_refs": ["0"], "version": "1.0",
                "comment": "c",
            }},
        },
    })
    with pytest.raises(MigrationError, match="removed-extension-property"):
        migrate_observed_data(v20)

    result = migrate_observed_data(v20, strict=False)
    arc = next(sco for sco in result.scos if sco.name == "a.zip")
    ext = arc.extensions["archive-ext"]
    assert "version" not in ext
    inner = next(sco for sco in result.scos if sco.name == "inner.bin")
    # Extension-internal local reference is rewritten to a STIX id.
    assert ext.contains_refs == [inner.id]


def test_extension_internal_http_reference_is_rewired():
    v20 = make_observed_data({
        "0": {"type": "artifact", "payload_bin": "aGk=",
              "mime_type": "text/plain"},
        "1": {"type": "ipv4-addr", "value": "4.4.4.4"},
        "2": {
            "type": "network-traffic", "src_ref": "1", "protocols": ["http"],
            "extensions": {"http-request-ext": {
                "request_method": "POST", "request_value": "/x",
                "message_body_data_ref": "0",
            }},
        },
    })

    result = migrate_observed_data(v20)
    nt = sco_by_type(result, "network-traffic")
    artifact = sco_by_type(result, "artifact")
    assert (
        nt.extensions["http-request-ext"].message_body_data_ref
        == artifact.id
    )


# ---------------------------------------------------------------------------
# Custom content
# ---------------------------------------------------------------------------

def test_custom_property_is_rejected_then_opted_in():
    v20 = make_observed_data({
        "0": {"type": "file", "name": "f", "x_sensitivity": "high"},
    })
    with pytest.raises(MigrationError, match="custom-property"):
        migrate_observed_data(v20)

    result = migrate_observed_data(v20, strict=False, allow_custom=True)
    assert result.scos[0].x_sensitivity == "high"
    assert result.scos[0].has_custom is True


def test_registered_custom_observable_migrates_when_allowed():
    from stix2.properties import StringProperty
    from stix2.v20 import CustomObservable as CustomObservable20
    from stix2.v21 import CustomObservable as CustomObservable21

    @CustomObservable20("x-asset", [
        ("owner", StringProperty(required=True)),
    ])
    class Asset20:
        pass

    @CustomObservable21("x-asset", [
        ("owner", StringProperty(required=True)),
    ])
    class Asset21:
        pass

    v20 = make_observed_data({
        "0": {"type": "x-asset", "owner": "alice"},
    })
    # Without allow_custom the custom type cannot be referenced from a
    # standard observed-data object.
    with pytest.raises(MigrationError):
        migrate_observed_data(v20)

    result = migrate_observed_data(v20, strict=False, allow_custom=True)
    sco = result.scos[0]
    assert sco.type == "x-asset"
    assert sco.owner == "alice"
    assert sco.id.startswith("x-asset--")
    # No id-contributing properties were declared on the custom type, so the
    # STIX 2.1 UUIDv4 fallback applies.
    assert uuid.UUID(sco.id.split("--", 1)[1]).version == 4


def test_unknown_observable_type_is_reported_and_skipped():
    v20 = make_observed_data({
        "0": {"type": "file", "name": "f"},
        "1": {"type": "x-gadget", "a": 1},
    })
    with pytest.raises(MigrationError, match="unknown-observable-type"):
        migrate_observed_data(v20)

    result = migrate_observed_data(v20, strict=False, allow_custom=True)
    assert any(
        issue.code == "unknown-observable-type" for issue in result.issues
    )
    assert all(sco.type != "x-gadget" for sco in result.scos)


def test_unknown_non_custom_property_is_always_rejected():
    v20 = make_observed_data({
        "0": {"type": "file", "name": "f", "bogus_prop": 1},
    })
    with pytest.raises(MigrationError, match="unknown-property"):
        migrate_observed_data(v20, strict=False, allow_custom=True)


# ---------------------------------------------------------------------------
# Bundle-level behaviour and result shape
# ---------------------------------------------------------------------------

def test_bundle_returns_unsupported_objects_instead_of_dropping_them():
    bundle = {
        "type": "bundle",
        "id": "bundle--33333333-3333-4333-8333-333333333333",
        "objects": [
            make_observed_data({"0": {"type": "url", "value": "https://x"}}),
            {
                "type": "indicator",
                "id": "indicator--cccccccc-3333-4333-8333-333333333333",
                "created": "2020-01-01T00:00:00Z",
                "modified": "2020-01-01T00:00:00Z",
                "pattern": "[url:value = 'https://x']",
                "valid_from": "2020-01-01T00:00:00Z",
            },
        ],
    }

    result = migrate_bundle(bundle, strict=False)

    assert any(
        issue.code == "unsupported-bundle-object" for issue in result.issues
    )
    assert result.extra_objects[0]["type"] == "indicator"


def test_migration_issue_is_a_value_object():
    issue = MigrationIssue(
        "code", "msg", "observed-data--x", "0", "path",
    )
    assert issue == MigrationIssue("code", "msg", "observed-data--x", "0",
                                   "path")
    assert issue.to_dict()["code"] == "code"


def test_non_bundle_input_is_rejected():
    with pytest.raises(MigrationError, match="expected a 'bundle'"):
        migrate_bundle({"type": "identity", "id": "identity--x"})


def test_missing_or_empty_objects_is_rejected():
    base = {
        "type": "observed-data",
        "id": "observed-data--77777777-7777-4777-8777-777777777777",
        "first_observed": "2020-01-01T00:00:00.000Z",
        "last_observed": "2020-01-01T00:01:00.000Z",
        "number_observed": 1,
    }
    with pytest.raises(MigrationError, match="'objects' mapping"):
        migrate_observed_data(dict(base))
    with pytest.raises(MigrationError, match="'objects' mapping"):
        migrate_observed_data(dict(base, objects={}))


def test_invalid_sdo_input_is_wrapped_as_migration_error():
    with pytest.raises(MigrationError, match="not valid STIX 2.1"):
        migrate_observed_data(make_observed_data(
            {"0": {"type": "url", "value": "http://x"}},
            # last_observed before first_observed
            first_observed="2020-01-02T00:00:00.000Z",
            last_observed="2020-01-01T00:01:00.000Z",
        ))


def test_empty_bundle_produces_empty_result():
    result = migrate_bundle({
        "type": "bundle",
        "id": "bundle--44444444-4444-4444-8444-444444444444",
        "objects": [],
    })
    assert result.objects == []
    assert result.as_bundle().type == "bundle"


def test_bundle_deduplicates_markings_and_preserves_od_order():
    marking = {
        "type": "marking-definition", "id": MARKING_ID,
        "definition_type": "statement",
        "definition": {"statement": "c"},
    }
    od_a = make_observed_data(
        {"0": {"type": "url", "value": "http://a"}},
        od_id="observed-data--aaaaaaaa-1111-4111-8111-111111111111",
        object_marking_refs=[MARKING_ID],
    )
    od_b = make_observed_data(
        {"0": {"type": "url", "value": "http://b"}},
        od_id="observed-data--bbbbbbbb-2222-4222-8222-222222222222",
        object_marking_refs=[MARKING_ID],
    )
    bundle = {
        "type": "bundle",
        "id": "bundle--66666666-6666-4666-8666-666666666666",
        # The same marking appears twice and must collapse to one.
        "objects": [marking, od_a, marking, od_b],
    }

    result = migrate_bundle(bundle)

    assert [m.id for m in result.markings] == [MARKING_ID]
    assert [od.id for od in result.observed_data] == [
        "observed-data--aaaaaaaa-1111-4111-8111-111111111111",
        "observed-data--bbbbbbbb-2222-4222-8222-222222222222",
    ]


def test_bundle_reparse_keeps_reference_closure():
    bundle = {
        "type": "bundle",
        "id": "bundle--55555555-5555-4555-8555-555555555555",
        "objects": [
            {
                "type": "marking-definition", "id": MARKING_ID,
                "definition_type": "statement",
                "definition": {"statement": "c"},
            },
            make_observed_data(
                {"0": {"type": "email-addr", "value": "a@b.com"}},
                object_marking_refs=[MARKING_ID],
            ),
        ],
    }
    result = migrate_bundle(bundle)
    bundle_obj = stix2.parse(
        result.as_bundle().serialize(), version="2.1",
    )
    ids = {obj.id for obj in bundle_obj.objects}
    for obj in bundle_obj.objects:
        for ref in obj.get("object_marking_refs", []):
            assert ref in ids
        if obj.type == "observed-data":
            for ref in obj.object_refs:
                assert ref in ids



def test_deep_copy_semantics_keep_input_extensions_intact():
    v20 = make_observed_data({
        "0": {
            "type": "file", "name": "f",
            "extensions": {"ntfs-ext": {"sid": "S-1-5-18"}},
        },
    })
    snapshot = copy.deepcopy(v20)

    result = migrate_observed_data(v20)

    assert v20 == snapshot
    sco = result.scos[0]
    assert sco.extensions["ntfs-ext"].sid == "S-1-5-18"
