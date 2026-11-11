"""Tests for controlled export according to data markings."""

import copy
import json

import pytest

from stix2 import (
    ControlledExportResult, Malware, Report, controlled_export, parse,
)
from stix2.v21 import TLP_RED, Indicator

from .constants import MARKING_IDS

M0, M1, M2 = MARKING_IDS[:3]

MALWARE_BASE = dict(
    type="malware",
    id="malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
    created="2016-04-06T20:03:00.000Z",
    modified="2016-04-06T20:03:00.000Z",
    name="Cryptolocker",
    is_family=False,
)


def test_result_type_and_repr():
    obj = Malware(**MALWARE_BASE)
    result = controlled_export(obj, [])

    assert isinstance(result, ControlledExportResult)
    assert result.exportable
    assert result.stix_object is not None
    assert result.reason is None
    assert "exportable=True" in repr(result)

    withheld = ControlledExportResult(reason="blocked")
    assert not withheld.exportable
    assert withheld.stix_object is None
    assert "exportable=False" in repr(withheld)


def test_unmarked_object_fully_exported_with_empty_allow_list():
    obj = Malware(**MALWARE_BASE)
    result = controlled_export(obj, [])

    assert result.exportable
    assert result.removed_paths == []
    assert result.disallowed_markings == []
    assert result.stix_object.serialize() == obj.serialize()


def test_disallowed_granular_property_is_removed():
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description"]},
        ],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert "description" not in exported
    assert result.removed_paths == ["description"]
    assert result.disallowed_markings == [M0]
    # The disallowed marking entry itself no longer appears in the output.
    assert all(
        marking.get("marking_ref") != M0
        for marking in exported.get("granular_markings", [])
    )


def test_allowed_granular_property_is_kept():
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description"]},
        ],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M0])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["description"] == "sensitive"
    assert result.removed_paths == []


def test_all_markings_on_a_path_must_be_allowed():
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description"]},
            {"marking_ref": M1, "selectors": ["description"]},
        ],
        **MALWARE_BASE,
    )

    partially_allowed = controlled_export(obj, [M0])
    assert "description" not in json.loads(
        partially_allowed.stix_object.serialize(),
    )

    fully_allowed = controlled_export(obj, [M0, M1])
    assert "description" in json.loads(fully_allowed.stix_object.serialize())


def test_granular_marking_is_inherited_by_descendants():
    data = {
        **MALWARE_BASE,
        "spec_version": "2.1",
        "x_tree": {"child": {"leaf": "secret", "shown": 1}},
        "granular_markings": [
            {"marking_ref": M0, "selectors": ["x_tree.child.leaf"]},
        ],
    }
    # Mark the parent instead, so every descendant must be withheld.
    data["granular_markings"] = [
        {"marking_ref": M0, "selectors": ["x_tree"]},
    ]
    result = controlled_export(data, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert "x_tree" not in exported
    assert result.removed_paths == ["x_tree"]


def test_nested_dict_filtering_keeps_siblings():
    data = {
        **MALWARE_BASE,
        "spec_version": "2.1",
        "x_tree": {
            "zero": 0,
            "flag": False,
            "empty": "",
            "shown": "ok",
        },
        "granular_markings": [
            {
                "marking_ref": M0,
                "selectors": [
                    "x_tree.zero",
                    "x_tree.flag",
                    "x_tree.empty",
                ],
            },
        ],
    }
    result = controlled_export(data, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    # Falsy values are real values and are handled exactly like truthy ones.
    assert exported["x_tree"] == {"shown": "ok"}
    assert set(result.removed_paths) == {
        "x_tree.zero",
        "x_tree.flag",
        "x_tree.empty",
    }


def test_falsy_top_level_values_are_not_accidentally_dropped():
    obj = Malware(
        x_zero=0,
        x_flag=False,
        x_empty="",
        allow_custom=True,
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["x_zero"] == 0
    assert exported["x_flag"] is False
    assert exported["x_empty"] == ""


def test_list_elements_are_removed_and_indices_remapped():
    obj = Malware(
        aliases=["a0", "a1", "a2", "a3"],
        granular_markings=[
            {"marking_ref": M0, "selectors": ["aliases.[0]", "aliases.[1]"]},
            {"marking_ref": M1, "selectors": ["aliases.[3]"]},
        ],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["aliases"] == ["a2", "a3"]

    surviving_marking = [
        marking for marking in exported["granular_markings"]
        if marking.get("marking_ref") == M1
    ][0]
    # The old element at index 3 is now at index 1; the selector must follow
    # the value rather than keep the stale index.
    assert surviving_marking["selectors"] == ["aliases.[1]"]


def test_remapping_does_not_confuse_removed_and_surviving_paths():
    # Element at index 1 is removed; the surviving element at index 2 is
    # remapped onto index 1.  Its selector must survive even though the
    # rewritten path string equals the removed element's old path.
    obj = Malware(
        aliases=["a0", "a1", "a2"],
        granular_markings=[
            {"marking_ref": M0, "selectors": ["aliases.[1]"]},
            {"marking_ref": M1, "selectors": ["aliases.[2]"]},
        ],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert exported["aliases"] == ["a0", "a2"]
    surviving_marking = [
        marking for marking in exported["granular_markings"]
        if marking.get("marking_ref") == M1
    ][0]
    assert surviving_marking["selectors"] == ["aliases.[1]"]
    assert exported["aliases"][1] == "a2"


def test_nested_list_selector_remapping():
    data = {
        **MALWARE_BASE,
        "spec_version": "2.1",
        "x_tree": {"items": ["i0", "i1", "i2"]},
        "granular_markings": [
            {"marking_ref": M0, "selectors": ["x_tree.items.[0]"]},
            {"marking_ref": M1, "selectors": ["x_tree.items.[2]"]},
        ],
    }
    result = controlled_export(data, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert exported["x_tree"]["items"] == ["i1", "i2"]
    surviving_marking = [
        marking for marking in exported["granular_markings"]
        if marking.get("marking_ref") == M1
    ][0]
    assert surviving_marking["selectors"] == ["x_tree.items.[1]"]


def test_path_matching_is_component_wise_not_string_prefix():
    obj = Malware(
        x_name="must stay",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["name"]},
        ],
        allow_custom=True,
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert "name" not in exported
    assert exported["x_name"] == "must stay"


def test_language_markings_do_not_restrict_export():
    obj = Malware(
        granular_markings=[
            {"lang": "en", "selectors": ["name"]},
            {"marking_ref": M0, "selectors": ["description"]},
        ],
        description="sensitive",
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["name"] == "Cryptolocker"
    assert "description" not in exported
    assert exported["granular_markings"] == [
        {"lang": "en", "selectors": ["name"]},
    ]

def test_object_level_marking_blocks_whole_object():
    obj = Malware(
        object_marking_refs=[M0],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M1])

    assert not result.exportable
    assert result.stix_object is None
    assert result.reason is not None
    assert result.disallowed_markings == [M0]


def test_object_level_marking_allowed_lets_object_through():
    obj = Malware(
        object_marking_refs=[M0],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M0])

    assert result.exportable
    assert result.stix_object.serialize() == obj.serialize()


def test_hiding_required_property_returns_explicit_failure():
    obj = Indicator(
        pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        pattern_type="stix",
        valid_from="2016-04-06T20:03:00.000Z",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["pattern"]},
        ],
    )
    result = controlled_export(obj, [M1])

    assert not result.exportable
    assert result.stix_object is None
    assert "invalid" in result.reason
    assert result.removed_paths == ["pattern"]


def test_emptying_required_list_returns_explicit_failure():
    obj = Report(
        name="r",
        published="2016-04-06T20:03:00.000Z",
        object_refs=["indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
        granular_markings=[
            {"marking_ref": M0, "selectors": ["object_refs.[0]"]},
        ],
    )
    result = controlled_export(obj, [M1])

    assert not result.exportable
    assert result.stix_object is None
    assert result.reason is not None


def test_original_object_is_never_modified():
    obj = Malware(
        aliases=["a0", "a1", "a2"],
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description", "aliases.[1]"]},
        ],
        **MALWARE_BASE,
    )
    before = obj.serialize()
    before_dict = copy.deepcopy(dict(obj))

    controlled_export(obj, [M1])

    assert obj.serialize() == before
    assert dict(obj) == before_dict


def test_exported_output_reparses_equivalently():
    obj = Malware(
        aliases=["a0", "a1", "a2"],
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description", "aliases.[1]"]},
        ],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M1])
    reparsed = parse(result.stix_object.serialize())

    assert reparsed.serialize() == result.stix_object.serialize()
    assert json.loads(reparsed.serialize())["aliases"] == ["a0", "a2"]


def test_plain_dict_input_is_supported():
    data = {
        **MALWARE_BASE,
        "spec_version": "2.1",
        "description": "sensitive",
        "granular_markings": [
            {"marking_ref": M0, "selectors": ["description"]},
        ],
    }
    original = copy.deepcopy(data)
    result = controlled_export(data, [M1])

    assert result.exportable
    assert "description" not in json.loads(result.stix_object.serialize())
    # The input dictionary is not mutated.
    assert data == original


def test_custom_properties_on_dict_input_remain_supported():
    data = {
        **MALWARE_BASE,
        "spec_version": "2.1",
        "x_custom": {"hidden": 1, "shown": 2},
        "granular_markings": [
            {"marking_ref": M0, "selectors": ["x_custom.hidden"]},
        ],
    }
    result = controlled_export(data, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["x_custom"] == {"shown": 2}


def test_marking_definition_objects_accepted_in_allow_list():
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": TLP_RED.id, "selectors": ["description"]},
        ],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [TLP_RED])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["description"] == "sensitive"


def test_marking_id_string_accepted_in_allow_list():
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description"]},
        ],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, M0)
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["description"] == "sensitive"


def test_method_form_matches_function_form():
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description"]},
        ],
        **MALWARE_BASE,
    )
    function_result = controlled_export(obj, [M1])
    method_result = obj.controlled_export([M1])

    assert method_result.exportable == function_result.exportable
    assert method_result.stix_object.serialize() == \
        function_result.stix_object.serialize()


def test_markings_are_compressed_in_output():
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": M1, "selectors": ["name"]},
            {"marking_ref": M1, "selectors": ["description"]},
            {"marking_ref": M0, "selectors": ["aliases.[0]"]},
        ],
        aliases=["a0"],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    m1_entries = [
        marking for marking in exported["granular_markings"]
        if marking.get("marking_ref") == M1
    ]
    assert len(m1_entries) == 1
    assert m1_entries[0]["selectors"] == ["description", "name"]


def test_dangling_selector_after_full_list_removal_is_dropped():
    obj = Report(
        name="r",
        published="2016-04-06T20:03:00.000Z",
        object_refs=[
            "indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
            "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        ],
        granular_markings=[
            {"marking_ref": M0, "selectors": ["object_refs.[0]"]},
        ],
    )
    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["object_refs"] == [
        "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    ]
    assert "granular_markings" not in exported


@pytest.mark.parametrize(
    "allow_list",
    [None, [], [M1], [M1, M2]],
)
def test_no_leakage_of_disallowed_content(allow_list):
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description"]},
        ],
        **MALWARE_BASE,
    )
    result = controlled_export(obj, allow_list)
    serialized = result.stix_object.serialize()

    assert "sensitive" not in serialized
    assert M0 not in serialized


def test_sco_granular_marking_is_enforced():
    from stix2.v21 import File

    obj = File(
        name="evil.exe",
        x_note="custom content",
        allow_custom=True,
        granular_markings=[
            {"marking_ref": M0, "selectors": ["x_note"]},
        ],
    )
    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert "x_note" not in exported
    assert exported["name"] == "evil.exe"


def test_sco_hiding_required_property_is_explicit_failure():
    from stix2.v21 import File

    obj = File(
        name="evil.exe",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["name"]},
        ],
    )
    result = controlled_export(obj, [M1])

    assert not result.exportable
    assert result.stix_object is None
    assert result.reason is not None
