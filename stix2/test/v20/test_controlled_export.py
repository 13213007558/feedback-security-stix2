"""Tests for controlled export according to data markings (STIX 2.0)."""

import copy
import json

from stix2 import controlled_export, parse
from stix2.v20 import Indicator, Malware

from .constants import MARKING_IDS

M0, M1 = MARKING_IDS[:2]

MALWARE_BASE = dict(
    type="malware",
    id="malware--9c4638ec-f1de-4ddb-abf4-1b760417654e",
    created="2016-04-06T20:03:00.000Z",
    modified="2016-04-06T20:03:00.000Z",
    name="Cryptolocker",
    labels=["ransomware"],
)


def test_granular_property_removed_and_object_unchanged():
    obj = Malware(
        description="sensitive",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["description"]},
        ],
        **MALWARE_BASE,
    )
    before = obj.serialize()

    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert "description" not in exported
    assert obj.serialize() == before
    assert parse(result.stix_object.serialize()).serialize() == \
        result.stix_object.serialize()


def test_list_removal_remaps_granular_selectors():
    obj = Malware(
        labels=["ransomware", "trojan"],
        granular_markings=[
            {"marking_ref": M0, "selectors": ["labels.[0]"]},
            {"marking_ref": M1, "selectors": ["labels.[1]"]},
        ],
        **{k: v for k, v in MALWARE_BASE.items() if k != "labels"},
    )
    result = controlled_export(obj, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert exported["labels"] == ["trojan"]
    surviving = [
        marking for marking in exported["granular_markings"]
        if marking.get("marking_ref") == M1
    ][0]
    assert surviving["selectors"] == ["labels.[0]"]


def test_object_level_marking_blocks_whole_object():
    obj = Malware(object_marking_refs=[M0], **MALWARE_BASE)

    blocked = controlled_export(obj, [M1])
    assert not blocked.exportable
    assert blocked.stix_object is None
    assert blocked.disallowed_markings == [M0]

    allowed = controlled_export(obj, [M0])
    assert allowed.exportable


def test_required_property_hidden_is_explicit_failure():
    obj = Indicator(
        id="indicator--a740531e-63ff-4e49-a9e1-a0a3eed0e3e7",
        created="2016-04-06T20:03:00.000Z",
        modified="2016-04-06T20:03:00.000Z",
        labels=["malicious-activity"],
        pattern="[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
        granular_markings=[
            {"marking_ref": M0, "selectors": ["pattern"]},
        ],
    )
    result = controlled_export(obj, [M1])

    assert not result.exportable
    assert result.stix_object is None
    assert result.reason is not None
    assert result.removed_paths == ["pattern"]


def test_dict_input_supported_and_not_mutated():
    data = {
        **MALWARE_BASE,
        "description": "sensitive",
        "granular_markings": [
            {"marking_ref": M0, "selectors": ["description"]},
        ],
    }
    original = copy.deepcopy(data)

    result = controlled_export(data, [M1])

    assert result.exportable
    assert "description" not in json.loads(result.stix_object.serialize())
    assert data == original


def test_falsy_custom_values_survive_filtering():
    data = {
        **MALWARE_BASE,
        "x_values": {"zero": 0, "flag": False, "empty": "", "kept": "v"},
        "granular_markings": [
            {"marking_ref": M0, "selectors": ["x_values.kept"]},
        ],
    }
    result = controlled_export(data, [M1])
    exported = json.loads(result.stix_object.serialize())

    assert result.exportable
    assert exported["x_values"] == {"zero": 0, "flag": False, "empty": ""}
