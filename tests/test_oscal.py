"""OSCAL is how the federal track's SSP and POA&M "go out". These tests hold them to NIST's
own OSCAL 1.1.2 JSON schemas (vendored in tests/schemas/) and to the repo: the SSP must be
generated from its reviewed source, claim only controls in FAFO's tailored baseline, implement
every control the crosswalk maps, and name components whose code exists."""

from __future__ import annotations

import importlib.util
import json
from datetime import timedelta

import jsonschema
import pytest

import reports_core as rc
from conftest import ROOT, MemoryReader, MemoryStore, MemoryWriter
from test_reports import T0, collect

SCHEMAS = ROOT / "tests" / "schemas"
CATALOG = json.loads((ROOT / "frameworks" / "nist-800-53-rev5.json").read_text())["controls"]
BY_OSCAL_ID = {c["id"]: label for label, c in CATALOG.items()}
SSP = json.loads((ROOT / "oscal" / "ssp.json").read_text())
SOURCE = json.loads((ROOT / "frameworks" / "ssp-implementation.json").read_text())


def validator(name: str) -> jsonschema.Draft7Validator:
    # NIST's token pattern uses \p{L} / \p{N}, which Python's re lacks; translate them to the
    # equivalent classes (letters: [^\W\d_], numbers: \d) without loosening anything else.
    text = (SCHEMAS / f"oscal_{name}_schema.json").read_text()
    text = text.replace("\\\\p{L}", "[^\\\\W\\\\d_]").replace("\\\\p{N}", "\\\\d")
    return jsonschema.Draft7Validator(json.loads(text), format_checker=jsonschema.FormatChecker())


def errors(name: str, doc: dict) -> list[str]:
    return [f"{list(e.path)}: {e.message[:200]}" for e in validator(name).iter_errors(doc)]


def generator():
    spec = importlib.util.spec_from_file_location("generate_ssp", ROOT / "scripts" / "generate_ssp.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_ssp_is_schema_valid():
    assert errors("ssp", SSP) == []


def test_profile_is_schema_valid():
    assert errors("profile", json.loads((ROOT / "oscal" / "fafo-moderate-profile.json").read_text())) == []


def test_schema_validation_actually_rejects_a_broken_document():
    broken = json.loads(json.dumps(SSP))
    del broken["system-security-plan"]["control-implementation"]
    assert errors("ssp", broken)


def test_ssp_is_generated_from_its_source_and_current():
    gen = generator()
    stamp = SSP["system-security-plan"]["metadata"]["last-modified"]
    assert gen.build_ssp(SOURCE, stamp) == SSP, "run: python3 scripts/generate_ssp.py"


def test_ssp_controls_resolve_and_sit_in_the_tailored_baseline():
    profile = json.loads((ROOT / "oscal" / "fafo-moderate-profile.json").read_text())["profile"]
    added = {i for imp in profile["imports"] for inc in imp.get("include-controls", []) for i in inc["with-ids"]}
    for req in SSP["system-security-plan"]["control-implementation"]["implemented-requirements"]:
        cid = req["control-id"]
        assert cid in BY_OSCAL_ID, f"{cid} is not in NIST SP 800-53 Rev. 5"
        c = CATALOG[BY_OSCAL_ID[cid]]
        assert not c["withdrawn"] and (c["moderate"] or cid in added), f"{cid} is outside the tailored baseline"


def test_every_crosswalk_control_is_implemented_in_the_ssp():
    m = json.loads((ROOT / "frameworks" / "mappings.json").read_text())
    mapped = {i for c in m["controls"] for i in c["mappings"]["nist_800_53_r5"]}
    missing = mapped - set(SOURCE["implementedRequirements"])
    assert not missing, f"mapped in the crosswalk but not implemented in the SSP: {sorted(missing)}"


def test_every_component_names_code_that_exists():
    for c in SOURCE["components"]:
        assert (ROOT / c["path"]).exists(), f"{c['key']}: {c['path']} does not exist"
    keys = {c["key"] for c in SOURCE["components"]}
    used = {s["component"] for stmts in SOURCE["implementedRequirements"].values() for s in stmts}
    assert used <= keys, used - keys


@pytest.fixture()
def oscal_poam(crosswalk):
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    writer = MemoryWriter()
    out = rc.generate_poam(MemoryReader(store), writer, now=T0 + timedelta(hours=1))
    return json.loads(writer.blobs[out["files"]["poam.oscal.json"]["path"]]), json.loads(writer.blobs[out["files"]["poam.json"]["path"]])


def test_reporter_poam_is_schema_valid_oscal(oscal_poam):
    doc, _ = oscal_poam
    assert errors("poam", doc) == []


def test_oscal_poam_matches_the_json_poam_and_the_ssp(oscal_poam):
    doc, plain = oscal_poam
    p = doc["plan-of-action-and-milestones"]
    assert len(p["poam-items"]) == plain["summary"]["open"]  # same number, two formats
    assert p["system-id"]["id"] == SSP["system-security-plan"]["system-characteristics"]["system-ids"][0]["id"]
    ids = {prop["value"] for o in p["observations"] for prop in o["props"] if prop["name"] == "control-id"}
    assert ids and ids <= set(BY_OSCAL_ID), "every control-id in the POA&M resolves in Rev. 5"


def test_empty_poam_is_still_valid_oscal():
    lineage = {"reportExecutionId": "e", "runId": "r", "runCompletedAt": T0.isoformat(), "crosswalkVersion": "v"}
    doc = rc.build_oscal_poam({"items": []}, lineage, T0)
    assert errors("poam", doc) == []
