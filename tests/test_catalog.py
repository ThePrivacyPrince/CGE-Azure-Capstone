"""Federal track coherence: every control ID the pipeline claims must exist in NIST SP 800-53
Rev. 5 and sit inside FAFO's tailored Moderate baseline. A mapping to a control that does not
exist (or was withdrawn) is the quietest way to lose an assessment, so CI refuses it."""

from __future__ import annotations

import json
import re

import pytest

from conftest import ROOT

CATALOG = json.loads((ROOT / "frameworks" / "nist-800-53-rev5.json").read_text())["controls"]
PROFILE = json.loads((ROOT / "oscal" / "fafo-moderate-profile.json").read_text())["profile"]
CONTROL_ID = re.compile(r"(?<![.\w])([A-Z]{2}-\d{1,2}(?:\(\d{1,2}\))?)(?![\w.(-])")


def tailored_baseline() -> set[str]:
    """Moderate (every catalog control flagged moderate) plus the profile's explicit additions."""
    added = {
        cid
        for imp in PROFILE["imports"]
        for inc in imp.get("include-controls", [])
        for cid in inc.get("with-ids", [])
    }
    return {label for label, c in CATALOG.items() if c["moderate"] or c["id"] in added}


def crosswalk_ids() -> set[str]:
    m = json.loads((ROOT / "frameworks" / "mappings.json").read_text())
    assert list(m["frameworks"]) == ["nist_800_53_r5"], "federal track: one catalog"
    return {i for c in m["controls"] for i in c["mappings"]["nist_800_53_r5"]}


def test_catalog_is_the_official_rev5_content():
    assert len(CATALOG) > 1000 and CATALOG["AC-2"]["title"] == "Account Management"
    assert CATALOG["SA-9(5)"]["title"] == "Processing, Storage, and Service Location"


@pytest.mark.parametrize("cid", sorted(crosswalk_ids()))
def test_every_crosswalk_control_resolves_and_is_active(cid):
    assert cid in CATALOG, f"{cid} is not a NIST SP 800-53 Rev. 5 control"
    assert not CATALOG[cid]["withdrawn"], f"{cid} is withdrawn in Rev. 5"


def test_every_crosswalk_control_is_in_the_tailored_baseline():
    outside = crosswalk_ids() - tailored_baseline()
    assert not outside, f"mapped but outside FAFO's tailored Moderate baseline: {sorted(outside)}"


def test_every_800_53_id_in_controls_md_resolves():
    text = (ROOT / "docs" / "CONTROLS.md").read_text()
    ids = set(CONTROL_ID.findall(text))
    assert ids, "CONTROLS.md cites no 800-53 controls"
    bad = sorted(i for i in ids if i not in CATALOG or CATALOG[i]["withdrawn"])
    assert not bad, f"CONTROLS.md cites controls that do not resolve in Rev. 5: {bad}"


def test_crosswalk_controls_all_appear_in_controls_md():
    text = (ROOT / "docs" / "CONTROLS.md").read_text()
    missing = sorted(i for i in crosswalk_ids() if i not in set(CONTROL_ID.findall(text)))
    assert not missing, f"in the crosswalk but not in CONTROLS.md: {missing}"
