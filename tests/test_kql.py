"""The KQL in kql/ is both documentation and the alert rules' source (stage 07 templatefile).
These checks catch the mistakes that only show up at plan or alert time: a placeholder the
stage does not pass, an unbalanced bracket, or a query that is not one of FAFO's own."""

from __future__ import annotations

import re

import pytest

from conftest import ROOT

KQL = sorted((ROOT / "kql").glob("*.kql"))
STAGE07 = (ROOT / "stages" / "07-detection" / "main.tf").read_text()
PLACEHOLDER = re.compile(r"\$\{(\w+)\}")
TAUGHT = {"unexpected-writer"}  # course-derived; everything else must be FAFO's own


def body(path):
    return "\n".join(line for line in path.read_text().splitlines() if not line.lstrip().startswith("//"))


def test_at_least_two_fafo_queries_beyond_the_taught_set():
    own = [p for p in KQL if p.stem not in TAUGHT]
    assert len(own) >= 2, [p.name for p in own]


@pytest.mark.parametrize("path", KQL, ids=lambda p: p.stem)
def test_every_placeholder_is_documented_and_passed_by_stage_07(path):
    text = path.read_text()
    used = set(PLACEHOLDER.findall(body(path)))
    header = "\n".join(line for line in text.splitlines() if line.lstrip().startswith("//"))
    assert used <= set(PLACEHOLDER.findall(header)), f"undocumented placeholders in {path.name}"
    call = re.search(rf'templatefile\("\$\{{local\.kql_dir\}}/{re.escape(path.name)}", \{{(.*?)\}}\)', STAGE07, re.S)
    assert call, f"{path.name} is not wired into an alert rule in stage 07"
    passed = set(re.findall(r"^\s*(\w+)\s*=", call.group(1), re.M))
    assert used == passed, f"{path.name}: query uses {sorted(used)}, stage 07 passes {sorted(passed)}"


@pytest.mark.parametrize("path", KQL, ids=lambda p: p.stem)
def test_rendered_query_is_well_formed(path):
    rendered = PLACEHOLDER.sub(lambda m: '"x"' if m.group(1) != "new_rows_filter" else "| where ingestion_time() > ago(15m)", body(path))
    assert "${" not in rendered
    first = next(line for line in rendered.splitlines() if line.strip())
    assert re.fullmatch(r"[A-Za-z]+", first.strip()), f"query must start with a table, got {first!r}"
    for open_, close in ("()", "[]", "{}"):
        assert rendered.count(open_) == rendered.count(close), f"unbalanced {open_}{close} in {path.name}"
    assert rendered.count('"') % 2 == 0, f"unbalanced quotes in {path.name}"


@pytest.mark.parametrize("path", KQL, ids=lambda p: p.stem)
def test_every_query_names_the_controls_it_serves(path):
    assert re.search(r"800-53: [A-Z]{2}-\d", path.read_text()), f"{path.name} has no 800-53 mapping"
