from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import evidence_core as ec
import reports_core as rc
from conftest import (
    MG, SEED, SUB, FakeCredential, FakeResponse, FakeSession, MemoryReader, MemoryStore, MemoryWriter, defender_item,
    policy_item, rbac_routes, subscriptions_route,
)

DEF_PATH = f"/subscriptions/{SUB}/providers/Microsoft.Security/assessments"
POL_PATH = f"/subscriptions/{SUB}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
PUBLIC_BLOB_ASSESSMENT_NAME = "51fd8bb1-0db4-bbf1-7e2b-cfcba7eb66a6"
T0 = datetime(2026, 10, 10, 6, tzinfo=timezone.utc)


def collect(store, crosswalk, public_access_status, now, tls_state="NonCompliant"):
    routes = {
        ("GET", DEF_PATH): [FakeResponse(200, {"value": [
            defender_item(PUBLIC_BLOB_ASSESSMENT_NAME, "Storage account public access should be disallowed", public_access_status),
            defender_item("bbbb", "Some brand new Defender check", "Unhealthy", severity="Low"),
        ]})],
        ("POST", POL_PATH): [FakeResponse(200, {"value": [policy_item("fafo-storage-min-tls12", tls_state)]})],
        **subscriptions_route(SUB),
        **rbac_routes(SUB),
    }
    client = ec.ArmClient(FakeCredential(), FakeSession(routes), sleep=lambda s: None, audit=lambda e: None)
    m = ec.run_collection(client, store, MG, crosswalk, now=now)
    # completedAt is wall-clock in the collector; pin it for deterministic tests.
    m["completedAt"] = (now + timedelta(minutes=5)).isoformat()
    store.upsert("runs", m)
    return m


def test_poam_reads_latest_completed_run_with_stable_first_seen(crosswalk):
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    m2 = collect(store, crosswalk, "Unhealthy", T0 + timedelta(days=3))
    writer = MemoryWriter()
    out = rc.generate_poam(MemoryReader(store), writer, now=T0 + timedelta(days=3, hours=1))

    body = json.loads(writer.blobs[out["files"]["poam.json"]["path"]])
    assert body["lineage"]["runId"] == m2["runId"] and body["lineage"]["digestVerified"] is True
    item = next(i for i in body["items"] if i["controlKey"] == "defender:storage-public-access")
    assert item["firstSeen"].startswith("2026-10-10")  # from history, not "today"
    assert item["scheduledCompletion"] == "2026-11-09"  # High = 30 days from first seen
    assert "AC-3" in item["frameworks"]["nist_800_53_r5"]
    assert body["summary"]["unmapped"] == 1  # the brand-new Defender check is flagged, not dropped


def test_partial_runs_are_never_reported(crosswalk):
    store = MemoryStore()
    good = collect(store, crosswalk, "Unhealthy", T0)
    store.upsert("runs", {**good, "id": "half", "runId": "half", "status": "partial",
                          "completedAt": (T0 + timedelta(hours=2)).isoformat()})
    out = rc.generate_poam(MemoryReader(store), MemoryWriter(), now=T0 + timedelta(hours=3))
    assert out["runId"] == good["runId"]


def test_stale_evidence_refuses_to_publish(crosswalk):
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    with pytest.raises(rc.StaleEvidenceError):
        rc.generate_poam(MemoryReader(store), MemoryWriter(), now=T0 + timedelta(days=2), max_age_hours=13)


def test_no_runs_raises():
    with pytest.raises(rc.NoCompletedRunError):
        rc.generate_poam(MemoryReader(MemoryStore()), MemoryWriter(), now=T0)


def test_publish_writes_one_folder_with_manifest_last(crosswalk):
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    writer = MemoryWriter()
    out = rc.generate_poam(MemoryReader(store), writer, now=T0 + timedelta(hours=1))
    folder = out["folder"]
    assert all(p.startswith(folder + "/") for p in writer.order)
    assert writer.order[-1] == f"{folder}/manifest.json"
    manifest = json.loads(writer.blobs[f"{folder}/manifest.json"])
    import hashlib

    for name, meta in manifest["files"].items():
        assert hashlib.sha256(writer.blobs[meta["path"]]).hexdigest() == meta["sha256"]
    assert out["reportExecutionId"] in folder


def test_two_runs_same_day_do_not_collide(crosswalk):
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    writer = MemoryWriter()
    rc.generate_poam(MemoryReader(store), writer, now=T0 + timedelta(hours=1))
    rc.generate_poam(MemoryReader(store), writer, now=T0 + timedelta(hours=1))  # Lab 6's HTTP 500, gone
    assert len([p for p in writer.order if p.endswith("manifest.json")]) == 2


def test_sar_delta_counts_only_explicit_fixes(crosswalk):
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    collect(store, crosswalk, "Healthy", T0 + timedelta(hours=6), tls_state="Compliant")
    writer = MemoryWriter()
    out = rc.generate_sar(MemoryReader(store), writer, now=T0 + timedelta(hours=7))
    card = json.loads(writer.blobs[out["files"]["scorecard.json"]["path"]])
    assert len(card["deltaFromPreviousRun"]["fixed"]) == 2  # public access + TLS: fail -> pass
    assert card["deltaFromPreviousRun"]["noLongerObserved"] == []
    md = writer.blobs[out["files"]["sar.md"]["path"]].decode()
    assert "Reproduce these numbers" in md and "NIST SP 800-53 Rev. 5" in md


def test_disappeared_finding_is_not_counted_as_fixed(crosswalk):
    prev = [{"findingKey": "k1", "result": "fail", "source": "defender"}]
    cur: list[dict] = []
    card = rc.build_scorecard(cur, prev, rc.Crosswalk(crosswalk, "v"))
    assert card["deltaFromPreviousRun"]["fixed"] == []
    assert card["deltaFromPreviousRun"]["noLongerObserved"] == ["k1"]


def test_crosswalk_rejects_unknown_match_keys_and_frameworks(crosswalk):
    bad = json.loads(json.dumps(crosswalk))
    bad["controls"][0]["match"]["displayNameStartsWith"] = "x"
    with pytest.raises(rc.CrosswalkError):
        rc.Crosswalk(bad, "v")
    bad = json.loads(json.dumps(crosswalk))
    bad["controls"][0]["mappings"]["iso_27001"] = ["A.5.1"]  # one catalog per track
    with pytest.raises(rc.CrosswalkError):
        rc.Crosswalk(bad, "v")


def test_every_policy_in_terraform_is_in_the_crosswalk(crosswalk):
    """CONTROLS.md must be current with the code; so must the crosswalk."""
    import re
    from conftest import ROOT

    names, roles = set(), set()
    for tf in (ROOT / "stages").rglob("*.tf"):
        text = tf.read_text()
        names |= set(re.findall(r'name\s*=\s*"((?:cge|fafo)-[a-z0-9-]+)"', text))
        roles |= set(re.findall(r'resource "azurerm_role_definition" "\w+" \{\s*name\s*=\s*"([^"]+)"', text))
    tf_policies = {n for n in names - roles if n.startswith(("cge-deny", "cge-dine", "cge-require", "cge-fix", "fafo-"))}
    assert len(tf_policies) >= 11, tf_policies  # the regex still finds every policy
    mapped = {c["match"].get("policyDefinitionName") for c in crosswalk["controls"]}
    assert tf_policies <= mapped, tf_policies - mapped


def test_injected_document_refuses_to_publish(crosswalk):
    store = MemoryStore()
    m = collect(store, crosswalk, "Unhealthy", T0)
    store.upsert("findings", {"id": "injected", "runId": m["runId"], "findingKey": "x", "result": "pass",
                               "source": "defender", "collectedAt": T0.isoformat(), "displayName": "x"})
    writer = MemoryWriter()
    with pytest.raises(rc.EvidenceIntegrityError):
        rc.generate_poam(MemoryReader(store), writer, now=T0 + timedelta(hours=1))
    assert writer.blobs == {}  # nothing published


def test_document_edited_in_place_refuses_to_publish(crosswalk):
    # Same id, different content: invisible to the id digest, caught by the content digest.
    store = MemoryStore()
    m = collect(store, crosswalk, "Unhealthy", T0)
    victim = next(d for d in store.all("findings") if d["runId"] == m["runId"] and d["result"] == "fail")
    store.upsert("findings", {**victim, "result": "pass", "rawStatus": "Healthy"})
    writer = MemoryWriter()
    with pytest.raises(rc.EvidenceIntegrityError):
        rc.generate_sar(MemoryReader(store), writer, now=T0 + timedelta(hours=1))
    assert writer.blobs == {}


def test_cosmos_system_fields_do_not_break_the_seal(crosswalk):
    store = MemoryStore()
    m = collect(store, crosswalk, "Unhealthy", T0)
    for d in store.all("findings"):
        store.upsert("findings", {**d, "_rid": "x", "_etag": "\"0\"", "_ts": 1792279864})
    out = rc.generate_poam(MemoryReader(store), MemoryWriter(), now=T0 + timedelta(hours=1))
    assert out["digestVerified"] is True and out["runId"] == m["runId"]


def test_collector_and_reporter_hash_content_identically():
    doc = {"id": "a", "result": "fail", "categories": ["Data"], "severity": None, "displayName": "Ünïcode ok", "_ts": 1}
    assert ec.content_sha256(doc) == rc.content_sha256(doc)


def test_runs_sealed_before_content_digest_still_verify(crosswalk):
    store = MemoryStore()
    m = collect(store, crosswalk, "Unhealthy", T0)
    legacy = {k: v for k, v in m.items() if k != "contentSetSha256"}
    store.upsert("runs", legacy)
    out = rc.generate_poam(MemoryReader(store), MemoryWriter(), now=T0 + timedelta(hours=1))
    assert out["digestVerified"] is True


def test_sar_reports_privileged_access_from_rbac_snapshots(crosswalk):
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    writer = MemoryWriter()
    out = rc.generate_sar(MemoryReader(store), writer, now=T0 + timedelta(hours=1))
    card = json.loads(writer.blobs[out["files"]["scorecard.json"]["path"]])
    pa = card["privilegedAccess"]
    assert pa["totals"] == {"assignments": 2, "privileged": 1, "subscriptionOwners": 1}
    assert pa["subscriptions"][SUB]["subscriptionOwners"][0]["principalId"] == "user-1"
    md = writer.blobs[out["files"]["sar.md"]["path"]].decode()
    assert "Privileged access" in md and "1 subscription(s)" in md
    # The number in the report is reproducible: the rbac query is in the receipts.
    assert any(q["container"] == "rbac" for q in out["queries"])


def test_tampered_rbac_snapshot_refuses_to_publish(crosswalk):
    store = MemoryStore()
    collect(store, crosswalk, "Unhealthy", T0)
    owner = next(d for d in store.all("rbac") if d["roleName"] == "Owner")
    store.upsert("rbac", {**owner, "roleName": "Reader", "privileged": False})  # hide a standing Owner
    with pytest.raises(rc.EvidenceIntegrityError):
        rc.generate_sar(MemoryReader(store), MemoryWriter(), now=T0 + timedelta(hours=1))


def test_poam_open_count_equals_failing_findings_in_the_run(crosswalk):
    """The grader's recompute: the report's number must equal the stored documents' count."""
    store = MemoryStore()
    m = collect(store, crosswalk, "Unhealthy", T0)
    out = rc.generate_poam(MemoryReader(store), (w := MemoryWriter()), now=T0 + timedelta(hours=1))
    body = json.loads(w.blobs[out["files"]["poam.json"]["path"]])
    failing = [d for d in store.all("findings") if d["runId"] == m["runId"] and d["result"] == "fail"]
    assert body["summary"]["open"] == len(failing)
