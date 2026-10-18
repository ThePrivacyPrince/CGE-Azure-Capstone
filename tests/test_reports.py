from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

import evidence_core as ec
import reports_core as rc
from conftest import SEED, SUB, FakeCredential, FakeResponse, FakeSession, MemoryReader, MemoryStore, MemoryWriter, defender_item, policy_item

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
        ("POST", POL_PATH): [FakeResponse(200, {"value": [policy_item("tf-storage-min-tls12", tls_state)]})],
    }
    client = ec.ArmClient(FakeCredential(), FakeSession(routes), sleep=lambda s: None, audit=lambda e: None)
    m = ec.run_collection(client, store, SUB, crosswalk, now=now)
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
    assert "PR.DS-01" in item["frameworks"]["nist_csf_2"]
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
    assert "Reproduce these numbers" in md and "NIST Cybersecurity Framework 2.0" in md


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
    bad["controls"][0]["mappings"]["iso_27001"] = ["A.5.1"]
    with pytest.raises(rc.CrosswalkError):
        rc.Crosswalk(bad, "v")


def test_every_policy_in_terraform_is_in_the_crosswalk(crosswalk):
    """CONTROLS.md must be current with the code; so must the crosswalk."""
    import re
    from conftest import ROOT

    names = set()
    for tf in (ROOT / "stages").rglob("*.tf"):
        names |= set(re.findall(r'name\s*=\s*"((?:cge|tf)-[a-z0-9-]+)"', tf.read_text()))
    tf_policies = {n for n in names if n.startswith(("cge-deny", "cge-dine", "cge-require", "cge-fix", "tf-storage-min", "tf-cosmos", "tf-allowed", "tf-fix"))}
    mapped = {c["match"].get("policyDefinitionName") for c in crosswalk["controls"]}
    assert tf_policies <= mapped, tf_policies - mapped


def test_injected_document_refuses_to_publish(crosswalk):
    store = MemoryStore()
    m = collect(store, crosswalk, "Unhealthy", T0)
    store.upsert("snapshots", {"id": "injected", "runId": m["runId"], "findingKey": "x", "result": "pass",
                               "source": "defender", "collectedAt": T0.isoformat(), "displayName": "x"})
    writer = MemoryWriter()
    with pytest.raises(rc.EvidenceIntegrityError):
        rc.generate_poam(MemoryReader(store), writer, now=T0 + timedelta(hours=1))
    assert writer.blobs == {}  # nothing published


def test_document_edited_in_place_refuses_to_publish(crosswalk):
    # Same id, different content: invisible to the id digest, caught by the content digest.
    store = MemoryStore()
    m = collect(store, crosswalk, "Unhealthy", T0)
    victim = next(d for d in store.all("snapshots") if d["runId"] == m["runId"] and d["result"] == "fail")
    store.upsert("snapshots", {**victim, "result": "pass", "rawStatus": "Healthy"})
    writer = MemoryWriter()
    with pytest.raises(rc.EvidenceIntegrityError):
        rc.generate_sar(MemoryReader(store), writer, now=T0 + timedelta(hours=1))
    assert writer.blobs == {}


def test_cosmos_system_fields_do_not_break_the_seal(crosswalk):
    store = MemoryStore()
    m = collect(store, crosswalk, "Unhealthy", T0)
    for d in store.all("snapshots"):
        store.upsert("snapshots", {**d, "_rid": "x", "_etag": "\"0\"", "_ts": 1792279864})
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
