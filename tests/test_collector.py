from __future__ import annotations

from datetime import datetime, timezone

import pytest

import evidence_core as ec
from conftest import SEED, SUB, FakeCredential, FakeResponse, FakeSession, MemoryStore, defender_item, policy_item

DEF_PATH = f"/subscriptions/{SUB}/providers/Microsoft.Security/assessments"
POL_PATH = f"/subscriptions/{SUB}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"
PUBLIC_BLOB_ASSESSMENT_NAME = "51fd8bb1-0db4-bbf1-7e2b-cfcba7eb66a6"


def arm(routes, sleeps=None):
    return ec.ArmClient(FakeCredential(), FakeSession(routes), sleep=(sleeps.append if sleeps is not None else lambda s: None), audit=lambda e: None)


def happy_routes():
    return {
        ("GET", DEF_PATH): [
            FakeResponse(200, {
                "value": [defender_item(PUBLIC_BLOB_ASSESSMENT_NAME, "Storage account public access should be disallowed", "Unhealthy")],
                "nextLink": f"https://management.azure.com{DEF_PATH}?page=2",
            }),
            FakeResponse(200, {"value": [defender_item("aaaa", "Storage accounts should prevent shared key access", "Unhealthy", severity="Medium")]}),
        ],
        ("POST", POL_PATH): [
            FakeResponse(200, {"value": [policy_item("cge-deny-public-blob", "NonCompliant")],
                               "@odata.nextLink": f"https://management.azure.com{POL_PATH}?$skiptoken=x"}),
            FakeResponse(200, {"value": [policy_item("tf-storage-min-tls12", "Compliant")]}),
        ],
    }


def test_run_writes_history_manifest_and_latest_state(crosswalk):
    store = MemoryStore()
    m = ec.run_collection(arm(happy_routes()), store, SUB, crosswalk, now=datetime(2026, 10, 17, 18, tzinfo=timezone.utc))

    assert m["status"] == "completed" and m["trigger"] == "timer"
    assert m["documentCount"] == 4 and m["sources"]["defender"]["documents"] == 2
    assert len(store.all("snapshots")) == 4  # both pages of both sources followed
    assert len(store.all("assessments")) == 2  # starter latest-state view: Defender only
    assert store.all("runs")[0]["status"] == "completed"
    assert store.all("mappings")[0]["id"] == f"crosswalk-{m['crosswalkVersion']}"
    for d in store.all("snapshots"):
        assert d["runId"] == m["runId"] and d["collectedAt"] and d["findingKey"]


def test_history_accumulates_across_runs_but_finding_identity_is_stable(crosswalk):
    store = MemoryStore()
    m1 = ec.run_collection(arm(happy_routes()), store, SUB, crosswalk)
    m2 = ec.run_collection(arm(happy_routes()), store, SUB, crosswalk)
    snaps = store.all("snapshots")
    assert len(snaps) == 8  # Lab 6 gap closed: run 2 did not overwrite run 1
    keys = {r: {d["findingKey"] for d in snaps if d["runId"] == r} for r in (m1["runId"], m2["runId"])}
    assert keys[m1["runId"]] == keys[m2["runId"]]
    assert len(store.all("assessments")) == 2  # latest-state view still one per finding


def test_retry_within_a_run_is_idempotent(crosswalk):
    store = MemoryStore()
    ec.run_collection(arm(happy_routes()), store, SUB, crosswalk, run_id="fixed-run")
    ec.run_collection(arm(happy_routes()), store, SUB, crosswalk, run_id="fixed-run")
    assert len(store.all("snapshots")) == 4


def test_latest_state_id_matches_the_starter_formula():
    import hashlib

    ctx = ec.RunContext("r", "2026-10-17T00:00:00+00:00", "t")
    snap = ec.normalize_defender(defender_item(PUBLIC_BLOB_ASSESSMENT_NAME, "x", "Healthy"), ctx, SUB)
    starter = hashlib.sha256(f"{PUBLIC_BLOB_ASSESSMENT_NAME}|{SEED}".encode()).hexdigest()[:32]
    assert ec.latest_state_document(snap)["id"] == starter  # upserts onto existing Lab docs


def test_one_source_failing_marks_run_partial_not_completed(crosswalk):
    routes = happy_routes()
    routes[("POST", POL_PATH)] = [FakeResponse(403, {"error": {"code": "AuthorizationFailed"}})]
    store = MemoryStore()
    m = ec.run_collection(arm(routes), store, SUB, crosswalk)
    assert m["status"] == "partial"
    assert m["sources"]["policy"]["errors"] and m["sources"]["defender"]["documents"] == 2


def test_everything_failing_marks_run_failed(crosswalk):
    routes = {("GET", DEF_PATH): [FakeResponse(403, {})], ("POST", POL_PATH): [FakeResponse(403, {})]}
    m = ec.run_collection(arm(routes), MemoryStore(), SUB, crosswalk)
    assert m["status"] == "failed" and m["documentCount"] == 0


def test_throttling_is_retried_with_retry_after():
    sleeps: list[float] = []
    routes = {("GET", DEF_PATH): [FakeResponse(429, {}, {"Retry-After": "7"}), FakeResponse(200, {"value": []})]}
    client = arm(routes, sleeps)
    assert list(client.paginate("GET", DEF_PATH)) == []
    assert sleeps == [7.0]


def test_non_retryable_error_raises():
    client = arm({("GET", DEF_PATH): [FakeResponse(404, {"error": "nope"})]})
    with pytest.raises(ec.ArmError):
        list(client.paginate("GET", DEF_PATH))


def test_manual_trigger_is_labeled_and_unknown_trigger_rejected(crosswalk):
    m = ec.run_collection(arm(happy_routes()), MemoryStore(), SUB, crosswalk, trigger="manual")
    assert m["trigger"] == "manual"
    with pytest.raises(ValueError):
        ec.run_collection(arm(happy_routes()), MemoryStore(), SUB, crosswalk, trigger="cron")


def test_normalization_maps_status_to_result():
    ctx = ec.RunContext("r", "t", "v")
    assert ec.normalize_defender(defender_item("a", "x", "Healthy"), ctx, SUB)["result"] == "pass"
    assert ec.normalize_defender(defender_item("a", "x", "Unhealthy"), ctx, SUB)["result"] == "fail"
    assert ec.normalize_defender(defender_item("a", "x", "NotApplicable"), ctx, SUB)["result"] == "not_applicable"
    assert ec.normalize_policy_state(policy_item("d", "NonCompliant"), ctx)["result"] == "fail"
    assert ec.normalize_policy_state(policy_item("d", "Exempt"), ctx)["result"] == "not_applicable"


def test_resource_id_falls_back_to_assessment_id():
    item = defender_item("abc", "x", "Healthy")
    item["properties"].pop("resourceDetails")
    ctx = ec.RunContext("r", "t", "v")
    assert ec.normalize_defender(item, ctx, SUB)["resourceId"] == SEED


def test_digest_is_reproducible_from_stored_documents(crosswalk):
    import hashlib

    store = MemoryStore()
    m = ec.run_collection(arm(happy_routes()), store, SUB, crosswalk)
    ids = sorted(d["id"] for d in store.all("snapshots") if d["runId"] == m["runId"])
    assert hashlib.sha256("\n".join(ids).encode()).hexdigest() == m["documentSetSha256"]
