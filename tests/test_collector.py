from __future__ import annotations

from datetime import datetime, timezone

import pytest

import evidence_core as ec
from conftest import (
    MG, OWNER_GUID, SEED, SUB, FakeCredential, FakeResponse, FakeSession, MemoryStore, defender_item,
    policy_item, rbac_routes, role_assignment, subscriptions_route,
)

SUB2 = "11111111-1111-1111-1111-111111111111"
PUBLIC_BLOB_ASSESSMENT_NAME = "51fd8bb1-0db4-bbf1-7e2b-cfcba7eb66a6"


def def_path(sub: str) -> str:
    return f"/subscriptions/{sub}/providers/Microsoft.Security/assessments"


def pol_path(sub: str) -> str:
    return f"/subscriptions/{sub}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults"


DEF_PATH = def_path(SUB)
POL_PATH = pol_path(SUB)


def arm(routes, sleeps=None):
    return ec.ArmClient(FakeCredential(), FakeSession(routes), sleep=(sleeps.append if sleeps is not None else lambda s: None), audit=lambda e: None)


def subscription_routes(sub: str) -> dict:
    seed = f"/subscriptions/{sub}/resourceGroups/rg-grc-sandbox-dev/providers/Microsoft.Storage/storageAccounts/stseed"
    return {
        ("GET", def_path(sub)): [
            FakeResponse(200, {
                "value": [defender_item(PUBLIC_BLOB_ASSESSMENT_NAME, "Storage account public access should be disallowed", "Unhealthy", resource=seed)],
                "nextLink": f"https://management.azure.com{def_path(sub)}?page=2",
            }),
            FakeResponse(200, {"value": [defender_item("aaaa", "Storage accounts should prevent shared key access", "Unhealthy", resource=seed, severity="Medium")]}),
        ],
        ("POST", pol_path(sub)): [
            FakeResponse(200, {"value": [policy_item("cge-deny-public-blob", "NonCompliant", resource=seed)],
                               "@odata.nextLink": f"https://management.azure.com{pol_path(sub)}?$skiptoken=x"}),
            FakeResponse(200, {"value": [policy_item("fafo-storage-min-tls12", "Compliant", resource=seed)]}),
        ],
        **rbac_routes(sub),
    }


def happy_routes(*subs: str) -> dict:
    subs = subs or (SUB,)
    routes = dict(subscriptions_route(*subs))
    for s in subs:
        routes.update(subscription_routes(s))
    return routes


def test_run_writes_history_manifest_and_latest_state(crosswalk):
    store = MemoryStore()
    m = ec.run_collection(arm(happy_routes()), store, MG, crosswalk, now=datetime(2026, 10, 17, 18, tzinfo=timezone.utc))

    assert m["status"] == "completed" and m["trigger"] == "timer"
    assert m["scope"] == {"managementGroup": MG, "subscriptions": [SUB]}
    assert m["sources"]["defender"]["documents"] == 2 and m["sources"]["rbac"]["documents"] == 2
    assert len(store.all("findings")) == 4  # both pages of both sources followed
    assert len(store.all("rbac")) == 2
    assert len(store.all("assessments")) == 2  # starter latest-state view: Defender only
    assert store.all("runs")[0]["status"] == "completed"
    assert store.all("mappings")[0]["id"] == f"crosswalk-{m['crosswalkVersion']}"
    for d in store.all("findings") + store.all("rbac"):
        # Both levels of the hierarchical partition key are always present.
        assert d["runId"] == m["runId"] and d["subscriptionId"] == SUB and d["collectedAt"]


def test_new_subscription_is_collected_with_no_configuration_change(crosswalk):
    """Scale by scope: FAFO's second subscription lands under the MG and the next run has it."""
    store = MemoryStore()
    m = ec.run_collection(arm(happy_routes(SUB, SUB2)), store, MG, crosswalk)
    assert m["status"] == "completed" and m["scope"]["subscriptions"] == sorted([SUB, SUB2])
    assert {d["subscriptionId"] for d in store.all("findings")} == {SUB, SUB2}
    assert {d["subscriptionId"] for d in store.all("rbac")} == {SUB, SUB2}
    assert m["subscriptionResults"][SUB2]["defender"] == 2


def test_one_subscription_failing_marks_the_whole_run_partial(crosswalk):
    routes = happy_routes(SUB, SUB2)
    routes[("POST", pol_path(SUB2))] = [FakeResponse(403, {"error": {"code": "AuthorizationFailed"}})]
    m = ec.run_collection(arm(routes), MemoryStore(), MG, crosswalk)
    assert m["status"] == "partial"
    assert m["subscriptionResults"][SUB2]["errors"] and not m["subscriptionResults"][SUB]["errors"]


def test_no_visible_subscriptions_fails_the_run(crosswalk):
    m = ec.run_collection(arm(subscriptions_route()), MemoryStore(), MG, crosswalk)
    assert m["status"] == "failed" and m["discoveryErrors"]


def test_disabled_subscriptions_are_out_of_scope():
    client = arm({("GET", "/subscriptions"): [FakeResponse(200, {"value": [
        {"subscriptionId": "b", "state": "Enabled"}, {"subscriptionId": "a", "state": "Disabled"}]})]})
    assert ec.discover_subscriptions(client) == ["b"]


def test_history_accumulates_across_runs_but_finding_identity_is_stable(crosswalk):
    store = MemoryStore()
    m1 = ec.run_collection(arm(happy_routes()), store, MG, crosswalk)
    m2 = ec.run_collection(arm(happy_routes()), store, MG, crosswalk)
    snaps = store.all("findings")
    assert len(snaps) == 8  # Lab 6 gap closed: run 2 did not overwrite run 1
    keys = {r: {d["findingKey"] for d in snaps if d["runId"] == r} for r in (m1["runId"], m2["runId"])}
    assert keys[m1["runId"]] == keys[m2["runId"]]
    assert len(store.all("assessments")) == 2  # latest-state view still one per finding
    assert len(store.all("rbac")) == 4  # RBAC history accumulates too


def test_retry_within_a_run_is_idempotent(crosswalk):
    store = MemoryStore()
    ec.run_collection(arm(happy_routes()), store, MG, crosswalk, run_id="fixed-run")
    ec.run_collection(arm(happy_routes()), store, MG, crosswalk, run_id="fixed-run")
    assert len(store.all("findings")) == 4 and len(store.all("rbac")) == 2


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
    m = ec.run_collection(arm(routes), store, MG, crosswalk)
    assert m["status"] == "partial"
    assert m["sources"]["policy"]["errors"] and m["sources"]["defender"]["documents"] == 2


def test_everything_failing_marks_run_failed(crosswalk):
    routes = {**subscriptions_route(SUB), ("GET", DEF_PATH): [FakeResponse(403, {})], ("POST", POL_PATH): [FakeResponse(403, {})],
              ("GET", f"/subscriptions/{SUB}/providers/Microsoft.Authorization/roleDefinitions"): [FakeResponse(403, {})]}
    m = ec.run_collection(arm(routes), MemoryStore(), MG, crosswalk)
    assert m["status"] == "failed" and m["documentCount"] == 0


def test_rbac_snapshot_classifies_scope_privilege_and_inheritance(crosswalk):
    store = MemoryStore()
    ec.run_collection(arm(happy_routes()), store, MG, crosswalk)
    docs = {d["roleName"]: d for d in store.all("rbac")}
    owner, reader = docs["Owner"], docs["Reader"]
    assert owner["privileged"] and owner["scopeLevel"] == "subscription" and not owner["inherited"]
    assert not reader["privileged"] and reader["scopeLevel"] == "managementGroup" and reader["inherited"]


def test_privileged_role_is_recognized_by_guid_even_without_a_definition():
    ctx = ec.RunContext("r", "t", "v")
    item = role_assignment(SUB, "x", OWNER_GUID, f"/subscriptions/{SUB}/resourceGroups/rg", "u")
    doc = ec.normalize_role_assignment(item, ctx, SUB, {})
    assert doc["privileged"] and doc["roleName"] == "unknown" and doc["scopeLevel"] == "resourceGroup"


def test_scope_levels():
    assert ec.scope_level("/") == "root"
    assert ec.scope_level("/providers/Microsoft.Management/managementGroups/mg") == "managementGroup"
    assert ec.scope_level(f"/subscriptions/{SUB}") == "subscription"
    assert ec.scope_level(f"/subscriptions/{SUB}/resourceGroups/rg") == "resourceGroup"
    assert ec.scope_level(f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/s") == "resource"


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
    m = ec.run_collection(arm(happy_routes()), MemoryStore(), MG, crosswalk, trigger="manual")
    assert m["trigger"] == "manual"
    with pytest.raises(ValueError):
        ec.run_collection(arm(happy_routes()), MemoryStore(), MG, crosswalk, trigger="cron")


def test_normalization_maps_status_to_result():
    ctx = ec.RunContext("r", "t", "v")
    assert ec.normalize_defender(defender_item("a", "x", "Healthy"), ctx, SUB)["result"] == "pass"
    assert ec.normalize_defender(defender_item("a", "x", "Unhealthy"), ctx, SUB)["result"] == "fail"
    assert ec.normalize_defender(defender_item("a", "x", "NotApplicable"), ctx, SUB)["result"] == "not_applicable"
    assert ec.normalize_policy_state(policy_item("d", "NonCompliant"), ctx)["result"] == "fail"
    assert ec.normalize_policy_state(policy_item("d", "Exempt"), ctx)["result"] == "not_applicable"


def test_policy_state_without_subscription_falls_back_to_the_queried_one():
    item = policy_item("d", "NonCompliant")
    item.pop("subscriptionId")
    doc = ec.normalize_policy_state(item, ec.RunContext("r", "t", "v"), SUB)
    assert doc["subscriptionId"] == SUB  # part of the partition key: never null


def test_resource_id_falls_back_to_assessment_id():
    item = defender_item("abc", "x", "Healthy")
    item["properties"].pop("resourceDetails")
    ctx = ec.RunContext("r", "t", "v")
    assert ec.normalize_defender(item, ctx, SUB)["resourceId"] == SEED


def test_digest_is_reproducible_from_stored_documents(crosswalk):
    import hashlib

    store = MemoryStore()
    m = ec.run_collection(arm(happy_routes()), store, MG, crosswalk)
    ids = sorted(d["id"] for d in store.all("findings") if d["runId"] == m["runId"])
    assert hashlib.sha256("\n".join(ids).encode()).hexdigest() == m["documentSetSha256"]
    rbac_ids = sorted(d["id"] for d in store.all("rbac"))
    assert hashlib.sha256("\n".join(rbac_ids).encode()).hexdigest() == m["containers"]["rbac"]["documentSetSha256"]
