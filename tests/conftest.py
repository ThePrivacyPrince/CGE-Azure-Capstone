"""Shared fakes. The functions' core modules take their Azure dependencies as
parameters, so the whole collect -> store -> report loop runs here with no cloud."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions" / "collect_assessments"))
sys.path.insert(0, str(ROOT / "functions" / "reports"))


class FakeToken:
    token = "test-token"  # not a credential: a fixed string for the fake session
    expires_on = 9_999_999_999


class FakeCredential:
    def __init__(self) -> None:
        self.calls = 0

    def get_token(self, *scopes: str) -> FakeToken:
        self.calls += 1
        return FakeToken()


class FakeResponse:
    def __init__(self, status: int, body: Any = None, headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self.headers = headers or {}
        self._body = body
        self.text = "" if body is None else json.dumps(body)

    def json(self) -> Any:
        return self._body


class FakeSession:
    """Routes by (method, path-without-query) to a queue of responses."""

    def __init__(self, routes: dict[tuple[str, str], list[FakeResponse]]) -> None:
        self.routes = {k: list(v) for k, v in routes.items()}
        self.calls: list[tuple[str, str]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        path = url.split("?")[0].replace("https://management.azure.com", "")
        self.calls.append((method, path))
        queue = self.routes.get((method, path))
        if not queue:
            raise AssertionError(f"unexpected call {method} {path}")
        return queue.pop(0)


class MemoryStore:
    """Cosmos stand-in: container -> id -> document (upsert semantics)."""

    def __init__(self) -> None:
        self.data: dict[str, dict[str, dict[str, Any]]] = {}

    def upsert(self, container: str, document: dict[str, Any]) -> None:
        self.data.setdefault(container, {})[document["id"]] = json.loads(json.dumps(document))

    def all(self, container: str) -> list[dict[str, Any]]:
        return list(self.data.get(container, {}).values())


class MemoryReader:
    """Answers exactly the queries reports_core issues, against a MemoryStore."""

    def __init__(self, store: MemoryStore) -> None:
        self.store = store

    def query(self, container, query, parameters=None, partition_key=None):  # type: ignore[no-untyped-def]
        import reports_core as rc

        p = {x["name"]: x["value"] for x in (parameters or [])}
        rows = self.store.all(container)
        if query == rc.Q_LATEST_COMPLETED:
            done = [r for r in rows if r.get("type") == "run-manifest" and r.get("status") == "completed"]
            return sorted(done, key=lambda r: r["completedAt"], reverse=True)[:1]
        if query == rc.Q_PREVIOUS_COMPLETED:
            done = [
                r for r in rows
                if r.get("type") == "run-manifest" and r.get("status") == "completed" and r["completedAt"] < p["@before"]
            ]
            return sorted(done, key=lambda r: r["completedAt"], reverse=True)[:1]
        if query == rc.Q_RUN_SNAPSHOTS:
            return [r for r in rows if r["runId"] == p["@runId"]]
        if query == rc.Q_CROSSWALK:
            return [r for r in rows if r["id"] == p["@id"] and r.get("frameworkId") == partition_key]
        if query == rc.Q_FIRST_SEEN:
            return [
                {"findingKey": r["findingKey"], "collectedAt": r["collectedAt"]}
                for r in rows
                if r.get("result") == "fail" and r["findingKey"] in p["@keys"]
            ]
        raise AssertionError(f"unexpected query {query}")


class MemoryWriter:
    def __init__(self) -> None:
        self.blobs: dict[str, bytes] = {}
        self.order: list[str] = []

    def upload(self, path: str, data: bytes, content_type: str) -> None:
        if path in self.blobs:
            raise FileExistsError(path)  # mirrors overwrite=False
        self.blobs[path] = data
        self.order.append(path)


SUB = "00000000-0000-0000-0000-000000000000"
SEED = f"/subscriptions/{SUB}/resourceGroups/rg-grc-sandbox-dev/providers/Microsoft.Storage/storageAccounts/stgrcseed15471"


def defender_item(name: str, display: str, code: str, resource: str = SEED, severity: str = "High") -> dict[str, Any]:
    return {
        "id": f"{resource}/providers/Microsoft.Security/assessments/{name}",
        "name": name,
        "properties": {
            "displayName": display,
            "resourceDetails": {"Source": "Azure", "Id": resource},
            "status": {"code": code, "statusChangeDate": "2026-10-17T18:00:00Z"},
            "metadata": {"severity": severity, "categories": ["Data"]},
        },
    }


def policy_item(definition: str, state: str, resource: str = SEED, assignment: str = "cge-grc-baseline") -> dict[str, Any]:
    return {
        "resourceId": resource,
        "subscriptionId": SUB,
        "policyAssignmentId": f"/providers/Microsoft.Management/managementGroups/mg-grc-sandbox/providers/Microsoft.Authorization/policyAssignments/{assignment}",
        "policyAssignmentName": assignment,
        "policyDefinitionName": definition,
        "policyDefinitionReferenceId": "",
        "policyDefinitionAction": "audit",
        "complianceState": state,
        "timestamp": "2026-10-17T17:55:00Z",
    }


@pytest.fixture()
def crosswalk() -> dict[str, Any]:
    return json.loads((ROOT / "frameworks" / "mappings.json").read_text())


@pytest.fixture()
def fakes():
    return {
        "FakeCredential": FakeCredential,
        "FakeResponse": FakeResponse,
        "FakeSession": FakeSession,
        "MemoryStore": MemoryStore,
        "MemoryReader": MemoryReader,
        "MemoryWriter": MemoryWriter,
    }
