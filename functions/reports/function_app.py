"""CGE-AZ pipeline - Stage 4 report generators (Tallyfin capstone edition).

Reports read from Cosmos ONLY - never from live services. The reporter identity
has no Azure Resource Manager role, so this is enforced by identity, not just by
convention. All logic is in ``reports_core.py`` (tested in tests/test_reports.py).

Generators:
  * POA&M  - daily (POAM_SCHEDULE): poam.json + poam.xlsx + manifest.json
  * SAR    - daily (SAR_SCHEDULE): sar.md + scorecard.json (per-framework view
             through the crosswalk, and change since the previous run) + manifest.json
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import azure.functions as func
from azure.identity import DefaultAzureCredential

from reports_core import BlobReportWriter, CosmosEvidenceReader, generate_poam, generate_sar

app = func.FunctionApp()


def _clients() -> tuple[CosmosEvidenceReader, BlobReportWriter]:
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    reader = CosmosEvidenceReader(os.environ["COSMOS_ENDPOINT"], os.environ["COSMOS_DATABASE"], credential)
    writer = BlobReportWriter(os.environ["REPORTS_ACCOUNT_URL"], os.environ["REPORTS_CONTAINER"], credential)
    return reader, writer


def _opts() -> dict[str, Any]:
    return {
        "max_age_hours": float(os.environ.get("MAX_RUN_AGE_HOURS", "13")),
        "app_version": os.environ.get("APP_VERSION", "dev"),
    }


def _summary(m: dict[str, Any]) -> dict[str, Any]:
    return {k: m.get(k) for k in ("report", "folder", "reportExecutionId", "runId", "digestVerified")}


@app.timer_trigger(schedule="%POAM_SCHEDULE%", arg_name="timer", run_on_startup=False, use_monitor=True)
def poam_daily(timer: func.TimerRequest) -> None:
    reader, writer = _clients()
    logging.info("POA&M: %s", json.dumps(_summary(generate_poam(reader, writer, **_opts()))))


@app.timer_trigger(schedule="%SAR_SCHEDULE%", arg_name="timer", run_on_startup=False, use_monitor=True)
def sar_daily(timer: func.TimerRequest) -> None:
    reader, writer = _clients()
    logging.info("SAR: %s", json.dumps(_summary(generate_sar(reader, writer, **_opts()))))


if os.environ.get("ENABLE_MANUAL_TRIGGERS", "false").lower() == "true":

    @app.route(route="poam", auth_level=func.AuthLevel.FUNCTION)
    def poam_now(req: func.HttpRequest) -> func.HttpResponse:
        reader, writer = _clients()
        return func.HttpResponse(json.dumps(_summary(generate_poam(reader, writer, **_opts()))) + "\n", mimetype="application/json")

    @app.route(route="sar", auth_level=func.AuthLevel.FUNCTION)
    def sar_now(req: func.HttpRequest) -> func.HttpResponse:
        reader, writer = _clients()
        return func.HttpResponse(json.dumps(_summary(generate_sar(reader, writer, **_opts()))) + "\n", mimetype="application/json")
