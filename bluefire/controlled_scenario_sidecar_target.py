"""Join one captured Strix shell result to a protected tenant sidecar event.

This is the target half of the controlled Test-provider observation. The
installed composition must additionally reopen exact exec admission, dispatch,
attachment and terminal custody before it may return a
``VerifiedScenarioObservation`` to the provider.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from urllib.parse import urlsplit

from .controlled_scenario_observation_journal import ControllerScenarioObservationJournal
from .controlled_scenario_target_contract import (
    ScenarioSidecarTargetError,
    expected_discovery_body,
    match_captured_http,
)
from .controlled_scenario_target_contract import (
    captured_http as _captured_http,
)
from .controlled_scenario_target_contract import (
    pending_command as _pending_command,
)
from .controlled_strix_scenario import ScenarioObservationRequest
from .evidence import EvidenceRecord
from .tenant_record_experiment_fixture import (
    TenantRecordExperimentCase,
    TenantRecordTargetUrlSet,
)
from .tenant_record_lab import TenantDefenseConfig, TenantRecordFixture
from .tenant_record_observer import TenantRecordObservationError, observe_tenant_response
from .tenant_record_sidecar_observer import (
    OwnedTenantSidecarObservationReader,
    SidecarTargetObservation,
)


@dataclass(frozen=True, slots=True)
class VerifiedScenarioSidecarTarget:
    call_capture_ref: str
    sidecar_source_ref: str
    evidence_retention_ref: str
    observed: SidecarTargetObservation
    evidence: EvidenceRecord


def verify_sidecar_target_result(
    *,
    request: ScenarioObservationRequest,
    operation_id: str,
    journal: ControllerScenarioObservationJournal,
    reader: OwnedTenantSidecarObservationReader,
    fixture: TenantRecordFixture,
    target_config: TenantDefenseConfig,
    case: TenantRecordExperimentCase,
    url_set: TenantRecordTargetUrlSet,
    run_id: str,
    step_id: str,
) -> VerifiedScenarioSidecarTarget:
    """Persist/reopen one exact target event before a Test-provider decision."""
    if (
        type(request) is not ScenarioObservationRequest
        or type(journal) is not ControllerScenarioObservationJournal
        or type(reader) is not OwnedTenantSidecarObservationReader
        or type(fixture) is not TenantRecordFixture
        or type(target_config) is not TenantDefenseConfig
        or type(case) is not TenantRecordExperimentCase
        or type(url_set) is not TenantRecordTargetUrlSet
        or request.attempt_id != case.attempt_id
        or case.asset_ref != fixture.digest
        or case.target_config_ref != target_config.digest
        or case.target_snapshot_ref != reader.source_binding["target_snapshot_ref"]
        or case.target_snapshot_id != reader.source_binding["target_snapshot_id"]
        or fixture.digest != reader.source_binding["fixture_digest"]
        or case.service_generation != reader.source_binding["service_generation"]
        or case.authorized_url_set_ref != url_set.digest
        or case.target_origin != url_set.target_origin
        or case.attempt_id != url_set.attempt_id
        or request.target_url not in url_set.urls
        or request.authorized_url_set_ref != url_set.digest
        or reader.source_binding["attempt_id"] != request.attempt_id
    ):
        raise ScenarioSidecarTargetError("target source and pending attempt differ")
    captured = journal.reopen_settled_exec(request.attempt_id, operation_id)
    tool = captured.document
    _pending_command(request, tool.get("argv"), fixture.protected_tenant_id)
    if tool.get("exit_code") != 0:
        raise ScenarioSidecarTargetError("captured target command did not complete")
    try:
        stdout = base64.b64decode(tool["stdout_base64"], validate=True)
        if stdout.decode("utf-8") != request.model_result:
            raise ValueError("model-visible result")
    except (KeyError, TypeError, ValueError, UnicodeError, binascii.Error) as exc:
        raise ScenarioSidecarTargetError(
            "model-visible result differs from captured shell"
        ) from exc
    _, headers, body = _captured_http(stdout)
    request_id = headers["x-bluefire-lab-request"]
    observed = reader.observe_request(request_id)
    reopened = reader.reopen_request(request.attempt_id, request_id)
    expected_path = urlsplit(request.target_url)
    target_path = expected_path.path + ("?" + expected_path.query if expected_path.query else "")
    if (
        reopened != observed
        or reopened.admitted_target_url != request.target_url
        or reopened.request_target != target_path
        or reopened.audit_row.request_id != request_id
        or reopened.source_receipt_ref == ""
    ):
        raise ScenarioSidecarTargetError("captured shell and protected target event differ")
    match_captured_http(
        stdout,
        source_status=reopened.response_status,
        source_headers=reopened.response_headers,
        source_body=reopened.response_body,
    )
    try:
        evidence = observe_tenant_response(
            fixture=fixture,
            config=target_config,
            audit_row=reopened.audit_row,
            response_status=reopened.response_status,
            response_headers=reopened.response_headers,
            response_body=reopened.response_body,
            attempt_id=request.attempt_id,
            run_id=run_id,
            step_id=step_id,
            target_scope_ref=case.scope_ref,
        )
    except TenantRecordObservationError as exc:
        raise ScenarioSidecarTargetError("target response lacks independent evidence") from exc
    if request.phase_id == "discover_target":
        if request.target_url != case.target_origin + "/openapi.json":
            raise ScenarioSidecarTargetError("discovery target URL differs from the case")
        if (
            reopened.audit_row.route != "metadata"
            or reopened.response_status != 200
            or body != expected_discovery_body(fixture)
        ):
            raise ScenarioSidecarTargetError("public discovery differs from target source")
    elif request.phase_id == "try_record_lookup" and reopened.audit_row.route != "record_lookup":
        raise ScenarioSidecarTargetError("record lookup phase differs from target route")
    elif request.phase_id == "try_bounded_export" and reopened.audit_row.route != "bounded_export":
        raise ScenarioSidecarTargetError("export phase differs from target route")
    retained = journal.retain_sidecar_evidence(
        request=request,
        operation_id=operation_id,
        sidecar_source_ref=reopened.source_receipt_ref,
        target_request_id=request_id,
        evidence=evidence,
        reader=reader,
        fixture=fixture,
        config=target_config,
        case=case,
        url_set=url_set,
    )
    if retained.tool_capture_ref != captured.capture_ref or retained.evidence != evidence:
        raise ScenarioSidecarTargetError("retained target evidence changed")
    return VerifiedScenarioSidecarTarget(
        captured.capture_ref,
        reopened.source_receipt_ref,
        retained.retention_ref,
        reopened,
        retained.evidence,
    )
