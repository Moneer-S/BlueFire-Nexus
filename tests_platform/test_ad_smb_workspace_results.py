"""Synthetic original terminals only; no channel authentication or native effects."""

from copy import deepcopy
from datetime import timedelta

import pytest

from bluefire.ad_smb_channel import AdSmbHostChannel
from bluefire.ad_smb_contract import AdSmbError, AdSmbScope
from bluefire.ad_smb_receiver_results import native_generation, result_record, stored_result
from bluefire.ad_smb_worker_wire import RECEIVER_RESULT_MAX, prepare_packet
from bluefire.ad_smb_workspace_results import project_original
from bluefire.util import content_hash
from tests_platform.test_ad_smb_audit import event as audit_event
from tests_platform.test_ad_smb_contract import NOW
from tests_platform.test_ad_smb_native_member_results import (
    audit_fixture,
)
from tests_platform.test_ad_smb_native_member_results import (
    fixture as member_fixture,
)
from tests_platform.test_ad_smb_native_results import denied
from tests_platform.test_ad_smb_receiver import original, packet, read_record, record
from tests_platform.test_ad_smb_worker_wire import (
    fixture as wire_fixture,
)
from tests_platform.test_ad_smb_worker_wire import (
    rebind_context,
    terminal_row,
)


def member_original(phase="inspect"):
    request, raw = member_fixture()
    scope = AdSmbScope.from_mapping(request["scope"])
    value, old_channel = original(phase)
    channel = AdSmbHostChannel.from_mapping(
        scope, {**old_channel.to_dict(), "scope_digest": scope.digest}
    )
    host = {
        **value["transport_identity"],
        "channel_digest": channel.digest,
        "native_generation": native_generation(channel),
    }
    value = rebind_context(
        value,
        scope=scope.to_dict(),
        scope_digest=scope.digest,
        host=host,
        change=request["change"] if phase in {"harden", "rollback"} else None,
    )
    value["transport_identity"] = host
    return value, channel, raw


def timed_record(value, channel, raw):
    public = packet(value, channel)
    terminal = terminal_row(public)
    terminal["result"] = raw
    return result_record(
        public,
        terminal,
        native_digest=channel.to_dict()["runner_binary_digest"],
        issue=None,
        receiver_completed_at=(NOW + timedelta(seconds=2)).isoformat(),
    )


def project(value, channel, saved):
    return project_original(value["manifest"]["params"]["ad_smb_request"], value, channel, saved)


def test_inspection_uses_recorded_receiver_time_and_exact_source_receipt():
    value, channel, raw = member_original()
    saved = timed_record(value, channel, raw)
    result = project(value, channel, saved)
    assert result["observation"]["snapshot"]["observed_at"] == saved["receiver_completed_at"]
    assert result["observation"]["snapshot"]["descriptor"] == raw["share"]["descriptor"]
    assert result["provenance"] == "runner_reported"
    assert result["observation"]["after_descriptor"] == raw["after_descriptor"]
    assert "receiver_completed_at" not in result


def test_v1_inspect_recovers_without_invented_snapshot_timestamp():
    value, channel, raw = member_original()
    saved = timed_record(value, channel, raw)
    saved["schema_version"] = "bluefire.ad-smb-receiver-result.v1"
    del saved["receiver_completed_at"]
    assert (
        stored_result(
            saved, value["manifest"], value["profile"], channel, maximum=RECEIVER_RESULT_MAX
        )
        == saved
    )
    with pytest.raises(AdSmbError, match="no receiver observation timestamp"):
        project(value, channel, saved)


@pytest.mark.parametrize(
    "time_value", [None, NOW - timedelta(microseconds=1), NOW + timedelta(seconds=31)]
)
def test_v2_refuses_missing_or_outside_original_receiver_timestamp(time_value):
    value, channel, raw = member_original()
    saved = timed_record(value, channel, raw)
    saved["receiver_completed_at"] = time_value.isoformat() if time_value else None
    with pytest.raises(AdSmbError):
        project(value, channel, saved)


def test_v2_completion_cannot_precede_possible_original_preparation_interval():
    value, channel, raw = member_original()
    public = prepare_packet(
        value,
        channel,
        challenge="a" * 64,
        credential_binding_digest=None,
        expected_upn_sha256=None,
        prior_local_authentication_ids=[],
        clock=NOW + timedelta(seconds=29),
    )
    terminal = terminal_row(public)
    terminal["result"] = raw
    saved = result_record(
        public,
        terminal,
        native_digest=channel.to_dict()["runner_binary_digest"],
        issue=None,
        receiver_completed_at=(NOW + timedelta(seconds=2)).isoformat(),
    )
    with pytest.raises(AdSmbError):
        project(value, channel, saved)
    earliest = NOW + timedelta(seconds=29) - timedelta(milliseconds=1) + timedelta(microseconds=1)
    saved["receiver_completed_at"] = (earliest - timedelta(microseconds=1)).isoformat()
    with pytest.raises(AdSmbError):
        project(value, channel, saved)
    saved["receiver_completed_at"] = earliest.isoformat()
    assert project(value, channel, saved)["observation"] is not None


def test_timeout_limited_v2_does_not_invent_a_late_preparation_lower_bound():
    value, channel = wire_fixture(
        limits={
            "timeout_ms": 1000,
            "max_stdout_bytes": 4259840,
            "max_stderr_bytes": 65536,
            "max_artifact_bytes": 1048576,
            "max_files": 2,
        }
    )
    host = {**value["transport_identity"], "native_generation": native_generation(channel)}
    value = rebind_context(value, host=host)
    value["transport_identity"] = host
    public = prepare_packet(
        value,
        channel,
        challenge="a" * 64,
        credential_binding_digest=None,
        expected_upn_sha256=None,
        prior_local_authentication_ids=[],
        clock=NOW,
    )
    saved = result_record(
        public,
        terminal_row(public),
        native_digest=channel.to_dict()["runner_binary_digest"],
        issue="native_error",
        receiver_completed_at=NOW.isoformat(),
    )
    assert (
        stored_result(
            saved, value["manifest"], value["profile"], channel, maximum=RECEIVER_RESULT_MAX
        )
        == saved
    )


@pytest.mark.parametrize("phase", ["harden", "rollback"])
def test_matched_share_write_projects_exact_descriptor_and_keeps_resource_binding(phase):
    value, channel, inspected = member_original(phase)
    request = value["manifest"]["params"]["ad_smb_request"]
    target = (
        request["change"]["after_descriptor"]
        if phase == "harden"
        else request["change"]["before"]["descriptor"]
    )
    raw = {
        "state": "readback_matched",
        "write_attempted": True,
        "set_status": 0,
        "readback": {**inspected["share"], "descriptor": target},
        "issue": None,
    }
    result = project(value, channel, timed_record(value, channel, raw))
    assert result["observation"]["state"] == "readback_matched"
    assert result["observation"]["snapshot"]["descriptor"] == target


@pytest.mark.parametrize(
    "state,attempt,status,issue",
    [
        ("not_attempted", False, None, "preimage_unavailable"),
        ("unknown", True, 5, "set_response_failed_state_unknown"),
    ],
)
def test_negative_write_is_not_upgraded(state, attempt, status, issue):
    value, channel, _ = member_original("harden")
    raw = {
        "state": state,
        "write_attempted": attempt,
        "set_status": status,
        "readback": None,
        "issue": issue,
    }
    result = project(value, channel, timed_record(value, channel, raw))
    assert result["observation"] == {"state": state, "snapshot": None}


@pytest.mark.parametrize("denial", [False, True])
def test_read_keeps_expected_remote_and_actual_local_identities_separate(denial):
    value, channel = original("baseline")
    saved = read_record(value, channel, 123)
    if denial:
        denied(saved["terminal"]["result"])
    result = project(value, channel, saved)
    row = result["observation"]
    assert row["state"] == ("open_access_denied" if denial else "bytes_matched")
    assert row["local_user_sid"] != row["expected_remote_sid"]
    assert row["authenticated_remote_reader"] is row["fresh_server_logon"] is False
    assert row["independent_observation"] is row["effective_access_claim"] is False


@pytest.mark.parametrize("partial", [False, True])
def test_audit_summary_does_not_self_certify_raw_xml(partial):
    value, channel = original("audit")
    _, raw = audit_fixture()
    event_xml = audit_event(when="2026-10-09T00:00:00.5000000Z")
    raw.update(
        state="byte_limit" if partial else "query_exhausted",
        raw_events=[event_xml.decode("utf-8")],
        utf8_bytes=len(event_xml),
    )
    saved = timed_record(value, channel, raw)
    result = project(value, channel, saved)
    assert result["observation"]["truncated"] is partial
    assert result["observation"]["events"] == 1
    assert "raw_events" not in str(result)
    assert result["observation"]["authenticated_source"] is False
    normalized = result["observation"]["normalized_observation"]
    assert normalized["schema_version"] == "bluefire.ad-smb-audit-observation.v2"
    assert normalized["reported_completeness"] == ("truncated" if partial else "complete")
    assert normalized["capture_batch_digest"].startswith("sha256:")
    assert normalized["source_receipt_digest"] == content_hash(saved)
    assert "record_epoch_digest" not in normalized
    assert normalized["events"][0]["client_ip"] == "10.44.0.3"
    assert normalized["events"][0]["record_id"] == "20"


def test_legacy_audit_summary_remains_valid_without_replay_payload():
    from bluefire.ad_smb_results import validate_execution

    value, _ = original("audit")
    request = value["manifest"]["params"]["ad_smb_request"]
    summary = {
        "source_digest": "sha256:" + "a" * 64,
        "events": 2,
        "truncated": False,
        "authenticated_source": False,
        "independent_observation": False,
        "effective_access_claim": False,
    }
    result = validate_execution(
        request,
        {
            "schema_version": "bluefire.ad-smb-execution.v1",
            "request_digest": content_hash(request),
            "provenance": "runner_reported",
            "dispatch": "attempted",
            "cleanup": "verified",
            "observation": summary,
        },
    )
    assert result["observation"] == summary


def test_audit_projection_is_repeatable_and_does_not_replay_or_mutate_source():
    value, channel = original("audit")
    _, raw = audit_fixture()
    raw["raw_events"] = [audit_event(when="2026-10-09T00:00:00.5000000Z").decode("utf-8")]
    raw["utf8_bytes"] = len(raw["raw_events"][0].encode("utf-8"))
    saved = timed_record(value, channel, raw)
    before = deepcopy((value, saved))
    first = project(value, channel, saved)
    second = project(value, channel, saved)
    assert first == second
    assert (value, saved) == before
    assert "raw_events" not in str(first)


def test_audit_projection_preserves_ambiguous_logon_correlation():
    value, channel = original("audit")
    _, raw = audit_fixture()
    raw["raw_events"] = [
        audit_event(4624, when="2026-10-09T00:00:00.4000000Z").decode("utf-8"),
        audit_event(4624, record_id=11, when="2026-10-09T00:00:00.4000000Z").decode("utf-8"),
        audit_event(when="2026-10-09T00:00:00.5000000Z").decode("utf-8"),
    ]
    raw["utf8_bytes"] = sum(len(event.encode("utf-8")) for event in raw["raw_events"])
    saved = timed_record(value, channel, raw)
    result = project(value, channel, saved)
    share_event = result["observation"]["normalized_observation"]["events"][-1]
    assert share_event["server_logon"] == "ambiguous"
    assert "logon_record_id" not in share_event


@pytest.mark.parametrize(
    "event_id,logon_field", [(4624, "TargetLogonId"), (5145, "SubjectLogonId")]
)
def test_zero_logon_id_is_valid_outside_scope_in_original_projection(event_id, logon_field):
    from bluefire.ad_smb_results import validate_execution

    workflow, channel = original("audit")
    _, raw = audit_fixture()
    event_xml = audit_event(
        event_id,
        when="2026-10-09T00:00:00.5000000Z",
        fields={logon_field: "0x0"},
    ).decode("utf-8")
    raw["raw_events"] = [event_xml]
    raw["utf8_bytes"] = len(event_xml.encode("utf-8"))
    request = workflow["manifest"]["params"]["ad_smb_request"]

    result = project(workflow, channel, timed_record(workflow, channel, raw))

    row = result["observation"]["normalized_observation"]["events"][0]
    assert row["binding"] == "outside_scope"
    assert row["logon_id"] == "0x0"
    assert "principal_sid" not in row
    validate_execution(request, result)


@pytest.mark.parametrize(
    "event_id,sid_field,logon_field",
    [(4624, "TargetUserSid", "TargetLogonId"), (5145, "SubjectUserSid", "SubjectLogonId")],
)
def test_zero_logon_id_is_valid_for_incomplete_original_projection(
    event_id, sid_field, logon_field
):
    from bluefire.ad_smb_results import validate_execution

    workflow, channel = original("audit")
    _, raw = audit_fixture()
    event_xml = audit_event(
        event_id,
        when="2026-10-09T00:00:00.5000000Z",
        fields={sid_field: None, logon_field: "0x0"},
    ).decode("utf-8")
    raw["raw_events"] = [event_xml]
    raw["utf8_bytes"] = len(event_xml.encode("utf-8"))
    request = workflow["manifest"]["params"]["ad_smb_request"]

    result = project(workflow, channel, timed_record(workflow, channel, raw))

    row = result["observation"]["normalized_observation"]["events"][0]
    assert row["binding"] == "incomplete"
    assert row["logon_id"] == "0x0"
    assert "principal_sid" not in row
    validate_execution(request, result)


@pytest.mark.parametrize("event_id", [4624, 5145])
def test_zero_logon_id_remains_forbidden_for_matched_saved_rows(event_id):
    from bluefire.ad_smb_results import validate_execution

    workflow, channel = original("audit")
    _, raw = audit_fixture()
    event_xml = audit_event(event_id, when="2026-10-09T00:00:00.5000000Z").decode("utf-8")
    raw["raw_events"] = [event_xml]
    raw["utf8_bytes"] = len(event_xml.encode("utf-8"))
    request = workflow["manifest"]["params"]["ad_smb_request"]
    result = project(workflow, channel, timed_record(workflow, channel, raw))
    row = result["observation"]["normalized_observation"]["events"][0]
    assert row["binding"] == "matched"
    row["logon_id"] = "0x0"

    with pytest.raises(AdSmbError, match="logon identity"):
        validate_execution(request, result)


@pytest.mark.parametrize(
    "raw_events",
    [
        ["<Event />"],
        [
            audit_event(when="2026-10-09T00:00:00.5000000Z").decode("utf-8"),
            audit_event(outcome="failure", when="2026-10-09T00:00:00.5000000Z").decode("utf-8"),
        ],
        [audit_event(4624, version=9, when="2026-10-09T00:00:00.5000000Z").decode("utf-8")],
    ],
    ids=["unsupported-xml", "conflicting-record", "unsupported-version"],
)
def test_unsupported_audit_event_content_settles_legacy_summary_without_replay(raw_events):
    value, channel = original("audit")
    _, raw = audit_fixture()
    raw["raw_events"] = raw_events
    raw["utf8_bytes"] = sum(len(event.encode("utf-8")) for event in raw_events)
    saved = timed_record(value, channel, raw)
    before = deepcopy((value, saved))

    result = project(value, channel, saved)

    observation = result["observation"]
    assert set(observation) == {
        "source_digest",
        "events",
        "truncated",
        "authenticated_source",
        "independent_observation",
        "effective_access_claim",
    }
    assert observation["events"] == len(raw_events)
    assert observation["truncated"] is False
    assert observation["authenticated_source"] is False
    assert "normalized_observation" not in observation
    assert "raw_events" not in str(result)
    assert all(event not in str(result) for event in raw_events)
    assert (value, saved) == before


def test_invalid_native_audit_capture_still_rejects_before_legacy_fallback():
    value, channel = original("audit")
    _, raw = audit_fixture()
    raw["raw_events"] = [""]
    raw["utf8_bytes"] = 0
    saved = timed_record(value, channel, raw)
    before = deepcopy((value, saved))

    with pytest.raises(AdSmbError):
        project(value, channel, saved)

    assert (value, saved) == before


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("normalized_observation", "log_continuity_verified"), True),
        (("normalized_observation", "events", 0, "client_ip"), "10.44.0.99"),
        (("normalized_observation", "record_epoch_digest"), "sha256:" + "f" * 64),
        (("normalized_observation", "events", 0, "observed_at"), "2026-10-09T00:00:01.0000001Z"),
        (("normalized_observation", "input_bytes"), 0),
    ],
)
def test_audit_projection_rejects_claim_or_identity_drift(path, replacement):
    from bluefire.ad_smb_results import validate_execution

    value, channel = original("audit")
    _, raw = audit_fixture()
    raw["raw_events"] = [audit_event(when="2026-10-09T00:00:00.5000000Z").decode("utf-8")]
    raw["utf8_bytes"] = len(raw["raw_events"][0].encode("utf-8"))
    request = value["manifest"]["params"]["ad_smb_request"]
    saved = timed_record(value, channel, raw)
    result = project(value, channel, saved)
    target = result["observation"]
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    with pytest.raises(AdSmbError):
        validate_execution(request, result)


@pytest.mark.parametrize(
    "value", [0, 1, "0", "00", "01", "+1", " 1", "18446744073709551616", 2**53]
)
def test_saved_normalized_record_ids_require_canonical_uint64_decimal_strings(value):
    from bluefire.ad_smb_results import validate_execution

    workflow, channel = original("audit")
    _, raw = audit_fixture()
    raw["raw_events"] = [audit_event(when="2026-10-09T00:00:00.5000000Z").decode("utf-8")]
    raw["utf8_bytes"] = len(raw["raw_events"][0].encode("utf-8"))
    request = workflow["manifest"]["params"]["ad_smb_request"]
    result = project(workflow, channel, timed_record(workflow, channel, raw))
    result["observation"]["normalized_observation"]["events"][0]["record_id"] = value
    with pytest.raises(AdSmbError):
        validate_execution(request, result)


def test_saved_normalized_record_ids_accept_uint64_max_and_correlated_decimal_reference():
    from bluefire.ad_smb_results import validate_execution

    workflow, channel = original("audit")
    _, raw = audit_fixture()
    raw["raw_events"] = [
        audit_event(4624, record_id=2**64 - 2, when="2026-10-09T00:00:00.4000000Z").decode("utf-8"),
        audit_event(record_id=2**64 - 1, when="2026-10-09T00:00:00.5000000Z").decode("utf-8"),
    ]
    raw["utf8_bytes"] = sum(len(event.encode("utf-8")) for event in raw["raw_events"])
    request = workflow["manifest"]["params"]["ad_smb_request"]
    result = project(workflow, channel, timed_record(workflow, channel, raw))
    normalized = result["observation"]["normalized_observation"]
    assert normalized["events"][0]["record_id"] == str(2**64 - 2)
    assert normalized["events"][1]["record_id"] == str(2**64 - 1)
    assert normalized["events"][1]["logon_record_id"] == str(2**64 - 2)
    validate_execution(request, result)


@pytest.mark.parametrize("value", [0, 1, "0", "01", "+1", "18446744073709551616"])
def test_saved_correlated_record_reference_requires_canonical_uint64_decimal_string(value):
    from bluefire.ad_smb_results import validate_execution

    workflow, channel = original("audit")
    _, raw = audit_fixture()
    raw["raw_events"] = [
        audit_event(4624, when="2026-10-09T00:00:00.4000000Z").decode("utf-8"),
        audit_event(when="2026-10-09T00:00:00.5000000Z").decode("utf-8"),
    ]
    raw["utf8_bytes"] = sum(len(event.encode("utf-8")) for event in raw["raw_events"])
    request = workflow["manifest"]["params"]["ad_smb_request"]
    result = project(workflow, channel, timed_record(workflow, channel, raw))
    result["observation"]["normalized_observation"]["events"][1]["logon_record_id"] = value
    with pytest.raises(AdSmbError):
        validate_execution(request, result)


@pytest.mark.parametrize("possible_effects", [False, True])
def test_native_error_is_no_observation_not_success(possible_effects):
    value, channel = original()
    saved = record(value, channel)
    saved["terminal"]["result"]["possible_effects"] = possible_effects
    saved["terminal"]["result"]["code"] = "native_failed"
    result = project(value, channel, saved)
    assert result["observation"] is None
    assert result["dispatch"] == ("attempted" if possible_effects else "not_started")


def test_projection_does_not_mutate_original_or_accept_another_task():
    value, channel, raw = member_original()
    saved = timed_record(value, channel, raw)
    before = deepcopy((value, saved))
    project(value, channel, saved)
    assert (value, saved) == before
    different = rebind_context(value, operation_job_id="job-" + "f" * 32)
    with pytest.raises(AdSmbError):
        project(different, channel, saved)
