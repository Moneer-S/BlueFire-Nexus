import json
from pathlib import Path
from typing import Any

import pytest

import bluefire.cli as cli
from bluefire.cli import _execute, _parser, _scenario_payload


def test_scenario_cli_accepts_packaged_id_or_explicit_path() -> None:
    parser = _parser()
    by_id = parser.parse_args(
        [
            "scenario",
            "run",
            "--scenario-id",
            "scenario.restricted.persistence-canary.v1",
        ]
    )
    assert _scenario_payload(by_id)["scenario_id"] == ("scenario.restricted.persistence-canary.v1")

    path = Path(__file__).resolve().parents[1] / "scenarios" / "sandbox_research_chain.yaml"
    by_path = parser.parse_args(["scenario", "run", str(path)])
    assert _scenario_payload(by_path)["scenario"]["id"] == ("scenario.sandbox.research.chain.v1")


def test_scenario_cli_requires_exactly_one_reference() -> None:
    parser = _parser()
    missing = parser.parse_args(["scenario", "validate"])
    with pytest.raises(ValueError, match="exactly one"):
        _scenario_payload(missing)

    both = parser.parse_args(
        [
            "scenario",
            "run",
            "scenarios/sandbox_research_chain.yaml",
            "--scenario-id",
            "scenario.sandbox.research.chain.v1",
        ]
    )
    with pytest.raises(ValueError, match="exactly one"):
        _scenario_payload(both)


class _RecordingService:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str):
        def record(*args: Any, **kwargs: Any):
            self.calls.append((name, args, kwargs))
            return {"called": name}

        return record


def test_cli_scenario_and_run_history_commands_use_shared_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _RecordingService()
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    parser = _parser()

    assert _execute(parser.parse_args(["scenario", "list"])) == {"called": "scenarios"}
    assert _execute(
        parser.parse_args(
            ["scenario", "version", "scenario.sandbox.research.chain.v1", "--version", "2"]
        )
    ) == {"called": "scenario_version"}
    assert _execute(
        parser.parse_args(
            ["runs", "events", "run-" + "a" * 32, "--after-sequence", "4", "--limit", "10"]
        )
    ) == {"called": "events"}

    assert service.calls == [
        ("scenarios", (), {}),
        (
            "scenario_version",
            ("scenario.sandbox.research.chain.v1",),
            {"version": 2},
        ),
        ("events", ("run-" + "a" * 32,), {"after_sequence": 4, "limit": 10}),
    ]


def test_cli_settings_and_resource_commands_preserve_json_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _RecordingService()
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    parser = _parser()
    document = tmp_path / "resource.json"
    document.write_text(json.dumps({"theme": "dark"}), encoding="utf-8")

    _execute(parser.parse_args(["settings", "set", "ui.preferences", str(document)]))
    _execute(
        parser.parse_args(
            [
                "resources",
                "save",
                "collector",
                "collector.local.v1",
                str(document),
                "--status",
                "draft",
            ]
        )
    )
    _execute(
        parser.parse_args(
            [
                "resources",
                "save",
                "research_source",
                "research.local.v1",
                str(document),
            ]
        )
    )
    _execute(parser.parse_args(["resources", "probe", "runner_profile", "sandbox-execute.v1"]))

    assert service.calls == [
        ("upsert_setting", ("ui.preferences", {"value": {"theme": "dark"}}), {}),
        (
            "save_resource",
            ("collector", "collector.local.v1", {"document": {"theme": "dark"}, "status": "draft"}),
            {},
        ),
        (
            "save_resource",
            ("research_source", "research.local.v1", {"document": {"theme": "dark"}}),
            {},
        ),
        ("probe_runner_profile", ("sandbox-execute.v1", {}), {}),
    ]


def test_cli_job_review_and_control_commands_use_durable_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _RecordingService()
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    parser = _parser()
    decision = tmp_path / "decision.json"
    decision.write_text(
        json.dumps({"proposal_digest": "sha256:" + "a" * 64, "decision": "accept"}),
        encoding="utf-8",
    )
    job_id = "job-" + "a" * 32
    proposal_id = "proposal-record-" + "b" * 32

    _execute(parser.parse_args(["jobs", "approve", job_id, "--approved-by", "operator"]))
    _execute(parser.parse_args(["jobs", "pause", job_id]))
    _execute(parser.parse_args(["jobs", "proposal-accept", job_id, proposal_id, str(decision)]))

    assert service.calls == [
        ("approve_job", (job_id, {"approved_by": "operator"}), {}),
        ("pause_job", (job_id,), {}),
        (
            "accept_proposal_review",
            (
                job_id,
                proposal_id,
                {"proposal_digest": "sha256:" + "a" * 64, "decision": "accept"},
            ),
            {},
        ),
    ]


def test_cli_detection_commands_cover_the_full_immutable_lifecycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _RecordingService()
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    parser = _parser()
    candidate_id = "detection-" + "a" * 20
    request = tmp_path / "detection-request.json"
    request.write_text(json.dumps({"reason": "Narrow the selection."}), encoding="utf-8")

    _execute(parser.parse_args(["detections", "health"]))
    _execute(parser.parse_args(["detections", "list"]))
    _execute(parser.parse_args(["detections", "detail", candidate_id]))
    _execute(parser.parse_args(["detections", "create", str(request)]))
    _execute(parser.parse_args(["detections", "parse", candidate_id]))
    for command, method in (
        ("exercise-fixtures", "exercise_detection_fixtures"),
        ("exercise-observed", "exercise_detection_observed"),
        ("evaluate-benign", "evaluate_detection_benign"),
        ("reject", "reject_detection_candidate"),
        ("clone", "clone_detection_candidate"),
        ("tune", "tune_detection_candidate"),
        ("compare", "compare_detection_candidates"),
    ):
        _execute(parser.parse_args(["detections", command, candidate_id, str(request)]))
        assert service.calls[-1] == (
            method,
            (candidate_id, {"reason": "Narrow the selection."}),
            {},
        )

    assert service.calls[:5] == [
        ("detection_health", (), {}),
        ("detection_candidates", (), {}),
        ("detection_candidate", (candidate_id,), {}),
        (
            "upsert_detection_hypothesis",
            ({"reason": "Narrow the selection."},),
            {},
        ),
        ("parse_detection_candidate", (candidate_id, {}), {}),
    ]


def test_cli_receiver_does_not_initialize_the_control_plane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[Any] = []

    def fake_receiver(config: Any) -> dict[str, Any]:
        seen.append(config)
        return {"reason": "max_requests"}

    def fail_service(_args: Any) -> None:
        raise AssertionError("receiver must not initialize BlueFireService")

    monkeypatch.setattr(cli, "run_loopback_receiver", fake_receiver)
    monkeypatch.setattr(cli, "_service", fail_service)

    result = _execute(
        _parser().parse_args(
            [
                "receiver",
                "--host",
                "127.0.0.1",
                "--port",
                "0",
                "--max-requests",
                "2",
                "--max-connections",
                "3",
                "--max-body-bytes",
                "1024",
            ]
        )
    )

    assert result == {"reason": "max_requests"}
    assert len(seen) == 1
    assert seen[0].host == "127.0.0.1"
    assert seen[0].port == 0
    assert seen[0].max_requests == 2
    assert seen[0].max_connections == 3
    assert seen[0].max_body_bytes == 1024
