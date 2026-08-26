import base64
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


def test_cli_runner_commands_use_only_explicit_managed_lifecycle_actions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _RecordingService()
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    parser = _parser()

    _execute(parser.parse_args(["runner", "status", "--profile", "sandbox-execute.v1"]))
    _execute(
        parser.parse_args(
            [
                "runner",
                "bootstrap",
                "--profile",
                "sandbox-execute.v1",
                "--allow-upgrade",
            ]
        )
    )
    _execute(parser.parse_args(["runner", "start", "--profile", "sandbox-execute.v1"]))
    _execute(parser.parse_args(["runner", "stop", "--profile", "sandbox-execute.v1"]))
    _execute(parser.parse_args(["runner", "revoke"]))
    _execute(
        parser.parse_args(["runner", "remove", "--confirm-runner-id", "bluefire-rust-runner.v1"])
    )

    assert service.calls == [
        ("runner_status", (), {"profile_id": "sandbox-execute.v1"}),
        (
            "bootstrap_runner",
            (),
            {"profile_id": "sandbox-execute.v1", "allow_upgrade": True},
        ),
        ("start_runner", (), {"profile_id": "sandbox-execute.v1"}),
        ("stop_runner", (), {"profile_id": "sandbox-execute.v1"}),
        ("revoke_runner", (), {}),
        (
            "remove_runner",
            (),
            {"confirm_runner_id": "bluefire-rust-runner.v1"},
        ),
    ]


def test_cli_action_package_commands_dispatch_exact_lifecycle_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _RecordingService()
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    parser = _parser()
    public_key = b"k" * 32
    public_key_file = tmp_path / "publisher-key.txt"
    public_key_file.write_text(
        base64.urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii") + "\n",
        encoding="utf-8",
    )
    provenance_file = tmp_path / "provenance.json"
    provenance_file.write_text(
        json.dumps({"source": "urn:bluefire:publisher-review"}),
        encoding="utf-8",
    )
    envelope_file = tmp_path / "package.json"
    envelope_file.write_text(
        json.dumps({"schema_version": "bluefire.action-package.v1"}),
        encoding="utf-8",
    )
    package_id = "com.example.discovery"
    version = "1.2.3"
    package_digest = "sha256:" + "a" * 64
    catalog_digest = "sha256:" + "b" * 64

    _execute(parser.parse_args(["packages", "inventory"]))
    _execute(parser.parse_args(["packages", "detail", package_id]))
    _execute(
        parser.parse_args(
            [
                "packages",
                "trust-publisher",
                "--publisher-id",
                "publisher.example",
                "--key-id",
                "release-2026",
                "--public-key-file",
                str(public_key_file),
                "--provenance-file",
                str(provenance_file),
                "--trusted-by",
                "security-reviewer",
            ]
        )
    )
    for command in ("suspend-publisher", "revoke-publisher"):
        _execute(
            parser.parse_args(
                [
                    "packages",
                    command,
                    "publisher.example",
                    "release-2026",
                    "--actor",
                    "security-reviewer",
                    "--reason",
                    "Key lifecycle review.",
                ]
            )
        )
    _execute(
        parser.parse_args(
            [
                "packages",
                "install",
                str(envelope_file),
                "--installed-by",
                "package-operator",
            ]
        )
    )
    _execute(
        parser.parse_args(
            [
                "packages",
                "activate",
                package_id,
                version,
                "--profile",
                "sandbox-execute.v1",
                "--activated-by",
                "package-operator",
                "--reason",
                "Reviewed release.",
            ]
        )
    )
    for command, actor_option in (
        ("deactivate", "--deactivated-by"),
        ("remove", "--removed-by"),
    ):
        _execute(
            parser.parse_args(
                [
                    "packages",
                    command,
                    package_id,
                    version,
                    "--package-digest",
                    package_digest,
                    "--catalog-generation",
                    "7",
                    "--catalog-digest",
                    catalog_digest,
                    actor_option,
                    "package-operator",
                    "--reason",
                    "Reviewed lifecycle transition.",
                ]
            )
        )

    assert service.calls == [
        ("action_packages", (), {}),
        ("action_package", (package_id,), {}),
        (
            "trust_action_package_publisher",
            (
                {
                    "publisher_id": "publisher.example",
                    "key_id": "release-2026",
                    "public_key": public_key,
                    "provenance": {"source": "urn:bluefire:publisher-review"},
                    "trusted_by": "security-reviewer",
                },
            ),
            {},
        ),
        (
            "transition_action_package_publisher",
            (
                "publisher.example",
                "release-2026",
                "suspend",
                {"actor": "security-reviewer", "reason": "Key lifecycle review."},
            ),
            {},
        ),
        (
            "transition_action_package_publisher",
            (
                "publisher.example",
                "release-2026",
                "revoke",
                {"actor": "security-reviewer", "reason": "Key lifecycle review."},
            ),
            {},
        ),
        (
            "install_action_package",
            (
                {
                    "envelope": {"schema_version": "bluefire.action-package.v1"},
                    "installed_by": "package-operator",
                },
            ),
            {},
        ),
        (
            "activate_action_package",
            (
                package_id,
                version,
                {
                    "runner_profile_id": "sandbox-execute.v1",
                    "activated_by": "package-operator",
                    "reason": "Reviewed release.",
                },
            ),
            {},
        ),
        (
            "deactivate_action_package",
            (
                package_id,
                version,
                {
                    "package_digest": package_digest,
                    "expected_catalog_generation": 7,
                    "expected_catalog_digest": catalog_digest,
                    "deactivated_by": "package-operator",
                    "reason": "Reviewed lifecycle transition.",
                },
            ),
            {},
        ),
        (
            "remove_action_package",
            (
                package_id,
                version,
                {
                    "package_digest": package_digest,
                    "expected_catalog_generation": 7,
                    "expected_catalog_digest": catalog_digest,
                    "removed_by": "package-operator",
                    "reason": "Reviewed lifecycle transition.",
                },
            ),
            {},
        ),
    ]


def test_cli_action_package_file_reads_are_bounded_and_path_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _RecordingService()
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    parser = _parser()
    oversized_secret = tmp_path / "operator-private-envelope.json"
    oversized_secret.write_text("{" + " " * (256 * 1024), encoding="utf-8")

    with pytest.raises(ValueError, match="exceeds") as oversized:
        _execute(
            parser.parse_args(
                [
                    "packages",
                    "install",
                    str(oversized_secret),
                    "--installed-by",
                    "operator",
                ]
            )
        )
    assert str(oversized_secret) not in str(oversized.value)
    assert oversized_secret.name not in str(oversized.value)

    missing_secret = tmp_path / "publisher-secret-key.txt"
    provenance = tmp_path / "provenance.json"
    provenance.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="unable to read publisher public key") as missing:
        _execute(
            parser.parse_args(
                [
                    "packages",
                    "trust-publisher",
                    "--publisher-id",
                    "publisher.example",
                    "--key-id",
                    "release",
                    "--public-key-file",
                    str(missing_secret),
                    "--provenance-file",
                    str(provenance),
                    "--trusted-by",
                    "operator",
                ]
            )
        )
    assert str(missing_secret) not in str(missing.value)
    assert missing_secret.name not in str(missing.value)
    assert service.calls == []


def test_cli_ui_delivers_one_capability_only_in_the_launch_url_fragment(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    service = _RecordingService()
    capability = "A" * 64
    serve_calls: list[tuple[Any, dict[str, Any]]] = []

    monkeypatch.setattr(cli, "_service", lambda _args: service)
    monkeypatch.setattr(cli, "generate_browser_bootstrap_capability", lambda: capability)

    def record_serve(target: Any, **kwargs: Any) -> None:
        on_ready = kwargs.pop("on_ready")
        serve_calls.append((target, kwargs))

        class BoundServer:
            server_address = ("127.0.0.1", 49321)

        on_ready(BoundServer())

    monkeypatch.setattr(cli, "serve", record_serve)

    result = _execute(_parser().parse_args(["ui", "--host", "127.0.0.1", "--port", "0"]))

    assert result is None
    assert serve_calls == [
        (
            service,
            {
                "host": "127.0.0.1",
                "port": 0,
                "browser_bootstrap_capability": capability,
            },
        )
    ]
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        f"BlueFire local console: http://127.0.0.1:49321/#bluefire-session={capability}\n"
    )
    launch_url = output.err.partition(": ")[2].strip()
    assert "?" not in launch_url.partition("#")[0]
    assert capability not in launch_url.partition("#")[0]
    assert capability not in repr(vars(service))


def test_cli_ui_bind_failure_never_announces_the_capability(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    service = _RecordingService()
    capability = "B" * 64
    monkeypatch.setattr(cli, "_service", lambda _args: service)
    monkeypatch.setattr(cli, "generate_browser_bootstrap_capability", lambda: capability)

    def fail_before_ready(_target: Any, **_kwargs: Any) -> None:
        raise OSError("listener unavailable")

    monkeypatch.setattr(cli, "serve", fail_before_ready)

    with pytest.raises(OSError, match="listener unavailable"):
        _execute(_parser().parse_args(["ui", "--port", "8765"]))

    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == ""
    assert capability not in output.out + output.err


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
    seen_enrollment: list[tuple[Path, bool]] = []

    class ActiveEnrollment:
        def hmac_key(self) -> bytes:
            return b"r" * 32

    def fake_enrollment(root: Path, *, require_active: bool = True) -> ActiveEnrollment:
        seen_enrollment.append((root, require_active))
        return ActiveEnrollment()

    def fake_receiver(config: Any) -> dict[str, Any]:
        seen.append(config)
        return {"reason": "max_requests"}

    def fail_service(_args: Any) -> None:
        raise AssertionError("receiver must not initialize BlueFireService")

    monkeypatch.setattr(cli, "run_loopback_receiver", fake_receiver)
    monkeypatch.setattr(cli, "_service", fail_service)
    monkeypatch.setattr(cli, "managed_product_root", lambda: Path("managed-product"))
    monkeypatch.setattr(cli, "load_local_enrollment", fake_enrollment)

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
                "4",
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
    assert seen[0].max_connections == 4
    assert seen[0].max_body_bytes == 1024
    assert seen[0].idle_timeout_seconds == 300.0
    assert seen[0].authentication_key == b"r" * 32
    assert seen_enrollment == [(Path("managed-product") / "enrollment", True)]


def test_cli_receiver_sanitizes_inactive_or_unavailable_enrollment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive = Path("operator-secret") / "enrollment"
    monkeypatch.setattr(cli, "managed_product_root", lambda: sensitive.parent)

    def fail_enrollment(_root: Path, *, require_active: bool = True) -> Any:
        assert require_active is True
        raise cli.RunnerTrustError(f"cannot read {sensitive}")

    monkeypatch.setattr(cli, "load_local_enrollment", fail_enrollment)
    monkeypatch.setattr(
        cli,
        "run_loopback_receiver",
        lambda _config: (_ for _ in ()).throw(AssertionError("receiver must not bind")),
    )

    with pytest.raises(RuntimeError, match="Managed receiver authentication is unavailable") as exc:
        _execute(_parser().parse_args(["receiver", "--port", "0"]))

    assert str(sensitive) not in str(exc.value)
