from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from tools.build_native_runner import (
    RUSTFLAG_SEPARATOR,
    RunnerBuildError,
    RunnerBuildPlan,
    build_release_runner,
    create_runner_build_plan,
    main,
    verify_runner_has_no_build_paths,
)


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "checkout"
    (root / "runner").mkdir(parents=True)
    (root / "runner" / "Cargo.toml").write_text("[package]\nname='runner'\n", encoding="utf-8")
    return root


def _environment(tmp_path: Path) -> dict[str, str]:
    return {
        "CARGO": "cargo-custom",
        "CARGO_HOME": str(tmp_path / "private user" / "cargo"),
        "RUSTUP_HOME": str(tmp_path / "private user" / "rustup"),
        "CARGO_TARGET_DIR": str(tmp_path / "private user" / "target"),
        "HOME": str(tmp_path / "private user"),
        "RUSTFLAGS": "--cfg inherited_flag_must_not_survive",
        "CARGO_ENCODED_RUSTFLAGS": "inherited_encoded_flag_must_not_survive",
        "UNCHANGED": "present",
    }


def _decode_flags(plan: RunnerBuildPlan) -> list[str]:
    return plan.environment["CARGO_ENCODED_RUSTFLAGS"].split(RUSTFLAG_SEPARATOR)


def test_build_plan_uses_fixed_argv_and_private_path_environment(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    inherited = _environment(tmp_path)

    plan = create_runner_build_plan(root, environment=inherited, windows=False)

    assert plan.argv == (
        "cargo-custom",
        "build",
        "--locked",
        "--release",
        "--manifest-path",
        str(root / "runner" / "Cargo.toml"),
        "--bin",
        "bluefire-runner",
    )
    assert plan.cwd == root
    assert plan.output_path == Path(inherited["CARGO_TARGET_DIR"]) / "release" / "bluefire-runner"
    assert plan.environment["CARGO_HOME"] == inherited["CARGO_HOME"]
    assert plan.environment["RUSTUP_HOME"] == inherited["RUSTUP_HOME"]
    assert plan.environment["CARGO_TARGET_DIR"] == inherited["CARGO_TARGET_DIR"]
    assert plan.environment["CARGO_INCREMENTAL"] == "0"
    assert plan.environment["UNCHANGED"] == "present"
    assert "RUSTFLAGS" not in plan.environment
    assert "inherited_encoded_flag_must_not_survive" not in _decode_flags(plan)
    assert inherited["RUSTFLAGS"] == "--cfg inherited_flag_must_not_survive"
    assert plan.target is None


@pytest.mark.parametrize(
    ("target", "filename"),
    [
        ("x86_64-unknown-linux-musl", "bluefire-runner"),
        ("x86_64-pc-windows-gnu", "bluefire-runner.exe"),
    ],
)
def test_explicit_target_controls_cargo_and_output_path(
    target: str,
    filename: str,
    tmp_path: Path,
) -> None:
    root = _repo(tmp_path)
    inherited = _environment(tmp_path)

    plan = create_runner_build_plan(root, environment=inherited, target=target)

    assert plan.argv == (
        "cargo-custom",
        "build",
        "--locked",
        "--release",
        "--target",
        target,
        "--manifest-path",
        str(root / "runner" / "Cargo.toml"),
        "--bin",
        "bluefire-runner",
    )
    assert plan.output_path == Path(inherited["CARGO_TARGET_DIR"]) / target / "release" / filename
    assert plan.target == target


@pytest.mark.parametrize(
    ("target", "windows"),
    [
        ("x86_64-unknown-linux-musl", True),
        ("x86_64-pc-windows-gnu", False),
    ],
)
def test_explicit_target_rejects_conflicting_windows_override(
    target: str,
    windows: bool,
    tmp_path: Path,
) -> None:
    with pytest.raises(RunnerBuildError, match="windows override conflicts"):
        create_runner_build_plan(
            _repo(tmp_path),
            environment=_environment(tmp_path),
            windows=windows,
            target=target,
        )


@pytest.mark.parametrize(
    "target",
    ["", " ", "aarch64-unknown-linux-musl", "../release", "--release", "linux\x00musl"],
)
def test_build_plan_rejects_noncanonical_targets(target: str, tmp_path: Path) -> None:
    with pytest.raises(RunnerBuildError, match="unsupported runner target"):
        create_runner_build_plan(
            _repo(tmp_path),
            environment=_environment(tmp_path),
            target=target,
        )


def test_ambient_cargo_target_must_match_an_explicit_target(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    environment = _environment(tmp_path)
    environment["CARGO_BUILD_TARGET"] = "x86_64-unknown-linux-musl"

    with pytest.raises(RunnerBuildError, match="requires an explicit --target"):
        create_runner_build_plan(root, environment=environment)

    with pytest.raises(RunnerBuildError, match="conflicts with the explicit --target"):
        create_runner_build_plan(
            root,
            environment=environment,
            target="x86_64-pc-windows-gnu",
        )

    plan = create_runner_build_plan(
        root,
        environment=environment,
        target="x86_64-unknown-linux-musl",
    )
    assert "CARGO_BUILD_TARGET" not in plan.environment


def test_build_plan_encodes_all_remaps_as_distinct_rustc_arguments(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    plan = create_runner_build_plan(root, environment=_environment(tmp_path), windows=True)

    flags = _decode_flags(plan)
    assert flags[-2:] == ["-C", "strip=symbols"]
    remap_arguments = flags[1:-2:2]
    assert flags[:-2:2] == ["--remap-path-prefix"] * len(remap_arguments)
    assert set(destination for _, destination in plan.remaps) == {
        "/bluefire/build/home",
        "/bluefire/build/workspace",
        "/bluefire/build/target",
        "/bluefire/build/cargo-home",
        "/bluefire/build/rustup-home",
        "/bluefire/source",
    }
    assert remap_arguments == [f"{source}={destination}" for source, destination in plan.remaps]
    sources = [source for source, _ in plan.remaps]
    assert sources == sorted(sources, key=len)
    positions = {source: index for index, (source, _) in enumerate(plan.remaps)}
    assert (
        positions[str(tmp_path / "private user")]
        < positions[str(tmp_path / "private user" / "target")]
    )
    assert positions[str(root.parent)] < positions[str(root)]
    assert plan.output_path.name == "bluefire-runner.exe"


def test_relative_build_roots_are_resolved_against_checkout(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    plan = create_runner_build_plan(
        root,
        environment={
            "CARGO_HOME": ".build/cargo",
            "RUSTUP_HOME": ".build/rustup",
            "CARGO_TARGET_DIR": ".build/target",
        },
        windows=False,
    )

    assert plan.environment["CARGO_HOME"] == str(root / ".build" / "cargo")
    assert plan.environment["RUSTUP_HOME"] == str(root / ".build" / "rustup")
    assert plan.environment["CARGO_TARGET_DIR"] == str(root / ".build" / "target")


@pytest.mark.parametrize("variable", ["CARGO_HOME", "RUSTUP_HOME", "CARGO_TARGET_DIR"])
def test_build_plan_rejects_empty_or_root_storage(variable: str, tmp_path: Path) -> None:
    root = _repo(tmp_path)
    environment = _environment(tmp_path)
    environment[variable] = ""
    with pytest.raises(RunnerBuildError, match=f"{variable} must not be empty"):
        create_runner_build_plan(root, environment=environment)

    environment[variable] = str(Path(root.anchor))
    with pytest.raises(RunnerBuildError, match=f"{variable} must not be a filesystem root"):
        create_runner_build_plan(root, environment=environment)


def test_build_execution_never_uses_a_shell_or_dynamic_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repo(tmp_path)
    plan = create_runner_build_plan(root, environment=_environment(tmp_path), windows=False)
    plan.output_path.parent.mkdir(parents=True)
    plan.output_path.write_bytes(b"private-path-free-runner")
    observed: dict[str, Any] = {}

    def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        observed["argv"] = argv
        observed.update(kwargs)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert build_release_runner(plan) == plan.output_path
    assert observed["argv"] == list(plan.argv)
    assert observed["cwd"] == root
    assert observed["env"] == dict(plan.environment)
    assert observed["check"] is True
    assert observed["shell"] is False


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
def test_output_scan_rejects_known_build_roots(encoding: str, tmp_path: Path) -> None:
    binary = tmp_path / "runner"
    marker = str(tmp_path / "private-user" / "checkout")
    binary.write_bytes(b"header" + marker.encode(encoding) + b"trailer")

    with pytest.raises(RunnerBuildError, match="unremapped source build path"):
        verify_runner_has_no_build_paths(binary, (("source", marker),))


def test_output_scan_accepts_only_remapped_paths(tmp_path: Path) -> None:
    binary = tmp_path / "runner"
    binary.write_bytes(b"panic at /bluefire/source/runner/src/main.rs")

    verify_runner_has_no_build_paths(
        binary,
        (("source", str(tmp_path / "private-user" / "checkout")),),
    )


def test_cli_forwards_one_validated_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, Any] = {}
    sentinel = object()

    def fake_plan(repo_root: Path, *, target: str | None = None) -> object:
        observed["repo_root"] = repo_root
        observed["target"] = target
        return sentinel

    def fake_build(plan: object) -> Path:
        observed["plan"] = plan
        return Path("unused")

    monkeypatch.setattr("tools.build_native_runner.create_runner_build_plan", fake_plan)
    monkeypatch.setattr("tools.build_native_runner.build_release_runner", fake_build)

    assert main(["--target", "x86_64-unknown-linux-musl"]) == 0
    assert observed["target"] == "x86_64-unknown-linux-musl"
    assert observed["plan"] is sentinel


def test_cli_rejects_duplicate_targets_before_planning(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def unexpected_plan(*args: Any, **kwargs: Any) -> object:
        pytest.fail("invalid CLI arguments must not create a build plan")

    monkeypatch.setattr("tools.build_native_runner.create_runner_build_plan", unexpected_plan)

    assert (
        main(
            [
                "--target",
                "x86_64-unknown-linux-musl",
                "--target",
                "x86_64-pc-windows-gnu",
            ]
        )
        == 2
    )
    assert "--target may be supplied only once" in capsys.readouterr().err
