from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import product_acceptance_process as process
from bluefire import release_readiness_runtime as runtime
from bluefire import release_readiness_suites as suites
from bluefire import release_readiness_toolchain as toolchain


@pytest.fixture
def configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, dict[str, str]]:
    repository = tmp_path / "source"
    repository.mkdir()
    (repository / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.98.0"\nprofile = "minimal"\n', encoding="utf-8"
    )
    root = tmp_path / "toolchains with spaces" / "1.98.0-x86_64-pc-windows-gnu"
    for relative in (
        "bin/cargo.exe",
        "bin/rustc.exe",
        "lib/rustlib/x86_64-pc-windows-gnu/bin/rust-lld.exe",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"inert test artifact")
    monkeypatch.setattr(toolchain, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(
        toolchain.shutil, "which", lambda *_args, **_kwargs: str(root / "bin/cargo.exe")
    )
    return repository, root, {"PATH": str(root / "bin"), "RUSTUP_TOOLCHAIN": root.name}


def test_opt_in_survives_only_to_the_enclosing_gate_and_never_inherits_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(toolchain.RUST_LINKER_ENV, toolchain.WINDOWS_GNU_LINKER)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "CARGO_HOME"):
        monkeypatch.setenv(name, "untrusted-parent-value")
    monkeypatch.setenv("BLUEFIRE_ACCEPTANCE_ID", "parent-authority")
    home = tmp_path / "home"
    home.mkdir()
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    environment = process._isolated_workflow_environment(
        runtime_home=home, runtime_temp=temporary, cargo_target=tmp_path / "target"
    )
    assert environment[toolchain.RUST_LINKER_ENV] == toolchain.WINDOWS_GNU_LINKER
    assert environment["CARGO_HOME"] == str(home / "cargo")
    assert environment["CARGO_NET_OFFLINE"] == "true"
    assert all(
        name not in environment
        for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER")
    )
    assert "untrusted-parent-value" not in environment.values()
    nested = runtime.suite_environment(environment)
    assert all(not name.startswith("BLUEFIRE_ACCEPTANCE_") for name in nested)


def test_default_linker_does_not_probe_or_change_existing_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        toolchain.shutil, "which", lambda *_args, **_kwargs: pytest.fail("unexpected lookup")
    )
    environment = {"PATH": "existing-path"}
    assert toolchain.fixed_rust_linker_environment(Path("unused"), None, environment) == {}
    assert environment == {"PATH": "existing-path"}


def test_explicit_gnu_configuration_generates_only_fixed_flags(
    configured: tuple[Path, Path, dict[str, str]],
) -> None:
    repository, root, environment = configured
    original = dict(environment)
    result = toolchain.fixed_rust_linker_environment(
        repository, toolchain.WINDOWS_GNU_LINKER, environment
    )
    assert result == {
        "RUSTC": str(root / "bin/rustc.exe"),
        "RUSTUP_TOOLCHAIN": root.name,
        "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(
            [
                "-C",
                f"linker={root / 'lib/rustlib/x86_64-pc-windows-gnu/bin/rust-lld.exe'}",
                "-C",
                "linker-flavor=ld.lld",
                "-C",
                "link-self-contained=yes",
                "-C",
                "target-feature=+crt-static",
            ]
        ),
    }
    assert environment == original


@pytest.mark.parametrize("mode", ["", "auto", "windows-gnu-self-contained --extra", "rust-lld"])
def test_unknown_linker_selection_is_refused(
    configured: tuple[Path, Path, dict[str, str]], mode: str
) -> None:
    repository, _, environment = configured
    with pytest.raises(ValueError, match="unsupported"):
        toolchain.fixed_rust_linker_environment(repository, mode, environment)


@pytest.mark.parametrize(
    "name", ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"]
)
def test_fixed_mode_refuses_injected_flags_and_wrappers(
    configured: tuple[Path, Path, dict[str, str]], name: str
) -> None:
    repository, _, environment = configured
    environment[name] = "arbitrary-command-or-argument"
    with pytest.raises(ValueError, match="custom compiler"):
        toolchain.fixed_rust_linker_environment(
            repository, toolchain.WINDOWS_GNU_LINKER, environment
        )


@pytest.mark.parametrize(
    "failure",
    [
        "wrong-version",
        "conflicting-rustup",
        "missing-linker",
        "directory-linker",
        "cargo-shim",
        "foreign-platform",
    ],
)
def test_toolchain_mismatch_refuses_before_any_subprocess(
    configured: tuple[Path, Path, dict[str, str]], monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    repository, root, environment = configured
    linker = root / "lib/rustlib/x86_64-pc-windows-gnu/bin/rust-lld.exe"
    if failure == "wrong-version":
        (repository / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "1.97.0"\n', encoding="utf-8"
        )
    elif failure == "conflicting-rustup":
        environment["RUSTUP_TOOLCHAIN"] = "stable"
    elif failure == "missing-linker":
        linker.unlink()
    elif failure == "directory-linker":
        linker.unlink()
        linker.mkdir()
    elif failure == "cargo-shim":
        shim = root / "bin/rustup.exe"
        shim.write_bytes(b"inert shim")
        monkeypatch.setattr(toolchain.shutil, "which", lambda *_args, **_kwargs: str(shim))
    else:
        monkeypatch.setattr(toolchain, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setenv(toolchain.RUST_LINKER_ENV, toolchain.WINDOWS_GNU_LINKER)
    monkeypatch.setattr(
        suites,
        "_run",
        lambda *_args, **_kwargs: pytest.fail("invalid configuration invoked native tool"),
    )
    with pytest.raises((ValueError, OSError)):
        suites._rust_suites(repository, repository / "scratch", environment)


def test_toolchain_alias_is_refused(configured: tuple[Path, Path, dict[str, str]]) -> None:
    repository, root, environment = configured
    rustc = root / "bin/rustc.exe"
    original = rustc.with_name("actual-rustc.exe")
    rustc.rename(original)
    try:
        rustc.symlink_to(original)
    except OSError:
        pytest.skip("ordinary file symlinks are unavailable")
    with pytest.raises(ValueError, match="canonical|alias"):
        toolchain.fixed_rust_linker_environment(
            repository, toolchain.WINDOWS_GNU_LINKER, environment
        )


def test_rust_suites_receive_fixed_flags_and_preserve_locked_commands(
    configured: tuple[Path, Path, dict[str, str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, root, environment = configured
    monkeypatch.setenv(toolchain.RUST_LINKER_ENV, toolchain.WINDOWS_GNU_LINKER)
    calls: list[tuple[list[str], dict[str, str], int]] = []

    def run(
        command: list[str], *, cwd: Path, environment: dict[str, str], timeout_seconds: int
    ) -> tuple[int, bytes, bytes]:
        assert cwd == repository
        calls.append((list(command), dict(environment), timeout_seconds))
        return 0, b"cargo 1.98.0\n" if "--version" in command else b"security_boundary: test\n", b""

    monkeypatch.setattr(suites, "_run", run)
    rows, reported = suites._rust_suites(repository, repository / "scratch", environment)
    assert len(calls) == 6
    assert all(row["passed"] for row in rows)
    assert reported["cargo_version_verified"] is True
    expected = toolchain.fixed_rust_linker_environment(
        repository, toolchain.WINDOWS_GNU_LINKER, environment
    )
    for command, actual, _ in calls:
        assert command[0] == str(root / "bin/cargo.exe")
        assert all(actual[name] == value for name, value in expected.items())
        assert actual["CARGO_INCREMENTAL"] == "0"
        assert actual["CARGO_TARGET_DIR"] == str(repository / "scratch/cargo-target")
        assert toolchain.RUST_LINKER_ENV not in actual
    assert [(command[1], timeout) for command, _, timeout in calls] == [
        ("--version", 30),
        ("test", 600),
        ("fmt", 600),
        ("clippy", 600),
        ("test", 1200),
        ("build", 1200),
    ]
    assert all(
        "--locked" in command
        for command, _, _ in calls
        if command[1] in {"test", "clippy", "build"}
    )
    assert all("--no-default-features" not in command for command, _, _ in calls)
    assert str(root) not in str(rows) + str(reported)
