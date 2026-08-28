"""Build the release Rust runner without retaining host build paths.

The command is deliberately fixed: callers may select Cargo and its storage
roots through standard environment variables, but cannot append compiler or
Cargo arguments.  Every host-controlled build root is remapped before rustc
sees it, and the resulting executable is scanned before it is accepted.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

RUSTFLAG_SEPARATOR = "\x1f"
RUNNER_BINARY = "bluefire-runner"


class RunnerBuildError(RuntimeError):
    """Raised when a private-path-safe release runner cannot be produced."""


@dataclass(frozen=True)
class RunnerBuildPlan:
    """Fully resolved command and environment for one release build."""

    argv: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    output_path: Path
    remaps: tuple[tuple[str, str], ...]
    private_path_markers: tuple[tuple[str, str], ...]


def _absolute_path(value: str | Path, *, relative_to: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = relative_to / path
    return path.resolve()


def _environment_root(
    environment: Mapping[str, str],
    name: str,
    default: Path,
    *,
    relative_to: Path,
) -> Path:
    raw = environment.get(name)
    if raw is not None and not raw.strip():
        raise RunnerBuildError(f"{name} must not be empty")
    root = _absolute_path(raw if raw is not None else default, relative_to=relative_to)
    if root == Path(root.anchor):
        raise RunnerBuildError(f"{name} must not be a filesystem root")
    return root


def _path_spellings(path: Path) -> tuple[str, ...]:
    """Return spellings rustc may observe for the same absolute host path."""

    native = str(path)
    values = [native, path.as_posix()]
    if path.drive and native.startswith(path.drive):
        values.extend((f"\\\\?\\{native}", f"//?/{path.as_posix()}"))
    return tuple(dict.fromkeys(values))


def _rustc_remaps(
    *,
    host_home: Path,
    workspace_root: Path | None,
    repo_root: Path,
    cargo_home: Path,
    rustup_home: Path,
    target_dir: Path,
) -> tuple[tuple[str, str], ...]:
    roots: tuple[tuple[Path, str], ...] = (
        (host_home, "/bluefire/build/home"),
        *(((workspace_root, "/bluefire/build/workspace"),) if workspace_root else ()),
        (repo_root, "/bluefire/source"),
        (target_dir, "/bluefire/build/target"),
        (cargo_home, "/bluefire/build/cargo-home"),
        (rustup_home, "/bluefire/build/rustup-home"),
    )
    remaps: list[tuple[str, str]] = []
    for root, destination in roots:
        for source in _path_spellings(root):
            if "=" in source or RUSTFLAG_SEPARATOR in source:
                raise RunnerBuildError("build roots cannot contain rustc flag separators")
            remaps.append((source, destination))
    # rustc applies the last matching prefix. Broad roots must precede their
    # nested, role-specific roots so the stable specific label wins.
    return tuple(sorted(dict.fromkeys(remaps), key=lambda item: len(item[0])))


def _encoded_rustflags(remaps: Sequence[tuple[str, str]]) -> str:
    flags: list[str] = []
    for source, destination in remaps:
        flags.extend(("--remap-path-prefix", f"{source}={destination}"))
    flags.extend(("-C", "strip=symbols"))
    return RUSTFLAG_SEPARATOR.join(flags)


def create_runner_build_plan(
    repo_root: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
    windows: bool | None = None,
) -> RunnerBuildPlan:
    """Construct a private-path-safe, fixed-argument release build plan."""

    root = _absolute_path(repo_root, relative_to=Path.cwd())
    manifest = root / "runner" / "Cargo.toml"
    if not manifest.is_file():
        raise RunnerBuildError("runner/Cargo.toml is unavailable")

    inherited = dict(os.environ if environment is None else environment)
    home_value = inherited.get("USERPROFILE") or inherited.get("HOME")
    host_home = _environment_root(
        {},
        "host home",
        Path(home_value) if home_value else Path.home(),
        relative_to=root,
    )
    workspace_root = root.parent if root.parent != Path(root.anchor) else None
    cargo_home = _environment_root(
        inherited,
        "CARGO_HOME",
        host_home / ".cargo",
        relative_to=root,
    )
    rustup_home = _environment_root(
        inherited,
        "RUSTUP_HOME",
        host_home / ".rustup",
        relative_to=root,
    )
    target_dir = _environment_root(
        inherited,
        "CARGO_TARGET_DIR",
        root / "runner" / "target",
        relative_to=root,
    )
    remaps = _rustc_remaps(
        host_home=host_home,
        workspace_root=workspace_root,
        repo_root=root,
        cargo_home=cargo_home,
        rustup_home=rustup_home,
        target_dir=target_dir,
    )

    build_environment = dict(inherited)
    build_environment.pop("RUSTFLAGS", None)
    build_environment["CARGO_HOME"] = str(cargo_home)
    build_environment["RUSTUP_HOME"] = str(rustup_home)
    build_environment["CARGO_TARGET_DIR"] = str(target_dir)
    build_environment["CARGO_INCREMENTAL"] = "0"
    build_environment["CARGO_ENCODED_RUSTFLAGS"] = _encoded_rustflags(remaps)

    cargo = inherited.get("CARGO", "cargo")
    if not cargo or "\x00" in cargo:
        raise RunnerBuildError("CARGO must name one executable")
    argv = (
        cargo,
        "build",
        "--locked",
        "--release",
        "--manifest-path",
        str(manifest),
        "--bin",
        RUNNER_BINARY,
    )
    is_windows = sys.platform == "win32" if windows is None else windows
    filename = f"{RUNNER_BINARY}.exe" if is_windows else RUNNER_BINARY
    markers = tuple(
        (label, spelling)
        for label, path in (
            ("home", host_home),
            *(((("workspace", workspace_root),) if workspace_root else ())),
            ("source", root),
            ("target", target_dir),
            ("cargo-home", cargo_home),
            ("rustup-home", rustup_home),
        )
        for spelling in _path_spellings(path)
    )
    return RunnerBuildPlan(
        argv=argv,
        cwd=root,
        environment=build_environment,
        output_path=target_dir / "release" / filename,
        remaps=remaps,
        private_path_markers=markers,
    )


def _encoded_markers(markers: Sequence[tuple[str, str]]) -> tuple[tuple[str, bytes], ...]:
    encoded: list[tuple[str, bytes]] = []
    for label, marker in markers:
        for value in dict.fromkeys((marker, marker.lower(), marker.upper())):
            encoded.extend(
                (
                    (label, value.encode("utf-8")),
                    (label, value.encode("utf-16-le")),
                )
            )
    return tuple((label, value) for label, value in encoded if value)


def verify_runner_has_no_build_paths(
    binary: str | Path,
    markers: Sequence[tuple[str, str]],
) -> None:
    """Reject an artifact containing any remapped host build root."""

    path = Path(binary)
    if path.is_symlink() or not path.is_file():
        raise RunnerBuildError("release runner output is unavailable")
    signatures = _encoded_markers(markers)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise RunnerBuildError("release runner output could not be inspected") from exc
    for label, signature in signatures:
        if signature in payload:
            raise RunnerBuildError(f"release runner contains an unremapped {label} build path")


def build_release_runner(plan: RunnerBuildPlan) -> Path:
    """Execute one fixed build plan and verify its produced artifact."""

    try:
        subprocess.run(
            list(plan.argv),
            cwd=plan.cwd,
            env=dict(plan.environment),
            check=True,
            shell=False,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RunnerBuildError("release runner build failed") from exc
    verify_runner_has_no_build_paths(plan.output_path, plan.private_path_markers)
    return plan.output_path


def main() -> int:
    try:
        plan = create_runner_build_plan(Path(__file__).resolve().parents[1])
        build_release_runner(plan)
    except RunnerBuildError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print("Built and private-path-verified the release runner.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
