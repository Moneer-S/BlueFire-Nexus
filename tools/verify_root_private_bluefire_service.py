"""Verify one root-private installed BlueFire service wheel before launch.

Copy this script and verify_installed_engine_experiment.py into a root-owned
private directory, then run this script with that directory's installed-venv
Python under ``-I -B``. This verifier does not launch a service or an engine.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import stat
import sys
import sysconfig
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Mapping, Sequence

_ROOT = re.compile(r"/root/bluefire-ci-[a-z0-9][a-z0-9-]{0,79}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_WHEEL_FILENAME = re.compile(
    r"bluefire_nexus-[A-Za-z0-9_.!+]+(?:-[0-9][A-Za-z0-9_.]*)?"
    r"-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+\.whl\Z"
)
_MAX_TREE_ENTRIES = 4096
_MAX_WHEEL_BYTES = 128 * 1024 * 1024


class VerificationError(ValueError):
    """Stable failure without exposing private paths or service inputs."""


def _canonical_path(value: str) -> Path:
    if type(value) is not str or not value or len(value) > 512:
        raise VerificationError("path_invalid")
    parsed = PurePosixPath(value)
    if not parsed.is_absolute() or str(parsed) != value or ".." in parsed.parts:
        raise VerificationError("path_invalid")
    return Path(value)


def _private_root(value: str) -> Path:
    path = _canonical_path(value)
    if _ROOT.fullmatch(value) is None:
        raise VerificationError("private_root_invalid")
    return path


def _staged_wheel(root: Path) -> Path:
    staged = root / "staged"
    _secure_path(staged, kind="directory", exact_mode=0o700)
    names = list(staged.iterdir())
    if len(names) != 1 or _WHEEL_FILENAME.fullmatch(names[0].name) is None:
        raise VerificationError("staged_wheel_invalid")
    return names[0]


def _secure_path(path: Path, *, kind: str, exact_mode: int | None = None) -> os.stat_result:
    """Reject symlinks and non-root/writable components from / through path."""

    if not path.is_absolute() or kind not in {"file", "directory"}:
        raise VerificationError("path_invalid")
    result: os.stat_result | None = None
    for part in reversed((path, *path.parents)):
        info = os.lstat(part)
        mode = stat.S_IMODE(info.st_mode)
        if (
            stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or mode & 0o022
            or (part != path and not stat.S_ISDIR(info.st_mode))
        ):
            raise VerificationError("path_custody_invalid")
        result = info
    assert result is not None
    if (
        (kind == "file" and not stat.S_ISREG(result.st_mode))
        or (kind == "directory" and not stat.S_ISDIR(result.st_mode))
        or (exact_mode is not None and stat.S_IMODE(result.st_mode) != exact_mode)
    ):
        raise VerificationError("path_custody_invalid")
    return result


def _secure_tree(root: Path) -> None:
    _secure_path(root, kind="directory")
    count = 0

    def failed(_error: OSError) -> None:
        raise VerificationError("installed_tree_unavailable")

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in (*dirs, *files):
            count += 1
            if count > _MAX_TREE_ENTRIES:
                raise VerificationError("installed_tree_bound")
            candidate = Path(directory) / name
            _secure_path(candidate, kind="directory" if name in dirs else "file")


def _sha256(path: Path, *, maximum: int) -> str:
    info = _secure_path(path, kind="file")
    if not 0 < info.st_size <= maximum:
        raise VerificationError("artifact_bound")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    if path.lstat().st_size != info.st_size:
        raise VerificationError("artifact_changed")
    return "sha256:" + value.hexdigest()


def _load_binding_helper(path: Path, expected_digest: str) -> ModuleType:
    if _sha256(path, maximum=256 * 1024) != expected_digest:
        raise VerificationError("binding_helper_changed")
    spec = importlib.util.spec_from_file_location("_bluefire_installed_wheel_binding", path)
    if spec is None or spec.loader is None:
        raise VerificationError("binding_helper_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in ("bind_installed_wheel", "build_identity_valid", "digest"):
        if not callable(getattr(module, name, None)):
            raise VerificationError("binding_helper_invalid")
    return module


def _check_venv_config(venv: Path) -> None:
    config = venv / "pyvenv.cfg"
    if _secure_path(config, kind="file").st_size > 4096:
        raise VerificationError("venv_config_invalid")
    lines = config.read_text(encoding="utf-8").splitlines()
    settings = [line.partition("=") for line in lines]
    values = [
        value.strip()
        for key, delimiter, value in settings
        if delimiter and key.strip() == "include-system-site-packages"
    ]
    if values != ["false"]:
        raise VerificationError("venv_config_invalid")


def _identity(
    *,
    info: Mapping[str, Any],
    version: str,
    wheel_digest: str,
    provider_digest: str,
    binding: Mapping[str, object],
    expected_revision: str,
    helper: ModuleType,
) -> dict[str, object]:
    source = info.get("source")
    build = info.get("build")
    ui = info.get("ui")
    product = info.get("product")
    if not all(isinstance(value, Mapping) for value in (source, build, ui, product)):
        raise VerificationError("build_info_invalid")
    if (
        source.get("revision") != expected_revision
        or source.get("provenance") != "git_archive"
        or product.get("version") != version
        or build.get("metadata_status") != "embedded"
        or ui.get("matches_build") is not True
        or not isinstance(ui.get("files"), list)
        or [item.get("name") for item in ui["files"] if isinstance(item, Mapping)]
        != ["app.js", "index.html", "styles.css", "fonts/InterVariable.woff2"]
    ):
        raise VerificationError("build_info_invalid")
    identity: dict[str, object] = {
        "distribution": "bluefire-nexus",
        "version": version,
        "wheel_sha256": wheel_digest,
        "source_revision": source["revision"],
        "source_provenance": source["provenance"],
        "build_metadata_status": build["metadata_status"],
        "ui_digest": ui.get("digest"),
        "ui_files": ui["files"],
        "ui_matches_build": ui["matches_build"],
        "controlled_provider_sha256": provider_digest,
        **binding,
    }
    if not helper.build_identity_valid(identity):
        raise VerificationError("installed_identity_invalid")
    return identity


def verify(args: argparse.Namespace) -> dict[str, object]:
    if sys.platform != "linux" or not sys.flags.isolated or not sys.flags.dont_write_bytecode:
        raise VerificationError("isolated_linux_required")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise VerificationError("root_required")
    root = _private_root(args.private_root)
    checkout = _canonical_path(args.forbid_root).resolve(strict=True)
    if not _REVISION.fullmatch(args.expected_source_revision):
        raise VerificationError("source_revision_invalid")
    if not all(
        type(value) is str and _DIGEST.fullmatch(value) is not None
        for value in (
            args.expected_wheel_sha256,
            args.expected_helper_sha256,
            args.expected_verifier_sha256,
        )
    ):
        raise VerificationError("digest_invalid")
    if root.is_relative_to(checkout) or checkout.is_relative_to(root):
        raise VerificationError("checkout_overlap")
    _secure_path(root, kind="directory", exact_mode=0o700)
    script = root / "verify_root_private_bluefire_service.py"
    helper_path = root / "verify_installed_engine_experiment.py"
    wheel = _staged_wheel(root)
    venv = root / "venv"
    if Path(__file__) != script or Path(sys.prefix) != venv:
        raise VerificationError("installed_process_identity_invalid")
    if Path.cwd().is_relative_to(checkout) or Path.cwd().is_relative_to(venv):
        raise VerificationError("working_directory_invalid")
    allowed_interpreters = {venv / "bin" / name for name in ("python", "python3", "python3.12")}
    if sys.prefix == sys.base_prefix or Path(sys.executable) not in allowed_interpreters:
        raise VerificationError("installed_interpreter_invalid")
    _secure_path(script, kind="file")
    if _sha256(script, maximum=256 * 1024) != args.expected_verifier_sha256:
        raise VerificationError("verifier_changed")
    _secure_path(helper_path, kind="file")
    _secure_path(wheel, kind="file", exact_mode=0o600)
    _secure_path(venv, kind="directory")
    _check_venv_config(venv)
    _secure_path(Path(sys.executable), kind="file")
    purelib = Path(sysconfig.get_path("purelib"))
    if not purelib.is_relative_to(venv):
        raise VerificationError("purelib_invalid")
    _secure_path(purelib, kind="directory")
    for raw in sys.path:
        if not raw:
            raise VerificationError("import_path_invalid")
        path = Path(raw)
        if not path.is_absolute() or path.is_relative_to(checkout):
            raise VerificationError("import_path_invalid")
        while not path.exists() and path != path.parent:
            path = path.parent
        _secure_path(path, kind="directory" if path.is_dir() else "file")
    helper = _load_binding_helper(helper_path, args.expected_helper_sha256)
    wheel_digest = _sha256(wheel, maximum=_MAX_WHEEL_BYTES)
    if wheel_digest != args.expected_wheel_sha256:
        raise VerificationError("wheel_changed")
    import bluefire
    from bluefire.build_info import build_info

    package = Path(bluefire.__file__)
    if not package.is_relative_to(purelib) or package.is_relative_to(checkout):
        raise VerificationError("checkout_import_refused")
    _secure_tree(package.parent)
    dist_infos = list(purelib.glob("bluefire_nexus-*.dist-info"))
    if len(dist_infos) != 1:
        raise VerificationError("distribution_ambiguous")
    _secure_tree(dist_infos[0])
    distribution = importlib.metadata.distribution("bluefire-nexus")
    if Path(distribution.locate_file("")) != purelib:
        raise VerificationError("distribution_location_invalid")
    version = distribution.version
    binding = helper.bind_installed_wheel(wheel, purelib=purelib, installed_version=version)
    identity = _identity(
        info=build_info(),
        version=version,
        wheel_digest=wheel_digest,
        provider_digest=_sha256(
            package.parent / "controlled_strix_provider.py", maximum=256 * 1024
        ),
        binding=binding,
        expected_revision=args.expected_source_revision,
        helper=helper,
    )
    report = {
        "schema_version": "bluefire.root-private-installed-service-verification.v1",
        "verified": True,
        "source_revision": args.expected_source_revision,
        "wheel_sha256": wheel_digest,
        "wheel_payload_digest": identity["wheel_payload_digest"],
        "installed_payload_digest": identity["installed_payload_digest"],
        "ui_digest": identity["ui_digest"],
        "version": version,
        "root_private": True,
        "service_started": False,
    }
    payload = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    descriptor = os.open(
        root / "installed-service-verification.json",
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        remaining = memoryview(payload)
        while remaining:
            count = os.write(descriptor, remaining)
            if count <= 0:
                raise VerificationError("report_write_unknown")
            remaining = remaining[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-root", required=True)
    parser.add_argument("--forbid-root", required=True)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--expected-wheel-sha256", required=True)
    parser.add_argument("--expected-helper-sha256", required=True)
    parser.add_argument("--expected-verifier-sha256", required=True)
    try:
        report = verify(parser.parse_args(argv))
    except (OSError, RuntimeError, ValueError):
        print("root-private installed service verification failed", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":  # pragma: no cover - copied installed entry
    raise SystemExit(main())
