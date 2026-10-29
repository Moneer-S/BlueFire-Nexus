"""Bounded installed-Windows native result publication checks, without checkout imports.

The four archived tests exercise generated-file publication and same-server
reconciliation. They do not establish a separate-identity file-access journey,
watchdog restart recovery, or a representative Windows desktop environment.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import importlib.util
import json
import math
import os
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

TEST_IDS = (
    "tests_platform/test_runner_durable_result.py::"
    "test_windows_short_native_result_promotion_publishes_exact_bytes",
    "tests_platform/test_runner_durable_result.py::"
    "test_windows_native_result_collision_preserves_both_candidates",
    "tests_platform/test_runner_durable_result.py::"
    "test_windows_deep_native_result_promotion_matches_retained_failure_geometry",
    "tests_platform/test_windows_file_access_managed_transport.py::"
    "test_managed_terminal_result_uses_real_short_native_publication",
)
_HELPER = "verify_installed_windows_cancellation.py"
_VERIFIER = "verify_installed_windows_result_publication.py"
_MAX_SECONDS = 300
_MAX_RECORD = 1024 * 1024
_PREIMPORTS = (
    "bluefire.runner_client",
    "bluefire.runner_durable_result",
    "bluefire.runner_private_files",
    "bluefire.runner_transport",
    "bluefire.windows_owner_acl",
    "bluefire.runner_windows_containment",
)


def _digest(path: Path) -> str:
    details = path.lstat()
    if (
        path.is_symlink()
        or getattr(details, "st_file_attributes", 0) & 0x400
        or not path.is_file()
        or details.st_size > 128 * 1024 * 1024
    ):
        raise ValueError("input is not a bounded regular file")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    _digest(path)
    with path.open("rb") as stream:
        raw = stream.read(_MAX_RECORD + 1)
    if len(raw) > _MAX_RECORD:
        raise ValueError("record is too large")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("record must be an object")
    return result


def _write_json(path: Path, value: object) -> None:
    raw = json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    if len(raw) > _MAX_RECORD:
        raise ValueError("record is too large")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _directory(path: Path) -> Path:
    path = path.absolute()
    for part in (path, *path.parents):
        details = part.lstat()
        if (
            not part.is_dir()
            or part.is_symlink()
            or getattr(details, "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("directory contains a link or reparse point")
    return path.resolve(strict=True)


def _snapshot(source: Path) -> dict[str, str]:
    """Bind archived test imports, configuration, and copied verifier helpers."""
    paths = [source / "pyproject.toml", source / "bluefire/_source_revision.txt"]
    paths.extend(source / "tools" / name for name in (_HELPER, _VERIFIER))
    tests = _directory(source / "tests_platform")
    total = 0

    def failed_walk(error: OSError) -> None:
        raise error

    for parent, directories, files in os.walk(tests, followlinks=False, onerror=failed_walk):
        for name in directories:
            _directory(Path(parent) / name)
        for name in files:
            if name.endswith(".py"):
                paths.append(Path(parent) / name)
    if len(paths) > 10000:
        raise ValueError("too many archived inputs")
    result = {}
    for path in sorted(paths):
        total += path.lstat().st_size
        if total > 64 * 1024 * 1024:
            raise ValueError("archived inputs exceed their bound")
        result[path.relative_to(source).as_posix()] = _digest(path)
    return result


def _snapshot_digest(value: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def _load_helper(source: Path, helper: Path) -> Any:
    if _digest(helper) != _digest(source / "tools" / _HELPER):
        raise ValueError("copied package verifier differs from the archive")
    spec = importlib.util.spec_from_file_location("_installed_publication_package", helper)
    if spec is None or spec.loader is None:
        raise ValueError("package verifier could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _installed_identity(args: argparse.Namespace) -> tuple[Path, dict[str, Any]]:
    source = _directory(args.source)
    forbidden = _directory(args.forbid_root)
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_revision):
        raise ValueError("source revision is invalid")
    if (source / ".git").exists() or not source.is_relative_to(forbidden):
        raise ValueError("an archived source directory is required")
    if (source / "bluefire/_source_revision.txt").read_text(
        "ascii"
    ).strip() != args.source_revision:
        raise ValueError("archived source revision differs")
    if _digest(Path(__file__)) != _digest(source / "tools" / _VERIFIER):
        raise ValueError("copied verifier differs from the archive")
    helper = _load_helper(source, args.helper)
    distribution = importlib.metadata.distribution("bluefire-nexus")
    candidates = {
        Path(sysconfig.get_paths()[kind]).resolve() / "bluefire"
        for kind in ("purelib", "platlib")
        if (Path(sysconfig.get_paths()[kind]) / "bluefire").is_dir()
    }
    if len(candidates) != 1:
        raise ValueError("installed package location is ambiguous")
    package = _directory(candidates.pop())
    if (
        package.is_relative_to(forbidden)
        or '"editable": true' in (distribution.read_text("direct_url.json") or "").lower()
        or not helper._installed_package_matches_wheel(args.wheel, package, distribution.version)
    ):
        raise ValueError("installed package differs from the wheel")
    info = _read_json(package / "_build_info.json")
    if (
        info.get("source_revision") != args.source_revision
        or info.get("source_provenance") != "git_archive"
    ):
        raise ValueError("installed wheel revision or provenance differs")
    archived_python = {
        path.relative_to(source / "bluefire").as_posix(): _digest(path)
        for path in (source / "bluefire").rglob("*.py")
    }
    installed_python = {
        path.relative_to(package).as_posix(): _digest(path) for path in package.rglob("*.py")
    }
    if not archived_python or archived_python != installed_python:
        raise ValueError("archived product Python differs from the installed wheel")
    for name in _PREIMPORTS:
        importlib.import_module(name)
    _module_origins(package)
    return package, {
        "source_revision": args.source_revision,
        "source_provenance": "git_archive",
        "product_version": distribution.version,
        "wheel_filename": args.wheel.name,
        "wheel_sha256": _digest(args.wheel),
        "verifier_sha256": _digest(Path(__file__)),
        "package_helper_sha256": _digest(args.helper),
        "installed_package_matches_wheel": True,
        "archived_product_python_matches": True,
    }


def _module_origins(package: Path) -> dict[str, str]:
    result = {}
    for name, module in tuple(sys.modules.items()):
        if name == "bluefire" or name.startswith("bluefire."):
            origin = getattr(module, "__file__", None)
            if not origin:
                raise ValueError("product module has no file origin")
            path = Path(origin).resolve(strict=True)
            if not path.is_relative_to(package):
                raise ValueError("product module was loaded outside the installed package")
            result[name] = _digest(path)
    if not result:
        raise ValueError("product was not preimported")
    return result


def _geometry(root: Path) -> dict[str, int]:
    units = len(str(root / "t").encode("utf-16-le")) // 2
    result = {
        "basetemp_units": units,
        "managed_pending_units_upper_bound": units + 32 + 156,
        "deep_parent_units": 233,
        "deep_staging_units": 249,
        "deep_final_units": 279,
        "deep_pending_units": 323,
    }
    if result["managed_pending_units_upper_bound"] >= 240:
        raise ValueError("short native test geometry is unavailable")
    return result


def _environment(root: Path, system_root: str, architecture: str) -> dict[str, str]:
    env = {
        "SYSTEMROOT": system_root,
        "WINDIR": system_root,
        "PATH": str(Path(sys.executable).parent) + os.pathsep + str(Path(system_root) / "System32"),
        "HOME": str(root / "home"),
        "USERPROFILE": str(root / "home"),
        "APPDATA": str(root / "home"),
        "LOCALAPPDATA": str(root / "home"),
        "TEMP": str(root / "temp"),
        "TMP": str(root / "temp"),
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    if architecture.lower() not in {"amd64", "x86_64"}:
        raise ValueError("this verifier requires Windows x64")
    env["PROCESSOR_ARCHITECTURE"] = "AMD64"
    return env


def _junit(raw_path: Path, published: Path) -> dict[str, Any]:
    """Publish counts and fixed test names, never captured output or tracebacks."""
    _digest(raw_path)
    raw = raw_path.read_bytes()
    if len(raw) > _MAX_RECORD or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise ValueError("JUnit input is invalid")
    document = ET.fromstring(raw)
    cases = list(document.iter("testcase"))
    expected = {
        (file.removesuffix(".py").replace("/", "."), name)
        for file, name in (test.split("::") for test in TEST_IDS)
    }
    seen = []
    counts = {"tests": len(cases), "failures": 0, "errors": 0, "skipped": 0}
    output = ET.Element("testsuite", name="installed_windows_result_publication")
    for case in cases:
        key = (case.get("classname", ""), case.get("name", ""))
        seen.append(key)
        known = key in expected
        safe = ET.SubElement(
            output,
            "testcase",
            classname=key[0] if known else "unrecognized_test",
            name=key[1] if known else "unrecognized_test",
        )
        try:
            duration = float(case.get("time", "0"))
            if math.isfinite(duration) and duration >= 0:
                safe.set("time", str(duration))
        except ValueError:
            pass
        for tag, count in (("failure", "failures"), ("error", "errors"), ("skipped", "skipped")):
            if case.find(tag) is not None:
                counts[count] += 1
                ET.SubElement(safe, tag, message="See the verifier's sanitized failure status.")
    declared = [node for node in document.iter("testsuite") if node.findall("testcase")]
    counts_match = all(
        sum(int(node.get(key, "-1")) for node in declared) == value for key, value in counts.items()
    )
    for key, value in counts.items():
        output.set(key, str(value))
    with published.open("xb") as stream:
        ET.ElementTree(output).write(stream, encoding="utf-8", xml_declaration=True)
    return {
        **counts,
        "exact_test_ids": len(seen) == 4 and set(seen) == expected,
        "declared_counts_match": counts_match,
        "passed": counts == {"tests": 4, "failures": 0, "errors": 0, "skipped": 0}
        and len(seen) == 4
        and set(seen) == expected
        and counts_match,
        "raw_junit_sha256": _digest(raw_path),
    }


def _exception_codes(error: BaseException) -> list[dict[str, Any]]:
    allowed = {
        "builtins": {
            "OSError",
            "PermissionError",
            "FileExistsError",
            "FileNotFoundError",
            "TimeoutError",
            "ValueError",
            "RuntimeError",
            "AssertionError",
        },
        "_pytest.outcomes": {"Failed", "Skipped"},
        "bluefire.runner_transport_errors": {"RunnerTransportError", "RunnerDurableResultExists"},
    }
    pending = [error]
    seen: set[int] = set()
    result = []
    while pending and len(result) < 8:
        current = pending.pop(0)
        if id(current) in seen:
            continue
        seen.add(id(current))
        kind = type(current)
        row: dict[str, Any] = {
            "error_type": (
                kind.__name__
                if kind.__name__ in allowed.get(kind.__module__, set())
                else "Exception"
            )
        }
        for key in ("errno", "winerror", "ntstatus"):
            value = getattr(current, key, None)
            if type(value) is int and -(2**31) <= value < 2**32:
                row[key] = value
        result.append(row)
        # Normalized product errors intentionally suppress display of context;
        # its numeric OS codes remain useful without disclosing the message.
        for nested in (current.__cause__, current.__context__):
            if isinstance(nested, BaseException):
                pending.append(nested)
    return result


class _FailureDiagnostics:
    def __init__(self, runtime: Path) -> None:
        self.runtime = runtime
        self.count = 0

    def pytest_runtest_makereport(self, item: Any, call: Any) -> None:
        if call.excinfo is None or self.count >= 12:
            return
        node = str(item.nodeid).replace("\\", "/")
        known = next((test for test in TEST_IDS if node == test or node.endswith("/" + test)), None)
        record = {
            "test_id": known or "unrecognized_test",
            "phase": call.when if call.when in {"setup", "call", "teardown"} else "unknown",
            "exceptions": _exception_codes(call.excinfo.value),
        }
        _write_json(self.runtime / f"failure-{self.count:02d}.json", record)
        self.count += 1


def _worker(args: argparse.Namespace) -> int:
    report: dict[str, Any] = {"status": "failed_or_incomplete", "stage": "identity"}
    try:
        _require_host()
        if (
            _directory(args.runtime).parent != _directory(args.runner_temp)
            or re.fullmatch(r"bfn-[0-9a-f]{8}", args.runtime.name) is None
        ):
            raise ValueError("worker runtime ownership differs")
        package, identity = _installed_identity(args)
        report["identity"] = identity
        before = _snapshot(args.source)
        report["source_inputs_sha256"] = _snapshot_digest(before)
        report["source_input_count"] = len(before)
        report["geometry"] = _geometry(args.runtime)
        import pytest

        # Only archived test helpers may use this entry; bluefire is already pinned.
        sys.path.insert(0, str(args.source))
        config = args.runtime / "pytest.ini"
        config.write_text("[pytest]\n", encoding="ascii")
        report["stage"] = "four_native_tests"
        code = pytest.main(
            [
                "-c",
                str(config),
                "--rootdir",
                str(args.source),
                "--noconftest",
                "--import-mode=importlib",
                "-p",
                "no:cacheprovider",
                "-p",
                "pytest_timeout",
                "--timeout=60",
                "--timeout-method=thread",
                "--basetemp",
                str(args.runtime / "t"),
                "--junitxml",
                str(args.runtime / "raw-junit.xml"),
                "-q",
                *(
                    str(args.source / test.split("::")[0]) + "::" + test.split("::")[1]
                    for test in TEST_IDS
                ),
            ],
            plugins=[_FailureDiagnostics(args.runtime)],
        )
        report["pytest_exit_code"] = int(code)
        report["stage"] = "postconditions"
        report["product_module_hashes"] = _module_origins(package)
        report["loaded_archived_inputs"] = {
            Path(module.__file__)
            .resolve()
            .relative_to(args.source)
            .as_posix(): _digest(Path(module.__file__))
            for name, module in tuple(sys.modules.items())
            if name.startswith("tests_platform") and getattr(module, "__file__", None)
        }
        if any(
            before.get(path) != digest for path, digest in report["loaded_archived_inputs"].items()
        ):
            raise ValueError("loaded test helper differs from the archive snapshot")
        if _snapshot(args.source) != before:
            raise ValueError("archived test inputs changed")
        _, after_identity = _installed_identity(args)
        if after_identity != identity:
            raise ValueError("installed product identity changed")
        report["source_inputs_unchanged"] = True
        report["installed_product_unchanged"] = True
        report["status"] = "passed" if code == 0 else "failed_or_incomplete"
    except Exception as error:
        report["error_type"] = type(error).__name__
    finally:
        _write_json(args.runtime / "worker.json", report)
    return 0 if report["status"] == "passed" else 1


def _supervise(
    command: list[str], *, runtime: Path, env: dict[str, str], containment: Any
) -> dict[str, Any]:
    result: dict[str, Any] = {"process_exited": False, "job_empty": False, "timed_out": False}
    process = None
    job = None
    assigned = False
    try:
        job = containment.create_job()
        with (runtime / "worker.log").open("xb") as log:
            process = subprocess.Popen(
                command,
                cwd=runtime,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=0x08000000 | 0x00000004,
            )
            containment.assign(job, process)
            assigned = True
            containment.resume_suspended(process)
            try:
                process.wait(timeout=_MAX_SECONDS)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
    except Exception as error:
        result["error_type"] = type(error).__name__
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    if assigned:
                        result["job_empty"] = bool(containment.terminate(process))
                    else:
                        process.kill()  # It has never resumed if assignment failed.
                process.wait(timeout=5)
                result["process_exited"] = process.poll() is not None
                result["returncode"] = process.returncode
                if assigned:
                    result["job_empty"] = bool(containment.finish(process))
                elif job is not None:
                    result["job_empty"] = bool(containment.close_handle(job))
            elif job is not None:
                result["job_empty"] = bool(containment.close_handle(job))
                result["process_exited"] = True
        except Exception as error:
            result["cleanup_error_type"] = type(error).__name__
    return result


def _cleanup(runtime: Path, runner_temp: Path) -> None:
    if (
        _directory(runtime).parent != _directory(runner_temp)
        or re.fullmatch(r"bfn-[0-9a-f]{8}", runtime.name) is None
    ):
        raise ValueError("runtime cleanup ownership differs")
    shutil.rmtree(runtime)
    if runtime.exists():
        raise OSError("runtime cleanup is incomplete")


def _require_host() -> None:
    if sys.platform != "win32" or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError("isolated Windows Python with bytecode disabled is required")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "wheel", "helper", "forbid-root", "output", "runner-temp"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--runtime", type=Path)
    args = parser.parse_args(argv)
    if args.worker:
        return _worker(args)
    report: dict[str, Any] = {
        "status": "failed_or_incomplete",
        "stage": "preflight",
        "coverage": "native generated-file result publication and same-server reconciliation",
        "not_covered": [
            "separate-identity effective access",
            "watchdog restart recovery",
            "Windows 11",
        ],
        "os": platform.platform(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "runtime_removed": False,
    }
    started = time.monotonic()
    runtime = None
    output_owned = False
    try:
        args.output.mkdir(parents=False, exist_ok=False)
        output_owned = True
        _directory(args.output)
        _require_host()
        runner_temp = _directory(args.runner_temp)
        runtime = runner_temp / ("bfn-" + uuid.uuid4().hex[:8])
        runtime.mkdir(exist_ok=False)
        for name in ("home", "temp"):
            (runtime / name).mkdir()
        report["geometry"] = _geometry(runtime)
        system_root = str(_directory(Path(os.environ["SYSTEMROOT"])))
        env = _environment(runtime, system_root, platform.machine())
        os.environ.clear()
        os.environ.update(env)
        _, identity = _installed_identity(args)
        report["identity"] = identity
        before = _snapshot(args.source)
        from bluefire.runner_windows_containment import WindowsJobContainment

        report["stage"] = "supervised_tests"
        command = [
            sys.executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            *(argv if argv is not None else sys.argv[1:]),
            "--worker",
            "--runtime",
            str(runtime),
        ]
        process = _supervise(
            command, runtime=runtime, env=env, containment=WindowsJobContainment(kill_on_close=True)
        )
        report["supervision"] = process
        report["stage"] = "evidence"
        report["failure_diagnostics"] = [
            _read_json(runtime / f"failure-{index:02d}.json")
            for index in range(12)
            if (runtime / f"failure-{index:02d}.json").is_file()
        ]
        if (runtime / "raw-junit.xml").is_file():
            report["junit"] = _junit(
                runtime / "raw-junit.xml", args.output / "result-publication.xml"
            )
        if (runtime / "worker.json").is_file():
            report["worker"] = _read_json(runtime / "worker.json")
        _, after_identity = _installed_identity(args)
        report["source_inputs_unchanged"] = before == _snapshot(args.source)
        report["identity_unchanged"] = identity == after_identity
        passed = (
            process.get("process_exited") is True
            and process.get("job_empty") is True
            and process.get("timed_out") is False
            and process.get("returncode") == 0
            and report.get("junit", {}).get("passed") is True
            and report.get("worker", {}).get("status") == "passed"
            and report["source_inputs_unchanged"]
            and report["identity_unchanged"]
        )
        if passed:
            # Persist useful evidence before removing only this stopped owned runtime.
            _write_json(args.output / "result-publication-observations.json", report)
            _cleanup(runtime, runner_temp)
            report["runtime_removed"] = True
            report["status"] = "passed"
    except Exception as error:
        report["error_type"] = type(error).__name__
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["runtime_retained"] = runtime is not None and runtime.exists()
        if output_owned:
            _write_json(args.output / "result-publication.json", report)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
