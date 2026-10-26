"""Exercise the protected macOS setup through its normal CLI and HTTP APIs."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import queue
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bluefire import runner_client

API = "/api/v1"
MAX_BODY = 1024 * 1024
POLL_SECONDS = 0.5
JOB_TIMEOUT = 180


class QualificationError(RuntimeError):
    def __init__(self, message: str, *, diagnostics: dict[str, Any] | None = None):
        super().__init__(message)
        self.diagnostics = diagnostics or {}


_KNOWN_SETUP_ERROR_CLASSES = {
    "The local identity inventory is unavailable.": "local_identity_inventory_unavailable",
    "The local identity inventory is invalid.": "local_identity_inventory_invalid",
    "The temporary identity inventory is unavailable.": "temporary_identity_inventory_unavailable",
    "The temporary identity inventory is invalid.": "temporary_identity_inventory_invalid",
    "No unused temporary numeric identities are available.": "temporary_identities_unavailable",
    "Another protected macOS setup session is active.": "setup_session_already_active",
    "The protected macOS setup is unavailable.": "protected_setup_unavailable",
    "Use a root-owned CPython 3.10.16 legacy or 3.11.18 qualification session on macOS arm64.": "unsupported_protected_runtime",
}
_SAFE_SETUP_ERROR_CLASSES = frozenset(_KNOWN_SETUP_ERROR_CLASSES.values()) | {
    "unclassified_command_failure"
}
_READINESS_FAILURE_STAGES = frozenset(
    {
        "readiness_wait",
        "child_identity_unavailable",
        "child_exited_before_readiness",
        "readiness_timeout",
        "loopback_origin_invalid",
        "bootstrap_capability_invalid",
    }
)


def _parse_child_cli_error(raw: str) -> dict[str, str] | None:
    """Keep only fixed CLI error codes and classifications, never message text."""
    if len(raw.encode("utf-8", errors="replace")) > 4096:
        return None
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    error = document.get("error") if isinstance(document, dict) else None
    if not isinstance(error, dict) or error.get("code") != "command_failed":
        return None
    message = error.get("message")
    if not isinstance(message, str):
        return None
    return {
        "error_code": "command_failed",
        "error_class": _KNOWN_SETUP_ERROR_CLASSES.get(message, "unclassified_command_failure"),
    }


def _safe_readiness_diagnostics(
    failure_stage: str,
    stopped: dict[str, Any],
    child_error: dict[str, str] | None,
) -> dict[str, Any]:
    """Project runtime state onto fixed, non-sensitive diagnostic fields."""
    result: dict[str, Any] = {
        "failure_stage": (
            failure_stage
            if isinstance(failure_stage, str) and failure_stage in _READINESS_FAILURE_STAGES
            else "readiness_wait"
        )
    }
    shutdown_method = stopped.get("shutdown_method")
    if isinstance(shutdown_method, str) and shutdown_method in {
        "supervisor_sigterm",
        "group_sigterm",
        "group_sigkill",
    }:
        result["shutdown_method"] = shutdown_method
    for field in ("process_group_gone", "streams_drained"):
        value = stopped.get(field)
        if type(value) is bool:
            result[field] = value
    returncode = stopped.get("supervisor_returncode")
    if type(returncode) is int and -255 <= returncode <= 255:
        result["supervisor_returncode"] = returncode
    if (
        isinstance(child_error, dict)
        and child_error.get("error_code") == "command_failed"
        and isinstance(child_error.get("error_class"), str)
        and child_error.get("error_class") in _SAFE_SETUP_ERROR_CLASSES
    ):
        result["error_code"] = "command_failed"
        result["error_class"] = child_error["error_class"]
    return result


@dataclass
class SupervisorHandle:
    process: subprocess.Popen[str]
    ready_lines: queue.Queue[str]
    stdout_lines: queue.Queue[str]
    child_errors: queue.Queue[dict[str, str]]
    reader_threads: tuple[threading.Thread, threading.Thread]


def _json_request(
    host: str, port: int, method: str, path: str, token: str, body: Any = None
) -> tuple[int, Any]:
    if not path.startswith(API + "/") or "?" in path or "#" in path:
        raise QualificationError("A noncanonical API path was requested.")
    headers = {"X-BlueFire-Session": token, "Accept": "application/json"}
    if method == "POST":
        headers["Origin"] = _origin(host, port)
    payload = None
    if body is not None:
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(payload) > MAX_BODY:
            raise QualificationError("A bounded qualification API body exceeded its limit.")
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        connection.request(method, path, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_BODY + 1)
        if len(raw) > MAX_BODY:
            raise QualificationError("A bounded qualification API response exceeded its limit.")
        if response.status == 204:
            return response.status, None
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise QualificationError("The local API returned a non-JSON response.") from exc
        return response.status, value
    finally:
        connection.close()


def _exchange_bootstrap(host: str, port: int, capability: str) -> str:
    connection = http.client.HTTPConnection(host, port, timeout=10)
    try:
        connection.request(
            "POST",
            API + "/session",
            body=b"",
            headers={
                "X-BlueFire-Browser-Bootstrap": capability,
                "Origin": _origin(host, port),
                "Content-Length": "0",
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        raw = response.read(MAX_BODY + 1)
        if response.status != 200 or len(raw) > MAX_BODY:
            raise QualificationError("The normal browser-session exchange did not succeed.")
        value = json.loads(raw.decode("utf-8"))
        session = value.get("session") if isinstance(value, dict) else None
        if not isinstance(session, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", session):
            raise QualificationError(
                "The browser-session exchange did not return a valid in-memory session."
            )
        return session
    finally:
        connection.close()


def _origin(host: str, port: int) -> str:
    return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"


def _expect(status: int, value: Any, accepted: tuple[int, ...] = (200,)) -> Any:
    if status not in accepted or not isinstance(value, (dict, list)):
        raise QualificationError(f"The local API returned unexpected HTTP status {status}.")
    if isinstance(value, dict) and value.get("error"):
        raise QualificationError("The local API rejected an exact reviewed qualification request.")
    return value


def _request(
    host: str,
    port: int,
    token: str,
    method: str,
    path: str,
    body: Any = None,
    accepted: tuple[int, ...] = (200,),
) -> Any:
    status, value = _json_request(host, port, method, path, token, body)
    return _expect(status, value, accepted)


def _poll(
    host: str, port: int, token: str, path: str, predicate, *, timeout: int = JOB_TIMEOUT
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: Any = None
    while time.monotonic() < deadline:
        last = _request(host, port, token, "GET", path)
        if predicate(last):
            return last
        if isinstance(last, dict):
            owner = last.get("owner", last)
            state = owner.get("state") if isinstance(owner, dict) else None
            if state in {"failed", "rejected", "cancelled", "expired"}:
                raise QualificationError("A reviewed local qualification job did not complete.")
        time.sleep(POLL_SECONDS)
    raise QualificationError("A reviewed local qualification job exceeded its fixed deadline.")


def _submit_file_access(
    host: str, port: int, token: str, control_id: str, operation: str
) -> dict[str, Any]:
    review_request = {"operation": operation, "control_owner_id": control_id}
    review = _request(host, port, token, "POST", API + "/file-access/review", review_request)
    if (
        review.get("operation") != operation
        or review.get("control_owner_id") != control_id
        or not isinstance(review.get("review_digest"), str)
    ):
        raise QualificationError(
            "The operation review was not bound to the selected retained control."
        )
    submission_id = str(uuid.uuid4())
    submitted = _request(
        host,
        port,
        token,
        "POST",
        API + "/file-access/operations",
        {
            "submission_id": submission_id,
            "review": review_request,
            "review_digest": review["review_digest"],
            "reviewed_by": "Hosted macOS lifecycle qualification",
        },
        accepted=(200, 202),
    )
    job_id = submitted.get("job", {}).get("job_id")
    if not isinstance(job_id, str) or not re.fullmatch(r"job-[0-9a-f]{32}", job_id):
        raise QualificationError(
            "The reviewed file operation did not return its exact saved job identity."
        )
    terminal = _poll(
        host,
        port,
        token,
        API + "/file-access/operations/" + job_id,
        lambda value: isinstance(value.get("job"), dict)
        and value["job"].get("state") in {"completed", "failed", "cancelled"},
    )
    if terminal["job"].get("state") != "completed":
        raise QualificationError("The reviewed file operation did not complete successfully.")
    return terminal


def _open_supervisor(python: Path) -> tuple[SupervisorHandle, str, int, str]:
    home = python.parent.parent.parent / "home"
    argv = [
        str(python),
        "-I",
        "-B",
        "-m",
        "bluefire",
        "runner",
        "macos-file-setup",
        "--confirm-create-generated-workspace",
        "--port",
        "0",
        "--no-browser",
    ]
    process = subprocess.Popen(
        argv,
        cwd=home,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONNOUSERSITE": "1",
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    ready_lines: queue.Queue[str] = queue.Queue(maxsize=1)
    stdout_lines: queue.Queue[str] = queue.Queue(maxsize=1)
    child_errors: queue.Queue[dict[str, str]] = queue.Queue(maxsize=1)

    def read_stderr() -> None:
        assert process.stderr is not None
        for raw in process.stderr:
            if raw.startswith("BlueFire original macOS file-access workspace: "):
                try:
                    ready_lines.put_nowait(raw[:2048])
                except queue.Full:
                    continue

    def read_stdout() -> None:
        assert process.stdout is not None
        for raw in process.stdout:
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                continue
            child_error = _parse_child_cli_error(raw)
            if child_error is not None:
                try:
                    child_errors.put_nowait(child_error)
                except queue.Full:
                    pass
                continue
            if (
                not isinstance(document, dict)
                or document.get("schema_version")
                != "bluefire.macos-file-access-local-supervisor-result.v1"
            ):
                continue
            try:
                stdout_lines.put_nowait(raw[:MAX_BODY])
            except queue.Full:
                continue

    stderr_reader = threading.Thread(
        target=read_stderr, name="bluefire-macos-supervisor-stderr", daemon=True
    )
    stdout_reader = threading.Thread(
        target=read_stdout, name="bluefire-macos-supervisor-stdout", daemon=True
    )
    handle = SupervisorHandle(
        process, ready_lines, stdout_lines, child_errors, (stderr_reader, stdout_reader)
    )
    stderr_reader.start()
    stdout_reader.start()
    failure_stage = "readiness_wait"
    try:
        deadline = time.monotonic() + 120
        ready_url = None
        while time.monotonic() < deadline:
            child_state = _child_exit_state(process.pid)
            if child_state is None:
                failure_stage = "child_identity_unavailable"
                raise QualificationError(
                    "The original setup process identity could not be retained."
                )
            if child_state:
                failure_stage = "child_exited_before_readiness"
                raise QualificationError(
                    "The protected macOS setup command exited before readiness."
                )
            try:
                line = ready_lines.get(timeout=0.5)
            except queue.Empty:
                continue
            if line.startswith("BlueFire original macOS file-access workspace: "):
                ready_url = line.partition(": ")[2].strip()
                break
        if ready_url is None:
            failure_stage = "readiness_timeout"
            raise QualificationError("The protected macOS setup did not report readiness in time.")
        parsed = urllib.parse.urlsplit(ready_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or not parsed.port
            or parsed.path != "/"
            or parsed.query
        ):
            failure_stage = "loopback_origin_invalid"
            raise QualificationError(
                "The protected macOS setup did not bind its expected loopback origin."
            )
        fragment = urllib.parse.parse_qs(parsed.fragment, strict_parsing=True)
        capabilities = fragment.get("bluefire-session", [])
        if len(capabilities) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", capabilities[0]):
            failure_stage = "bootstrap_capability_invalid"
            raise QualificationError(
                "The protected macOS setup omitted its memory-only bootstrap capability."
            )
        return handle, parsed.hostname, parsed.port, capabilities[0]
    except BaseException as error:
        stopped = _stop_supervisor(handle)
        detail = f"shutdown={stopped['shutdown_method']} exited={stopped['supervisor_exited']} group_gone={stopped['process_group_gone']} streams_drained={stopped['streams_drained']}"
        try:
            child_error = handle.child_errors.get_nowait()
        except queue.Empty:
            child_error = None
        raise QualificationError(
            f"Protected macOS setup readiness failed; {detail}.",
            diagnostics=_safe_readiness_diagnostics(failure_stage, stopped, child_error),
        ) from error


def _stop_supervisor(handle: SupervisorHandle) -> dict[str, Any]:
    """Stop only the original owned process group, then bound wait and stream drainage."""
    process = handle.process
    process_group_signal_sent = False
    shutdown_method = "supervisor_sigterm"
    owned_child = _child_exit_state(process.pid) if process.returncode is None else None
    if owned_child is None:
        # The original child is no longer an unreaped owner, so its numeric
        # process-group ID must not be signalled or rediscovered.
        group_gone = False
    else:
        try:
            # Do not use Popen.send_signal/poll/wait yet: reaping the original
            # child would release the PID used as this process group's identity.
            os.kill(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        group_gone = _wait_owned_group(process, timeout=25)
        owned_child = _child_exit_state(process.pid)
    if not group_gone and owned_child is not None:
        shutdown_method = "group_sigterm"
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process_group_signal_sent = True
        except ProcessLookupError:
            pass
        group_gone = _wait_owned_group(process, timeout=5)
    if not group_gone and _child_exit_state(process.pid) is not None:
        shutdown_method = "group_sigkill"
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process_group_signal_sent = True
        except ProcessLookupError:
            pass
        group_gone = _wait_owned_group(process, timeout=10)
    for reader in handle.reader_threads:
        reader.join(timeout=3)
    streams_drained = all(not reader.is_alive() for reader in handle.reader_threads)
    # Never close a TextIOWrapper from this thread while its reader may still
    # be blocked in readline holding the wrapper lock. A live daemon reader is
    # reported as undrained and keeps the qualification from succeeding.
    drained = process.returncode is not None and group_gone and streams_drained
    stdout = None
    try:
        stdout = handle.stdout_lines.get_nowait()
    except queue.Empty:
        pass
    return {
        "supervisor_exited": process.returncode is not None,
        "supervisor_returncode": process.returncode,
        "shutdown_method": shutdown_method,
        "process_group_signal_sent": process_group_signal_sent,
        "process_group_gone": group_gone,
        "stdout_receipt_obtained": stdout is not None,
        "streams_drained": streams_drained,
        "drained": drained,
        "stdout": stdout,
    }


def _wait_owned_group(process: subprocess.Popen[str], *, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        child_state = _child_exit_state(process.pid)
        if child_state is None:
            return False
        if child_state and not _group_has_live_members(process.pid):
            # No group member can still receive a signal. It is now safe to
            # reap the original child and release the group identifier.
            try:
                process.wait(timeout=0)
            except subprocess.TimeoutExpired:
                return False
            return process.returncode is not None
        time.sleep(0.1)
    return False


def _child_exit_state(pid: int) -> bool | None:
    """Observe original-child exit without reaping its PID/group identity."""
    try:
        if not runner_client._darwin_child_status_ownership_available():
            return None
        return runner_client._darwin_child_exited_without_reap(pid)
    except (ChildProcessError, OSError, ValueError):
        return None


def _group_has_live_members(group_id: int) -> bool:
    """Treat zombies as non-running, while the unreaped leader pins group_id."""
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,pgid=,stat="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return True
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            member_group = int(fields[1])
        except ValueError:
            continue
        if member_group == group_id and not fields[2].startswith("Z"):
            return True
    return False


def _run(args: argparse.Namespace) -> None:
    if (
        os.geteuid() != 0
        or sys.version_info[:3] != (3, 11, 18)
        or platform.system() != "Darwin"
        or platform.machine() != "arm64"
    ):
        raise QualificationError(
            "The lifecycle verifier requires the exact protected CPython 3.11.18 macOS arm64 runtime."
        )
    python = Path(args.python).absolute()
    prefix = Path(args.prefix).resolve(strict=True)
    if (
        not re.fullmatch(r"[0-9]+-[0-9]+", args.run_identity)
        or prefix != Path("/private/var/db/bluefire-macos-runtime") / args.run_identity
    ):
        raise QualificationError("The lifecycle verifier prefix is not bound to this hosted run.")
    resolved_python = python.resolve(strict=True)
    if (
        not resolved_python.is_relative_to(prefix)
        or not resolved_python.is_file()
        or resolved_python.stat().st_uid != 0
        or resolved_python.stat().st_mode & 0o022
    ):
        raise QualificationError(
            "The lifecycle verifier interpreter is outside its root-owned protected prefix."
        )
    wheel = Path(args.wheel).resolve(strict=True)
    if wheel.suffix != ".whl" or not wheel.is_file():
        raise QualificationError("The lifecycle verifier requires the exact built wheel.")
    if wheel.stat().st_size > 500 * 1024 * 1024:
        raise QualificationError("The exact wheel exceeds the fixed inspection size limit.")
    wheel_digest = hashlib.sha256()
    with wheel.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            wheel_digest.update(chunk)
    wheel_hash = wheel_digest.hexdigest()
    with zipfile.ZipFile(wheel) as archive:
        build_info_names = [
            name
            for name in archive.namelist()
            if name == "bluefire/_build_info.json"
            or (".data/" in name and name.endswith("/bluefire/_build_info.json"))
        ]
        if len(build_info_names) != 1:
            raise QualificationError("The exact wheel has no unique committed source identity.")
        build_info = json.loads(archive.read(build_info_names[0]))
    if (
        not re.fullmatch(r"[0-9a-f]{40,64}", args.source_revision)
        or build_info.get("source_provenance") != "git_archive"
        or build_info.get("source_revision") != args.source_revision
    ):
        raise QualificationError(
            "The exact wheel does not match the selected committed source revision."
        )
    supervisor, host, port, bootstrap = _open_supervisor(python)
    session = None
    shutdown = None
    result: dict[str, Any] = {
        "schema_version": "bluefire.macos-file-access-lifecycle-qualification.v1",
        "status": "failed",
    }
    failure = None
    try:
        session = _exchange_bootstrap(host, port, bootstrap)
        status, _ = _json_request(host, port, "GET", API + "/session", session)
        if status != 204:
            raise QualificationError("The issued local browser session did not validate.")

        current = _request(host, port, session, "GET", API + "/file-access/status")
        enrollment = current.get("enrollment")
        if (
            current.get("platform") != "macos"
            or current.get("available") is not True
            or not isinstance(enrollment, dict)
        ):
            raise QualificationError(
                "The original protected setup did not expose an available macOS enrollment."
            )
        imported = _request(
            host,
            port,
            session,
            "POST",
            API + "/file-access/setup-import",
            {
                "enrollment_id": enrollment.get("enrollment_id"),
                "enrollment_digest": enrollment.get("enrollment_digest"),
            },
        )
        control_id = imported.get("control_owner_id")
        if not isinstance(control_id, str) or not re.fullmatch(
            r"file-control-[0-9a-f]{64}", control_id
        ):
            raise QualificationError(
                "The normal setup-import route did not return the original control identity."
            )

        baseline = _submit_file_access(host, port, session, control_id, "baseline")
        control = _request(host, port, session, "GET", API + "/file-access/controls/" + control_id)
        resource = control.get("resource", {})
        baseline_record = control.get("baseline", {})
        if (
            control.get("status") != "baseline_verified"
            or resource.get("mode") != "0640"
            or baseline_record.get("non_owner") != "allowed"
            or baseline_record.get("owner") != "allowed"
            or baseline_record.get("sha256") != resource.get("sha256")
            or baseline_record.get("record_count") != resource.get("record_count")
        ):
            raise QualificationError("The reviewed original baseline did not verify both readers.")
        baseline_sha256 = resource.get("sha256")
        baseline_count = resource.get("record_count")
        harden = _submit_file_access(host, port, session, control_id, "harden")
        control = _request(host, port, session, "GET", API + "/file-access/controls/" + control_id)
        if (
            control.get("status") != "hardened"
            or control.get("resource", {}).get("mode") != "0600"
            or control.get("resource", {}).get("sha256") != baseline_sha256
            or control.get("resource", {}).get("record_count") != baseline_count
            or control.get("usage_state") != "settled"
        ):
            raise QualificationError(
                "The reviewed hardening operation did not settle the exact protected resource."
            )

        review_request = {
            "schema_version": "bluefire.composition-review-request.v2",
            "pack": "bluefire.macos-file-access-pack.v1",
            "control_owner_id": control_id,
            "question": "Verify a fresh non-owner read is denied while the original owner reads the same unchanged generated records.",
            "limits": None,
        }
        review = _request(host, port, session, "POST", API + "/composition/context", review_request)
        if (
            review.get("schema_version") != "bluefire.composition-review.v2"
            or review.get("pack") != review_request["pack"]
            or not isinstance(review.get("review_digest"), str)
        ):
            raise QualificationError(
                "The finite macOS capability review was not returned by the normal API."
            )
        submission_id = str(uuid.uuid4())
        owner_id = "job-" + submission_id.replace("-", "")
        granted = _request(
            host,
            port,
            session,
            "POST",
            API + "/composition/objectives",
            {
                "submission_id": submission_id,
                "review": review_request,
                "review_digest": review["review_digest"],
                "reviewed_by": "Hosted macOS lifecycle qualification",
            },
            accepted=(200, 202),
        )
        if granted.get("owner", {}).get("job_id") != owner_id:
            raise QualificationError(
                "The capability grant did not preserve its submitted identity."
            )
        objective = _poll(
            host,
            port,
            session,
            API + "/composition/objectives/" + owner_id,
            lambda value: value.get("grant") is not None,
        )
        if objective["grant"].get("status") != "active":
            raise QualificationError("The reviewed finite capability grant is not active.")
        context = _request(
            host,
            port,
            session,
            "POST",
            API + "/composition/objectives/" + owner_id + "/proposal-context",
            {"prior_attempt_id": None},
        )
        candidate = context.get("initial_proposal")
        if (
            not isinstance(candidate, dict)
            or candidate.get("schema_version") != "bluefire.composition-proposal.v1"
            or len(candidate.get("steps", [])) != 3
        ):
            raise QualificationError(
                "The original fixed macOS graph was not returned as the established proposal."
            )
        attempt_submission = str(uuid.uuid4())
        attempt_id = "job-" + attempt_submission.replace("-", "")
        attempt = _request(
            host,
            port,
            session,
            "POST",
            API + "/composition/objectives/" + owner_id + "/attempts",
            {"submission_id": attempt_submission, "proposal": candidate, "prior_attempt_id": None},
            accepted=(200, 202),
        )
        submitted = [row for row in attempt.get("attempts", []) if row.get("job_id") == attempt_id]
        if len(submitted) != 1:
            raise QualificationError(
                "The reviewed exact graph attempt was not retained under its submitted identity."
            )
        objective = _poll(
            host,
            port,
            session,
            API + "/composition/objectives/" + owner_id,
            lambda value: any(
                item.get("job_id") == attempt_id
                and item.get("progress", {}).get("settlement") == "settled"
                and isinstance(item.get("progress", {}).get("verified_result"), dict)
                for item in value.get("attempts", [])
            ),
        )
        settled = next(item for item in objective["attempts"] if item.get("job_id") == attempt_id)
        verified = settled["progress"]["verified_result"]
        observation = verified.get("macos_file_access_result", {})
        objective_result = verified.get("objective", {})
        required_checks = {
            "probe_authenticated",
            "non_owner_denied",
            "owner_read_verified",
            "same_resource",
            "same_control_revision",
            "same_original_binding",
            "content_preserved",
            "requests_closed",
            "no_attempt_artifacts",
            "enrollment_retained",
        }
        checks = objective_result.get("checks", {})
        if (
            objective_result.get("established") is not True
            or set(checks) != required_checks
            or not all(value is True for value in checks.values())
        ):
            raise QualificationError(
                "The settled original graph did not satisfy every macOS capability check."
            )
        if (
            observation.get("non_owner_decision") != "denied"
            or observation.get("owner_decision") != "allowed"
            or observation.get("request_closure") != "verified_closed"
            or observation.get("attempt_artifacts") != "not_created"
            or observation.get("workers_retained") is not True
            or observation.get("whole_enrollment_cleanup") is not False
            or observation.get("sha256") != baseline_sha256
            or observation.get("record_count") != baseline_count
        ):
            raise QualificationError(
                "The saved original-producer result did not support its expected denial, owner access, and retained-state claims."
            )
        result.update(
            {
                "status": "passed",
                "run_identity": args.run_identity,
                "wheel_sha256": wheel_hash,
                "source_revision": args.source_revision,
                "protected_prefix": "job-scoped root-owned prefix; retained until hosted runner teardown",
                "runtime": {
                    "python": list(sys.version_info[:3]),
                    "platform": platform.platform(),
                    "machine": platform.machine(),
                },
                "flow": {
                    "normal_session_exchange": True,
                    "normal_setup_import": True,
                    "baseline_reviewed": True,
                    "harden_reviewed": True,
                    "finite_capability_reviewed": True,
                    "fixed_graph_attempt_reviewed": True,
                    "model_requests": 0,
                    "native_builds_during_verification": 0,
                    "resources_created": "only through the original protected setup CLI",
                    "generated_resource_retained": True,
                    "workers_retained_during_attempt": observation.get("workers_retained"),
                    "whole_setup_cleanup_proven": False,
                    "attempt_artifacts": "not_created",
                    "cancellation_recovery": "not exercised",
                },
                "checks": checks,
                "baseline_job_state": baseline.get("job", {}).get("state"),
                "harden_job_state": harden.get("job", {}).get("state"),
                "attempt_settlement": settled["progress"].get("settlement"),
                "resource_sha256": observation.get("sha256"),
                "record_count": observation.get("record_count"),
            }
        )
    except BaseException as exc:
        failure = {"error_type": type(exc).__name__, "message": str(exc)[:500]}
    finally:
        stopped = _stop_supervisor(supervisor)
        result["supervisor_stop"] = {
            key: stopped[key]
            for key in (
                "supervisor_exited",
                "supervisor_returncode",
                "shutdown_method",
                "process_group_signal_sent",
                "process_group_gone",
                "stdout_receipt_obtained",
                "streams_drained",
            )
        }
        if (
            stopped["drained"]
            and stopped["shutdown_method"] == "supervisor_sigterm"
            and stopped["supervisor_returncode"] == 0
            and stopped["stdout"] is not None
        ):
            shutdown = json.loads(stopped["stdout"])
        else:
            failure = failure or {
                "error_type": "SupervisorDrainUnknown",
                "message": "The original supervisor or its owned process group did not complete graceful shutdown and drain.",
            }
    if not isinstance(shutdown, dict):
        result["status"] = "failed"
        result["failure"] = failure or {
            "error_type": "ShutdownReceiptUnavailable",
            "message": "No graceful original-supervisor shutdown receipt was retained.",
        }
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        raise QualificationError("The original setup did not return a graceful shutdown receipt.")
    generated = shutdown.get("generated_resource", {})
    components = shutdown.get("components", {})
    host = shutdown.get("host", {})
    if (
        shutdown.get("status") != "stopped_cleanly"
        or host.get("host_closed") is not True
        or host.get("descriptor_cleanup_unknown") is not False
        or host.get("creation_unknown") is not False
        or components.get("workers_closed") is not True
        or components.get("namespace_handles_closed") is not True
        or shutdown.get("workspace_retained") is not True
        or shutdown.get("identity_accounts_created") is not False
        or generated.get("resource_retained") is not True
        or generated.get("fixture_removed") is not False
        or generated.get("whole_setup_cleanup_proven") is not False
    ):
        failure = failure or {
            "error_type": "ShutdownProjectionMismatch",
            "message": "The original supervisor shutdown result did not truthfully report retained defense and setup scope.",
        }
    result["shutdown"] = {
        "status": shutdown.get("status"),
        "host_closed": host.get("host_closed"),
        "workers_closed": components.get("workers_closed"),
        "namespace_handles_closed": components.get("namespace_handles_closed"),
        "workspace_retained": shutdown.get("workspace_retained"),
        "identity_accounts_created": shutdown.get("identity_accounts_created"),
        "resource_retained": generated.get("resource_retained"),
        "fixture_removed": generated.get("fixture_removed"),
        "whole_setup_cleanup_proven": generated.get("whole_setup_cleanup_proven"),
        "state_at_shutdown": generated.get("state_at_shutdown"),
    }
    if failure:
        result["status"] = "failed"
        result["failure"] = failure
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if failure:
        raise QualificationError(
            "The bounded macOS lifecycle qualification failed; see its sanitized report."
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--run-identity", required=True)
    parser.add_argument("--wheel", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        _run(args)
    except (
        OSError,
        ValueError,
        QualificationError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as exc:
        failure = {
            "schema_version": "bluefire.macos-file-access-lifecycle-qualification.v1",
            "status": "failed",
            "error_type": type(exc).__name__,
            "message": str(exc)[:500],
        }
        if isinstance(exc, QualificationError):
            failure.update(exc.diagnostics)
        try:
            output = Path(args.output)
            if not output.exists():
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    json.dumps(failure, sort_keys=True, indent=2) + "\n", encoding="utf-8"
                )
        except OSError:
            pass
        print(json.dumps(failure), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
