from __future__ import annotations

import hashlib
import json
import os
import platform
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from bluefire import strix_linux_fixed_exec as fixed_exec
from bluefire import strix_worker_fixed_bootstrap as fixed_bootstrap
from bluefire import strix_worker_seccomp as seccomp
from bluefire import strix_worker_seccomp_bootstrap as lockdown


def _evaluate(number: int, *, first_argument: int = 0, arch: int = 0xC000003E) -> int:
    data = struct.pack(
        "<iIQQQQQQQ",
        number,
        arch,
        0,
        first_argument,
        0,
        0,
        0,
        0,
        0,
    )
    accumulator = 0
    program = lockdown._POLICY
    pc = 0
    while pc < len(program):
        row = program[pc]
        if row.code == lockdown._BPF_LD_W_ABS:
            accumulator = struct.unpack_from("<I", data, row.value)[0]
            pc += 1
        elif row.code == lockdown._BPF_ALU_AND_K:
            accumulator &= row.value
            pc += 1
        elif row.code == lockdown._BPF_JMP_JEQ_K:
            pc += 1 + (row.jt if accumulator == row.value else row.jf)
        elif row.code == lockdown._BPF_JMP_JSET_K:
            pc += 1 + (row.jt if accumulator & row.value else row.jf)
        elif row.code == lockdown._BPF_RET_K:
            return row.value
        else:  # pragma: no cover - protects the test evaluator from policy expansion
            raise AssertionError(f"unhandled BPF opcode {row.code:#x}")
    raise AssertionError("seccomp program did not return")


def test_policy_has_stable_canonical_identity() -> None:
    assert seccomp.POLICY_SCHEMA == "bluefire.strix-worker-seccomp-policy.v1"
    assert len(seccomp.POLICY_BYTES) == len(lockdown._POLICY) * 8
    assert seccomp.POLICY_DIGEST == (
        "sha256:40524c5404267c5237a70ff0e9c6c916a825e447aa0b6bb4eb39a67d9cb36fc6"
    )
    assert seccomp.POLICY_DIGEST == ("sha256:" + hashlib.sha256(seccomp.POLICY_BYTES).hexdigest())
    assert lockdown.ctypes.sizeof(lockdown._SockFilter) == 8


def test_fixed_bootstrap_binds_exact_lockdown_source_and_policy() -> None:
    source = Path(lockdown.__file__).read_bytes()
    assert b"\r\n" not in source
    assert fixed_bootstrap.LOCKDOWN_SOURCE_DIGEST == (
        "sha256:" + hashlib.sha256(source).hexdigest()
    )
    assert fixed_bootstrap.POLICY_DIGEST == seccomp.POLICY_DIGEST
    assert fixed_bootstrap.RUNTIME_SITE_PACKAGES == "/runtime/lib/python3.12/site-packages"
    assert fixed_bootstrap.CONTROLLED_WORKER_MODULE == (
        "bluefire.strix_controlled_installed_worker"
    )
    assert fixed_bootstrap._REQUIRED_RUNTIME_IMPORTS == (
        "bluefire.strix_controlled_installed_worker",
        "strix",
        "strix.runtime.backends",
        "strix.interface.main",
        "agents",
        "agents.sandbox.session",
        "agents.sandbox.snapshot",
        "agents.sandbox.types",
        "openai",
    )
    attributes = (Path(__file__).parents[1] / ".gitattributes").read_text(encoding="utf-8")
    assert "/bluefire/strix_worker_fixed_bootstrap.py text eol=lf" in attributes
    assert "/bluefire/strix_worker_seccomp_bootstrap.py text eol=lf" in attributes


def test_fixed_bootstrap_validates_sys_before_path_loaded_imports() -> None:
    source = Path(fixed_bootstrap.__file__).read_text(encoding="utf-8")
    sys_import = source.index("import sys")
    startup_check = source.index('if __name__ == "__main__":')
    first_path_import = source.index("import importlib.util")
    assert sys_import < startup_check < first_path_import
    assert "import hashlib" not in source


def test_fixed_bootstrap_reads_only_exact_nonwritable_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "worker_lockdown.py"
    content = b"POLICY_DIGEST = 'test'\n"
    source.write_bytes(content)
    source.chmod(0o444)
    monkeypatch.setattr(fixed_bootstrap, "LOCKDOWN_PATH", os.fspath(source))
    monkeypatch.setattr(
        fixed_bootstrap,
        "LOCKDOWN_SOURCE_DIGEST",
        "sha256:" + hashlib.sha256(content).hexdigest(),
    )
    assert fixed_bootstrap._read_lockdown_source() == content

    source.chmod(0o644)
    with pytest.raises(RuntimeError, match="identity is invalid"):
        fixed_bootstrap._read_lockdown_source()


def test_fixed_bootstrap_rejects_nonclosure_search_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        fixed_bootstrap.sys,
        "path",
        [
            "/runtime/lib/python312.zip",
            "/runtime/lib/python3.12",
            "/runtime/lib/python3.12/lib-dynload",
        ],
    )
    fixed_bootstrap._validate_stdlib_paths()
    fixed_bootstrap.sys.path.append("/usr/lib/python3.12")
    with pytest.raises(RuntimeError, match="not closure-private"):
        fixed_bootstrap._validate_stdlib_paths()


def _isolated_interpreter_state() -> SimpleNamespace:
    return SimpleNamespace(
        executable="/runtime/bin/python",
        prefix="/runtime",
        base_prefix="/runtime",
        exec_prefix="/runtime",
        base_exec_prefix="/runtime",
        dont_write_bytecode=True,
        modules={},
        flags=SimpleNamespace(
            isolated=1,
            ignore_environment=1,
            no_site=1,
            no_user_site=1,
            dont_write_bytecode=1,
            utf8_mode=1,
            safe_path=1,
        ),
    )


def test_fixed_bootstrap_accepts_only_exact_isolated_interpreter() -> None:
    fixed_bootstrap._validate_interpreter(_isolated_interpreter_state())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("executable", "/usr/bin/python3"),
        ("prefix", "/usr"),
        ("base_prefix", "/usr"),
        ("exec_prefix", "/usr"),
        ("base_exec_prefix", "/usr"),
        ("dont_write_bytecode", False),
        ("modules", {"site": object()}),
    ],
)
def test_fixed_bootstrap_rejects_interpreter_identity_drift(field: str, value: object) -> None:
    state = _isolated_interpreter_state()
    setattr(state, field, value)
    with pytest.raises(RuntimeError, match="isolation flags do not match"):
        fixed_bootstrap._validate_interpreter(state)


@pytest.mark.parametrize(
    "flag",
    [
        "isolated",
        "ignore_environment",
        "no_site",
        "no_user_site",
        "dont_write_bytecode",
        "utf8_mode",
        "safe_path",
    ],
)
def test_fixed_bootstrap_rejects_missing_startup_flag(flag: str) -> None:
    state = _isolated_interpreter_state()
    setattr(state.flags, flag, 0)
    with pytest.raises(RuntimeError, match="isolation flags do not match"):
        fixed_bootstrap._validate_interpreter(state)


def _observation_basis() -> dict[str, object]:
    armed = {
        "schema_version": fixed_bootstrap.ARMED_SCHEMA,
        "attempt_id": "attempt-1",
        "plan_ref": "sha256:" + "1" * 64,
        "worker_custody_identity_digest": "sha256:" + "2" * 64,
        "seccomp_profile_digest": fixed_bootstrap.POLICY_DIGEST,
        "no_new_privileges": True,
        "seccomp_mode": 2,
        "tsync": True,
    }
    receipt: dict[str, object] = {
        name: True for name in fixed_bootstrap._QUALIFIED_RECEIPT_BASE_FIELDS
    }
    receipt.update({
        "schema_version": fixed_bootstrap.QUALIFIED_SCHEMA,
        "attempt_id": armed["attempt_id"],
        "plan_ref": armed["plan_ref"],
        "worker_custody_identity_digest": armed["worker_custody_identity_digest"],
        "seccomp_profile_digest": armed["seccomp_profile_digest"],
        "native_observation_ref": "sha256:" + "3" * 64,
        "worker_host_pid": os.getpid(),
        "worker_uid": fixed_bootstrap._effective_uid(),
        "worker_gid": fixed_bootstrap._effective_gid(),
    })
    basis: dict[str, object] = {
        "schema_version": fixed_bootstrap.OBSERVATION_BASIS_SCHEMA,
        "armed_payload": armed,
        "qualified_receipt_base": receipt,
    }
    basis["basis_ref"] = fixed_bootstrap._document_ref(basis)
    return basis


def test_observation_basis_binds_armed_and_qualified_identity() -> None:
    basis = _observation_basis()

    assert fixed_bootstrap._validate_observation_basis(basis) == basis

    substituted = json.loads(json.dumps(basis))
    substituted["qualified_receipt_base"]["worker_host_pid"] = os.getpid() + 1
    substituted["basis_ref"] = fixed_bootstrap._document_ref(
        {name: value for name, value in substituted.items() if name != "basis_ref"}
    )
    with pytest.raises(RuntimeError, match="qualified receipt basis is invalid"):
        fixed_bootstrap._validate_observation_basis(substituted)


def test_observation_receipt_base_matches_controller_exact_contract() -> None:
    assert fixed_bootstrap._QUALIFIED_RECEIPT_BASE_FIELDS == (
        fixed_exec._RECEIPT_FIELDS
        - fixed_bootstrap._POST_ARM_RECEIPT_FIELDS
        - {"receipt_ref"}
    )


def test_observation_envelopes_are_canonical_and_phase_bound() -> None:
    payload = _observation_basis()["armed_payload"]
    assert isinstance(payload, dict)

    encoded = fixed_bootstrap._observation_envelope("armed", payload)
    envelope = json.loads(encoded)

    assert encoded == fixed_bootstrap._canonical_json_bytes(envelope)
    assert envelope == {
        "schema_version": fixed_bootstrap.OBSERVATION_ENVELOPE_SCHEMA,
        "phase": "armed",
        "payload": payload,
        "payload_ref": fixed_bootstrap._document_ref(payload),
    }
    with pytest.raises(RuntimeError, match="phase is invalid"):
        fixed_bootstrap._observation_envelope("ready", payload)


def test_post_arm_process_probes_require_policy_errno(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refused(*_args: object) -> None:
        raise PermissionError(1, "refused")

    monkeypatch.setattr(fixed_bootstrap.os, "execve", refused)
    monkeypatch.setattr(fixed_bootstrap.os, "fork", refused, raising=False)

    fixed_bootstrap._probe_process_refusals()


def test_post_arm_same_process_thread_probe() -> None:
    assert fixed_bootstrap._REQUIRED_CONCURRENT_THREAD_PROBES == 8
    fixed_bootstrap._probe_required_thread()


def test_import_origin_validation_rejects_preloaded_host_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(fixed_bootstrap.os.path, "realpath", lambda path: path)
    runtime = SimpleNamespace(
        __file__="/runtime/lib/python3.12/site-packages/example.py",
        __spec__=SimpleNamespace(origin=None, submodule_search_locations=None),
    )
    fixed_bootstrap._validate_module_origin("runtime.example", runtime)

    host = SimpleNamespace(
        __file__="/usr/lib/python3.12/site-packages/example.py",
        __spec__=SimpleNamespace(origin=None, submodule_search_locations=None),
    )
    with pytest.raises(RuntimeError, match="escaped the private runtime"):
        fixed_bootstrap._validate_module_origin("host.example", host)


def test_complete_observation_sends_armed_then_qualified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    basis = _observation_basis()
    sent: list[tuple[str, dict[str, object]]] = []

    class Channel:
        closed = False

        def close(self) -> None:
            self.closed = True

    channel = Channel()
    monkeypatch.setattr(fixed_bootstrap, "_read_observation_basis", lambda: basis)
    monkeypatch.setattr(fixed_bootstrap, "_open_observation_socket", lambda: channel)
    monkeypatch.setattr(
        fixed_bootstrap,
        "_send_observation",
        lambda _channel, phase, payload: sent.append((phase, payload)),
    )
    monkeypatch.setattr(fixed_bootstrap, "_probe_process_refusals", lambda: None)
    monkeypatch.setattr(fixed_bootstrap, "_probe_required_thread", lambda: None)
    monkeypatch.setattr(fixed_bootstrap, "_probe_runtime_imports", lambda: None)
    installation = SimpleNamespace(
        policy_digest=fixed_bootstrap.POLICY_DIGEST,
        no_new_privileges=True,
        seccomp_mode=2,
        tsync=True,
    )

    fixed_bootstrap._complete_observation(installation)

    assert [phase for phase, _payload in sent] == ["armed", "qualified"]
    qualified = sent[1][1]
    assert qualified["startup_imports_verified"] is True
    assert qualified["required_threads_verified"] is True
    assert qualified["exec_process_probes_refused"] is True
    assert qualified["receipt_ref"] == fixed_bootstrap._document_ref(
        {name: value for name, value in qualified.items() if name != "receipt_ref"}
    )
    assert channel.closed is True


@pytest.mark.skipif(sys.platform != "linux", reason="Linux descriptor and SCM proof")
def test_observation_uses_sealed_basis_and_kernel_credentialed_seqpackets() -> None:
    import fcntl
    import socket

    basis = _observation_basis()
    encoded_basis = fixed_bootstrap._canonical_json_bytes(basis)
    basis_fd = os.memfd_create(
        "bluefire-fixed-exec-basis",
        os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC,
    )
    os.write(basis_fd, encoded_basis)
    os.fchmod(basis_fd, 0o400)
    fcntl.fcntl(basis_fd, fcntl.F_ADD_SEALS, fixed_bootstrap._MEMFD_SEALS)

    assert fixed_bootstrap._read_observation_basis(basis_fd) == basis
    with pytest.raises(OSError):
        os.fstat(basis_fd)

    receiver, sender = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    sender_fd = os.dup(sender.fileno())
    channel = fixed_bootstrap._open_observation_socket(sender_fd)
    payload = basis["armed_payload"]
    assert isinstance(payload, dict)
    fixed_bootstrap._send_observation(channel, "armed", payload)
    data, ancillary, flags, _address = receiver.recvmsg(
        fixed_bootstrap._MAX_OBSERVATION_BYTES,
        socket.CMSG_SPACE(struct.calcsize("3i")),
    )
    credentials = [
        struct.unpack("3i", value[: struct.calcsize("3i")])
        for level, kind, value in ancillary
        if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
    ]
    assert flags == 0
    assert json.loads(data)["phase"] == "armed"
    assert credentials == [(os.getpid(), os.geteuid(), os.getegid())]
    channel.close()
    with pytest.raises(OSError):
        os.fstat(sender_fd)
    receiver.close()
    sender.close()


@pytest.mark.parametrize("number", lockdown._DENIED_SYSCALLS)
def test_policy_refuses_every_explicit_privileged_syscall(number: int) -> None:
    assert _evaluate(number) == lockdown._errno_result(lockdown._LINUX_EPERM)


def test_policy_refuses_x32_aliases_and_wrong_architecture() -> None:
    assert _evaluate(lockdown._X32_SYSCALL_BIT | 1) == lockdown._SECCOMP_RET_KILL_PROCESS
    assert _evaluate(1, arch=0x40000003) == lockdown._SECCOMP_RET_KILL_PROCESS


def test_clone3_reports_unsupported_for_pthread_fallback() -> None:
    assert _evaluate(lockdown._SYS_CLONE3) == lockdown._errno_result(lockdown._LINUX_ENOSYS)


def test_typical_pthread_clone_is_allowed() -> None:
    typical = (
        lockdown._CLONE_REQUIRED
        | 0x00000200  # CLONE_FS
        | 0x00000400  # CLONE_FILES
        | 0x00040000  # CLONE_SYSVSEM
        | 0x00080000  # CLONE_SETTLS
        | 0x00100000  # CLONE_PARENT_SETTID
        | 0x00200000  # CLONE_CHILD_CLEARTID
    )
    assert _evaluate(lockdown._SYS_CLONE, first_argument=typical) == lockdown._SECCOMP_RET_ALLOW


@pytest.mark.parametrize(
    "flags",
    [
        lockdown._CLONE_REQUIRED & ~lockdown._CLONE_VM,
        lockdown._CLONE_REQUIRED & ~lockdown._CLONE_SIGHAND,
        lockdown._CLONE_REQUIRED & ~lockdown._CLONE_THREAD,
        lockdown._CLONE_REQUIRED | 17,
        lockdown._CLONE_REQUIRED | 0x00020000,  # CLONE_NEWNS
        lockdown._CLONE_REQUIRED | 0x40000000,  # CLONE_NEWNET
        lockdown._CLONE_REQUIRED | (1 << 32),
    ],
)
def test_non_thread_or_namespace_clone_is_refused(flags: int) -> None:
    assert _evaluate(lockdown._SYS_CLONE, first_argument=flags) == lockdown._errno_result(
        lockdown._LINUX_EPERM
    )


@pytest.mark.parametrize("number", [0, 1, 2, 3, 41, 42, 202, 257])
def test_ordinary_io_socket_and_thread_support_syscalls_remain_available(number: int) -> None:
    assert _evaluate(number) == lockdown._SECCOMP_RET_ALLOW


def test_digest_mismatch_fails_before_platform_or_kernel_mutation() -> None:
    with pytest.raises(seccomp.StrixWorkerSeccompError, match="identity does not match"):
        seccomp.arm_installed_worker_seccomp(expected_policy_digest="sha256:" + "0" * 64)


@pytest.mark.skipif(
    sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"},
    reason="the real seccomp proof requires Linux x86_64",
)
def test_real_subprocess_allows_threads_and_refuses_process_escape() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "bluefire.strix_worker_seccomp", "--self-test"],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    result = json.loads(completed.stdout)
    assert result["schema_version"] == "bluefire.strix-worker-seccomp-self-test.v1"
    assert result["installation"]["policy_digest"] == seccomp.POLICY_DIGEST
    assert result["thread_allowed"] is True
    assert result["clone3_refused_as_unsupported"] is True
    assert result["process_clone_refused"] is True
    assert result["fork_refused"] is True
    assert result["vfork_refused"] is True
    assert result["exec_refused"] is True
    assert result["namespace_change_refused"] is True
    # Filesystem and network are the native namespace authority's job, and the
    # ordinary subprocess mode deliberately leaves those proof fields unset.
    assert result["filesystem_escape_refused"] is None
    assert result["network_escape_refused"] is None
