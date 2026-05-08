"""Focused tests for the standard `execution` module interpreter detection.

ExecutionModule was historically pinned to bare T1059 regardless of
the command, which left every PowerShell / bash / python /
JavaScript step claiming the parent technique even though every
detection vendor maps interpreter-specific telemetry to the
sub-technique. This module pins:

- recognised interpreters resolve to their specific T1059.X mitre,
- ``.exe`` suffix and Windows-style path prefix are stripped before
  the lookup,
- unrecognised interpreters fall back to the parent T1059,
- the resolved interpreter and mitre surface in artifacts /
  detection_hints / telemetry.details so downstream surfaces
  (manifest, viewer, copilot) see the same value.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from src.core.modules.impl.standard_modules import (
    ExecutionModule,
    _EXECUTION_INTERPRETER_PROFILES,
    _resolve_execution_profile,
)


def _ctx(tmp_path: Path, **overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "run_id": "execution-interp-test",
        "output_dir": tmp_path,
        "config": {},
        "dry_run": True,
        "max_runtime": 60,
        "allowed_subnets": [],
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    "command,expected_mitre,expected_interpreter",
    [
        ("powershell -nop -enc QQ==", "T1059.001", "powershell"),
        ("PowerShell.exe -nop", "T1059.001", "powershell"),
        ("pwsh -Command 'Get-Process'", "T1059.001", "powershell"),
        ("osascript -e 'tell app'", "T1059.002", "applescript"),
        ("cmd /c dir", "T1059.003", "windows_cmd"),
        ("cmd.exe /c whoami", "T1059.003", "windows_cmd"),
        ("bash -lc 'id'", "T1059.004", "unix_shell"),
        ("/bin/sh -c 'echo'", "T1059.004", "unix_shell"),
        ("/usr/bin/zsh", "T1059.004", "unix_shell"),
        ("ksh script.sh", "T1059.004", "unix_shell"),
        ("dash test.sh", "T1059.004", "unix_shell"),
        ("fish -c 'pwd'", "T1059.004", "unix_shell"),
        ("cscript script.vbs", "T1059.005", "vbscript"),
        ("wscript.exe job.js", "T1059.005", "vbscript"),
        ("python script.py", "T1059.006", "python"),
        ("python3 -c 'print()'", "T1059.006", "python"),
        ("py -c 'print()'", "T1059.006", "python"),
        ("/usr/local/bin/python3 -m mod", "T1059.006", "python"),
        ("node app.js", "T1059.007", "javascript"),
        ("deno run app.ts", "T1059.007", "javascript"),
        ("jsc test.js", "T1059.007", "javascript"),
    ],
)
def test_interpreter_resolves_to_specific_subtechnique(
    command: str,
    expected_mitre: str,
    expected_interpreter: str,
    tmp_path: Path,
) -> None:
    mod = ExecutionModule()
    result = mod.execute({"command": command, "target_os": "windows"}, _ctx(tmp_path))
    assert result.techniques == [expected_mitre], command
    assert result.detection_hints["mitre_technique"] == expected_mitre, command
    assert result.detection_hints["interpreter"] == expected_interpreter, command
    assert result.artifacts["mitre_technique"] == expected_mitre, command
    assert result.artifacts["interpreter"] == expected_interpreter, command
    # Telemetry detail snapshot too.
    assert result.telemetry[0].details["mitre_technique"] == expected_mitre, command
    assert result.telemetry[0].details["interpreter"] == expected_interpreter, command


def test_unrecognised_interpreter_falls_back_to_parent_t1059(tmp_path: Path) -> None:
    mod = ExecutionModule()
    result = mod.execute({"command": "echo hello"}, _ctx(tmp_path))
    assert result.techniques == ["T1059"]
    assert result.detection_hints["interpreter"] == "unknown"
    assert result.detection_hints["mitre_technique"] == "T1059"


def test_default_command_resolves_to_parent(tmp_path: Path) -> None:
    """No command param -> default `echo simulated-execution` -> bare T1059.

    `echo` is intentionally NOT in the interpreter catalog (it's a
    builtin in every shell, not a scripting interpreter), so the
    fallback path keeps the bare parent technique.
    """
    mod = ExecutionModule()
    result = mod.execute({}, _ctx(tmp_path))
    assert result.techniques == ["T1059"]
    assert result.detection_hints["interpreter"] == "unknown"


def test_attack_techniques_class_attr_covers_every_interpreter() -> None:
    declared = set(ExecutionModule.attack_techniques)
    expected = {"T1059", *(p["mitre"] for p in _EXECUTION_INTERPRETER_PROFILES.values())}
    assert declared == expected


def test_resolve_execution_profile_handles_empty_command() -> None:
    """Defensive: empty string falls back to parent T1059, not crash."""
    profile = _resolve_execution_profile("")
    assert profile == {"mitre": "T1059", "interpreter": "unknown"}


def test_resolve_execution_profile_strips_exe_suffix() -> None:
    """`POWERSHELL.EXE` and `Powershell.exe` both resolve to T1059.001."""
    assert _resolve_execution_profile("POWERSHELL.EXE -nop")["mitre"] == "T1059.001"
    assert _resolve_execution_profile("Powershell.exe -nop")["mitre"] == "T1059.001"
    assert _resolve_execution_profile("powershell.EXE -nop")["mitre"] == "T1059.001"


def test_resolve_execution_profile_strips_windows_path_prefix() -> None:
    profile = _resolve_execution_profile(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop"
    )
    assert profile["mitre"] == "T1059.001"
    assert profile["interpreter"] == "powershell"


def test_resolve_execution_profile_strips_posix_path_prefix() -> None:
    profile = _resolve_execution_profile("/usr/bin/python3 -c 'print()'")
    assert profile["mitre"] == "T1059.006"
    assert profile["interpreter"] == "python"


def test_quoted_path_with_spaces_resolves_correctly() -> None:
    """Codex P2: quoted Windows path with spaces must not truncate.

    Naive ``str.split`` truncated
    ``"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -c ...`` to
    ``"C:\\Program``, falling back to T1059 / unknown. The fix
    routes the first-token extraction through ``shlex.split`` with
    ``posix=False`` so the quoted token stays intact.
    """
    profile = _resolve_execution_profile(
        '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -c "Get-Process"'
    )
    assert profile["mitre"] == "T1059.001"
    assert profile["interpreter"] == "powershell"


def test_quoted_posix_path_with_spaces_resolves_correctly() -> None:
    """Quoted POSIX path with spaces (e.g., ``/Users/test user/bin``)
    also resolves to the right sub-technique."""
    profile = _resolve_execution_profile('"/Users/test user/bin/python3" script.py')
    assert profile["mitre"] == "T1059.006"
    assert profile["interpreter"] == "python"


def test_single_quoted_path_resolves_correctly() -> None:
    """Single-quoted POSIX path resolves cleanly too."""
    profile = _resolve_execution_profile("'/usr/bin/bash' -lc 'id'")
    assert profile["mitre"] == "T1059.004"
    assert profile["interpreter"] == "unix_shell"


def test_quoted_path_in_full_module_run_records_subtechnique(tmp_path: Path) -> None:
    """Module-level: quoted-path command surfaces the resolved
    sub-technique in artifacts / hints / telemetry, not bare T1059.
    """
    mod = ExecutionModule()
    result = mod.execute(
        {"command": '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -c "Get-Process"'},
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1059.001"]
    assert result.detection_hints["mitre_technique"] == "T1059.001"
    assert result.detection_hints["interpreter"] == "powershell"
    assert result.artifacts["mitre_technique"] == "T1059.001"


def test_unbalanced_quote_falls_back_to_whitespace_split() -> None:
    """``shlex.split`` raises ``ValueError`` on unbalanced quotes.

    The fallback path uses whitespace split, which preserves the
    historic behaviour of getting the first whitespace-delimited
    token. Recognised interpreter names without surrounding quotes
    still resolve correctly even when the rest of the command is
    malformed.
    """
    profile = _resolve_execution_profile('powershell "unmatched-quote -c x')
    assert profile["mitre"] == "T1059.001"
    assert profile["interpreter"] == "powershell"


def test_failure_path_carries_resolved_mitre(tmp_path: Path) -> None:
    """When subprocess.run raises, the failure record reflects the
    resolved sub-technique (was historically pinned to T1059)."""

    class _AlwaysRaisesProc:
        def __init__(self, *_args, **_kwargs) -> None:
            raise RuntimeError("simulated subprocess failure")

    import src.core.modules.impl.standard_modules as standard_modules

    real_run = standard_modules.subprocess.run
    standard_modules.subprocess.run = lambda *a, **kw: _AlwaysRaisesProc()
    try:
        mod = ExecutionModule()
        mod.update_config({"allow_real_execution": True})
        result = mod.execute(
            {"command": "powershell -nop"},
            _ctx(tmp_path, dry_run=False),
        )
    finally:
        standard_modules.subprocess.run = real_run
    assert result.status == "failure"
    assert result.techniques == ["T1059.001"]
