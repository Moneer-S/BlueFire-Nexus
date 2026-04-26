from pathlib import Path

from src.core.command_control.command_control import CommandControl


def test_command_control_execute_returns_valid_module_result(tmp_path: Path):
    command_control = CommandControl()
    result = command_control.execute(
        {"operation": "proxy_c2", "details": {"target": "127.0.0.1"}},
        {"output_dir": str(tmp_path)},
    )

    assert result.module == "command_control"
    assert result.status in {"success", "partial_success", "error"}
    assert result.techniques == ["T1071.001"]
    assert isinstance(result.artifacts, dict)
    assert "result_path" in result.artifacts
    assert isinstance(result.telemetry, list)
    assert result.telemetry
    assert result.telemetry[0].event_type == "command_control_operation"
