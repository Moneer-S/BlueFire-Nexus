from src.core.models import RunContext
from src.core.safety import SafetyGate, SafetyViolation


def _ctx(dry_run: bool = True):
    return RunContext(
        run_id="safety-test",
        output_dir=__import__("pathlib").Path("output/safety-test"),
        config={},
        dry_run=dry_run,
        max_runtime=60,
        allowed_subnets=["10.0.0.0/24"],
    )


def test_safety_allows_target_in_subnet():
    gate = SafetyGate(_ctx())
    gate.ensure_safe({"target": "10.0.0.5"})


def test_safety_blocks_target_outside_subnet():
    gate = SafetyGate(_ctx())
    try:
        gate.ensure_safe({"target": "8.8.8.8"})
    except SafetyViolation:
        assert True
    else:
        raise AssertionError("expected SafetyViolation")


def test_safety_blocks_destructive_without_ack():
    gate = SafetyGate(_ctx())
    try:
        gate.ensure_safe({"destructive": True, "target": "10.0.0.7"})
    except SafetyViolation:
        assert True
    else:
        raise AssertionError("expected SafetyViolation")
