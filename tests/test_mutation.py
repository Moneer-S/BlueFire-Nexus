from src.core.ai.mutation import mutate_step_params
from src.core.bluefire_nexus import BlueFireNexus


def test_mutate_technique_adds_lab_flags():
    nexus = BlueFireNexus()
    base = {"target": "10.0.0.7", "destructive": True}
    mutated = nexus.mutate_technique("exfiltration", base, strategy="evasion-lite")

    assert mutated["module"] == "exfiltration"
    assert mutated["strategy"] == "evasion-lite"
    assert mutated["mutated_params"]["i_understand_this_is_a_lab"] is True
    assert mutated["mutated_params"]["network_touch"] is False


def test_mutate_step_and_technique_share_protocol_shift_behavior():
    step = mutate_step_params(
        {"protocol": "http", "retry_interval": 10},
        allowed=True,
        strategy="protocol_shift",
    )
    assert step.mutated["protocol"] == "dns"
    assert step.mutated["retry_interval"] == 15

    nexus = BlueFireNexus()
    mutated = nexus.mutate_technique(
        "command_control",
        {"protocol": "http", "retry_interval": 10},
        strategy="protocol-shift",
    )
    assert mutated["mutated_params"]["protocol"] == "dns"
    assert mutated["mutated_params"]["retry_interval"] == 15
