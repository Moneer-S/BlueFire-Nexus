from src.core.bluefire_nexus import BlueFireNexus


def test_mutate_technique_adds_lab_flags():
    nexus = BlueFireNexus()
    base = {"target": "10.0.0.7", "destructive": True}
    mutated = nexus.mutate_technique("exfiltration", base, strategy="evasion-lite")

    assert mutated["module"] == "exfiltration"
    assert mutated["strategy"] == "evasion-lite"
    assert mutated["mutated_params"]["i_understand_this_is_a_lab"] is True
    assert mutated["mutated_params"]["network_touch"] is False
