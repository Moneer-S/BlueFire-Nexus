"""Fixed retained-file recipe compilation and typed original-input bindings."""

from .capability_packs import FILE_ACCESS_METHODS
from .config import AutonomyLevel
from .contracts import ExecutionMode, ScenarioDefinition
from .domain_errors import ProductStoreError
from .planner import ExecutionPlan
from .util import content_hash


def recipe(operation, control=None):
    rows = {
        "create": [
            ("seed", "sandbox.fixture.create.v1", {"record_count": 8}, "retained"),
            ("transform", "sandbox.fixture.transform.v1", {"redact_values": False}, "retained"),
            ("clean_seed", "sandbox.cleanup.v1", {"verify_removal": True}, "retained"),
            ("mode", "sandbox.permission.chmod.v1", {"mode": "0640"}, "retained"),
        ],
        "baseline": [],
        "harden": [("mode", "sandbox.permission.chmod.v1", {"mode": "0600"}, "retained")],
        "rollback": [("mode", "sandbox.permission.chmod.v1", {"mode": "0640"}, "retained")],
        "reset": [("reset", "sandbox.cleanup.v1", {"verify_removal": True}, "retained")],
    }
    if operation not in rows:
        raise ProductStoreError("The retained file operation is unsupported.")
    selected = list(rows[operation])
    if operation == "reset" and control is not None and control["status"] == "recovery_required":
        selected = [
            (
                "reset_" + row["workspace"],
                "sandbox.cleanup.v1",
                {"verify_removal": True},
                row["workspace"],
            )
            for row in control["source"]["recovery"]
        ]
    if operation in ("baseline", "rollback"):
        selected += [
            ("probe", FILE_ACCESS_METHODS[0], {}, "observation"),
            ("owner", FILE_ACCESS_METHODS[1], {}, "observation"),
            ("clean_observations", "sandbox.cleanup.v1", {"verify_removal": True}, "observation"),
        ]
    return [
        {
            "step_id": step,
            "action_id": action,
            "behavior_id": (
                "sandbox.permission.relax.v1" if action == "sandbox.permission.chmod.v1" else action
            ),
            "parameters": parameters,
            "workspace": workspace,
        }
        for step, action, parameters, workspace in selected
    ]


def plan_step(document):
    from .contracts import SafetyTier
    from .planner import PlanStep

    return PlanStep(
        **{
            **document,
            "safety_tier": SafetyTier(document["safety_tier"]),
            "expected_outputs": tuple(document["expected_outputs"]),
            "required_capabilities": tuple(document["required_capabilities"]),
            "alternates": tuple(document["alternates"]),
        }
    )


def _plan(engine, current, operation):
    rows = recipe(
        operation, None if current.get("control") is None else current["control"]["document"]
    )
    scenario = ScenarioDefinition.from_mapping(
        {
            "schema_version": "bluefire.scenario.v1",
            "id": "scenario.file-access-control-" + operation + ".v1",
            "title": "Reviewed retained file " + operation,
            "purpose": "Exact retained-resource operation; inputs bind previous owned control artifacts.",
            "start": rows[0]["step_id"],
            "steps": [
                {
                    "id": row["step_id"],
                    "behavior_id": row["behavior_id"],
                    "parameters": row["parameters"],
                    "inputs": {},
                }
                for row in rows
            ],
            "edges": [],
            "provenance": {
                "source": "BlueFire fixed retained-resource control",
                "reference": operation,
                "license": "MIT",
                "derived": False,
                "notes": "Not a self-contained model graph; retained inputs are independently bound in the approval state.",
            },
        }
    )
    steps = []
    for step, row in zip(scenario.steps, rows, strict=True):
        current["registry"].get_behavior(step.behavior_id).validate_parameters(step.parameters)
        steps.append(
            engine.planner._compile_step(
                step,
                behavior_id=step.behavior_id,
                mode=ExecutionMode.EXECUTE,
                profile=current["profile"],
                action_id=row["action_id"],
            )
        )
    plan = ExecutionPlan(
        "bluefire.execution-plan.v1",
        scenario.id,
        scenario.purpose,
        ExecutionMode.EXECUTE,
        AutonomyLevel.OFF,
        {},
        current["profile"].id,
        content_hash(scenario.to_dict()),
        tuple(steps),
        (),
    )
    return scenario, plan


def _inputs(step_id, outputs, source):
    if step_id == "transform":
        return {"workspace": outputs["seed"]["workspace"]}
    if step_id == "clean_seed":
        return {"workspace": outputs["seed"]["workspace"]}
    if step_id == "mode":
        return {
            "fixture": (
                outputs["transform"]["fixture"] if "transform" in outputs else source["fixture"]
            )
        }
    if step_id == "owner":
        return {"probe": outputs["probe"]["probe"]}
    if step_id == "clean_observations":
        return {"workspace": outputs["probe"]["workspace"]}
    return {}


def _receipts(step_id, outputs, source):
    if step_id.startswith("reset_") and source is not None and "recovery" in source:
        return list(
            next(
                row["snapshot"]["documents"]
                for row in source["recovery"]
                if step_id == "reset_" + row["workspace"]
            )
        )
    if step_id == "clean_seed":
        return list(outputs["seed"]["workspace"]["receipt_ids"])
    if step_id in ("mode", "reset"):
        return list(
            outputs["transform"]["fixture"]["receipt_ids"]
            if "transform" in outputs
            else source["fixture"]["receipt_ids"]
        )
    if step_id == "clean_observations":
        return [
            *outputs["probe"]["probe"]["receipt_ids"],
            *outputs["owner"]["verification"]["receipt_ids"],
        ]
    return []
