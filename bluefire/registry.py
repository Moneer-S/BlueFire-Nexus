"""Explicit behavior/action registry with no dynamic imports or entry points."""

from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Mapping, Protocol, TypeVar

from .contracts import (
    ActionDefinition,
    BehaviorDefinition,
    ContractError,
    ScenarioDefinition,
    _load_yaml_mapping,
)

if TYPE_CHECKING:
    from .config import RunnerProfile


class RegistryError(ContractError):
    """Raised when a catalog or scenario cannot be registered safely."""


class _Identified(Protocol):
    @property
    def id(self) -> str: ...


_RegistryItem = TypeVar("_RegistryItem", bound=_Identified)


class BehaviorRegistry:
    """Immutable-by-convention registry of declarative behaviors and actions."""

    def __init__(
        self,
        behaviors: Iterable[BehaviorDefinition],
        actions: Iterable[ActionDefinition],
    ) -> None:
        self._behaviors = self._index(behaviors, "behavior")
        self._actions = self._index(actions, "action")
        self._validate_references()

    @staticmethod
    def _index(
        items: Iterable[_RegistryItem],
        kind: str,
    ) -> dict[str, _RegistryItem]:
        indexed: dict[str, _RegistryItem] = {}
        for item in items:
            if item.id in indexed:
                raise RegistryError(f"duplicate {kind} ID: {item.id}")
            indexed[item.id] = item
        return indexed

    @classmethod
    def from_catalog(cls, catalog_dir: str | Path) -> "BehaviorRegistry":
        """Load the two versioned built-in catalog documents from a directory."""

        root = Path(catalog_dir)
        behavior_doc = _load_catalog_document(
            root / "behaviors.yaml", "bluefire.behavior-catalog.v1", "behavior catalog"
        )
        action_doc = _load_catalog_document(
            root / "actions.yaml", "bluefire.action-catalog.v1", "action catalog"
        )
        behaviors = [
            BehaviorDefinition.from_mapping(item, f"behavior catalog.items[{index}]")
            for index, item in enumerate(behavior_doc["items"])
        ]
        actions = [
            ActionDefinition.from_mapping(item, f"action catalog.items[{index}]")
            for index, item in enumerate(action_doc["items"])
        ]
        return cls(behaviors, actions)

    @property
    def behavior_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._behaviors))

    @property
    def behaviors(self) -> tuple[BehaviorDefinition, ...]:
        """Return the exact immutable-by-convention behavior snapshot."""

        return tuple(self._behaviors[item_id] for item_id in sorted(self._behaviors))

    @property
    def action_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._actions))

    @property
    def actions(self) -> tuple[ActionDefinition, ...]:
        """Return the exact immutable-by-convention action snapshot."""

        return tuple(self._actions[item_id] for item_id in sorted(self._actions))

    def extended(
        self,
        *,
        behaviors: Iterable[BehaviorDefinition] = (),
        actions: Iterable[ActionDefinition] = (),
    ) -> "BehaviorRegistry":
        """Create one new registry snapshot without mutating this registry."""

        return BehaviorRegistry(
            (*self.behaviors, *tuple(behaviors)),
            (*self.actions, *tuple(actions)),
        )

    def get_behavior(self, behavior_id: str) -> BehaviorDefinition:
        try:
            return self._behaviors[behavior_id]
        except KeyError as exc:
            raise RegistryError(f"unknown behavior ID: {behavior_id}") from exc

    def get_action(self, action_id: str) -> ActionDefinition:
        try:
            return self._actions[action_id]
        except KeyError as exc:
            raise RegistryError(f"unknown action ID: {action_id}") from exc

    def compatible_behaviors(self, behavior_id: str) -> tuple[str, ...]:
        """Return behavior IDs with identical typed I/O and parameter contracts."""

        target = self.get_behavior(behavior_id)
        signature = target.io_signature()
        return tuple(
            sorted(
                candidate.id
                for candidate in self._behaviors.values()
                if candidate.id != behavior_id and candidate.io_signature() == signature
            )
        )

    def _validate_references(self) -> None:
        for action in self._actions.values():
            if action.cleanup_action_id and action.cleanup_action_id not in self._actions:
                raise RegistryError(
                    f"action {action.id} references unknown cleanup action {action.cleanup_action_id}"
                )
            if action.cleanup_action_id == action.id:
                raise RegistryError(f"action {action.id} cannot clean itself up")

        for behavior in self._behaviors.values():
            for action_id in behavior.action_ids:
                action = self.get_action(action_id)
                missing_capabilities = set(action.capabilities) - set(behavior.capabilities)
                if missing_capabilities:
                    raise RegistryError(
                        f"behavior {behavior.id} does not declare action capabilities: "
                        f"{', '.join(sorted(missing_capabilities))}"
                    )
                if action.safety_tier is not behavior.safety_tier:
                    raise RegistryError(
                        f"action {action.id} safety tier differs from {behavior.id}"
                    )
                if not set(action.platforms).issubset(set(behavior.platforms)):
                    raise RegistryError(
                        f"action {action.id} platforms exceed behavior {behavior.id} platforms"
                    )
                if _artifact_signature(action.inputs) != _artifact_signature(behavior.inputs):
                    raise RegistryError(
                        f"action {action.id} input contract differs from {behavior.id}"
                    )
                if _artifact_signature(action.outputs) != _artifact_signature(behavior.outputs):
                    raise RegistryError(
                        f"action {action.id} output contract differs from {behavior.id}"
                    )
                if _parameter_signature(action.parameters) != _parameter_signature(
                    behavior.parameters
                ):
                    raise RegistryError(
                        f"action {action.id} parameter contract differs from {behavior.id}"
                    )

    def validate_scenario(self, scenario: ScenarioDefinition) -> None:
        """Validate registry references, typed propagation, graph shape and reachability."""

        steps = {step.id: step for step in scenario.steps}
        if scenario.start not in steps:
            raise RegistryError(f"scenario start step does not exist: {scenario.start}")

        behaviors: dict[str, BehaviorDefinition] = {}
        for step in scenario.steps:
            behavior = self.get_behavior(step.behavior_id)
            behaviors[step.id] = behavior
            behavior.validate_parameters(step.parameters, f"step {step.id}.parameters")
            for alternate_id in step.alternates:
                alternate = self.get_behavior(alternate_id)
                if alternate.io_signature() != behavior.io_signature():
                    raise RegistryError(
                        f"step {step.id} alternate {alternate_id} is not contract-compatible"
                    )
                alternate.validate_parameters(
                    step.parameters, f"step {step.id} alternate {alternate_id}.parameters"
                )

        successors: dict[str, set[str]] = defaultdict(set)
        predecessors: dict[str, set[str]] = defaultdict(set)
        for edge in scenario.edges:
            if edge.from_step not in steps:
                raise RegistryError(f"edge references unknown source step: {edge.from_step}")
            if edge.to_step not in steps:
                raise RegistryError(f"edge references unknown destination step: {edge.to_step}")
            successors[edge.from_step].add(edge.to_step)
            predecessors[edge.to_step].add(edge.from_step)

        if predecessors[scenario.start]:
            raise RegistryError("scenario start step cannot have incoming edges")
        order = _topological_order(tuple(steps), successors, predecessors)
        reachable = _reachable_from(scenario.start, successors)
        unreachable = set(steps) - reachable
        if unreachable:
            raise RegistryError(
                f"scenario contains unreachable steps: {', '.join(sorted(unreachable))}"
            )

        dominators = _dominators(order, scenario.start, predecessors)
        for step in scenario.steps:
            behavior = behaviors[step.id]
            input_specs = {spec.name: spec for spec in behavior.inputs}
            unknown_ports = set(step.inputs) - set(input_specs)
            if unknown_ports:
                raise RegistryError(
                    f"step {step.id} binds unknown input ports: {', '.join(sorted(unknown_ports))}"
                )
            missing_ports = {
                spec.name
                for spec in behavior.inputs
                if spec.required and spec.name not in step.inputs
            }
            if missing_ports:
                raise RegistryError(
                    f"step {step.id} is missing input bindings: {', '.join(sorted(missing_ports))}"
                )
            for port, binding in step.inputs.items():
                if binding.from_step not in steps:
                    raise RegistryError(
                        f"step {step.id} input {port} references unknown step {binding.from_step}"
                    )
                if binding.from_step not in dominators[step.id]:
                    raise RegistryError(
                        f"step {step.id} input {port} is not guaranteed by all incoming paths"
                    )
                source_outputs = {spec.name: spec for spec in behaviors[binding.from_step].outputs}
                if binding.artifact not in source_outputs:
                    raise RegistryError(
                        f"step {step.id} input {port} references unknown artifact "
                        f"{binding.from_step}.{binding.artifact}"
                    )
                source_spec = source_outputs[binding.artifact]
                target_spec = input_specs[port]
                if (source_spec.type, source_spec.multiple) != (
                    target_spec.type,
                    target_spec.multiple,
                ):
                    raise RegistryError(
                        f"step {step.id} input {port} type does not match "
                        f"{binding.from_step}.{binding.artifact}"
                    )

    def validate_runner_profile(self, profile: "RunnerProfile") -> None:
        """Validate a profile's action IDs, capabilities, tiers and platforms."""

        for action_id in (*profile.enabled_actions, *profile.blocked_actions):
            self.get_action(action_id)
        for action_id in profile.enabled_actions:
            action = self.get_action(action_id)
            missing_capabilities = set(action.capabilities) - set(profile.capabilities)
            if missing_capabilities:
                raise RegistryError(
                    f"profile {profile.id} lacks action capabilities: "
                    f"{', '.join(sorted(missing_capabilities))}"
                )
            if action.safety_tier not in profile.safety_tiers:
                raise RegistryError(
                    f"profile {profile.id} does not permit {action.safety_tier.value} actions"
                )
            if not set(action.platforms).intersection(profile.platforms):
                raise RegistryError(f"profile {profile.id} has no platform for action {action.id}")
            if "network.loopback" in action.capabilities:
                if "network.loopback" not in profile.scope:
                    raise RegistryError(f"profile {profile.id} lacks loopback network scope")
                if not any(_is_loopback(network) for network in profile.network_allowlist):
                    raise RegistryError(f"profile {profile.id} lacks a loopback network allowance")


def _load_catalog_document(path: Path, version: str, context: str) -> Mapping[str, Any]:
    document = _load_yaml_mapping(path, context)
    unknown = set(document) - {"schema_version", "items"}
    missing = {"schema_version", "items"} - set(document)
    if unknown:
        raise RegistryError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")
    if missing:
        raise RegistryError(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if document["schema_version"] != version:
        raise RegistryError(f"{context}.schema_version must be {version}")
    if not isinstance(document["items"], list):
        raise RegistryError(f"{context}.items must be a list")
    return document


def _artifact_signature(specs: Iterable[Any]) -> tuple[Any, ...]:
    return tuple(spec.signature() for spec in specs)


def _parameter_signature(specs: Iterable[Any]) -> tuple[Any, ...]:
    return tuple(spec.signature() for spec in specs)


def _is_loopback(network: str) -> bool:
    import ipaddress

    return ipaddress.ip_network(network).is_loopback


def _topological_order(
    step_ids: tuple[str, ...],
    successors: Mapping[str, set[str]],
    predecessors: Mapping[str, set[str]],
) -> tuple[str, ...]:
    indegree = {step_id: len(predecessors[step_id]) for step_id in step_ids}
    queue = deque(sorted(step_id for step_id, count in indegree.items() if count == 0))
    result: list[str] = []
    while queue:
        step_id = queue.popleft()
        result.append(step_id)
        for successor in sorted(successors[step_id]):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                queue.append(successor)
    if len(result) != len(step_ids):
        raise RegistryError("scenario graph contains a cycle")
    return tuple(result)


def _reachable_from(start: str, successors: Mapping[str, set[str]]) -> set[str]:
    result: set[str] = set()
    pending = [start]
    while pending:
        step_id = pending.pop()
        if step_id in result:
            continue
        result.add(step_id)
        pending.extend(successors[step_id])
    return result


def _dominators(
    order: tuple[str, ...], start: str, predecessors: Mapping[str, set[str]]
) -> dict[str, set[str]]:
    dominators: dict[str, set[str]] = {start: {start}}
    for step_id in order:
        if step_id == start:
            continue
        parents = predecessors[step_id]
        common = set.intersection(*(dominators[parent] for parent in parents))
        dominators[step_id] = common | {step_id}
    return dominators


def load_builtin_registry() -> BehaviorRegistry:
    return BehaviorRegistry.from_catalog(Path(__file__).with_name("catalog"))


__all__ = ["BehaviorRegistry", "RegistryError", "load_builtin_registry"]
