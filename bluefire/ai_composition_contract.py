"""Pure fixed provider schemas for bounded capability graph proposals."""

from typing import Any, Mapping

from .capability_packs import (
    FILE_ACCESS_METHODS,
    FILE_ACCESS_PACK,
    MACOS_FILE_ACCESS_METHODS,
    MACOS_FILE_ACCESS_PACK,
    RECEIVER_PACK,
)
from .capability_resources import METHODS, CapabilityContractError, semantic_ports

PURPOSE = "bluefire_composition_proposal"
# Distinct purposes keep an existing receiver-only usage grant from widening to either file pack.
FILE_ACCESS_PURPOSE = "bluefire_linux_file_access_composition_proposal"
MACOS_FILE_ACCESS_PURPOSE = "bluefire_macos_file_access_composition_proposal"
_NODE = {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,99}$"}


def _object(properties: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


_RECEIVER_PARAMETERS: tuple[dict[str, Any], ...] = (
    {"record_count": {"type": "integer", "minimum": 1, "maximum": 100}},
    {"redact_values": {"type": "boolean"}},
    {},
    {},
    {"bundle_format": {"type": "string", "enum": ["jsonl"]}},
    {"port": {"type": "integer", "minimum": 1024, "maximum": 65535}},
    {"verify_removal": {"type": "boolean", "enum": [True]}},
)
_FILE_ACCESS_PARAMETERS: tuple[dict[str, Any], ...] = (
    {},
    {},
    {"verify_removal": {"type": "boolean", "enum": [True]}},
)
_MACOS_FILE_ACCESS_PARAMETERS: tuple[dict[str, Any], ...] = ({}, {}, {})


def _input_ref(input_port, methods, pack):
    compatible = {
        output[0]
        for method in methods
        for output in semantic_ports(method, pack=pack)[1]
        if output[1:] == input_port[1:3]
    }
    return _object({"from_step": _NODE, "artifact": {"type": "string", "enum": sorted(compatible)}})


def _step_schemas(methods, parameters_by_method, pack):
    for method, parameters in zip(methods, parameters_by_method, strict=True):
        fields = {
            "id": _NODE,
            "behavior_id": {"type": "string", "enum": [method]},
            "parameters": _object(parameters),
        }
        yield _object(fields)
        ports = {
            item[0]: _input_ref(item, methods, pack)
            for item in semantic_ports(method, pack=pack)[0]
        }
        yield _object({**fields, "inputs": _object(ports)})


def _output_schema(methods, parameters_by_method, pack) -> Mapping[str, Any]:
    return _object(
        {
            "schema_version": {
                "type": "string",
                "enum": ["bluefire.composition-proposal.v1"],
            },
            "title": {"type": "string", "minLength": 1, "maxLength": 200},
            "start": _NODE,
            "steps": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "items": {"anyOf": list(_step_schemas(methods, parameters_by_method, pack))},
            },
            "edges": {
                "type": "array",
                "maxItems": 256,
                "items": _object(
                    {
                        "from_step": _NODE,
                        "outcome": {
                            "type": "string",
                            "enum": ["success", "partial", "blocked", "failed"],
                        },
                        "to_step": _NODE,
                    }
                ),
            },
            "evidence_refs": {
                "type": "array",
                "minItems": 1,
                "maxItems": 64,
                "items": {"type": "string", "minLength": 1, "maxLength": 200},
            },
            "rationale": {"type": "string", "minLength": 1, "maxLength": 2000},
        }
    )


OUTPUT_SCHEMA: Mapping[str, Any] = _output_schema(METHODS, _RECEIVER_PARAMETERS, RECEIVER_PACK)
FILE_ACCESS_OUTPUT_SCHEMA: Mapping[str, Any] = _output_schema(
    FILE_ACCESS_METHODS, _FILE_ACCESS_PARAMETERS, FILE_ACCESS_PACK
)
MACOS_FILE_ACCESS_OUTPUT_SCHEMA: Mapping[str, Any] = _output_schema(
    MACOS_FILE_ACCESS_METHODS, _MACOS_FILE_ACCESS_PARAMETERS, MACOS_FILE_ACCESS_PACK
)

_PACK_CONTRACTS = {
    RECEIVER_PACK: (PURPOSE, OUTPUT_SCHEMA),
    FILE_ACCESS_PACK: (FILE_ACCESS_PURPOSE, FILE_ACCESS_OUTPUT_SCHEMA),
    MACOS_FILE_ACCESS_PACK: (MACOS_FILE_ACCESS_PURPOSE, MACOS_FILE_ACCESS_OUTPUT_SCHEMA),
}


def proposal_contract(pack: str) -> tuple[str, Mapping[str, Any]]:
    """Return one of the three reviewed pack contracts, never a dynamic registry schema."""
    try:
        return _PACK_CONTRACTS[pack]
    except (KeyError, TypeError):
        raise CapabilityContractError(
            "composition context selected an unsupported capability pack"
        ) from None
