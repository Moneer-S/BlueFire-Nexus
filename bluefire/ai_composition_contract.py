"""Pure fixed provider schema for bounded capability graph proposals."""

from typing import Any, Mapping

from .capability_resources import METHODS

PURPOSE = "bluefire_composition_proposal"
_NODE = {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,99}$"}


def _object(properties):
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(properties),
        "properties": properties,
    }


_PARAMETERS: tuple[dict[str, Any], ...] = (
    {"record_count": {"type": "integer", "minimum": 1, "maximum": 100}},
    {"redact_values": {"type": "boolean"}},
    {},
    {},
    {"bundle_format": {"type": "string", "enum": ["jsonl"]}},
    {"port": {"type": "integer", "minimum": 1024, "maximum": 65535}},
    {"verify_removal": {"type": "boolean", "enum": [True]}},
)
OUTPUT_SCHEMA: Mapping[str, Any] = _object(
    {
        "schema_version": {"type": "string", "enum": ["bluefire.composition-proposal.v1"]},
        "title": {"type": "string", "minLength": 1, "maxLength": 200},
        "start": _NODE,
        "steps": {
            "type": "array",
            "minItems": 1,
            "maxItems": 64,
            "items": {
                "anyOf": [
                    _object(
                        {
                            "id": _NODE,
                            "behavior_id": {"type": "string", "enum": [method]},
                            "parameters": _object(parameters),
                        }
                    )
                    for method, parameters in zip(METHODS, _PARAMETERS, strict=True)
                ]
            },
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
