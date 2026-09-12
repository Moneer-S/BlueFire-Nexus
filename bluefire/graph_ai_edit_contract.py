"""Fixed graph-step model output schema shared by authoring and consent enforcement."""

from typing import Any

OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["parameters", "rationale", "assumptions"],
    "properties": {
        "parameters": {
            "type": "array",
            "minItems": 1,
            "maxItems": 32,
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["name", "value"],
                "properties": {
                    "name": {"type": "string", "maxLength": 100},
                    "value": {
                        "anyOf": [
                            {"type": "string", "maxLength": 1000},
                            {"type": "number"},
                            {"type": "boolean"},
                        ]
                    },
                },
            },
        },
        "rationale": {"type": "string", "minLength": 1, "maxLength": 4000},
        "assumptions": {
            "type": "array",
            "maxItems": 8,
            "items": {"type": "string", "minLength": 1, "maxLength": 500},
        },
    },
}
