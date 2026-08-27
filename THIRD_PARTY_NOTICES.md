# Third-party notices and source intake

BlueFire Nexus records third-party source provenance before any public content is imported, adapted, or integrated through an external adapter. A source record is not proof that remote bytes were fetched, vendored, redistributed, or executed.

Current built-in records are stored in `bluefire/data/research_sources.yaml` and exposed through Research Sources:

| Source | Classification | Content handling | Notice |
|---|---|---|---|
| MITRE ATT&CK Enterprise STIX data | `metadata_import` | External reference only; selected behavior metadata carries attribution | ATT&CK and MITRE marks are used for attribution and do not imply endorsement. |
| Sigma specification | `reference_only` | Metadata only | Used as a format/semantics reference. |
| pySigma | `external_adapter` | Separately installed optional package; no source vendored | Used only through bounded parser-validation integration when available. |
| yara-python | `external_adapter` | Separately installed optional package; no source vendored | Used only through bounded compiler integration when available. |
| Atomic Red Team | `reference_only` | Metadata only | Used as a comparative behavior/test-structure reference; external tests are not copied or executed. |

Before any `compatible_code_adaptation`, perform file-level license review, preserve attribution and notices, isolate copied code paths, and record modifications in the source metadata.
