"""Resource budget for full normalized-run SQL evaluation, separate from AI context."""

RUN_EXECUTION_LIMITS = {
    "fixtures": 10_000,
    "fixture_bytes": 16 * 1024 * 1024,
    "query_bytes": 32 * 1024,
    "result_rows": 10_000,
    "result_fields": 64,
    "result_bytes": 16 * 1024 * 1024,
    "vm_steps": 5_000_000,
    "deadline_ms": 2_000,
}
