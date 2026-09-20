# Native tool installation identity

The native-tool setup foundation separates an approved installation identity
from an operation's logical parameters. Records persist in existing runner
profiles and are bound to operator approval. A dedicated setup UI, inspected
runner inventory and external-tool execution dispatch remain unimplemented.
No method becomes ready by parsing a record or completing this inspection.

`bluefire.native_tool_installations.NativeToolInstallation` validates an exact
`bluefire.native-tool-installation.v1` record containing:

- the reviewed adapter ID, version and contract digest;
- the tool ID and approved version assertion;
- Linux platform and supported architecture;
- expected executable size and SHA-256 digest;
- a canonical absolute installation location chosen during trusted setup.

The parser rejects invocation arguments, environment settings, URLs and unknown
fields. Its detached record has a canonical digest. `check_binding()` compares
the record to the compiled adapter identity; parsing or matching alone does not
establish who approved that record. Installation locations belong to trusted
setup and must never become run parameters or model-selected executable paths.

`bluefire.native_tool_inspection.inspect_native_tool()` performs read-only Linux
inspection. It walks from a held root directory descriptor without following
symlinks, requires protected root-owned directories and an executable regular
file, refuses special permission bits and file capabilities, and checks native
ELF architecture. It hashes bounded bytes from the held file descriptor, compares
the expected digest and size, and rechecks metadata and directory bindings.
Cancellation and a five-second budget are checked between filesystem calls;
they cannot interrupt a blocked kernel filesystem call.

The inspector does not execute the tool, query `--version`, search PATH, install
dependencies or modify the file. The version is a setup assertion bound to its
approved digest, not a claim derived from untrusted version output. A successful
inspection is a point-in-time identity check, not authority for a future run.
Dispatch must recheck the sealed installation binding and the opened executable
before effects; legacy exact-plan approvals must not gain tool authority.

Runner profiles can now carry a finite `native_tool_installations` list. Its
contents are included in the saved profile, operator approval state, adaptive
authorization, policy digest and approved manifest hash. Changing the location,
version or content identity invalidates the previous approval. An absent or
empty list preserves the legacy profile digest. Dispatch derives records only
from that reviewed profile and projects them to the actual platform and final
reviewed actions; cleanup does not inherit unrelated installations. The Rust
runner refuses records unless their adapter identity matches an explicitly
registered method's compiled tool binding. Existing methods declare no such
binding, so adding setup records cannot grant them external-tool authority.
For this first schema, adapter IDs identify compiled action IDs. No method is
currently admitted by this new boundary. Service preflight refuses unsupported
setup before issuing an approval, and its runner probe reports degraded readiness.
The eventual setup inventory must inspect the actual execution environment
before a compiled tool adapter can become ready.

The runner also provides read-only pinning for a single file named by a committed
creation receipt. It validates both receipt and commit identity using bounded,
no-follow reads, checks the expected content and size, requires current-user
ownership and a single hard link, and retains the opened file for later checks.
It detects changed content or path attachment. On Unix, hashing uses positioned
reads so neither initial pinning nor a recheck changes the consumer's read offset.
A metadata-only operation may
retain the original creation receipt for deletion during cleanup. This helper
does not itself execute a tool, change permissions or authorize a target path.

Current tests use explicit filesystem models for replacement, permissions,
capabilities, cancellation, deadlines and read failures. They are software tests,
not evidence of an external security method executing or a target defense firing.
