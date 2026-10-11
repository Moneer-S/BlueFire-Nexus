# Native tool installation identity

Native-tool setup separates a reviewed installation identity from an operation's
logical parameters. Records persist in runner profiles and are bound to operator
approval. The workspace supports inspection and saved bindings for the compiled
Linux GNU chmod and GNU gzip adapters. Authenticated runner inventory, protected
installation inspection and dispatch-time checks are implemented. Parsing a record
alone does not establish readiness, and a successful inspection does not authorize
execution or prove a defensive outcome.

## Workspace Setup

1. Connect an authenticated Linux runner through **Runners** using an active
   Execute profile. Tool inspection does not start a replacement runner.
2. In **Runner profiles**, use an inactive saved Execute profile with the desired
   method enabled. **Configure methods** saves a draft with the same profile ID.
   Deactivate an active profile before changing its tool binding.
3. Choose **Set up GNU chmod** or **Set up GNU gzip**. Enter the protected
   installation location and one of the exact package versions offered by the
   dialog, then choose **Inspect installation**. Both the package assertion and
   executable fingerprint must match the reviewed Linux amd64 build list.
4. **Save tool binding** retains a successful inspection in the draft profile.
   **Validate & activate** is a separate action. A run still needs its current
   scope, readiness checks and approval.

Changing the location, version, profile or selected tool invalidates the displayed
inspection. Unknown builds remain unavailable until a reviewed product update;
the dialog does not install packages, execute `--version`, or accept an arbitrary
binary based only on its declared name. Supported package fingerprints live in
the compiled reviewed-build tables, not in operator-entered run parameters.

## Installation Record

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
reviewed digest, not a claim derived from untrusted version output. A successful
inspection is a point-in-time identity check, not authority for a future run.
Dispatch rechecks the sealed installation binding and the opened executable
before effects; legacy exact-plan approvals must not gain tool authority.

Runner profiles can now carry a finite `native_tool_installations` list. Its
contents are included in the saved profile, operator approval state, adaptive
authorization, policy digest and approved manifest hash. Changing the location,
version or content identity invalidates the previous approval. An absent or
empty list preserves the legacy profile digest. Dispatch derives records only
from that reviewed profile and projects them to the actual platform and final
reviewed actions; cleanup does not inherit unrelated installations. The Rust
runner refuses records unless their adapter identity matches an explicitly
registered method's compiled tool binding. The supported bindings are
`sandbox.permission.chmod.v1` and `sandbox.collection.atomic-gzip.v1`; unrelated
methods cannot acquire external-tool authority by adding a record. Adapter IDs
identify compiled action IDs. Setup verifies the compiled descriptor and inspects
the actual execution environment, checking inventory and authenticated transport
identity before and after inspection. Readiness remains unavailable when a
required binding is absent, unsupported, changed or cannot be inspected.

The runner also provides read-only pinning for a single file named by a committed
creation receipt. It validates both receipt and commit identity using bounded,
no-follow reads, checks the expected content and size, requires current-user
ownership and a single hard link, and retains the opened file for later checks.
It detects changed content or path attachment. On Unix, hashing uses positioned
reads so neither initial pinning nor a recheck changes the consumer's read offset.
A metadata-only operation may
retain the original creation receipt for deletion during cleanup. This helper
does not itself execute a tool, change permissions or authorize a target path.

Filesystem-model tests cover replacement, permissions, capabilities, cancellation,
deadlines and read failures. Setup and workspace regressions cover unsupported
builds, stale responses and preservation of profile state. These tests and saved
inspection records are not evidence that a security method executed or a target
defense prevented access. Fresh installed runs and independently attributed
observations remain necessary for those claims.
