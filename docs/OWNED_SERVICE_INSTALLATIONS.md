# Owned-service installation inspection contracts

Protected service admission has two closed installation roles. They are read-only
inspection contracts, not registered actions, adaptive methods, or legacy
`bluefire.tool-adapter.v1` contracts. They add no command, installer, arbitrary
executable input, or service-manager invocation. The native CLI still refuses an
admitted service request because the fixed service adapter is unregistered.

`runner/src/service_installations.rs` defines each complete canonical JSON document
in `Role::contract`. Its schema is
`bluefire.owned-service-installation-contract.v1`. The document excludes its own
resulting digest. Canonical hashing uses the existing sorted-key JSON rules in
`runner/src/canonical.rs`; native parity tests and the inspection path compare the
result with the compiled binding. Existing tool-adapter contracts are unchanged.

| Role | Adapter ID | Adapter version | Tool ID | Contract SHA-256 |
| --- | --- | --- | --- | --- |
| Manager | `owned.service.manager.v1` | `1.0.0` | `owned.service.manager.binary.v1` | `54f7fb7bd236d5c28f79903ca6b9efb01bd2144c3f8793ad0d22f776894fa6a7` |
| Payload | `owned.service.payload.v1` | `1.0.0` | `owned.service.payload.binary.v1` | `60bb8f6cd6e6b796bd1a7039b1e38c793faeb89f088302730f05da6f89d965e7` |

The installation record's `adapter_contract_digest` includes the `sha256:` prefix.
Fixture contract digests are not admitted. Changing a contract or Cargo package
version requires reviewing and updating its compiled digest; stale bindings fail
closed.

## Exact identities

The manager accepts only the Ubuntu Noble amd64 systemctl build recorded in
[reviewed native builds](REVIEWED_NATIVE_BUILDS.md#owned-service-manager-ubuntu-noble-amd64).
The contract binds its exact package version, architecture, executable size/hash,
official build/source references, source archive hashes, and license reference.
An operator-declared version, familiar path, or observed local hash cannot add a
build. Other versions and architectures are unavailable.

The payload uses the existing BlueFire runner's fixed `owned-service-payload`
entrypoint, with its existing finite 1–120-second duration grammar. Its version is
derived from `CARGO_PKG_VERSION` at compile time. Its bytes and size must equal
the current native runner image observed through a held `/proc/self/exe`
descriptor and matched against the authenticated launch-context digest. The
request cannot select a different authoritative version, payload hash, or size.
No self-referential ELF digest is embedded in the binary. Linux x86-64 and aarch64
payload records can be checked, but this manager allowlist admits x86-64 only.

## Inspection boundary

Both roles require exactly one matching profile record. The scope binds each
record's canonical digest, tool ID, path, and content hash; duplicate adapters,
missing records, swapped roles, relabelled binaries, and mismatched contract
identities are refused before installation inspection.

The service path reuses the full-record protected inspector. It retains the
root-owned, non-writable directory chain; nofollow component traversal; bounded
regular executable and supported ELF checks; rejection of special permission
bits/capabilities; and exact size/hash and retained-handle rechecks. The executing
runner is authenticated separately; its own launch location does not substitute
for a protected payload installation. Current-image observation, both role
inspections, and final rechecks share the same two-second monotonic deadline.
There is no fresh timeout per role or recheck. GNU chmod's existing reviewed-build
inspection policy and candidate-inspection behavior are unchanged.

This establishes installation identity only. Live manager instance/bus identity,
independent resource observations, reservation, action registration, and service
effects remain separate boundaries. An uninstalled test binary in an owned home
directory remains unavailable as a protected payload.
