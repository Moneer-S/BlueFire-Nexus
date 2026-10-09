# Owned-service installation inspection contracts

Protected v1 service admission has two closed installation roles. They are read-only
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

## Explicit observation-runtime requests

The additive scope, grant and admission v2 schemas bind an `observation_runtime`
request. All three versions must match. V1 retains its exact two-installation
meaning and rejects the additional field. A runner that advertises only the v1
grant or admission protocol cannot receive v2 through that capability.

The request contains the runtime schema, a contract digest, the explicitly
reviewed system-broker UID, and exact `broker` and `systemd_daemon` installation
references. The references use the existing tool ID, path, record digest and
content-hash fields. Their installation-only adapter IDs are
`owned.service.observation.broker.v1` and
`owned.service.observation.systemd.v1`, respectively, with adapter version
`1.0.0` and Linux x86-64 metadata. They do not replace the existing `manager`
role, which continues to mean the `systemctl` executable.

The whole runtime request participates in the existing canonical scope digest,
approval, journal identity and execution binding. It cannot add caller-chosen
endpoints, process IDs, commands, fallback providers or dependency lists. A future
reviewed contract must fix the broker/daemon builds, dependency and configuration
trust limits, and system/session topology. The non-root session UID comes from
the existing target; the system-broker account must be explicitly reviewed.

**No production observation-runtime contract is supported yet.** Well-formed
metadata can be validated and bound, but the native admission path refuses v2
runtime support before returning installation authority. A familiar executable,
root ownership or a syntactically valid contract digest cannot bypass that
refusal. Exact provider provenance, protected runtime inspection and authenticated
peer acquisition remain required. The fixed service action remains unregistered.
