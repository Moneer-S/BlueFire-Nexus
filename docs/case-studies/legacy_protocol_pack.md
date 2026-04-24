# Case Study: Legacy Protocol Capability Pack

## Objective

Demonstrate that the legacy protocol research family (DNS tunneling, TLS fast
flux behavior, QUIC transport, Solana RPC, and network-obfuscation helpers) is
fully integrated as a first-class capability pack in the active runtime.

## Capability pack highlights

- Shared module surface: `legacy_protocol_research`
- Safety controls:
  - global master toggle: `modules.legacy.enable_all_lab_capabilities`
  - per-pack toggle: `modules.legacy.c2_pack.enabled`
  - per-capability toggles under `modules.legacy.c2_pack.capabilities.*`
- Mode controls:
  - `simulate` (default, no live side effects)
  - `emulate` (lab-only, explicit acknowledgment required)

## ATT&CK-oriented protocol coverage

- `dns_tunneling` -> `T1071.004`
- `tls_fast_flux` -> `T1090`
- `websocket_quic` -> `T1572`
- `solana_rpc` -> `T1572`
- `network_obfuscator_legacy` -> `T1090`

## Detection engineering output

Protocol runs feed normalized hints into:

- Sigma (`output/<run_id>/detections/sigma/*.yml`)
- YARA-L (`output/<run_id>/detections/yara_l/*.yaral`)
- Splunk SPL (`output/<run_id>/detections/spl/*.spl`)
- Coverage summary (`output/<run_id>/detections/coverage_<run_id>.json`)

Each run preserves transport metadata, endpoints, protocol details, and
simulate/emulate mode in telemetry and reporting artifacts.

## Blue-team usage

Use the protocol pack to validate:

1. DNS anomaly analytics (chunking, record usage, query patterns)
2. Beacon endpoint rotation and HTTPS cadence analytics
3. QUIC/UDP monitoring workflows in mixed enterprise traffic
4. New protocol channels (RPC/blockchain C2 research) with explicit lab gating
