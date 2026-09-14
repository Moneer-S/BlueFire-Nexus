# Responsible use

BlueFire Nexus is dual-use purple-team and detection-research software. It is intended for bounded experiments on systems, accounts, networks, and labs you own or are explicitly authorized to test.

The MIT license does not grant permission to access another party's systems, data, or accounts and does not replace applicable law, contract, policy, or rules of engagement.

## Before any experiment

Document:

- the owner and written authorization;
- exact systems/environment and time window;
- objective and permitted behaviors;
- excluded systems/data;
- maximum safety tier, scope, and budgets;
- expected effects and collection sources;
- approval and stop contacts;
- cleanup/reset and incident procedure;
- data handling, retention, and reporting rules.

If authorization is ambiguous, stop. Do not infer permission from network reachability, possession of credentials, an open-source license, or a successful preflight.

## Start safely

1. Run the graph in Simulate with AI Off.
2. Review every behavior, action, alternate, parameter, outcome edge, collector, and limitation.
3. Use a dedicated unprivileged runner and disposable sandbox.
4. Select the narrowest Execute profile and operator scope.
5. Prefer loopback/internal disposable fixtures; the shipped profile uses loopback only.
6. Confirm independent observation and cleanup readiness.
7. Preview the exact Execute plan before approval.
8. Monitor the run and retain refusal/block states honestly.
9. Verify cleanup and validate the final bundle.

## AI use

Use Assist before Auto for a new provider, scenario, action, or environment. Model output is untrusted and may be wrong even when schema-valid.

Do not:

- provide the model credentials, secrets, personal data, customer telemetry, or unreviewed sensitive evidence;
- ask it to invent actions, commands, scripts, payloads, targets, or credentials;
- treat its rationale as policy approval or technical proof;
- let a model-generated detection mark itself validated;
- broaden a profile or scope to accommodate a proposal.

Keep evidence-content forwarding disabled unless the data owner and provider policy permit it.

## Execute use

Execute performs real effects. The current pack is bounded, but fixture creation, transforms, discovery, staging/archive, local export, loopback communication, and cleanup are still real local activity.

Do not:

- run as administrator/root;
- target a home directory, production endpoint, corporate network, personal account, cloud account, VPN/LAN asset, or installed defensive product without explicit authorization;
- bypass runner profiles, approval, scope, or cleanup;
- add a generic shell/command action;
- expose the loopback API remotely;
- restore historical direct-effect Python code as a supported execution path;
- execute external research scripts or Atomic tests blindly.

Credential, lateral-movement, and defense-evasion families remain metadata-only. Persistence research includes one fixed non-executable canary inside a dedicated restricted runner-owned sandbox; it is not a host persistence change. Do not represent unavailable categories as operational or re-enable old code to make them appear complete.

## Evidence honesty

- Synthetic evidence is not execution.
- Runner-reported executed evidence is not independent observation.
- Missing observation is `unknown`, not “clean” or “not detected.”
- A policy refusal differs from a defensive prevention.
- A counterfactual path did not occur.
- A parsed rule is not production validated.
- A bundle digest is not a signature.
- A comparison delta is not causal proof.

Reports should state what was dynamically exercised, structurally tested, simulated, unavailable, and dependent on external credentials/infrastructure.

## Data handling

Run bundles can contain sensitive paths, telemetry, operator labels, environment facts, and detection details even when actions are benign.

- Store runs and SQLite metadata in a protected local directory.
- Set external retention and disk quotas.
- Do not publish raw run bundles without review.
- Create separate sanitized exports; do not edit originals and continue to call their hash valid.
- Never commit secrets, real local telemetry, customer data, internal targets, personal identifiers, or environment dumps.
- Keep external research clones/caches outside the repository and preserve source/license attribution.

## Stop conditions

Pause or terminate the experiment if:

- the selected target/scope differs from authorization;
- the runner identity/inventory/profile is unexpected;
- an action requests an unknown capability or path;
- a defensive control or system owner asks you to stop;
- effects appear outside the sandbox;
- budgets or time bounds are exceeded;
- cleanup fails or receipts cannot be reconciled;
- independent telemetry suggests unintended impact;
- provider or collector data handling violates policy.

Preserve evidence and receipts, notify the authorized owner, and follow the agreed incident procedure. Do not conceal, relabel, or retry the failure automatically.

## Third-party content

Review provenance, pin, license, integrity, prerequisites, parameters, effects, cleanup, and test scope. Public detection rules are comparison baselines, not evasion targets. External actions require explicit enablement and either a reviewed compiled integration or a signature-verified, content-addressed no-host-import WASM provider bound to an exact version, digest, declared limits, activation record, and runner inventory. Declarative plugin metadata alone grants no execution authority; scripts, Python entry points, arbitrary host commands, native shared libraries, and imported host functions remain unsupported.

## Reporting vulnerabilities

Use the private process in [SECURITY.md](../SECURITY.md). Do not include live credentials, unauthorized targets, private telemetry, or working exploit details in a public issue.

## Disclaimer

BlueFire provides technical controls that reduce accidental scope expansion; it does not determine legal authorization or guarantee that an experiment is safe for a particular environment. Operators and organizations remain responsible for authorization, deployment, monitoring, incident response, data handling, and cleanup.
