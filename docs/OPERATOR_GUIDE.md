# Operator guide

The normal product loop is:

> Design -> Simulate or Execute -> Observe -> adapt or change the defense -> Replay -> Compare ->
> verify the gap is closed.

## 1. Design

Choose a seeded scenario or create a versioned graph in Builder. Read its purpose, provenance,
limitations, typed artifacts, branch outcomes, safety tiers, collector expectations, and cleanup
path. Resolve every validation error before preflight.

## 2. Simulate

Begin with Simulate and AI Off. Inspect predicted effects and counterfactual branches. Assist can
draft a registered choice for review; Auto can apply a policy-valid registered choice only where
the mode and policy permit it.

## 3. Execute

Use a disposable authorized target. Confirm runner readiness, choose an Execute profile, bind the
explicit scope and collectors, review the human-readable preflight, and issue the one-time exact
approval. The Rust runner revalidates authority before each registered action. There is no shell
or arbitrary program field.

## 4. Observe and clean up

Distinguish runner-reported `executed` evidence from independently collected `observed`
evidence. Review missing and unexpected fields, hashes, lineage, collector health, detection
results, and control blocks. Cleanup must reconcile all receipt-owned effects to zero; a partial
or failed cleanup is a release-blocking result, not a warning to ignore.

## 5. Adapt, replay, and compare

The defense-frontier scenario records the first block, selects a semantically valid registered
alternate, executes the objective, records a defense change, and performs a controlled replay.
Compare explains path, prevention and detection bypass, telemetry, objective, cleanup, budgets,
and improvement or regression. A difference is evidence to investigate, not automatic causal
proof.

Use [Troubleshooting](TROUBLESHOOTING.md) for readiness failures and [Responsible use](RESPONSIBLE_USE.md)
for the authorization boundary.
