# Owned receiver content policy

This optional Linux component asks whether an authenticated destination can refuse
retained synthetic records while accepting a redacted collection of those records.
It implements a bounded same-host transfer control. It does not demonstrate
credential acquisition, remote access, or lateral compromise.

This checkpoint provides the receiver policy and owned session API. It is not yet
connected to scenario execution, review, replay, or the normal UI/CLI. Existing
receiver defaults remain unchanged. The owned session requires Linux pidfd
containment; it refuses before launching on other platforms.

## Policy definitions

Both immutable policies require the existing managed-task HMAC challenge protocol,
an exact task/body SHA-256/length binding, and strict public synthetic JSONL. The
receiver hashes and parses the actual authenticated request body. Bodies must have
1–100 complete records and be at most 1 MiB. The schema and generated values are
the existing BlueFire collection-semantics contract; arbitrary values, archives,
empty streams, malformed or truncated records are unsupported.

* `receiver.reviewed-records.v1` accepts all valid reviewed synthetic records.
* `receiver.redacted-only.v1` accepts only when every record is explicitly redacted.
  A retained or empty unredacted value is refused. Zero retained values alone do
  not establish successful redaction.

An authentication, framing, timeout, or body-digest failure produces no
authenticated content decision. A valid authenticated body with unsupported
content produces `invalid_content`, which remains insufficient evidence. A valid
retained body refused by the second policy produces `policy_refused`; this is an
observed destination decision, not proof that the transport action succeeded.

## Single-use session contract

`OwnedReceiverSession.prepare(policy_id, port=4317)` starts only the fixed installed
Python worker on literal `127.0.0.1`. It pins the current interpreter and worker
inodes during launch, retains the child object before construction can be
interrupted, and registers the exact child with the existing Linux containment
owner. No command, script path, environment, key, payload, or observation can be
supplied through this API.

The worker arms parent-death handling before any enrollment read or listener
creation. The parent verifies its armed frame after containment registration,
then supplies the immutable prepare frame. The worker obtains the existing active
managed enrollment locally; no key appears in channel frames or results.

The returned review binding includes exact policy content/hash, literal endpoint,
random launch and receiver session IDs, actual child PID and creation identity,
installed worker source generation, expiry, and a digest of the complete binding.
The lifetime is at most 240 seconds. The ordinary receiver-defense integration includes this exact binding in canonical native review and authorization before task dispatch.

`bind_task(task_id, digest=…, size=…, review_digest=…)` consumes readiness once. Its
inputs come from the actual approved native task and bounded artifact adapter at dispatch.
A changed review, expired session, changed source generation, repeated binding,
ambiguous write, or replaced session requires a new prepare and review. There is
no silent refresh or retry with new authority.

The private channel permits four response frames: armed, ready, bound, terminal.
Each frame is at most 8 KiB and every read has an absolute deadline. The parent
checks the terminal task, body digest/length, policy, receiver identity, semantic
counts, and counters; it then requires channel EOF and successful reconciliation
of the exact child before returning a verified accepted/refused observation.
Reports contain counts and identities, never body values or credentials.

EOF or extra parent input stops the listener; parent death also terminates the
worker. Shutdown joins/reaps only the owned child using existing containment.
Close/kill failures retain the exact in-memory owner for bounded reconciliation.
Retrying cleanup cannot create a missing observation. No session or process is
adopted from stored JSON or a PID after application restart: missing ownership or
terminal evidence is insufficient, and a new session/review is required.

## Validation and limits

Focused tests use generated public bytes, in-memory protocol streams, fake
processes/kernel boundaries, and private temporary files. They check real HMAC
verification and content parsing, refusal distinctions, immutable bindings,
startup order, EOF/deadlines, and recoverable cleanup. This checkpoint has not
launched the new worker or executed a native companion scenario. A dedicated isolated Linux lab run remains necessary before claiming real end-to-end receiver enforcement. The service/controller integration below has portable protocol-double coverage, not an installed enforcement claim.


## Ordinary service and job composition

The public `receiver-defense/context` operation resolves one immutable saved
scenario and native RunIntent. It requires Linux, Execute, runtime AI Off, one
registered JSONL collection.stage → peer handoff chain, and explicit handoff
cleanup outcomes. Simulate and unsupported hosts cannot prepare a receiver.
Current selected-profile readiness is exposed separately from the immutable
context digest; read-only context and replay preparation start no process.

An exact UUID creates a durable `receiver.defense` owner. Its canonical
`progress.admission` distinguishes pending, accepted, and definitive refused
admission. A stale or unavailable context closes that UUID without work;
`context` may be null only in a definitive refused admission. An unreviewed fresh
snapshot never substitutes for the operator's retained requested digest.

Each explicit Prepare creates `receiver.defense.prepare`, retaining the exact
construction attempt before any possible launch. The baseline uses ordinary
`scenario.run`; protected and restored phases use ordinary full `scenario.replay`
of the verified baseline. Native review reserves one UUID-derived execution ID;
normal Execute approval remains a separate action and expires no later than the
receiver. Parent Stop vetoes child publication and transition to running under
the same SQLite writer boundary. The dispatch hook binds exactly one actual
artifact SHA/size and native task ID before the ambiguous private write.
Protected/restored bytes must equal the authenticated baseline before network
handoff. Uncertain tasks and generic job retries never repeat receiver effects.

An expired unused settled preparation can be replaced only explicitly, after
verified exact cleanup and settlement of its previous native approval. Up to
twelve previous attempts remain attached to the owner. Losing in-memory ownership
never grants authority from a stored PID or session document. Failed construction
with verified closure can recover; a retained or unknown child remains uncertain.
Shutdown attempts every owned object and retained failed-construction owner and
reports failure if any cleanup remains unverified.

Results keep the independent receiver terminal, ordinary finalized source
binding, byte identity, and cleanup separately. The immutable run document stays
in its finalized bundle; public phase and child result views hydrate that same
verified run instead of copying transport metadata into the job credential
boundary. Later verified receiver cleanup has its own exact receipt and preserves
cleanup at finalization. Missing or invalid-content observations do not establish
prevention. A cancelled Execute that has not finalized remains pending ordinary
run cleanup recovery; receiver closure alone does not settle the test or permit
repeating the effect. If the native callback already retained an exact finalized
run link, result reconciliation uses that link without another execution.

Only three independently verified phases establish the displayed A→B→A result:
reviewed-records accepts retained public values, redacted-only refuses the same
bytes, and a fresh reviewed-records receiver accepts again. Final native jobs and
both cleanup dimensions must settle before the whole test is complete. This is
restored destination behavior, not VM reset, broad defense efficacy, held-out
validation, deployment, or an AI policy decision. Saved owners remain discoverable
through bounded keyset pagination, with unfinished owners before settled history.
