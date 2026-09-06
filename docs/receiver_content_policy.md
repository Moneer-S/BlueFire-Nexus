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
The lifetime is at most 240 seconds. A later integration must include this exact
binding in ordinary canonical review and authorization before task dispatch.

`bind_task(task_id, digest=…, size=…, review_digest=…)` consumes readiness once. Its
inputs must eventually come from the approved task and bounded artifact adapter.
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
launched the new worker or executed a native companion scenario. A dedicated
isolated Linux lab run and the ordinary review/evidence integration remain
necessary before claiming an end-to-end companion experiment.
