# Strix exec lifetime supervisor

The V2 Docker exec path requires an external lifetime owner before its first
socket write. An attached stream ending is not proof that work in the container
ended: a process can close stdout and leave descendants running. The Linux
supervisor therefore owns the whole operation until independently verified
container absence.

This is an exec-operation owner after its arm receipt, not the initial
container-creation owner. If the broker dies before the guardian starts, no
exec lease has been returned and no exec request may be sent. The outer
attempt owner must still reconcile or remove that pre-existing container;
installed qualification must test this handoff rather than treating the exec
supervisor as container custody before activation.

## Protected shape

- The controller starts a separate broker from a private, controller-written
  launch record. The broker verifies the controller with Unix peer credentials,
  `/proc` start time, and a pidfd.
- Before an exec lease becomes live, the broker durably records its exact
  attempt, claim, controller fence, custody/network policy, operation,
  container, daemon endpoint, deadline, and reviewed container identity.
- The broker starts a per-operation guardian and waits for its authenticated
  heartbeat before retaining an active lease. The guardian holds pidfds for
  both controller and broker, enforces
  the absolute deadline, and receives bounded heartbeats. Broker loss therefore
  does not drop cleanup custody.
- The guardian has no general Docker API. It can only inspect the exact admitted
  container, validate its name, pinned image and complete label identity, stop
  it, force-remove it, then inspect the same identifier until the pinned daemon
  returns the exact bounded 404 absence response.
- The inspected labels are the admitted V2 attempt, run, type, and image
  identity labels. Policy, execution, and profile digests bind the supervisor
  identity to the accepted controller policy without appearing as circular
  labels in the policy's own label set.
- Completion uses that same conservative absence path. Attach EOF and exec
  inspection never mint `verified_complete`.
- Terminal receipts have monotonic event cursors and remain in the private
  journal until the controller explicitly acknowledges the exact cursor and
  receipt reference after retaining product evidence. Delivery, disconnect,
  and close do not acknowledge evidence.
- The current fixed cleanup grammar supports Docker API `v1.43` only. The
  supervisor rejects another API version before activation. Terminal event
  evidence refers to the observed final container absence digest; the private
  guardian result also retains the bounded Docker exchange-chain digest.

## Recovery

Recovery is a separate, no-launch mode. It cannot arm an operation. A restarted
broker reconciles every active or cleanup-pending row, imports a guardian's
fsynced terminal result when present, or repeats the same fixed idempotent
cleanup. An unfinished RPC becomes a retained uncertainty response rather than
being guessed successful. Repeated recovery before acknowledgement returns the
same terminal cursor and receipt.

The journal uses a private directory, an exclusive process lock, SQLite DELETE
journaling with `synchronous=FULL`, bounded rows and documents, exact identity
joins, and an append-only acknowledgement chain. Socket device/inode and Docker
peer credentials are rechecked by the existing controller transport on every
exchange.

## Activation boundary

The implementation remains fail-closed on non-Linux hosts, missing pidfds,
identity drift, private-directory drift, daemon ambiguity, a stalled or
malformed response, journal corruption, or unverified absence. A Test-provider
Docker transport cannot satisfy live absence proof.

Production activation additionally requires the hosted Linux qualification to
exercise a real owned container, controller and broker crash cases, deadline
and cancellation, background work surviving attach EOF, repeated recovery,
exact receipt acknowledgement, daemon identity drift, and independent final
container inventory. Until that candidate proof is retained and reviewed, the
installed composition must not advertise V2 exec as qualified.
