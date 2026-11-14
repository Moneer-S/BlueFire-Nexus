# Linux Strix worker containment

BlueFire's first installed Strix profile is designed around a controller-owned Linux worker
boundary. The boundary is deliberately separate from Strix's tools and model
logic: it constrains the worker process, exposes only reviewed controller
relays, and retains evidence that the controller can revalidate before every
model lease or target effect.

This profile is not a general container or shell executor. A serialized
receipt is evidence only. It cannot relaunch a worker, reconnect to a worker,
or authorize another operation.

## Fixed launch profile

The controller prepares one private, copied runtime closure and pins its root,
interpreter, bootstrap, installed packages, dynamic loader and libraries, and
CA bundle by digest. The native helper creates the worker from a new address
space and retains the pidfd returned by the spawn operation. It does not look
up a numeric PID later and treat that lookup as process ownership.

The fixed worker command uses isolated Python with `site` disabled. An
immutable bootstrap installs the final syscall filter before it adds the exact
runtime site-packages directory, imports the installed worker, or requests
model or effect authority. The worker cannot select its executable, arguments,
environment, import root, mount source, or network destinations.

The first profile intentionally shares the host PID namespace. This preserves
exact kernel credential authentication on the private Unix packet channel.
It never accepts an unmapped PID of zero. Mount, network, IPC, and UTS
namespaces are private. The worker root omits `/proc`; the controller inspects
the worker through its own host procfs and retained namespace descriptors.

## Identity and resource boundary

Each launch receives a fresh disposable numeric UID and GID. The worker has no
supplementary groups, Linux capabilities, or privilege-escalation path. Its
cgroup v2 leaf has explicit memory, swap, CPU, and task limits. The task limit
is a denial-of-service bound, not the process-isolation proof: pinned Strix and
its SDK require ordinary threads.

The final TSYNC seccomp policy permits legacy clone only when the required
same-thread-group flags are present and the exit signal is zero. It returns
`ENOSYS` for `clone3` so the reviewed pthread path can fall back, and rejects
fork, vfork, process clone, exec, namespace, mount, privileged kernel-control,
and unreviewed io_uring operations. The controller verifies that every cgroup
task remains a thread of the original TGID.

The private root exposes only:

- three immutable, sealed inputs at fixed `/inputs` paths;
- the pinned runtime and bootstrap, mounted read-only;
- private writable home, temporary, and configuration directories;
- a worker-owned private controller endpoint; and
- a minimal, reviewed device set when the pinned runtime demonstrates it is
  necessary.

It does not bind host credentials, the Docker socket, the host root, or a host
procfs. Exact input, mount, endpoint, and runtime identities are retained in
the activation evidence.

## Network and effect authority

The worker network namespace has loopback only, no default route, no DNS, no
target route, and no daemon socket. The controller creates the exact model and
Caido-compatible relay listeners inside that namespace before releasing the
worker, transfers their descriptors to their controller-owned services, and
closes the worker's listener copies before the installed worker starts.

Target and filesystem effects still cross BlueFire's reviewed operation RPC.
The live containment verifier checks the spawn-owned process identity, cgroup,
namespaces, roots, sealed inputs, controller channel, and relay inventory
before the model lease is issued and before each admitted effect. This keeps
content admission, model planning, and effect authorization distinct.

## Cancellation, cleanup, and recovery

Cancellation targets the spawn-owned pidfd and exact cgroup, then proves the
cgroup is empty. Because the endpoint directory belongs to the disposable
worker identity, a retained native-helper authority performs identity-checked,
fd-relative endpoint cleanup. The controller does not unlink a worker-owned
path by name and assume success.

Cleanup evidence binds the process, cgroup, namespaces, endpoint, sealed
inputs, private roots, relay listeners, identity lease, and runtime generation.
Any missing or contradictory absence proof leaves cleanup unresolved and keeps
the identity or resources available for reconciliation. Reopening the durable
journal can inspect that history, but cannot recreate live launch authority.

## Qualification boundary

Contract tests and the harmless worker self-test establish only their named
mechanics. Production qualification additionally requires the exact pinned
runtime closure, installed Strix startup, ordinary thread use, a controller
relay exchange, independently observed tool effects, cancellation, and full
cleanup under the native helper on the recorded Linux image and architecture.
Deterministic providers can prove transport and lifecycle behavior. They do
not establish useful live-model behavior.

If namespaces, cgroup delegation, pidfds, sealed inputs, the final syscall
filter, exact runtime closure, or controller relay custody are unavailable,
this profile fails closed. It does not silently fall back to the stock Docker
backend or a less isolated process.
