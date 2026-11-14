# Strix test sandbox image

BlueFire has a separate, test-only image contract for qualifying the installed
Strix mechanics on an owned hosted runner. It is not a revision of the
production-lineage `StrixImageContractV2`. That historical contract is bound to
the upstream Strix sandbox image. The test contract does not use, pull, derive
from, or qualify that image.

The authoritative parser is
[`StrixTestSandboxImageContractV1`](../bluefire/strix_test_sandbox_image.py).
Its schema is `bluefire.strix-test-sandbox-image.v1`. Parsing canonical bytes
does not prove that an image was built or run. A positive qualification record
also needs the exact hosted build, import, startup, inspection, SBOM, self-test,
and cleanup evidence described below.

## Exact base and native tool closure

The only base is the Docker Official Debian image identified by the historical
label `bookworm-20260918-slim`. The label is explanatory and is never used as
build authority. The contract pins all of these OCI identities:

| Role | Identity |
| --- | --- |
| OCI index | `sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251` |
| Linux AMD64 manifest | `sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b` |
| Image config | `sha256:db9f02c6bde9fa90cc8074c92754b2b046947392f1a857726e77f041febb7b82` |
| Compressed base layer | `sha256:774043ccc8ccd0d0833a9ee0792142ab7ad93df971e59dd248fbf82db16d0150` |

The build reference is
`docker.io/library/debian@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`.
The contract records the registry and Docker Hub tag APIs used to resolve the
index, child, config, and layer on 2026-11-05. A later moving tag cannot replace
any of those objects.

The base supplies the captured Strix shell requirements:

- Bash `5.2.15-2+b13` for normal ShellTool work;
- Dash `0.5.12-2` for `/bin/sh` envelopes;
- coreutils `9.1-1` for `mkdir` and `rm`; and
- tar `1.34+dfsg-1.2+deb12u1` for staged workspace extraction.

The pinned Strix startup wire also invokes curl. Curl is added from an offline,
ordered set of SHA-256 checked Debian Bookworm AMD64 packages. The direct
package is `curl 7.88.1-10+deb12u15`, file
`curl_7.88.1-10+deb12u15_amd64.deb`, with SHA-256
`0dd9b6bf7a0bd11af2d68a52ec44c2a223fa7c11f9104c36ce1047e1137d4a8f`.
Its exact added dependency set is:

- `libcurl4`, `libbrotli1`, `libgssapi-krb5-2`, `libk5crypto3`,
  `libkrb5-3`, `libkrb5support0`, and `libkeyutils1`;
- `libldap-2.5-0`, `libsasl2-2`, and `libsasl2-modules-db`; and
- `libnghttp2-14`, `libpsl5`, `librtmp1`, `libssh2-1`, and `libssl3`.

[`package_lock_document()`](../bluefire/strix_test_sandbox_image.py) is the
canonical source for every package version, immutable pool URL, archive name,
SHA-256, architecture, and in-image Debian copyright path. The qualifier must
download those archives before the image build, compare the exact ordered set
with `validate_package_archive_digests()`, and build with network mode `none`
and pulling disabled. The final image must not contain a usable package manager
and does not permit runtime installs.

No upstream `strix-sandbox`, Kali image, Caido CLI, Caido server, official Caido
image, or derived Caido image is part of the base or package closure.

## Sealed installed runtime

The image contract does not infer an installed Strix runtime from the Debian
base. It binds a final
`bluefire.strix-linux-qualified-runtime-composite.v1` root under `/runtime`.
That composite is available only after the prelaunch closure plan and a fresh
fixed-exec qualification have both succeeded. The preparation manifest alone
is not authority to build this image. The qualified composite must identify
all of the following with SHA-256 references:

- its composite reference, prelaunch plan, fixed-exec qualification, and
  complete inventory;
- the CPython 3.12.14 interpreter;
- the fixed installed worker entry point;
- the minimal `bluefire-strix-worker` artifact, its exact `RECORD`, source
  revision, and installed-distribution inventory;
- the pinned Strix candidate at source revision
  `6b7ae2ebe4d47037a927aade23265ff4e4f27e84`;
- the exact fixed worker invocation; and
- the distinct prelaunch and postlaunch records.

The runtime closure, not the base image's available commands, establishes the
interpreter, Strix, Agents SDK, Python dependency, standard-library, dynamic
loader, shared-library, and CA-certificate identities used by the installed
worker. The image build binds the runtime manifest reference again. A changed
interpreter, dependency inventory, worker artifact, entry point, source
revision, or qualification record creates a different image candidate and
cannot reuse an earlier receipt.

The full `bluefire-nexus` product wheel is structurally refused. Its
cryptography requirement is incompatible with the exact dependency selected
by pinned Strix, and the image must not loosen either side or co-install two
conflicting environments. The qualified composite records
`full_product_wheel_present: false`; hosted preparation checks the installed
distribution metadata and the container self-test checks it again.

The installed worker launch is exactly:

```text
/runtime/bin/python -I -S -B -X utf8 /bootstrap/worker.py
```

Caller arguments are not accepted. The controller, not the image, owns the
exact attempt configuration, objective, model connection, descriptors, and
lifecycle authority.

## BlueFire Test Caido protocol provider

The controller runs BlueFire's test protocol provider outside the restricted
worker image. Its maintained module is `bluefire.test_caido_protocol_provider`.
The image contract separately binds the controller provider source and
invocation digests; the provider is test-only, not production eligible, and
not live Caido proof. No provider module is inserted into the qualified worker
runtime after its inventory and wheel `RECORD` have been verified.

The provider adopts four controller-owned descriptors:

```text
<controller-owned-python> -I -m bluefire.test_caido_protocol_provider \
  --manifest-fd <controller-owned-fd> \
  --listener-fd <prebound-127.0.0.1:48080-fd> \
  --audit-fd <controller-owned-fd> \
  --ready-fd <controller-owned-fd>
```

It does not create, bind, listen on, or connect a socket. The guest's native
launcher prebinds numeric loopback `127.0.0.1:48080` in the private attempt
network namespace and transfers the listener descriptor to the controller.
That transfer and provider reachability need separate installed proof. The
safe source conformance command is:

```text
python -m bluefire.test_caido_protocol_provider --describe
```

The invocation document and digest also bind the descriptor behavior. The
provider provenance is fixed to the reviewed `caido-sdk-client 0.2.0` wheel,
the captured SDK wire fixture, the SDK project document, and the pinned Strix
Caido bootstrap source. Their exact SHA-256 values are constants in the test
image contract. This evidence qualifies protocol compatibility only. It does
not qualify a Caido binary or live Caido behavior.

## Runtime containment

The fixed runtime profile uses numeric identity `1000:1000`, work directory
`/workspace`, and entry point
`/opt/bluefire/bin/strix-test-sandbox-entrypoint`. The root filesystem is read
only. `/workspace` is the only writable tmpfs and is private, mode `0700`,
`nosuid`, `nodev`, and `noexec`, with a 512 MiB limit. `HOME`, `TMPDIR`, and the
cache root all resolve below that workspace.

The profile also requires:

- no bind mounts, named volumes, published ports, devices, Docker socket, or
  host gateway;
- no added capabilities, all capabilities dropped, no new privileges, and the
  runtime-default seccomp profile;
- private PID, IPC, and UTS namespaces;
- one attempt-internal network, no DNS, no public egress, and no additional
  networks;
- only the test provider on fixed sandbox loopback and the
  controller-enrolled owned-target relay as admitted destinations;
- 2 GiB memory with no additional swap, two CPU equivalents, and 256 PIDs;
  and
- no runtime image pulls, installs, or automatic restart.

An image declaration cannot widen these fields. The attempt controller still
has to bind the actual network, target relay, model route, authorization,
resource limits, and cleanup ownership before execution.

## Hosted qualification lifecycle

The positive path is intentionally runner-private and uses a standard
`ubuntu-24.04` Linux x86-64 hosted runner. One coherent job must:

1. verify the exact checked-out BlueFire revision;
2. obtain and verify the sealed CPython 3.12.14 prelaunch plan, fixed-exec
   qualification, final qualified composite, and provider artifact;
3. fetch only the pinned base and exact package archives;
4. construct a deterministic build context and Dockerfile;
5. build into the local Docker daemon with pulling disabled and build network
   `none`, then save only that tagged image to a private Docker archive;
6. use the hosted runner's reviewed Skopeo `1.13.3` package to convert the
   local Docker archive to a private OCI archive. The source is
   `docker-archive:` and the destination is `oci-archive:`; no registry
   transport is used. Record the exact Skopeo package and executable digest;
7. retain the private OCI layout long enough to record the Dockerfile, context,
   base, final index, platform manifest, config, and ordered layer identities;
8. confirm the OCI config equals the built daemon image ID, remove the exact
   private image, reload its saved Docker archive, and confirm the reloaded
   image ID is unchanged;
9. start the image under the fixed non-root, read-only, capability-free profile
   and run the harmless self-test; describe the separate installed controller
   provider in the same job;
10. generate an SBOM tied to the final image plus separate provenance, notice,
   and self-test evidence digests;
11. hand the exact contract and qualification references to the same-job
    installed execution proof when that proof is in scope; and
12. remove only the exact labeled container, image, build context, staged
    runtime, Docker archive, and OCI layout, then verify their absence. The hosted runner also
    removes its private downloaded inputs and runtime at job teardown.

The current manual workflow rebuilds and prepares the pinned Strix candidate,
the minimal BlueFire worker wheel, and the prelaunch runtime from one checkout
revision. It validates their digests, then requires a separately produced
native fixed-exec qualification and final composite before image construction.
The preparation result is labeled `prepared-not-startup-qualified`; it cannot
satisfy that gate. Until an installed controller creates the final composite
in the same job, dispatching this workflow stops without an image pass.

After image qualification, the job archives the same committed BlueFire
revision, builds and inspects its Linux wheel with the staged native runner,
and installs it in a separate service environment outside the checkout. The
installed service smoke check uses that environment. This sequence keeps the
full product and its dependencies outside the sealed worker image. It does not
yet run the installed Strix experiment; that proof requires the final native
composite and the product journey step before private image cleanup.

After image and service cleanup, the job retains a bounded, owner-private
`producer-identity.json` containing only source and artifact digests, host
image identity, and the image cleanup receipt digest if one exists. It does
not claim installed execution. An exact allowlist then removes the candidate
checkout and wheel, worker wheel, qualification and prelaunch materials,
runtime composite, and downloaded image build inputs. The image contract,
cleanup receipt, and private identity summary remain available for a later
sanitized proof bundle; no executable materials or raw paths are uploaded.

The output manifest filename is
`strix-test-sandbox-image-manifest.json`. Its canonical SHA-256 is the image
contract reference. `StrixTestSandboxImageContractV1` exposes the separate
`qualification_ref`, `runtime_closure_ref`, and digest-pinned image reference
for explicit controller composition. Callers must reopen the canonical bytes
and type-check this test contract. They must not select it through a
caller-controlled mode string or coerce it into `StrixImageContractV2`.

Cleanup uses schema `bluefire.strix-test-sandbox-image-cleanup.v1` and filename
`strix-test-sandbox-image-cleanup.json`. A positive
`StrixTestSandboxImageCleanupReceiptV1` requires confirmed absence of the exact
container, image, build context, Docker archive, OCI layout, and staged runtime.

The local converter is the standard [Skopeo image copy transport](https://github.com/podman-container-tools/skopeo/blob/main/docs/skopeo.1.md),
which documents Docker archive to OCI conversion. GitHub's
[Ubuntu 24.04 runner image inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
lists Skopeo `1.13.3`. Qualification requires the package-owned
`/usr/bin/skopeo` path. A changed package identity fails qualification until
reviewed; the workflow does not install a replacement at runtime.
The converter permits an unsigned source only for the just-built local Docker
archive. The source and destination transport vectors are fixed in code, and
the daemon image ID must match the OCI config before any positive receipt.
Uncertain cleanup is not a positive receipt.

The image, runtime root, controller provider artifact, downloaded packages, build context,
OCI archive, and image layers must remain in runner-private temporary storage.
The workflow must not log in to a registry, push an image, export a shared
cache, or upload those materials. If bounded evidence is retained, it must be
an explicit allowlist of non-secret JSON or SBOM records, never a directory or
broad glob containing executable material.

## Proof levels and current limit

A parsed contract establishes schema and identity consistency only.

A hosted build receipt can establish that one exact image was built, imported,
started, inspected, inventoried, self-tested, and removed on the recorded
runner. It does not, by itself, establish that the installed Strix engine made
a tool call, reached the owned target, was cancelled correctly, or completed
the attack, defense, and retest experiment.

An installed mechanics run may separately establish real engine startup,
ShellTool execution, provider transport, target responses, cancellation, and
cleanup. Deterministic provider behavior remains test-provider evidence. It is
not a live-model decision-quality result and it is not live Caido proof.

The contract always records:

- `test_only: true` and `runner_private: true`;
- image upload and publication disallowed;
- `production_runtime_admitted: false`;
- `live_engine_proof: false` for the image qualification itself;
- `live_caido_proof: false`; and
- `redistribution_authorized: false`.

No current contract record should be described as successful hosted proof
until the exact workflow produces the positive build, import, startup,
self-test, SBOM, and cleanup records. If Docker, the sealed runtime, the Test
provider artifact, the pinned base, a package archive, or the verified SBOM
tool is unavailable, qualification stops at the missing input. Static tests
remain useful contract evidence but do not substitute for that run.

## Resuming qualification

To resume after an interrupted or unavailable hosted run, retain only the
non-secret expected identities needed to reconstruct the candidate:

- exact BlueFire and Strix source revisions;
- runtime closure manifest and qualification references;
- provider composite source and artifact digest;
- pinned base descriptors and canonical package-lock digest; and
- the qualifier revision and expected runner platform.

Start a fresh hosted job and recreate all executable inputs from those trusted
references. Do not reuse an unverified runner directory, local tag, container,
or partial OCI layout. A new attempt receives a new cleanup label and new
qualification reference. The old failed or interrupted record remains
historical evidence and is never rewritten as a pass.
