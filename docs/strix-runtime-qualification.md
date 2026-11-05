# Strix runtime qualification preparation

This step prepares ephemeral runtime inputs for the separately built Strix package-declared
`1.7.0` modified-source candidate, not an official Strix release. It
does not qualify Strix for use. It does not import or launch Strix, execute its TUI sidecar, start
the sandbox image, contact a target or model, publish a package, or change BlueFire's execution
authority.

The pull request workflow checks the exact candidate source and build at the
checked-out synthetic merge commit, prepares the offline Python closure, and
inventories the pinned image without running it. A trigger or passing check does
not establish runtime qualification or admission.

## Exact inputs

The preparation first rebuilds the candidate described in
[`engine-provenance.md`](engine-provenance.md). It then refuses to proceed unless all of these
identities agree:

- BlueFire's exact checked-out commit;
- upstream Strix commit `6b7ae2ebe4d47037a927aade23265ff4e4f27e84` and tree
  `23c06e4a0e58bdf3b4979863d7623230e4091332`;
- the candidate manifest, `SHA256SUMS`, wheel, policy-overlay prompt, startup-overlay
  `strix/interface/main.py`, and frozen `uv.lock`;
- CPython 3.12.14 on Linux x86-64 and uv 0.13.6; and
- sandbox OCI index
  `sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30`.

The candidate checkout must still contain exactly the reviewed prompt and startup modifications. The preparation
does not reconstruct source from an unbound archive or a moving tag.

The proposed controlled-image contract separately pins `strix-agent 1.7.0`,
`openai-agents 0.19.0`, `docker 7.1.0`, Caido `0.56.0`, and `caido-sdk-client 0.2.0`. These short
pins are not a complete dependency inventory. The preparation must preserve the exact resolved
lock closure and digest. A future image builder and verifier must prove that closure agrees with
the declared components before admission; the current contract parser does not perform that
cross-check and therefore supplies no positive admission claim.

## Offline Python closure

The exact upstream lock is exported with `uv export --frozen --no-dev --no-emit-project`. The
preparation rejects an unhashed requirement, index option, find-links option, editable input,
direct URL, VCS reference, or local file reference. It downloads every selected requirement with
pip 25.3 using `--only-binary=:all:`, `--require-hashes`, `--no-deps`, and an empty cache. The pip
wheel itself is fixed to its official PyPI URL, size, and SHA-256
`9655943313a94722b7774661c21049070f6bbb0a1516bf02f7c8d5d9201514cd`.

Installation occurs in a fresh virtual environment with no bundled pip. The exact pip wheel is run
in isolated, no-site mode and manages that empty environment in one install operation, before any
new `.pth` file can participate in interpreter startup. Dependencies come only from the generated
wheelhouse with `--no-index`; a derived one-shot manifest binds both the exported dependency hashes
and the separately hash-bound local candidate wheel. `--no-deps` prevents any metadata-driven
resolution. Strix is not imported and its CLI is not invoked.

The receipt records the actual virtual-environment interpreter, every wheel, installed distribution
metadata, the generated `strix` launcher, the installed package `RECORD`, the entry point, and the
installed policy prompt and startup `main.py`. Both installed files must match their candidate
SHA-256 identities and their installed package `RECORD` entries; the installed `RECORD` bytes are
compared across jobs. A missing binary wheel, extra
distribution, hash drift, source distribution, link, special file, ambiguous name, oversized
closure, or prompt/startup/entry-point mismatch fails closed.

This establishes a one-platform offline installation closure only. It is not proof of artifact
reproducibility, safe runtime behavior, containment, or effectiveness.

## OCI identity and inventory

The preparation uses the registry HTTP API directly to retrieve the pinned OCI index. It selects
exactly one `linux/amd64` child and verifies the raw index, child manifest, image config, layer
descriptors, platform, and root filesystem identities. It does not use Docker, Podman, a daemon, or
an image `run` operation.

The image inventory uses Anchore Syft 1.56.0 from its fixed Linux AMD64 release archive. The
archive SHA-256 is
`1c2493cfcf52d3367d6cb25780d9190c111c2219c34c820574c43e8bae15c528`; the official checksums
file is also downloaded and verified at SHA-256
`a2db61bc71f8f7ea8c67fc4a81b8e4e6474386e6a07d104bd2e78e964d5d7ec7`. The archive is inspected
without general extraction, and only a regular Linux x86-64 ELF named `syft` is written. Syft scans
the exact platform-child digest with an explicit registry source and produces native Syft JSON and
CycloneDX JSON. Syft reads the child's layers from the registry for inventory, which the receipt
records explicitly; it does not load or execute a container.

The generated notices report is an inventory aid, not a rights decision. It explicitly leaves image
NOTICE completeness, license review, and redistribution review unresolved. The Apache-2.0 license
of the Strix source repository is not applied to the image or its third-party packages.

This inventory describes the pinned upstream sandbox OCI child. It does not create or qualify the
separate controlled `bluefire.strix-derived-image.v1` artifact proposed for an installed attempt.
That contract must bind the actual derived image, base image, Dockerfile, dependency-lock, SBOM,
provenance and attestation digests. Admission must pair it with the complete independently verified
controller receipt set: two local-build checks and ten hosted-qualification checks. The upstream
index or this inventory cannot stand in for that set. No production
signing authority is configured, so the derived-image path remains fail closed.

The preparation manifest also preserves the candidate's blocked
`qualification.redistribution_review`. Go TUI dependencies, bundled frontend/viewer assets,
the complete Python runtime wheel closure, and OCI image notices/rights all remain unreviewed.
License expressions, notice completeness, and confirmed rights remain unknown (`null`);
redistribution readiness and authorization remain false. See the
[redistribution gate](engine-provenance.md#redistribution-remains-blocked) for the pinned official
sources and exact scope. Hash-bound inventory or installation does not complete that review.

## Workflow and outputs

`.github/workflows/strix-runtime-qualification.yml` uses a standard `ubuntu-24.04` hosted runner,
read-only repository permission, exact commit-pinned setup actions, a 60-minute job
limit, and no retained checkout credential. It has no scheduled,
push, package, release, container, target, or model step.

Successful preparation keeps the rebuilt candidate and bounded preparation directory only in
ephemeral runner-temp. It publishes no Actions artifact or cache. Public-repository Actions
artifacts are retrievable by repository readers; short retention does not restrict access. No
reviewed public evidence-receipt contract exists, so raw inventory or receipts are not uploaded
either. The preparation directory contains:

- the frozen hashed requirements and offline dependency wheelhouse;
- a Python runtime installation receipt;
- the exact OCI index/child/config/layer inventory;
- native Syft and CycloneDX image SBOMs;
- an explicitly incomplete third-party notices review;
- a canonical preparation manifest; and
- `SHA256SUMS` over every emitted preparation payload and the manifest.

The manifest always records `runtime_qualified: false`, all execution flags as false, and the hosted
runner, action, Python, uv, pip, Syft, candidate, wheel, prompt, startup, and image identities.

A later installed journey must also retain the exact controlled derived-image declaration and
all receipt references. Their absence cannot be repaired by copying the upstream OCI index identity
into a journey record.

## Remaining gates

These ephemeral inputs must receive independent provenance and security review through a separately
reviewed private process before any publication. The blocked redistribution review applies to
wheels, modified source, dependency closures, bundled assets, and OCI data. Normal BlueFire wheels
and releases exclude these payloads. A second clean build must
be compared before making a reproducibility claim. Separate controlled work must establish outer
network containment, admission, lifecycle stop, cancellation, evidence capture, cleanup, and owned
target binding before any Strix launch can be considered. Image notices, license terms, and
redistribution rights remain an explicit owner/legal review item. Live-model usefulness is a later,
separately authorized proof.

Until those gates pass, the result is a non-executed qualification preparation and must not be used
as a `StrixBuildIdentity` admission result.
