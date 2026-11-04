# Strix runtime qualification preparation

This step prepares reviewable runtime inputs for the separately built Strix engine candidate. It
does not qualify Strix for use. It does not import or launch Strix, execute its TUI sidecar, start
the sandbox image, contact a target or model, publish a package, or change BlueFire's execution
authority.

The workflow is manual and has not been dispatched merely by adding it to the repository.

## Exact inputs

The preparation first rebuilds the candidate described in
[`engine-provenance.md`](engine-provenance.md). It then refuses to proceed unless all of these
identities agree:

- BlueFire's exact checked-out commit;
- upstream Strix commit `6b7ae2ebe4d47037a927aade23265ff4e4f27e84` and tree
  `23c06e4a0e58bdf3b4979863d7623230e4091332`;
- the candidate manifest, `SHA256SUMS`, wheel, policy-overlay prompt, and frozen `uv.lock`;
- CPython 3.12.14 on Linux x86-64 and uv 0.13.6; and
- sandbox OCI index
  `sha256:78df914f3029464c9d00580f531ec51025c251c422ec3b09c3f19c5fa6d80c30`.

The candidate checkout must still contain only the reviewed prompt modification. The preparation
does not reconstruct source from an unbound archive or a moving tag.

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
installed policy prompt. A missing binary wheel, extra distribution, hash drift, source distribution,
link, special file, ambiguous name, oversized closure, or prompt/entry-point mismatch fails closed.

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

## Workflow and outputs

`.github/workflows/strix-runtime-qualification.yml` uses a standard `ubuntu-24.04` hosted runner,
read-only repository permission, exact commit-pinned setup and artifact actions, a 60-minute job
limit, no retained checkout credential, and three-day artifact retention. It has no scheduled,
push, package, release, container, target, or model step.

Successful preparation uploads both the rebuilt candidate and a bounded preparation directory. The
preparation directory contains:

- the frozen hashed requirements and offline dependency wheelhouse;
- a Python runtime installation receipt;
- the exact OCI index/child/config/layer inventory;
- native Syft and CycloneDX image SBOMs;
- an explicitly incomplete third-party notices review;
- a canonical preparation manifest; and
- `SHA256SUMS` over every emitted preparation payload and the manifest.

The manifest always records `runtime_qualified: false`, all execution flags as false, and the hosted
runner, action, Python, uv, pip, Syft, candidate, wheel, prompt, and image identities.

## Remaining gates

These artifacts must receive independent provenance and security review. A second clean build must
be compared before making a reproducibility claim. Separate controlled work must establish outer
network containment, admission, lifecycle stop, cancellation, evidence capture, cleanup, and owned
target binding before any Strix launch can be considered. Image notices, license terms, and
redistribution rights remain an explicit owner/legal review item. Live-model usefulness is a later,
separately authorized proof.

Until those gates pass, the result is a non-executed qualification preparation and must not be used
as a `StrixBuildIdentity` admission result.
