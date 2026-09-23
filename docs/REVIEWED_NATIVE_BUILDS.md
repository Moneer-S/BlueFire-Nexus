# Reviewed native tool builds

GNU chmod setup accepts the builds listed below. The runner compares the exact
package version, architecture, executable size and SHA-256 with its compiled
allowlist, in addition to its protected-path, ownership, ELF and privilege checks.
It repeats the check immediately before execution on the held executable.
An operator assertion, familiar filename, root ownership or `--version` output
cannot add a build. Unknown versions, architectures and byte sequences fail closed.

## GNU chmod: Ubuntu Noble amd64

Supported package version: **9.4-3ubuntu6.1**, architecture **x86_64** (Debian amd64).
This is one reviewed historical build, not a claim to support all GNU releases or
a recommendation to downgrade an updated host. Additional builds require a reviewed
BlueFire update. The adapter's aarch64 implementation has no admitted build yet.

Provenance comes from [official Launchpad build 31108836](https://launchpad.net/ubuntu/+source/coreutils/9.4-3ubuntu6.1/+build/31108836).
The [package](https://launchpad.net/ubuntu/+source/coreutils/9.4-3ubuntu6.1/+build/31108836/+files/coreutils_9.4-3ubuntu6.1_amd64.deb)
matches the SHA-256 and size published in both its official
[changes metadata](https://launchpad.net/ubuntu/+source/coreutils/9.4-3ubuntu6.1/+build/31108836/+files/coreutils_9.4-3ubuntu6.1_amd64.changes)
and [build metadata](https://launchpad.net/ubuntu/+source/coreutils/9.4-3ubuntu6.1/+build/31108836/+files/coreutils_9.4-3ubuntu6.1_amd64.buildinfo).
This provenance uses official HTTPS artifacts; it is not a claim of an independently
verified archive signing-key chain.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `coreutils_9.4-3ubuntu6.1_amd64.deb` | 1412772 | `935cdbd9362d0a4c64c198736b896c17651b2c463a3dae08b9e6a48b57d3a52d` |
| `usr/bin/chmod` extracted from that package | 55816 | `4158cfdb26fb11602bebf64dc585bea557f2b7287eb49ad51c54f1f8897acada` |

To reproduce the review, obtain these official artifacts, compare the complete
package hash and size with the metadata, unpack the Debian archive and its
`data.tar.zst` **without installing or executing it**, and hash `usr/bin/chmod`.
Review the package provenance and the executable tuple before editing
`runner/src/reviewed_chmod_builds.rs`. No runtime download or user-supplied
allowlist is involved. A protected nondefault installation location may bind the
same reviewed bytes; changing the location does not relax identity verification.

GNU Coreutils is GPL-3.0-or-later. BlueFire records identity metadata only; it does
not bundle this executable. Existing third-party notices and the MIT license for
BlueFire remain in effect. Package identity is prerequisite evidence, not evidence
that a security experiment executed or achieved its objective.
