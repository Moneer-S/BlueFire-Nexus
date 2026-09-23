# Reviewed native tool builds

GNU chmod and GNU gzip setup accept the builds listed below. The runner compares the exact
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

## GNU gzip: Ubuntu Noble amd64

Supported package versions: **1.12-1ubuntu3.1** and **1.12-1ubuntu3.2**, architecture **x86_64** (Debian
amd64). Other versions and aarch64 builds require a reviewed identity update;
an installation path or an operator's version assertion is insufficient.

The [official Ubuntu package](https://security.ubuntu.com/ubuntu/pool/main/g/gzip/gzip_1.12-1ubuntu3.2_amd64.deb)
matches its size and SHA-256 in the
[Noble security package metadata](https://security.ubuntu.com/ubuntu/dists/noble-security/main/binary-amd64/Packages.gz).
The executable and copyright below were extracted as inert archive members. No
package scripts or candidate executables were run to identify the build. As with
the chmod review, official HTTPS provenance is not an independently verified
archive signing-key chain.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `gzip_1.12-1ubuntu3.2_amd64.deb` | 99204 | `4067522fbffe22672e4cf683bfc32e4a304bc872cf76f10049ab36d1a9eedb91` |
| `usr/bin/gzip` extracted from that package | 93424 | `afea077ce127d4fa9ad410d3066ba2b54dea19c0b44f04adf56c72d5f7b7a9bb` |
| `usr/share/doc/gzip/copyright` | 2895 | `1ca5dd5098fe2e1c0f0d05196f5b3da8b414a807702e6ca8b536eb5fd3059130` |

The historical **1.12-1ubuntu3.1** build is independently verified through
[Launchpad build 30376309](https://launchpad.net/ubuntu/+source/gzip/1.12-1ubuntu3.1/+build/30376309).
Its [package](https://launchpad.net/ubuntu/+source/gzip/1.12-1ubuntu3.1/+build/30376309/+files/gzip_1.12-1ubuntu3.1_amd64.deb)
matches the size and SHA-256 in both its
[changes metadata](https://launchpad.net/ubuntu/+source/gzip/1.12-1ubuntu3.1/+build/30376309/+files/gzip_1.12-1ubuntu3.1_amd64.changes)
and [build metadata](https://launchpad.net/ubuntu/+source/gzip/1.12-1ubuntu3.1/+build/30376309/+files/gzip_1.12-1ubuntu3.1_amd64.buildinfo).
This supports an existing reviewed lab image, not a recommendation to downgrade.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `gzip_1.12-1ubuntu3.1_amd64.deb` | 98982 | `d3ea567e3c25ebcd272e541ad49c447bc1d7f3720b8081132177ddb3ca9b1f96` |
| `usr/bin/gzip` extracted from that package | 93424 | `16f1f8dbe5b47b3c1160b9066bd15bfdd80548b1b878b1a025c462fec0ca02b1` |

Linux Rust CI prepares the pinned 1.12-1ubuntu3.2 executable under a fresh
root-owned directory in `/usr/lib`, after verifying its existing ancestors are
root-owned, non-symlink directories without group or other write access. It does
not change existing directory permissions. The disposable job exposes this
protected path only to the test fixture via
`BLUEFIRE_TEST_GZIP`. Product execution does not read this variable. This keeps
real gzip positive tests enabled without trusting an image's changing system
package. The dependency is neither included in uploaded runner assets nor bundled
into BlueFire wheels.

To reproduce the review, verify the complete Debian package against official
metadata, unpack `data.tar.zst` without installing it, and hash `usr/bin/gzip`.
Changes to `runner/src/reviewed_gzip_builds.rs` require review of that tuple.
Protected nondefault locations may bind identical bytes. Read-only setup checks
ownership, permissions, parent directories, ELF architecture and file capabilities;
the runner repeats identity checks immediately before effects.

GNU gzip remains an external GPL-3.0-or-later dependency. The package's documentation
uses additional GFDL and FSF-manpages terms. BlueFire does not bundle the executable
or package documentation. Its existing MIT license and Atomic Red Team notices
remain unchanged. These package checks establish provenance, not an observed run
or a detection result.
