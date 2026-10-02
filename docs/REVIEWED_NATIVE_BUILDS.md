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

## Owned-service manager: Ubuntu Noble amd64

The closed owned-service installation inspector recognizes **systemd
255.4-1ubuntu8.12**, architecture **x86_64** (Debian amd64), as its systemctl
manager binary. This is installation identity metadata only: the service action
remains unregistered, and no installer or manager invocation is added. Its compiled
role bindings are documented in [owned-service installation contracts](OWNED_SERVICE_INSTALLATIONS.md).

Provenance comes from [official Launchpad build 31559902](https://launchpad.net/ubuntu/+source/systemd/255.4-1ubuntu8.12/+build/31559902),
the [binary package](https://launchpadlibrarian.net/835611282/systemd_255.4-1ubuntu8.12_amd64.deb),
and its [published changes metadata](https://launchpadlibrarian.net/835611224/systemd_255.4-1ubuntu8.12_amd64.changes).
The package's control record identifies that version and amd64 architecture.
Its systemctl member is ELF64 little-endian, machine 62/x86-64.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `systemd_255.4-1ubuntu8.12_amd64.deb` | 3474856 | `f4bfc1162fe45590c5422935323e324616aba72fd42771a0b4beb5d74e4d2689` |
| `usr/bin/systemctl` in that package | 1501304 | `d03995d5d2ce6a5dd1822854f80c40cdf3d92c7a008179d89e80e5ffcd1a9aa2` |
| `systemd_255.4.orig.tar.gz` | 14952427 | `96e75bd08c57ad401677456fb88ef54a9f05bb1695693013bc6ecce839640fd5` |
| `systemd_255.4-1ubuntu8.12.debian.tar.xz` | 257724 | `74c143cbd1e1c3aea57726171cb0810534bc957d863a31aff91aa956a1ea76c9` |

The [source publication](https://launchpad.net/ubuntu/+source/systemd/255.4-1ubuntu8.12)
and [source descriptor](https://launchpadlibrarian.net/833625632/systemd_255.4-1ubuntu8.12.dsc)
bind the [upstream source archive](https://launchpadlibrarian.net/833625626/systemd_255.4.orig.tar.gz)
and [Ubuntu packaging archive](https://launchpadlibrarian.net/833625630/systemd_255.4-1ubuntu8.12.debian.tar.xz)
to these source hashes and sizes. To reproduce the review, compare the complete
package to its changes metadata and the sources to the descriptor, then read the
Debian package's `data.tar.zst` member and hash `usr/bin/systemctl`. Do not install
or execute package content to establish identity. This review used official HTTPS
artifacts and checksum comparisons; it does not claim independent signing-key
verification or a reproducible rebuild.

The exact upstream [systemctl source](https://github.com/systemd/systemd-stable/blob/v255.4/src/systemctl/systemctl.c)
declares `LGPL-2.1-or-later`, with the
[license text](https://github.com/systemd/systemd-stable/blob/v255.4/LICENSE.LGPL2.1).
The Ubuntu packaging `debian/copyright` declares the default LGPL-2.1+ license and
file-specific exceptions. It is identical to the binary package's
`usr/share/doc/systemd/copyright` (SHA-256
`a7d06854714a1ca99f6dbd1a1641dde5bcf28635be149f6554449618f8f427f3`).
BlueFire includes identity metadata only, without the executable or archives.
Unknown builds require a reviewed source update. A matching package member does
not relax protected installation checks or establish a running manager identity,
dependency closure, service execution, or completed cleanup.
