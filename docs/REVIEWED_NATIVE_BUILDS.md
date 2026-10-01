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
