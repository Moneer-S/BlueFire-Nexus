"""Build two fixed upstreams into six unapproved Ubuntu candidate executables.

This manual CI helper is not product setup or a general builder. All subprocesses
receive a new explicit environment. Ordinary configure probes and required build
generators run; the six resulting tools and upstream test suites never run.
Runtime inspection is inert candidate evidence, not protected closure admission.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

OPENSSH_REVISION = (
    "a8c72b842423f0774f542d3c2197247c3dd28d74"  # pragma: allowlist secret -- public upstream commit
)
STRACE_REVISION = (
    "195ac8ddbf6fad16ff1ff125b0feb725b6c46dcf"  # pragma: allowlist secret -- public upstream commit
)
OPENSSH_PREFIX = "/usr/lib/bluefire-owned-sftp/openssh-10.6p1-bf1"
STRACE_PREFIX = "/usr/lib/bluefire-owned-sftp/strace-7.2-bf1"
SOURCES = (
    ("openssh", "https://github.com/openssh/openssh-portable.git", "V_10_6_P1", OPENSSH_REVISION),
    ("strace", "https://github.com/strace/strace.git", "v7.2", STRACE_REVISION),
)
MEMBERS = (
    ("client", "openssh", "sftp", OPENSSH_PREFIX + "/bin/sftp"),
    ("transport", "openssh", "ssh", OPENSSH_PREFIX + "/bin/ssh"),
    ("server", "openssh", "sshd", OPENSSH_PREFIX + "/sbin/sshd"),
    ("session_helper", "openssh", "sshd-session", OPENSSH_PREFIX + "/libexec/sshd-session"),
    ("auth_helper", "openssh", "sshd-auth", OPENSSH_PREFIX + "/libexec/sshd-auth"),
    ("observer", "strace", "src/strace", STRACE_PREFIX + "/bin/strace"),
)
OPENSSH_CONFIGURE = (
    "./configure",
    "--prefix=" + OPENSSH_PREFIX,
    "--bindir=" + OPENSSH_PREFIX + "/bin",
    "--sbindir=" + OPENSSH_PREFIX + "/sbin",
    "--libexecdir=" + OPENSSH_PREFIX + "/libexec",
    "--sysconfdir=" + OPENSSH_PREFIX + "/etc",
    "--with-privsep-user=bf-sftp-privsep",
    "--with-privsep-path=/run/bluefire-sftp/privsep",
    "--with-sandbox=seccomp_filter",
    "--without-pam",
    "--without-libedit",
    "--without-kerberos5",
    "--without-selinux",
    "--without-ldns",
    "--without-wtmpdb",
    "--disable-pkcs11",
    "--disable-security-key",
    "--disable-strip",
)
STRACE_CONFIGURE = (
    "./configure",
    "--prefix=" + STRACE_PREFIX,
    "--enable-mpers=no",
    "--enable-stacktrace=no",
    "--without-libselinux",
)
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_RUNTIME_FILES = 64
BUILD_PACKAGES = (
    "gcc",
    "binutils",
    "make",
    "autoconf",
    "automake",
    "gawk",
    "pkg-config",
    "git",
    "libc6-dev",
    "libssl-dev",
    "zlib1g-dev",
    "libcrypt-dev",
)


class CandidateBuildError(RuntimeError):
    pass


def identity(path: Path) -> dict:
    data = path.read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}


def clean_environment(home: Path, build_root: Path, epoch: str | None = None) -> dict[str, str]:
    result = {
        "HOME": str(home),
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false",
        "CC": "/usr/bin/gcc",
        "CPPFLAGS": "",
        "LIBS": "",
        "CFLAGS": f"-O2 -g -ffile-prefix-map={build_root}=/bluefire-build "
        f"-fdebug-prefix-map={build_root}=/bluefire-build",
        "LDFLAGS": "-Wl,-z,relro -Wl,-z,now",
    }
    if epoch is not None:
        if re.fullmatch(r"[0-9]{1,12}", epoch) is None:
            raise CandidateBuildError("Invalid pinned commit timestamp")
        result["SOURCE_DATE_EPOCH"] = epoch
    return result


def parse_elf(text: str) -> dict:
    needed = re.findall(r"\(NEEDED\).*Shared library: \[([^\]]+)\]", text)
    interpreters = re.findall(r"Requesting program interpreter: ([^\]]+)\]", text)
    if "Advanced Micro Devices X86-64" not in text or "ELF64" not in text:
        raise CandidateBuildError("Candidate is not native x86_64 ELF64")
    if re.search(r"\((?:RPATH|RUNPATH)\)", text):
        raise CandidateBuildError("Unexpected candidate ELF search path")
    if len(interpreters) > 1 or any("/" in item for item in needed):
        raise CandidateBuildError("Unexpected candidate ELF dependency form")
    return {"needed": sorted(set(needed)), "interpreter": interpreters[0] if interpreters else None}


def parse_cache(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for line in text.splitlines():
        match = re.match(r"\s*(\S+) \(([^)]+)\) => (/\S+)\s*$", line)
        if match and "x86-64" in match[2]:
            result.setdefault(match[1], []).append(match[3])
    return {key: sorted(set(values)) for key, values in result.items()}


def archive_sources(source: Path, destination: Path, *, tracked: list[str] | None = None) -> None:
    """Retain complete pinned source, then generated non-object build inputs.

    Never include Git configuration, ELF objects/executables or archive objects in
    the generated-source archive. The prebuild archive retains every tracked file.
    """
    paths = (
        [source / name for name in tracked] if tracked is not None else sorted(source.rglob("*"))
    )
    with tarfile.open(destination, "w:gz", dereference=False) as output:
        for path in paths:
            relative = path.relative_to(source)
            if ".git" in relative.parts or (path.is_dir() and not path.is_symlink()):
                continue
            if path.is_symlink():
                if not path.resolve().is_relative_to(source):
                    raise CandidateBuildError("Upstream source symlink escapes its checkout")
            elif path.is_file() and tracked is None:
                with path.open("rb") as stream:
                    if stream.read(8).startswith((b"\x7fELF", b"!<arch>")):
                        continue
            else:
                if not path.is_file():
                    raise CandidateBuildError("Unexpected upstream source member")
            output.add(path, arcname=relative.as_posix(), recursive=False)


class Builder:
    def __init__(self, root: Path):
        self.root = root
        self.artifact = root / "artifact"
        self.evidence = self.artifact / "evidence"
        self.source_output = self.artifact / "corresponding-source"
        self.home = root / "home"
        self.environment = clean_environment(self.home, root)
        self.commands: list[dict] = []
        for path in (self.artifact, self.evidence, self.source_output):
            path.mkdir(mode=0o700)

    def run(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        name: str,
        *,
        timeout: int = 600,
        allow_failure: bool = False,
    ) -> str:
        # No caller-supplied command/argv entry point; all calls below are tool-owned.
        log = self.evidence / (name + ".txt")
        with log.open("xb") as stream:
            completed = subprocess.run(  # nosec B603 -- fixed tool-owned commands
                argv,
                cwd=cwd,
                env=self.environment,
                stdout=stream,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        self.commands.append(
            {"argv": list(argv), "log": log.name, "returncode": completed.returncode}
        )
        if log.stat().st_size > MAX_LOG_BYTES:
            raise CandidateBuildError("Candidate build log exceeded review bound")
        if completed.returncode and not allow_failure:
            raise CandidateBuildError("Fixed candidate build step failed: " + name)
        return log.read_text(encoding="utf-8", errors="replace")

    def package_owner(self, path: Path, name: str) -> str:
        # Ubuntu's merged /usr can leave dpkg recording the historical /lib
        # spelling. Accept that spelling only when it resolves to these same bytes.
        resolved = path.resolve(strict=True)
        choices = [resolved, path]
        if str(resolved).startswith("/usr/lib/"):
            alias = Path(str(resolved)[4:])
            if alias.resolve(strict=True) == resolved:
                choices.append(alias)
        for number, choice in enumerate(dict.fromkeys(choices)):
            text = self.run(
                ("/usr/bin/dpkg-query", "-S", str(choice)),
                self.root,
                f"owner-{name}-{number}",
                allow_failure=True,
            )
            rows = text.strip().splitlines()
            if len(rows) == 1 and ": " in rows[0]:
                package = rows[0].split(": ", 1)[0]
                if re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::amd64)?", package):
                    return package
        raise CandidateBuildError("Runtime/toolchain file has no single Ubuntu package owner")

    def acquire(self, name: str, url: str, tag: str, revision: str) -> dict:
        source = self.root / name
        source.mkdir()
        self.run(("/usr/bin/git", "init", "."), source, name + "-init")
        self.run(("/usr/bin/git", "remote", "add", "origin", url), source, name + "-remote")
        self.run(
            ("/usr/bin/git", "fetch", "--depth=1", "origin", "tag", tag), source, name + "-fetch"
        )
        actual = self.run(
            ("/usr/bin/git", "rev-parse", f"refs/tags/{tag}^{{commit}}"), source, name + "-pin"
        ).strip()
        if actual != revision:
            raise CandidateBuildError("Upstream tag moved away from reviewed source commit")
        self.run(("/usr/bin/git", "checkout", "--detach", revision), source, name + "-checkout")
        self.run(("/usr/bin/git", "fsck", "--no-reflogs"), source, name + "-fsck")
        if self.run(
            ("/usr/bin/git", "status", "--porcelain", "--untracked-files=all"),
            source,
            name + "-clean",
        ).strip():
            raise CandidateBuildError("Upstream checkout is dirty before build")
        self.run(
            ("/usr/bin/git", "cat-file", "-p", f"refs/tags/{tag}"), source, name + "-tag-object"
        )
        tree = self.run(
            ("/usr/bin/git", "rev-parse", "HEAD^{tree}"), source, name + "-tree"
        ).strip()
        files = self.run(("/usr/bin/git", "ls-files"), source, name + "-tracked").splitlines()
        if (source / ".gitmodules").exists():
            raise CandidateBuildError("Unreviewed additional upstream source dependency")
        archive = self.source_output / (name + "-pinned-source.tar.gz")
        archive_sources(source, archive, tracked=files)
        epoch = self.run(
            ("/usr/bin/git", "show", "-s", "--format=%ct", "HEAD"), source, name + "-epoch"
        ).strip()
        return {
            "project": name,
            "url": url,
            "tag": tag,
            "commit": revision,
            "tree": tree,
            "source_archive": archive.name,
            **identity(archive),
            "epoch": epoch,
        }

    def build(self) -> list[dict]:
        sources = [self.acquire(*source) for source in SOURCES]
        for source in sources:
            name = source["project"]
            path = self.root / name
            self.environment = clean_environment(self.home, self.root, source["epoch"])
            if name == "openssh":
                self.run(("/usr/bin/autoreconf",), path, "openssh-autoreconf")
                self.run(OPENSSH_CONFIGURE, path, "openssh-configure")
                self.run(
                    ("/usr/bin/make", "-j2", "sftp", "ssh", "sshd", "sshd-session", "sshd-auth"),
                    path,
                    "openssh-make",
                )
            else:
                self.run(("./bootstrap",), path, "strace-bootstrap")
                self.run(STRACE_CONFIGURE, path, "strace-configure")
                # all generates source prerequisites; restricting SUBDIRS avoids test builds.
                self.run(("/usr/bin/make", "-j2", "SUBDIRS=bundled src"), path, "strace-make")
            generated = self.source_output / (name + "-generated-build-source.tar.gz")
            archive_sources(path, generated)
            source["generated_source"] = {"path": generated.name, **identity(generated)}
            self.run(
                ("/usr/bin/git", "status", "--porcelain", "--untracked-files=all"),
                path,
                name + "-postbuild-status",
            )
            self.run(("/usr/bin/git", "diff", "--binary"), path, name + "-postbuild-tracked-diff")
        return sources

    def runtime(self, member_paths: list[Path]) -> dict:
        cache_text = self.run(("/sbin/ldconfig", "-p"), self.root, "loader-cache")
        cache = parse_cache(cache_text)
        pending = list(member_paths)
        seen: set[Path] = set()
        files: list[dict] = []
        packages = set(BUILD_PACKAGES)
        toolchain = []
        for tool in (
            "gcc",
            "ld",
            "make",
            "autoconf",
            "automake",
            "gawk",
            "git",
            "readelf",
            "pkg-config",
        ):
            path = Path("/usr/bin") / tool
            package = self.package_owner(path, "toolchain-" + tool)
            packages.add(package)
            toolchain.append(
                {
                    "path": str(path),
                    "resolved_path": str(path.resolve()),
                    "package": package,
                    **identity(path),
                }
            )
        while pending:
            path = pending.pop(0)
            resolved = path.resolve(strict=True)
            if resolved in seen:
                continue
            seen.add(resolved)
            if len(seen) > MAX_RUNTIME_FILES:
                raise CandidateBuildError("Runtime closure exceeded finite candidate bound")
            number = str(len(files))
            elf = parse_elf(
                self.run(
                    ("/usr/bin/readelf", "-hW", "-lW", "-dW", str(resolved)),
                    self.root,
                    "elf-" + number,
                )
            )
            row = {"path": str(path), "resolved_path": str(resolved), **identity(resolved), **elf}
            row["symlink"] = os.readlink(path) if path.is_symlink() else None
            file_metadata = resolved.stat()
            row["uid"] = file_metadata.st_uid
            row["mode"] = stat.S_IMODE(file_metadata.st_mode)
            read_xattr = getattr(os, "getxattr", None)
            if read_xattr is None:
                raise CandidateBuildError("Linux file capability inspection unavailable")
            try:
                row["file_capabilities"] = read_xattr(resolved, "security.capability").hex()
            except OSError as error:
                row["file_capabilities"] = (
                    "absent" if error.errno == errno.ENODATA else "unavailable"
                )
            if not resolved.is_relative_to(self.artifact):
                package = self.package_owner(path, number)
                packages.add(package)
                row["package"] = package
            dependencies = []
            for needed in elf["needed"]:
                paths = cache.get(needed, [])
                if not paths:
                    raise CandidateBuildError("ELF dependency missing from candidate loader cache")
                dependencies.append({"needed": needed, "cache_candidates": paths})
                pending.extend(Path(item) for item in paths)
            if elf["interpreter"]:
                pending.append(Path(elf["interpreter"]))
            row["candidate_resolution"] = dependencies
            files.append(row)
        package_rows = []
        for package_number, package in enumerate(sorted(packages)):
            version = self.run(
                ("/usr/bin/dpkg-query", "-W", "-f=${Version}", package),
                self.root,
                f"package-version-{package_number}",
            ).strip()
            metadata = self.run(
                ("/usr/bin/apt-cache", "show", package + "=" + version),
                self.root,
                f"package-metadata-{package_number}",
            )
            uri = self.run(
                ("/usr/bin/apt-get", "--print-uris", "download", package + "=" + version),
                self.root,
                f"package-uri-{package_number}",
            )
            row = {
                "package": package,
                "version": version,
                "apt_metadata_log": f"package-metadata-{package_number}.txt",
                "archive_uri_log": f"package-uri-{package_number}.txt",
                "archive_sha256": re.findall(r"^SHA256: ([a-f0-9]{64})$", metadata, re.M),
            }
            if not row["archive_sha256"] or "https://" not in uri and "http://" not in uri:
                raise CandidateBuildError("Exact installed package archive provenance unavailable")
            copyright_path = Path("/usr/share/doc") / package.split(":")[0] / "copyright"
            if copyright_path.exists():
                target = (
                    self.artifact / "package-notices" / (package.replace(":", "_") + "-copyright")
                )
                target.parent.mkdir(exist_ok=True)
                shutil.copyfile(copyright_path, target)
                row["copyright"] = {
                    "path": str(target.relative_to(self.artifact)),
                    **identity(target),
                }
            package_rows.append(row)
        return {
            "status": "unapproved-cache-candidate-closure",
            "files": files,
            "packages": package_rows,
            "toolchain_files": toolchain,
            "limitations": [
                "All cache alternatives retained; actual loader selection, protected ancestor/symlink custody, capabilities and namespace runtime must be independently reviewed.",
                "Build host is not the prepared lab. NSS and OpenSSL configuration/modules require separate exact prepared-lab review.",
            ],
        }

    def execute(self, revision: str, image_os: str, image_version: str) -> None:
        self.run(
            ("/usr/bin/dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"),
            self.root,
            "installed-packages",
        )
        self.run(("/usr/bin/apt-cache", "policy"), self.root, "apt-policy")
        self.run(("/usr/bin/uname", "-a"), self.root, "kernel")
        for tool in ("gcc", "ld", "make", "autoconf", "automake", "gawk", "git"):
            self.run(("/usr/bin/" + tool, "--version"), self.root, "toolchain-" + tool)
        shutil.copyfile("/etc/os-release", self.evidence / "os-release")
        sources = self.build()
        members = []
        paths = []
        for role, source, executable, installation in MEMBERS:
            target = self.artifact / "candidates" / installation.lstrip("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.root / source / executable, target)
            target.chmod(0o755)
            paths.append(target)
            members.append(
                {
                    "role": role,
                    "source": source,
                    "installation_location": installation,
                    "artifact_path": str(target.relative_to(self.artifact)),
                    **identity(target),
                }
            )
        runtime = self.runtime(paths)
        configs = [
            Path(value)
            for value in (
                "/etc/ld.so.cache",
                "/etc/ld.so.conf",
                "/etc/nsswitch.conf",
                "/etc/ssl/openssl.cnf",
            )
        ]
        configs.extend(sorted(Path("/etc/ld.so.conf.d").glob("*.conf")))
        if len(configs) > 64:
            raise CandidateBuildError("Loader configuration exceeded finite evidence bound")
        config_rows = []
        for path in configs:
            if path.is_file():
                target = self.evidence / (str(path).strip("/").replace("/", "_") + ".input")
                shutil.copyfile(path, target)
                config_rows.append(
                    {"path": str(path), "evidence_path": target.name, **identity(path)}
                )
        notices = (
            ("openssh", "LICENCE"),
            ("strace", "COPYING"),
            ("strace", "LGPL-2.1-or-later"),
            ("strace", "tests/COPYING"),
            ("strace", "tests/GPL-2.0-or-later"),
            ("strace", "bundled/linux/COPYING"),
        )
        for project, relative in notices:
            target = self.artifact / "upstream-notices" / project / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(self.root / project / relative, target)
        recipe = self.artifact / "build_owned_sftp_candidate.py"
        shutil.copyfile(Path(__file__), recipe)
        manifest = {
            "schema_version": "bluefire.owned-sftp-candidate-build.v1",
            "status": "unapproved_candidate",
            "execution_available": False,
            "bluefire_source_revision": revision,
            "host": {
                "image_os": image_os,
                "image_version": image_version,
                "architecture": "x86_64",
            },
            "sources": sources,
            "members": members,
            "runtime": runtime,
            "build_host_configuration": config_rows,
            "ld_so_preload_present": False,
            "recipe": identity(recipe),
            "commands": self.commands,
            "candidate_tools_executed": False,
            "build_execution": "Upstream configure probes and required source/build generators only; no candidate tool, test suite or experiment invocation.",
            "admission": "No reviewed-build table, protected installation, runtime authority or public support claim is produced.",
        }
        (self.artifact / "candidate-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        (self.artifact / "README.txt").write_text(
            "UNAPPROVED OWNED SFTP CANDIDATES\nSix executables, complete pinned and generated corresponding sources, build recipe and candidate evidence.\nNot a protected installation or execution grant. Review source, notices, exact package/runtime closure and prepared-lab custody before admission.\n",
            encoding="utf-8",
        )
        inventory = {
            str(path.relative_to(self.artifact)): identity(path)
            for path in sorted(self.artifact.rglob("*"))
            if path.is_file()
        }
        if sum(item["size_bytes"] for item in inventory.values()) > MAX_ARTIFACT_BYTES:
            raise CandidateBuildError("Candidate artifact exceeded 256 MiB review bound")
        (self.artifact / "SHA256SUMS.json").write_text(
            json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
        )
        if (
            sum(path.stat().st_size for path in self.artifact.rglob("*") if path.is_file())
            > MAX_ARTIFACT_BYTES
        ):
            raise CandidateBuildError("Final candidate artifact exceeded 256 MiB review bound")


def main() -> int:
    if len(sys.argv) != 1 or sys.platform != "linux" or platform.machine() != "x86_64":
        raise CandidateBuildError("Fixed builder requires Ubuntu 24.04 x86_64 and no arguments")
    if os.geteuid() == 0:
        raise CandidateBuildError("Candidate compilation requires an ordinary build account")
    if Path("/etc/ld.so.preload").exists():
        raise CandidateBuildError("Unexpected build-host global loader preload")
    os_release = Path("/etc/os-release").read_text()
    if not re.search(r"^ID=ubuntu$", os_release, re.M) or not re.search(
        r'^VERSION_ID="24\.04"$', os_release, re.M
    ):
        raise CandidateBuildError("Fixed builder requires Ubuntu 24.04")
    revision = os.environ.get("BLUEFIRE_SOURCE_REVISION", "")
    if re.fullmatch(r"[a-f0-9]{40}", revision) is None:
        raise CandidateBuildError("Exact BlueFire source revision is required")
    root = Path(os.environ["SFTP_BUILD_ROOT"])
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise CandidateBuildError("Fresh absolute owned build directory required")
    if set(path.name for path in root.iterdir()) != {"home"} or list((root / "home").iterdir()):
        raise CandidateBuildError("Build directory and HOME must be fresh")
    Builder(root).execute(
        revision, os.environ["BLUEFIRE_IMAGE_OS"], os.environ["BLUEFIRE_IMAGE_VERSION"]
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CandidateBuildError, OSError, subprocess.SubprocessError) as error:
        print("Owned SFTP candidate build failed: " + str(error), file=sys.stderr)
        raise SystemExit(1) from error
