# Build identity diagnostics

The authenticated `GET /api/v1/build-info` route reports the loaded product version,
recorded build metadata and the bytes of the fixed packaged UI assets. It accepts
no query parameters and has no mutation route. Settings may display these details;
they do not belong in ordinary workspace headings.

The existing setuptools build writes `_build_info.json` into build output after
copying the package. Its manifest contains the product version and the size/SHA-256
of `app.js`, `index.html` and `styles.css`. It does not change the source checkout.
Git archives substitute the exact commit into `_source_revision.txt`; that value
is retained as `source.revision` with provenance `git_archive`. Working checkouts
keep the literal archive placeholder, and builds without an archive marker report
`revision: null`. Runtime Git state, environment variables and branch names never
supply a revision. Source distributions preserve the marker as package data.

`build.metadata_status` is `embedded`, `unavailable` (older install/source checkout)
or `invalid`. `build.digest` identifies validated recorded metadata, not the wheel
ZIP or a signed attestation. `ui.digest` identifies the current fixed packaged
assets. `ui.matches_build` is true/false when recorded metadata is valid, and null
when comparison is unavailable. Missing/unreadable/unsafe assets have no digest;
they cannot match a valid recorded build. An asset mismatch preserves the recorded
build details so the operator can distinguish changed files from missing metadata.

This is diagnostic identity, not proof of source cleanliness, publisher trust,
execution authority or the content of a previously cached browser tab. It reports
no filesystem paths, environment, credentials, process identities or user data.
Reads are bounded to regular non-symlink resources and fixed names.

The existing normal `bluefire ui` launcher binds the loopback listener before
printing its private one-use bootstrap URL. Its current path does not automatically
open a browser. Binding/management ownership failure does not create a replacement
service; the existing owner remains authoritative. Browser auto-open and an
operator-friendly existing-instance handoff are separate launcher work, not
implemented by this diagnostics change.
