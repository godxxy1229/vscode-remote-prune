# Remote Prune (Preview)

Conservative cleanup of old **VS Code Stable server installations on Linux Remote-SSH hosts**. Keep every running version and one additional newest unused version. Preview every candidate and its preservation reason before choosing a manual cleanup.

**No Python, separately installed Node.js, Go toolchain, npm packages, or background service is required on the remote host.** The UI uses VS Code's extension host. Small, statically linked Linux x64 and ARM64 executables are included. The native source is included for inspection.

## Scope

Only recognized installations owned by the login user under these default locations are considered:

- `~/.vscode-server/cli/servers/Stable-<40-character-commit>`
- `~/.vscode-server/bin/<40-character-commit>`

This extension does **not** clean extensions, logs, caches, workspaces, `/tmp`, application data, databases, or backups. It does not stop processes. Custom server roots, Insiders, WSL, containers, Windows and macOS remote hosts are unsupported. A Windows or macOS **client** connected to supported Linux over Remote-SSH is fine.

Install Remote Prune **in the SSH host**, not just the local client. Workspace Trust is required. Automatic deletion is **off by default**, and repository/workspace settings cannot turn it on.

## Required read-only inspector

Before cleanup, a host administrator must review and install the bundled read-only process inspector. Remote Prune never elevates to install it automatically. The inspector examines process executable paths, commands, open-file links and memory mappings, but outputs only recognized version names, in-use flags, completeness and its checksum. It does not output command lines, environment variables, file contents or process/customer details.

The root-owned executable is `/usr/local/libexec/remote-prune-inspect`. The per-user sudo rule permits **only that executable without arguments**. Root execution with any argument is refused. The inspector contains no file deletion or process termination operation. Actual cleanup always runs as the ordinary SSH user.

From the installed extension directory, after reviewing `scripts/install-helper.sh` and the native source:

```sh
# Choose the architecture of the REMOTE host, not your local client.
# aarch64: bin/linux-arm64/inspector
# x86_64: bin/linux-x64/inspector
sha256sum bin/linux-arm64/inspector
sudo sh scripts/install-helper.sh YOUR_SSH_USERNAME REVIEWED_SHA256
```

The installer refuses to overwrite a different existing helper or sudo rule. It validates sudoers before committing the rule. Standard Linux `sudo`, `sha256sum`, `install`, `cmp`, `stat`, `sync`, and `visudo` are needed for this explicit administrator step. They are not a Python or Go runtime requirement.

Missing helper, insufficient inspection permissions, incomplete process inspection, checksum mismatch or an unknown protocol means **no deletion**. On an update, review the new helper and extension again before re-enabling automatic cleanup.

## Commands

- **Remote Prune: Preview Server Cleanup** — candidates, sizes and preservation reasons.
- **Remote Prune: Clean Selected Server Versions** — select eligible versions, then confirm permanent removal. All checks are repeated after confirmation.
- **Remote Prune: Show Cleanup History** — recent attempts and any interrupted operation.
- **Remote Prune: Enable Daily Cleanup on This Host** — explicit opt-in for this SSH user and host.
- **Remote Prune: Disable Daily Cleanup on This Host** — stop future automatic attempts.

The status bar shows manual/daily/review status and the next check time. The Output panel contains the latest detailed report.

## Preservation and deletion rules

1. Preserve every installation observed in use by any inspected process, plus the newest unused version.
2. Preserve installations first observed less than 24 hours ago or changed within the last 24 hours. Changed identity/content starts a new observation period.
3. Reject ambiguous installation metadata, symlinks, hard-linked files, special files, mount points, unexpected ownership, world-writable entries and oversized scans. Official archives can contain `0664` files and `0775` directories: these are accepted only behind a private `0700` login home, with its same group. Group-writable installations in a shared home are preserved. Identity and full content checksums are rechecked.
4. Use a host/user-wide OS lock. A second window cannot clean concurrently.
5. Save a durable pending record, atomically rename a candidate to a quarantine name in the same parent, and inspect again. Newly observed use restores the original name if safe.
6. Delete through an opened directory handle using Go's `os.Root`, which prevents recursive deletion from escaping the directory through symlink substitutions. Root privileges are never used to delete.

The inspector is a point-in-time check, not a kernel process-launch lock. Unknown or changing state is treated conservatively. Keep your user account and administrator account trusted; this is not an isolation boundary against malicious code running as that same user or root.

Removal is permanent. A matching VS Code client can normally download its server again, but **file-level undo is not provided**. Do not store your own files in VS Code server installations.

## Daily cleanup

The first automatic attempt is scheduled **24 hours after activation**. Windows on the same host/user share the schedule and attempt record. The extension is not a daemon: it runs only while a remote extension host is alive. After an overdue reconnect, it waits 60 seconds and makes one attempt; missed days are not replayed.

A failed or deferred attempt also moves the next attempt 24 hours ahead. Clock reversal suspends cleanup. Extension/helper checksum changes require revalidation and explicit re-enabling. All manual safety checks also apply to automatic cleanup.

State and at most 30 history entries are stored in `~/.remote-prune/state.json`, capped at 5 MiB. No ongoing directory scans are used for scheduling. File-content checks and size scans happen only during preview/cleanup. The extension watches only its small state record so another window can notice a scheduling change.

## Interrupted cleanup / removal

An interrupted quarantine or partial deletion is **never resumed automatically**. Disable daily cleanup and preserve the pending record. Inspect the exact recorded original and quarantine paths. Restore a complete quarantine to its original name only after checking identity, active use and absence of an original-name conflict. Do not clear the pending record merely to force another cleanup. Partially deleted installations require operator review and usually client-driven reinstallation.

To uninstall: disable daily cleanup, wait for any operation to finish, uninstall the extension from the SSH host, then have the administrator remove only its reviewed sudo rule and `/usr/local/libexec/remote-prune-inspect` (if no other configured users depend on it). Retaining the small local history is safe. No application restart is needed.

## Privacy, source and validation

No telemetry, network requests, customer-data collection, authentication tokens or remote uploads are implemented. See `PRIVACY.md`. All native runtime code uses Go's standard library; no external Go dependencies are included. Build-time npm dependencies are not shipped.

Preview 0.1.0 is validated with synthetic directories, actual file/mapping holders, process interruption, concurrency and clock tests on AWS Linux ARM64, plus Windows extension-host simulations. Linux x64 is cross-built from the same source; native x64 runtime validation is not claimed. Real 24-hour scheduling and long-term behavior need ongoing observation.

Build from this project using Node.js/npm for TypeScript and Go 1.25 or newer for the native executables. These are **developer-only dependencies**:

```text
npm ci --ignore-scripts
npm test
# On Linux, from native/: go test ./core
# Cross-build with CGO_ENABLED=0, GOOS=linux, GOARCH=arm64 or amd64.
# Build ./cmd/engine and ./cmd/inspector into bin/linux-arm64 or bin/linux-x64.
npm run package
```

The VSIX file allowlist excludes local toolchains, tests, operational evidence, SSH settings and unrelated projects. The included source and licenses can be reviewed before installing.
