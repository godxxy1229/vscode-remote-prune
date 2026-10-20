# Remote Prune

Clean old **VS Code Stable server installations** on Linux Remote-SSH hosts. Keeps every running version, the newest unused version, and installations observed or changed within 24 hours.

**No Python or separate runtime installation.** Supports Linux ARM64 and x64. Install in the SSH host with Workspace Trust enabled.

## Setup

A host administrator must install the bundled **read-only process inspector** before cleanup. From the installed extension directory, review the helper and installer, then run:

```sh
# ARM64; use linux-x64 for x86_64 hosts.
sha256sum bin/linux-arm64/inspector
sudo sh scripts/install-helper.sh YOUR_SSH_USERNAME REVIEWED_SHA256
```

The installer adds a root-owned inspector and a sudo rule for that command only, without arguments. Deletion runs as your SSH user. Incomplete safety checks prevent cleanup.

## Use

Open the Command Palette and search **Remote Prune**:

- **Preview Server Cleanup** — candidates and preservation reasons.
- **Clean Selected Server Versions** — review and confirm deletion.
- **Show Cleanup History** — recent results.
- **Enable / Disable Daily Cleanup on This Host** — optional automation.

Automatic cleanup is **off by default**. When enabled, it starts after 24 hours and runs only while the remote extension host is active. An overdue reconnect triggers one check after 60 seconds. Updates require revalidation and re-enabling.

## Limits

- Only recognized Stable servers under `~/.vscode-server` are eligible. Extensions, logs, caches, workspaces, databases and backups are untouched. Custom roots, Insiders, WSL and containers are unsupported.
- **Deletion is permanent.** Interrupted cleanup is left for review, never automatically resumed. Disable daily cleanup before recovery or uninstalling.
- No telemetry or network requests. Preview validated on AWS ARM64; x64 is cross-built, not runtime-tested. Real daily scheduling and long-term stability remain unverified.

Detailed setup, recovery and technical notes are included in **USAGE.md** and **PRIVACY.md** in the installed extension folder. See [BUILDING.md](https://github.com/godxxy1229/vscode-remote-prune/blob/main/BUILDING.md) to build from source.
