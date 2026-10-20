# Privacy

Remote Prune sends no telemetry and makes no network requests. It does not read workspace or application data. It reads recognized VS Code server installation files for metadata and integrity checks.

The root-owned inspector reads Linux process metadata only to detect use of fixed server paths. Commands, environment variables, file contents and raw process information are not emitted or stored. Only recognized version names, use/completeness flags, timestamps and helper checksum are returned.

Local state in `~/.remote-prune/state.json` contains installation identities, hashes, preservation reasons, schedule and bounded execution history. No tokens or customer information belong in this state. Up to 30 history entries and 5 MiB total are retained.

VS Code/Marketplace and SSH have their own behavior and privacy policies, separate from this extension.
