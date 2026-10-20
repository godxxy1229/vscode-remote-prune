# Build from source

Development requires Node.js 22+, npm and Go 1.25+. These tools are **not required on the cleanup host**; the extension bundles its Linux executables.

```sh
git clone https://github.com/godxxy1229/vscode-remote-prune.git
cd vscode-remote-prune
npm ci --ignore-scripts
npm test
npm run build:native
npm run package
node scripts/check-package.cjs
```

`build:native` cross-builds Linux ARM64 and x64 with CGO disabled. It does not execute the cleanup engine or install the privileged inspector. `npm test` compiles TypeScript and runs the extension-host simulations.

Run native tests on a Linux host, **as a non-root user**, using temporary synthetic directories:

```sh
cd native
go test ./core
```

The native suite uses real test processes to exercise file/mapping protection and interruption handling. Prior native validation was on AWS ARM64; Linux x64 was cross-built, not runtime-tested.

Generated `bin/`, `dist/`, VSIX files, `node_modules/`, local toolchains and operational validation records are excluded from Git. The VSIX uses a separate file allowlist in `.vscodeignore`.

The source includes metadata and documentation changes made after the Marketplace 0.1.1 release; building it does not reproduce that published archive byte-for-byte. Review a new package and its checksums before installing. Runtime or package metadata changes pause approved automatic cleanup until revalidation and explicit re-enabling.

The public source repository does not include deployment credentials, production data or host-specific evidence. Review `USAGE.md`, `PRIVACY.md`, `NOTICE` and the licenses before deploying the helper.
