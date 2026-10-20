// Build bundled Linux executables locally; never installs or invokes them.
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');

const root = path.resolve(__dirname, '..');
for (const [directory, goarch] of [['linux-arm64', 'arm64'], ['linux-x64', 'amd64']]) {
  const output = path.join(root, 'bin', directory);
  fs.mkdirSync(output, {recursive: true});
  for (const command of ['engine', 'inspector']) {
    const result = spawnSync('go', [
      'build', '-trimpath', '-ldflags=-s -w',
      '-o', path.join(output, command), `./cmd/${command}`
    ], {
      cwd: path.join(root, 'native'),
      env: {...process.env, GOOS: 'linux', GOARCH: goarch, CGO_ENABLED: '0', GOWORK: 'off'},
      stdio: 'inherit',
      shell: false
    });
    if (result.error) {
      console.error('Could not start Go. Install Go 1.25+ and add it to PATH.');
      process.exit(1);
    }
    if (result.status !== 0) process.exit(result.status || 1);
    console.log(`Built ${directory}/${command}`);
  }
}
