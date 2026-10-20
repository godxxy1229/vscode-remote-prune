import * as vscode from 'vscode';
import { spawn } from 'node:child_process';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';

interface Item { key: string; version?: string; allocated_bytes?: number; reason: string }
interface Auto { next_at: number; suspended: string | null }
interface Result { items?: Item[]; eligible?: string[]; auto?: Auto | null; [key: string]: unknown }

export function supported(platform: string, remoteName: string | undefined): boolean {
  return platform === 'linux' && remoteName === 'ssh-remote';
}

export function nextDelay(auto: Auto | null | undefined, now: number, initial: boolean): number | undefined {
  if (!auto || auto.suspended || !Number.isFinite(auto.next_at) || !Number.isFinite(now)) return undefined;
  const remaining = auto.next_at * 1000 - now;
  return remaining <= 0 ? (initial ? 60000 : 1000) : Math.max(1000, remaining);
}

export function activate(context: vscode.ExtensionContext): void {
  const channel = vscode.window.createOutputChannel('Remote Prune');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 49);
  status.command = 'remotePrune.preview';
  status.text = '$(shield) Remote Prune';
  status.tooltip = 'Remote Prune: fixed-scope Linux SSH server cleanup';
  let timer: NodeJS.Timeout | undefined;
  let busy = false;
  let disposed = false;
  let watcher: fs.FSWatcher | undefined;
  let watchTimer: NodeJS.Timeout | undefined;
  let autoSignature = '';
  const engine = path.join(context.extensionPath, 'bin', `linux-${process.arch}`, 'engine');

  async function run(command: string, payload?: unknown): Promise<Result> {
    if (!supported(process.platform, vscode.env.remoteName) || !vscode.workspace.isTrusted) {
      throw new Error('Cleanup is available only in a trusted Linux Remote-SSH workspace.');
    }
    if (busy) throw new Error('Another Remote Prune operation is still running.');
    busy = true;
    try {
      if (!['x64', 'arm64'].includes(process.arch)) throw new Error('This preview supports Linux x64 and ARM64 only.');
      const binary = fs.lstatSync(engine);
      if (!binary.isFile() || binary.isSymbolicLink()) throw new Error('The bundled engine is missing or unsafe.');
      // VSIX archives created on Windows may not retain POSIX execute bits.
      if ((binary.mode & 0o100) === 0) fs.chmodSync(engine, 0o755);
      return await new Promise<Result>((resolve, reject) => {
        // No shell, workspace executable, PATH lookup, user-supplied path or elevation.
        const child = spawn(engine, [command], {
          cwd: context.extensionPath,
          env: { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8', GOMAXPROCS: '1' },
          stdio: ['pipe', 'pipe', 'pipe']
        });
        let output = ''; let excess = false;
        child.stdout.setEncoding('utf8');
        child.stdout.on('data', data => {
          if (output.length + data.length > 6 * 1024 * 1024) excess = true;
          if (!excess) output += data;
        });
        // Do not surface raw tracebacks or unrelated process details.
        child.stderr.resume();
        child.on('error', () => reject(new Error('The bundled Linux engine could not be started. Check host architecture and executable permissions.')));
        child.on('close', code => {
          try {
            if (excess) throw new Error('Engine output exceeded the limit.');
            const value = JSON.parse(output);
            if (code !== 0 || !value.ok) throw new Error(`Operation refused: ${value.reason ?? 'engine_failed'}`);
            resolve(value.result);
          } catch (error) { reject(error); }
        });
        child.stdin.on('error', () => { /* The close handler reports the result. */ });
        child.stdin.end(payload === undefined ? '' : JSON.stringify(payload));
        // A started deletion is not killed on UI cancellation or extension disposal.
        // Its OS lock and write-ahead pending record survive the window lifecycle.
      });
    } finally { busy = false; }
  }

  function display(value: Result): void {
    channel.clear(); channel.appendLine(JSON.stringify(value, null, 2)); channel.show(true);
  }
  function failure(error: unknown): void {
    const message = error instanceof Error ? error.message : 'Operation unavailable.';
    channel.appendLine(message);
    status.text = '$(shield) Prune: review';
    status.tooltip = message;
    void vscode.window.showWarningMessage(`Remote Prune: ${message}`);
  }
  async function schedule(initial = false): Promise<void> {
    if (timer) clearTimeout(timer);
    timer = undefined;
    if (disposed || !supported(process.platform, vscode.env.remoteName)) return;
    if (busy) { timer = setTimeout(() => { void schedule(initial); }, 60000); return; }
    try {
      const value = await run('status');
      const auto = value.auto;
      autoSignature = JSON.stringify(auto);
      if (!watcher) {
        try {
          const stateDirectory = path.join(os.userInfo().homedir, '.remote-prune');
          watcher = fs.watch(stateDirectory, (_event, name) => {
            if (String(name) !== 'state.json' || disposed) return;
            if (watchTimer) clearTimeout(watchTimer);
            watchTimer = setTimeout(() => {
              try {
                const stateFile = path.join(stateDirectory, 'state.json');
                if (fs.lstatSync(stateFile).size > 5 * 1024 * 1024) return;
                const state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
                if (JSON.stringify(state.auto) !== autoSignature) void schedule();
              } catch { /* The next command/attempt reports unreadable state. */ }
            }, 200);
          });
          watcher.on('error', () => { watcher?.close(); watcher = undefined; });
        } catch { /* Scheduling still works in this window without fs.watch. */ }
      }
      status.text = auto?.suspended ? '$(shield) Prune: review' : auto ? '$(shield) Prune: daily' : '$(shield) Prune: manual';
      status.tooltip = auto?.suspended ? `Automatic cleanup paused: ${auto.suspended}`
        : auto ? `Next eligible check: ${new Date(auto.next_at * 1000).toLocaleString()}` : 'Automatic cleanup is disabled.';
      const delay = nextDelay(auto, Date.now(), initial);
      if (delay !== undefined && !disposed) {
        timer = setTimeout(async () => {
          try {
            const report = await run('auto');
            channel.appendLine(JSON.stringify(report));
          } catch (error) { failure(error); }
          await schedule();
        }, Math.min(delay, 2147483647));
      }
    } catch (error) {
      if (error instanceof Error && error.message.includes('another_cleanup_running')) {
        timer = setTimeout(() => { void schedule(initial); }, 60000);
        return;
      }
      // No retry loop for unreadable state; next explicit command/connection retries.
      failure(error);
    }
  }
  function command(id: string, callback: () => Promise<void>): void {
    context.subscriptions.push(vscode.commands.registerCommand(id, async () => {
      try { await callback(); } catch (error) { failure(error); }
      await schedule();
    }));
  }
  command('remotePrune.preview', async () => { display(await run('preview')); });
  command('remotePrune.history', async () => { display(await run('history')); });
  command('remotePrune.cleanup', async () => {
    const report = await run('preview');
    const choices = (report.items ?? []).filter(x => x.reason === 'eligible').map(x => ({
      label: `${x.version} — ${x.key}`, description: `${((x.allocated_bytes ?? 0) / 1048576).toFixed(1)} MiB allocated`, key: x.key
    }));
    if (!choices.length) { display(report); await vscode.window.showInformationMessage('Remote Prune: no eligible unused server installations.'); return; }
    const selected = await vscode.window.showQuickPick(choices, { canPickMany: true, title: 'Choose unused server installations to remove' });
    if (!selected?.length) return;
    const answer = await vscode.window.showWarningMessage(
      `Permanently remove ${selected.length} selected VS Code server installation(s)? They can be downloaded again, but there is no file-level undo. Running versions are rechecked.`,
      { modal: true }, 'Remove Selected');
    if (answer === 'Remove Selected') display(await run('cleanup', { selected: selected.map(x => x.key) }));
  });
  command('remotePrune.enableAuto', async () => {
    const answer = await vscode.window.showWarningMessage(
      'Enable daily server cleanup for this Linux user/host? The first attempt is in 24 hours. All SSH windows share this choice. Cleanup runs only while an extension host is active and permanently removes eligible server binaries after safety checks.',
      { modal: true }, 'Enable on This Host');
    if (answer === 'Enable on This Host') display(await run('enable-auto'));
  });
  command('remotePrune.disableAuto', async () => { display(await run('disable-auto')); });
  context.subscriptions.push(channel, status, { dispose: () => { disposed = true; if (timer) clearTimeout(timer); if (watchTimer) clearTimeout(watchTimer); watcher?.close(); } });
  if (supported(process.platform, vscode.env.remoteName)) { status.show(); void schedule(true); }
}
