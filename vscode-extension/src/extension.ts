import * as vscode from 'vscode';
import { analyzeSorobanSource, looksLikeSorobanSource, filterBySeverity, type Severity } from './analyzer';
import { type EditorFinding, type SanctifierExtensionApi } from './types';
import { folderLooksLikeSorobanProject, invalidateWorkspaceCache } from './workspace';
import { spawn } from 'child_process';
import { existsSync } from 'fs';

const SOURCE = 'sanctifier';
const EXTENSION_VERSION: string = (() => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return (require('../package.json') as { version: string }).version;
  } catch {
    return '0.0.0';
  }
})();

function getConfig() {
  return vscode.workspace.getConfiguration('sanctifier');
}

function findingToDiagnostic(doc: vscode.TextDocument, f: EditorFinding): vscode.Diagnostic {
  const lineIdx = Math.max(0, Math.min(doc.lineCount - 1, f.line - 1));
  const line = doc.lineAt(lineIdx);
  const range =
    f.endLine !== undefined
      ? new vscode.Range(
          lineIdx,
          0,
          Math.max(lineIdx, f.endLine - 1),
          f.endCharacter ?? Number.MAX_SAFE_INTEGER
        )
      : new vscode.Range(lineIdx, 0, lineIdx, line.range.end.character || line.text.length);

  const sev =
    f.severity === 'error'
      ? vscode.DiagnosticSeverity.Error
      : f.severity === 'information'
        ? vscode.DiagnosticSeverity.Information
        : vscode.DiagnosticSeverity.Warning;

  const d = new vscode.Diagnostic(range, f.message, sev);
  d.code = f.code;
  d.source = SOURCE;
  return d;
}

export async function activate(context: vscode.ExtensionContext): Promise<SanctifierExtensionApi> {
  const collection = vscode.languages.createDiagnosticCollection(SOURCE);
  const outputChannel = vscode.window.createOutputChannel('Sanctifier');

  /** Live snapshot of findings keyed by document URI string. */
  const findingsCache = new Map<string, EditorFinding[]>();
  /** Last-seen text per document — skip re-analysis when content is unchanged. */
  const contentCache = new Map<string, string>();

  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 10);
  statusBar.command = 'sanctifier.toggleEnable';
  statusBar.tooltip = 'Sanctifier — click to toggle';
  context.subscriptions.push(statusBar, collection, outputChannel);

  function updateStatusBar(): void {
    const enabled = getConfig().get<boolean>('enable') ?? true;
    if (!enabled) {
      statusBar.text = '$(shield) Sanctifier: off';
      statusBar.show();
      return;
    }
    let total = 0;
    for (const findings of findingsCache.values()) {
      total += findings.length;
    }
    statusBar.text = total > 0 ? `$(shield) Sanctifier: ${total}` : '$(shield) Sanctifier';
    statusBar.show();
  }

  const debouncers = new Map<string, ReturnType<typeof setTimeout>>();

  const runAnalysis = (doc: vscode.TextDocument) => {
    if (doc.languageId !== 'rust') {
      return;
    }
    const cfg = getConfig();
    if (!cfg.get<boolean>('enable')) {
      collection.delete(doc.uri);
      findingsCache.delete(doc.uri.toString());
      updateStatusBar();
      return;
    }
    const text = doc.getText();
    if (!looksLikeSorobanSource(text)) {
      collection.delete(doc.uri);
      findingsCache.delete(doc.uri.toString());
      updateStatusBar();
      return;
    }

    const key = doc.uri.toString();
    if (contentCache.get(key) === text) {
      return;
    }
    contentCache.set(key, text);

    const minSeverity = (cfg.get<string>('minSeverity') ?? 'warning') as Severity;
    const allFindings = analyzeSorobanSource(text);
    const findings = filterBySeverity(allFindings, minSeverity);

    findingsCache.set(doc.uri.toString(), findings);
    const diags = findings.map((f) => findingToDiagnostic(doc, f));
    collection.set(doc.uri, diags);
    updateStatusBar();
  };

  const schedule = (doc: vscode.TextDocument) => {
    const onlySorobanWs = getConfig().get<boolean>('onlyInSorobanWorkspace');
    if (onlySorobanWs) {
      const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
      if (!folder) {
        collection.delete(doc.uri);
        findingsCache.delete(doc.uri.toString());
        updateStatusBar();
        return;
      }
    }
    const ms = getConfig().get<number>('debounceMs') ?? 400;
    const key = doc.uri.toString();
    const prev = debouncers.get(key);
    if (prev) {
      clearTimeout(prev);
    }
    debouncers.set(
      key,
      setTimeout(async () => {
        debouncers.delete(key);
        const requireSoroban = getConfig().get<boolean>('onlyInSorobanWorkspace');
        if (requireSoroban) {
          const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
          if (!folder) {
            collection.delete(doc.uri);
            findingsCache.delete(doc.uri.toString());
            updateStatusBar();
            return;
          }
          const ok = await folderLooksLikeSorobanProject(folder);
          if (!ok) {
            collection.delete(doc.uri);
            findingsCache.delete(doc.uri.toString());
            updateStatusBar();
            return;
          }
        }
        runAnalysis(doc);
      }, ms)
    );
  };

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => schedule(e.document)),
    vscode.workspace.onDidOpenTextDocument((d) => schedule(d)),
    vscode.workspace.onDidCloseTextDocument((d) => {
      const k = d.uri.toString();
      collection.delete(d.uri);
      findingsCache.delete(k);
      contentCache.delete(k);
      debouncers.delete(k);
      updateStatusBar();
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      invalidateWorkspaceCache();
      contentCache.clear();
      findingsCache.clear();
      for (const doc of vscode.workspace.textDocuments) {
        schedule(doc);
      }
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('sanctifier')) {
        invalidateWorkspaceCache();
        contentCache.clear();
        findingsCache.clear();
        for (const doc of vscode.workspace.textDocuments) {
          schedule(doc);
        }
      }
    })
  );

  for (const doc of vscode.workspace.textDocuments) {
    schedule(doc);
  }

  // ── Commands ────────────────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand('sanctifier.toggleEnable', async () => {
      const cfg = getConfig();
      const current = cfg.get<boolean>('enable') ?? true;
      await cfg.update('enable', !current, vscode.ConfigurationTarget.Global);
      vscode.window.showInformationMessage(
        `Sanctifier is now ${!current ? 'enabled' : 'disabled'}.`
      );
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('sanctifier.showOutput', () => {
      outputChannel.show(true);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('sanctifier.analyzeWorkspace', async () => {
      const exe = getConfig().get<string>('sanctifierPath')?.trim();
      if (!exe) {
        vscode.window.showWarningMessage(
          'Set sanctifier.sanctifierPath to your sanctifier CLI binary, then run again.'
        );
        return;
      }
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showErrorMessage('Open a folder to analyze.');
        return;
      }

      // Remote workspaces (SSH, Codespaces, WSL) use non-file URIs; the CLI
      // must run on the same machine as the source files.
      if (folder.uri.scheme !== 'file') {
        vscode.window.showErrorMessage(
          'Sanctifier workspace analysis requires a local folder. ' +
          'Remote workspaces (SSH / Codespaces / WSL) are not yet supported — ' +
          'install the CLI on the remote host and run it from the integrated terminal.'
        );
        return;
      }

      if (!existsSync(exe)) {
        vscode.window.showErrorMessage(
          `sanctifier CLI not found at "${exe}". ` +
          'Check the sanctifier.sanctifierPath setting and ensure the binary is installed.'
        );
        return;
      }

      outputChannel.clear();
      outputChannel.show(true);
      outputChannel.appendLine(`[sanctifier] Scanning ${folder.uri.fsPath} …`);

      const minSeverity = (getConfig().get<string>('minSeverity') ?? 'warning') as Severity;

      const output = await new Promise<string | undefined>((resolve) => {
        const p = spawn(
          exe,
          ['analyze', folder.uri.fsPath, '--format', 'json', '--min-severity', minSeverity],
          { cwd: folder.uri.fsPath }
        );
        let out = '';
        let err = '';
        p.stdout.on('data', (b: Buffer) => (out += b.toString()));
        p.stderr.on('data', (b: Buffer) => (err += b.toString()));
        p.on('close', (code) => {
          if (err) {
            outputChannel.appendLine(`[sanctifier][stderr] ${err.trim()}`);
          }
          if (code !== 0 && !out) {
            outputChannel.appendLine(`[sanctifier] CLI exited with code ${code}.`);
            resolve(undefined);
          } else {
            resolve(out || undefined);
          }
        });
        p.on('error', (e) => {
          outputChannel.appendLine(`[sanctifier][error] ${e.message}`);
          resolve(undefined);
        });
      });

      if (!output) {
        vscode.window.showErrorMessage(
          'sanctifier CLI produced no output. Check sanctifierPath and the output channel.'
        );
        return;
      }

      outputChannel.appendLine(output);
      outputChannel.appendLine('[sanctifier] Scan complete.');
    })
  );

  updateStatusBar();

  // ── Public API (stable) ──────────────────────────────────────────────────────
  const api: SanctifierExtensionApi = {
    version: EXTENSION_VERSION,
    getFindings(documentUri: string): EditorFinding[] {
      return findingsCache.get(documentUri) ?? [];
    },
  };

  return api;
}

export function deactivate(): void {
  invalidateWorkspaceCache();
}
