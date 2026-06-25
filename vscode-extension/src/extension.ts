import * as vscode from 'vscode';
import * as fs from 'fs';
import { analyzeSorobanSource, looksLikeSorobanSource, type EditorFinding } from './analyzer';
import { spawn } from 'child_process';

const SOURCE = 'sanctifier';

let sorobanWorkspaceCache: boolean | null = null;

function getConfig() {
  return vscode.workspace.getConfiguration('sanctifier');
}

async function workspaceLooksLikeSorobanProject(): Promise<boolean> {
  if (sorobanWorkspaceCache !== null) {
    return sorobanWorkspaceCache;
  }
  const files = await vscode.workspace.findFiles('**/Cargo.toml', '**/target/**', 40);
  for (const uri of files) {
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const t = doc.getText();
      if (/soroban-sdk|soroban_sdk/.test(t)) {
        sorobanWorkspaceCache = true;
        return true;
      }
    } catch {
      /* skip */
    }
  }
  sorobanWorkspaceCache = false;
  return false;
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

function validateSanctifierPath(exePath: string): void {
  const trimmed = exePath.trim();
  if (!trimmed) {
    return;
  }
  if (!fs.existsSync(trimmed)) {
    vscode.window.showWarningMessage(
      `Sanctifier: sanctifierPath "${trimmed}" was not found on disk. ` +
        'Update sanctifier.sanctifierPath to a valid CLI binary path.',
    );
  }
}

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  const collection = vscode.languages.createDiagnosticCollection(SOURCE);

  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = '$(shield) Sanctifier';
  statusBar.tooltip = 'Sanctifier: Soroban security analysis active';
  statusBar.show();
  context.subscriptions.push(statusBar);

  const debouncers = new Map<string, ReturnType<typeof setTimeout>>();

  const runAnalysis = (doc: vscode.TextDocument) => {
    if (doc.languageId !== 'rust') {
      return;
    }
    const cfg = getConfig();
    if (!cfg.get<boolean>('enable')) {
      collection.delete(doc.uri);
      return;
    }
    const text = doc.getText();
    if (!looksLikeSorobanSource(text)) {
      collection.delete(doc.uri);
      return;
    }

    statusBar.text = '$(sync~spin) Sanctifier: analyzing…';
    const findings = analyzeSorobanSource(text);
    const diags = findings.map((f) => findingToDiagnostic(doc, f));
    collection.set(doc.uri, diags);
    statusBar.text =
      diags.length > 0
        ? `$(shield) Sanctifier (${diags.length} hint${diags.length === 1 ? '' : 's'})`
        : '$(shield) Sanctifier';
  };

  const schedule = (doc: vscode.TextDocument) => {
    const onlySorobanWs = getConfig().get<boolean>('onlyInSorobanWorkspace');
    if (onlySorobanWs && !vscode.workspace.workspaceFolders?.length) {
      collection.delete(doc.uri);
      return;
    }
    const ms = Math.min(5000, Math.max(100, getConfig().get<number>('debounceMs') ?? 400));
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
          const ok = await workspaceLooksLikeSorobanProject();
          if (!ok) {
            collection.delete(doc.uri);
            return;
          }
        }
        runAnalysis(doc);
      }, ms)
    );
  };

  context.subscriptions.push(
    collection,
    vscode.workspace.onDidChangeTextDocument((e) => schedule(e.document)),
    vscode.workspace.onDidOpenTextDocument((d) => schedule(d)),
    vscode.workspace.onDidCloseTextDocument((d) => {
      collection.delete(d.uri);
      debouncers.delete(d.uri.toString());
    }),
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('sanctifier')) {
        sorobanWorkspaceCache = null;
        if (e.affectsConfiguration('sanctifier.sanctifierPath')) {
          validateSanctifierPath(getConfig().get<string>('sanctifierPath') ?? '');
        }
        for (const doc of vscode.workspace.textDocuments) {
          schedule(doc);
        }
      }
    })
  );

  for (const doc of vscode.workspace.textDocuments) {
    schedule(doc);
  }

  context.subscriptions.push(
    vscode.commands.registerCommand('sanctifier.analyzeWorkspace', async () => {
      const exe = getConfig().get<string>('sanctifierPath')?.trim();
      if (!exe) {
        vscode.window.showWarningMessage(
          'Set sanctifier.sanctifierPath to your sanctifier CLI binary, then run again.',
        );
        return;
      }
      if (!fs.existsSync(exe)) {
        vscode.window.showErrorMessage(
          `Sanctifier: binary not found at "${exe}". ` +
            'Update sanctifier.sanctifierPath to a valid path and try again.',
        );
        return;
      }
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showErrorMessage('Open a folder to analyze.');
        return;
      }
      statusBar.text = '$(sync~spin) Sanctifier: running full scan…';
      const { output, stderr } = await new Promise<{ output: string | undefined; stderr: string }>(
        (resolve) => {
          const p = spawn(exe, ['analyze', folder.uri.fsPath, '--format', 'json'], {
            cwd: folder.uri.fsPath,
          });
          let out = '';
          let err = '';
          p.stdout.on('data', (b: Buffer) => (out += b.toString()));
          p.stderr.on('data', (b: Buffer) => (err += b.toString()));
          p.on('close', () => resolve({ output: out || undefined, stderr: err }));
          p.on('error', () => resolve({ output: undefined, stderr: '' }));
        },
      );
      statusBar.text = '$(shield) Sanctifier';
      if (!output) {
        const isWasmFailure =
          /wasm32|wasm-unknown|target.*wasm|error\[E/i.test(stderr);
        if (isWasmFailure) {
          const choice = await vscode.window.showErrorMessage(
            'Sanctifier: WASM compilation failed. ' +
              'Ensure the wasm32 target is installed: `rustup target add wasm32-unknown-unknown`.',
            'Show Error Output',
          );
          if (choice === 'Show Error Output') {
            const errDoc = await vscode.workspace.openTextDocument({
              content: stderr,
              language: 'text',
            });
            await vscode.window.showTextDocument(errDoc, { preview: true });
          }
        } else {
          vscode.window.showErrorMessage(
            'Sanctifier CLI failed or produced no output. ' +
              'Check sanctifier.sanctifierPath and ensure the binary is executable.',
          );
        }
        return;
      }
      const token = output;
      const doc = await vscode.workspace.openTextDocument({
        content: token,
        language: 'json',
      });
      await vscode.window.showTextDocument(doc, { preview: true });
    })
  );
}

export function deactivate(): void {
  sorobanWorkspaceCache = null;
}
