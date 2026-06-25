// Minimal VS Code API stub for unit tests (jest environment — no real VS Code available).
export const window = {
  showWarningMessage: jest.fn(),
  showErrorMessage: jest.fn(),
  showInformationMessage: jest.fn(),
  showSaveDialog: jest.fn(),
  showOpenDialog: jest.fn(),
  activeTextEditor: undefined,
};

export const workspace = {
  getConfiguration: jest.fn(() => ({
    get: jest.fn(),
  })),
  workspaceFolders: undefined,
  findFiles: jest.fn(() => Promise.resolve([])),
  openTextDocument: jest.fn(),
  textDocuments: [],
  onDidChangeTextDocument: jest.fn(() => ({ dispose: jest.fn() })),
  onDidOpenTextDocument: jest.fn(() => ({ dispose: jest.fn() })),
  onDidCloseTextDocument: jest.fn(() => ({ dispose: jest.fn() })),
  onDidChangeConfiguration: jest.fn(() => ({ dispose: jest.fn() })),
};

export const languages = {
  createDiagnosticCollection: jest.fn(() => ({
    set: jest.fn(),
    delete: jest.fn(),
    clear: jest.fn(),
    dispose: jest.fn(),
  })),
};

export const commands = {
  registerCommand: jest.fn(() => ({ dispose: jest.fn() })),
};

export class Uri {
  static file(p: string): Uri { return new Uri(p); }
  static parse(s: string): Uri { return new Uri(s); }
  constructor(public fsPath: string) {}
  toString() { return `file://${this.fsPath}`; }
}

export enum DiagnosticSeverity {
  Error = 0,
  Warning = 1,
  Information = 2,
  Hint = 3,
}

export class Range {
  constructor(
    public startLine: number,
    public startCharacter: number,
    public endLine: number,
    public endCharacter: number
  ) {}
}

export class Diagnostic {
  public code?: string;
  public source?: string;
  constructor(
    public range: Range,
    public message: string,
    public severity: DiagnosticSeverity
  ) {}
}
