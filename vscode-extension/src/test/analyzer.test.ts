import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import { analyzeSorobanSource, looksLikeSorobanSource, CODES, filterBySeverity, SEVERITY_ORDER } from '../analyzer';

// Fixtures live in src/test/fixtures; resolve from compiled output location
const fixturesDir = path.join(__dirname, '..', '..', 'src', 'test', 'fixtures');

function fixture(name: string): string {
  return fs.readFileSync(path.join(fixturesDir, name), 'utf8');
}

describe('looksLikeSorobanSource', () => {
  it('detects #[contractimpl] attribute', () => {
    assert.ok(looksLikeSorobanSource('#[contractimpl]\nimpl Foo {}'));
  });

  it('detects soroban_sdk crate usage', () => {
    assert.ok(looksLikeSorobanSource('use soroban_sdk::Env;'));
  });

  it('detects #[contract] attribute', () => {
    assert.ok(looksLikeSorobanSource('#[contract]\nstruct Foo;'));
  });

  it('returns false for plain Rust with no Soroban markers', () => {
    assert.ok(!looksLikeSorobanSource('fn main() {\n  println!("hello");\n}'));
  });
});

describe('analyzeSorobanSource — auth gap (S001)', () => {
  it('flags a privileged fn missing require_auth', () => {
    const src = fixture('auth_gap.rs');
    const findings = analyzeSorobanSource(src);
    assert.ok(
      findings.some((f) => f.code === CODES.AUTH_GAP),
      `expected S001 finding; got: ${JSON.stringify(findings)}`
    );
  });

  it('does not flag when require_auth is present', () => {
    const src = fixture('safe_contract.rs');
    const findings = analyzeSorobanSource(src);
    assert.ok(
      !findings.some((f) => f.code === CODES.AUTH_GAP),
      `unexpected S001 finding; got: ${JSON.stringify(findings)}`
    );
  });
});

describe('analyzeSorobanSource — unsafe patterns (S002 / S006)', () => {
  it('flags panic! with S002', () => {
    const src = fixture('panic_contract.rs');
    const findings = analyzeSorobanSource(src);
    assert.ok(
      findings.some((f) => f.code === CODES.PANIC_USAGE),
      `expected S002; got: ${JSON.stringify(findings)}`
    );
  });

  it('flags .unwrap() with S006', () => {
    const src = fixture('panic_contract.rs');
    const findings = analyzeSorobanSource(src);
    assert.ok(
      findings.some((f) => f.code === CODES.UNSAFE_PATTERN),
      `expected S006; got: ${JSON.stringify(findings)}`
    );
  });

  it('does not flag commented-out unwrap', () => {
    const src = '// let x = val.unwrap();\nfn safe() {}';
    const findings = analyzeSorobanSource(src);
    assert.ok(!findings.some((f) => f.code === CODES.UNSAFE_PATTERN));
  });
});

describe('analyzeSorobanSource — arithmetic overflow (S003)', () => {
  it('flags unchecked arithmetic inside contractimpl', () => {
    const src = fixture('overflow_contract.rs');
    const findings = analyzeSorobanSource(src);
    assert.ok(
      findings.some((f) => f.code === CODES.ARITHMETIC_OVERFLOW),
      `expected S003; got: ${JSON.stringify(findings)}`
    );
  });

  it('does not flag checked_add', () => {
    const src = fixture('overflow_contract.rs');
    const findings = analyzeSorobanSource(src);
    const overflowFindings = findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW);
    const lines = src.split('\n');
    for (const f of overflowFindings) {
      const lineText = lines[f.line - 1] ?? '';
      assert.ok(
        !lineText.includes('checked_'),
        `S003 should not fire on a line containing checked_: "${lineText}"`
      );
    }
  });

  it('does not flag arithmetic outside contractimpl', () => {
    const src = 'fn helper(a: i128, b: i128) -> i128 { a + b }';
    const findings = analyzeSorobanSource(src);
    assert.ok(!findings.some((f) => f.code === CODES.ARITHMETIC_OVERFLOW));
  });
});

describe('analyzeSorobanSource — deduplication', () => {
  it('does not emit duplicate findings for the same line and code', () => {
    const src = [
      'use soroban_sdk::contractimpl;',
      'struct C;',
      '#[contractimpl]',
      'impl C {',
      '  pub fn bad(a: i128, b: i128) -> i128 { a + b }',
      '}',
    ].join('\n');
    const findings = analyzeSorobanSource(src);
    const keys = findings.map((f) => `${f.line}:${f.code}:${f.message.slice(0, 40)}`);
    const unique = new Set(keys);
    assert.strictEqual(keys.length, unique.size, 'duplicate findings detected');
  });
});

describe('SEVERITY_ORDER', () => {
  it('ranks information < warning < error', () => {
    assert.ok(SEVERITY_ORDER.information < SEVERITY_ORDER.warning);
    assert.ok(SEVERITY_ORDER.warning < SEVERITY_ORDER.error);
  });
});

describe('filterBySeverity', () => {
  const mixed = [
    { line: 1, code: 'S002', severity: 'error' as const, message: 'panic' },
    { line: 2, code: 'S001', severity: 'warning' as const, message: 'auth gap' },
    { line: 3, code: 'S003', severity: 'information' as const, message: 'hint' },
  ];

  it('passes all findings when minSeverity is information', () => {
    assert.strictEqual(filterBySeverity(mixed, 'information').length, 3);
  });

  it('drops information-level findings when minSeverity is warning', () => {
    const result = filterBySeverity(mixed, 'warning');
    assert.strictEqual(result.length, 2);
    assert.ok(result.every((f) => f.severity !== 'information'));
  });

  it('keeps only errors when minSeverity is error', () => {
    const result = filterBySeverity(mixed, 'error');
    assert.strictEqual(result.length, 1);
    assert.strictEqual(result[0].code, 'S002');
  });

  it('returns empty array when no findings meet threshold', () => {
    const infoOnly = [{ line: 1, code: 'S003', severity: 'information' as const, message: 'hint' }];
    assert.deepStrictEqual(filterBySeverity(infoOnly, 'error'), []);
  });

  it('returns empty array for empty input', () => {
    assert.deepStrictEqual(filterBySeverity([], 'warning'), []);
  });
});
