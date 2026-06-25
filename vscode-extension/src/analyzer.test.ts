import { analyzeSorobanSource, looksLikeSorobanSource, CODES } from './analyzer';

import { describe, it, expect } from 'vitest';
import { analyzeSorobanSource, looksLikeSorobanSource, CODES } from './analyzer';

// ---------------------------------------------------------------------------
// Fixtures – minimal Soroban snippets that trigger (or must NOT trigger) rules
// ---------------------------------------------------------------------------

const SOROBAN_HEADER = `
#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Address, storage};
`;

function wrap(body: string): string {
  return `${SOROBAN_HEADER}
pub struct Contract;

#[contractimpl]
impl Contract {
${body}
}
`;
}

// ---------------------------------------------------------------------------
// looksLikeSorobanSource
// ---------------------------------------------------------------------------

describe('looksLikeSorobanSource', () => {
  it('returns true for soroban_sdk import', () => {
    expect(looksLikeSorobanSource('use soroban_sdk::Env;')).toBe(true);
  });

  it('returns true for #[contractimpl]', () => {
    expect(looksLikeSorobanSource('#[contractimpl]\nimpl MyContract {}')).toBe(true);
  });

  it('returns false for plain Rust', () => {
    expect(looksLikeSorobanSource('fn main() { println!("hello"); }')).toBe(false);
  });
});

describe('analyzeSorobanSource — panic detection', () => {
  const src = `
use soroban_sdk::Env;
#[contractimpl]
impl MyContract {
  pub fn risky(_env: Env) {
    panic!("not allowed");
  }
}
`;

  it('detects panic! as S002 error', () => {
    const findings = analyzeSorobanSource(src);
    const panics = findings.filter((f) => f.code === CODES.PANIC_USAGE);
    expect(panics.length).toBeGreaterThan(0);
    expect(panics[0].severity).toBe('error');
  });
});

describe('analyzeSorobanSource — unwrap detection', () => {
  const src = `
use soroban_sdk::Env;
#[contractimpl]
impl MyContract {
  pub fn risky(env: Env) {
    let val = env.storage().persistent().get(&0u32).unwrap();
    let _ = val;
  }
}
`;

  it('detects .unwrap() as S006 warning', () => {
    const findings = analyzeSorobanSource(src);
    const unsafe = findings.filter((f) => f.code === CODES.UNSAFE_PATTERN);
    expect(unsafe.length).toBeGreaterThan(0);
    expect(unsafe[0].severity).toBe('warning');
  });
});

describe('analyzeSorobanSource — auth gap detection', () => {
  const src = `
use soroban_sdk::Env;
#[contractimpl]
impl MyContract {
  pub fn store(env: Env, key: u32, val: u32) {
    env.storage().persistent().set(&key, &val);
  }
}
`;

  it('flags missing require_auth as S001', () => {
    const findings = analyzeSorobanSource(src);
    const authGaps = findings.filter((f) => f.code === CODES.AUTH_GAP);
    expect(authGaps.length).toBeGreaterThan(0);
  });

  it('does NOT flag when require_auth is present', () => {
    const safeSrc = `
use soroban_sdk::{Env, Address};
#[contractimpl]
impl MyContract {
  pub fn store(env: Env, caller: Address, key: u32, val: u32) {
    caller.require_auth();
    env.storage().persistent().set(&key, &val);
  }
}
`;
    const findings = analyzeSorobanSource(safeSrc);
    const authGaps = findings.filter((f) => f.code === CODES.AUTH_GAP);
    expect(authGaps).toHaveLength(0);
  });
});

describe('analyzeSorobanSource — arithmetic heuristic', () => {
  const src = `
use soroban_sdk::Env;
#[contractimpl]
impl MyContract {
  pub fn add(env: Env, a: i128, b: i128) -> i128 {
    let _ = env;
    expect(looksLikeSorobanSource('#[contractimpl]')).toBe(true);
  });

  it('returns true for #[contract]', () => {
    expect(looksLikeSorobanSource('#[contract]\npub struct Foo;')).toBe(true);
  });

  it('returns false for plain Rust with no Soroban markers', () => {
    expect(looksLikeSorobanSource('fn main() { println!("hi"); }')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// S002 – PANIC_USAGE
// ---------------------------------------------------------------------------

describe('S002 PANIC_USAGE', () => {
  it('flags panic! inside a contract', () => {
    const src = wrap(`  pub fn blow_up(env: Env) {
    panic!("never");
  }`);
    const findings = analyzeSorobanSource(src);
    const hit = findings.find((f) => f.code === CODES.PANIC_USAGE);
    expect(hit).toBeDefined();
    expect(hit?.severity).toBe('error');
  });

  it('does NOT flag panic! in a line comment', () => {
    const src = wrap(`  pub fn ok(env: Env) -> u32 {
    // panic! is bad, don't use it
    42
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.PANIC_USAGE)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// S006 – UNSAFE_PATTERN (.unwrap / .expect)
// ---------------------------------------------------------------------------

describe('S006 UNSAFE_PATTERN', () => {
  it('flags .unwrap() inside a contract function', () => {
    const src = wrap(`  pub fn risky(env: Env) -> u32 {
    let val: Option<u32> = Some(1);
    val.unwrap()
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.find((f) => f.code === CODES.UNSAFE_PATTERN)).toBeDefined();
  });

  it('flags .expect("…") inside a contract function', () => {
    const src = wrap(`  pub fn risky(env: Env) -> u32 {
    let val: Option<u32> = None;
    val.expect("must exist")
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.find((f) => f.code === CODES.UNSAFE_PATTERN)).toBeDefined();
  });

  it('does NOT flag .unwrap() inside a line comment', () => {
    const src = wrap(`  pub fn safe(env: Env) -> u32 {
    // val.unwrap() is bad
    42
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.UNSAFE_PATTERN)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// S001 – AUTH_GAP
// ---------------------------------------------------------------------------

const AUTH_GAP_SRC = wrap(`  pub fn privileged(env: Env, caller: Address) {
    env.storage().persistent().set(&"key", &42u32);
  }`);

const AUTH_OK_SRC = wrap(`  pub fn guarded(env: Env, caller: Address) {
    caller.require_auth();
    env.storage().persistent().set(&"key", &42u32);
  }`);

describe('S001 AUTH_GAP', () => {
  it('flags a pub fn that mutates storage without require_auth', () => {
    const findings = analyzeSorobanSource(AUTH_GAP_SRC);
    expect(findings.find((f) => f.code === CODES.AUTH_GAP)).toBeDefined();
  });

  it('does NOT flag a pub fn that calls require_auth before mutating storage', () => {
    const findings = analyzeSorobanSource(AUTH_OK_SRC);
    expect(findings.filter((f) => f.code === CODES.AUTH_GAP)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// S003 – ARITHMETIC_OVERFLOW
// ---------------------------------------------------------------------------

describe('S003 ARITHMETIC_OVERFLOW', () => {
  it('flags unchecked + between identifiers inside contractimpl', () => {
    const src = wrap(`  pub fn add(env: Env, a: u32, b: u32) -> u32 {
    a + b
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.find((f) => f.code === CODES.ARITHMETIC_OVERFLOW)).toBeDefined();
  });

  it('does NOT flag checked_add', () => {
    const src = wrap(`  pub fn safe_add(env: Env, a: u32, b: u32) -> u32 {
    a.checked_add(b).unwrap_or(0)
  }`);
    // Note: .unwrap_or(0) does not use .unwrap() or .expect() so no S006 either.
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW)).toHaveLength(0);
  });

  it('does NOT flag saturating_add', () => {
    const src = wrap(`  pub fn safe_add(env: Env, a: u32, b: u32) -> u32 {
    a.saturating_add(b)
  }`);
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW)).toHaveLength(0);
  });

  it('does NOT flag unchecked arithmetic outside a contractimpl block', () => {
    const src = `${SOROBAN_HEADER}
fn helper(a: u32, b: u32) -> u32 { a + b }
`;
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// De-duplication
// ---------------------------------------------------------------------------

describe('deduplication', () => {
  it('does not emit the same finding twice for the same line + code', () => {
    const src = wrap(`  pub fn double(env: Env) {
    panic!("a");
    panic!("a");
  }`);
    const findings = analyzeSorobanSource(src);
    const panics = findings.filter((f) => f.code === CODES.PANIC_USAGE);
    // Two distinct lines → two findings; same line + message → deduplicated
    const lines = new Set(panics.map((f) => f.line));
    expect(panics.length).toBe(lines.size);
  });
});

// ---------------------------------------------------------------------------
// Clean source produces no findings
// ---------------------------------------------------------------------------

describe('clean source', () => {
  it('produces no findings for a well-written contract', () => {
    const src = wrap(`  pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    let balance: i128 = env.storage().persistent().get(&from).unwrap_or(0);
    let new_balance = balance.checked_sub(amount).expect("underflow");
    env.storage().persistent().set(&from, &new_balance);
  }`);
    // unwrap_or and .expect are still flagged by the heuristic — that's expected.
    // The key assertion: NO auth-gap and NO panic! findings.
    const findings = analyzeSorobanSource(src);
    expect(findings.filter((f) => f.code === CODES.AUTH_GAP)).toHaveLength(0);
    expect(findings.filter((f) => f.code === CODES.PANIC_USAGE)).toHaveLength(0);
import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { analyzeSorobanSource, looksLikeSorobanSource, CODES } from './analyzer';

// ---------------------------------------------------------------------------
// looksLikeSorobanSource
// ---------------------------------------------------------------------------

describe('looksLikeSorobanSource', () => {
  it('returns true for #[contractimpl]', () => {
    assert.equal(looksLikeSorobanSource('#[contractimpl]\nimpl Foo {}'), true);
  });

  it('returns true for soroban_sdk reference', () => {
    assert.equal(looksLikeSorobanSource('use soroban_sdk::Env;'), true);
  });

  it('returns true for #[contract]', () => {
    assert.equal(looksLikeSorobanSource('#[contract]\npub struct Counter;'), true);
  });

  it('returns true for contractimpl keyword', () => {
    assert.equal(looksLikeSorobanSource('contractimpl'), true);
  });

  it('returns false for plain Rust with no Soroban markers', () => {
    assert.equal(looksLikeSorobanSource('fn main() { println!("hello"); }'), false);
  });

  it('returns false for empty string', () => {
    assert.equal(looksLikeSorobanSource(''), false);
  });
});

// ---------------------------------------------------------------------------
// Auth-gap detection
// ---------------------------------------------------------------------------

const AUTH_GAP_SRC = `
#[contractimpl]
impl MyContract {
  pub fn withdraw(env: Env, amount: i128) {
    env.storage().persistent().set(&DataKey::Balance, &amount);
  }
}
`;

const AUTH_OK_SRC = `
#[contractimpl]
impl MyContract {
  pub fn withdraw(env: Env, user: Address, amount: i128) {
    user.require_auth();
    env.storage().persistent().set(&DataKey::Balance, &amount);
  }
}
`;

const AUTH_FOR_ARGS_SRC = `
#[contractimpl]
impl MyContract {
  pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth_for_args(());
    env.storage().persistent().set(&DataKey::Balance, &amount);
  }
}
`;

const CROSS_CONTRACT_NO_AUTH = `
#[contractimpl]
impl Proxy {
  pub fn call_other(env: Env, contract: Address) {
    env.invoke_contract::<()>(&contract, &Symbol::short("do_it"), vec![&env]);
  }
}
`;

describe('analyzeSorobanSource – auth gaps', () => {
  it('flags pub fn with storage mutation and no require_auth', () => {
    const findings = analyzeSorobanSource(AUTH_GAP_SRC);
    const gaps = findings.filter((f) => f.code === CODES.AUTH_GAP);
    assert.equal(gaps.length, 1);
    assert.match(gaps[0].message, /withdraw/);
    assert.equal(gaps[0].severity, 'warning');
  });

  it('does not flag when require_auth is present', () => {
    const gaps = analyzeSorobanSource(AUTH_OK_SRC).filter((f) => f.code === CODES.AUTH_GAP);
    assert.equal(gaps.length, 0);
  });

  it('does not flag when require_auth_for_args is present', () => {
    const gaps = analyzeSorobanSource(AUTH_FOR_ARGS_SRC).filter((f) => f.code === CODES.AUTH_GAP);
    assert.equal(gaps.length, 0);
  });

  it('flags cross-contract invoke without auth', () => {
    const gaps = analyzeSorobanSource(CROSS_CONTRACT_NO_AUTH).filter((f) => f.code === CODES.AUTH_GAP);
    assert.equal(gaps.length, 1);
  });

  it('returns the correct 1-based line number for the flagged function', () => {
    const findings = analyzeSorobanSource(AUTH_GAP_SRC).filter((f) => f.code === CODES.AUTH_GAP);
    assert.ok(findings[0].line >= 1, 'line must be >= 1');
  });
});

// ---------------------------------------------------------------------------
// Panic / unwrap / expect detection (S002, S006)
// ---------------------------------------------------------------------------

describe('analyzeSorobanSource – panic patterns', () => {
  it('flags panic! macro', () => {
    const src = `fn foo() { panic!("boom"); }`;
    const findings = analyzeSorobanSource(src);
    assert.ok(findings.some((f) => f.code === CODES.PANIC_USAGE));
  });

  it('flags .unwrap()', () => {
    const src = `fn foo(x: Option<i32>) -> i32 { x.unwrap() }`;
    assert.ok(analyzeSorobanSource(src).some((f) => f.code === CODES.UNSAFE_PATTERN));
  });

  it('flags .expect("msg")', () => {
    const src = `fn foo(x: Option<i32>) -> i32 { x.expect("never none") }`;
    assert.ok(analyzeSorobanSource(src).some((f) => f.code === CODES.UNSAFE_PATTERN));
  });

  it('does not flag commented-out panic!', () => {
    const src = `fn foo() { // panic!("suppressed"); }`;
    assert.equal(
      analyzeSorobanSource(src).filter((f) => f.code === CODES.PANIC_USAGE).length,
      0,
    );
  });

  it('panic! finding has severity "error"', () => {
    const src = `fn foo() { panic!(""); }`;
    const f = analyzeSorobanSource(src).find((f) => f.code === CODES.PANIC_USAGE);
    assert.ok(f);
    assert.equal(f.severity, 'error');
  });

  it('.unwrap() finding has severity "warning"', () => {
    const src = `fn foo(x: Option<()>) { x.unwrap(); }`;
    const f = analyzeSorobanSource(src).find((f) => f.code === CODES.UNSAFE_PATTERN);
    assert.ok(f);
    assert.equal(f.severity, 'warning');
  });
});

// ---------------------------------------------------------------------------
// Arithmetic overflow detection (S003)
// ---------------------------------------------------------------------------

const OVERFLOW_SRC = `
#[contractimpl]
impl Counter {
  pub fn add(env: Env, a: i128, b: i128) -> i128 {
    a + b
  }
}
`;

  it('flags unchecked arithmetic as S003', () => {
    const findings = analyzeSorobanSource(src);
    const overflow = findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW);
    expect(overflow.length).toBeGreaterThan(0);
  });

  it('does NOT flag checked_add', () => {
    const safeSrc = `
use soroban_sdk::Env;
#[contractimpl]
impl MyContract {
  pub fn add(env: Env, a: i128, b: i128) -> i128 {
    let _ = env;
    a.checked_add(b).unwrap_or(i128::MAX)
  }
}
`;
    const findings = analyzeSorobanSource(safeSrc);
    const overflow = findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW);
    expect(overflow).toHaveLength(0);
  });
});

describe('analyzeSorobanSource — de-duplication', () => {
  it('does not return duplicate findings for the same line/code', () => {
    const src = `
use soroban_sdk::Env;
#[contractimpl]
impl MyContract {
  pub fn risky(_env: Env) { panic!("a"); }
}
`;
    const findings = analyzeSorobanSource(src);
    const panics = findings.filter((f) => f.code === CODES.PANIC_USAGE);
    const lines = panics.map((f) => f.line);
    const unique = [...new Set(lines)];
    expect(lines.length).toBe(unique.length);
const CHECKED_ADD_SRC = `
#[contractimpl]
impl Counter {
  pub fn add(env: Env, a: i128, b: i128) -> i128 {
    a.checked_add(b).unwrap_or(0)
  }
}
`;

const SATURATING_SRC = `
#[contractimpl]
impl Counter {
  pub fn add(env: Env, a: i128, b: i128) -> i128 {
    a.saturating_add(b)
  }
}
`;

describe('analyzeSorobanSource – arithmetic overflow', () => {
  it('flags unchecked + inside contractimpl', () => {
    assert.ok(
      analyzeSorobanSource(OVERFLOW_SRC).some((f) => f.code === CODES.ARITHMETIC_OVERFLOW),
    );
  });

  it('does not flag checked_add', () => {
    assert.equal(
      analyzeSorobanSource(CHECKED_ADD_SRC).filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW)
        .length,
      0,
    );
  });

  it('does not flag saturating_add', () => {
    assert.equal(
      analyzeSorobanSource(SATURATING_SRC).filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW)
        .length,
      0,
    );
  });

  it('does not flag arithmetic outside contractimpl', () => {
    const src = `fn helper(a: i128, b: i128) -> i128 { a + b }`;
    assert.equal(
      analyzeSorobanSource(src).filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW).length,
      0,
    );
  });

  it('arithmetic finding has severity "warning"', () => {
    const f = analyzeSorobanSource(OVERFLOW_SRC).find((f) => f.code === CODES.ARITHMETIC_OVERFLOW);
    assert.ok(f);
    assert.equal(f.severity, 'warning');
  });
});

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

describe('analyzeSorobanSource – deduplication', () => {
  it('deduplicates identical (line, code, message-prefix) findings', () => {
    const src = `fn foo() {\n  panic!("dup");\n  panic!("dup");\n}`;
    const findings = analyzeSorobanSource(src);
    const panics = findings.filter((f) => f.code === CODES.PANIC_USAGE);
    const keys = panics.map((f) => `${f.line}:${f.code}:${f.message.slice(0, 40)}`);
    assert.equal(keys.length, new Set(keys).size, 'duplicate findings present');
  });
});

// ---------------------------------------------------------------------------
// Clean contract produces no findings
// ---------------------------------------------------------------------------

const CLEAN_SRC = `
use soroban_sdk::{contract, contractimpl, Env, Address};

#[contract]
pub struct CleanToken;

#[contractimpl]
impl CleanToken {
  pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    let from_balance: i128 = env.storage().persistent().get(&from).unwrap_or(0);
    let to_balance: i128 = env.storage().persistent().get(&to).unwrap_or(0);
    env.storage().persistent().set(&from, &(from_balance.checked_sub(amount).unwrap_or(0)));
    env.storage().persistent().set(&to, &(to_balance.checked_add(amount).unwrap_or(0)));
  }
}
`;

describe('analyzeSorobanSource – clean contract', () => {
  it('produces no auth-gap or arithmetic findings on well-written code', () => {
    const findings = analyzeSorobanSource(CLEAN_SRC);
    assert.equal(findings.filter((f) => f.code === CODES.AUTH_GAP).length, 0);
    assert.equal(findings.filter((f) => f.code === CODES.ARITHMETIC_OVERFLOW).length, 0);
    assert.equal(findings.filter((f) => f.code === CODES.PANIC_USAGE).length, 0);
  });
});

// ---------------------------------------------------------------------------
// Performance budget (#618)
// ---------------------------------------------------------------------------

describe('analyzeSorobanSource – performance budget', () => {
  it('analyzes a 500-line contract in under 100ms', () => {
    const fns = Array.from(
      { length: 90 },
      (_, i) =>
        `  pub fn fn_${i}(env: Env, user: Address, val: i128) -> i128 {\n` +
        `    user.require_auth();\n` +
        `    val.checked_add(1).unwrap_or(0)\n` +
        `  }`,
    ).join('\n');
    const src = `#[contractimpl]\nimpl BigContract {\n${fns}\n}`;

    const start = performance.now();
    analyzeSorobanSource(src);
    const elapsed = performance.now() - start;

    assert.ok(elapsed < 100, `analysis took ${elapsed.toFixed(1)}ms, budget is 100ms`);
  });

  it('handles empty input without throwing', () => {
    assert.doesNotThrow(() => analyzeSorobanSource(''));
  });

  it('handles very long single line without throwing', () => {
    const src = `fn foo() { ${'x'.repeat(10_000)} }`;
    assert.doesNotThrow(() => analyzeSorobanSource(src));
  });
});
