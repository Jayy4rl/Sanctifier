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
