use soroban_sdk::Env;
use syn::{parse_str, File, Item, Type, Fields, Meta, ExprMethodCall, Macro};
use syn::visit::{self, Visit};
use syn::spanned::Spanned;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashSet;

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SanctifyConfig {
    pub ignore_paths: Vec<String>,
    pub enabled_rules: Vec<String>,
    pub ledger_limit: usize,
    pub strict_mode: bool,
}

impl Default for SanctifyConfig {
    fn default() -> Self {
        Self {
            ignore_paths: vec!["target".to_string(), ".git".to_string()],
            enabled_rules: vec![
                "auth_gaps".to_string(),
                "panics".to_string(),
                "arithmetic".to_string(),
                "ledger_size".to_string(),
            ],
            ledger_limit: 64000,
            strict_mode: false,
        }
    }
}

// ── Existing types ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct SizeWarning {
    pub struct_name: String,
    pub estimated_size: usize,
    pub limit: usize,
}

#[derive(Debug, Serialize, Clone, Copy)]
pub enum PatternType {
    Panic,
    Unwrap,
    Expect,
}

#[derive(Debug, Serialize, Clone)]
pub struct UnsafePattern {
    pub pattern_type: PatternType,
    pub line: usize,
    pub snippet: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct PanicIssue {
    pub function_name: String,
    pub issue_type: String, // "panic!", "unwrap", "expect"
    pub location: String,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("invariant violation: {0}")]
    InvariantViolation(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub trait SanctifiedGuard {
    fn check_invariant(&self, env: &Env) -> Result<(), Error>;
}

// ── ArithmeticIssue ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct ArithmeticIssue {
    pub function_name: String,
    pub operation: String,
    pub suggestion: String,
    pub location: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    pub severity: String,
    pub file: String,
    pub line: usize,
    pub message: String,
}

// ── Analyzer ──────────────────────────────────────────────────────────────────

pub struct Analyzer {
    pub config: SanctifyConfig,
}

impl Analyzer {
    pub fn new(config: SanctifyConfig) -> Self {
        Self { config }
    }

    pub fn scan_auth_gaps(&self, source: &str) -> Vec<String> {
        let file = match parse_str::<File>(source) {
            Ok(f) => f,
            Err(_) => return vec![],
        };
        let mut gaps = Vec::new();
        for item in file.items {
            if let Item::Impl(i) = item {
                for impl_item in &i.items {
                    if let syn::ImplItem::Fn(f) = impl_item {
                        if let syn::Visibility::Public(_) = f.vis {
                            let mut has_mutation = false;
                            let mut has_auth = false;
                            self.check_fn_body(&f.block, &mut has_mutation, &mut has_auth);
                            if has_mutation && !has_auth {
                                gaps.push(f.sig.ident.to_string());
                            }
                        }
                    }
                }
            }
        }
        gaps
    }

    pub fn scan_panics(&self, source: &str) -> Vec<PanicIssue> {
        let file = match parse_str::<File>(source) {
            Ok(f) => f,
            Err(_) => return vec![],
        };
        let mut issues = Vec::new();
        for item in file.items {
            if let Item::Impl(i) = item {
                for impl_item in &i.items {
                    if let syn::ImplItem::Fn(f) = impl_item {
                        let fn_name = f.sig.ident.to_string();
                        self.check_fn_panics(&f.block, &fn_name, &mut issues);
                    }
                }
            }
        }
        issues
    }

    fn check_fn_panics(&self, block: &syn::Block, fn_name: &str, issues: &mut Vec<PanicIssue>) {
        for stmt in &block.stmts {
            match stmt {
                syn::Stmt::Expr(expr, _) => self.check_expr_panics(expr, fn_name, issues),
                syn::Stmt::Local(local) => {
                    if let Some(init) = &local.init { self.check_expr_panics(&init.expr, fn_name, issues); }
                }
                syn::Stmt::Macro(m) => {
                    if m.mac.path.is_ident("panic") {
                        issues.push(PanicIssue { function_name: fn_name.to_string(), issue_type: "panic!".to_string(), location: fn_name.to_string() });
                    }
                }
                _ => {}
            }
        }
    }

    fn check_expr_panics(&self, expr: &syn::Expr, fn_name: &str, issues: &mut Vec<PanicIssue>) {
        match expr {
            syn::Expr::Macro(m) => {
                if m.mac.path.is_ident("panic") {
                    issues.push(PanicIssue { function_name: fn_name.to_string(), issue_type: "panic!".to_string(), location: fn_name.to_string() });
                }
            }
            syn::Expr::MethodCall(m) => {
                let method_name = m.method.to_string();
                if method_name == "unwrap" || method_name == "expect" {
                    issues.push(PanicIssue { function_name: fn_name.to_string(), issue_type: method_name, location: fn_name.to_string() });
                }
                self.check_expr_panics(&m.receiver, fn_name, issues);
                for arg in &m.args { self.check_expr_panics(arg, fn_name, issues); }
            }
            syn::Expr::Call(c) => { for arg in &c.args { self.check_expr_panics(arg, fn_name, issues); } }
            syn::Expr::Block(b) => self.check_fn_panics(&b.block, fn_name, issues),
            syn::Expr::If(i) => {
                self.check_expr_panics(&i.cond, fn_name, issues);
                self.check_fn_panics(&i.then_branch, fn_name, issues);
                if let Some((_, else_expr)) = &i.else_branch { self.check_expr_panics(else_expr, fn_name, issues); }
            }
            syn::Expr::Match(m) => {
                self.check_expr_panics(&m.expr, fn_name, issues);
                for arm in &m.arms { self.check_expr_panics(&arm.body, fn_name, issues); }
            }
            _ => {}
        }
    }

    fn check_fn_body(&self, block: &syn::Block, has_mutation: &mut bool, has_auth: &mut bool) {
        for stmt in &block.stmts {
            match stmt {
                syn::Stmt::Expr(expr, _) => self.check_expr(expr, has_mutation, has_auth),
                syn::Stmt::Local(local) => {
                    if let Some(init) = &local.init { self.check_expr(&init.expr, has_mutation, has_auth); }
                }
                syn::Stmt::Macro(m) => {
                    if m.mac.path.is_ident("require_auth") || m.mac.path.is_ident("require_auth_for_args") {
                        *has_auth = true;
                    }
                }
                _ => {}
            }
        }
    }

    fn check_expr(&self, expr: &syn::Expr, has_mutation: &mut bool, has_auth: &mut bool) {
        match expr {
            syn::Expr::Call(c) => {
                if let syn::Expr::Path(p) = &*c.func {
                    if let Some(segment) = p.path.segments.last() {
                        let ident = segment.ident.to_string();
                        if ident == "require_auth" || ident == "require_auth_for_args" { *has_auth = true; }
                    }
                }
                for arg in &c.args { self.check_expr(arg, has_mutation, has_auth); }
            }
            syn::Expr::MethodCall(m) => {
                let method_name = m.method.to_string();
                if method_name == "set" || method_name == "update" || method_name == "remove" {
                    let receiver_str = quote::quote!(#m.receiver).to_string();
                    if receiver_str.contains("storage") || receiver_str.contains("persistent") || receiver_str.contains("temporary") || receiver_str.contains("instance") {
                        *has_mutation = true;
                    }
                }
                if method_name == "require_auth" || method_name == "require_auth_for_args" { *has_auth = true; }
                self.check_expr(&m.receiver, has_mutation, has_auth);
                for arg in &m.args { self.check_expr(arg, has_mutation, has_auth); }
            }
            syn::Expr::Block(b) => self.check_fn_body(&b.block, has_mutation, has_auth),
            syn::Expr::If(i) => {
                self.check_expr(&i.cond, has_mutation, has_auth);
                self.check_fn_body(&i.then_branch, has_mutation, has_auth);
                if let Some((_, else_expr)) = &i.else_branch { self.check_expr(else_expr, has_mutation, has_auth); }
            }
            syn::Expr::Match(m) => {
                self.check_expr(&m.expr, has_mutation, has_auth);
                for arm in &m.arms { self.check_expr(&arm.body, has_mutation, has_auth); }
            }
            _ => {}
        }
    }

    pub fn check_storage_collisions(&self, _keys: Vec<String>) -> bool { false }

    pub fn analyze_ledger_size(&self, source: &str) -> Vec<SizeWarning> {
        let file = match parse_str::<File>(source) { Ok(f) => f, Err(_) => return vec![], };
        let mut warnings = Vec::new();
        for item in file.items {
            if let Item::Struct(s) = item {
                let has_contracttype = s.attrs.iter().any(|attr| {
                    if let Meta::Path(path) = &attr.meta { path.is_ident("contracttype") || path.segments.iter().any(|s| s.ident == "contracttype") } else { false }
                });
                if has_contracttype {
                    let size = self.estimate_struct_size(&s);
                    if size > self.config.ledger_limit || (self.config.strict_mode && size > self.config.ledger_limit / 2) {
                        warnings.push(SizeWarning { struct_name: s.ident.to_string(), estimated_size: size, limit: self.config.ledger_limit });
                    }
                }
            }
        }
        warnings
    }

    pub fn analyze_unsafe_patterns(&self, source: &str) -> Vec<UnsafePattern> {
        let file = match parse_str::<File>(source) { Ok(f) => f, Err(_) => return vec![], };
        let mut visitor = UnsafeVisitor { patterns: Vec::new() };
        visitor.visit_file(&file);
        visitor.patterns
    }

    pub fn scan_arithmetic_overflow(&self, source: &str) -> Vec<ArithmeticIssue> {
        let file = match parse_str::<File>(source) { Ok(f) => f, Err(_) => return vec![], };
        let mut visitor = ArithVisitor { issues: Vec::new(), current_fn: None, seen: HashSet::new() };
        visitor.visit_file(&file);
        visitor.issues
    }

    fn estimate_struct_size(&self, s: &syn::ItemStruct) -> usize {
        let mut total = 0;
        match &s.fields {
            Fields::Named(fields) => { for f in &fields.named { total += self.estimate_type_size(&f.ty); } }
            Fields::Unnamed(fields) => { for f in &fields.unnamed { total += self.estimate_type_size(&f.ty); } }
            Fields::Unit => {}
        }
        total
    }

    fn estimate_type_size(&self, ty: &Type) -> usize {
        match ty {
            Type::Path(tp) => {
                if let Some(seg) = tp.path.segments.last() {
                    match seg.ident.to_string().as_str() {
                        "u32" | "i32" | "bool" => 4,
                        "u64" | "i64" => 8,
                        "u128" | "i128" | "I128" | "U128" => 16,
                        "Address" => 32,
                        "Bytes" | "BytesN" | "String" | "Symbol" => 64,
                        "Vec" | "Map" => 128,
                        _ => 32,
                    }
                } else { 8 }
            }
            _ => 8,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_with_limit() {
        let mut config = SanctifyConfig::default();
        config.ledger_limit = 50;
        let analyzer = Analyzer::new(config);
        let source = r#"
            #[contracttype]
            pub struct ExceedsLimit {
                pub buffer: Bytes, // 64 bytes estimated
            }
        "#;
        let warnings = analyzer.analyze_ledger_size(source);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].struct_name, "ExceedsLimit");
        assert_eq!(warnings[0].estimated_size, 64);
    }

    #[test]
    fn test_scan_auth_gaps() {
        let analyzer = Analyzer::new(SanctifyConfig::default());
        let source = r#"
            #[contractimpl]
            impl MyContract {
                pub fn set_data(env: Env, val: u32) {
                    env.storage().instance().set(&DataKey::Val, &val);
                }
            }
        "#;
        let gaps = analyzer.scan_auth_gaps(source);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0], "set_data");
    }
}

// ── Visitors ──────────────────────────────────────────────────────────────────

struct UnsafeVisitor {
    patterns: Vec<UnsafePattern>,
}

impl<'ast> Visit<'ast> for UnsafeVisitor {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("panic") {
            let line = node.path.get_ident().map(|i| i.span().start().line).unwrap_or(0);
            self.patterns.push(UnsafePattern { pattern_type: PatternType::Panic, line, snippet: "panic!()".to_string() });
        }
        visit::visit_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if method == "unwrap" || method == "expect" {
            let line = node.method.span().start().line;
            let pattern_type = if method == "unwrap" { PatternType::Unwrap } else { PatternType::Expect };
            self.patterns.push(UnsafePattern { pattern_type, line, snippet: format!(".{}()", method) });
        }
        visit::visit_expr_method_call(self, node);
    }
}

struct ArithVisitor {
    issues: Vec<ArithmeticIssue>,
    current_fn: Option<String>,
    seen: HashSet<(String, String)>,
}

impl ArithVisitor {
    fn classify_op(op: &syn::BinOp) -> Option<(&'static str, &'static str)> {
        match op {
            syn::BinOp::Add(_) => Some(("+", "Use `.checked_add()`")),
            syn::BinOp::Sub(_) => Some(("-", "Use `.checked_sub()`")),
            syn::BinOp::Mul(_) => Some(("*", "Use `.checked_mul()`")),
            syn::BinOp::AddAssign(_) => Some(("+=", "Replace with checked_add")),
            syn::BinOp::SubAssign(_) => Some(("-=", "Replace with checked_sub")),
            syn::BinOp::MulAssign(_) => Some(("*=", "Replace with checked_mul")),
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for ArithVisitor {
    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let prev = self.current_fn.take();
        self.current_fn = Some(node.sig.ident.to_string());
        visit::visit_impl_item_fn(self, node);
        self.current_fn = prev;
    }
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let prev = self.current_fn.take();
        self.current_fn = Some(node.sig.ident.to_string());
        visit::visit_item_fn(self, node);
        self.current_fn = prev;
    }
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if let Some(fn_name) = self.current_fn.clone() {
            if let Some((op_str, suggestion)) = Self::classify_op(&node.op) {
                if !is_string_literal(&node.left) && !is_string_literal(&node.right) {
                    let key = (fn_name.clone(), op_str.to_string());
                    if !self.seen.contains(&key) {
                        self.seen.insert(key);
                        let line = node.left.span().start().line;
                        self.issues.push(ArithmeticIssue { function_name: fn_name.clone(), operation: op_str.to_string(), suggestion: suggestion.to_string(), location: format!("{}:{}", fn_name, line) });
                    }
                }
            }
        }
        visit::visit_expr_binary(self, node);
    }
}

fn is_string_literal(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(_), .. }))
}
