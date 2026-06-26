use crate::commands::color as c;
use crate::telemetry::{self, AnalysisTelemetry};
use crate::vulndb::{VulnDatabase, VulnMatch};
use clap::Args;
use colored::*;
#[allow(unused_imports)]
use rayon::prelude::*;
use sanctifier_core::finding_codes;
use sanctifier_core::rules::RuleRegistry;
use sanctifier_core::{Analyzer, SanctifyConfig};
use sha2::{Digest, Sha256};
#[allow(unused_imports)]
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum SeverityLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum AnalysisProfile {
    /// Report all findings; exit 1 on any
    Strict,
    /// Report findings but never exit 1
    Lenient,
    /// Full report mode for security audits
    Audit,
    /// Exit 1 only on critical or high findings
    Ci,
}

impl std::str::FromStr for SeverityLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("unknown severity: {}", other)),
        }
    }
}

impl AnalysisProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Lenient => "lenient",
            Self::Audit => "audit",
            Self::Ci => "ci",
        }
    }
    pub fn description(self) -> &'static str {
        match self {
            Self::Strict => "Report all findings, exit 1 on any",
            Self::Lenient => "Report findings but never exit 1",
            Self::Audit => "Full report mode for security audit output",
            Self::Ci => "Exit 1 only on critical or high findings",
        }
    }
}

#[derive(Args, Debug, Clone)]
pub struct AnalyzeArgs {
    /// Path to the contract directory or Cargo.toml
    #[arg(default_value = ".")]
    pub path: PathBuf,

    #[arg(short, long, default_value = "text")]
    pub format: String,
    /// Limit for ledger entry size in bytes
    #[arg(short, long, default_value = "64000")]
    pub limit: usize,
    /// Path to a custom vulnerability database JSON file
    #[arg(long)]
    pub vuln_db: Option<PathBuf>,
    /// Per-file analysis timeout in seconds (0 = no timeout)
    #[arg(short, long, default_value = "30")]
    pub timeout: u64,
    /// Webhook endpoint(s) to notify when scan completes
    #[arg(long = "webhook-url")]
    pub webhook_urls: Vec<String>,
    /// Return non-zero exit code when findings meet or exceed severity threshold
    #[arg(long)]
    pub exit_code: bool,
    /// Minimum severity threshold for --exit-code (critical|high|medium|low)
    #[arg(long, value_enum, default_value_t = SeverityLevel::High)]
    pub min_severity: SeverityLevel,
    /// Disable incremental analysis cache
    #[arg(short = 'n', long)]
    pub no_cache: bool,
    /// Analysis profile preset — overrides --exit-code and --min-severity when set
    #[arg(long, value_enum)]
    pub profile: Option<AnalysisProfile>,
}

// ── Per-file result container ────────────────────────────────────────────────

/// All findings produced by analysing a single `.rs` file.
#[derive(Default, serde::Serialize, Clone, Debug)]
pub(crate) struct FileAnalysisResult {
    pub(crate) file_path: String,
    pub(crate) collisions: Vec<sanctifier_core::StorageCollisionIssue>,
    pub(crate) size_warnings: Vec<sanctifier_core::SizeWarning>,
    pub(crate) unsafe_patterns: Vec<sanctifier_core::UnsafePattern>,
    pub(crate) auth_gaps: Vec<sanctifier_core::AuthGapIssue>,
    pub(crate) panic_issues: Vec<sanctifier_core::PanicIssue>,
    pub(crate) arithmetic_issues: Vec<sanctifier_core::ArithmeticIssue>,
    pub(crate) custom_matches: Vec<sanctifier_core::CustomRuleMatch>,
    pub(crate) vuln_matches: Vec<VulnMatch>,
    pub(crate) event_issues: Vec<sanctifier_core::EventIssue>,
    pub(crate) unhandled_results: Vec<sanctifier_core::UnhandledResultIssue>,
    pub(crate) upgrade_reports: Vec<sanctifier_core::UpgradeReport>,
    pub(crate) smt_issues: Vec<sanctifier_core::SmtInvariantIssue>,
    pub(crate) truncation_bounds_issues: Vec<sanctifier_core::TruncationBoundsIssue>,
    pub(crate) sep41_checked_contracts: Vec<String>,
    pub(crate) sep41_issues: Vec<sanctifier_core::Sep41Issue>,
    pub(crate) variable_shadowing_violations: Vec<sanctifier_core::RuleViolation>,
    pub(crate) timed_out: bool,
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn exec(args: AnalyzeArgs) -> anyhow::Result<()> {
    let should_exit_on_findings = args.exit_code;
    let found_issues = run_analysis(args)?;
    if found_issues && should_exit_on_findings {
        std::process::exit(1);
    }
    Ok(())
}

/// Run the full analysis and dispatch to the appropriate output format.
pub(crate) fn run_analysis(args: AnalyzeArgs) -> anyhow::Result<bool> {
    if args.format == "ndjson" {
        return stream_ndjson(&args);
    }

    let path = &args.path;
    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }
    if !is_soroban_project(path) {
        eprintln!("No Soroban project found at {:?}", path);
        return Ok(false);
    }

    let start = Instant::now();
    let config = load_config(path);
    let telemetry_enabled = config.telemetry;

    // When a single file is given, scan only that file — not its parent directory.
    let rs_files: Vec<PathBuf> = if path.is_file() {
        vec![path.clone()]
    } else {
        collect_rs_files(path, &config.ignore_paths)
    };

    let registry = RuleRegistry::with_default_rules();
    let analyzer = Analyzer::new(config.clone());

    let mut all_violations: Vec<(String, sanctifier_core::RuleViolation)> = Vec::new();
    let mut size_warnings_total: usize = 0;
    let mut collision_total: usize = 0;

    for file_path in &rs_files {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let file_str = file_path.display().to_string();
        eprintln!("Analyzing {}", file_str);
        tracing::debug!(target: "sanctifier", "Scanning Rust source file: {}", file_str);
        for v in registry.run_all(&content) {
            all_violations.push((file_str.clone(), v));
        }
        size_warnings_total += analyzer.analyze_ledger_size(&content).len();
        collision_total += analyzer.scan_storage_collisions(&content).len();
    }

    let total = all_violations.len();
    let duration_ms = start.elapsed().as_millis() as u64;
    if telemetry_enabled {
        let rule_ids = all_violations
            .iter()
            .map(|(_, violation)| violation.rule_name.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let payload = AnalysisTelemetry {
            tool_version: telemetry::sanitize_version(env!("CARGO_PKG_VERSION")),
            duration_ms,
            rule_ids,
        };
        if let Err(err) = telemetry::emit_analysis_telemetry(&payload) {
            warn!(target: "sanctifier", error = %err, "Failed to submit opt-in telemetry");
        }
    }

    // Notify webhooks (non-fatal)
    if !args.webhook_urls.is_empty() {
        use crate::commands::webhook::{
            send_scan_completed_webhooks, ScanWebhookPayload, ScanWebhookSummary,
        };
        let payload = ScanWebhookPayload {
            event: "scan_completed",
            project_path: path.display().to_string(),
            timestamp_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .to_string(),
            summary: ScanWebhookSummary {
                total_findings: total,
                has_critical: all_violations
                    .iter()
                    .any(|(_, v)| matches!(v.severity, sanctifier_core::Severity::Error)),
                has_high: all_violations
                    .iter()
                    .any(|(_, v)| matches!(v.severity, sanctifier_core::Severity::Warning)),
            },
        };
        let _ = send_scan_completed_webhooks(&args.webhook_urls, &payload);
    }

    if args.format == "json" {
        let rule_violations: Vec<serde_json::Value> = all_violations
            .into_iter()
            .map(|(file, v)| {
                serde_json::json!({
                    "file": file,
                    "rule_name": v.rule_name,
                    "severity": format!("{:?}", v.severity),
                    "message": v.message,
                    "location": v.location,
                    "suggestion": v.suggestion,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version": "1.0.0",
                "rule_violations": rule_violations,
                "error_codes": finding_codes::all_finding_codes(),
                "summary": {
                    "total_findings": total,
                    "duration_ms": duration_ms,
                    "version": env!("CARGO_PKG_VERSION"),
                },
            }))?
        );
    } else {
        if let Some(profile) = args.profile {
            println!(
                "{} Profile: {} — {}",
                c::blue("ℹ"),
                c::bold(profile.as_str()),
                profile.description()
            );
        }
        let has_auth = all_violations
            .iter()
            .any(|(_, v)| v.rule_name.contains("auth"));
        let has_panic = all_violations
            .iter()
            .any(|(_, v)| v.rule_name.contains("panic"));
        let has_arith = all_violations
            .iter()
            .any(|(_, v)| v.rule_name.contains("arithmetic") || v.rule_name.contains("overflow"));
        if has_auth {
            println!("Found potential Authentication Gaps!");
        }
        if has_panic {
            println!("Found explicit Panics/Unwraps!");
        }
        if has_arith {
            println!("Found unchecked Arithmetic Operations!");
        }
        if !all_violations.is_empty() {
            println!("\n{} Found {} issue(s):", "⚠️".yellow(), total);
            for (file, v) in &all_violations {
                println!(
                    "   {} [{}] {} — {}",
                    "->".red(),
                    v.rule_name.bold(),
                    file,
                    v.message
                );
                if let Some(s) = &v.suggestion {
                    println!("      Suggestion: {}", s);
                }
            }
        }
        if size_warnings_total == 0 {
            println!("No ledger size issues found.");
        }
        if collision_total == 0 {
            println!("No storage key collisions found.");
        }
        println!("\nStatic analysis complete.");
    }

    Ok(total > 0)
}

/// Stream one NDJSON line per finding immediately after each file is analysed.
/// Downstream tools (CI pipelines, log aggregators) can begin consuming output
/// without waiting for the full workspace scan to complete.
///
/// Each finding line:
/// ```json
/// {"event":"finding","file":"src/lib.rs","rule":"arithmetic_overflow","severity":"Warning","message":"...","location":"fn:5","suggestion":"..."}
/// ```
/// Terminal line:
/// ```json
/// {"event":"done","total_findings":12,"duration_ms":843}
/// ```
fn stream_ndjson(args: &AnalyzeArgs) -> anyhow::Result<bool> {
    let path = &args.path;
    if !is_soroban_project(path) {
        eprintln!("No Soroban project found at {:?}", path);
        return Ok(false);
    }

    let start = Instant::now();
    let config = load_config(path);
    let scan_root = if path.is_file() {
        path.parent().unwrap_or(path).to_path_buf()
    } else {
        path.clone()
    };
    let rs_files = collect_rs_files(&scan_root, &config.ignore_paths);
    let registry = RuleRegistry::with_default_rules();
    let stdout = std::io::stdout();
    let mut total = 0usize;

    for file_path in &rs_files {
        let content = match fs::read_to_string(file_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let file_str = file_path.display().to_string();
        let violations = registry.run_all(&content);

        // Lock stdout once per file so all findings from this file are contiguous.
        let mut out = stdout.lock();
        for v in violations {
            total += 1;
            let line = serde_json::json!({
                "event": "finding",
                "file": file_str,
                "rule": v.rule_name,
                "severity": format!("{:?}", v.severity),
                "message": v.message,
                "location": v.location,
                "suggestion": v.suggestion,
            });
            writeln!(out, "{}", line)?;
        }
        out.flush()?;
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    let mut out = stdout.lock();
    writeln!(
        out,
        "{}",
        serde_json::json!({
            "event": "done",
            "total_findings": total,
            "duration_ms": duration_ms,
        })
    )?;
    out.flush()?;

    Ok(total > 0)
}

#[allow(dead_code)]
fn walk_dir(
    dir: &Path,
    analyzer: &Analyzer,
    collisions: &mut Vec<sanctifier_core::StorageCollisionIssue>,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_dir(&path, analyzer, collisions)?;
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            if let Ok(content) = fs::read_to_string(&path) {
                let file_name = path.display().to_string();
                let mut issues = analyzer.scan_storage_collisions(&content);
                for issue in &mut issues {
                    issue.location = format!("{}:{}", file_name, issue.location);
                }
                collisions.extend(issues);
            }
        }
    }
    Ok(())
}

// ── Analyse one file ─────────────────────────────────────────────────────────

pub(crate) fn analyze_single_file(
    analyzer: &Analyzer,
    vuln_db: &VulnDatabase,
    content: &str,
    file_name: &str,
) -> FileAnalysisResult {
    let mut res = FileAnalysisResult {
        file_path: file_name.to_string(),
        ..Default::default()
    };

    let mut c = analyzer.scan_storage_collisions(content);
    for i in &mut c {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.collisions = c;

    res.size_warnings = analyzer.analyze_ledger_size(content);

    let mut u = analyzer.analyze_unsafe_patterns(content);
    for i in &mut u {
        i.snippet = format!("{}:{}", file_name, i.snippet);
    }
    res.unsafe_patterns = u;

    for g in analyzer.scan_auth_gaps(content) {
        res.auth_gaps.push(sanctifier_core::AuthGapIssue {
            function_name: format!("{}:{}", file_name, g),
            location: file_name.to_string(),
        });
    }

    let mut p = analyzer.scan_panics(content);
    for i in &mut p {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.panic_issues = p;

    let mut a = analyzer.scan_arithmetic_overflow(content);
    for i in &mut a {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.arithmetic_issues = a;

    let tb: Vec<sanctifier_core::TruncationBoundsIssue> = analyzer
        .run_rule(content, "truncation_bounds")
        .into_iter()
        .map(|v| sanctifier_core::TruncationBoundsIssue {
            function_name: String::new(),
            kind: "truncation".to_string(),
            expression: String::new(),
            suggestion: v.suggestion.unwrap_or_default(),
            location: format!("{}:{}", file_name, v.location),
        })
        .collect();
    res.truncation_bounds_issues = tb;

    let mut custom = analyzer.analyze_custom_rules(content);
    for m in &mut custom {
        m.snippet = format!("{}:{}: {}", file_name, m.line, m.snippet);
    }
    res.custom_matches = custom;

    res.vuln_matches = vuln_db.scan(content, file_name);

    let mut e = analyzer.scan_events(content);
    for i in &mut e {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.event_issues = e;

    let mut r = analyzer.scan_unhandled_results(content);
    for i in &mut r {
        i.location = format!("{}:{}", file_name, i.location);
    }
    res.unhandled_results = r;

    // Scan for variable shadowing using the rule system
    let mut vs = analyzer.run_rule(content, "variable_shadowing");
    for v in &mut vs {
        v.location = format!("{}:{}", file_name, v.location);
    }
    res.variable_shadowing_violations = vs;

    let mut up = analyzer.analyze_upgrade_patterns(content);
    for f in &mut up.findings {
        f.location = format!("{}:{}", file_name, f.location);
    }
    res.upgrade_reports.push(up);

    // SMT invariant verification requires the z3 feature; leave empty when not available.
    res.smt_issues = vec![];

    let sep41_report = analyzer.verify_sep41_interface(content);
    if sep41_report.candidate {
        res.sep41_checked_contracts.push(file_name.to_string());
        for mut issue in sep41_report.issues {
            issue.location = format!("{}:{}", file_name, issue.location);
            res.sep41_issues.push(issue);
        }
    }

    res
}

// ── Timeout wrapper ──────────────────────────────────────────────────────────

pub(crate) fn run_with_timeout<F, R>(timeout: Option<Duration>, f: F) -> Option<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    match timeout {
        None => Some(f()),
        Some(dur) => {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(f());
            });
            rx.recv_timeout(dur).ok()
        }
    }
}

// ── File collection ──────────────────────────────────────────────────────────

pub(crate) fn collect_rs_files(dir: &Path, ignore_paths: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    collect_rs_files_inner(dir, ignore_paths, &mut out);
    out
}

fn collect_rs_files_inner(dir: &Path, ignore_paths: &[String], out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if !ignore_paths.iter().any(|p| path.ends_with(p)) {
                collect_rs_files_inner(&path, ignore_paths, out);
            }
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn chrono_timestamp() -> String {
    let now = std::time::SystemTime::now();
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}", secs)
}

pub(crate) fn load_config(path: &Path) -> SanctifyConfig {
    let mut current = if path.is_file() {
        path.parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        path.to_path_buf()
    };
    loop {
        let config_path = current.join(".sanctify.toml");
        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                match toml::from_str(&content) {
                    Ok(config) => return config,
                    Err(e) => {
                        eprintln!("Error: Invalid configuration file at {}\n{}", config_path.display(), e);
                        std::process::exit(1);
                    }
                }
            }
        }
        if !current.pop() {
            break;
        }
    }
    SanctifyConfig::default()
}

pub(crate) fn is_soroban_project(path: &Path) -> bool {
    if path.extension().and_then(|s| s.to_str()) == Some("rs") {
        return true;
    }
    let cargo_toml_path = if path.is_dir() {
        path.join("Cargo.toml")
    } else {
        path.to_path_buf()
    };
    cargo_toml_path.exists()
}

// ── Cache ────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    format!("{:x}", hasher.finalize())
}
