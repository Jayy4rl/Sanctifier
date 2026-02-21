use clap::{Parser, Subcommand};
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};
use sanctifier_core::{Analyzer, ArithmeticIssue, SizeWarning, UnsafePattern, PatternType, Finding, SanctifyConfig};

#[derive(Parser)]
#[command(name = "sanctifier")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a Soroban contract
    Analyze {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(short, long, default_value = "text")]
        format: String,
        #[arg(short, long, default_value = "64000")]
        limit: usize,
    },
    /// Initialize Sanctifier
    Init,
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Analyze { path, format, limit } => {
            let is_json = format == "json";
            if !is_soroban_project(path) { eprintln!("{} Error: {:?} is not a valid Soroban project.", "❌".red(), path); std::process::exit(1); }
            let mut config = if Path::new(".sanctify.toml").exists() {
                let content = fs::read_to_string(".sanctify.toml").unwrap_or_default();
                toml::from_str(&content).unwrap_or_else(|_| SanctifyConfig::default())
            } else { SanctifyConfig::default() };
            if *limit != 64000 { config.ledger_limit = *limit; }
            if is_json { eprintln!("{} Analyzing contract at {:?}...", "🔍".blue(), path); } else { println!("{} Analyzing contract at {:?}...", "🔍".blue(), path); }
            let analyzer = Analyzer::new(config);
            let mut all_size_warnings = Vec::new();
            let mut all_unsafe_patterns = Vec::new();
            let mut all_auth_gaps = Vec::new();
            let mut all_panic_issues = Vec::new();
            let mut all_arithmetic_issues = Vec::new();
            if path.is_dir() {
                analyze_directory(path, &analyzer, &mut all_size_warnings, &mut all_unsafe_patterns, &mut all_auth_gaps, &mut all_panic_issues, &mut all_arithmetic_issues);
            } else {
                if let Ok(content) = fs::read_to_string(path) {
                    all_size_warnings.extend(analyzer.analyze_ledger_size(&content));
                    let p = analyzer.analyze_unsafe_patterns(&content);
                    for mut x in p { x.snippet = format!("{}: {}", path.display(), x.snippet); all_unsafe_patterns.push(x); }
                    let g = analyzer.scan_auth_gaps(&content);
                    for x in g { all_auth_gaps.push(format!("{}: {}", path.display(), x)); }
                    let pan = analyzer.scan_panics(&content);
                    for x in pan { let mut m = x.clone(); m.location = format!("{}: {}", path.display(), m.location); all_panic_issues.push(m); }
                    let ar = analyzer.scan_arithmetic_overflow(&content);
                    for mut x in ar { x.location = format!("{}: {}", path.display(), x.location); all_arithmetic_issues.push(x); }
                }
            }
            if is_json {
                let mut findings = Vec::new();
                for w in &all_size_warnings { findings.push(Finding { severity: "warning".to_string(), file: w.struct_name.clone(), line: 0, message: format!("Ledger size warning: estimated {} bytes", w.estimated_size) }); }
                for p in &all_unsafe_patterns { findings.push(Finding { severity: "warning".to_string(), file: p.snippet.clone(), line: p.line, message: "Unsafe pattern detected".to_string() }); }
                for g in &all_auth_gaps { findings.push(Finding { severity: "error".to_string(), file: g.clone(), line: 0, message: "Potential authentication gap".to_string() }); }
                for p in &all_panic_issues { findings.push(Finding { severity: "warning".to_string(), file: p.location.clone(), line: 0, message: format!("Explicit panic: {}", p.issue_type) }); }
                for a in &all_arithmetic_issues { findings.push(Finding { severity: "warning".to_string(), file: a.location.clone(), line: 0, message: format!("Unchecked `{}`: {}", a.operation, a.suggestion) }); }
                println!("{}", serde_json::to_string_pretty(&findings).unwrap());
            } else {
                if all_size_warnings.is_empty() && all_unsafe_patterns.is_empty() && all_auth_gaps.is_empty() && all_panic_issues.is_empty() && all_arithmetic_issues.is_empty() { println!("No issues found."); } else {
                    for gap in &all_auth_gaps { println!("{} Auth Gap: {}", "🛑".red(), gap); }
                    for ar in &all_arithmetic_issues { println!("{} Unchecked {}: {} ({})", "🔢".yellow(), ar.operation, ar.suggestion, ar.location); }
                }
            }
        }
        Commands::Init => {
            let config = SanctifyConfig::default();
            let toml = toml::to_string_pretty(&config).unwrap_or_default();
            if !Path::new(".sanctify.toml").exists() { fs::write(".sanctify.toml", toml).ok(); println!("{} Created .sanctify.toml", "✅".green()); } else { println!("{} .sanctify.toml already exists", "⚠️".yellow()); }
        }
    }
}

fn is_soroban_project(path: &Path) -> bool {
    let cargo = if path.is_dir() { path.join("Cargo.toml") } else { path.to_path_buf() };
    if !cargo.exists() { return false; }
    fs::read_to_string(cargo).map(|c| c.contains("soroban-sdk")).unwrap_or(false)
}

fn analyze_directory(dir: &Path, analyzer: &Analyzer, all_size_warnings: &mut Vec<SizeWarning>, all_unsafe_patterns: &mut Vec<UnsafePattern>, all_auth_gaps: &mut Vec<String>, all_panic_issues: &mut Vec<sanctifier_core::PanicIssue>, all_arithmetic_issues: &mut Vec<ArithmeticIssue>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() { analyze_directory(&path, analyzer, all_size_warnings, all_unsafe_patterns, all_auth_gaps, all_panic_issues, all_arithmetic_issues); } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                if let Ok(content) = fs::read_to_string(&path) {
                    let w = analyzer.analyze_ledger_size(&content);
                    for mut x in w { x.struct_name = format!("{}: {}", path.display(), x.struct_name); all_size_warnings.push(x); }
                    let p = analyzer.analyze_unsafe_patterns(&content);
                    for mut x in p { x.snippet = format!("{}: {}", path.display(), x.snippet); all_unsafe_patterns.push(x); }
                    let g = analyzer.scan_auth_gaps(&content);
                    for x in g { all_auth_gaps.push(format!("{}: {}", path.display(), x)); }
                    let pan = analyzer.scan_panics(&content);
                    for x in pan { let mut m = x.clone(); m.location = format!("{}: {}", path.display(), m.location); all_panic_issues.push(m); }
                    let ar = analyzer.scan_arithmetic_overflow(&content);
                    for mut x in ar { x.location = format!("{}: {}", path.display(), x.location); all_arithmetic_issues.push(x); }
                }
            }
        }
    }
}
