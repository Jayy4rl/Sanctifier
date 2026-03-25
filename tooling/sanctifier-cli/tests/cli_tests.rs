#![allow(deprecated)]
use assert_cmd::Command;
use jsonschema::JSONSchema;
use std::env;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("sanctifier").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("Usage: sanctifier"));
}

#[test]
fn test_analyze_valid_contract() {
    let mut cmd = Command::cargo_bin("sanctifier").unwrap();
    let fixture_path = env::current_dir()
        .unwrap()
        .join("tests/fixtures/valid_contract.rs");

    cmd.arg("analyze")
        .arg(fixture_path)
        .assert()
        .success()
        .stdout(predicates::str::contains("Static analysis complete."))
        .stdout(predicates::str::contains("No ledger size issues found."))
        .stdout(predicates::str::contains(
            "No storage key collisions found.",
        ));
}

#[test]
fn test_analyze_vulnerable_contract() {
    let mut cmd = Command::cargo_bin("sanctifier").unwrap();
    let fixture_path = env::current_dir()
        .unwrap()
        .join("tests/fixtures/vulnerable_contract.rs");

    cmd.arg("analyze")
        .arg(fixture_path)
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Found potential Authentication Gaps!",
        ))
        .stdout(predicates::str::contains("Found explicit Panics/Unwraps!"))
        .stdout(predicates::str::contains(
            "Found unchecked Arithmetic Operations!",
        ));
}

#[test]
fn test_analyze_json_output() {
    let mut cmd = Command::cargo_bin("sanctifier").unwrap();
    let fixture_path = env::current_dir()
        .unwrap()
        .join("tests/fixtures/valid_contract.rs");

    let assert = cmd
        .arg("analyze")
        .arg(fixture_path)
        .arg("--format")
        .arg("json")
        .assert()
        .success();

    // JSON starts with {
    assert.stdout(predicates::str::starts_with("{"));
}

#[test]
fn test_analyze_empty_macro_heavy() {
    let mut cmd = Command::cargo_bin("sanctifier").unwrap();
    let fixture_path = env::current_dir()
        .unwrap()
        .join("tests/fixtures/macro_heavy.rs");

    cmd.arg("analyze")
        .arg(fixture_path)
        .assert()
        .success()
        .stdout(predicates::str::contains("Static analysis complete."));
}

#[test]
fn test_init_creates_sanctify_toml_in_current_directory() {
    let temp_dir = tempdir().unwrap();
    let mut cmd = Command::cargo_bin("sanctifier").unwrap();

    cmd.current_dir(temp_dir.path())
        .arg("init")
        .assert()
        .success();

    let config_path = temp_dir.path().join(".sanctify.toml");
    assert!(
        config_path.exists(),
        "Expected init command to create .sanctify.toml"
    );
}

#[test]
fn test_init_fails_when_config_exists_without_force() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join(".sanctify.toml");
    fs::write(&config_path, "existing content").unwrap();

    let mut cmd = Command::cargo_bin("sanctifier").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("init")
        .assert()
        .failure();

    let content = fs::read_to_string(&config_path).unwrap();
    assert_eq!(content, "existing content");
}

#[test]
fn test_init_overwrites_when_force_is_set() {
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join(".sanctify.toml");
    fs::write(&config_path, "existing content").unwrap();

    let mut cmd = Command::cargo_bin("sanctifier").unwrap();
    cmd.current_dir(temp_dir.path())
        .arg("init")
        .arg("--force")
        .assert()
        .success();

    let content = fs::read_to_string(&config_path).unwrap();
    assert_ne!(content, "existing content");
    assert!(content.contains("ignore_paths"));
}

/// Verifies that `sanctifier analyze --format json` output conforms to the
/// published JSON Schema at `schemas/analysis-output.json`.
#[test]
fn test_json_output_validates_against_schema() {
    // Locate the schema relative to the workspace root (two levels up from
    // this package's Cargo.toml directory).
    let schema_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/analysis-output.json");
    let schema_text = fs::read_to_string(&schema_path)
        .expect("schemas/analysis-output.json should exist at the workspace root");
    let schema_value: serde_json::Value =
        serde_json::from_str(&schema_text).expect("schema file should be valid JSON");
    let compiled =
        JSONSchema::compile(&schema_value).expect("schema should compile without errors");

    let fixture_path = env::current_dir()
        .unwrap()
        .join("tests/fixtures/vulnerable_contract.rs");

    let output = Command::cargo_bin("sanctifier")
        .unwrap()
        .arg("analyze")
        .arg(fixture_path)
        .arg("--format")
        .arg("json")
        .env_remove("RUST_LOG")
        .output()
        .expect("sanctifier should run");

    let stdout = String::from_utf8(output.stdout).expect("stdout should be UTF-8");
    let instance: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON output should parse");

    let result = compiled.validate(&instance);
    if let Err(errors) = result {
        let messages: Vec<String> = errors.map(|e| e.to_string()).collect();
        panic!(
            "JSON output does not conform to schemas/analysis-output.json:\n{}",
            messages.join("\n")
        );
    }
}
