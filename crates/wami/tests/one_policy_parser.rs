//! One door for reading a policy document (wami 001): the authorizer, the
//! simulation, the tenant authorizer and every write path read JSON into a
//! `PolicyDocument` through `policy_evaluator::decode_policy_document`, so
//! what one refuses the others refuse. Every place production code in `wami`
//! and `wami-condition` deserializes anything is listed below: the policy
//! door, which must stay exactly one, and every other deserialization with
//! the reason it is not one. A new site — `from_str`, `from_value`,
//! `from_slice`, `from_reader` or a `deserialize` call — turns this test red
//! until it is classified.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The doors that read a policy document. Exactly one.
const POLICY_DOORS: &[(&str, usize)] = &[("wami/src/service/auth/policy_evaluator.rs", 1)];

/// Every other deserialization: (file, count, why it reads no policy).
const OTHER: &[(&str, usize, &str)] = &[
    ("wami/src/arn/types.rs", 2, "an ARN's text"),
    ("wami/src/wami/tenant/model.rs", 1, "a tenant id's text"),
    (
        "wami/src/wami/identity/identity_provider/operations.rs",
        1,
        "an OIDC discovery document",
    ),
    (
        "wami/src/wami/instance/bootstrap.rs",
        1,
        "assume_role_policy: a trust policy, no PolicyDocument type",
    ),
    (
        "wami/src/wami/policies/permissions_boundary/operations.rs",
        2,
        "the simulation's boundary verdict reads JSON as Value: wami 003",
    ),
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The file without its inline test modules (`#[cfg(test)] mod x { … }`),
/// skipped by brace count — everything else is scanned, code after a test
/// module included.
fn without_test_modules(text: &str) -> String {
    let mut kept = String::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let is_test_module = line.trim() == "#[cfg(test)]"
            && lines
                .peek()
                .is_some_and(|next| next.trim_start().starts_with("mod ") && next.contains('{'));
        if !is_test_module {
            kept.push_str(line);
            kept.push('\n');
            continue;
        }
        let mut depth = 0i64;
        for inner in lines.by_ref() {
            depth += inner.matches('{').count() as i64 - inner.matches('}').count() as i64;
            if depth <= 0 && inner.contains('}') {
                break;
            }
        }
    }
    kept
}

fn is_deserialization(line: &str) -> bool {
    let line = line.trim_start();
    !line.starts_with("//")
        && (["from_str", "from_value", "from_slice", "from_reader"]
            .iter()
            .any(|f| {
                line.contains(&format!("serde_json::{f}")) || line.contains(&format!("{f}::<"))
            })
            || line.contains("::deserialize("))
}

#[test]
fn every_deserialization_in_production_code_is_known_and_one_reads_policies() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    rust_files(&crates.join("wami/src"), &mut files);
    rust_files(&crates.join("wami-condition/src"), &mut files);
    assert!(files.len() > 50, "the scan found {} files", files.len());
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for path in &files {
        // wami-condition's `tests.rs` is an out-of-line test module.
        if path.ends_with("wami-condition/src/tests.rs") {
            continue;
        }
        let production = without_test_modules(&std::fs::read_to_string(path).unwrap());
        let count = production.lines().filter(|l| is_deserialization(l)).count();
        if count > 0 {
            let relative = path.strip_prefix(&crates).unwrap();
            found.insert(relative.to_string_lossy().replace('\\', "/"), count);
        }
    }
    assert_eq!(POLICY_DOORS.len(), 1, "one door reads policies");
    let known: BTreeMap<String, usize> = POLICY_DOORS
        .iter()
        .map(|(file, count)| ((*file).to_string(), *count))
        .chain(
            OTHER
                .iter()
                .map(|(file, count, _)| ((*file).to_string(), *count)),
        )
        .collect();
    assert_eq!(
        found, known,
        "a deserialization site appeared, moved or went"
    );
}
