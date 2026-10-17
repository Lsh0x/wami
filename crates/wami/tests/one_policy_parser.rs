//! One door for reading a policy document (wami 001): the authorizer, the
//! simulation and every write path read JSON into a `PolicyDocument` through
//! `policy_evaluator::decode_policy_document`, so what one refuses the others
//! refuse. Every place production code in `wami` and `wami-condition`
//! deserializes anything is listed below with the reason it is not a second
//! door; a new one — `from_str`, `from_value`, `from_slice`, `from_reader` or a
//! `deserialize` call — turns this test red until it is classified.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// (file, count, why it is not a policy-reading door)
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "wami/src/service/auth/policy_evaluator.rs",
        1,
        "decode_policy_document: THE door",
    ),
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
        "wami/src/wami/tenant/authorization.rs",
        1,
        "the tenant authorizer, the third evaluator: wami 003",
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
        // wami-condition's `tests.rs` is a test module (`#[cfg(test)] mod tests`).
        if path.ends_with("tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(path).unwrap();
        // Production code only: the tests build documents however they like.
        let production = text.split("#[cfg(test)]").next().unwrap();
        let count = production.lines().filter(|l| is_deserialization(l)).count();
        if count > 0 {
            let relative = path.strip_prefix(&crates).unwrap();
            let key = relative.to_string_lossy().replace('\\', "/");
            found.insert(key, count);
        }
    }
    let known: BTreeMap<String, usize> = KNOWN
        .iter()
        .map(|(file, count, _)| ((*file).to_string(), *count))
        .collect();
    assert_eq!(
        found, known,
        "a deserialization site appeared, moved or went"
    );
}
