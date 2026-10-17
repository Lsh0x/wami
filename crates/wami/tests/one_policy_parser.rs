//! One door for reading a policy document (wami 001): the authorizer, the
//! simulation and every write path read JSON into a `PolicyDocument` through
//! `policy_evaluator::decode_policy_document`, so what one refuses the others
//! refuse. A second `serde_json::from_str` in the auth or policies services is
//! a second door — this test counts them.

use std::path::{Path, PathBuf};

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

#[test]
fn the_auth_and_policies_services_parse_a_document_in_one_place() {
    let service = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service");
    let mut files = Vec::new();
    rust_files(&service.join("auth"), &mut files);
    rust_files(&service.join("policies"), &mut files);
    assert!(files.len() > 5, "the scan found {} files", files.len());
    let mut doors = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        // Production code only: the tests build documents however they like.
        let production = text.split("#[cfg(test)]").next().unwrap();
        for (number, line) in production.lines().enumerate() {
            if line.contains("serde_json::from_str") || line.contains("from_str::<PolicyDocument>")
            {
                doors.push(format!("{}:{}", path.display(), number + 1));
            }
        }
    }
    assert_eq!(doors.len(), 1, "{doors:#?}");
    assert!(doors[0].contains("policy_evaluator.rs"), "{doors:#?}");
}
