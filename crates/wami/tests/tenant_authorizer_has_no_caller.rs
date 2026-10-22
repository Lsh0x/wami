//! `TenantAuthorizer` is a third policy evaluator (wami 001 found it): it
//! drops a document it cannot read, never reads a condition, and matches the
//! Effect case-sensitively. Bringing it onto the one evaluator is wami 003.
//! Until then nothing may call it: a caller appearing is this test going red,
//! not a door opening without a word.

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
fn nothing_in_the_workspace_calls_the_tenant_authorizer() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let home = Path::new("wami/src/wami/tenant/authorization.rs");
    let this = Path::new("wami/tests/tenant_authorizer_has_no_caller.rs");
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    assert!(files.len() > 50, "the scan found {} files", files.len());
    let callers: Vec<_> = files
        .iter()
        .filter(|path| !path.ends_with(home) && !path.ends_with(this))
        .filter(|path| {
            std::fs::read_to_string(path)
                .unwrap()
                .contains("TenantAuthorizer")
        })
        .collect();
    assert!(
        callers.is_empty(),
        "TenantAuthorizer has callers — move them to AuthorizationService or do wami 003 first: {callers:?}"
    );
}
