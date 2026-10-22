//! Source scans that keep wami 005's keys honest (S7, S14).
//!
//! A test calling the API cannot see a method nobody calls yet, nor a key
//! assigned in a sixth constructor: these read the production source.
//! Test modules (`#[cfg(test)]` to the end of a file) and the conformance
//! suite — test code behind a feature — are left out.

use std::collections::BTreeMap;
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

/// The file without its test module: everything from the first
/// `#[cfg(test)]` on is test code in this crate.
fn production(text: &str) -> &str {
    text.find("#[cfg(test)]").map_or(text, |cut| &text[..cut])
}

fn sources(sub: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root.join(sub), &mut files);
    files
        .into_iter()
        .filter(|p| !p.to_string_lossy().contains("store/conformance"))
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap();
            let rel = p
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (rel, production(&text).to_string())
        })
        .collect()
}

/// Parameter names that identify a principal, a group, a role, a
/// credential's owner or a certificate.
const IDENTIFIERS: &[&str] = &[
    "user_name",
    "group_name",
    "role_name",
    "principal_name",
    "certificate_name",
    "server_certificate_name",
    "owner",
    "user",
    "group",
    "role",
];

/// Every `fn` signature of the file, whitespace collapsed.
fn signatures(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find("fn ") {
        let after = &rest[at..];
        let Some(open) = after.find('(') else { break };
        let mut depth = 0usize;
        let mut end = None;
        for (i, ch) in after[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { break };
        out.push(
            after[..=end]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
        );
        rest = &after[end..];
    }
    out
}

/// The bare-name parameters this task leaves, by file, function and
/// PARAMETER (so a new bare-name parameter of a listed function is red too:
/// review round 1, T11) — the
/// OAuth and GDPR families, which address a user by `user_name` (GDPR with a
/// `tenant_id` beside it, as two strings). Re-keying them is wami 012
/// ("OAuth and GDPR address a user by (tenant, name)"), with the token `sub`
/// for its own design round. Anything else is red (orchestrator ruling on
/// S7, process #13333).
const WAMI_012: &[(&str, &str, &str, &str)] = &[
    (
        "store/traits/oauth/mod.rs",
        "revoke_refresh_chain",
        "user_name",
        "a refresh chain by client and bare user name: wami 012",
    ),
    (
        "store/traits/oauth/mod.rs",
        "get_consent",
        "user_name",
        "a consent by client and bare user name: wami 012",
    ),
    (
        "store/traits/oauth/mod.rs",
        "revoke_consent",
        "user_name",
        "a consent by client and bare user name: wami 012",
    ),
    (
        "store/traits/gdpr/consent.rs",
        "get_active_consent",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "store/traits/gdpr/consent.rs",
        "list_user_consents",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "store/traits/gdpr/consent.rs",
        "revoke_all_user_consents",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "store/traits/gdpr/consent.rs",
        "list_user_erasure_certificates",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "store/traits/gdpr/consent.rs",
        "export_user_data",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "service/oauth/oidc.rs",
        "claims_for",
        "user_name",
        "OIDC claims by bare user name (UserClaimsSource): wami 012",
    ),
    (
        "service/oauth/oidc.rs",
        "grant_consent",
        "user_name",
        "a consent by client and bare user name: wami 012",
    ),
    (
        "service/oauth/oidc.rs",
        "withdraw_consent",
        "user_name",
        "a consent by client and bare user name: wami 012",
    ),
    (
        "service/oauth/oidc.rs",
        "profile_of",
        "user_name",
        "OIDC profile by bare user name: wami 012",
    ),
    (
        "service/oauth/oidc.rs",
        "mint",
        "user_name",
        "a token whose sub is a bare user name: wami 012",
    ),
    (
        "service/gdpr/mod.rs",
        "grant_consent",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "service/gdpr/mod.rs",
        "revoke_consent",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "service/gdpr/mod.rs",
        "revoke_all_consents",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "service/gdpr/mod.rs",
        "list_user_consents",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "service/gdpr/mod.rs",
        "is_processing_allowed",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "service/gdpr/mod.rs",
        "request_erasure",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "service/gdpr/mod.rs",
        "export_user_data",
        "user_name",
        "(tenant_id, user_name) as two strings: wami 012",
    ),
    (
        "service/gdpr/mod.rs",
        "compute_verification_hash",
        "user_name",
        "hashes the name it is given; follows wami 012",
    ),
];

/// The function a signature names: `fn name(` or `fn name<`.
fn fn_name(sig: &str) -> &str {
    let after = &sig[sig.find("fn ").map_or(0, |i| i + 3)..];
    let end = after.find(['(', '<']).unwrap_or(after.len());
    after[..end].trim()
}

/// S7: no store trait and no service method takes a bare string where it
/// names a principal, a group, a role, an owner or a certificate — but the
/// sites wami 012 owns, named above.
#[test]
fn no_trait_or_service_method_takes_a_bare_name() {
    let mut bare = Vec::new();
    for sub in ["store/traits", "service"] {
        for (file, text) in sources(sub) {
            for sig in signatures(&text) {
                for name in IDENTIFIERS {
                    for ty in ["&str", "String", "Option<&str>", "Option<String>"] {
                        if sig.contains(&format!("{name}: {ty}"))
                            && !WAMI_012.iter().any(|(f, func, param, _)| {
                                *f == file && *func == fn_name(&sig) && param == name
                            })
                        {
                            bare.push(format!("{file}: {sig}"));
                        }
                    }
                }
            }
        }
    }
    assert_eq!(bare, Vec::<String>::new(), "bare-name parameters");
}

/// S7: no key is built from an ARN's resource id in production code — it is
/// the principal's stable id, never its name.
#[test]
fn no_key_is_built_from_an_arns_resource_id() {
    let mut built = Vec::new();
    for (file, text) in sources("") {
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut rest = flat.as_str();
        while let Some(at) = rest.find("ScopedName::new(") {
            let call = &rest[at..rest.len().min(at + 200)];
            let end = call.find(';').unwrap_or(call.len());
            if call[..end].contains("resource_id") || call[..end].contains("resource.") {
                built.push(format!("{file}: {}", &call[..end]));
            }
            rest = &rest[at + 1..];
        }
    }
    assert_eq!(
        built,
        Vec::<String>::new(),
        "keys built from an ARN's resource"
    );
}

/// The text between the parenthesis `text` starts with and its match.
fn argument(text: &str) -> &str {
    let mut depth = 0usize;
    for (i, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &text[1..i];
                }
            }
            _ => {}
        }
    }
    ""
}

/// S14: inside wami, the caller key is assigned only by the constructors that
/// hold the caller's record — authentication (2), the root user (2) and
/// bootstrap's root context (1) — each from that record.
#[test]
fn the_caller_key_is_set_only_by_the_constructors_holding_the_record() {
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    let mut from_arn = Vec::new();
    for (file, text) in sources("") {
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        for (at, _) in flat.match_indices(".caller_key(") {
            let open = at + ".caller_key".len();
            let arg = argument(&flat[open..]);
            // `.caller_key()` reads the key; only an argument assigns one.
            if arg.is_empty() {
                continue;
            }
            *found.entry(file.clone()).or_default() += 1;
            if arg.contains("arn") || arg.contains("resource") {
                from_arn.push(format!("{file}: .caller_key({arg})"));
            }
        }
    }
    let expected: BTreeMap<String, usize> = [
        ("service/auth/authentication.rs", 2),
        ("wami/identity/root_user.rs", 2),
        ("wami/instance/bootstrap.rs", 1),
    ]
    .into_iter()
    .map(|(f, n)| (f.to_string(), n))
    .collect();
    assert_eq!(
        found, expected,
        "a caller key is assigned somewhere new, or no longer"
    );
    assert_eq!(
        from_arn,
        Vec::<String>::new(),
        "a caller key built from an ARN"
    );
}

/// The allowlist names only what is there: a site wami 012 re-keys must leave
/// the list with it, or the list would excuse a parameter that came back.
#[test]
fn every_wami_012_exception_still_exists() {
    let mut gone = Vec::new();
    for (file, func, param, _) in WAMI_012 {
        let sub = if file.starts_with("store/") {
            "store/traits"
        } else {
            "service"
        };
        let held = sources(sub)
            .into_iter()
            .filter(|(f, _)| f == file)
            .flat_map(|(_, text)| signatures(&text))
            .any(|sig| fn_name(&sig) == *func && sig.contains(&format!("{param}: &str")));
        if !held {
            gone.push(format!("{file}: {func}"));
        }
    }
    assert_eq!(gone, Vec::<String>::new(), "exceptions with no site left");
}

/// Production source of every crate of the workspace that holds a context or
/// a guard: wami and wami-core, test modules left out.
fn all_production() -> Vec<(String, String)> {
    let mut out = sources("");
    let core = Path::new(env!("CARGO_MANIFEST_DIR")).join("../wami-core/src");
    let mut files = Vec::new();
    rust_files(&core, &mut files);
    for p in files {
        let text = std::fs::read_to_string(&p).unwrap();
        let rel = format!(
            "wami-core/{}",
            p.strip_prefix(&core)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        );
        out.push((rel, production(&text).to_string()));
    }
    out
}

/// T10: no production code writes a session's role key — `SessionInfo` is a
/// public struct, so a field set by literal escapes S14's `.caller_key(`
/// scan; a role key is built by whoever holds the role's RECORD, and inside
/// wami nobody opens a session.
#[test]
fn no_production_code_writes_a_role_key() {
    let mut written = Vec::new();
    for (file, text) in all_production() {
        for line in text.lines() {
            let line = line.trim();
            if line.contains("assumed_role_key:")
                && !line.starts_with("pub ")
                && !line.starts_with("///")
                && !line.starts_with("//")
            {
                written.push(format!("{file}: {line}"));
            }
        }
    }
    assert_eq!(
        written,
        Vec::<String>::new(),
        "a role key written in production code"
    );
}

/// T13: no service keeps a private guard or renders a guarded ARN from the
/// caller's tenant — every guard is the shared one in
/// service/auth/authorizer.rs, and that one renders the TARGET's tenant.
#[test]
fn no_private_guard_and_no_caller_tenant_arn_returns() {
    let mut found = Vec::new();
    for (file, text) in sources("service") {
        let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if file != "service/auth/authorizer.rs" {
            for pattern in ["fn guard(", "fn guard<", "fn guard_", "iam_resource_arn"] {
                if flat.contains(pattern) {
                    found.push(format!("{file}: defines `{pattern}`"));
                }
            }
        }
        if !file.starts_with("service/auth/") && flat.contains("check_or_deny(") {
            found.push(format!("{file}: calls check_or_deny past the shared guard"));
        }
        if file == "service/auth/authorizer.rs" {
            for pattern in [
                "iam_arn(context, context.tenant_path()",
                "tenant_path: context.tenant_path()",
            ] {
                if flat.contains(pattern) {
                    found.push(format!(
                        "{file}: renders a guarded ARN from the caller's tenant ({pattern})"
                    ));
                }
            }
        }
    }
    assert_eq!(
        found,
        Vec::<String>::new(),
        "a private guard or a caller-tenant ARN"
    );
}
