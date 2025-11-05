# AGENT.md

This guide powers automation agents and contributors working in the WAMI repository. It captures the authoritative workflows, structures, and expectations derived from `README.md`, the workspace documentation under `docs/`, and the Mermaid relationship graph in `knowledge_graph.mmd`.

## WAMI At A Glance
- Domain: multi-cloud IAM, STS, and SSO with strict tenant isolation and a unified ARN system.
- Tech stack: Rust 2021 workspace with procedural macros, async-first domain modules, and in-memory store adapters.
- Distribution: primary crate `wami` re-exports workspace crates; published on crates.io (`wami = "0.11.0"`).
- Test posture: 539 unit tests, 89.43% coverage, full suite runs with `cargo test --workspace`.
- Design pillars: domain-driven layering, pluggable storage traits, numeric tenant hierarchy, provider-aware ARN transformations.

## Repository Layout (Workspace Root)
- Core & foundation: `crates/wami-core` (`arn/builder.rs`, `parser.rs`, `transformer.rs`, `types.rs`, `context.rs`, `error.rs`, `types.rs`).
- Traits & interfaces: `crates/wami-traits/src/lib.rs` supplies store/service abstraction traits and registries.
- Provider integration: `crates/wami-provider` plus vendor crates under `crates/cloud-provider/wami-provider-{aws,azure,gcp,custom}`.
- Domain crates: `crates/wami-credentials`, `crates/wami-identity`, with builders, models, and request objects.
- Macros & orchestration: `crates/wami-macros` (derive/service/register macros) and `crates/wami-service` (registry helpers).
- Facade crate: `crates/wami` exposes domain modules under `src/wami/`, services under `src/service/`, and store traits/memory implementations under `src/store/`.
- Documentation: `docs/` hosts architecture, guides, migration notes, status reports, and update checklists; use `docs/WORKSPACE_STRUCTURE.md` for crate breakdown.
- Knowledge assets: `knowledge_graph.mmd` and `knowledge_graph.html` visualize inter-crate relationships; regenerate after structural changes.

## Domain & Layered Modules
- ARN system lives in `crates/wami-core/src/arn/{builder,parser,transformer,types}.rs` and is consumed across providers and stores.
- Context and error handling come from `wami-core::context` and `wami-core::error`, establishing shared `WamiContext`, `AmiError`, and `Result` types.
- Pure domain logic is organized under `crates/wami/src/wami/*` covering identity, credentials, policies, STS, SSO admin, tenants, tags, reports, and STS federation.
- Service orchestration modules under `crates/wami/src/service/*` wrap domain functions with store access; macros from `wami-macros` eliminate boilerplate.
- Store traits in `crates/wami/src/store/traits` map to memory adapters in `crates/wami/src/store/memory`; each trait has a corresponding in-memory implementation and tests (see `store/memory/*/tests.rs`).
- Provider-specific transformations rely on `crates/wami-provider/src/arn_builder.rs` and `provider_info.rs`, backed by the cloud-provider crates.

## Knowledge Graph Usage
- File: `knowledge_graph.mmd` mirrors the workspace structure with groups for core, traits, providers, macros, credentials, WAMI domain, store traits, and store memory.
- Workflow: inspect the graph before cross-cutting edits to identify dependent modules; update or regenerate the graph if new modules or files are introduced or renamed.
- Analysis: Run `python3 codeanalysis/analyze_codebase.py` to generate fresh inventory, then `python3 codeanalysis/generate_graph.py` to regenerate graph artifacts. Latest analysis: November 6, 2025 (307 files, 260 structs, 39 traits, 1,779 functions, 0 circular dependencies).

## Build, Test, and Development Commands
- Environment: repository requires only Rust toolchain; no extra services for unit tests.
- Build all crates: `cargo build --workspace`.
- Test all crates: `cargo test --workspace`; scope with `cargo test -p <crate>` or `cargo test -p wami -- <filter>` for focused runs.
- Format: `cargo fmt --all` or `cargo fmt --all -- --check` for CI parity.
- Lint: `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- Coverage alignment: `cargo llvm-cov --workspace --summary-only` to mirror CI metrics.
- Examples: run `cargo run --example <example_name>` within `crates/wami/`; reference the 24 examples catalogued in `docs/EXAMPLES.md` and `examples/README.md`.

## Coding Patterns & Conventions
- Maintain separation between domain logic (pure functions) and store/provider layers; avoid direct I/O in `src/wami/` modules.
- Use `#[wami_macros::service(...)]` to generate service structs; disable generated constructors with `generate_new = false` when custom wiring is required.
- Compose store trait aliases (see `store/traits/...`) when services depend on multiple domains, keeping signatures concise.
- Log through `tracing`; propagate structured errors with `thiserror`-based types from `wami-core`.
- Ensure new public APIs include Rustdoc examples and unit tests colocated with the code.
- Respect facade expectations: re-export necessary items via `crates/wami/src/lib.rs` when adding new domain modules or services.

## Testing Guidelines
- Unit tests live adjacent to modules across crates; integration tests consolidate under crate-level `tests/` directories such as `crates/wami/src/store/memory/*/tests.rs` and `crates/wami/src/wami/tenant/tests.rs`.
- Memory store suites validate contract compliance; extend them when adding new resource types or operations.
- When altering ARN behavior, run focused tests in `crates/wami-core/src/arn/*` and provider crates, then execute the full workspace suite.
- Use example binaries as smoke tests for builder APIs; they are maintained to compile cleanly.
- Coverage tracking via `cargo llvm-cov` should remain above the documented 89% benchmark; investigate significant drops before merging.

## Documentation & Change Management
- Follow `docs/DOCUMENTATION_UPDATE.md` whenever introducing or modifying modules, commands, or workflows; it lists required doc touchpoints.
- Update `README.md`, `docs/WORKSPACE_STRUCTURE.md`, `docs/ARCHITECTURE.md`, and relevant guides (IAM, STS, SSO, Multi-tenant, Store Implementation) to reflect new capabilities or paths.
- Maintain `docs/status/` summaries and `docs/issues/ISSUE_*.md` when completing roadmap items; move finished work into status or completion docs.
- Keep `docs/AGENT.md` synchronized with structural changes so automation agents operate with current information.

## Adding New Crates
- Placement: create crates under `crates/` (core/domain/macro/service crates) or `crates/cloud-provider/` (provider-specific crates). Use the `wami-<domain>` or `wami-provider-<vendor>` naming convention for directories and package names, matching existing crates like `crates/wami-credentials` and `crates/cloud-provider/wami-provider-aws`.
- Workspace membership: append the new crate path to the `[workspace].members` array in `/Cargo.toml` so tooling and CI include it.
- Manifest template: follow existing `Cargo.toml` conventions—edition `2021`, MIT license, short description, and path dependencies to sibling crates (`wami-core`, `wami-provider`, etc.) as needed.
- Baseline files: include `README.md` summarizing the crate’s scope and usage, and a `src/lib.rs` that re-exports modules. Domain crates typically organize submodules by resource (`builder.rs`, `model.rs`, `requests.rs`) mirroring the patterns in `crates/wami-credentials/src`.
- Integration: update `crates/wami/Cargo.toml` to depend on the new crate and re-export its API from `crates/wami/src/lib.rs` (plus relevant submodules) to keep end-user imports stable.
- Tests & examples: add unit tests near the new modules and extend in-memory store tests if the crate introduces new storage-facing types.
- Documentation: refresh `docs/WORKSPACE_STRUCTURE.md`, `docs/ARCHITECTURE.md`, `README.md`, and `knowledge_graph.mmd` to describe the crate’s role. Note the addition in `docs/DOCUMENTATION_UPDATE.md` and ensure `docs/AGENT.md` reflects the new structure.

## Commit & PR Guidelines
- Practice atomic commits: each commit must capture a single logical change; supporting tests and docs that relate directly to that change may be included.
- Pre-commit hook enforces atomic scope heuristics and runs `cargo fmt --all -- --check` plus `cargo clippy --workspace --all-targets --all-features -- -D warnings` when Rust files are staged; fix failures instead of bypassing with `--no-verify` unless absolutely necessary.
- Commit messages follow Conventional Commits with subjects ≤ 72 characters, avoiding multi-change phrasing (`and`, `&`); example: `feat(credentials): add service credential revocation`.
- Reference issues with closing keywords (e.g., `Closes #123`) and ensure the configured git email (`github@lsh.tech`) is used.
- Keep PRs focused on the stated scope, restate the change summary, attach test/lint/doc status, and include screenshots or API samples for visible updates.
- Consult `docs/atomic-commits.md` for examples, troubleshooting, and enforcement details.

## Agent Workflow Checklist
- Review `knowledge_graph.mmd` and the module you're touching before edits to understand dependencies.
- Modify the targeted crate or module (core, domain, store, provider) and ensure re-exports stay consistent.
- Run scoped tests first (`cargo test -p <crate>`), then `cargo test --workspace` when work spans multiple crates.
- Format and lint before exit (`cargo fmt --all`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`).
- Update documentation and regenerate supporting artifacts as required.

## Reference Documents
- `README.md`: overview, quick start, feature highlights, examples, and architecture synopsis.
- `docs/WORKSPACE_STRUCTURE.md`: in-depth crate responsibilities and migration tips.
- `docs/ARCHITECTURE.md`: layered design, domain/service/store delineation.
- `docs/ARN_SPECIFICATION.md` and `docs/ARN_ARCHITECTURE_COMPLETE.md`: canonical ARN formats and provider transformations.
- `docs/GETTING_STARTED.md`, `docs/IAM_GUIDE.md`, `docs/STS_GUIDE.md`, `docs/SSO_ADMIN_GUIDE.md`, `docs/MULTI_TENANT_GUIDE.md`: primary domain guides.
- `docs/STORE_IMPLEMENTATION.md`: instructions for building alternate store backends.
- `docs/MULTICLOUD_PROVIDERS.md` and `docs/MULTICLOUD_STATUS.md`: provider feature matrix and roadmap status.
- `docs/status/*.md`: progress tracking and milestone completion summaries.

