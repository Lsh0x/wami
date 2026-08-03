<!-- Repo-Specific Agent Rules Template -->
# Repository Agent Guide

## Overview

- **Repository Name**: wami
- **Purpose**: Multi-cloud Identity and Access Management (IAM), Security Token Service (STS), and Single Sign-On (SSO) library for Rust. Provides pure domain logic with pluggable storage, supporting AWS, GCP, Azure, and custom providers.
- **Primary Owners**: LSH (github@lsh.tech)
- **Tech Stack**: Rust, Tokio (async), Cargo workspace, multi-crate architecture

## Alignment With Global Rules

- This repository inherits the global rules from `~/.cursor/AGENT_GLOBAL.md`.
- Deviations or extensions MUST be documented below with rationale.
- Artifact storage is discovered via `~/.flowmates/config.json` → `{flowmates_repo}/projects/{repo-identifier}/` (centralized in flowmates repository).

## Repository Layout

| Path | Description | Notes |
| --- | --- | --- |
| `crates/` | Workspace crates | Modular architecture with separate crates |
| `crates/wami-core/` | Foundation primitives | ARN, context, error, types |
| `crates/wami/` | Main façade crate | Re-exports everything, service layer, stores |
| `crates/wami-condition/` | Policy condition evaluation | Condition keys and operators |
| `crates/wami-credentials/` | Credential management domain | Access keys, MFA, certificates |
| `docs/` | Extended documentation, guides, ADRs | Comprehensive guides and architecture docs |
| `crates/wami/examples/` | Runnable usage examples | 24 working examples |
| `crates/wami/src/store/memory/` | In-memory store implementations | Reference implementations |

## Domain Conventions

- **Domain-Driven Design**: Pure domain logic separated from storage (no storage dependencies in domain layer)
- **Workspace Architecture**: Modular crates (`wami-core`, `wami-credentials`, `wami-condition`, etc.)
- **Service Pattern**: Services use `#[service]` macro for boilerplate reduction
- **Store Traits**: Pluggable storage via trait composition (`UserStore`, `RoleStore`, etc.)
- **ARN System**: Unified resource naming with multi-tenant and multi-cloud support
- **Multi-Tenant**: Opaque numeric tenant IDs (u64) for security
- **Error Handling**: `AmiError` and `Result<T>` types from `wami-core`
- **Context Pattern**: `WamiContext` carries authentication/authorization info through operations

## Build & Test Commands

- `cargo build --workspace` - Build entire workspace
- `cargo test --workspace` - Run all tests (539 tests, 89.43% coverage)
- `cargo test -p wami-core` - Test specific crate
- `cargo fmt --all` - Format all code
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` - Lint all code
- `cargo run --example 01_hello_wami` - Run specific example
- `cargo doc --workspace --open` - Generate and open documentation 

## Documentation Touchpoints

- `README.md`: Quick start, architecture synopsis, feature overview, examples
- `docs/ARCHITECTURE.md`: Layered design, domain boundaries, data flow
- `docs/WORKSPACE_STRUCTURE.md`: Crate/module breakdown, workspace organization
- `docs/GETTING_STARTED.md`: Step-by-step tutorial for first WAMI app
- `docs/IAM_GUIDE.md`: Complete IAM operations guide
- `docs/STS_GUIDE.md`: Temporary credentials and sessions
- `docs/MULTI_TENANT_GUIDE.md`: Tenant isolation and hierarchy
- `docs/ARN_SPECIFICATION.md`: Complete ARN format documentation
- `docs/issues/`: Issue tracker with proposals, todos, in-progress items 

## Repo-Specific Agents

Define any additional agents or overrides. Extend the global agent list using the same JSON structure. Reference global agents when behaviour changes.

```json
{
  "agents": [
    {
      "id": "repo-architect-agent",
      "name": "Repository Architect Agent",
      "model": "auto",
      "context": [
        "Deep expertise in this repository’s architecture and domain conventions.",
        "Validate new designs against the documented architecture and ensure alignment with multi-tenant constraints."
      ],
      "files": [
        "./docs/ARCHITECTURE.md",
        "./docs/WORKSPACE_STRUCTURE.md"
      ],
      "capabilities": [
        "review-architecture",
        "recommend-refactor",
        "assess-boundary-violations"
      ],
      "triggers": [
        "user-request: architecture-review",
        "pre-merge: structural-change"
      ]
    }
  ]
}
```

### Agent Overrides

- **Example**: Override `tester-agent` to enforce repository-specific smoke test suites.

```json
{
  "overrides": [
    {
      "id": "tester-agent",
      "additionalContext": [
        "Always run smoke tests in ./examples before code merges.",
        "Report flakiness trends to owner team."],
      "additionalTriggers": [
        "pre-release"
      ]
    }
  ]
}
```

## Exceptions to Global Rules

- Capture any intentional deviations (e.g., lower coverage threshold for legacy modules).
- Provide justification, owner approval, and a revisit timeline.

## Onboarding Checklist

- [ ] Clone repository and run bootstrap script / `init-repo-agent`.
- [ ] Configure environment variables / secrets as documented.
- [ ] Run full test suite and ensure baseline artifacts (knowledge graph, inventories) are generated.
- [ ] Read `AGENT.md`, `README.md`, and architecture docs.

## Appendix

- Link to issue tracker labels, CI dashboards, deployment pipelines.
- Provide glossary of domain terms specific to the repo.
- Add references to external systems or contracts.


