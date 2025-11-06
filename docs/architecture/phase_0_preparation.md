# Phase 0 – Preparation Summary

This document captures the initial audit requested by the workspace transformation plan. It
records the current manifests, module layout, and cross-cutting dependencies at the outset of
the migration from the monolithic `wami` crate to a structured workspace.

## Workspace State

- Root `Cargo.toml` already declares a workspace that contains:
  - `wami/` – the legacy crate hosting all domains (IAM, STS, SSO, stores, providers, etc.).
  - `wami-macros/` – procedural macros that were prototyped during a previous refactor.
- Git history shows the original `src/` tree was moved under `wami/src/`; any `git diff`
  currently reports deletions because of that relocation.
- Examples were also moved under `wami/examples/` and retain one binary per scenario.

## Manifest Summary

| Crate          | Type        | Key Dependencies                              | Notes |
|----------------|-------------|-----------------------------------------------|-------|
| Root workspace | workspace   | —                                             | Only lists members; no packages |
| `wami`         | library/bin | `aws-sdk-*`, `tokio`, `chrono`, `serde`, etc. | Large monolith: >120 modules |
| `wami-macros`  | proc-macro  | `syn`, `quote`, `proc-macro2`                 | Contains WIP attribute macros |

### Feature Flags

`wami/Cargo.toml` currently defines no crate features. All domains compile unconditionally and
are tightly coupled through module imports (`mod service`, `mod store`, etc.).

### Module Boundaries (from `knowledge_graph.mmd`)

- **Core logic** (`arn`, `context`, `error`, `types`) lives under `wami/src/` alongside domain
  code, making reuse difficult.
- **Domain layer (`wami/…`)** contains credentials, identity, policies, reports, STS, SSO
  admin, tenants, etc. Each domain exposes `builder`, `model`, `operations`, and `requests`
  modules with significant duplication.
- **Service layer (`service/…`)** orchestrates domain operations and stores but repeats the
  same `Arc<RwLock<S>>` pattern.
- **Store layer (`store/…`)** provides traits and in-memory implementations, again mirroring
  the same CRUD boilerplate for each resource.
- **Provider layer (`provider/…`)** integrates with AWS/GCP/Azure and should become its own
  crate once the core types are extracted.

## Identified Tasks for Phase 1

1. Create a canonical `crates/` directory that will host the future workspace members.
2. Carve out a `wami-core` crate to host shared types (`arn`, `context`, `error`, `types`).
3. Keep the existing `wami` crate compiling by re-exporting the moved modules until all dependants
   are migrated.

This document serves as the deliverable for the Preparation phase and will be updated if further
audits are required.

