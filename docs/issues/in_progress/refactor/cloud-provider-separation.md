# Separate Cloud Provider Crates

**Type:** refactor  
**Status:** in_progress  
**Branch:** refactor/reorganize_directory  
**Linked roadmap section:** n/a

---

## 🧠 Context
The cloud provider implementations (AWS, Azure, GCP, Custom) were previously part of the `wami-provider` crate. They have been separated into individual crates under `crates/cloud-provider/`:
- `wami-provider-aws`
- `wami-provider-azure`
- `wami-provider-gcp`
- `wami-provider-custom`

This separation improves modularity, allows independent versioning, and reduces dependencies when only specific providers are needed. The files are currently untracked and need to be properly integrated into the workspace.

## 🎯 Goal
Complete the separation of cloud provider crates by:
1. Ensuring all new crates are properly configured in the workspace
2. Updating dependencies and imports throughout the codebase
3. Removing old provider code from `wami-provider`
4. Updating documentation to reflect the new structure
5. Committing all changes

## 📏 Success Metrics
- [x] All provider crates compile successfully
- [x] All tests pass
- [x] No references to old provider paths remain
- [x] Workspace structure is documented and consistent

## 🧩 Acceptance Criteria
- [x] All four provider crates (`wami-provider-aws`, `wami-provider-azure`, `wami-provider-gcp`, `wami-provider-custom`) are in workspace
- [x] `Cargo.toml` workspace includes new crates
- [x] Dependencies updated in consuming crates
- [x] Old provider code removed from `wami-provider` crate
- [x] All imports updated to use new crate paths
- [x] Tests updated and passing
- [x] Documentation updated (README, architecture docs, examples)
- [x] CHANGELOG entry added
- [x] No compilation errors or warnings

## 🛠️ Implementation Outline
1. Create/switch to branch `refactor/cloud-provider-separation`
2. Verify all provider crates are properly structured with `Cargo.toml` and `src/lib.rs`
3. Update root `Cargo.toml` to include new crates in workspace
4. Update `wami-provider/Cargo.toml` to remove old provider code dependencies
5. Update imports in `wami/src/provider/` and other consuming code
6. Remove old provider files from `wami-provider/src/` (already deleted per git status)
7. Update `wami-provider/src/lib.rs` to reflect new structure
8. Run tests to ensure everything compiles and works
9. Update documentation:
   - README files in each provider crate
   - Main workspace README
   - Architecture documentation
   - Examples
10. Add CHANGELOG entry
11. Format, lint, and test
12. Commit changes
13. Move this file to `in_progress/` then `done/`
14. Create PR referencing this issue

## 🔍 Alternatives Considered
- Keeping all providers in one crate → Rejected: Better modularity and smaller dependencies with separation
- Using feature flags instead → Rejected: Separate crates provide better compile-time optimization

## ⚠️ Risks / Mitigations
- Risk: Breaking changes in API surface → Mitigation: Review all public APIs, maintain backward compatibility where possible
- Risk: Missing dependency updates → Mitigation: Run full test suite, check all imports
- Risk: Documentation inconsistencies → Mitigation: Update all relevant docs, verify examples work

## 🔗 Discussion Notes
User requested creation of this issue to track the completion of cloud provider crate separation. The directory structure has been created but integration and cleanup remain.

