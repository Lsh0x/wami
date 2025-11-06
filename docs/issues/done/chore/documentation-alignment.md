# Update Documentation to Align with Code

**Type:** chore  
**Status:** done  
**Branch:** chore/documentation-alignment  
**Linked roadmap section:** n/a

---

## 🧠 Context

Recent codebase changes have introduced misalignments between documentation and actual code:

1. **API_REFERENCE.md** contains outdated builder function signatures (still references `provider` and `account_id` instead of `context: &WamiContext`)
2. **API_REFERENCE.md** shows incorrect module paths (`wami::identity::user` vs actual `wami::wami::identity::user::builder`)
3. **EXAMPLES.md** uses deprecated `InMemoryWamiStore` instead of `InMemoryStore`
4. **README.md** shows outdated project structure (old provider structure instead of separated cloud-provider crates)
5. **lib.rs** doc example uses `InMemoryWamiStore` instead of `InMemoryStore`

These misalignments cause confusion for developers trying to use the library and can lead to compilation errors when copying examples.

## 🎯 Goal

Update all documentation to accurately reflect the current codebase structure, API signatures, and usage patterns. Ensure all examples are compilable and follow current best practices.

## 📏 Success Metrics

- [ ] All documentation examples compile without errors
- [ ] API_REFERENCE.md accurately reflects current builder signatures
- [ ] All store references use `InMemoryStore` (not `InMemoryWamiStore`)
- [ ] Project structure diagrams reflect cloud-provider separation
- [ ] Module paths are correct throughout documentation

## 🧩 Acceptance Criteria

- [ ] `docs/API_REFERENCE.md` updated with correct builder signatures:
  - `build_access_key(user_name: String, context: &WamiContext) -> Result<AccessKey>`
  - `build_user(user_name: String, path: Option<String>, context: &WamiContext) -> Result<User>`
  - All other builders updated to use `WamiContext`
- [ ] `docs/API_REFERENCE.md` module paths corrected:
  - Note that types are re-exported at `wami::identity::{User, Group, Role}`
  - Builders are at `wami::wami::identity::user::builder::build_user`
  - Credentials come from `wami_credentials` crate
- [ ] `docs/EXAMPLES.md` updated:
  - Replace `InMemoryWamiStore::new()` with `InMemoryStore::default()`
  - Replace `use wami::store::memory::InMemoryWamiStore` with `use wami::store::memory::InMemoryStore`
- [ ] `README.md` project structure section updated:
  - Remove old `provider/aws.rs`, `provider/gcp.rs`, `provider/azure.rs`
  - Note that providers are in separate crates under `crates/cloud-provider/`
- [ ] `crates/wami/src/lib.rs` doc example updated:
  - Use `InMemoryStore::default()` instead of `InMemoryWamiStore::default()`
  - Use `InMemoryStore` import instead of `InMemoryWamiStore`
- [ ] All documentation examples verified to compile
- [ ] CHANGELOG entry added documenting documentation updates

## 🛠️ Implementation Outline

1. Create/switch to branch `chore/documentation-alignment`
2. Review and fix `docs/API_REFERENCE.md`:
   - Update builder function signatures to use `WamiContext`
   - Fix module paths to reflect actual structure
   - Add notes about re-exports vs direct module access
3. Update `docs/EXAMPLES.md`:
   - Search and replace `InMemoryWamiStore` with `InMemoryStore`
   - Update initialization to use `::default()` instead of `::new()`
4. Update `README.md`:
   - Fix project structure diagram to show cloud-provider crates
   - Update any provider-related examples
5. Fix `crates/wami/src/lib.rs` doc example
6. Verify all examples compile:
   ```bash
   cargo test --doc --workspace
   ```
7. Check for any other documentation files with similar issues
8. Update CHANGELOG.md
9. Move this file to `in_progress/` then `done/`
10. Create PR referencing this issue

## 🔍 Specific Files to Update

### High Priority
- `docs/API_REFERENCE.md` (lines 114-121, 16-93)
- `docs/EXAMPLES.md` (lines 158, 203)
- `README.md` (lines 369-372)
- `crates/wami/src/lib.rs` (lines 21, 33)

### Additional Checks
- `docs/GETTING_STARTED.md` - verify all examples are current
- `docs/WORKSPACE_STRUCTURE.md` - verify it's up to date
- Any other docs that reference `InMemoryWamiStore`

## ⚠️ Risks / Mitigations

- **Risk**: Breaking existing documentation links or references
  - **Mitigation**: Search entire docs directory for all occurrences before updating
- **Risk**: Missing some outdated references
  - **Mitigation**: Use grep to find all `InMemoryWamiStore` and `provider: &dyn CloudProvider` references
- **Risk**: Examples may not compile after changes
  - **Mitigation**: Run `cargo test --doc` to verify all doc examples compile

## 🔗 Discussion Notes

Identified during codebase analysis when user asked to verify documentation alignment. Multiple discrepancies found between documented API and actual code implementation.


