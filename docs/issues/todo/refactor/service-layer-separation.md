# Split Service Layer into Separate Crates

**Type:** refactor  
**Status:** todo  
**Branch:** refactor/service-layer-separation  
**Linked roadmap section:** n/a

---

## 🧠 Context

The service layer in `crates/wami/src/service/` currently contains 38 service files organized into 8 subdirectories:
- `auth/` - Authentication and Authorization (2 files)
- `credentials/` - AccessKey, LoginProfile, MfaDevice, etc. (7 files)
- `identity/` - User, Group, Role, ServiceLinkedRole (5 files)
- `policies/` - Policy, Attachment, Evaluation, Inline, PermissionsBoundary (5 files)
- `reports/` - CredentialReport (1 file)
- `sso_admin/` - AccountAssignment, Application, Instance, PermissionSet, TrustedTokenIssuer (5 files)
- `sts/` - Session, Identity, AssumeRole, Federation, SessionToken (6 files)
- `tenant/` - Tenant service (1 file)

This monolithic structure makes it difficult to:
- Compile only specific service domains
- Add new service types without rebuilding the entire service layer
- Maintain clear boundaries between service domains
- Enable feature flags for optional service domains

Following the pattern established with domain crates (`wami-identity`, `wami-credentials`) and cloud-provider separation, splitting the service layer into separate crates would improve modularity and compilation times.

## 🎯 Goal

Split the service layer into separate workspace crates, mirroring the domain structure. Each service crate should:
- Be independently compilable
- Have clear dependencies on domain and store crates
- Maintain backward compatibility through re-exports in the main `wami` crate
- Follow the same architectural patterns as existing workspace crates

## 📏 Success Metrics

- [ ] Service layer split into at least 4-5 separate crates (e.g., `wami-service-identity`, `wami-service-credentials`, `wami-service-policies`, `wami-service-sts`)
- [ ] Compilation time reduced for incremental builds
- [ ] All existing tests pass
- [ ] Backward compatibility maintained (all public APIs accessible via `wami::` crate)
- [ ] Clear dependency boundaries between service crates

## 🧩 Acceptance Criteria

- [ ] Create new service crates under `crates/service/` or similar structure:
  - `wami-service-identity` - User, Group, Role, ServiceLinkedRole, IdentityProvider services
  - `wami-service-credentials` - AccessKey, LoginProfile, MfaDevice, Certificate services
  - `wami-service-policies` - Policy, Attachment, Evaluation, Inline, PermissionsBoundary services
  - `wami-service-sts` - Session, Identity, AssumeRole, Federation, SessionToken services
  - `wami-service-sso-admin` - SSO Admin services (or keep in main crate if too small)
  - `wami-service-reports` - CredentialReport service (or merge into appropriate crate)
  - `wami-service-auth` - Authentication and Authorization services
  - `wami-service-tenant` - Tenant service (or merge into appropriate crate)
- [ ] Update `Cargo.toml` workspace members to include new service crates
- [ ] Each service crate has proper `Cargo.toml` with correct dependencies:
  - `wami-core` for context and error types
  - `wami-traits` for service trait definitions
  - Domain crates (`wami-identity`, `wami-credentials`) as needed
  - Store traits from main `wami` crate
  - `wami-macros` for `#[service]` macro
- [ ] Main `wami` crate re-exports all services for backward compatibility
- [ ] Update `crates/wami/src/service/mod.rs` to re-export from service crates
- [ ] All existing service tests continue to pass
- [ ] Documentation updated (WORKSPACE_STRUCTURE.md, README.md)
- [ ] CHANGELOG entry added

## 🛠️ Implementation Outline

1. Create/switch to branch `refactor/service-layer-separation`
2. Analyze service dependencies:
   - Map which services depend on which domain crates
   - Identify shared dependencies (wami-core, wami-traits, wami-macros)
   - Identify cross-service dependencies
3. Design crate structure:
   - Decide on crate granularity (4-5 crates vs 8 crates)
   - Consider merging small services (auth, reports, tenant) into larger crates
   - Plan dependency graph
4. Create new service crates:
   - Create `crates/service/` directory structure
   - Create `Cargo.toml` for each service crate
   - Move service files to appropriate crates
   - Update imports and module structure
5. Update main crate:
   - Update `crates/wami/Cargo.toml` to depend on new service crates
   - Update `crates/wami/src/service/mod.rs` to re-export services
   - Ensure all public APIs remain accessible
6. Update workspace:
   - Add service crates to root `Cargo.toml` workspace members
   - Verify workspace builds correctly
7. Update tests:
   - Move service tests to appropriate service crates
   - Ensure all tests pass
   - Update test imports
8. Update documentation:
   - Update `docs/WORKSPACE_STRUCTURE.md` with new service crate structure
   - Update `README.md` if needed
   - Update any architecture diagrams
9. Verify backward compatibility:
   - Check that all existing examples still compile
   - Verify public API surface hasn't changed
10. Update CHANGELOG.md
11. Move this file to `in_progress/` then `done/`
12. Create PR referencing this issue

## 🔍 Proposed Crate Structure

### Option 1: Fine-grained (8 crates)
```
crates/service/
├── wami-service-auth/
├── wami-service-credentials/
├── wami-service-identity/
├── wami-service-policies/
├── wami-service-reports/
├── wami-service-sso-admin/
├── wami-service-sts/
└── wami-service-tenant/
```

### Option 2: Coarse-grained (4-5 crates) - Recommended
```
crates/service/
├── wami-service-identity/      # identity + auth
├── wami-service-credentials/   # credentials + reports
├── wami-service-policies/      # policies
├── wami-service-sts/          # sts
└── wami-service-sso-admin/     # sso-admin + tenant (small, can merge)
```

**Recommendation**: Option 2 (coarse-grained) to reduce complexity while still achieving modularity benefits.

## 🔍 Alternatives Considered

- **Keep monolithic structure** → Rejected: Doesn't improve compilation times or modularity
- **Split by store type** → Rejected: Services are organized by domain, not store
- **Feature flags instead of crates** → Rejected: Doesn't improve compilation times for incremental builds

## ⚠️ Risks / Mitigations

- **Risk**: Breaking changes in public API
  - **Mitigation**: Careful re-export strategy in main crate, comprehensive testing
- **Risk**: Circular dependencies between service crates
  - **Mitigation**: Design dependency graph upfront, avoid cross-service dependencies
- **Risk**: Increased complexity in workspace structure
  - **Mitigation**: Clear documentation, follow established patterns from domain crates
- **Risk**: Migration complexity
  - **Mitigation**: Incremental approach, keep main crate re-exports working throughout

## 🔗 Discussion Notes

This refactoring follows the successful pattern established with:
- Domain crate separation (`wami-identity`, `wami-credentials`)
- Cloud-provider separation (`wami-provider-aws`, `wami-provider-gcp`, etc.)

The service layer is a logical next step for modularization, as it's the largest remaining monolithic component in the workspace.


