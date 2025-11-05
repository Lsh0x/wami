# Increase Test Coverage

**Type:** chore  
**Status:** in_progress  
**Branch:** chore/increase-test-coverage  
**Linked roadmap section:** n/a

---

## 🧠 Context

The codebase currently has 446 tests passing, but test coverage analysis shows gaps in several areas:
- Service layer tests may not cover all error paths
- Edge cases in domain builders may be untested
- Integration tests between layers may be missing
- Store trait implementations may have incomplete test coverage
- Policy evaluation edge cases may need more coverage

Improving test coverage will:
- Increase confidence in code correctness
- Help catch regressions during refactoring
- Improve documentation through test examples
- Ensure all error paths are tested

## 🎯 Goal

Increase overall test coverage to above 90% (currently reported at 89.43%) and ensure comprehensive coverage of:
- All service layer methods (success and error paths)
- Domain builder functions (edge cases and validation)
- Store implementations (CRUD operations, queries, error handling)
- Policy evaluation (complex scenarios, edge cases)
- Multi-tenant isolation scenarios

## 📏 Success Metrics

- [ ] Overall test coverage above 90% (baseline: 89.43%)
- [ ] Service layer coverage above 85%
- [ ] Domain builder coverage above 95%
- [ ] Store implementation coverage above 90%
- [ ] Policy evaluation coverage above 85%
- [ ] All error paths have at least one test

## 🧩 Acceptance Criteria

- [ ] Coverage report generated showing current state:
  ```bash
  cargo test --workspace --all-features
  cargo install cargo-tarpaulin
  cargo tarpaulin --workspace --out Html
  ```
- [ ] Gap analysis completed identifying uncovered code paths
- [ ] Test coverage increased for:
  - **Service layer**: All service methods have success and error path tests
  - **Builders**: Edge cases (empty strings, invalid inputs, None values)
  - **Stores**: Error conditions (not found, already exists, concurrent access)
  - **Policy evaluation**: Complex policies, wildcards, conditions
  - **Multi-tenant**: Cross-tenant isolation, hierarchy queries
- [ ] Integration tests added for:
  - Service → Store → Domain flow
  - Multi-provider scenarios
  - Tenant isolation verification
- [ ] Property-based tests added where appropriate (using `quickcheck` or `proptest`)
- [ ] Documentation updated with test coverage metrics
- [ ] CHANGELOG entry added

## 🛠️ Implementation Outline

1. Create/switch to branch `chore/increase-test-coverage`
2. Generate baseline coverage report:
   ```bash
   cargo install cargo-tarpaulin
   cargo tarpaulin --workspace --out Html --out Xml
   ```
3. Analyze coverage gaps:
   - Identify files with < 80% coverage
   - Identify untested functions/methods
   - Identify missing error path tests
4. Prioritize test additions:
   - High priority: Service layer error paths
   - Medium priority: Builder edge cases
   - Low priority: Happy path additions (already well covered)
5. Add service layer tests:
   - Test error paths (validation failures, store errors)
   - Test edge cases (empty inputs, None values)
   - Test concurrent access scenarios
6. Add builder tests:
   - Test invalid inputs (empty strings, invalid ARNs)
   - Test None/Some handling
   - Test context validation
7. Add store tests:
   - Test error conditions (duplicate creation, not found)
   - Test concurrent modifications
   - Test query edge cases (empty results, pagination)
8. Add policy evaluation tests:
   - Complex nested policies
   - Wildcard matching edge cases
   - Condition evaluation
   - Deny vs Allow precedence
9. Add integration tests:
   - Complete workflows (create user → create access key → authenticate)
   - Multi-tenant isolation
   - Provider switching scenarios
10. Add property-based tests (optional):
    - ARN building/parsing round-trips
    - Policy document validation
11. Verify coverage increase:
    ```bash
    cargo tarpaulin --workspace --out Html
    ```
12. Update documentation:
    - Add coverage metrics to README or docs
    - Document how to run coverage reports
13. Update CHANGELOG.md
14. Move this file to `in_progress/` then `done/`
15. Create PR referencing this issue

## 🔍 Specific Areas to Cover

### Service Layer (Priority: High)
- [ ] `AuthenticationService` - Invalid credentials, expired sessions
- [ ] `AuthorizationService` - Policy evaluation failures
- [x] `UserService` - Duplicate user creation, user not found ✅ Added 8 error path tests
- [x] `AccessKeyService` - Key limit reached, invalid user ✅ Added 4 error path tests
- [x] `PolicyService` - Invalid policy documents, policy not found ✅ Added 5 error path tests (also fixed bug: service now uses path_prefix)
- [ ] `SessionService` - Expired sessions, invalid tokens
- [ ] `EvaluationService` - Complex policy scenarios
- [x] `InlinePolicyService` - User/role/group not found, invalid JSON ✅ Added 7 error path tests

### Domain Builders (Priority: Medium)
- [x] `build_user` - Empty user name, invalid path, invalid context ✅ Added 9 edge case tests
- [x] `build_access_key` - Invalid user, invalid context ✅ Added 6 edge case tests
- [x] `build_group` - Duplicate names, invalid paths ✅ Added 6 edge case tests
- [x] `build_role` - Invalid trust policy, invalid ARN ✅ Added 9 edge case tests

### Store Implementations (Priority: Medium)
- [ ] `InMemoryStore` - Concurrent access, race conditions
- [x] Error conditions - Not found, already exists, invalid state ✅ Added 12 edge case tests
- [x] Query edge cases - Empty results, pagination boundaries ✅ Added tests + **FIXED 2 BUGS**:
  - Bug 1: Empty string path prefix matched all paths (fixed in user/group/role stores)
  - Bug 2: Pagination with max_items=0 caused panic (fixed in user/group/role stores)
- [ ] Multi-tenant isolation - Verify tenant boundaries

### Policy Evaluation (Priority: High)
- [x] Complex nested policies ✅ Added 17 complex scenario tests
- [x] Wildcard matching (resource, action) ✅ Added tests for prefix matching, exact vs wildcard
- [ ] Condition evaluation (StringEquals, DateGreaterThan, etc.) - Not yet implemented
- [x] Deny vs Allow precedence ✅ Added tests for deny winning over allow
- [ ] NotAction, NotResource scenarios - Not yet implemented

### Integration Tests (Priority: Low)
- [ ] Complete user lifecycle (create → update → delete)
- [ ] Access key creation and rotation
- [ ] Role assumption flow
- [ ] Multi-tenant resource access
- [ ] Provider switching scenarios

## 🔍 Testing Tools

- **Coverage**: `cargo-tarpaulin` for coverage reports
- **Property-based**: `quickcheck` or `proptest` for property-based testing
- **Mocking**: Consider `mockall` if needed for complex dependencies
- **Integration**: Use existing test infrastructure

## ⚠️ Risks / Mitigations

- **Risk**: Tests may be fragile or slow
  - **Mitigation**: Focus on unit tests, use integration tests sparingly, avoid flaky tests
- **Risk**: Coverage may not reflect actual quality
  - **Mitigation**: Focus on meaningful coverage (error paths, edge cases), not just line count
- **Risk**: Test maintenance burden
  - **Mitigation**: Keep tests simple and focused, document complex test scenarios
- **Risk**: Missing critical edge cases
  - **Mitigation**: Review error handling code, test all error return paths

## 🔗 Discussion Notes

Current test coverage is already good (89.43%), but there are opportunities to improve:
- Service layer error paths
- Edge cases in builders
- Policy evaluation complexity
- Multi-tenant isolation verification

This work will support upcoming refactoring efforts (service layer separation) by ensuring comprehensive test coverage before breaking changes.

