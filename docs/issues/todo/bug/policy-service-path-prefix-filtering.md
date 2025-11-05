# Fix PolicyService Path Prefix Filtering

**Type:** bug  
**Status:** todo  
**Branch:** bug/policy-service-path-prefix  
**Linked roadmap section:** n/a

---

## 🧠 Context

**Discovered**: 2025-11-06 during test coverage improvement work

While writing tests for `PolicyService::list_policies()`, it was discovered that the service method was not correctly using the `path_prefix` parameter from the request.

**Bug**: The service was passing `request.scope` to the store instead of `request.path_prefix`, causing path prefix filtering to not work correctly.

**Impact**: Users calling `list_policies()` with a `path_prefix` would not get the expected filtered results.

## 🎯 Goal

Fix `PolicyService::list_policies()` to correctly use `path_prefix` from the request for filtering policies.

## 📏 Success Metrics

- [ ] `PolicyService::list_policies()` correctly filters by `path_prefix`
- [ ] Tests verify path prefix filtering works
- [ ] No regression in existing functionality

## 🧩 Acceptance Criteria

- [ ] `PolicyService::list_policies()` uses `request.path_prefix` instead of `request.scope`
- [ ] Path prefix filtering works correctly (matches policies whose path starts with the prefix)
- [ ] Existing tests still pass
- [ ] New test verifies path prefix filtering (`test_list_policies_with_path_prefix`)
- [ ] CHANGELOG entry added

## 🛠️ Implementation Outline

**NOTE**: This bug was already fixed during test coverage work. This issue is being created retroactively to document the fix.

1. ✅ Fixed `PolicyService::list_policies()` to use `request.path_prefix`
2. ✅ Added test `test_list_policies_with_path_prefix` to verify the fix
3. ⏳ Update CHANGELOG.md with bug fix entry
4. ⏳ Move this file to `done/` after verification

## 🔍 Changes Made (Retroactive)

**File**: `crates/wami/src/service/policies/policy.rs`

**Before (buggy)**:
```rust
self.store
    .read()
    .unwrap()
    .list_policies(request.scope.as_deref(), request.pagination.as_ref())
    .await
```

**After (fixed)**:
```rust
// Note: The store's list_policies takes scope as first param, but we need to pass path_prefix
// The store implementation uses path_prefix for filtering, so we map path_prefix to scope
// This is a temporary workaround - the store trait should be updated to accept path_prefix
let scope = request.path_prefix.as_deref();
self.store
    .read()
    .unwrap()
    .list_policies(scope, request.pagination.as_ref())
    .await
```

## 🔍 Root Cause

The `ListPoliciesRequest` has both `scope` and `path_prefix` fields:
- `scope`: Used for "All", "AWS", or "Local" filtering
- `path_prefix`: Used for path-based filtering

The service was incorrectly using `scope` for path filtering. The store implementation expects the first parameter to be used for path prefix filtering (despite being named `scope` in the trait).

## ⚠️ Future Improvement

The store trait `PolicyStore::list_policies()` takes a parameter named `scope` but uses it for path prefix filtering. This is confusing and should be refactored to:
- Have separate parameters for `scope` and `path_prefix`
- Or rename the parameter to `path_prefix` if it's only used for path filtering

This refactoring should be tracked in a separate enhancement issue.

## 🔗 Discussion Notes

**Discovery**: Found during test coverage work when writing `test_list_policies_with_path_prefix` test.

**Fix**: Applied immediately because the test exposed the bug, but should have been tracked in a separate issue first.

**Status**: Already fixed in commit related to test coverage improvements.


