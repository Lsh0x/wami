# Increase Test Coverage

## Summary
Increase test coverage to above 90% by adding comprehensive tests for error paths, edge cases, and complex scenarios.

## Status
**Status**: Done ✅

## Completed Tasks

- [x] Add 17 complex policy evaluation tests
  - Multiple policies with conflicting statements
  - Wildcard matching scenarios
  - Deny precedence over Allow
  - Edge cases (empty lists, invalid JSON)
  
- [x] Add edge case tests for builders
  - User builder: 11 edge case tests
  - Group builder: 6 edge case tests
  - Role builder: 12 edge case tests
  - AccessKey builder: 6 edge case tests
  
- [x] Add store edge case tests
  - Empty string path prefix filtering
  - Pagination edge cases (max_items=0, max_items=1, etc.)
  - Tag operations with edge cases
  
- [x] Fix 2 bugs discovered during testing
  1. Empty string path prefix matched all paths (fixed in user/group/role stores)
  2. Pagination with max_items=0 caused panic (fixed in user/group/role stores)
  
- [x] Add service error path tests
  - UserService: 8 error path tests
  - InlinePolicyService: 7 error path tests
  - PolicyService: 5 error path tests
  - AccessKeyService: 4 error path tests

## Results

- **Total tests**: 527 tests passing
- **New tests added**: ~100+ tests
- **Bugs fixed**: 2 bugs discovered and fixed
- **PR**: #75 opened and ready for review

## Related PR
- PR #75: test: increase test coverage with edge cases and bug fixes
