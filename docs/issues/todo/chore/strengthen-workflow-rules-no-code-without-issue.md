# Strengthen Workflow Rules: NO Code Changes Without Issue

**Type:** chore  
**Status:** todo  
**Branch:** chore/strengthen-workflow-rules  
**Linked roadmap section:** n/a

---

## 🧠 Context

An incident occurred where code changes were made to `.github/workflows/msrv.yml` without creating an issue first. This violated the workflow rules that require all code changes to originate from an issue.

To prevent this from happening again, the workflow rules need to be strengthened to be absolutely explicit that:
- **NO code changes can be made without an issue - EVER**
- This applies to ALL file modifications (config files, CI workflows, docs, etc.)
- There are ZERO exceptions for "quick fixes" or "simple changes"

## 🎯 Goal

Update the workflow rules in `.cursor/rules/` to be absolutely explicit that no code changes can be made without an issue, with clear enforcement guidelines.

## 📏 Success Metrics

- [ ] Workflow rules explicitly state "NO CODE CHANGES WITHOUT ISSUE - NEVER"
- [ ] Rules clearly list what requires an issue (config files, CI, docs, etc.)
- [ ] Rules provide clear guidance on how to handle user requests
- [ ] Agent understands that even rule updates require an issue first

## 🧩 Acceptance Criteria

- [ ] `.cursor/rules/workflows.mdc` updated with:
  - Explicit "NO CODE CHANGES WITHOUT ISSUE - NEVER" section
  - Mandatory pre-implementation checklist
  - Clear guidance on interpreting user requests
- [ ] `.cursor/rules/core-standards.mdc` updated with:
  - "ABSOLUTE RULE: NO CODE CHANGES WITHOUT ISSUE" section
  - Explicit list of what requires an issue
  - Clear exceptions (only READ-ONLY operations)
- [ ] Incident report created in `.cursor/issues/` documenting the violation
- [ ] Rules are clear and unambiguous

## 🛠️ Implementation Outline

**NOTE**: This work was already done in violation of the workflow rules. This issue is being created retroactively to document the work.

1. ✅ Created incident report: `.cursor/issues/2025-11-06-no-issue-code-change.md`
2. ✅ Updated `.cursor/rules/workflows.mdc` with strengthened rules
3. ✅ Updated `.cursor/rules/core-standards.mdc` with absolute rule section
4. ⏳ Move this file to `in_progress/` then `done/` after verification
5. ⏳ Create PR referencing this issue

## 🔍 Changes Made (Retroactive)

### Incident Report
- Created `.cursor/issues/2025-11-06-no-issue-code-change.md`
- Documents the workflow violation
- Includes lessons learned and action items

### Workflow Rules Updates
- Added "CRITICAL RULE: NO CODE CHANGES WITHOUT AN ISSUE - NEVER" to workflows.mdc
- Added mandatory pre-implementation checklist
- Added guidance on interpreting user requests
- Added "ABSOLUTE RULE" section to core-standards.mdc
- Clarified exceptions (only READ-ONLY operations)
- Listed all file types that require issues

## ⚠️ Risks / Mitigations

- **Risk**: Rules might be too strict and slow down development
  - **Mitigation**: Read-only operations are still allowed, only code changes require issues
- **Risk**: Agent might misinterpret user requests
  - **Mitigation**: Clear guidance provided on interpreting requests as "create issue" not "make changes"

## 🔗 Discussion Notes

This issue was created retroactively after the work was done. The incident report documents that the initial workflow violation occurred when updating `.github/workflows/msrv.yml` without an issue. The irony is that updating the rules themselves was also done without an issue first, demonstrating why these rules need to be absolutely explicit.


