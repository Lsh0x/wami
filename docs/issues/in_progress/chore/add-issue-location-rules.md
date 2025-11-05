# Add Issue Location Requirements to Rules

**Type:** chore  
**Status:** in_progress  
**Branch:** chore/add-issue-location-rules  
**Linked roadmap section:** n/a

---

## 🧠 Context

There's confusion about where issues should be created:
- Project issues should be in `docs/issues/todo/{type}/` (in repository)
- Workflow/rule issues should be in `~/.cursor/issues/` (global config)

The workflow rules need to be updated to explicitly state this requirement to prevent agents from creating project issues in the wrong location.

## 🎯 Goal

Update workflow rules in `.cursor/rules/` to explicitly document that:
- Project issues MUST be in `docs/issues/todo/{type}/`
- Workflow issues go in `~/.cursor/issues/`
- Clear separation between project work and agent improvement

## 📏 Success Metrics

- [ ] Rules explicitly state project issues go in `docs/issues/todo/`
- [ ] Rules explicitly state workflow issues go in `~/.cursor/issues/`
- [ ] Examples provided showing correct vs incorrect locations
- [ ] Agent understands the distinction

## 🧩 Acceptance Criteria

- [x] `.cursor/rules/workflows.mdc` updated with:
  - Explicit note in exploration workflow about issue location ✅
  - Note that project issues go in `docs/issues/todo/{type}/` ✅
  - Note that workflow issues go in `~/.cursor/issues/` ✅
- [x] `.cursor/rules/core-standards.mdc` updated with:
  - Critical rule about project issues location ✅
  - Clear separation explanation ✅
- [x] Issue created in `~/.cursor/issues/` documenting this rule (for reference) ✅
- [ ] CHANGELOG entry added (if needed)

## 🛠️ Implementation Outline

**NOTE**: This work was partially done during test coverage work. This issue tracks completing it properly.

1. Create/switch to branch `chore/add-issue-location-rules`
2. Update `.cursor/rules/workflows.mdc`:
   - Add explicit location requirements in exploration workflow
   - Update bug discovery section to specify correct location
3. Update `.cursor/rules/core-standards.mdc`:
   - Add critical rule about issue locations
   - Clarify separation of concerns
4. Verify rules are clear and unambiguous
5. Move this file to `in_progress/` then `done/`
6. Create PR referencing this issue

## 🔍 Changes Needed

### workflows.mdc
- Add explicit location requirement in step 7 of exploration workflow
- Update bug discovery section to specify `docs/issues/todo/{type}/`

### core-standards.mdc
- Add critical rule: "Project issues MUST be in `docs/issues/todo/`, NOT in `.cursor/issues/` or `~/.cursor/issues/`"
- Add clarification about separation

## ⚠️ Risks / Mitigations

- **Risk**: Rules might be too verbose
  - **Mitigation**: Keep it concise but clear, use examples
- **Risk**: Agents might still confuse the locations
  - **Mitigation**: Use explicit examples and clear separation

## 🔗 Discussion Notes

This rule update is needed because agents have been creating issues in the wrong locations. The distinction between project work (in repo) and workflow improvements (in global config) needs to be absolutely clear.

**Status**: Partially implemented during test coverage work, but should have been tracked in this issue first.

