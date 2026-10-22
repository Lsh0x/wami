# Changelog

## [0.19.0](https://github.com/Lsh0x/wami/compare/wami-core-v0.18.0...wami-core-v0.19.0) (2026-10-22)


### ⚠ BREAKING CHANGES

* **auth:** store traits take `&ScopedName` (tenant, name) for every principal, group, owner and certificate argument, and lists take `&TenantPath`; the bare-name methods are removed, and a create on a held key is `ResourceExists`. `iam_resource_arn` is removed (use `target_arn`/`tenant_arn` or the guards in `wami::service::auth`). `authorize` and every guard refuse a non-root context whose caller key names no stored user or whose user's ARN is not the caller ARN. `WamiArn::is_root_user` is true only at tenant path exactly `0`, and `WamiContextBuilder::build` fails for `is_root(true)` with a non-root caller ARN. A user named `root` (any case) is refused; attaching a policy from another tenant is `InvalidParameter`.
* **auth:** `ConditionError` gains the `InvalidConditionValue` variant; `parse_condition_block` refuses unknown operators and unreadable values it used to accept; `evaluate_condition_block` returns `Err` where an operator error used to be `Ok(false)`.

### Bug Fixes

* **auth:** a guard judges the target; a principal is (tenant, name) ([#149](https://github.com/Lsh0x/wami/issues/149)) ([829b2ff](https://github.com/Lsh0x/wami/commit/829b2ffc64c3ba2b20953a934132aee58d973b05))
* **auth:** an unreadable policy refuses the decision — it never reads as false ([#147](https://github.com/Lsh0x/wami/issues/147)) ([68cc532](https://github.com/Lsh0x/wami/commit/68cc532dfb71a7dc19c960ab08a6ed08d0015382))

## [0.18.0](https://github.com/Lsh0x/wami/compare/wami-core-v0.17.0...wami-core-v0.18.0) (2026-08-10)


### ⚠ BREAKING CHANGES

* `space:*` no longer parses. `WamiAction::SpaceRead`, `SpaceUpdate` and `SpaceDelete` are removed — use the `tenant:` equivalents, which already existed — and the other five are renamed. `WamiServicePrefix::Space` is gone. Any stored policy document naming a `space:` action will stop matching: `WamiAction::from_str` refuses it, and `matches_pattern` compares strings, so an Allow silently grants nothing and a Deny silently denies nothing. Rewrite them before upgrading.

### Refactoring

* a space was a tenant, and three actions had two names ([#143](https://github.com/Lsh0x/wami/issues/143)) ([faac409](https://github.com/Lsh0x/wami/commit/faac4096a6fa9537a5b933f8f709d8fa67ff63b2))

## [0.17.0](https://github.com/Lsh0x/wami/compare/wami-core-v0.16.0...wami-core-v0.17.0) (2026-08-09)


### ⚠ BREAKING CHANGES

* **core:** fold wami-traits in, and stop the macros naming it relatively ([#130](https://github.com/Lsh0x/wami/issues/130))
* **auth:** `Authorizer::authorize` and `AuthorizationService::authorize` return `Result<Decision>` instead of `Result<bool>`; call `.is_allowed()` for the old boolean. `evaluate_policy_document` returns `Option<StatementHit>` instead of `PolicyEffect`. `parse_policy_doc` returns `Result` and takes the `PolicySource` it is parsing. `PolicyStatement` has a new `sid` field. Policy documents that are valid JSON but not valid policies are now rejected on write.
* AmiError loses AwsSdk, StsSdk and SsoAdminSdk. Provider translations move behind features, off by default.

### Features

* **auth:** authorize returns a motivated Decision, and an unreadable policy is an error ([#121](https://github.com/Lsh0x/wami/issues/121)) ([9b1d44c](https://github.com/Lsh0x/wami/commit/9b1d44c675d8766fc849cf51f79371183f340202))
* **context:** record how authority was obtained, without touching ARNs ([#108](https://github.com/Lsh0x/wami/issues/108)) ([55959fc](https://github.com/Lsh0x/wami/commit/55959fcf802f44cfcd418c8c37311e1d070fd076)), closes [#49](https://github.com/Lsh0x/wami/issues/49)
* **context:** render provenance as one queryable trail ([#110](https://github.com/Lsh0x/wami/issues/110)) ([c49256d](https://github.com/Lsh0x/wami/commit/c49256d62fad940199a71c921dd2633e0d80a4a5)), closes [#49](https://github.com/Lsh0x/wami/issues/49)
* **sts:** JWT Ed25519 signed tokens for STS services ([#98](https://github.com/Lsh0x/wami/issues/98)) ([546d8b7](https://github.com/Lsh0x/wami/commit/546d8b764026d5502c4da20b7f0710118e852b36))


### Bug Fixes

* **ci:** labeler workflow — remove unsupported body-contains option, ([546d8b7](https://github.com/Lsh0x/wami/commit/546d8b764026d5502c4da20b7f0710118e852b36))
* **context:** close two holes a second review found in provenance ([#109](https://github.com/Lsh0x/wami/issues/109)) ([f5e9c0a](https://github.com/Lsh0x/wami/commit/f5e9c0aa0f0cff5a49becceada0113f5771e6fe3))
* **deps:** drop the AWS HTTP stack, which broke the Windows CI ([#103](https://github.com/Lsh0x/wami/issues/103)) ([3853062](https://github.com/Lsh0x/wami/commit/3853062e14b0c8f448b35ed54e30d62dcf83f6ac))


### Refactoring

* **arn:** one file per provider transformer ([#111](https://github.com/Lsh0x/wami/issues/111)) ([08c5eba](https://github.com/Lsh0x/wami/commit/08c5eba43c690ffbf04a216c317b707389bd5737))
* **context:** derive tenant, instance and root from the caller ARN ([#101](https://github.com/Lsh0x/wami/issues/101)) ([534e962](https://github.com/Lsh0x/wami/commit/534e9622122e4f8116a04f212fe110fbb620b842)), closes [#67](https://github.com/Lsh0x/wami/issues/67)
* **core:** fold wami-traits in, and stop the macros naming it relatively ([#130](https://github.com/Lsh0x/wami/issues/130)) ([6147ea4](https://github.com/Lsh0x/wami/commit/6147ea4a8bb91732d28b884fc61437be6d554450))
* no cloud provider knowledge in a default build ([#112](https://github.com/Lsh0x/wami/issues/112)) ([8f9938b](https://github.com/Lsh0x/wami/commit/8f9938b73d6f01383e597c2bbb0e1c3d3c4f4794))
* Reorganize codebase into workspace structure ([#72](https://github.com/Lsh0x/wami/issues/72)) ([11da721](https://github.com/Lsh0x/wami/commit/11da721699dd732aac0bcd53726cdaae7456343e))
