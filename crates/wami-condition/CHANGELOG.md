# Changelog

## [0.18.0](https://github.com/Lsh0x/wami/compare/wami-condition-v0.17.1...wami-condition-v0.18.0) (2026-10-22)


### ⚠ BREAKING CHANGES

* **auth:** store traits take `&ScopedName` (tenant, name) for every principal, group, owner and certificate argument, and lists take `&TenantPath`; the bare-name methods are removed, and a create on a held key is `ResourceExists`. `iam_resource_arn` is removed (use `target_arn`/`tenant_arn` or the guards in `wami::service::auth`). `authorize` and every guard refuse a non-root context whose caller key names no stored user or whose user's ARN is not the caller ARN. `WamiArn::is_root_user` is true only at tenant path exactly `0`, and `WamiContextBuilder::build` fails for `is_root(true)` with a non-root caller ARN. A user named `root` (any case) is refused; attaching a policy from another tenant is `InvalidParameter`.
* **auth:** `ConditionError` gains the `InvalidConditionValue` variant; `parse_condition_block` refuses unknown operators and unreadable values it used to accept; `evaluate_condition_block` returns `Err` where an operator error used to be `Ok(false)`.

### Bug Fixes

* **auth:** a guard judges the target; a principal is (tenant, name) ([#149](https://github.com/Lsh0x/wami/issues/149)) ([829b2ff](https://github.com/Lsh0x/wami/commit/829b2ffc64c3ba2b20953a934132aee58d973b05))
* **auth:** an unreadable policy refuses the decision — it never reads as false ([#147](https://github.com/Lsh0x/wami/issues/147)) ([68cc532](https://github.com/Lsh0x/wami/commit/68cc532dfb71a7dc19c960ab08a6ed08d0015382))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * wami-core bumped from 0.18.0 to 0.19.0

## [0.17.1](https://github.com/Lsh0x/wami/compare/wami-condition-v0.17.0...wami-condition-v0.17.1) (2026-08-10)


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * wami-core bumped from 0.17.0 to 0.18.0

## [0.17.0](https://github.com/Lsh0x/wami/compare/wami-condition-v0.16.0...wami-condition-v0.17.0) (2026-08-09)


### Features

* implement policy condition keys evaluation ([#77](https://github.com/Lsh0x/wami/issues/77)) ([500d8db](https://github.com/Lsh0x/wami/commit/500d8db9dfe55c0459314635ab2664ff15a4e403))
* **sts:** JWT Ed25519 signed tokens for STS services ([#98](https://github.com/Lsh0x/wami/issues/98)) ([546d8b7](https://github.com/Lsh0x/wami/commit/546d8b764026d5502c4da20b7f0710118e852b36))


### Bug Fixes

* **ci:** labeler workflow — remove unsupported body-contains option, ([546d8b7](https://github.com/Lsh0x/wami/commit/546d8b764026d5502c4da20b7f0710118e852b36))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * wami-core bumped from 0.16.0 to 0.17.0
