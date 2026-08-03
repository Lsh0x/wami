# Changelog

All notable changes to this project will be documented in this file.

## [0.17.0](https://github.com/Lsh0x/wami/compare/v0.16.0...v0.17.0) (2026-08-03)


### ⚠ BREAKING CHANGES

* fold the provider crates and wami-credentials into wami ([#131](https://github.com/Lsh0x/wami/issues/131))
* **core:** fold wami-traits in, and stop the macros naming it relatively ([#130](https://github.com/Lsh0x/wami/issues/130))

### Refactoring

* **core:** fold wami-traits in, and stop the macros naming it relatively ([#130](https://github.com/Lsh0x/wami/issues/130)) ([6147ea4](https://github.com/Lsh0x/wami/commit/6147ea4a8bb91732d28b884fc61437be6d554450))
* fold the provider crates and wami-credentials into wami ([#131](https://github.com/Lsh0x/wami/issues/131)) ([0f11cf5](https://github.com/Lsh0x/wami/commit/0f11cf5140ed93334e258be690d4942c3b662e4f))

## [0.16.0](https://github.com/Lsh0x/wami/compare/v0.15.0...v0.16.0) (2026-08-02)


### ⚠ BREAKING CHANGES

* **oauth:** `build_client` takes a seventh argument, `redirect_uris`. Pass `vec![]` for a client that only uses `client_credentials`.
* **oauth:** `AuthorizationCode`, `RefreshToken`, `AuthorizationRequest` and `IdTokenRequest` each gain an `event` field. Store implementers constructing them literally need `event: None`; both persisted structs carry `#[serde(default)]`, so records already in a database deserialise unchanged.
* **oauth:** `KeyManager::verify_claims_as` takes a fourth argument, `TypePolicy`. `KeyManager::verify_claims` is unchanged and still examines no `typ` — that contract predates RFC 9068 typing and was not narrowed.
* **oauth:** `build_client` refuses a client whose `audience` equals its `client_id`. An access token and an ID token would then be addressed identically, and `aud` would stop separating them.

### Features

* **oauth:** OpenID Connect user flows — code + PKCE, consent, rotation ([#124](https://github.com/Lsh0x/wami/issues/124)) ([fc119cc](https://github.com/Lsh0x/wami/commit/fc119cc74b5781eae7a0885a3998d4854784aab7)), closes [#119](https://github.com/Lsh0x/wami/issues/119)
* **oauth:** explicit token typing (RFC 9068) and authentication-event claims ([#126](https://github.com/Lsh0x/wami/issues/126)) ([2a75c98](https://github.com/Lsh0x/wami/commit/2a75c987be0cdda7fab240218c313820761672e7)), closes [#125](https://github.com/Lsh0x/wami/issues/125)


### Documentation

* **oauth:** guide for the authorization server and the OpenID Provider, with an end-to-end sequence diagram ([#126](https://github.com/Lsh0x/wami/issues/126))

## [0.15.0](https://github.com/Lsh0x/wami/compare/v0.14.0...v0.15.0) (2026-08-02)


### ⚠ BREAKING CHANGES

* **auth:** `Authorizer::authorize` and `AuthorizationService::authorize` return `Result<Decision>` instead of `Result<bool>`; call `.is_allowed()` for the old boolean. `evaluate_policy_document` returns `Option<StatementHit>` instead of `PolicyEffect`. `parse_policy_doc` returns `Result` and takes the `PolicySource` it is parsing. `PolicyStatement` has a new `sid` field. Policy documents that are valid JSON but not valid policies are now rejected on write.
* every service constructor takes `Arc<tokio::sync::RwLock<S>>` instead of `Arc<std::sync::RwLock<S>>`, and `store()` returns the same. Callers swap `use std::sync::RwLock` for `use tokio::sync::RwLock`.
* **sts:** `KeyManager::verify_token` takes the expected audience as a second argument. Callers relying on the previous behaviour pass `"wami"`.

### Features

* **auth:** authorize returns a motivated Decision, and an unreadable policy is an error ([#121](https://github.com/Lsh0x/wami/issues/121)) ([9b1d44c](https://github.com/Lsh0x/wami/commit/9b1d44c675d8766fc849cf51f79371183f340202))
* **oauth:** issue, introspect and revoke machine-to-machine tokens ([#122](https://github.com/Lsh0x/wami/issues/122)) ([a4a3744](https://github.com/Lsh0x/wami/commit/a4a3744e83cd41a85d1cf572a49b469f8c6848e6))


### Bug Fixes

* **sts:** verify_token takes the expected audience ([#116](https://github.com/Lsh0x/wami/issues/116)) ([99041e9](https://github.com/Lsh0x/wami/commit/99041e948236657f4cff993dea2c177d7c98f89a)), closes [#114](https://github.com/Lsh0x/wami/issues/114)


### Refactoring

* settle every store lock on tokio::sync::RwLock ([#117](https://github.com/Lsh0x/wami/issues/117)) ([0adf805](https://github.com/Lsh0x/wami/commit/0adf805a4db8979680551375679502e264591d82))

## [0.14.0](https://github.com/Lsh0x/wami/compare/v0.13.0...v0.14.0) (2026-08-01)


### ⚠ BREAKING CHANGES

* AmiError loses AwsSdk, StsSdk and SsoAdminSdk. Provider translations move behind features, off by default.

### Refactoring

* no cloud provider knowledge in a default build ([#112](https://github.com/Lsh0x/wami/issues/112)) ([8f9938b](https://github.com/Lsh0x/wami/commit/8f9938b73d6f01383e597c2bbb0e1c3d3c4f4794))

## [0.13.0](https://github.com/Lsh0x/wami/compare/v0.12.0...v0.13.0) (2026-08-01)


### Features

* implement policy condition keys evaluation ([#77](https://github.com/Lsh0x/wami/issues/77)) ([500d8db](https://github.com/Lsh0x/wami/commit/500d8db9dfe55c0459314635ab2664ff15a4e403))
* **sts:** carry a kid in tokens, and let keys rotate ([#105](https://github.com/Lsh0x/wami/issues/105)) ([cb0be6d](https://github.com/Lsh0x/wami/commit/cb0be6dfc9e67be2c04bcc4bcd8a868f37e3aad4)), closes [#102](https://github.com/Lsh0x/wami/issues/102)
* **sts:** JWT Ed25519 signed tokens for STS services ([#98](https://github.com/Lsh0x/wami/issues/98)) ([546d8b7](https://github.com/Lsh0x/wami/commit/546d8b764026d5502c4da20b7f0710118e852b36))


### Bug Fixes

* **ci:** labeler workflow — remove unsupported body-contains option, ([546d8b7](https://github.com/Lsh0x/wami/commit/546d8b764026d5502c4da20b7f0710118e852b36))
* **ci:** release-please rejects the changelog path ([#106](https://github.com/Lsh0x/wami/issues/106)) ([66ce599](https://github.com/Lsh0x/wami/commit/66ce599afcfa0422c0f78cd7a207fdba5594e58c))
* **deps:** drop the AWS HTTP stack, which broke the Windows CI ([#103](https://github.com/Lsh0x/wami/issues/103)) ([3853062](https://github.com/Lsh0x/wami/commit/3853062e14b0c8f448b35ed54e30d62dcf83f6ac))


### Refactoring

* **context:** derive tenant, instance and root from the caller ARN ([#101](https://github.com/Lsh0x/wami/issues/101)) ([534e962](https://github.com/Lsh0x/wami/commit/534e9622122e4f8116a04f212fe110fbb620b842)), closes [#67](https://github.com/Lsh0x/wami/issues/67)
* Reorganize codebase into workspace structure ([#72](https://github.com/Lsh0x/wami/issues/72)) ([11da721](https://github.com/Lsh0x/wami/commit/11da721699dd732aac0bcd53726cdaae7456343e))

## [0.12.0] - 2025-10-31

### 🚀 Features

- Complete ARN migration and fix all doc tests (#68)
- Implement opaque numeric tenant IDs (Issue #47) (#70)

### 📚 Documentation

- Update README with ARN support and correct WamiContext usage (#69)

### 🚜 Refactor

- Organize documentation files (#71)

## [0.11.0] - 2025-10-30

### 🚀 Features

- Implement policy attachment to users, groups, and roles (Issue #27)

### ⚙️ Miscellaneous Tasks

- **release:** V0.11.0 [skip ci]

## [0.10.1] - 2025-10-30

### 🐛 Bug Fixes

- **ci:** Correct codecov workflow conditional syntax

### ⚙️ Miscellaneous Tasks

- **release:** V0.10.1 [skip ci]

## [0.10.0] - 2025-10-30

### 🚀 Features

- Implement permissions boundaries (Issue #22)

### ⚙️ Miscellaneous Tasks

- **release:** V0.10.0 [skip ci]

## [0.9.0] - 2025-10-30

### 🚀 Features

- Add multicloud provider infrastructure (Phase 1)
- Integrate provider system into Store traits (Phase 2)
- Refactor IAM modules to use CloudProvider (Phase 3a)
- Refactor roles.rs to use CloudProvider (Phase 3b)
- Refactor policies.rs to use CloudProvider (Phase 3c)
- Refactor server_certificates.rs to use CloudProvider (Phase 3d)
- **multicloud:** Complete Phase 3 - refactor remaining IAM modules to use CloudProvider
- **multicloud:** Add comprehensive provider tests and multicloud documentation (Phase 4)
- Add WAMI ARN and provider tracking to all resources
- Implement hierarchical multi-tenant architecture
- Implement hierarchical multi-tenant architecture
- Refactor tenant authorization to use IAM policy evaluation
- Implement secure ARN-centric architecture (Phase 1)
- Unified ARN-centric store architecture with comprehensive documentation
- Add ARN fields to STS and Tenant models for unified store
- Update IAM builders to use WamiArnBuilder for opaque ARNs
- Major refactor to pure function architecture
- Complete service layer implementation with 23 services
- Add 21 working examples with comprehensive documentation
- Implement Identity Provider Module (Issue #19)

### 🐛 Bug Fixes

- Replace rustyiam with wami in doc examples
- Update tests to work with new client API
- Add clippy allow for result_large_err in ARN parsing
- Correct doctest imports and ARN reconstruction
- Fix rustdoc bare URL warning in identity provider model
- **ci:** Correct package name from rustyiam to wami in auto-release workflow

### 📚 Documentation

- Add multicloud implementation status tracker
- Update multicloud status - implementation complete ✅
- Fix broken intra-doc links in IAM, STS, and SSO Admin modules
- Add comprehensive documentation structure
- Phase 2 ARN-Centric Architecture COMPLÉTÉE 🎉
- Fix all doc test examples for new architecture

### 🚜 Refactor

- Rename project from rustyiam to WAMI (Who Am I)
- Reorganize store module structure
- Extract resource builders from client logic
- **user:** Migrate User to self-contained resource structure
- Move user resource from resources/ to iam/
- Remove redundant builders/ directory
- Migrate group resource to self-contained structure
- Migrate role resource to self-contained structure
- Migrate policy resource to self-contained structure
- Migrate access_key resource to self-contained structure
- Migrate mfa_device resource to self-contained structure
- Migrate login_profile resource to self-contained structure
- **iam:** Convert all modules to self-contained structure
- **sts:** Convert to self-contained module structure
- Move tenant store to centralized store module
- Consolidate tenant authorization logic and simplify store traits

### ⚙️ Miscellaneous Tasks

- **release:** V0.9.0 [skip ci]

## [0.8.0] - 2025-10-26

### 🚀 Features

- Implement signing certificates module

### ⚙️ Miscellaneous Tasks

- **release:** V0.8.0 [skip ci]

## [0.7.0] - 2025-10-26

### 🚀 Features

- Implement service-linked roles module

### ⚙️ Miscellaneous Tasks

- **release:** V0.7.0 [skip ci]

## [0.6.0] - 2025-10-26

### 🚀 Features

- Implement service-specific credentials module

### ⚙️ Miscellaneous Tasks

- **release:** V0.6.0 [skip ci]

## [0.5.0] - 2025-10-26

### 🚀 Features

- Implement server certificates module for SSL/TLS certificate management

### ⚙️ Miscellaneous Tasks

- **release:** V0.5.0 [skip ci]

## [0.4.0] - 2025-10-26

### 🚀 Features

- Implement IAM reports module (credential reports and account summary)

### ⚙️ Miscellaneous Tasks

- **release:** V0.4.0 [skip ci]

## [0.3.0] - 2025-10-25

### 🚀 Features

- Implement IAM policy evaluation/simulation module

### ⚙️ Miscellaneous Tasks

- **release:** V0.3.0 [skip ci]

## [0.2.7] - 2025-10-25

### 🚜 Refactor

- Implement IAM resource tagging using IamStore trait

### ⚙️ Miscellaneous Tasks

- **release:** V0.2.7 [skip ci]

## [0.2.6] - 2025-10-25

### 🚜 Refactor

- Implement IAM policy methods using IamStore trait

### ⚙️ Miscellaneous Tasks

- **release:** V0.2.6 [skip ci]

## [0.2.5] - 2025-10-25

### 🚜 Refactor

- Implement login profile (password) methods using IamStore trait

### ⚙️ Miscellaneous Tasks

- **release:** V0.2.5 [skip ci]

## [0.2.4] - 2025-10-25

### 🚜 Refactor

- Implement roles methods using IamStore trait

### ⚙️ Miscellaneous Tasks

- **release:** V0.2.4 [skip ci]

## [0.2.3] - 2025-10-25

### 🚜 Refactor

- Implement MFA devices methods using IamStore trait

### ⚙️ Miscellaneous Tasks

- **release:** V0.2.3 [skip ci]

## [0.2.2] - 2025-10-25

### 🚜 Refactor

- Implement groups methods using IamStore trait

### ⚙️ Miscellaneous Tasks

- **release:** V0.2.2 [skip ci]

## [0.2.1] - 2025-10-25

### 🚜 Refactor

- Implement access_keys methods using IamStore trait

### ⚙️ Miscellaneous Tasks

- **release:** V0.2.1 [skip ci]

## [0.2.0] - 2025-10-25

### 🚀 Features

- Initial AWS IAM, STS, and SSO Admin operations library
- Complete in-memory AWS IAM, STS, and SSO Admin implementation
- Implement trait-based store architecture for easy backend swapping
- Complete trait-based architecture refactoring for STS and SSO Admin
- Implement dynamic AWS account ID generation
- Add account ID retrieval and logging capabilities
- Add AWS environment variable logging and export functionality
- Rename package to rustyiam and set MSRV to 1.81.0
- Add automatic version bumping and docs deployment workflow
- **hooks:** Add conventional commit template hook

### 🐛 Bug Fixes

- Correct AWS SSO Admin SDK package name
- Resolve build errors and ensure CI compatibility
- Resolve all clippy warnings for CI
- Remove Cargo.lock for library crate
- **ci:** Resolve workflow issues and add setup guide
- **ci:** Correct all GitHub Actions workflow issues
- **ci:** Make codecov upload optional and non-blocking
- **ci:** Simplify release workflow
- Replace git-cliff-action with manual install due to Debian Buster EOL

### 📚 Documentation

- Add comprehensive rustdoc with examples and reorganize README
- Add versioning section to README
- Add comprehensive versioning and release documentation
- **hooks:** Update README with prepare-commit-msg hook info
- Add repository setup reference to README

### 🚜 Refactor

- **ci:** Simplify workfkow

### 🧪 Testing

- Add comprehensive unit and integration tests

### ⚙️ Miscellaneous Tasks

- Modernize and enhance GitHub Actions workflows
- Add pre-commit hooks for code quality
- Update MSRV to 1.86.0
- Update MSRV to 1.90.0
- **release:** V0.2.0 [skip ci]

<!-- generated by git-cliff -->
