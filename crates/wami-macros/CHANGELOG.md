# Changelog

## [0.18.0](https://github.com/Lsh0x/wami/compare/wami-macros-v0.17.0...wami-macros-v0.18.0) (2026-08-09)


### ⚠ BREAKING CHANGES

* **core:** fold wami-traits in, and stop the macros naming it relatively ([#130](https://github.com/Lsh0x/wami/issues/130))
* every service constructor takes `Arc<tokio::sync::RwLock<S>>` instead of `Arc<std::sync::RwLock<S>>`, and `store()` returns the same. Callers swap `use std::sync::RwLock` for `use tokio::sync::RwLock`.
* AmiError loses AwsSdk, StsSdk and SsoAdminSdk. Provider translations move behind features, off by default.

### Refactoring

* **core:** fold wami-traits in, and stop the macros naming it relatively ([#130](https://github.com/Lsh0x/wami/issues/130)) ([6147ea4](https://github.com/Lsh0x/wami/commit/6147ea4a8bb91732d28b884fc61437be6d554450))
* no cloud provider knowledge in a default build ([#112](https://github.com/Lsh0x/wami/issues/112)) ([8f9938b](https://github.com/Lsh0x/wami/commit/8f9938b73d6f01383e597c2bbb0e1c3d3c4f4794))
* Reorganize codebase into workspace structure ([#72](https://github.com/Lsh0x/wami/issues/72)) ([11da721](https://github.com/Lsh0x/wami/commit/11da721699dd732aac0bcd53726cdaae7456343e))
* settle every store lock on tokio::sync::RwLock ([#117](https://github.com/Lsh0x/wami/issues/117)) ([0adf805](https://github.com/Lsh0x/wami/commit/0adf805a4db8979680551375679502e264591d82))

## [0.17.0](https://github.com/Lsh0x/wami/compare/wami-macros-v0.16.0...wami-macros-v0.17.0) (2026-08-09)


### ⚠ BREAKING CHANGES

* **core:** fold wami-traits in, and stop the macros naming it relatively ([#130](https://github.com/Lsh0x/wami/issues/130))
* every service constructor takes `Arc<tokio::sync::RwLock<S>>` instead of `Arc<std::sync::RwLock<S>>`, and `store()` returns the same. Callers swap `use std::sync::RwLock` for `use tokio::sync::RwLock`.
* AmiError loses AwsSdk, StsSdk and SsoAdminSdk. Provider translations move behind features, off by default.

### Refactoring

* **core:** fold wami-traits in, and stop the macros naming it relatively ([#130](https://github.com/Lsh0x/wami/issues/130)) ([6147ea4](https://github.com/Lsh0x/wami/commit/6147ea4a8bb91732d28b884fc61437be6d554450))
* no cloud provider knowledge in a default build ([#112](https://github.com/Lsh0x/wami/issues/112)) ([8f9938b](https://github.com/Lsh0x/wami/commit/8f9938b73d6f01383e597c2bbb0e1c3d3c4f4794))
* Reorganize codebase into workspace structure ([#72](https://github.com/Lsh0x/wami/issues/72)) ([11da721](https://github.com/Lsh0x/wami/commit/11da721699dd732aac0bcd53726cdaae7456343e))
* settle every store lock on tokio::sync::RwLock ([#117](https://github.com/Lsh0x/wami/issues/117)) ([0adf805](https://github.com/Lsh0x/wami/commit/0adf805a4db8979680551375679502e264591d82))
