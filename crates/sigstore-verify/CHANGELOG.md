# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.4](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-verify-v0.6.3...sigstore-verify-v0.6.4) - 2026-02-26

### Fixed

- be more strict about unknown key types and verification ([#70](https://github.com/prefix-dev/sigstore-rust/pull/70))

## [0.6.2](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-verify-v0.6.1...sigstore-verify-v0.6.2) - 2026-02-04

### Other

- add native-tls feature, bump reqwest ([#51](https://github.com/prefix-dev/sigstore-rust/pull/51))

## [0.6.1](https://github.com/prefix-dev/sigstore-rust/compare/sigstore-verify-v0.6.0...sigstore-verify-v0.6.1) - 2026-01-26

### Fixed

- *(conformance)* add verification with key ([#41](https://github.com/prefix-dev/sigstore-rust/pull/41))

## [0.6.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.5.0...sigstore-verify-v0.6.0) - 2025-12-08

### Added

- add fuzzing tests ([#13](https://github.com/wolfv/sigstore-rust/pull/13))

### Other

- improve types and add interop test workflow ([#9](https://github.com/wolfv/sigstore-rust/pull/9))

## [0.5.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.4.0...sigstore-verify-v0.5.0) - 2025-12-01

### Added

- Add SigningConfig support and V2 bundle fixes ([#6](https://github.com/wolfv/sigstore-rust/pull/6))

## [0.4.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.3.0...sigstore-verify-v0.4.0) - 2025-11-28

### Other

- introduce new artifact api

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.2.0...sigstore-verify-v0.3.0) - 2025-11-28

### Other

- make all interfaces more type safe
- remove more types
- improve sign / verify flow, add conda specific test
- more cleanup of functions
- remove manual verification code and use webpki

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.1.1...sigstore-verify-v0.2.0) - 2025-11-27

### Other

- require trust root in constructor, remove more unused code, update readme
- remove duplicated types, add license and readme files

## [0.1.1](https://github.com/wolfv/sigstore-rust/compare/sigstore-verify-v0.1.0...sigstore-verify-v0.1.1) - 2025-11-27

### Fixed

- fix verification
- fix publishing

### Other

- add conformance test
- add all test data
- add tests for verify
- add new crates
