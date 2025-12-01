# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
