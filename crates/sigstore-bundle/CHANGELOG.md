# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-bundle-v0.5.0...sigstore-bundle-v0.6.0) - 2025-12-08

### Added

- add fuzzing tests ([#13](https://github.com/wolfv/sigstore-rust/pull/13))

### Other

- improve types and add interop test workflow ([#9](https://github.com/wolfv/sigstore-rust/pull/9))

## [0.5.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-bundle-v0.4.0...sigstore-bundle-v0.5.0) - 2025-12-01

### Added

- Add SigningConfig support and V2 bundle fixes ([#6](https://github.com/wolfv/sigstore-rust/pull/6))

## [0.3.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-bundle-v0.2.0...sigstore-bundle-v0.3.0) - 2025-11-28

### Other

- remove more types
- remove certifactePem
- unify certificate encoding
- simplifications by only supporting v03 bundle creation
- improve sign / verify flow, add conda specific test

## [0.2.0](https://github.com/wolfv/sigstore-rust/compare/sigstore-bundle-v0.1.1...sigstore-bundle-v0.2.0) - 2025-11-27

### Other

- remove duplicated types, add license and readme files

## [0.1.1](https://github.com/wolfv/sigstore-rust/compare/sigstore-bundle-v0.1.0...sigstore-bundle-v0.1.1) - 2025-11-27

### Fixed

- fix publishing
- fix clippy
- fix up
- fix other conformance issue

### Other

- fmt
- more type safety
- more simplifications
- slim down codebase
- some clean up
- improve dsse verification
- add happy-path bundle
- remove raw json stuff as it should not be needed
- hash raw dsse
- more type safety
- type safety improvements
- make the conformance suite pass
- initial commit
