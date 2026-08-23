# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog], and this project follows
[Semantic Versioning].

## [Unreleased]

## [0.1.0] - 2026-08-23

### Added

- Pure Rust `.narinfo` parsing with a one-mebibyte input limit and structured
  errors.
- Canonical, store-aware writing with sorted and deduplicated references.
- Typed compression values with forward-compatible unknown names.
- Nix cache fingerprint construction and Ed25519 public-key/signature
  verification.
- Pure content-addressed path verification through `nix-derivation` identity
  types.
- Validated construction through `NarInfoBuilder`.
- Nix-generated offline golden, optional live Nix parity test, and public parser
  fuzz target.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[Unreleased]: https://github.com/cachix/nix-narinfo/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cachix/nix-narinfo/releases/tag/v0.1.0
