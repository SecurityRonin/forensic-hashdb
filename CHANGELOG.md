# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/SecurityRonin/forensic-hashdb/compare/forensic-hashdb-v0.2.1...forensic-hashdb-v0.2.2) - 2026-08-08

### Fixed

- *(supply-chain)* vet records for the versions the MSRV pin resolves
- *(msrv)* pin getrandom down to 0.3.4 so `cargo test` runs at the declared 1.75

### Other

- adopt the canonical workspace lints block

## [0.2.1](https://github.com/SecurityRonin/forensic-hashdb/compare/forensic-hashdb-v0.2.0...forensic-hashdb-v0.2.1) - 2026-07-25

### Documentation

- reverse-write PRD + ADRs; mkdocs excludes governance docs (fleet standard)
- use verbatim Apache-2.0 license text

### Fixed

- *(vet)* declare own crates first-party so version bumps don't break supply-chain audit
