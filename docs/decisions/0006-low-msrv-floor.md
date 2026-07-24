# 6. Low MSRV floor (1.75), decoupled from the dev toolchain

Date: 2026-07-24
Status: Accepted

## Context

`forensic-hashdb` is a published library that other fleet crates link
(`issen-mem`, `issen-signatures`, and any future consumer). The fleet MSRV
policy separates the **dev toolchain** (what the repo builds/clippy/fmt with)
from the **declared MSRV** (`rust-version` — a downstream compatibility
promise). For published libraries the promise is kept low and CI-verified so the
crate stays reusable by consumers on older toolchains; only apps declare their
MSRV equal to the pinned toolchain.

This repo pins its dev toolchain to the current fleet stable
(`rust-toolchain.toml` → `channel = "1.96.0"`).

## Decision

Declare `rust-version = "1.75"` in `Cargo.toml`, well below the `1.96.0` dev
toolchain, treating the low floor as a deliberate compatibility feature — not an
accident to be bumped up to match the toolchain. The crate uses only APIs
available on 1.75 (`OnceLock`, `let … else`, mmap via `memmap2`). Raise the
floor only if a genuinely-needed newer-Rust feature demands it, since raising a
published crate's MSRV narrows its audience and is a near-breaking change.

## Consequences

- Consumers on Rust 1.75+ can link the crate without a toolchain bump.
- The dev toolchain and the promised MSRV move independently: the fleet can bump
  the pinned stable without touching this floor.
- The 1.75 floor is a claim CI should verify (a low-MSRV job), matching how
  `forensicnomicon` and the `*-core` readers verify theirs; the README badges
  `Rust 1.75+`.
