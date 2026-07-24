# 1. A standalone, source-agnostic hash-lookup crate

Date: 2026-07-24
Status: Accepted

## Context

A file's hash means the same thing wherever the bytes came from — a page
carved out of a memory dump, a `$DATA` run in an NTFS image, or a file on a
live disk. "Have I seen this hash before?" is therefore one question, not one
question per acquisition path.

The code that answered it originally lived at
`memory-forensic/crates/forensic-hashdb`, but **no `memory-forensic` crate ever
depended on it** — it was a publishing home of convenience (commit `a6bed2d`).
Meanwhile two *different* paths grew a need for it: the memory-triage path
(`issen-mem`) and the disk/scan path (`issen-signatures`). Keeping a
cross-repo capability buried inside one consumer's repo inverts the dependency
story and hides it from the other consumer.

The fleet's own precedent for "a leaf capability with many consumers lives on
its own" is `forensicnomicon` and `4n6mount`.

## Decision

1. Extract the crate into its own standalone repository, `forensic-hashdb`,
   rooted by an empty `[workspace]` table in `Cargo.toml` so cargo never joins
   a parent workspace (see the header comment in `Cargo.toml`).
2. Make source-agnosticism the organizing principle: the databases are keyed on
   a raw `&[u8; 32]` SHA-256 (or a hex string, for analyst feeds) — never on a
   file path, an offset, or an acquisition-medium type. The same
   `is_known_good(&sha256)` / `lookup(&sha256)` call serves the memory path and
   the disk path identically.
3. Position it as the fleet's single hash-lookup home — one implementation, not
   a memory-side copy and a disk-side copy.

## Consequences

- Both consumers depend *down* onto one leaf; adding a fifth database or a new
  provenance source benefits every consumer at once.
- The crate carries the fleet panic-free lint recipe as a first-class repo
  (see ADR 0005), rather than inheriting a parent workspace's config.
- The original extraction commit (`a6bed2d`) cited this decision as "ADR-0011",
  the number it would have carried in `memory-forensic`'s ADR sequence; in this
  standalone repo it is renumbered 0001 as the founding decision. Later
  in-code references to "ADR-0011" (`feed.rs`, `Cargo.toml`) point at this same
  decision.
