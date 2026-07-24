# 5. Panic-free posture: unsafe=deny with one bounded mmap allow, fuzzed, 100% coverage

Date: 2026-07-24
Status: Accepted

## Context

The crate reads analyst-supplied files — a binary known-good DB it maps into
memory, and text/CSV IOC feeds — so its inputs are untrusted and
attacker-influenceable. Under the fleet Paranoid Gatekeeper standard, a crate
that parses untrusted bytes must never panic, never read out of bounds, and
never trust a length field.

The base fleet recipe is `unsafe_code = "forbid"`. But `known_good` needs
exactly one `unsafe` block: `memmap2::MmapOptions::map`, which is inherently
`unsafe` in its API. `forbid` cannot be locally overridden by an `#[allow]`, so
`forbid` is incompatible with a single justified mmap site.

## Decision

1. **Downgrade the lint to `unsafe_code = "deny"` and grant one bounded per-site
   `#[allow(unsafe_code)]`** at the mmap in `known_good.rs`, with an inline
   `// SAFETY:` note stating the invariant (file opened read-only; caller must
   not mutate while mapped — the standard mmap contract). This is the exact
   `deny` + bounded-allow exception the fleet already accepts for `ewf`'s mmap
   scanners; `rg 'allow(unsafe_code)'` is the complete audit surface (one site).
2. **Deny `clippy::unwrap_used` and `expect_used` in production** (`Cargo.toml`
   `[lints.clippy]`); production reads are bounds-checked and degrade to a
   non-match/skip instead of panicking.
3. **Fuzz every untrusted-input surface.** `fuzz/fuzz_targets/fuzz_known_good.rs`
   opens arbitrary bytes as a DB and runs `is_known_good`;
   `fuzz/fuzz_targets/fuzz_feed.rs` loads arbitrary text/CSV into a `HashFeed`
   and queries it. Both must never panic.
4. **Keep 100% production line coverage**, with the one genuinely-unreachable
   defensive guard (the binary-search slice fallback in `known_good`) annotated
   `// cov:unreachable: mid < count bounds the slice` rather than deleted — the
   defense-in-depth net stays, the coverage gate exempts only that annotated
   line. A second `// cov:unreachable` guards the `parse_hex` chunk loop in
   `lol_drivers` (table entries are exactly 64 hex chars).

## Consequences

- Malformed input degrades to an error, a non-match, or a skipped line — never a
  crash or a raw-pointer path.
- The README and badges advertise "fuzzed" as the measured claim and
  "panic-free by lint" as the qualified static posture; the crate carries the
  `unsafe deny` badge posture, **not** an `unsafe-forbidden` badge, because it
  has one bounded allow (honest labeling per Evidence-Based Rigor).
- The static lints occasionally require more verbose bounds-checked code than a
  quick `unwrap`; that is the accepted cost of the posture.
