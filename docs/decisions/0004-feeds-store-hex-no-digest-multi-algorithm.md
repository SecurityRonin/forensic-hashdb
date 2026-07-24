# 4. Analyst feeds store hex strings, do not compute digests, and are multi-algorithm

Date: 2026-07-24
Status: Accepted

## Context

Analysts arrive with ad-hoc IOC lists — a ThreatFox export, a colleague's CSV,
an internal blocklist. Unlike the curated NSRL/malware databases, these are:

- **multi-algorithm** — MD5, SHA-1, and SHA-256 hashes are mixed in the wild,
  because different feeds standardize on different digests;
- **already hashed** — the analyst has hex strings, not files to digest;
- **loaded at runtime**, from a text or CSV file the analyst points at.

This capability previously lived in `issen-signatures` as `HashIocStore`; it was
ported here so hash lookup has one home (commits `85c069b`, `a359f65`; ADR 0001).

A design question falls out: should the feed hold hashes, or should it also
*compute* them from file bytes?

## Decision

1. **`HashFeed` stores lowercase hex *strings*, partitioned into six sets
   (bad/good × MD5/SHA-1/SHA-256).** It never computes a digest — digesting file
   bytes is the caller's job (and the fleet's hashing crate, `blazehash`, owns
   that primitive). This keeps `forensic-hashdb` a pure lookup crate. Concretely
   the only runtime dependency is `memmap2`; there is no `blazehash` dependency
   and no `sha2`/`md-5` in the tree (`Cargo.toml`).
2. **Algorithm is auto-detected from hex length** — 32 → MD5, 40 → SHA-1, 64 →
   SHA-256 (`HashAlgorithm::from_hex_len`); the analyst does not have to declare
   which digest a list uses.
3. **Lookups normalize case and surrounding whitespace**, and a hit returns a
   `HashMatch` carrying the algorithm and the feed's provenance label
   (`src/feed.rs`).
4. **Malformed input is handled per its severity.** A hash of wrong length or
   with non-hex characters is rejected loudly by the single-insert API
   (`FeedError`, showing the offending value), but the *file loader* skips a
   malformed line and continues — a bad row in an analyst CSV must not abort the
   whole load, and the count of ingested hashes is returned.

## Consequences

- `forensic-hashdb` does one job (lookup) and pulls no crypto dependency; the
  hashing/lookup boundary is clean and matches the fleet's prefer-our-own-crates
  split (hashing → `blazehash`, lookup → here).
- Multi-algorithm support is transparent to the caller; a feed can mix MD5 and
  SHA-256 lines freely.
- Because the feed holds hex strings (not `[u8; 32]`), it is a separate surface
  from the SHA-256-keyed curated databases — deliberately, since analyst feeds
  are not restricted to SHA-256.
