# forensic-hashdb

[![Crates.io](https://img.shields.io/crates/v/forensic-hashdb.svg)](https://crates.io/crates/forensic-hashdb)
[![docs.rs](https://img.shields.io/docsrs/forensic-hashdb)](https://docs.rs/forensic-hashdb)
[![Rust 1.75+](https://img.shields.io/badge/rust-1.75%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/forensic-hashdb/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/forensic-hashdb/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](https://github.com/SecurityRonin/forensic-hashdb/actions/workflows/ci.yml)
[![Security audit](https://img.shields.io/badge/security-audit-brightgreen.svg)](https://github.com/SecurityRonin/forensic-hashdb/actions/workflows/ci.yml)

**Bucket any file by its hash in one lookup — known-good and safe to ignore, known-bad, or a known-vulnerable driver — whether the bytes came from a memory dump or a disk image.**

A hash match is source-agnostic. `forensic-hashdb` is the one place the fleet answers "have I seen this hash before?" — four databases behind a `&[u8; 32]` (or hex) key, tuned for triage: exclude the noise, flag the threats.

## Four databases

```rust
use forensic_hashdb::known_good::KnownGoodDb;
use forensic_hashdb::lol_drivers;

// Exclude the noise: NSRL/CIRCL known-legitimate files (zero false positives).
let nsrl = KnownGoodDb::open("nsrl.bin".as_ref())?;
if nsrl.is_known_good(&sha256) {
    return; // an OS/app file — skip it, don't clutter the timeline
}

// Flag a BYOVD driver by hash (embedded, no file to ship).
if lol_drivers::is_vulnerable_driver(&sha256) {
    // known-vulnerable Windows driver (loldrivers.io)
}
# Ok::<(), forensic_hashdb::known_good::KnownGoodError>(())
```

| Database | Answers | Backing |
|---|---|---|
| `known_good` | "legitimate OS/app file I can exclude?" — NSRL / CIRCL | mmap, sorted 32-byte records, binary search (scales to full NSRL) |
| `known_bad` | "known malware?" — provenance-tracked (MalwareBazaar, VirusShare, …) | `HashMap`, full `BadFileInfo` on hit |
| `lol_drivers` | "known-vulnerable driver (BYOVD)?" — loldrivers.io | embedded at compile time, CVE-tagged |
| `feed` | "in *my* IOC list?" — analyst-supplied MD5/SHA1/SHA256, loaded from text/CSV | in-memory, per-algorithm |

## Analyst feeds

Load an arbitrary hash list at runtime — one hash per line, `#` comments, first CSV field, algorithm auto-detected by length:

```rust
use forensic_hashdb::feed::HashFeed;

let mut feed = HashFeed::new("threatfox");
feed.load_bad_from_file("iocs.csv".as_ref())?;
if let Some(m) = feed.lookup_bad(&hex_hash) {
    // m.algorithm, m.source — provenance for the report
}
# Ok::<(), forensic_hashdb::feed::FeedError>(())
```

## Trust but verify

- **Zero false positives** on `known_good` — exact binary search, no probabilistic structure, safe for forensic exclusion.
- **Panic-free.** `unsafe_code = deny` (one bounded `mmap` site, justified); no `unwrap`/`expect` in production; bounded reads.
- **Fuzzed** — the binary DB reader and the feed loader take arbitrary bytes with no panic.
- **100% line coverage.**

Used across the fleet by both the memory-triage path and the disk/scan path — one hash-lookup capability, not two.

---

[Privacy Policy](https://securityronin.github.io/forensic-hashdb/privacy/) · [Terms of Service](https://securityronin.github.io/forensic-hashdb/terms/) · © 2026 Security Ronin Ltd
