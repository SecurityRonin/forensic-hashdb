# forensic-hashdb

The fleet's one hash-lookup capability. A file's hash means the same thing wherever
the bytes came from — a memory page or an NTFS `$DATA` run — so bucketing it as
known-good, known-bad, or a known-vulnerable driver lives in one crate, keyed on a
`&[u8; 32]` SHA-256 (or hex string for feeds).

## Four databases

- **`known_good`** — NSRL / CIRCL known-legitimate files. mmap-backed, sorted
  32-byte records, binary search; zero false positives, so it is safe to *exclude*
  a match from the timeline.
- **`known_bad`** — provenance-tracked malware hashes (MalwareBazaar, VirusShare,
  Malshare, AlienVault OTX, custom). Returns full `BadFileInfo` on a hit.
- **`lol_drivers`** — known-vulnerable Windows drivers (loldrivers.io), embedded at
  compile time and CVE-tagged, for BYOVD detection with no file to ship.
- **`feed`** — analyst-supplied IOC hash lists (MD5/SHA1/SHA256, auto-detected by
  length), loaded from text/CSV at runtime.

## Design

- **Zero-FP exclusion.** `known_good` is an exact binary search — no Bloom/XOR
  probabilistic layer in the exclusion path — so a match is a safe decision.
- **Scales.** mmap + binary search handles the full NSRL set without loading it
  into the heap.
- **Panic-free.** `unsafe_code = deny` with one justified bounded `mmap` site; no
  `unwrap`/`expect` in production; bounded reads; fuzzed; 100% line coverage.
- **One capability, two paths.** Consumed by the memory-triage path and the
  disk/scan path alike (ADR-0011) — the same lookup, not two implementations.

See [Validation](validation.md) for the evidence behind these claims.
