# 3. Zero-false-positive known-good: sorted 32-byte records, mmap + binary search

Date: 2026-07-24
Status: Accepted

## Context

The `known_good` database drives an *exclusion* decision: a hit means "this is a
legitimate OS/app file, drop it from the timeline." That is the most dangerous
direction to be wrong in — a false positive silently discards evidence. A
probabilistic membership structure (Bloom/XOR filter) is attractive for size,
but any of them admits false positives by construction, which is unacceptable on
the exclusion path.

The corpus is also large (full NSRL RDS), so loading it into the heap is not an
option.

## Decision

1. **On-disk format: a flat file of sorted 32-byte SHA-256 records, nothing
   else.** The record width is fixed at 32 bytes (raw SHA-256, no length
   prefix, no endianness question — bytes are compared as-is). `open()` rejects
   any file whose length is not a multiple of 32 with
   `KnownGoodError::InvalidFileSize { bytes }` (`src/known_good.rs`), surfacing
   the offending size rather than reading a torn record.
2. **Access: `memmap2::Mmap` + binary search** over the sorted records
   (`is_known_good`). mmap keeps the working set out of the heap so the full
   NSRL set is usable; binary search over sorted fixed-width records is exact.
3. **No probabilistic layer on the exclusion path.** A `known_good` hit is a
   yes/no from an exact comparison — zero false positives, safe for forensic
   exclusion. Where a probabilistic pre-screen is ever wanted it belongs only on
   the *flag* path, never the exclude path: `known_bad::might_be_malicious` is
   documented as a future XOR-filter pre-screen (Phase 2) precisely because a
   false positive there merely triggers a second exact lookup, it does not
   discard evidence (`src/known_bad.rs`).

## Consequences

- The exclusion answer is decision-grade; `docs/validation.md` records this as
  the correctness argument for the crate.
- The operator must build the binary file (sorted 32-byte records) from the
  NSRL RDS themselves — the crate provides the *lookup*, not the corpus.
- Empty file is a valid empty DB (`mmap: None`, every lookup returns `false`),
  so a not-yet-populated deployment degrades cleanly rather than erroring.
- The binary-search slice read is bounds-checked and degrades to a non-match if
  its dominating invariant is ever violated; that guard is annotated
  `// cov:unreachable` (see ADR 0005).
