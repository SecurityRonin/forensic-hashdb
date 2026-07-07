# Validation

`forensic-hashdb` is a lookup crate: it answers membership queries against hash
sets. Correctness is established by the evidence below.

## Exact matching — no false positives

`known_good` and `known_bad` are exact-match structures (binary search over sorted
32-byte records; `HashMap`), so a hit is a *decision-grade* answer — there is no
probabilistic layer in the exclusion path that could mis-exclude a file. The
binary search is bounds-checked: an out-of-range slice degrades to a non-match, and
that guard is annotated `// cov:unreachable` because the search index provably
stays within the record count.

## Panic-free + fuzzed

The crate reads analyst-supplied files — a binary known-good DB (mmap) and text/CSV
feeds — so it meets the panic-free posture: `unsafe_code = deny` (one justified
bounded `mmap` site in `known_good`), no `unwrap`/`expect`/`panic!` in production,
and length-checked reads.

- **`fuzz_known_good`** opens arbitrary bytes as a DB and runs `is_known_good` over
  them — no panic, no out-of-bounds read, whatever the file size or contents.
- **`fuzz_feed`** loads arbitrary text/CSV into a `HashFeed` and queries it — a
  malformed line is skipped, never fatal.

Both run as a smoke pass on every push/PR and a deep run weekly.

## Coverage

100% production line coverage (`cargo llvm-cov`), enforced in CI by a `DA:n,0`
gate that fails on any uncovered production line, honoring the single
`// cov:unreachable` guard above.

## The data behind the databases

The hash *contents* (NSRL/CIRCL sets, malware feeds, the loldrivers list) are
sourced from their upstream publishers and are the analyst's to supply or refresh;
this crate provides the *lookup*, not the corpus. `known_good` reads a binary file
the operator builds from the NSRL RDS; `feed` reads whatever IOC list the analyst
points it at; `lol_drivers` embeds a snapshot of loldrivers.io.
