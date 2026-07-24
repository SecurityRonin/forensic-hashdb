# forensic-hashdb — Purpose & Scope

> Library tier. This is a **Purpose & Scope** document, not a product PRD:
> `forensic-hashdb` ships no binary an examiner runs — it is a crate that other
> fleet code *links*. (Per the fleet PRD & ADR standard, library crates get a
> lighter `docs/PRD.md`, not a full product-requirements doc.)

## What it is

`forensic-hashdb` is the fleet's single hash-lookup capability: the one place
that answers **"have I seen this file hash before, and what bucket is it in?"**
A hash match is source-agnostic — the same SHA-256 means the same thing whether
the bytes were carved from a memory dump or read from a disk image — so the
lookup lives in one crate keyed on a raw `&[u8; 32]` (or a hex string, for
analyst feeds), not on a path or an acquisition medium.

It provides four databases (see ADR 0002):

- **`known_good`** — NSRL / CIRCL known-legitimate files. mmap-backed, sorted
  32-byte records, exact binary search; zero false positives, so a hit is safe
  to *exclude* from the timeline (ADR 0003).
- **`known_bad`** — provenance-tracked malware hashes (MalwareBazaar,
  VirusShare, Malshare, AlienVault OTX, custom). Returns full `BadFileInfo`
  (source, family, tags) on a hit.
- **`lol_drivers`** — known-vulnerable Windows drivers (loldrivers.io), embedded
  at compile time and CVE-tagged, for BYOVD detection with no file to ship.
- **`feed`** — analyst-supplied IOC hash lists (MD5 / SHA-1 / SHA-256,
  auto-detected by hex length), loaded from text/CSV at runtime (ADR 0004).

## Who links it

- **`issen-mem`** — the memory-triage path: bucket hashes of pages/modules
  carved from a dump.
- **`issen-signatures`** — the disk/scan path: bucket hashes of files from an
  image or a live scan. (This crate absorbed that repo's `HashIocStore` as the
  `feed` module.)
- Any future fleet consumer needing "known-good exclusion" or "known-bad /
  BYOVD flagging" — one implementation, not a per-path copy (ADR 0001).

## Scope

- Membership lookup over hash sets: exact yes/no for the curated SHA-256
  databases; provenance-returning lookup for `known_bad`; multi-algorithm
  hex-string lookup for analyst feeds.
- Reading the on-disk known-good binary format (sorted 32-byte records) and the
  text/CSV feed format, robustly, against untrusted/analyst-supplied bytes.
- Embedding and serving the small BYOVD driver list.

## Non-goals

- **Computing digests.** This crate stores and looks up hashes; it never hashes
  file bytes. Digesting is the caller's job (fleet hashing primitive:
  `blazehash`). The only runtime dependency is `memmap2` (ADR 0004).
- **Shipping the corpus.** The NSRL/CIRCL sets and malware feeds are the
  analyst's to supply or refresh; the crate provides the lookup, not the data
  (`known_good` reads a file the operator builds from the NSRL RDS; `feed` reads
  whatever list the analyst points at). `lol_drivers` is the one embedded set,
  because it is small and slow-moving.
- **A runnable front-end.** No CLI, GUI, or MCP server — a consumer wires the
  lookup into its own tool.
- **Fuzzy / probabilistic matching on the exclusion path.** The exclude answer
  is exact by construction (ADR 0003).

## Correctness & robustness

- **Zero false positives** on the exclusion path — exact binary search, no
  probabilistic layer (ADR 0003).
- **Panic-free posture** — `unsafe_code = deny` with one bounded, justified
  `mmap` site; no `unwrap`/`expect` in production; bounds-checked reads; both
  untrusted-input surfaces fuzzed; 100% production line coverage (ADR 0005).
- Evidence is written up in [`validation.md`](validation.md).

## Key decisions

See [`docs/decisions/`](decisions/): standalone source-agnostic crate (0001),
four databases (0002), zero-FP known-good (0003), hex-storing multi-algorithm
feeds (0004), panic-free/fuzzed posture (0005), low MSRV floor (0006).
