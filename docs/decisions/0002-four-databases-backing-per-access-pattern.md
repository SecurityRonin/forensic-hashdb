# 2. Four databases, each backed by the structure its access pattern needs

Date: 2026-07-24
Status: Accepted

## Context

"Have I seen this hash?" is really four questions with different data shapes,
different sizes, and different provenance needs:

- **Exclude the noise** — is this a legitimate OS/app file (NSRL/CIRCL)? The
  corpus is huge (full NSRL is tens of millions of records) and the answer is a
  bare yes/no, but it must be *decision-grade* (a false positive would wrongly
  exclude evidence).
- **Flag known malware** — with full provenance (which feed, malware family,
  tags) so the answer can go into a report.
- **Flag a known-vulnerable driver (BYOVD)** — a *small*, slow-changing list
  that wants CVE tagging and no external file to ship.
- **Match my own IOC list** — an analyst-supplied hash set, loaded at runtime,
  possibly in MD5/SHA-1/SHA-256.

Forcing one backing structure on all four would either bloat the small cases or
fail to scale the large one.

## Decision

Provide four modules, each with the backing its access pattern dictates
(`src/known_good.rs`, `src/known_bad.rs`, `src/lol_drivers.rs`, `src/feed.rs`):

| Module | Backing | Why |
|---|---|---|
| `known_good` | mmap over a sorted 32-byte-record file + binary search | scales to full NSRL without heap-loading; exact, zero-FP (ADR 0003) |
| `known_bad` | `HashMap<[u8;32], BadFileInfo>` | O(1) lookup that returns full provenance (`BadFileInfo`) on a hit |
| `lol_drivers` | `Vec<DriverInfo>` embedded at compile time via `OnceLock`, CVE-tagged | list is small and ships *with the binary* — no file to distribute |
| `feed` | in-memory `HashSet<String>` per algorithm | analyst-supplied, loaded at runtime, multi-algorithm (ADR 0004) |

## Consequences

- The four are independent modules behind one crate; a consumer pulls only the
  ones it needs (`known_good::KnownGoodDb`, `lol_drivers::is_vulnerable_driver`,
  `feed::HashFeed`, …).
- `lol_drivers` is embedded, so BYOVD detection works with zero deployment
  steps; the trade-off is that refreshing the list is a code change plus a
  release, acceptable for a slow-moving list.
- `known_bad` returns a borrowed `&BadFileInfo` so the provenance (source,
  family, tags) is available for the report, not just a boolean.
- Adding a fifth database is an additive module, not a rework of the others.
