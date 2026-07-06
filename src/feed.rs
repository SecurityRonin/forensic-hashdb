//! Analyst-supplied hash feeds — the ad-hoc counterpart to the curated DBs.
//!
//! Where [`crate::known_good`] and [`crate::known_bad`] are curated SHA-256
//! reference databases, a [`HashFeed`] holds *analyst-supplied* known-good and
//! known-bad hashes loaded at runtime from a text or CSV file (one hash per line).
//! It is multi-algorithm — MD5, SHA-1, or SHA-256, auto-detected by hex length —
//! and pure `std` (it stores hex strings; it does not compute digests).
//!
//! This is the store that used to live as `issen-signatures`'
//! `HashIocStore`; it moved here so hash lookup has one home (ADR-0011).

use std::collections::HashSet;
use std::io::BufRead;
use std::path::Path;

/// The hash algorithm, distinguished by hex-string length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
    Sha256,
}

impl HashAlgorithm {
    /// Expected hex-string length for this algorithm.
    #[must_use]
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Md5 => 32,
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    /// Detect the algorithm from a hex-string length (`None` if it matches none).
    #[must_use]
    pub fn from_hex_len(len: usize) -> Option<Self> {
        match len {
            32 => Some(Self::Md5),
            40 => Some(Self::Sha1),
            64 => Some(Self::Sha256),
            _ => None,
        }
    }

    /// Display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }
}

/// A rejected hash (wrong length or non-hex characters).
#[derive(Debug)]
pub struct FeedError {
    pub hash: String,
    pub expected: String,
}

impl std::fmt::Display for FeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid hash {:?} (expected {})",
            self.hash, self.expected
        )
    }
}

impl std::error::Error for FeedError {}

impl From<std::io::Error> for FeedError {
    fn from(e: std::io::Error) -> Self {
        Self {
            hash: String::new(),
            expected: format!("readable file: {e}"),
        }
    }
}

/// A known-bad match, with the source feed's label for provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMatch {
    pub hash: String,
    pub algorithm: HashAlgorithm,
    pub source: String,
}

/// An analyst-supplied multi-algorithm known-good / known-bad hash set.
///
/// Hashes are stored as lowercase hex strings, partitioned by algorithm
/// (auto-detected by length). Lookups normalize case and surrounding whitespace.
#[derive(Debug)]
pub struct HashFeed {
    bad_md5: HashSet<String>,
    bad_sha1: HashSet<String>,
    bad_sha256: HashSet<String>,
    good_md5: HashSet<String>,
    good_sha1: HashSet<String>,
    good_sha256: HashSet<String>,
    source_label: String,
}

impl HashFeed {
    /// An empty feed carrying a provenance label.
    #[must_use]
    pub fn new(source_label: impl Into<String>) -> Self {
        Self {
            bad_md5: HashSet::new(),
            bad_sha1: HashSet::new(),
            bad_sha256: HashSet::new(),
            good_md5: HashSet::new(),
            good_sha1: HashSet::new(),
            good_sha256: HashSet::new(),
            source_label: source_label.into(),
        }
    }

    /// The provenance label.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.source_label
    }

    /// Normalize + validate a hash, returning `(normalized, algorithm)`.
    fn normalize(hash: &str) -> Result<(String, HashAlgorithm), FeedError> {
        let normalized = hash.trim().to_lowercase();
        let algo = HashAlgorithm::from_hex_len(normalized.len()).ok_or_else(|| FeedError {
            hash: hash.to_string(),
            expected: "MD5(32), SHA1(40), or SHA256(64) hex chars".to_string(),
        })?;
        if !normalized.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(FeedError {
                hash: hash.to_string(),
                expected: format!("{} hex", algo.name()),
            });
        }
        Ok((normalized, algo))
    }

    /// Insert a known-bad hash (algorithm auto-detected).
    pub fn insert_bad(&mut self, hash: &str) -> Result<(), FeedError> {
        let (normalized, algo) = Self::normalize(hash)?;
        match algo {
            HashAlgorithm::Md5 => self.bad_md5.insert(normalized),
            HashAlgorithm::Sha1 => self.bad_sha1.insert(normalized),
            HashAlgorithm::Sha256 => self.bad_sha256.insert(normalized),
        };
        Ok(())
    }

    /// Insert a known-good hash (algorithm auto-detected).
    pub fn insert_good(&mut self, hash: &str) -> Result<(), FeedError> {
        let (normalized, algo) = Self::normalize(hash)?;
        match algo {
            HashAlgorithm::Md5 => self.good_md5.insert(normalized),
            HashAlgorithm::Sha1 => self.good_sha1.insert(normalized),
            HashAlgorithm::Sha256 => self.good_sha256.insert(normalized),
        };
        Ok(())
    }

    /// Look up a known-bad hash, returning a [`HashMatch`] on a hit.
    #[must_use]
    pub fn lookup_bad(&self, hash: &str) -> Option<HashMatch> {
        let normalized = hash.trim().to_lowercase();
        let algo = HashAlgorithm::from_hex_len(normalized.len())?;
        let found = match algo {
            HashAlgorithm::Md5 => self.bad_md5.contains(&normalized),
            HashAlgorithm::Sha1 => self.bad_sha1.contains(&normalized),
            HashAlgorithm::Sha256 => self.bad_sha256.contains(&normalized),
        };
        found.then(|| HashMatch {
            hash: normalized,
            algorithm: algo,
            source: self.source_label.clone(),
        })
    }

    /// True if the hash is in the known-good set (e.g. an NSRL subset).
    #[must_use]
    pub fn is_known_good(&self, hash: &str) -> bool {
        let normalized = hash.trim().to_lowercase();
        let Some(algo) = HashAlgorithm::from_hex_len(normalized.len()) else {
            return false;
        };
        match algo {
            HashAlgorithm::Md5 => self.good_md5.contains(&normalized),
            HashAlgorithm::Sha1 => self.good_sha1.contains(&normalized),
            HashAlgorithm::Sha256 => self.good_sha256.contains(&normalized),
        }
    }

    /// Load known-bad hashes from a text/CSV file (one per line; `#` comments and
    /// blank lines skipped; the first comma/tab/space-delimited field is taken).
    /// Returns the number of valid hashes ingested; malformed lines are skipped.
    pub fn load_bad_from_file(&mut self, path: &Path) -> Result<usize, FeedError> {
        self.load_from_file(path, true)
    }

    /// Load known-good hashes from a text/CSV file (same format as
    /// [`HashFeed::load_bad_from_file`]).
    pub fn load_good_from_file(&mut self, path: &Path) -> Result<usize, FeedError> {
        self.load_from_file(path, false)
    }

    fn load_from_file(&mut self, path: &Path, bad: bool) -> Result<usize, FeedError> {
        let reader = std::io::BufReader::new(std::fs::File::open(path)?);
        let mut count = 0;
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let hash = trimmed.split([',', '\t', ' ']).next().unwrap_or(trimmed);
            let inserted = if bad {
                self.insert_bad(hash)
            } else {
                self.insert_good(hash)
            };
            if inserted.is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Total known-bad hashes across all algorithms.
    #[must_use]
    pub fn bad_count(&self) -> usize {
        self.bad_md5.len() + self.bad_sha1.len() + self.bad_sha256.len()
    }

    /// Total known-good hashes across all algorithms.
    #[must_use]
    pub fn good_count(&self) -> usize {
        self.good_md5.len() + self.good_sha1.len() + self.good_sha256.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{HashAlgorithm, HashFeed};
    use std::io::Write;

    #[test]
    fn algorithm_detects_by_hex_length() {
        assert_eq!(HashAlgorithm::from_hex_len(32), Some(HashAlgorithm::Md5));
        assert_eq!(HashAlgorithm::from_hex_len(40), Some(HashAlgorithm::Sha1));
        assert_eq!(HashAlgorithm::from_hex_len(64), Some(HashAlgorithm::Sha256));
        assert_eq!(HashAlgorithm::from_hex_len(10), None);
        assert_eq!(HashAlgorithm::Md5.hex_len(), 32);
        assert_eq!(HashAlgorithm::Sha256.name(), "SHA256");
    }

    #[test]
    fn insert_and_lookup_bad_across_algorithms() {
        let mut feed = HashFeed::new("test-feed");
        assert_eq!(feed.name(), "test-feed");
        let md5 = "a".repeat(32);
        let sha1 = "b".repeat(40);
        let sha256 = "c".repeat(64);
        feed.insert_bad(&md5).unwrap();
        feed.insert_bad(&sha1).unwrap();
        feed.insert_bad(&sha256).unwrap();
        assert_eq!(feed.bad_count(), 3);

        let m = feed.lookup_bad(&sha256).unwrap();
        assert_eq!(m.algorithm, HashAlgorithm::Sha256);
        assert_eq!(m.source, "test-feed");
        assert_eq!(m.hash, sha256);
        assert!(feed.lookup_bad(&"d".repeat(64)).is_none());
    }

    #[test]
    fn lookup_is_case_and_whitespace_insensitive() {
        let mut feed = HashFeed::new("f");
        let sha256 = "AB".repeat(32); // 64 hex chars, uppercase
        feed.insert_bad(&sha256).unwrap();
        assert!(feed
            .lookup_bad(&format!("  {}  ", sha256.to_lowercase()))
            .is_some());
    }

    #[test]
    fn known_good_filtering() {
        let mut feed = HashFeed::new("nsrl-subset");
        let good = "1".repeat(64);
        feed.insert_good(&good).unwrap();
        assert!(feed.is_known_good(&good));
        assert!(feed.is_known_good(&good.to_uppercase()));
        assert!(!feed.is_known_good(&"2".repeat(64)));
        assert!(!feed.is_known_good("not-a-hash"));
        assert_eq!(feed.good_count(), 1);
    }

    #[test]
    fn invalid_hash_is_rejected_loudly() {
        let mut feed = HashFeed::new("f");
        assert!(feed.insert_bad("xyz").is_err()); // wrong length
        assert!(feed.insert_bad(&"z".repeat(64)).is_err()); // right length, non-hex
        assert_eq!(feed.bad_count(), 0);
    }

    #[test]
    fn loads_bad_and_good_from_file_skipping_comments() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "# a comment").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "{}", "a".repeat(64)).unwrap();
        writeln!(f, "{},extra,columns", "b".repeat(32)).unwrap(); // CSV: first field only
        writeln!(f, "not-a-valid-hash").unwrap(); // skipped, not counted
        f.flush().unwrap();

        let mut feed = HashFeed::new("file-feed");
        let n = feed.load_bad_from_file(f.path()).unwrap();
        assert_eq!(n, 2, "two valid hashes; comment/blank/invalid skipped");
        assert!(feed.lookup_bad(&"a".repeat(64)).is_some());
        assert!(feed.lookup_bad(&"b".repeat(32)).is_some());

        // The good loader reads the same one-per-line format into the good set.
        let mut g = tempfile::NamedTempFile::new().unwrap();
        writeln!(g, "{}", "e".repeat(64)).unwrap();
        g.flush().unwrap();
        let mut good = HashFeed::new("good-file");
        assert_eq!(good.load_good_from_file(g.path()).unwrap(), 1);
        assert!(good.is_known_good(&"e".repeat(64)));
    }
}
