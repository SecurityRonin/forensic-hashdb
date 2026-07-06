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
