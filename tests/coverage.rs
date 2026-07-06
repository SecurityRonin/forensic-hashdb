//! Completion tests covering the per-algorithm arms and error paths the unit
//! tests (SHA-256-leaning) don't reach — so the standalone crate meets the fleet
//! 100% line-coverage gate.

use forensic_hashdb::feed::{HashAlgorithm, HashFeed};
use forensic_hashdb::known_good::{KnownGoodDb, KnownGoodError};

#[test]
fn hash_algorithm_all_variants() {
    for (algo, len, name) in [
        (HashAlgorithm::Md5, 32, "MD5"),
        (HashAlgorithm::Sha1, 40, "SHA1"),
        (HashAlgorithm::Sha256, 64, "SHA256"),
    ] {
        assert_eq!(algo.hex_len(), len);
        assert_eq!(algo.name(), name);
        assert_eq!(HashAlgorithm::from_hex_len(len), Some(algo));
    }
    assert_eq!(HashAlgorithm::from_hex_len(7), None);
}

#[test]
fn feed_covers_every_algorithm_arm() {
    let mut feed = HashFeed::new("f");
    let md5 = "a".repeat(32);
    let sha1 = "b".repeat(40);
    let sha256 = "c".repeat(64);
    // good + bad inserts across all three algorithms hit each match arm
    for h in [&md5, &sha1, &sha256] {
        feed.insert_good(h).unwrap();
        feed.insert_bad(h).unwrap();
    }
    for h in [&md5, &sha1, &sha256] {
        assert!(feed.is_known_good(h));
        assert!(feed.lookup_bad(h).is_some());
    }
    assert_eq!(feed.good_count(), 3);
    assert_eq!(feed.bad_count(), 3);
    // wrong-length input short-circuits (from_hex_len None) in both lookups
    assert!(feed.lookup_bad("tooshort").is_none());
    assert!(!feed.is_known_good("tooshort"));
}

#[test]
fn feed_error_messages_and_io() {
    let mut feed = HashFeed::new("f");
    // wrong length
    let e = feed.insert_bad("xy").unwrap_err();
    assert!(format!("{e}").contains("expected"));
    // right length, non-hex
    let e = feed.insert_good(&"z".repeat(64)).unwrap_err();
    assert!(format!("{e}").contains("hex"));
    // a missing file surfaces as a FeedError via From<io::Error>
    let e = feed
        .load_bad_from_file(std::path::Path::new("/no/such/feed/file"))
        .unwrap_err();
    assert!(format!("{e}").contains("readable file"));
}

#[test]
fn known_good_error_paths() {
    // InvalidFileSize Display
    let e = KnownGoodError::InvalidFileSize { bytes: 31 };
    assert!(format!("{e}").contains("31"));
    // Io Display via a missing path (open fails -> From<io::Error> -> Io)
    let r = KnownGoodDb::open(std::path::Path::new("/no/such/hashdb"));
    assert!(r.is_err());
    if let Err(e) = r {
        assert!(matches!(e, KnownGoodError::Io(_)));
        assert!(format!("{e}").contains("I/O"));
    }
}

#[test]
fn known_good_is_empty() {
    let f = tempfile::NamedTempFile::new().unwrap(); // zero-length file
    let db = KnownGoodDb::open(f.path()).unwrap();
    assert!(db.is_empty());
    assert_eq!(db.len(), 0);
}
