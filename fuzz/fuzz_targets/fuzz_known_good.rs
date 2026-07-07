#![no_main]
//! KnownGoodDb mmaps an analyst-supplied binary DB (sorted 32-byte SHA-256
//! records) and binary-searches it. Opening arbitrary bytes and querying must
//! never panic or read out of bounds, whatever the file size or contents.

use std::io::Write;

use forensic_hashdb::known_good::KnownGoodDb;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut f) = tempfile::NamedTempFile::new() else {
        return;
    };
    if f.write_all(data).is_err() || f.flush().is_err() {
        return;
    }
    // open() rejects non-multiple-of-32 sizes; on success, query with a hash
    // derived from the input to exercise the binary search over arbitrary bytes.
    if let Ok(db) = KnownGoodDb::open(f.path()) {
        let mut probe = [0u8; 32];
        for (i, b) in data.iter().take(32).enumerate() {
            probe[i] = *b;
        }
        let _ = db.is_known_good(&probe);
        let _ = db.len();
        let _ = db.is_empty();
    }
});
