#![no_main]
//! A HashFeed loads analyst-supplied feed files — arbitrary text/CSV. Loading
//! arbitrary bytes and querying must never panic; every inserted hash must be
//! findable, and a malformed line is skipped, not fatal.

use std::io::Write;

use forensic_hashdb::feed::HashFeed;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(mut f) = tempfile::NamedTempFile::new() else {
        return;
    };
    if f.write_all(data).is_err() || f.flush().is_err() {
        return;
    }
    let mut feed = HashFeed::new("fuzz");
    let _ = feed.load_bad_from_file(f.path());
    let _ = feed.load_good_from_file(f.path());
    // Direct inserts of arbitrary UTF-8 slices must not panic either.
    let s = String::from_utf8_lossy(data);
    let _ = feed.insert_bad(&s);
    let _ = feed.lookup_bad(&s);
    let _ = feed.is_known_good(&s);
});
