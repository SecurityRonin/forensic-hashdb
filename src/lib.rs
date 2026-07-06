//! forensic-hashdb — zero-FP file hash databases for digital forensic investigation.
//!
//! Three databases:
//! - [`known_good`] — exact matching against NSRL/CIRCL known-legitimate files (zero false positives)
//! - [`known_bad`]  — provenance-tracked malware hash lookup (MalwareBazaar, VirusShare, etc.)
//! - [`lol_drivers`] — embedded known-vulnerable Windows driver hashes (loldrivers.io)
//! - [`feed`] — analyst-supplied multi-algorithm (MD5/SHA1/SHA256) hash feeds loaded from text/CSV

pub mod feed;
pub mod known_bad;
pub mod known_good;
pub mod lol_drivers;
mod types;

pub use types::{BadFileInfo, BadFileSource, DriverInfo};
