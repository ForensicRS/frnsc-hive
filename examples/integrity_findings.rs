//! Surfaces an analyst-relevant integrity signal — a base-block checksum mismatch — as a
//! `forensic_rs::pipeline::finding::Finding`, not just an engineer-facing `warn!` log line.
//!
//! A well-formed hive load produces no findings at all, which wouldn't make for a very
//! interesting example, so this deliberately corrupts a copy of the real SAM fixture's bytes
//! (flipping one byte inside its checksummed region) before loading it, to make the mechanism
//! visible. `HiveRegistryReader::from_fs`/`load_user_hives` hit this same code path internally —
//! this example calls the lower-level `open_hive_with_logs` directly (against an in-memory
//! filesystem holding the corrupted bytes) so it can drive a single, deliberately-corrupted file
//! without needing a full on-disk hive layout.
//!
//! Demonstrates:
//! - `forensic_rs::prelude::testing::InMemoryVirtualFileSystem`, a first-class test double this
//!   crate's own tests use — not just for tests, it's equally useful for a quick repro like this.
//! - `frnsc_hive::reader::open_hive_with_logs`, which records a `Finding` for integrity problems
//!   encountered while loading, in addition to logging them.
//!
//! Run with: `cargo run --example integrity_findings`

use std::sync::Arc;

use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use frnsc_hive::reader::{HiveRegistryReader, open_hive_with_logs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read the real, well-formed SAM fixture's bytes off disk.
    let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C/", Arc::new(StdVirtualFS::new())));
    let mut original = fs.open(FPath::new("C:\\Windows\\System32\\Config\\SAM"))?;
    let mut raw = Vec::new();
    original.read_to_end(&mut raw)?;

    // 2. Flip one byte inside the checksummed region (the base block's first 508 bytes) without
    //    updating the stored checksum at bytes 508..512 — this lands inside the
    //    `last_written_timestamp` field, so the hive still parses as structurally valid and
    //    stays "clean" (`prim_sequence == sec_sequence`), isolating the checksum finding from any
    //    dirty-hive finding.
    raw[16] ^= 0xFF;

    // 3. Wrap the corrupted bytes in an in-memory filesystem and load it through the same
    //    `open_hive_with_logs` helper `HiveRegistryReader::from_fs` uses internally.
    let mem_fs: Arc<dyn FileSystem> = Arc::new(InMemoryVirtualFileSystem::new().with_file("SAM", raw));
    let mut findings = Vec::new();
    let hive = open_hive_with_logs(&mem_fs, FPath::new(""), "SAM", &mut findings).expect("bytes still parse as a hive");

    println!("Loaded the (corrupted) hive; {} finding(s) recorded:", findings.len());
    for finding in &findings {
        println!("  [{:?}] {:?}: {}", finding.severity, finding.category, finding.title);
        println!("    {}", finding.description);
    }

    // 4. The hive still opens and is still readable — a checksum mismatch is reported, not
    //    treated as fatal (recovery/parsing never blocks on it).
    let mut reader = HiveRegistryReader::new();
    reader.set_sam(hive);
    let root = reader.key(r"HKLM\SAM\Domains")?;
    println!(
        "Hive still readable despite the corruption: {} subkey(s) under HKLM\\SAM\\Domains",
        root.keys()?.len()
    );

    Ok(())
}
