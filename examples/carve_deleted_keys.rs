//! Carves deleted registry keys out of a hive's unallocated cells — the `RecoverDeleted` API this
//! crate exposes via `Registry::as_recovery`, backed by `src/recovery.rs`'s strict, false-positive
//! guarded carving scan (see that module's doc comment for exactly what's validated).
//!
//! In two parts:
//! 1. A guaranteed-output demo against a tiny, hand-built synthetic hive whose bytes deliberately
//!    contain one "deleted" key — real fixture hives generally have nothing carveable (nothing's
//!    been deleted from them since they were captured), so this part exists to reliably show the
//!    mechanism working, and doubles as a readable illustration of the REGF cell layout.
//! 2. The same `deleted_keys`/`deleted_values` calls run against the real SAM/SECURITY fixtures,
//!    to show it also runs cleanly against genuine hive files (most likely finding nothing, which
//!    is the expected, honest result — not every hive has recoverable deleted data).
//!
//! Run with: `cargo run --example carve_deleted_keys`

use std::sync::Arc;

use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;
use forensic_rs::prelude::*;
use frnsc_hive::cell::KEY_COMP_NAME_FLAG;
use frnsc_hive::consts::ROOT_CELL_OFFSET;
use frnsc_hive::reader::{HiveFiles, HiveRegistryReader};

/// Builds a full REGF cell buffer (4-byte length prefix, negative/allocated, padded to a multiple
/// of 8 bytes) wrapping `content` — the shape every hive cell has on disk.
fn wrap_cell_padded(content: &[u8]) -> Vec<u8> {
    let unpadded = 4 + content.len();
    let padded = unpadded.div_ceil(8) * 8;
    let mut buf = Vec::with_capacity(padded);
    buf.extend_from_slice(&(-(padded as i32)).to_le_bytes());
    buf.extend_from_slice(content);
    buf.resize(padded, 0);
    buf
}

/// Builds a minimal `nk` (key node) cell's content: signature, flags, a plausible FILETIME, a
/// parent offset, every list/count field zeroed or `0xFFFFFFFF` (absent), and an ASCII name.
fn key_node_content(name: &str, last_written_timestamp: u64, parent: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"nk");
    buf.extend_from_slice(&KEY_COMP_NAME_FLAG.to_le_bytes()); // ASCII name, not UTF-16LE
    buf.extend_from_slice(&last_written_timestamp.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // access_bits
    buf.extend_from_slice(&parent.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // number_subkeys
    buf.extend_from_slice(&0u32.to_le_bytes()); // number_volatile_subkeys
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // subkeys_list_offset
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // volatile_subkeys_list_offset
    buf.extend_from_slice(&0u32.to_le_bytes()); // number_key_values
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // key_values_list_offset
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // key_security_offset
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // class_name_offset
    buf.extend_from_slice(&0u32.to_le_bytes()); // largest_subkey_class_name_length
    buf.extend_from_slice(&0u16.to_le_bytes()); // largest_subkey_name_length
    buf.push(0); // virt_and_user_flags
    buf.push(0); // debug
    buf.extend_from_slice(&0u32.to_le_bytes()); // largest_value_name_length
    buf.extend_from_slice(&0u32.to_le_bytes()); // largest_value_data_size
    buf.extend_from_slice(&0u32.to_le_bytes()); // work_var
    let name_bytes = name.as_bytes();
    buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // key_name_length
    buf.extend_from_slice(&0u16.to_le_bytes()); // class_name_length
    buf.extend_from_slice(name_bytes);
    buf
}

/// Builds a minimal, synthetic, single-hbin hive: an allocated root `nk` cell (every hive needs a
/// real root the reader can open) followed by trailing *unallocated* space that still physically
/// holds one deleted `nk` cell's bytes — exactly what a deletion (which only updates the
/// containing free-list entry, not the freed cell's own leftover bytes) leaves behind on disk.
fn build_synthetic_hive_with_a_deleted_key() -> Vec<u8> {
    const BIN_SIZE: usize = 4096;
    let root_cell = wrap_cell_padded(&key_node_content("ROOT", 0, 0xFFFF_FFFF));
    let deleted_cell = wrap_cell_padded(&key_node_content(
        "RecoveredKeyName",
        130_000_000_000_000_000, // a plausible FILETIME (roughly year 2012), well within range
        0xFFFF_FFFF,             // parent offset points nowhere live, so parent_hint won't resolve
    ));

    let mut hbin = Vec::with_capacity(BIN_SIZE);
    hbin.extend_from_slice(b"hbin");
    hbin.extend_from_slice(&0u32.to_le_bytes()); // offset
    hbin.extend_from_slice(&(BIN_SIZE as u32).to_le_bytes()); // size
    hbin.extend_from_slice(&[0u8; 16]); // reserved + timestamp
    hbin.extend_from_slice(&0u32.to_le_bytes()); // spare
    hbin.extend_from_slice(&root_cell);

    // The rest of the bin is one unallocated span. Cells are always 8-byte aligned in absolute
    // terms, so 4 bytes of slack after the span's own length prefix lands `deleted_cell` on a
    // valid boundary — exactly where a real deleted cell's bytes would still sit.
    let free_span_start = hbin.len();
    let free_len = BIN_SIZE - free_span_start;
    hbin.extend_from_slice(&(free_len as i32).to_le_bytes()); // positive length => unallocated
    hbin.resize(free_span_start + 8, 0);
    hbin.extend_from_slice(&deleted_cell);
    hbin.resize(BIN_SIZE, 0);

    let mut raw = vec![0u8; 4096]; // base block
    raw[0..4].copy_from_slice(b"regf");
    raw[36..40].copy_from_slice(&(ROOT_CELL_OFFSET as u32).to_le_bytes()); // root_cell_offset
    raw[40..44].copy_from_slice(&(BIN_SIZE as u32).to_le_bytes()); // hive_bins_data_size
    raw.extend_from_slice(&hbin);
    raw
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // --- Part 1: a synthetic hive with a known deleted key --------------------------------------

    let mem_fs = InMemoryVirtualFileSystem::new().with_file("synthetic", build_synthetic_hive_with_a_deleted_key());
    let file = mem_fs.open(FPath::new("synthetic"))?;
    let mut reader = HiveRegistryReader::new();
    reader.set_sam(HiveFiles::new(FPathBuf::new(), file)?);

    let registry: Box<dyn Registry> = Box::new(reader);
    let recovery = registry
        .as_recovery()
        .expect("HiveRegistryReader implements RecoverDeleted");

    println!("--- Synthetic hive (guaranteed to have one recoverable deleted key) ---");
    for key in recovery.deleted_keys()? {
        // `Recovered` has no `Deref` on purpose — `.value()`/`.recovery()`/`.locus()` keep the
        // recovery mode visible at every use site instead of it silently dropping out.
        println!(
            "Recovered deleted key: name={:?} last_write={:?} parent_hint={:?} recovery={:?} locus={:?}",
            key.value().name,
            key.value().last_write,
            key.value().parent_hint,
            key.recovery(),
            key.locus(),
        );
    }

    // --- Part 2: the real fixture hives ----------------------------------------------------------

    let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C/", Arc::new(StdVirtualFS::new())));
    let mut real_reader = HiveRegistryReader::new();
    real_reader.set_sam(HiveFiles::new(
        FPathBuf::new(),
        fs.open(FPath::new("C:\\Windows\\System32\\Config\\SAM"))?,
    )?);
    real_reader.set_security(HiveFiles::new(
        FPathBuf::new(),
        fs.open(FPath::new("C:\\Windows\\System32\\Config\\SECURITY"))?,
    )?);

    let real_registry: Box<dyn Registry> = Box::new(real_reader);
    let real_recovery = real_registry.as_recovery().unwrap();
    let deleted_keys = real_recovery.deleted_keys()?;
    let deleted_values = real_recovery.deleted_values()?;

    println!("\n--- Real SAM/SECURITY fixtures ---");
    println!(
        "{} deleted key(s), {} deleted value(s) recovered — 0 is the expected, honest result for \
         a small fixture nothing has been deleted from; the synthetic demo above is what proves \
         the carving mechanism itself works.",
        deleted_keys.len(),
        deleted_values.len()
    );
    for key in &deleted_keys {
        println!("  key: {key:?}");
    }
    for value in &deleted_values {
        println!("  value: {value:?}");
    }

    Ok(())
}
