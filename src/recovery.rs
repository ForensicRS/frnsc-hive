//! Carves deleted registry keys/values out of a hive's unallocated cells, backing
//! [forensic_rs::traits::registry::RecoverDeleted] for [crate::reader::HiveRegistryReader].
//!
//! ## How this differs from the normal read path
//!
//! [crate::hive::read_cells] (the hot path used by every other read in this crate) walks a hive
//! bin's cell list once, parses each *allocated* (negative-length-prefix) cell, and discards
//! unallocated (positive-length-prefix) spans down to a bare offset — see
//! [crate::cell::UnallocatedCell]. This module walks the same cell-list framing independently
//! (re-reading the hive-bins-data region rather than going through
//! [crate::reader::HiveFiles::get_cell_at_offset]'s cache), keeping the raw bytes of every
//! unallocated span instead of discarding them, and scans each one for leftover `nk`/`vk` cell
//! bytes from a deleted key/value that the OS hasn't yet overwritten with new data. A deleted
//! cell's own length prefix stays negative (as it was allocated when written) even though the
//! *containing* free-list entry wrapping it now carries a positive one — that's exactly what this
//! scan looks for.
//!
//! ## Forensic soundness: strict validation over recall
//!
//! Scanning raw bytes for a 2-byte signature is not, on its own, reliable evidence of a deleted
//! cell — ordinary binary data (string content, padding, a previous cell's tail) can incidentally
//! contain `nk`/`vk` by chance. A false positive here means a fabricated key/value in a case
//! report, which is worse than a missed one. Every candidate is therefore required to:
//! - parse structurally through the same [crate::cell::read_cell] the normal read path uses
//!   (bounds-checked field-by-field, so a match is at minimum internally self-consistent), AND
//! - fit entirely within the free span it was found in (never spilling into an adjacent,
//!   unrelated cell), AND
//! - pass [Self]-specific plausibility checks ([is_plausible_key_node]/[is_plausible_key_value]):
//!   a non-empty name and an in-range `FILETIME` for a key, sane flag bits for a value.
//!
//! A candidate that fails any of these is silently dropped, not reported with lower confidence —
//! there is no partial-credit "maybe" a case report can act on.
//!
//! ## Known limitations
//!
//! - [RecoveredKey::parent_hint] is populated only when the deleted key's recorded parent offset
//!   still resolves to a currently-*allocated* key node; otherwise it's `None` — guessing a parent
//!   from an unrelated nearby cell would itself be fabricated evidence.
//! - [RecoveredValue::key_hint] is always `None`. A deleted value's owning key is not recoverable
//!   from the value cell alone (it has no back-pointer); reconstructing it would require
//!   cross-referencing every recovered key's value-list offsets against every recovered value's
//!   offset, itself built from unallocated, possibly-overwritten bytes — attempting that
//!   correlation on already-uncertain carved data compounds the uncertainty rather than resolving
//!   it, so this crate deliberately does not attempt it.
//! - A deleted value's data is decoded confidently when resident (stored inline in the `vk` cell
//!   itself) or when its non-resident data cell still parses as a structurally valid `Invalid`
//!   cell; otherwise the value's *existence* and *name* are still reported, with
//!   [forensic_rs::prelude::RegValue::None] standing in for data that can no longer be safely
//!   attributed — never a guess at what the data might have been.

use forensic_rs::prelude::*;

use crate::cell::{HiveCell, KEY_NODE_SIGNATURE, KEY_VALUE_SIGNATURE, KeyNodeCell, KeyValueCell, read_cell};
use crate::reader::{HiveFiles, decode_value_cell};

/// `FILETIME` for 2000-01-01 00:00:00 UTC — `(unix_seconds + 11_644_473_600) * 10_000_000` with
/// `unix_seconds = 946_684_800`. A conservative lower plausibility bound: a genuine deleted key
/// from a Windows XP-or-earlier hive would be rejected by this, trading a handful of legitimate
/// very-old timestamps for meaningfully fewer false-positive carves out of random bytes.
const MIN_PLAUSIBLE_FILETIME: u64 = 125_911_584_000_000_000;
/// `FILETIME` for 2100-01-01 00:00:00 UTC, same derivation as [MIN_PLAUSIBLE_FILETIME] with
/// `unix_seconds = 4_102_444_800`. An upper bound far enough out to never reject a genuine
/// timestamp in practice.
const MAX_PLAUSIBLE_FILETIME: u64 = 157_469_184_000_000_000;
/// Sanity cap on `number_subkeys`/`number_key_values`/similar counts, far beyond anything a real
/// hive contains — catches a spurious match whose "count" fields decode as huge garbage.
const MAX_PLAUSIBLE_COUNT: u32 = 1_000_000;
/// Registry value flag bits actually defined ([crate::cell::VALUE_COMP_NAME_FLAG] |
/// [crate::cell::VALUE_IS_TOMBSTONE]); any other bit set is a plausibility red flag.
const KNOWN_VALUE_FLAGS: u16 = crate::cell::VALUE_COMP_NAME_FLAG | crate::cell::VALUE_IS_TOMBSTONE;

/// One unallocated (free) cell-list span, both fields relative to the start of the hive-bins-data
/// region — i.e. the same coordinate space [crate::reader::HiveFiles::get_cell_at_offset] uses.
struct FreeSpan {
    /// Offset of the span's own 4-byte length prefix.
    start: usize,
    /// The span's declared length in bytes, including that 4-byte prefix.
    len: usize,
}

/// Walks `bins` (a full hive-bins-data buffer) bin by bin, cell by cell, collecting every
/// unallocated span. Stops (without erroring — this is best-effort recovery, not the primary read
/// path) at the first structurally inconsistent bin or cell-list entry, returning whatever spans
/// were found before that point.
fn find_free_spans(bins: &[u8]) -> Vec<FreeSpan> {
    let mut spans = Vec::new();
    let mut bin_pos = 0usize;
    while bin_pos + 32 <= bins.len() {
        if bins[bin_pos..bin_pos + 4] != *b"hbin" {
            break;
        }
        let Ok(bin_size_bytes) = <[u8; 4]>::try_from(&bins[bin_pos + 8..bin_pos + 12]) else {
            break;
        };
        let bin_size = u32::from_le_bytes(bin_size_bytes) as usize;
        if bin_size < 32 || bin_pos + bin_size > bins.len() {
            break;
        }
        let content_end = bin_pos + bin_size;
        let mut cell_pos = bin_pos + 32;
        while cell_pos + 4 <= content_end {
            let Ok(len_bytes) = <[u8; 4]>::try_from(&bins[cell_pos..cell_pos + 4]) else {
                break;
            };
            let cell_len_i = i32::from_le_bytes(len_bytes);
            let cell_len = cell_len_i.unsigned_abs() as usize;
            if cell_len < 4 || cell_pos + cell_len > content_end {
                break;
            }
            if cell_len_i >= 0 {
                spans.push(FreeSpan {
                    start: cell_pos,
                    len: cell_len,
                });
            }
            cell_pos += cell_len;
        }
        bin_pos += bin_size;
    }
    spans
}

/// Scans one free span for embedded `nk`/`vk` cells at every 8-byte-aligned candidate offset
/// (cells are always 8-byte aligned in absolute hive-bins-data terms, and `span.start` is itself a
/// valid former cell boundary, so stepping by 8 from there stays aligned). Returns each
/// structurally valid candidate paired with its absolute hive-bins-data offset — plausibility
/// filtering happens in the caller, per cell kind.
fn carve_span(bins: &[u8], span: &FreeSpan) -> Vec<(u64, HiveCell)> {
    let mut found = Vec::new();
    let span_end = span.start + span.len;
    let mut pos = span.start;
    while pos + 6 <= span_end {
        let signature = [bins[pos + 4], bins[pos + 5]];
        if signature == *KEY_NODE_SIGNATURE || signature == *KEY_VALUE_SIGNATURE {
            // Bounded to `span_end`, never the whole buffer — a candidate must parse entirely
            // within the free span it was found in, not spill into an adjacent, unrelated cell.
            if let Ok(cell @ (HiveCell::KeyNode(_) | HiveCell::KeyValue(_))) =
                read_cell(&bins[pos..span_end], pos as u64)
            {
                found.push((pos as u64, cell));
            }
        }
        pos += 8;
    }
    found
}

/// A `last_written_timestamp` in [MIN_PLAUSIBLE_FILETIME]..=[MAX_PLAUSIBLE_FILETIME], a non-empty
/// name, and subkey/value counts under [MAX_PLAUSIBLE_COUNT] — see this module's doc comment for
/// why a bare structural parse isn't enough on its own.
fn is_plausible_key_node(kn: &KeyNodeCell) -> bool {
    !kn.key_name.is_empty()
        && (MIN_PLAUSIBLE_FILETIME..=MAX_PLAUSIBLE_FILETIME).contains(&kn.last_written_timestamp)
        && kn.number_subkeys <= MAX_PLAUSIBLE_COUNT
        && kn.number_key_values <= MAX_PLAUSIBLE_COUNT
}

/// Only the flag bits the format actually defines may be set — see this module's doc comment.
fn is_plausible_key_value(kv: &KeyValueCell) -> bool {
    kv.flags & !KNOWN_VALUE_FLAGS == 0
}

/// If `parent_offset` currently resolves to an *allocated* key node (i.e. one still reachable
/// through the normal read path, not itself carved), returns its name. Never guesses a parent
/// from unrelated nearby bytes — see this module's doc comment on [RecoveredKey::parent_hint].
fn resolve_parent_hint(hive: &mut HiveFiles, parent_offset: u32) -> Option<String> {
    match hive.get_cell_at_offset(parent_offset as u64) {
        Ok(HiveCell::KeyNode(kn)) => Some(kn.key_name.clone()),
        _ => None,
    }
}

/// Decodes a recovered value's data confidently when resident, or when its non-resident data
/// cell still resolves to a structurally valid `Invalid` cell; otherwise returns
/// [RegValue::None] rather than attributing data that can no longer be safely traced back to
/// this value. See this module's doc comment on data-recovery limitations.
fn decode_recovered_value(hive: &mut HiveFiles, kv: &KeyValueCell) -> RegValue {
    decode_value_cell(hive, kv.data_type, kv.data_offset, kv.data_size, kv.flags).unwrap_or(RegValue::None)
}

/// Carves every deleted key this hive's unallocated cells still hold plausible remains of. See
/// this module's doc comment for the validation this applies and its known limitations.
///
/// Each result is wrapped in [`Recovered`] carrying the cell's own absolute hive-bins-data
/// offset as `Locus::Hive { cell, value_index: 0 }` — `value_index` has no meaning for a key
/// carved directly by free-space scanning (it isn't reached via any key's value-list
/// enumeration), so `0` here is a placeholder, not a claim about a real zeroth value.
pub(crate) fn scan_deleted_keys(hive: &mut HiveFiles) -> ForensicResult<Vec<Recovered<RecoveredKey>>> {
    let bins = hive.hive_bins_data()?;
    let mut candidates = Vec::new();
    for span in find_free_spans(&bins) {
        for (offset, cell) in carve_span(&bins, &span) {
            if let HiveCell::KeyNode(kn) = cell {
                if is_plausible_key_node(&kn) {
                    candidates.push((offset, kn));
                }
            }
        }
    }
    drop(bins); // the parent-hint lookup below re-borrows `hive` mutably
    let mut recovered = Vec::with_capacity(candidates.len());
    for (offset, kn) in candidates {
        let parent_hint = resolve_parent_hint(hive, kn.parent);
        recovered.push(Recovered::new(
            RecoveredKey {
                name: kn.key_name,
                last_write: Some(ForensicTimestamp::from_win_filetime(kn.last_written_timestamp)),
                parent_hint,
            },
            Recovery::DeletedMetadata,
            Locus::Hive { cell: offset as u32, value_index: 0 },
        ));
    }
    Ok(recovered)
}

/// Carves every deleted value this hive's unallocated cells still hold plausible remains of. See
/// this module's doc comment for the validation this applies and its known limitations —
/// [RecoveredValue::key_hint] is always `None`.
///
/// Same [`Recovered`]/[`Locus::Hive`] treatment as [`scan_deleted_keys`], and for the same
/// reason: a value carved independently of any key's enumeration has no list position to report,
/// so `value_index: 0` is a placeholder — the cell offset alone is this value's real address.
pub(crate) fn scan_deleted_values(hive: &mut HiveFiles) -> ForensicResult<Vec<Recovered<RecoveredValue>>> {
    let bins = hive.hive_bins_data()?;
    let mut candidates = Vec::new();
    for span in find_free_spans(&bins) {
        for (offset, cell) in carve_span(&bins, &span) {
            if let HiveCell::KeyValue(kv) = cell {
                if is_plausible_key_value(&kv) {
                    candidates.push((offset, kv));
                }
            }
        }
    }
    drop(bins); // the data-decode lookup below re-borrows `hive` mutably
    let mut recovered = Vec::with_capacity(candidates.len());
    for (offset, kv) in candidates {
        let value = decode_recovered_value(hive, &kv);
        recovered.push(Recovered::new(
            RecoveredValue {
                key_hint: None,
                name: kv.value_name,
                value,
            },
            Recovery::DeletedMetadata,
            Locus::Hive { cell: offset as u32, value_index: 0 },
        ));
    }
    Ok(recovered)
}

#[cfg(test)]
mod tst {
    use super::*;

    /// Builds a full `nk` cell buffer (4-byte length prefix, negative/allocated + `content`,
    /// where `content` starts with the 2-byte "nk" signature), matching the layout
    /// [crate::cell::read_cell] parses — mirroring `cell.rs`'s own test helper for the same shape.
    fn build_key_node_bytes(name: &str, last_written_timestamp: u64, parent: u32) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let mut content = Vec::new();
        content.extend_from_slice(b"nk");
        // KEY_COMP_NAME_FLAG: key_name is ASCII (matching `name_bytes` below), not UTF-16LE.
        content.extend_from_slice(&crate::cell::KEY_COMP_NAME_FLAG.to_le_bytes());
        content.extend_from_slice(&last_written_timestamp.to_le_bytes());
        content.extend_from_slice(&0u32.to_le_bytes()); // access_bits
        content.extend_from_slice(&parent.to_le_bytes());
        content.extend_from_slice(&0u32.to_le_bytes()); // number_subkeys
        content.extend_from_slice(&0u32.to_le_bytes()); // number_volatile_subkeys
        content.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // subkeys_list_offset
        content.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // volatile_subkeys_list_offset
        content.extend_from_slice(&0u32.to_le_bytes()); // number_key_values
        content.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // key_values_list_offset
        content.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // key_security_offset
        content.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // class_name_offset
        content.extend_from_slice(&0u32.to_le_bytes()); // largest_subkey_class_name_length
        content.extend_from_slice(&0u16.to_le_bytes()); // largest_subkey_name_length
        content.push(0); // virt_and_user_flags
        content.push(0); // debug
        content.extend_from_slice(&0u32.to_le_bytes()); // largest_value_name_length
        content.extend_from_slice(&0u32.to_le_bytes()); // largest_value_data_size
        content.extend_from_slice(&0u32.to_le_bytes()); // work_var
        content.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // key_name_length
        content.extend_from_slice(&0u16.to_le_bytes()); // class_name_length
        content.extend_from_slice(name_bytes);

        let cell_len = 4 + content.len();
        let padded_len = cell_len.div_ceil(8) * 8;
        let mut buf = Vec::with_capacity(padded_len);
        buf.extend_from_slice(&(-(padded_len as i32)).to_le_bytes());
        buf.extend_from_slice(&content);
        buf.resize(padded_len, 0);
        buf
    }

    /// Wraps `cell_bytes` (an allocated-looking, negative-prefix cell) inside one hbin whose
    /// remaining space is one big unallocated (positive-prefix) span — i.e. a bin that looks like
    /// the deleted cell's old bytes are still physically present but no longer referenced by any
    /// live structure. Places `cell_bytes` at the next 8-byte-aligned offset after the free
    /// span's own 4-byte length prefix (absolute offset 40 — 32 for the hbin header + 4 for the
    /// prefix, rounded up to the next multiple of 8), matching the real format's cell-alignment
    /// invariant: a genuine deleted cell's own start was always 8-aligned, since it was a real
    /// cell boundary before it was freed.
    fn wrap_in_unallocated_bin(cell_bytes: &[u8]) -> Vec<u8> {
        const BIN_SIZE: usize = 4096;
        const CELL_START: usize = 40;
        let mut bin = Vec::with_capacity(BIN_SIZE);
        bin.extend_from_slice(b"hbin");
        bin.extend_from_slice(&0u32.to_le_bytes()); // offset
        bin.extend_from_slice(&(BIN_SIZE as u32).to_le_bytes()); // size
        bin.extend_from_slice(&[0u8; 16]); // reserved + timestamp
        bin.extend_from_slice(&0u32.to_le_bytes()); // spare
        assert_eq!(32, bin.len());

        let free_len = BIN_SIZE - 32; // the whole rest of the bin is one unallocated span
        bin.extend_from_slice(&(free_len as i32).to_le_bytes()); // positive => unallocated
        bin.resize(CELL_START, 0); // slack landing the embedded cell on an 8-aligned offset
        bin.extend_from_slice(cell_bytes);
        bin.resize(BIN_SIZE, 0);
        bin
    }

    #[test]
    fn recovers_a_plausible_deleted_key_from_an_unallocated_span() {
        let cell_bytes = build_key_node_bytes("DeletedSubkey", MIN_PLAUSIBLE_FILETIME + 1, 0xFFFF_FFFF);
        let bins = wrap_in_unallocated_bin(&cell_bytes);

        let spans = find_free_spans(&bins);
        assert_eq!(1, spans.len());
        let found = carve_span(&bins, &spans[0]);
        let names: Vec<&str> = found
            .iter()
            .filter_map(|(_, c)| match c {
                HiveCell::KeyNode(kn) => Some(kn.key_name.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            names.contains(&"DeletedSubkey"),
            "expected to carve DeletedSubkey, got {names:?}"
        );
    }

    #[test]
    fn rejects_a_structurally_valid_but_implausible_timestamp() {
        // A structurally valid nk cell whose timestamp is *not* a plausible FILETIME (e.g. 1,
        // which parses fine as a u64 but is nowhere near a real registry write time) must not be
        // reported — this is exactly the kind of "parses but isn't real" false positive the
        // plausibility check exists to catch.
        let kn = KeyNodeCell {
            flags: 0,
            last_written_timestamp: 1,
            access_bits: 0,
            parent: 0,
            number_subkeys: 0,
            number_volatile_subkeys: 0,
            subkeys_list_offset: 0xFFFF_FFFF,
            volatile_subkeys_list_offset: 0xFFFF_FFFF,
            number_key_values: 0,
            key_values_list_offset: 0xFFFF_FFFF,
            key_security_offset: 0xFFFF_FFFF,
            class_name_offset: 0xFFFF_FFFF,
            largest_subkey_class_name_length: 0,
            largest_subkey_name_length: 0,
            virt_and_user_flags: 0,
            debug: 0,
            largest_value_name_length: 0,
            largest_value_data_size: 0,
            work_var: 0,
            key_name_length: 4,
            class_name_length: 0,
            key_name: "Test".into(),
            offset: 0,
        };
        assert!(!is_plausible_key_node(&kn));
    }

    #[test]
    fn random_bytes_yield_no_false_positive_recovered_keys() {
        // A buffer of non-cell, pseudo-random-looking bytes must recover nothing — the
        // false-positive guard this module's doc comment promises. Deterministic (not actually
        // random) so this test is reproducible.
        let mut bins = Vec::with_capacity(4096);
        bins.extend_from_slice(b"hbin");
        bins.extend_from_slice(&0u32.to_le_bytes());
        bins.extend_from_slice(&4096u32.to_le_bytes());
        bins.extend_from_slice(&[0u8; 16]);
        bins.extend_from_slice(&0u32.to_le_bytes());
        bins.extend_from_slice(&(4096i32 - 32).to_le_bytes()); // one big unallocated span
        let mut state: u32 = 0x9E37_79B9;
        while bins.len() < 4096 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            bins.push((state >> 24) as u8);
        }

        let spans = find_free_spans(&bins);
        let mut all_candidates = Vec::new();
        for span in &spans {
            all_candidates.extend(carve_span(&bins, span));
        }
        let plausible: Vec<_> = all_candidates
            .into_iter()
            .filter(|(_, c)| match c {
                HiveCell::KeyNode(kn) => is_plausible_key_node(kn),
                HiveCell::KeyValue(kv) => is_plausible_key_value(kv),
                _ => false,
            })
            .collect();
        assert!(
            plausible.is_empty(),
            "expected no plausible candidates in random bytes, got {plausible:?}"
        );
    }
}
