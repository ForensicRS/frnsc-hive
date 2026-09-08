//! Parses the top-level framing of a REGF hive file: the base block (file header) and hive bin
//! headers, one level below [crate::reader] and one level above [crate::cell].
//!
//! [read_base_block] reads and validates the 4096-byte base block, dispatching between the two
//! on-disk layouts ([read_base_block_wxp], the pre-Windows-10 flavor, and [read_base_block_w10],
//! which adds the transaction-log GUIDs and a `"rmtm"` signature check via [is_win10_format]) and
//! normalizing both into the shared [BaseBlock]. [read_hive_bin_at_file_position]/[read_bin_header]
//! read one hive bin's 32-byte header plus its raw data; [read_cells] then splits that raw data
//! into individual [crate::cell::HiveCell]s by repeatedly delegating to [crate::cell::read_cell].

use forensic_rs::prelude::{
    ByteReader, Finding, FindingCategory, FindingSeverity, ForensicError, ForensicResult, FromBytes, VirtualFile,
};
use forensic_rs::warn;

use crate::cell::{HiveCell, read_cell};

pub struct HivePrimaryFile {
    pub base_block: BaseBlock,
}

#[derive(Debug)]
pub struct BaseBlock {
    /// Primary sequence number.
    /// This number is incremented by 1 in the beginning of a write operation on the primary file
    pub prim_sequence: u32,
    /// Secondary sequence number.
    /// This number is incremented by 1 at the end of a write operation on the primary file,
    /// a primary sequence number and a secondary sequence number should be equal after a successful write operation
    pub sec_sequence: u32,
    /// FILETIME (UTC)
    pub last_written_timestamp: u64,
    /// Major version of a hive writer
    pub major_version: u32,
    /// Minor version of a hive writer
    pub minor_version: u32,
    /// 0 means primary file
    pub file_type: u32,
    /// 1 means direct memory load
    pub file_format: u32,
    /// Offset of a root cell in bytes, relative from the start of the hive bins data
    pub root_cell_offset: u32,
    /// Size of the hive bins data in bytes
    pub hive_bins_data_size: u32,
    /// Logical sector size of the underlying disk in bytes divided by 512
    pub clustering_factor: u32,
    /// UTF-16LE string (contains a partial file path to the primary file, or a file name of the primary file), used for debugging purposes
    pub file_name: [u8; 64],
    /// XOR-32 checksum of the previous 508 bytes
    pub checksum: u32,
    /// This field has no meaning on a disk
    pub boot_type: u32,
    /// This field has no meaning on a disk
    pub boot_recovery: u32,
}

#[derive(Debug)]
pub struct HiveBinHeader {
    /// ASCII string hbin
    pub signature: u32,
    /// Offset of a current hive bin in bytes, relative from the start of the hive bins data
    pub offset: u32,
    /// Size of a current hive bin in bytes
    pub size: u32,
    pub reserved: u64,
    /// FILETIME (UTC), defined for the first hive bin only (see below)
    pub timestamp: u64,
    /// Spare (or MemAlloc). This field has no meaning on a disk (see below)
    pub spare: u32,
}

impl FromBytes for HiveBinHeader {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        Ok(HiveBinHeader {
            signature: reader.read_u32_le()?,
            offset: reader.read_u32_le()?,
            size: reader.read_u32_le()?,
            reserved: reader.read_u64_le()?,
            timestamp: reader.read_u64_le()?,
            spare: reader.read_u32_le()?,
        })
    }
}

pub fn is_win10_format(buff: &[u8]) -> bool {
    if buff.len() != 4096 {
        return false;
    }
    &buff[164..168] == b"rmtm"
}

pub fn is_valid_base_block(buff: &[u8]) -> bool {
    if buff.len() != 4096 {
        return false;
    }
    &buff[0..4] == b"regf"
}

pub fn is_hive_data(buff: &[u8]) -> bool {
    if buff.len() != 32 {
        return false;
    }
    &buff[0..4] == b"hbin"
}

/// XOR-32 checksum over the base block's first 508 bytes, compared against the stored checksum
/// at offset 508..512. Returns `false` (rather than panicking) for a buffer too short to contain
/// either region — relevant now that this is also called from format-probing code that may feed
/// it an arbitrary, possibly truncated file.
pub fn checksum_is_correct(buff: &[u8]) -> bool {
    if buff.len() < 512 {
        return false;
    }
    let mut c: i32 = 0;
    for i in (0..508).step_by(4) {
        // Bounds already guaranteed by the length check above; `unwrap_or_default` here is
        // unreachable, not a fallback for truncated evidence.
        let v = i32::from_le_bytes(buff[i..i + 4].try_into().unwrap_or_default());
        c ^= v;
    }
    if c == -1 {
        c = -2;
    } else if c == 0 {
        c = -1;
    }
    let checksum = i32::from_le_bytes(buff[508..512].try_into().unwrap_or_default());
    c == checksum
}

pub enum KernelTransactionManagerFlags {
    LockedHive = 0x00000001,
    DefragmentedHive = 0x00000002,
}

/// Reads the pre-Windows-10 base block layout (see the format spec's `BaseBlockWXP`) directly
/// off `reader` into the shared [BaseBlock] shape — there is no intermediate on-disk-layout
/// struct: the two formats only diverge in the reserved/GUID region between the shared leading
/// fields and the shared trailing `checksum`/`boot_type`/`boot_recovery` fields, which this
/// function simply `skip()`s over. `reader` must be positioned right after the 4-byte `"regf"`
/// signature (already validated by [is_valid_base_block] before this is called).
fn read_base_block_wxp(reader: &mut ByteReader) -> ForensicResult<BaseBlock> {
    let prim_sequence = reader.read_u32_le()?;
    let sec_sequence = reader.read_u32_le()?;
    let last_written_timestamp = reader.read_u64_le()?;
    let major_version = reader.read_u32_le()?;
    let minor_version = reader.read_u32_le()?;
    let file_type = reader.read_u32_le()?;
    let file_format = reader.read_u32_le()?;
    let root_cell_offset = reader.read_u32_le()?;
    let hive_bins_data_size = reader.read_u32_le()?;
    let clustering_factor = reader.read_u32_le()?;
    let file_name = reader.read_fixed::<64>()?;
    // reserved(56) + offreg_signature(4) + offreg_flags(4) + reserved1(332) = 396 bytes, landing
    // exactly at offset 508 (checksum) from the start of the base block.
    reader.skip(56 + 4 + 4 + 332)?;
    let checksum = reader.read_u32_le()?;
    // serialization_timestamp(8) + reserved2(3568) = 3576 bytes, landing at offset 4088.
    reader.skip(8 + 3568)?;
    let boot_type = reader.read_u32_le()?;
    let boot_recovery = reader.read_u32_le()?;
    Ok(BaseBlock {
        prim_sequence,
        sec_sequence,
        last_written_timestamp,
        major_version,
        minor_version,
        file_type,
        file_format,
        root_cell_offset,
        hive_bins_data_size,
        clustering_factor,
        file_name,
        checksum,
        boot_type,
        boot_recovery,
    })
}

/// Reads the Windows-10 base block layout (adds the transaction-log GUIDs and a `"rmtm"`
/// signature). The GUID fields (`rm_id`/`log_id`/`tm_id`/`flags`/`guid_signature`/
/// `last_reorganized_timestamp`) aren't carried into [BaseBlock] — nothing in this crate reads
/// them — so they're `skip()`'d rather than decoded into typed values. `reader` must be
/// positioned right after the 4-byte `"regf"` signature, same as [read_base_block_wxp].
fn read_base_block_w10(reader: &mut ByteReader) -> ForensicResult<BaseBlock> {
    let prim_sequence = reader.read_u32_le()?;
    let sec_sequence = reader.read_u32_le()?;
    let last_written_timestamp = reader.read_u64_le()?;
    let major_version = reader.read_u32_le()?;
    let minor_version = reader.read_u32_le()?;
    let file_type = reader.read_u32_le()?;
    let file_format = reader.read_u32_le()?;
    let root_cell_offset = reader.read_u32_le()?;
    let hive_bins_data_size = reader.read_u32_le()?;
    let clustering_factor = reader.read_u32_le()?;
    let file_name = reader.read_fixed::<64>()?;
    // rm_id(16) + log_id(16) + flags(4) + tm_id(16) + guid_signature(4) +
    // last_reorganized_timestamp(8) + offreg_signature(4) + offreg_flags(4) + reserved1(324)
    // = 396 bytes, landing at offset 508 (checksum), same as the WXP layout above.
    reader.skip(16 + 16 + 4 + 16 + 4 + 8 + 4 + 4 + 324)?;
    let checksum = reader.read_u32_le()?;
    reader.skip(8 + 3568)?;
    let boot_type = reader.read_u32_le()?;
    let boot_recovery = reader.read_u32_le()?;
    Ok(BaseBlock {
        prim_sequence,
        sec_sequence,
        last_written_timestamp,
        major_version,
        minor_version,
        file_type,
        file_format,
        root_cell_offset,
        hive_bins_data_size,
        clustering_factor,
        file_name,
        checksum,
        boot_type,
        boot_recovery,
    })
}

/// Reads and validates the 4096-byte base block. A base-block checksum mismatch does not fail
/// the read (the rest of the hive may still be usable) but is recorded both as a `warn!` line
/// (for engineers) and as an `InvalidChecksum` [Finding] pushed onto `findings` (for analysts) —
/// see the crate's `forensic-rs-tool-review` skill on the Finding/log/error three-way split.
pub fn read_base_block(file: &mut Box<dyn VirtualFile>, findings: &mut Vec<Finding>) -> ForensicResult<BaseBlock> {
    let mut buffer = vec![0u8; 4096];
    file.read_exact(&mut buffer)?;
    if !is_valid_base_block(&buffer) {
        return Err(ForensicError::registry_hive_error("base_block", "invalid base block"));
    }
    if !checksum_is_correct(&buffer) {
        warn!("Incorrect checksum for Hive");
        findings.push(
            Finding::new(
                FindingSeverity::High,
                FindingCategory::InvalidChecksum,
                "Hive base block checksum mismatch",
            )
            .with_description(
                "The XOR-32 checksum over the hive's base block does not match the stored checksum. \
             The header may be corrupted or the file truncated/tampered with; values read from \
             this hive should be treated with caution.",
            ),
        );
    }
    let mut reader = ByteReader::new(&buffer);
    reader.skip(4)?; // "regf" signature, already validated by is_valid_base_block above
    if is_win10_format(&buffer) {
        read_base_block_w10(&mut reader)
    } else {
        read_base_block_wxp(&mut reader)
    }
}

pub fn read_bin_header(file: &mut Box<dyn VirtualFile>) -> ForensicResult<HiveBinHeader> {
    let mut buffer = vec![0u8; 32];
    file.read_exact(&mut buffer)?;
    if !is_hive_data(&buffer) {
        return Err(ForensicError::registry_hive_error(
            "hive_bin_header",
            "signature does not match",
        ));
    }
    let mut reader = ByteReader::new(&buffer);
    reader.read_as()
}

pub fn read_hive_bin_at_file_position(file: &mut Box<dyn VirtualFile>) -> ForensicResult<(HiveBinHeader, Vec<u8>)> {
    let initial_offset = file.stream_position().unwrap_or_default();
    let header = match read_bin_header(file) {
        Ok(v) => v,
        Err(e) => {
            file.seek(std::io::SeekFrom::Start(initial_offset))?;
            return Err(e);
        }
    };
    if header.size < 32 {
        file.seek(std::io::SeekFrom::Start(initial_offset))?;
        return Err(ForensicError::registry_hive_error("hive_bin_header", "too small"));
    }
    let mut buff = vec![0u8; header.size as usize - 32];
    file.read_exact(&mut buff)?;
    Ok((header, buff))
}

/// Splits `data` (one hive bin's raw content) into individual [HiveCell]s. A cell that fails to
/// parse (unrecognized/corrupt content past a plausible length prefix) is skipped rather than
/// aborting the whole bin — but skipped cells are tallied and reported as a single aggregate
/// `IntegrityIssue` [Finding] pushed onto `findings` (one per bin, not one per cell — a bin with
/// many skipped cells would otherwise flood the findings list with duplicates of the same signal).
pub fn read_cells(data: &[u8], bin_offset: u64, findings: &mut Vec<Finding>) -> ForensicResult<Vec<HiveCell>> {
    let len = data.len();
    if len < 4 {
        return Err(ForensicError::registry_hive_error("hive_cell", "too small"));
    }
    let mut offset = 0usize;
    let mut list = Vec::with_capacity(128);
    let mut skipped = 0u32;
    loop {
        if offset > len {
            return Err(ForensicError::registry_hive_error(
                "hive_cell",
                "offset at position larger than the buffer",
            ));
        } else if offset == len {
            break;
        }
        // Size of a current cell in bytes, including this field (aligned to 8 bytes): the size is
        // positive if a cell is unallocated or negative if a cell is allocated (use absolute
        // values for calculations). Read via `ByteReader` rather than a raw slice so a truncated
        // trailing cell (fewer than 4 bytes remaining) returns an `Err` instead of panicking.
        let mut peek = ByteReader::new(&data[offset..]);
        let cell_len_i = peek.read_i32_le()?;
        let cell_len = cell_len_i.unsigned_abs() as usize;
        if offset + cell_len > len {
            return Err(ForensicError::registry_hive_error(
                "hive_cell",
                "end position larger than the buffer",
            ));
        }
        let cell_data = &data[offset..offset + cell_len];
        let cell = match read_cell(cell_data, bin_offset + offset as u64) {
            Ok(v) => v,
            Err(_e) => {
                skipped += 1;
                offset += cell_len;
                continue;
            }
        };
        list.push(cell);
        offset += cell_len;
    }
    if skipped > 0 {
        findings.push(
            Finding::new(
                FindingSeverity::Medium,
                FindingCategory::IntegrityIssue,
                "Unparseable cells skipped in hive bin",
            )
            .with_description(format!(
                "{skipped} cell(s) in the hive bin at offset {bin_offset} had an unrecognized \
                 or corrupt signature and were skipped; the parsed subkey/value tree for this bin \
                 may be incomplete."
            )),
        );
    }
    Ok(list)
}

#[cfg(test)]
mod tst {
    use super::*;
    use crate::tst::*;
    #[test]
    fn can_read_hive_header_block() {
        let fs = init_virtual_fs();
        let mut sam_file = read_sam_hive(&fs);
        let base_block = read_base_block(&mut sam_file, &mut Vec::new()).unwrap();
        assert_eq!(
            str_to_unicode_with_ending(b"\\SystemRoot\\System32\\Config\\SAM"),
            &base_block.file_name[0..64]
        );
        let mut sec_file: Box<dyn VirtualFile> = read_sec_hive(&fs);
        let base_block = read_base_block(&mut sec_file, &mut Vec::new()).unwrap();
        assert_eq!(
            str_to_unicode_with_ending(b"emRoot\\System32\\Config\\SECURITY"),
            &base_block.file_name[0..64]
        );
    }

    #[test]
    fn can_read_sam_hive_data() {
        let fs = init_virtual_fs();
        let mut sam_file = read_sam_hive(&fs);
        let base_block = read_base_block(&mut sam_file, &mut Vec::new()).unwrap();
        // Position to 4096 + offset -32 (header)
        sam_file
            .seek(std::io::SeekFrom::Start(4096 + base_block.root_cell_offset as u64 - 32))
            .unwrap();
        let hive_bin = read_hive_bin_at_file_position(&mut sam_file).unwrap();
        read_cells(
            &hive_bin.1,
            4096 + base_block.root_cell_offset as u64 - 32,
            &mut Vec::new(),
        )
        .unwrap();
        let mut offset = 4096 + base_block.root_cell_offset as u64 - 32;
        let mut cell_offset = 32;
        loop {
            if offset >= base_block.hive_bins_data_size.into() {
                break;
            }
            sam_file.seek(std::io::SeekFrom::Start(offset)).unwrap();
            let hive_bin = read_hive_bin_at_file_position(&mut sam_file).unwrap();
            let cells = read_cells(&hive_bin.1, cell_offset, &mut Vec::new()).unwrap();
            println!("{:?}", cells);
            offset += hive_bin.0.size as u64;
            cell_offset += hive_bin.0.size as u64;
        }
    }
    #[test]
    fn can_read_security_hive_data() {
        let fs = init_virtual_fs();
        let mut sec_file = read_sec_hive(&fs);
        let base_block = read_base_block(&mut sec_file, &mut Vec::new()).unwrap();
        // Position to 4096 + offset -32 (header)

        let mut offset = 4096 + base_block.root_cell_offset as u64 - 32;

        loop {
            if offset >= base_block.hive_bins_data_size.into() {
                break;
            }
            sec_file.seek(std::io::SeekFrom::Start(offset)).unwrap();
            let hive_bin = read_hive_bin_at_file_position(&mut sec_file).unwrap();
            let cells = read_cells(
                &hive_bin.1,
                offset - 4064 - base_block.root_cell_offset as u64,
                &mut Vec::new(),
            )
            .unwrap();
            println!("{:?}", cells);
            offset += hive_bin.0.size as u64;
        }
    }

    #[test]
    #[ignore = "requires the large ./artifacts/.../SOFTWARE fixture"]
    fn can_read_software_hive_data() {
        let fs = init_virtual_fs();
        let mut sec_file = read_software_hive(&fs);
        let base_block = read_base_block(&mut sec_file, &mut Vec::new()).unwrap();
        // Position to 4096 + offset -32 (header)

        let mut offset = 4096 + base_block.root_cell_offset as u64 - 32;

        loop {
            if offset >= base_block.hive_bins_data_size.into() {
                break;
            }
            sec_file.seek(std::io::SeekFrom::Start(offset)).unwrap();
            let hive_bin = read_hive_bin_at_file_position(&mut sec_file).unwrap();
            let cells = read_cells(
                &hive_bin.1,
                offset - 4064 - base_block.root_cell_offset as u64,
                &mut Vec::new(),
            )
            .unwrap();
            println!("{:?}", cells);
            offset += hive_bin.0.size as u64;
        }
    }

    #[test]
    fn can_read_supersecretadmin_hive_data() {
        let fs = init_virtual_fs();
        let mut sec_file = read_supersecretadmin_hive(&fs);
        let base_block = read_base_block(&mut sec_file, &mut Vec::new()).unwrap();
        // Position to 4096 + offset -32 (header)

        let mut offset = 4096 + base_block.root_cell_offset as u64 - 32;

        loop {
            if offset >= base_block.hive_bins_data_size.into() {
                break;
            }
            sec_file.seek(std::io::SeekFrom::Start(offset)).unwrap();
            let hive_bin = read_hive_bin_at_file_position(&mut sec_file).unwrap();
            let cells = read_cells(
                &hive_bin.1,
                offset - 4064 - base_block.root_cell_offset as u64,
                &mut Vec::new(),
            )
            .unwrap();
            println!("{:?}", cells);
            offset += hive_bin.0.size as u64;
        }
    }

    // --- read_cells: truncated trailing cell must error, not panic --------------------------

    #[test]
    fn read_cells_rejects_truncated_trailing_cell_without_panicking() {
        // One well-formed, fully-allocated 8-byte "invalid" cell (length prefix + 4 content
        // bytes, no signature match) followed by 1-3 stray bytes: fewer than the 4 bytes needed
        // to even read the next cell's length prefix. Before switching to `ByteReader`, this
        // sliced `data[offset..offset+4]` directly and panicked instead of returning an `Err`.
        let mut data = (-8i32).to_le_bytes().to_vec();
        data.extend_from_slice(&[0xAA, 0xAA, 0xAA, 0xAA]);
        data.push(0xFF); // truncated trailing cell: only 1 byte where a length prefix is expected
        assert!(read_cells(&data, 0, &mut Vec::new()).is_err());
    }
}
