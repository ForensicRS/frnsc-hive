use forensic_rs::{traits::vfs::VirtualFile, prelude::ForensicResult, notifications::NotificationType, notify_info};

use crate::cell::read_cell;

pub struct HivePrimaryFile {
    pub base_block : BaseBlock
}

#[derive(Debug)]
pub struct BaseBlock {
    /// Primary sequence number.
    /// This number is incremented by 1 in the beginning of a write operation on the primary file
    pub prim_sequence : u32,
    /// Secondary sequence number.
    /// This number is incremented by 1 at the end of a write operation on the primary file, 
    /// a primary sequence number and a secondary sequence number should be equal after a successful write operation
    pub sec_sequence : u32,
    /// FILETIME (UTC)
    pub last_written_timestamp : u64,
    /// Major version of a hive writer
    pub major_version : u32,
    /// Minor version of a hive writer
    pub minor_version : u32,
    /// 0 means primary file
    pub file_type : u32,
    /// 1 means direct memory load
    pub file_format : u32,
    /// Offset of a root cell in bytes, relative from the start of the hive bins data
    pub root_cell_offset : u32,
    /// Size of the hive bins data in bytes
    pub hive_bins_data_size : u32,
    /// Logical sector size of the underlying disk in bytes divided by 512
    pub clustering_factor : u32,
    /// UTF-16LE string (contains a partial file path to the primary file, or a file name of the primary file), used for debugging purposes
    pub file_name : [u8; 64],
    /// XOR-32 checksum of the previous 508 bytes
    pub checksum : u32,
    /// This field has no meaning on a disk
    pub boot_type : u32,
    /// This field has no meaning on a disk
    pub boot_recovery : u32
}

#[repr(C, packed)]
pub struct BaseBlockWXP {
    /// ASCII String regf
    pub signature : u32,
    /// Primary sequence number.
    /// This number is incremented by 1 in the beginning of a write operation on the primary file
    pub prim_sequence : u32,
    /// Secondary sequence number.
    /// This number is incremented by 1 at the end of a write operation on the primary file, 
    /// a primary sequence number and a secondary sequence number should be equal after a successful write operation
    pub sec_sequence : u32,
    /// FILETIME (UTC)
    pub last_written_timestamp : u64,
    /// Major version of a hive writer
    pub major_version : u32,
    /// Minor version of a hive writer
    pub minor_version : u32,
    /// 0 means primary file
    pub file_type : u32,
    /// 1 means direct memory load
    pub file_format : u32,
    /// Offset of a root cell in bytes, relative from the start of the hive bins data
    pub root_cell_offset : u32,
    /// Size of the hive bins data in bytes
    pub hive_bins_data_size : u32,
    /// Logical sector size of the underlying disk in bytes divided by 512
    pub clustering_factor : u32,
    /// UTF-16LE string (contains a partial file path to the primary file, or a file name of the primary file), used for debugging purposes
    pub file_name : [u8; 64],
    pub reserved : [u8; 56],
    /// ASCII string "OfRg" The Offline Registry Library (offreg.dll) is writing the following additional fields to the base block when the hive is serialized 
    pub offreg_signature : u32,
    /// This is the only value used "1"
    pub offreg_flags : u32,
    pub reserved1 : [u8; 332],
    /// XOR-32 checksum of the previous 508 bytes
    pub checksum : u32,
    /// FILETIME UTC. Writed by offreg.dll
    pub serialization_timestamp : u64,
    pub reserved2 : [u8; 3568],
    /// This field has no meaning on a disk
    pub boot_type : u32,
    /// This field has no meaning on a disk
    pub boot_recovery : u32
}

#[repr(C, packed)]
pub struct BaseBlockW10 {
    /// ASCII String regf
    pub signature : u32,
    /// Primary sequence number.
    /// This number is incremented by 1 in the beginning of a write operation on the primary file
    pub prim_sequence : u32,
    /// Secondary sequence number.
    /// This number is incremented by 1 at the end of a write operation on the primary file, 
    /// a primary sequence number and a secondary sequence number should be equal after a successful write operation
    pub sec_sequence : u32,
    /// FILETIME (UTC)
    pub last_written_timestamp : u64,
    /// Major version of a hive writer
    pub major_version : u32,
    /// Minor version of a hive writer
    pub minor_version : u32,
    /// 0 means primary file
    pub file_type : u32,
    /// 1 means direct memory load
    pub file_format : u32,
    /// Offset of a root cell in bytes, relative from the start of the hive bins data
    pub root_cell_offset : u32,
    /// Size of the hive bins data in bytes
    pub hive_bins_data_size : u32,
    /// Logical sector size of the underlying disk in bytes divided by 512
    pub clustering_factor : u32,
    /// UTF-16LE string (contains a partial file path to the primary file, or a file name of the primary file), used for debugging purposes
    pub file_name : [u8; 64],
    /// Resource Manager GUID
    pub rm_id : u128,
    /// GUID used to generate a file name of a physical log file
    pub log_id : u128,
    /// Bit mask
    pub flags : u32,
    /// GUID used to generate a file name of a log file stream for the Transaction Manager
    pub tm_id : u128,
    /// ASCII string "rmtm" unless hive is frozen
    pub guid_signature : u32,
    /// FILETIME (UTC)
    pub last_reorganized_timestamp : u64,
    /// ASCII string "OfRg" The Offline Registry Library (offreg.dll) is writing the following additional fields to the base block when the hive is serialized 
    pub offreg_signature : u32,
    /// This is the only value used "1"
    pub offreg_flags : u32,
    pub reserved1 : [u8; 324],
    /// XOR-32 checksum of the previous 508 bytes
    pub checksum : u32,
    /// FILETIME UTC. Writed by offreg.dll
    pub serialization_timestamp : u64,
    pub reserved2 : [u8; 3568],
    /// This field has no meaning on a disk
    pub boot_type : u32,
    /// This field has no meaning on a disk
    pub boot_recovery : u32
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct HiveBinHeader {
    /// ASCII string hbin
    pub signature : u32,
    /// Offset of a current hive bin in bytes, relative from the start of the hive bins data
    pub offset : u32,
    /// Size of a current hive bin in bytes
    pub size : u32,
    pub reserved : u64,
    /// FILETIME (UTC), defined for the first hive bin only (see below)
    pub timestamp : u64,
    /// Spare (or MemAlloc). This field has no meaning on a disk (see below)
    pub spare : u32
}


impl From<BaseBlockW10> for BaseBlock {
    fn from(value: BaseBlockW10) -> Self {
        BaseBlock { prim_sequence: value.prim_sequence, sec_sequence: value.sec_sequence, last_written_timestamp: value.last_written_timestamp, major_version: value.major_version, minor_version: value.minor_version, file_type: value.file_type, file_format: value.file_format, root_cell_offset: value.root_cell_offset, hive_bins_data_size: value.hive_bins_data_size, clustering_factor: value.clustering_factor, file_name: value.file_name, checksum: value.checksum, boot_type: value.boot_type, boot_recovery: value.boot_recovery }
    }
}
impl From<&BaseBlockW10> for BaseBlock {
    fn from(value: &BaseBlockW10) -> Self {
        BaseBlock { prim_sequence: value.prim_sequence, sec_sequence: value.sec_sequence, last_written_timestamp: value.last_written_timestamp, major_version: value.major_version, minor_version: value.minor_version, file_type: value.file_type, file_format: value.file_format, root_cell_offset: value.root_cell_offset, hive_bins_data_size: value.hive_bins_data_size, clustering_factor: value.clustering_factor, file_name: value.file_name, checksum: value.checksum, boot_type: value.boot_type, boot_recovery: value.boot_recovery }
    }
}

impl From<BaseBlockWXP> for BaseBlock {
    fn from(value: BaseBlockWXP) -> Self {
        BaseBlock { prim_sequence: value.prim_sequence, sec_sequence: value.sec_sequence, last_written_timestamp: value.last_written_timestamp, major_version: value.major_version, minor_version: value.minor_version, file_type: value.file_type, file_format: value.file_format, root_cell_offset: value.root_cell_offset, hive_bins_data_size: value.hive_bins_data_size, clustering_factor: value.clustering_factor, file_name: value.file_name, checksum: value.checksum, boot_type: value.boot_type, boot_recovery: value.boot_recovery }
    }
}
impl From<&BaseBlockWXP> for BaseBlock {
    fn from(value: &BaseBlockWXP) -> Self {
        BaseBlock { prim_sequence: value.prim_sequence, sec_sequence: value.sec_sequence, last_written_timestamp: value.last_written_timestamp, major_version: value.major_version, minor_version: value.minor_version, file_type: value.file_type, file_format: value.file_format, root_cell_offset: value.root_cell_offset, hive_bins_data_size: value.hive_bins_data_size, clustering_factor: value.clustering_factor, file_name: value.file_name, checksum: value.checksum, boot_type: value.boot_type, boot_recovery: value.boot_recovery }
    }
}

pub fn is_win10_format(buff : &[u8]) -> bool {
    if buff.len() != 4096 {
        return false
    }
    &buff[164..168] == b"rmtm"
}

pub fn is_valid_base_block(buff : &[u8]) -> bool {
    if buff.len() != 4096 {
        return false
    }
    &buff[0..4] == b"regf"
}

pub fn is_hive_data(buff : &[u8]) -> bool {
    if buff.len() != 32 {
        return false
    }
    &buff[0..4] == b"hbin"
}

pub fn checksum_is_correct(buff : &[u8]) -> bool {
    let mut c : i32 = 0;
    for i in (0..508).step_by(4) {
        let v = i32::from_ne_bytes(buff[i..i+4].try_into().unwrap_or_default());
        c = c ^ v;
    }
    if c == -1 {
        c = -2;
    }else if c == 0 {
        c = -1;
    }
    let checksum = i32::from_ne_bytes(buff[508..512].try_into().unwrap_or_default());
    c == checksum
    
}

pub enum KernelTransactionManagerFlags {
    LockedHive = 0x00000001,
    DefragmentedHive = 0x00000002
}

pub fn read_base_block(file : &mut Box<dyn VirtualFile>) -> ForensicResult<BaseBlock> {
    let mut buffer = vec![0u8;4096];
    file.read_exact(&mut buffer)?;
    if !is_valid_base_block(&buffer) {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    if !checksum_is_correct(&buffer) {
        notify_info!(NotificationType::Informational, "Incorrect checksum for Hive");
    }
    if is_win10_format(&buffer) {
        let (head, body, tail) = unsafe { buffer.align_to::<BaseBlockW10>() };
        if head.len() != 0 || tail.len() != 0{
            return Err(forensic_rs::prelude::ForensicError::BadFormat);
        }
        let base_block = &body[0];
        return Ok(base_block.into())
    }
    let (head, body, tail) = unsafe { buffer.align_to::<BaseBlockWXP>() };
    if head.len() != 0 || tail.len() != 0{
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    let base_block = &body[0];
    return Ok(base_block.into())
}
pub fn read_bin_header(file : &mut Box<dyn VirtualFile>) -> ForensicResult<HiveBinHeader> {
    let mut buffer = vec![0u8;32];
    file.read_exact(&mut buffer)?;
    if !is_hive_data(&buffer) {
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    let (head, body, tail) = unsafe { buffer.align_to::<HiveBinHeader>() };
    if head.len() != 0 || tail.len() != 0{
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    let header = &body[0];
    Ok(HiveBinHeader { signature: header.signature, offset: header.offset, size: header.size, reserved: header.reserved, timestamp: header.timestamp, spare: header.spare })
}

pub fn read_hive_bin_at_file_position(file : &mut Box<dyn VirtualFile>) -> ForensicResult<(HiveBinHeader, Vec<u8>)> {
    let initial_offset = file.stream_position().unwrap_or_default();
    let header = match read_bin_header(file) {
        Ok(v) => v,
        Err(e) => {
            file.seek(std::io::SeekFrom::Start(initial_offset))?;
            return Err(e);
        }
    };
    if header.size < 32 {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let mut buff = vec![0u8; header.size as usize - 32];
    file.read_exact(&mut buff)?;
    return Ok((header, buff))
}


pub fn read_cells(data : &[u8]) -> ForensicResult<()> {
    let len = data.len();
    if len < 4 {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let mut offset = 0;
    loop {
        if offset > len {
            return Err(forensic_rs::prelude::ForensicError::BadFormat)
        }else if offset == len {
            break;
        }
        // Size of a current cell in bytes, including this field (aligned to 8 bytes): the size is positive if a cell is unallocated or negative if a cell is allocated (use absolute values for calculations)
        let cell_len_i = i32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap_or_default());
        let cell_len = cell_len_i.abs() as usize;
        if offset + cell_len > len {
            return Err(forensic_rs::prelude::ForensicError::BadFormat)
        }
        let cell_data = &data[offset + 4..offset + cell_len];
        let cell = match read_cell(cell_data) {
            Ok(v) => v,
            Err(e) => {
                println!("Invalid Cell {:?}", e);
                offset = offset + cell_len;
                continue;
            }
        };
        println!("{:?}", cell);
        // TODO
        offset = offset + cell_len;
    }
    Ok(())
}


#[cfg(test)]
mod tst {
    use crate::tst::*;
    use super::*;
    #[test]
    fn can_read_hive_header_block() {
        init_tst();
        let mut fs = init_virtual_fs();
        let mut sam_file = read_sam_hive(&mut fs);
        let base_block = read_base_block(&mut sam_file).unwrap();
        assert_eq!(str_to_unicode_with_ending(b"\\SystemRoot\\System32\\Config\\SAM"), &base_block.file_name[0..64]);
        let mut sec_file: Box<dyn VirtualFile> = read_sec_hive(&mut fs);
        let base_block = read_base_block(&mut sec_file).unwrap();
        assert_eq!(str_to_unicode_with_ending(b"emRoot\\System32\\Config\\SECURITY"), &base_block.file_name[0..64]);
        assert_no_notifications();
        
    }

    #[test]
    fn can_read_sam_hive_data() {
        init_tst();
        let mut fs = init_virtual_fs();
        let mut sam_file = read_sam_hive(&mut fs);
        let base_block = read_base_block(&mut sam_file).unwrap();
        assert_no_notifications();
        // Position to 4096 + offset -32 (header)
        sam_file.seek(std::io::SeekFrom::Start(4096 + base_block.root_cell_offset as u64 - 32)).unwrap();
        let hive_bin = read_hive_bin_at_file_position(&mut sam_file).unwrap();
        read_cells(&hive_bin.1).unwrap();
    }
    #[test]
    fn can_read_security_hive_data() {
        init_tst();
        let mut fs = init_virtual_fs();
        let mut sec_file = read_sec_hive(&mut fs);
        let base_block = read_base_block(&mut sec_file).unwrap();
        assert_no_notifications();
        // Position to 4096 + offset -32 (header)
        
        let mut i = 0;
        let mut offset = 4096 + base_block.root_cell_offset as u64 - 32;
        
        loop {
            if offset >= base_block.hive_bins_data_size.into() {
                break;
            }
            println!("Hive Bin {}", i);
            i = i+1;
            sec_file.seek(std::io::SeekFrom::Start(offset)).unwrap();
            let hive_bin = read_hive_bin_at_file_position(&mut sec_file).unwrap();
            read_cells(&hive_bin.1).unwrap();
            offset += hive_bin.0.size as u64;
        }
        
    }
}