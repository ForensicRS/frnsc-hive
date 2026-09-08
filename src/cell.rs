//! Parses individual REGF cells: the `nk`/`vk`/`sk`/`li`/`lf`/`lh`/`ri`-signed structures that
//! make up a hive bin's contents (see [crate::hive] for the bin-level framing around them).
//!
//! Each recognized cell type implements [FromBytes], decoded directly off a [ByteReader] cursor
//! (fixed header fields first, then any variable-length trailing data such as a key/value name or
//! a security descriptor, read off the same cursor). [read_cell] dispatches on the 2-byte
//! signature to the matching `read_*_cell` function and wraps the result in the [HiveCell] enum;
//! an unrecognized signature becomes [HiveCell::Invalid] (its raw bytes are kept as-is — this is
//! also how a `KeyValue`'s resident data cell is represented, since it has no signature of its
//! own) and a positive cell-size prefix (meaning "unallocated") becomes [HiveCell::Unallocated].
//!
//! [BigDataCell]/the `db` signature is defined per the format spec but never produced by
//! [read_cell] — chunked "big data" values (values too large to store in one cell) are not
//! currently decoded.

use forensic_rs::prelude::{ByteReader, ForensicError, ForensicResult, FromBytes};
pub const INDEX_LEAF_SIGNATURE: &[u8; 2] = b"li";
pub const FAST_LEAF_SIGNATURE: &[u8; 2] = b"lf";
pub const HASH_LEAF_SIGNATURE: &[u8; 2] = b"lh";
pub const INDEX_ROOT_SIGNATURE: &[u8; 2] = b"ri";
pub const KEY_NODE_SIGNATURE: &[u8; 2] = b"nk";
pub const KEY_SECURITY_SIGNATURE: &[u8; 2] = b"sk";
pub const KEY_VALUE_SIGNATURE: &[u8; 2] = b"vk";

/// Is volatile (not used, a key node on a disk isn't expected to have this flag set)
pub const KEY_VOLATILE_FLAG: u16 = 0x0001;
/// Is the mount point of another hive (a key node on a disk isn't expected to have this flag set)
pub const KEY_HIVE_EXIT_FLAG: u16 = 0x0002;
/// Is the root key for this hive
pub const KEY_HIVE_ENTRY_FLAG: u16 = 0x0004;
/// This key can't be deleted
pub const KEY_NO_DELETE_FLAG: u16 = 0x0008;
/// This key is a symlink (a target key is specified as a UTF-16LE string (REG_LINK) in a value named "SymbolicLinkValue", example: \REGISTRY\MACHINE\SOFTWARE\Classes\Wow6432Node)
pub const KEY_SYM_LINK_FLAG: u16 = 0x0010;
/// Key name is an ASCII string, possibly an extended ASCII string (otherwise it is a UTF-16LE string)
pub const KEY_COMP_NAME_FLAG: u16 = 0x0020;
/// Is a predefined handle (a handle is stored in the Number of key values field)
pub const KEY_PREDEF_HANDLE_FLAG: u16 = 0x0040;

/// Value name is an ASCII string, possibly an extended ASCII string (otherwise it is a UTF-16LE string)
pub const VALUE_COMP_NAME_FLAG: u16 = 0x0001;
/// Is a tombstone value (the flag is used starting from Insider Preview builds of Windows 10 "Redstone 1"), a tombstone value also has the Data type field set to REG_NONE, the Data size field set to 0, and the Data offset field set to 0xFFFFFFFF
pub const VALUE_IS_TOMBSTONE: u16 = 0x0002;

#[derive(Debug, Clone)]
pub enum HiveCell {
    IndexLeaf(IndexLeafCell),
    FastLeaf(FastLeafCell),
    HashLeaf(HashLeafCell),
    IndexRoot(IndexRootCell),
    KeyNode(KeyNodeCell),
    KeyValue(KeyValueCell),
    KeySecurity(KeySecurityCell),
    BigData(BigDataCell),
    Unallocated(UnallocatedCell),
    Invalid(InvalidCell),
}
impl HiveCell {
    pub fn offset(&self) -> u64 {
        match self {
            HiveCell::IndexLeaf(v) => v.offset,
            HiveCell::FastLeaf(v) => v.offset,
            HiveCell::HashLeaf(v) => v.offset,
            HiveCell::IndexRoot(v) => v.offset,
            HiveCell::KeyNode(v) => v.offset,
            HiveCell::KeyValue(v) => v.offset,
            HiveCell::KeySecurity(v) => v.offset,
            HiveCell::BigData(v) => v.offset,
            HiveCell::Unallocated(v) => v.offset,
            HiveCell::Invalid(v) => v.offset,
        }
    }
}
#[derive(Debug, Clone)]
pub struct UnallocatedCell {
    pub offset: u64,
    /// The cell's declared size in bytes (including the 4-byte length-prefix field itself), as
    /// read directly from the positive length prefix — i.e. how many bytes past `offset`
    /// (relative to the hive-bins-data start) this free span spans. Lets [crate::recovery] scan
    /// exactly this span for leftover, still-negative-length-prefixed `nk`/`vk` cell bytes from a
    /// deleted key/value that hasn't yet been overwritten.
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct InvalidCell {
    pub offset: u64,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IndexLeafCell {
    /// List of offsets of the key node elements in bytes relative from the start of the hive bins data
    pub elements: Vec<IndexLeafListElements>,
    pub offset: u64,
}
#[derive(Debug, Clone)]
pub struct IndexLeafListElements {
    /// Key node element offset in bytes relative from the start of the hive bins data
    pub offset: u32,
}
#[derive(Debug, Clone)]
pub struct FastLeafCell {
    pub elements: Vec<FastLeafListElements>,
    pub offset: u64,
}
#[derive(Debug, Clone)]
pub struct FastLeafListElements {
    /// Key node offset: In bytes, relative from the start of the hive bins data
    pub offset: u32,
    /// The first 4 ASCII characters of a key name string (used to speed up lookups)
    pub name_hint: String,
}
#[derive(Debug, Clone)]
pub struct HashLeafCell {
    pub elements: Vec<HashLeafListElements>,
    pub offset: u64,
}
#[derive(Debug, Clone)]
pub struct HashLeafListElements {
    /// Key node offset: In bytes, relative from the start of the hive bins data
    pub offset: u32,
    /// Hash of a key name string, see below (used to speed up lookups)
    pub name_hash: u32,
}

impl HashLeafCell {
    pub fn hash_name(name: &str) -> u32 {
        let mut h: u32 = 0;
        if name.is_ascii() {
            for &char in name.as_bytes() {
                let char = Self::uppercase(char);
                h = 37u32.wrapping_mul(h).wrapping_add(char);
            }
        } else {
            for char in name.to_ascii_uppercase().encode_utf16() {
                h = 37u32.wrapping_mul(h).wrapping_add(char as u32);
            }
        }
        h
    }

    pub fn uppercase(v: u8) -> u32 {
        if v.is_ascii_lowercase() {
            (b'A' + (v - b'a')) as u32
        } else {
            v as u32
        }
    }
}

/// An Index root can't point to another Index root.
/// A subkeys list can't point to an Index root.
/// List elements within subkeys lists referenced by a single Index root must be sorted as a whole.
#[derive(Debug, Clone)]
pub struct IndexRootCell {
    pub elements: Vec<IndexRootSubkeyOffset>,
    pub offset: u64,
}
#[derive(Debug, Clone)]
pub struct IndexRootSubkeyOffset {
    /// Subkeys list offset: In bytes, relative from the start of the hive bins data
    pub subkeys_list_offset: u32,
}

#[derive(Debug, Clone)]
pub struct KeyNodeCell {
    /// Flags. Bit mask, see below
    pub flags: u16,
    /// Last written timestamp. FILETIME (UTC)
    pub last_written_timestamp: u64,
    /// Access bits. Bit mask, see below (this field is used as of Windows 8 and Windows Server 2012; in previous versions of Windows, this field is reserved and called Spare)
    pub access_bits: u32,
    /// Parent. Offset of a parent key node in bytes, relative from the start of the hive bins data (this field has no meaning on a disk for a root key node)
    pub parent: u32,
    /// Number of subkeys
    pub number_subkeys: u32,
    /// Number of volatile subkeys
    pub number_volatile_subkeys: u32,
    /// Subkeys list offset. In bytes, relative from the start of the hive bins data (also, this field may point to an Index root)
    pub subkeys_list_offset: u32,
    /// Volatile subkeys list offset. This field has no meaning on a disk (volatile keys are not written to a file)
    pub volatile_subkeys_list_offset: u32,
    /// Number of key values
    pub number_key_values: u32,
    /// Key values list offset. In bytes, relative from the start of the hive bins data
    pub key_values_list_offset: u32,
    /// Key security offset. In bytes, relative from the start of the hive bins data
    pub key_security_offset: u32,
    /// Class name offset. n bytes, relative from the start of the hive bins data
    pub class_name_offset: u32,
    /// Largest subkey class name length. In bytes
    pub largest_subkey_class_name_length: u32,
    /// Largest subkey name length. In bytes, a subkey name is treated as a UTF-16LE string.
    /// Starting from Windows Vista, Windows Server 2003 SP2, and Windows XP SP3, the Largest subkey name length field has been split into 4 bit fields
    pub largest_subkey_name_length: u16,
    /// Virtualization control flags and User flags (Wow64 flags)
    pub virt_and_user_flags: u8,
    /// Enabling Breakpoints for Registry Keys using the CmpRegDebugBreakEnabled kernel variable
    pub debug: u8,
    /// Largest value name length. In bytes, a value name is treated as a UTF-16LE string
    pub largest_value_name_length: u32,
    /// Largest value data size. In bytes
    pub largest_value_data_size: u32,
    /// WorkVar. Cached index
    pub work_var: u32,
    /// Key name length. In bytes
    pub key_name_length: u16,
    /// Class name length. In bytes
    pub class_name_length: u16,
    /// ASCII (extended) string or UTF-16LE string
    pub key_name: String,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct KeyValueCell {
    pub name_length: u16,
    pub data_size: u32,
    pub data_offset: u32,
    pub data_type: u32,
    pub flags: u16,
    pub value_name: String,
    pub offset: u64,
}
#[derive(Debug, Clone)]
pub struct KeySecurityCell {
    pub flink: u32,
    pub blink: u32,
    pub ref_count: u32,
    pub sec_desc_size: u32,
    pub sec_desc: Vec<u8>,
    pub offset: u64,
}
#[derive(Debug, Clone)]
pub struct BigDataCell {
    pub offset: u64,
}

/// Reads a `len`-byte extended-ASCII (Latin-1, byte value == codepoint) name off `reader`. Kept
/// as a hand-rolled `from_utf8_lossy`-equivalent rather than [ByteReader::read_ascii_string]
/// (Latin-1 passthrough, never fails) to preserve today's exact decode behavior (best-effort
/// UTF-8, only the genuinely-invalid sequences get replaced) — a real correctness question
/// (which interpretation better matches the format spec) is left for a follow-up, not decided
/// silently as a side effect of this migration.
fn read_extended_ascii_name(reader: &mut ByteReader, len: usize) -> ForensicResult<String> {
    Ok(String::from_utf8_lossy(reader.read_bytes(len)?).to_string())
}

impl FromBytes for IndexLeafCell {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let signature = reader.read_bytes(2)?;
        if signature != INDEX_LEAF_SIGNATURE {
            return Err(ForensicError::registry_cell_error("index_leaf", "invalid signature"));
        }
        let n_elements = reader.read_u16_le()?;
        let mut elements = Vec::with_capacity(n_elements.into());
        for _ in 0..n_elements {
            elements.push(IndexLeafListElements {
                offset: reader.read_u32_le()?,
            });
        }
        Ok(IndexLeafCell { elements, offset: 0 })
    }
}

impl FromBytes for FastLeafCell {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let signature = reader.read_bytes(2)?;
        if signature != FAST_LEAF_SIGNATURE {
            return Err(ForensicError::registry_cell_error("fast_leaf", "invalid signature"));
        }
        let n_elements = reader.read_u16_le()?;
        let mut elements = Vec::with_capacity(n_elements.into());
        for _ in 0..n_elements {
            let offset = reader.read_u32_le()?;
            let raw = reader.read_bytes(4)?;
            let end = raw.iter().position(|&v| v == 0).unwrap_or(4);
            let name_hint = String::from_utf8_lossy(&raw[..end]).to_string();
            elements.push(FastLeafListElements { offset, name_hint });
        }
        Ok(FastLeafCell { elements, offset: 0 })
    }
}

impl FromBytes for HashLeafCell {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let signature = reader.read_bytes(2)?;
        if signature != HASH_LEAF_SIGNATURE {
            return Err(ForensicError::registry_cell_error("hash_leaf", "invalid signature"));
        }
        let n_elements = reader.read_u16_le()?;
        let mut elements = Vec::with_capacity(n_elements.into());
        for _ in 0..n_elements {
            let offset = reader.read_u32_le()?;
            let name_hash = reader.read_u32_le()?;
            elements.push(HashLeafListElements { offset, name_hash });
        }
        Ok(HashLeafCell { elements, offset: 0 })
    }
}

impl FromBytes for IndexRootCell {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let signature = reader.read_bytes(2)?;
        if signature != INDEX_ROOT_SIGNATURE {
            return Err(ForensicError::registry_cell_error("index_root", "invalid signature"));
        }
        let n_elements = reader.read_u16_le()?;
        let mut elements = Vec::with_capacity(n_elements.into());
        for _ in 0..n_elements {
            elements.push(IndexRootSubkeyOffset {
                subkeys_list_offset: reader.read_u32_le()?,
            });
        }
        Ok(IndexRootCell { elements, offset: 0 })
    }
}

impl FromBytes for KeyNodeCell {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let signature = reader.read_bytes(2)?;
        if signature != KEY_NODE_SIGNATURE {
            return Err(ForensicError::registry_cell_error("key_node", "invalid signature"));
        }
        let flags = reader.read_u16_le()?;
        let last_written_timestamp = reader.read_u64_le()?;
        let access_bits = reader.read_u32_le()?;
        let parent = reader.read_u32_le()?;
        let number_subkeys = reader.read_u32_le()?;
        let number_volatile_subkeys = reader.read_u32_le()?;
        let subkeys_list_offset = reader.read_u32_le()?;
        let volatile_subkeys_list_offset = reader.read_u32_le()?;
        let number_key_values = reader.read_u32_le()?;
        let key_values_list_offset = reader.read_u32_le()?;
        let key_security_offset = reader.read_u32_le()?;
        let class_name_offset = reader.read_u32_le()?;
        let largest_subkey_class_name_length = reader.read_u32_le()?;
        let largest_subkey_name_length = reader.read_u16_le()?;
        let virt_and_user_flags = reader.read_u8()?;
        let debug = reader.read_u8()?;
        let largest_value_name_length = reader.read_u32_le()?;
        let largest_value_data_size = reader.read_u32_le()?;
        let work_var = reader.read_u32_le()?;
        let key_name_length = reader.read_u16_le()?;
        let class_name_length = reader.read_u16_le()?;
        let key_name = if flags & KEY_COMP_NAME_FLAG == 0 {
            reader.read_utf16le_string(key_name_length as usize)?
        } else {
            read_extended_ascii_name(reader, key_name_length as usize)?
        };
        Ok(KeyNodeCell {
            flags,
            last_written_timestamp,
            access_bits,
            parent,
            number_subkeys,
            number_volatile_subkeys,
            subkeys_list_offset,
            volatile_subkeys_list_offset,
            number_key_values,
            key_values_list_offset,
            key_security_offset,
            class_name_offset,
            largest_subkey_class_name_length,
            largest_subkey_name_length,
            virt_and_user_flags,
            debug,
            largest_value_name_length,
            largest_value_data_size,
            work_var,
            key_name_length,
            class_name_length,
            key_name,
            offset: 0,
        })
    }
}

impl FromBytes for KeyValueCell {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let signature = reader.read_bytes(2)?;
        if signature != KEY_VALUE_SIGNATURE {
            return Err(ForensicError::registry_cell_error("key_value", "invalid signature"));
        }
        let name_length = reader.read_u16_le()?;
        let data_size = reader.read_u32_le()?;
        let data_offset = reader.read_u32_le()?;
        let data_type = reader.read_u32_le()?;
        let flags = reader.read_u16_le()?;
        let _spare = reader.read_u16_le()?;
        let value_name = if name_length != 0 {
            if flags & VALUE_COMP_NAME_FLAG == 0 {
                reader.read_utf16le_string(name_length as usize)?
            } else {
                read_extended_ascii_name(reader, name_length as usize)?
            }
        } else {
            String::new()
        };
        Ok(KeyValueCell {
            name_length,
            data_size,
            data_offset,
            data_type,
            flags,
            value_name,
            offset: 0,
        })
    }
}

impl FromBytes for KeySecurityCell {
    fn from_bytes(reader: &mut ByteReader) -> ForensicResult<Self> {
        let signature = reader.read_bytes(2)?;
        if signature != KEY_SECURITY_SIGNATURE {
            return Err(ForensicError::registry_cell_error("key_security", "invalid signature"));
        }
        let _reserved = reader.read_u16_le()?;
        let flink = reader.read_u32_le()?;
        let blink = reader.read_u32_le()?;
        let ref_count = reader.read_u32_le()?;
        let sec_desc_size = reader.read_u32_le()?;
        let sec_desc = reader.read_bytes(sec_desc_size as usize)?.to_vec();
        Ok(KeySecurityCell {
            flink,
            blink,
            ref_count,
            sec_desc_size,
            sec_desc,
            offset: 0,
        })
    }
}

pub fn peek_cell(data: &[u8]) -> usize {
    let mut reader = ByteReader::new(data);
    match reader.read_i32_le() {
        Ok(v) => v.unsigned_abs() as usize,
        Err(_) => 0,
    }
}

pub fn read_cell(data: &[u8], offset: u64) -> ForensicResult<HiveCell> {
    if data.len() < 6 {
        return Err(ForensicError::registry_cell_error("cell", "too small"));
    }
    let mut reader = ByteReader::new(data);
    let cell_len_i = reader.read_i32_le()?;
    if cell_len_i >= 0 {
        return Ok(HiveCell::Unallocated(UnallocatedCell {
            offset,
            size: cell_len_i as u32,
        }));
    }
    let cell_len = cell_len_i.unsigned_abs() as usize;
    // A declared length whose magnitude is smaller than the 4-byte length prefix itself is
    // corrupt/adversarial input: without this check, slicing `data[4..cell_len]` below would
    // panic (start index > end index) instead of returning an `Err`.
    if cell_len < 4 {
        return Err(ForensicError::registry_cell_error(
            "cell",
            "declared length smaller than the length prefix",
        ));
    }
    let signature = reader.read_bytes(2)?;
    if cell_len > data.len() {
        return Err(ForensicError::registry_cell_error("cell", "not enough buffer size"));
    }
    let cell_data = &data[4..cell_len];
    let cell = if signature == INDEX_LEAF_SIGNATURE {
        HiveCell::IndexLeaf(read_index_leaf_cell(cell_data, offset)?)
    } else if signature == FAST_LEAF_SIGNATURE {
        HiveCell::FastLeaf(read_fast_leaf_cell(cell_data, offset)?)
    } else if signature == HASH_LEAF_SIGNATURE {
        HiveCell::HashLeaf(read_hash_leaf_cell(cell_data, offset)?)
    } else if signature == INDEX_ROOT_SIGNATURE {
        HiveCell::IndexRoot(read_index_root_cell(cell_data, offset)?)
    } else if signature == KEY_NODE_SIGNATURE {
        HiveCell::KeyNode(read_key_node_cell(cell_data, offset)?)
    } else if signature == KEY_SECURITY_SIGNATURE {
        HiveCell::KeySecurity(read_key_security_cell(cell_data, offset)?)
    } else if signature == KEY_VALUE_SIGNATURE {
        HiveCell::KeyValue(read_key_value_cell(cell_data, offset)?)
    } else {
        HiveCell::Invalid(InvalidCell {
            offset,
            content: cell_data.to_vec(),
        })
    };
    Ok(cell)
}

pub fn read_index_leaf_cell(data: &[u8], offset: u64) -> ForensicResult<IndexLeafCell> {
    let mut reader = ByteReader::new(data);
    let mut cell: IndexLeafCell = reader.read_as()?;
    cell.offset = offset;
    Ok(cell)
}

pub fn read_fast_leaf_cell(data: &[u8], offset: u64) -> ForensicResult<FastLeafCell> {
    let mut reader = ByteReader::new(data);
    let mut cell: FastLeafCell = reader.read_as()?;
    cell.offset = offset;
    Ok(cell)
}

pub fn read_hash_leaf_cell(data: &[u8], offset: u64) -> ForensicResult<HashLeafCell> {
    let mut reader = ByteReader::new(data);
    let mut cell: HashLeafCell = reader.read_as()?;
    cell.offset = offset;
    Ok(cell)
}

pub fn read_index_root_cell(data: &[u8], offset: u64) -> ForensicResult<IndexRootCell> {
    let mut reader = ByteReader::new(data);
    let mut cell: IndexRootCell = reader.read_as()?;
    cell.offset = offset;
    Ok(cell)
}

pub fn read_key_node_cell(data: &[u8], offset: u64) -> ForensicResult<KeyNodeCell> {
    let mut reader = ByteReader::new(data);
    let mut cell: KeyNodeCell = reader.read_as()?;
    cell.offset = offset;
    Ok(cell)
}

pub fn read_key_security_cell(data: &[u8], offset: u64) -> ForensicResult<KeySecurityCell> {
    let mut reader = ByteReader::new(data);
    let mut cell: KeySecurityCell = reader.read_as()?;
    cell.offset = offset;
    Ok(cell)
}

pub fn read_key_value_cell(data: &[u8], offset: u64) -> ForensicResult<KeyValueCell> {
    let mut reader = ByteReader::new(data);
    let mut cell: KeyValueCell = reader.read_as()?;
    cell.offset = offset;
    Ok(cell)
}

impl InvalidCell {
    pub fn into_reg_sz_extended(&self) -> String {
        let s: Vec<u16> = self
            .content
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let first_zero = match s.iter().rev().position(|&v| v == 0) {
            Some(v) => s.len() - v,
            None => s.len(),
        };
        let last_zero = match s[0..first_zero].iter().rev().position(|&v| v != 0) {
            Some(v) => first_zero - v,
            // Every element up to `first_zero` is a null: there is no content to keep.
            None => 0,
        };
        String::from_utf16_lossy(&s[..last_zero])
    }
    pub fn into_reg_sz_ascii(&self) -> String {
        let first_zero = match self.content.iter().rev().position(|&v| v == 0) {
            Some(v) => self.content.len() - v,
            None => self.content.len(),
        };
        let last_zero = match self.content[0..first_zero].iter().rev().position(|&v| v != 0) {
            Some(v) => first_zero - v,
            // Every element up to `first_zero` is a null: there is no content to keep.
            None => 0,
        };
        String::from_utf8_lossy(&self.content[..last_zero]).to_string()
    }
    /// Decodes this cell's content as a native-endian `DWORD`. Errors (rather than fabricating a
    /// `0`) when the content isn't exactly 4 bytes — a truncated/corrupt resident value must be
    /// surfaced as such, never silently decoded as a plausible-looking `DWORD:0`.
    pub fn into_dword(&self) -> ForensicResult<u32> {
        let bytes: [u8; 4] = self.content[..].try_into().map_err(|_| {
            ForensicError::registry_cell_error(
                "key_value_data",
                format!("expected 4 bytes for a DWORD, got {}", self.content.len()),
            )
        })?;
        Ok(u32::from_ne_bytes(bytes))
    }
    pub fn into_dword_le(&self) -> ForensicResult<u32> {
        let bytes: [u8; 4] = self.content[..].try_into().map_err(|_| {
            ForensicError::registry_cell_error(
                "key_value_data",
                format!("expected 4 bytes for a DWORD, got {}", self.content.len()),
            )
        })?;
        Ok(u32::from_le_bytes(bytes))
    }
    pub fn into_dword_be(&self) -> ForensicResult<u32> {
        let bytes: [u8; 4] = self.content[..].try_into().map_err(|_| {
            ForensicError::registry_cell_error(
                "key_value_data",
                format!("expected 4 bytes for a DWORD, got {}", self.content.len()),
            )
        })?;
        Ok(u32::from_be_bytes(bytes))
    }
    pub fn into_qword_le(&self) -> ForensicResult<u64> {
        let bytes: [u8; 8] = self.content[..].try_into().map_err(|_| {
            ForensicError::registry_cell_error(
                "key_value_data",
                format!("expected 8 bytes for a QWORD, got {}", self.content.len()),
            )
        })?;
        Ok(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn should_hash_sam_name() {
        assert_eq!(116109, HashLeafCell::hash_name("SAM"));
        assert_eq!(116109, HashLeafCell::hash_name("sam"));
        assert_eq!(116109, HashLeafCell::hash_name("SaM"));
    }

    /// Regression test: `uppercase` used to check membership in the exclusive range
    /// `b'a'..b'z'`, which never matches `b'z'` (0x7A) — a name's case-insensitive hash would
    /// differ depending on whether it ended in a lowercase or uppercase `Z`, breaking HashLeaf
    /// lookups for any subkey name containing a lowercase `z`.
    #[test]
    fn uppercase_covers_lowercase_z() {
        assert_eq!(b'Z' as u32, HashLeafCell::uppercase(b'z'));
        assert_eq!(HashLeafCell::hash_name("BUZZ"), HashLeafCell::hash_name("buzz"));
    }

    // --- test helpers --------------------------------------------------------------------

    /// Builds a full REGF cell buffer (4-byte size prefix + `content`, where `content` starts
    /// with the 2-byte signature) the way it appears inside a hive bin, for feeding into
    /// `read_cell`/`peek_cell`.
    fn wrap_cell(content: &[u8]) -> Vec<u8> {
        let total_len = 4 + content.len();
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(&(-(total_len as i32)).to_le_bytes());
        buf.extend_from_slice(content);
        buf
    }

    /// Builds a full 76-byte `KeyNodeCell` header (all-zero except signature/flags/name
    /// length) followed by the encoded key name, matching what `read_key_node_cell` expects.
    fn build_key_node_bytes(key_name: &str, ascii_name: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(KEY_NODE_SIGNATURE);
        let flags: u16 = if ascii_name { KEY_COMP_NAME_FLAG } else { 0 };
        buf.extend_from_slice(&flags.to_le_bytes()); // flags
        buf.extend_from_slice(&0u64.to_le_bytes()); // last_written_timestamp
        buf.extend_from_slice(&0u32.to_le_bytes()); // access_bits
        buf.extend_from_slice(&0u32.to_le_bytes()); // parent
        buf.extend_from_slice(&0u32.to_le_bytes()); // number_subkeys
        buf.extend_from_slice(&0u32.to_le_bytes()); // number_volatile_subkeys
        buf.extend_from_slice(&0u32.to_le_bytes()); // subkeys_list_offset
        buf.extend_from_slice(&0u32.to_le_bytes()); // volatile_subkeys_list_offset
        buf.extend_from_slice(&0u32.to_le_bytes()); // number_key_values
        buf.extend_from_slice(&0u32.to_le_bytes()); // key_values_list_offset
        buf.extend_from_slice(&0u32.to_le_bytes()); // key_security_offset
        buf.extend_from_slice(&0u32.to_le_bytes()); // class_name_offset
        buf.extend_from_slice(&0u32.to_le_bytes()); // largest_subkey_class_name_length
        buf.extend_from_slice(&0u16.to_le_bytes()); // largest_subkey_name_length
        buf.push(0); // virt_and_user_flags
        buf.push(0); // debug
        buf.extend_from_slice(&0u32.to_le_bytes()); // largest_value_name_length
        buf.extend_from_slice(&0u32.to_le_bytes()); // largest_value_data_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // work_var
        let name_bytes: Vec<u8> = if ascii_name {
            key_name.as_bytes().to_vec()
        } else {
            key_name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
        };
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // key_name_length
        buf.extend_from_slice(&0u16.to_le_bytes()); // class_name_length
        buf.extend_from_slice(&name_bytes);
        assert_eq!(76, buf.len() - name_bytes.len());
        buf
    }

    /// Builds a full 20-byte `KeyValueCell` header followed by the value name.
    fn build_key_value_bytes(value_name: &str, ascii_name: bool) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(KEY_VALUE_SIGNATURE);
        let name_bytes: Vec<u8> = if ascii_name {
            value_name.as_bytes().to_vec()
        } else {
            value_name.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
        };
        buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // name_length
        buf.extend_from_slice(&4u32.to_le_bytes()); // data_size
        buf.extend_from_slice(&0x1000u32.to_le_bytes()); // data_offset
        buf.extend_from_slice(&DATA_TYPE_REG_DWORD_TEST.to_le_bytes()); // data_type
        let flags: u16 = if ascii_name { VALUE_COMP_NAME_FLAG } else { 0 };
        buf.extend_from_slice(&flags.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // spare
        assert_eq!(20, buf.len());
        buf.extend_from_slice(&name_bytes);
        buf
    }
    const DATA_TYPE_REG_DWORD_TEST: u32 = 4;

    /// Builds a full 20-byte `KeySecurityCell` header followed by `sec_desc`.
    fn build_key_security_bytes(sec_desc: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(KEY_SECURITY_SIGNATURE);
        buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
        buf.extend_from_slice(&0u32.to_le_bytes()); // flink
        buf.extend_from_slice(&0u32.to_le_bytes()); // blink
        buf.extend_from_slice(&0u32.to_le_bytes()); // ref_count
        buf.extend_from_slice(&(sec_desc.len() as u32).to_le_bytes()); // sec_desc_size
        assert_eq!(20, buf.len());
        buf.extend_from_slice(sec_desc);
        buf
    }

    fn invalid_cell(content: &[u8]) -> InvalidCell {
        InvalidCell {
            offset: 0,
            content: content.to_vec(),
        }
    }

    // --- read_key_node_cell ----------------------------------------------------------------

    #[test]
    fn read_key_node_cell_rejects_too_small_buffer() {
        assert!(read_key_node_cell(&[0u8; 10], 0).is_err());
    }

    #[test]
    fn read_key_node_cell_rejects_wrong_signature() {
        let mut buf = build_key_node_bytes("Foo", true);
        buf[0] = b'x';
        assert!(read_key_node_cell(&buf, 0).is_err());
    }

    #[test]
    fn read_key_node_cell_rejects_name_length_overflowing_buffer() {
        let mut buf = build_key_node_bytes("Foo", true);
        buf.truncate(76); // drop the actual name bytes but keep key_name_length=3
        assert!(read_key_node_cell(&buf, 0).is_err());
    }

    #[test]
    fn read_key_node_cell_decodes_ascii_compressed_name() {
        let buf = build_key_node_bytes("SAM", true);
        let cell = read_key_node_cell(&buf, 42).unwrap();
        assert_eq!("SAM", cell.key_name);
        assert_eq!(42, cell.offset);
        assert_eq!(KEY_COMP_NAME_FLAG, cell.flags);
    }

    #[test]
    fn read_key_node_cell_decodes_utf16_name() {
        let buf = build_key_node_bytes("Ñandú", false);
        let cell = read_key_node_cell(&buf, 7).unwrap();
        assert_eq!("Ñandú", cell.key_name);
        assert_eq!(7, cell.offset);
    }

    // --- read_key_value_cell ---------------------------------------------------------------

    #[test]
    fn read_key_value_cell_rejects_too_small_buffer() {
        assert!(read_key_value_cell(&[0u8; 5], 0).is_err());
    }

    #[test]
    fn read_key_value_cell_rejects_wrong_signature() {
        let mut buf = build_key_value_bytes("Foo", true);
        buf[0] = b'x';
        assert!(read_key_value_cell(&buf, 0).is_err());
    }

    #[test]
    fn read_key_value_cell_rejects_name_length_overflowing_buffer() {
        let mut buf = build_key_value_bytes("Foo", true);
        buf.truncate(20);
        assert!(read_key_value_cell(&buf, 0).is_err());
    }

    #[test]
    fn read_key_value_cell_decodes_ascii_compressed_name() {
        let buf = build_key_value_bytes("Version", true);
        let cell = read_key_value_cell(&buf, 3).unwrap();
        assert_eq!("Version", cell.value_name);
        assert_eq!(3, cell.offset);
        assert_eq!(4, cell.data_size);
        assert_eq!(0x1000, cell.data_offset);
    }

    #[test]
    fn read_key_value_cell_decodes_utf16_name() {
        let buf = build_key_value_bytes("Versión", false);
        let cell = read_key_value_cell(&buf, 3).unwrap();
        assert_eq!("Versión", cell.value_name);
    }

    // --- read_key_security_cell -------------------------------------------------------------

    #[test]
    fn read_key_security_cell_rejects_too_small_buffer() {
        assert!(read_key_security_cell(&[0u8; 5], 0).is_err());
    }

    #[test]
    fn read_key_security_cell_rejects_wrong_signature() {
        let mut buf = build_key_security_bytes(&[1, 2, 3]);
        buf[0] = b'x';
        assert!(read_key_security_cell(&buf, 0).is_err());
    }

    #[test]
    fn read_key_security_cell_rejects_sec_desc_size_overflowing_buffer() {
        let mut buf = build_key_security_bytes(&[1, 2, 3]);
        buf.truncate(20); // header claims 3 bytes of sec_desc but none are present
        assert!(read_key_security_cell(&buf, 0).is_err());
    }

    #[test]
    fn read_key_security_cell_decodes_sec_desc() {
        let buf = build_key_security_bytes(&[0xAA, 0xBB, 0xCC]);
        let cell = read_key_security_cell(&buf, 9).unwrap();
        assert_eq!(vec![0xAA, 0xBB, 0xCC], cell.sec_desc);
        assert_eq!(9, cell.offset);
    }

    // --- read_cell dispatch -----------------------------------------------------------------

    #[test]
    fn read_cell_rejects_too_small_buffer() {
        assert!(read_cell(&[0u8; 4], 0).is_err());
    }

    #[test]
    fn read_cell_treats_positive_length_as_unallocated() {
        let mut buf = 8i32.to_le_bytes().to_vec();
        buf.extend_from_slice(&[0, 0]);
        match read_cell(&buf, 5).unwrap() {
            HiveCell::Unallocated(v) => assert_eq!(5, v.offset),
            other => panic!("expected Unallocated, got {:?}", other),
        }
    }

    #[test]
    fn read_cell_rejects_oversized_declared_length() {
        let mut buf = (-1000i32).to_le_bytes().to_vec();
        buf.extend_from_slice(b"nk");
        assert!(read_cell(&buf, 0).is_err());
    }

    #[test]
    fn read_cell_rejects_declared_length_smaller_than_prefix_without_panicking() {
        // A declared cell length of 1..3 bytes (absolute value) is smaller than the 4-byte
        // length prefix that encodes it — corrupt/adversarial input. Before this guard existed,
        // `read_cell` sliced `data[4..cell_len]` unconditionally and panicked here instead of
        // returning an error.
        for bad_len in [-1i32, -2, -3] {
            let mut buf = bad_len.to_le_bytes().to_vec();
            buf.extend_from_slice(b"nk");
            assert!(
                read_cell(&buf, 0).is_err(),
                "declared length {bad_len} should error, not panic"
            );
        }
    }

    #[test]
    fn read_cell_wraps_unknown_signature_as_invalid() {
        let content = vec![0xFF, 0xFE, 0x01, 0x02, 0x03, 0x04];
        let buf = wrap_cell(&content);
        match read_cell(&buf, 0).unwrap() {
            HiveCell::Invalid(v) => assert_eq!(content, v.content),
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    #[test]
    fn read_cell_dispatches_index_leaf() {
        let buf = wrap_cell(&[b'l', b'i', 0, 0]);
        assert!(matches!(read_cell(&buf, 0).unwrap(), HiveCell::IndexLeaf(_)));
    }

    #[test]
    fn read_cell_dispatches_fast_leaf() {
        let buf = wrap_cell(&[b'l', b'f', 0, 0]);
        assert!(matches!(read_cell(&buf, 0).unwrap(), HiveCell::FastLeaf(_)));
    }

    #[test]
    fn read_cell_dispatches_hash_leaf() {
        let buf = wrap_cell(&[b'l', b'h', 0, 0]);
        assert!(matches!(read_cell(&buf, 0).unwrap(), HiveCell::HashLeaf(_)));
    }

    #[test]
    fn read_cell_dispatches_index_root() {
        let buf = wrap_cell(&[b'r', b'i', 0, 0]);
        assert!(matches!(read_cell(&buf, 0).unwrap(), HiveCell::IndexRoot(_)));
    }

    #[test]
    fn read_cell_dispatches_key_node() {
        let buf = wrap_cell(&build_key_node_bytes("", true));
        assert!(matches!(read_cell(&buf, 0).unwrap(), HiveCell::KeyNode(_)));
    }

    #[test]
    fn read_cell_dispatches_key_value() {
        let buf = wrap_cell(&build_key_value_bytes("", true));
        assert!(matches!(read_cell(&buf, 0).unwrap(), HiveCell::KeyValue(_)));
    }

    #[test]
    fn read_cell_dispatches_key_security() {
        let buf = wrap_cell(&build_key_security_bytes(&[]));
        assert!(matches!(read_cell(&buf, 0).unwrap(), HiveCell::KeySecurity(_)));
    }

    // --- peek_cell --------------------------------------------------------------------------

    #[test]
    fn peek_cell_returns_zero_for_too_small_buffer() {
        assert_eq!(0, peek_cell(&[1, 2, 3]));
    }

    #[test]
    fn peek_cell_returns_absolute_value_of_negative_length() {
        assert_eq!(16, peek_cell(&(-16i32).to_le_bytes()));
    }

    // --- InvalidCell conversion helpers ------------------------------------------------------

    #[test]
    fn into_reg_sz_ascii_stops_at_first_null_terminator() {
        let cell = invalid_cell(b"Hello\0\0\0");
        assert_eq!("Hello", cell.into_reg_sz_ascii());
    }

    #[test]
    fn into_reg_sz_ascii_handles_empty_and_all_zero_content() {
        assert_eq!("", invalid_cell(&[]).into_reg_sz_ascii());
        assert_eq!("", invalid_cell(&[0, 0, 0]).into_reg_sz_ascii());
    }

    #[test]
    fn into_reg_sz_ascii_uses_full_length_when_no_terminator() {
        let cell = invalid_cell(b"NoTerminator");
        assert_eq!("NoTerminator", cell.into_reg_sz_ascii());
    }

    fn utf16_bytes_with_nulls(s: &str, trailing_nulls: usize) -> Vec<u8> {
        let mut v: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        for _ in 0..trailing_nulls {
            v.extend_from_slice(&0u16.to_le_bytes());
        }
        v
    }

    #[test]
    fn into_reg_sz_extended_decodes_even_length_utf16() {
        let cell = invalid_cell(&utf16_bytes_with_nulls("Hello", 1));
        assert_eq!("Hello", cell.into_reg_sz_extended());
    }

    #[test]
    fn into_reg_sz_extended_drops_trailing_odd_byte_without_panicking() {
        let mut content = utf16_bytes_with_nulls("Hi", 1);
        content.push(0xAA); // stray trailing byte, not a full u16
        let cell = invalid_cell(&content);
        assert_eq!("Hi", cell.into_reg_sz_extended());
    }

    #[test]
    fn into_reg_sz_extended_handles_empty_and_all_zero_content() {
        assert_eq!("", invalid_cell(&[]).into_reg_sz_extended());
        assert_eq!("", invalid_cell(&[0, 0, 0, 0]).into_reg_sz_extended());
    }

    #[test]
    fn into_reg_sz_extended_handles_multiple_trailing_nulls() {
        let cell = invalid_cell(&utf16_bytes_with_nulls("Hi", 3));
        assert_eq!("Hi", cell.into_reg_sz_extended());
    }

    #[test]
    fn into_dword_variants_decode_correct_length_content() {
        assert_eq!(
            0x04030201,
            invalid_cell(&[0x01, 0x02, 0x03, 0x04]).into_dword_le().unwrap()
        );
        assert_eq!(
            0x01020304,
            invalid_cell(&[0x01, 0x02, 0x03, 0x04]).into_dword_be().unwrap()
        );
    }

    /// Regression test: a truncated/oversized resident DWORD used to silently decode as `0` — a
    /// fabricated value indistinguishable from a genuine `DWORD:0` in a case report. It must
    /// error instead.
    #[test]
    fn into_dword_variants_error_for_wrong_length() {
        assert!(invalid_cell(&[]).into_dword().is_err());
        assert!(invalid_cell(&[1, 2, 3]).into_dword().is_err());
        assert!(invalid_cell(&[1, 2, 3, 4, 5]).into_dword().is_err());
        assert!(invalid_cell(&[1, 2, 3]).into_dword_le().is_err());
        assert!(invalid_cell(&[1, 2, 3]).into_dword_be().is_err());
    }

    #[test]
    fn into_qword_le_decodes_correct_length_content() {
        let cell = invalid_cell(&[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, cell.into_qword_le().unwrap());
    }

    #[test]
    fn into_qword_le_errors_for_wrong_length() {
        assert!(invalid_cell(&[]).into_qword_le().is_err());
        assert!(invalid_cell(&[1, 2, 3, 4, 5, 6, 7]).into_qword_le().is_err());
        assert!(invalid_cell(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).into_qword_le().is_err());
    }
}
