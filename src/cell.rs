use forensic_rs::prelude::ForensicResult;
pub const INDEX_LEAF_SIGNATURE : &'static [u8; 2] = b"li";
pub const FAST_LEAF_SIGNATURE : &'static [u8; 2] = b"lf";
pub const HASH_LEAF_SIGNATURE : &'static [u8; 2] = b"lh";
pub const INDEX_ROOT_SIGNATURE : &'static [u8; 2] = b"ri";
pub const KEY_NODE_SIGNATURE : &'static [u8; 2] = b"nk";
pub const KEY_SECURITY_SIGNATURE : &'static [u8; 2] = b"sk";
pub const KEY_VALUE_SIGNATURE : &'static [u8; 2] = b"vk";

/// Is volatile (not used, a key node on a disk isn't expected to have this flag set)
pub const KEY_VOLATILE_FLAG : u16 = 0x0001;
/// Is the mount point of another hive (a key node on a disk isn't expected to have this flag set)
pub const KEY_HIVE_EXIT_FLAG : u16 = 0x0002;
/// Is the root key for this hive
pub const KEY_HIVE_ENTRY_FLAG : u16 = 0x0004;
/// This key can't be deleted
pub const KEY_NO_DELETE_FLAG : u16 = 0x0008;
/// This key is a symlink (a target key is specified as a UTF-16LE string (REG_LINK) in a value named "SymbolicLinkValue", example: \REGISTRY\MACHINE\SOFTWARE\Classes\Wow6432Node)
pub const KEY_SYM_LINK_FLAG : u16 = 0x0010;
/// Key name is an ASCII string, possibly an extended ASCII string (otherwise it is a UTF-16LE string)
pub const KEY_COMP_NAME_FLAG : u16 = 0x0020;
/// Is a predefined handle (a handle is stored in the Number of key values field)
pub const KEY_PREDEF_HANDLE_FLAG : u16 = 0x0040;

/// Value name is an ASCII string, possibly an extended ASCII string (otherwise it is a UTF-16LE string)
pub const VALUE_COMP_NAME_FLAG : u16 = 0x0001;
/// Is a tombstone value (the flag is used starting from Insider Preview builds of Windows 10 "Redstone 1"), a tombstone value also has the Data type field set to REG_NONE, the Data size field set to 0, and the Data offset field set to 0xFFFFFFFF
pub const VALUE_IS_TOMBSTONE : u16 = 0x0002;

#[derive(Debug)]
pub enum HiveCell {
    IndexLeaf(IndexLeafCell),
    FastLeaf(FastLeafCell),
    HashLeaf(HashLeafCell),
    IndexRoot(IndexRootCell),
    KeyNode(KeyNodeCell),
    KeyValue(KeyValueCell),
    KeySecurity(KeySecurityCell),
    BigData(BigDataCell),
    #[cfg(feature="carving")]
    /// Used only for carving data in registry cells
    Invalid(Vec<u8>)
}
#[derive(Debug)]
pub struct IndexLeafCell {
    /// List of offsets of the key node elements in bytes relative from the start of the hive bins data
    pub elements : Vec<IndexLeafListElements>
}
#[derive(Debug)]
pub struct IndexLeafListElements {
    /// Key node element offset in bytes relative from the start of the hive bins data
    pub offset : u32
}
#[derive(Debug)]
pub struct FastLeafCell {
    pub elements : Vec<FastLeafListElements>
}
#[derive(Debug)]
pub struct FastLeafListElements {
    /// Key node offset: In bytes, relative from the start of the hive bins data
    pub offset : u32,
    /// The first 4 ASCII characters of a key name string (used to speed up lookups)
    pub name_hint : [u8; 4]
}
#[derive(Debug)]
pub struct HashLeafCell {
    pub elements : Vec<HashLeafListElements>
}
#[derive(Debug)]
pub struct HashLeafListElements {
    /// Key node offset: In bytes, relative from the start of the hive bins data
    pub offset : u32,
    /// The first 4 ASCII characters of a key name string (used to speed up lookups)
    pub name_hint : [u8; 4]
}

/// An Index root can't point to another Index root.
/// A subkeys list can't point to an Index root.
/// List elements within subkeys lists referenced by a single Index root must be sorted as a whole.
#[derive(Debug)]
pub struct IndexRootCell {
    pub elements : Vec<IndexRootSubkeyOffset>
}
#[derive(Debug)]
pub struct IndexRootSubkeyOffset {
    /// Subkeys list offset: In bytes, relative from the start of the hive bins data
    pub subkeys_list_offset : u32,
}

#[derive(Debug)]
pub struct KeyNodeCell {
    /// Flags. Bit mask, see below
    pub flags : u16,
    /// Last written timestamp. FILETIME (UTC)
    pub last_written_timestamp : u64,
    /// Access bits. Bit mask, see below (this field is used as of Windows 8 and Windows Server 2012; in previous versions of Windows, this field is reserved and called Spare)
    pub access_bits : u32,
    /// Parent. Offset of a parent key node in bytes, relative from the start of the hive bins data (this field has no meaning on a disk for a root key node)
    pub parent : u32,
    /// Number of subkeys
    pub number_subkeys : u32,
    /// Number of volatile subkeys
    pub number_volatile_subkeys : u32,
    /// Subkeys list offset. In bytes, relative from the start of the hive bins data (also, this field may point to an Index root)
    pub subkeys_list_offset : u32,
    /// Volatile subkeys list offset. This field has no meaning on a disk (volatile keys are not written to a file)
    pub volatile_subkeys_list_offset : u32,
    /// Number of key values
    pub number_key_values : u32,
    /// Key values list offset. In bytes, relative from the start of the hive bins data
    pub key_values_list_offset : u32,
    /// Key security offset. In bytes, relative from the start of the hive bins data
    pub key_security_offset : u32,
    /// Class name offset. n bytes, relative from the start of the hive bins data
    pub class_name_offset : u32,
    /// Largest subkey class name length. In bytes
    pub largest_subkey_class_name_length : u32,
    /// Largest subkey name length. In bytes, a subkey name is treated as a UTF-16LE string.
    /// Starting from Windows Vista, Windows Server 2003 SP2, and Windows XP SP3, the Largest subkey name length field has been split into 4 bit fields
    pub largest_subkey_name_length : u16,
    /// Virtualization control flags and User flags (Wow64 flags)
    pub virt_and_user_flags : u8,
    /// Enabling Breakpoints for Registry Keys using the CmpRegDebugBreakEnabled kernel variable
    pub debug : u8,
    /// Largest value name length. In bytes, a value name is treated as a UTF-16LE string
    pub largest_value_name_length : u32,
    /// Largest value data size. In bytes
    pub largest_value_data_size : u32,
    /// WorkVar. Cached index
    pub work_var : u32,
    /// Key name length. In bytes
    pub key_name_length : u16,
    /// Class name length. In bytes
    pub class_name_length : u16,
    /// ASCII (extended) string or UTF-16LE string
    pub key_name : String
}

#[repr(C,packed)]
pub struct KeyNodeCellPacked {
    /// Signature "nk". ASCII string
    pub signature : u16,
    /// Flags. Bit mask, see below
    pub flags : u16,
    /// Last written timestamp. FILETIME (UTC)
    pub last_written_timestamp : u64,
    /// Access bits. Bit mask, see below (this field is used as of Windows 8 and Windows Server 2012; in previous versions of Windows, this field is reserved and called Spare)
    pub access_bits : u32,
    /// Parent. Offset of a parent key node in bytes, relative from the start of the hive bins data (this field has no meaning on a disk for a root key node)
    pub parent : u32,
    /// Number of subkeys
    pub number_subkeys : u32,
    /// Number of volatile subkeys
    pub number_volatile_subkeys : u32,
    /// Subkeys list offset. In bytes, relative from the start of the hive bins data (also, this field may point to an Index root)
    pub subkeys_list_offset : u32,
    /// Volatile subkeys list offset. This field has no meaning on a disk (volatile keys are not written to a file)
    pub volatile_subkeys_list_offset : u32,
    /// Number of key values
    pub number_key_values : u32,
    /// Key values list offset. In bytes, relative from the start of the hive bins data
    pub key_values_list_offset : u32,
    /// Key security offset. In bytes, relative from the start of the hive bins data
    pub key_security_offset : u32,
    /// Class name offset. n bytes, relative from the start of the hive bins data
    pub class_name_offset : u32,
    /// Largest subkey class name length. In bytes
    pub largest_subkey_class_name_length : u32,
    /// Largest subkey name length. In bytes, a subkey name is treated as a UTF-16LE string.
    /// Starting from Windows Vista, Windows Server 2003 SP2, and Windows XP SP3, the Largest subkey name length field has been split into 4 bit fields
    pub largest_subkey_name_length : u16,
    /// Virtualization control flags and User flags (Wow64 flags)
    pub virt_and_user_flags : u8,
    /// Enabling Breakpoints for Registry Keys using the CmpRegDebugBreakEnabled kernel variable
    pub debug : u8,
    /// Largest value name length. In bytes, a value name is treated as a UTF-16LE string
    pub largest_value_name_length : u32,
    /// Largest value data size. In bytes
    pub largest_value_data_size : u32,
    /// WorkVar. Cached index
    pub work_var : u32,
    /// Key name length. In bytes
    pub key_name_length : u16,
    /// Class name length. In bytes
    pub class_name_length : u16,
}
#[derive(Debug)]
pub struct KeyValueCell {
    pub name_length : u16,
    pub data_size : u32,
    pub data_offset : u32,
    pub data_type: u32,
    pub flags : u16,
    pub value_name : String,
}
#[repr(C, packed)]
pub struct KeyValueCellPacked {
    pub signature : u16,
    pub name_length : u16,
    pub data_size : u32,
    pub data_offset : u32,
    pub data_type: u32,
    pub flags : u16,
    pub spare : u16,
}
#[derive(Debug)]
pub struct KeySecurityCell {
    pub flink : u32,
    pub blink : u32,
    pub ref_count : u32,
    pub sec_desc_size : u32,
    pub sec_desc : Vec<u8>
}
#[repr(C, packed)]
pub struct KeySecurityCellPacked{
    pub signature : u16,
    pub reserved : u16,
    pub flink : u32,
    pub blink : u32,
    pub ref_count : u32,
    pub sec_desc_size : u32
}
#[derive(Debug)]
pub struct BigDataCell {

}

pub fn read_cell(data : &[u8]) -> ForensicResult<HiveCell> {
    let signature = &data[0..2];
    let cell = if signature == INDEX_LEAF_SIGNATURE {
        let cell = read_index_leaf_cell(data)?;
        HiveCell::IndexLeaf(cell)
    }else if signature == FAST_LEAF_SIGNATURE {
        let cell = read_fast_leaf_cell(data)?;
        HiveCell::FastLeaf(cell)
    }else if signature == HASH_LEAF_SIGNATURE {
        let cell = read_hash_leaf_cell(data)?;
        HiveCell::HashLeaf(cell)
    }else if signature == INDEX_ROOT_SIGNATURE {
        let cell = read_index_root_cell(data)?;
        HiveCell::IndexRoot(cell)
    }else if signature == KEY_NODE_SIGNATURE {
        let cell = read_key_node_cell(data)?;
        HiveCell::KeyNode(cell)
    }else if signature == KEY_SECURITY_SIGNATURE {
        let cell = read_key_security_cell(data)?;
        HiveCell::KeySecurity(cell)
    }else if signature == KEY_VALUE_SIGNATURE {
        let cell = read_key_value_cell(data)?;
        HiveCell::KeyValue(cell)
    }else {
        #[cfg(feature="carving")]
        return Ok(HiveCell::Invalid(Vec::from(data)));
        #[cfg(not(feature="carving"))]
        return Err(forensic_rs::prelude::ForensicError::Other(format!("Invalid format signature: {}", String::from_utf8_lossy(signature))));
    };
    Ok(cell)
}

pub fn read_index_leaf_cell(data :&[u8]) -> ForensicResult<IndexLeafCell> {
    let signature = &data[0..2];
    if signature != INDEX_LEAF_SIGNATURE {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let n_elements = u16::from_ne_bytes(data[2..4].try_into().unwrap_or_default());
    let total_size_elements = (n_elements as usize) * 4 + 4;
    if total_size_elements > data.len() {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let mut offset_list = Vec::with_capacity(n_elements.into());
    for i in (4..(4 + 4*n_elements as usize)).step_by(4) {
        let offset = u32::from_ne_bytes(data[i..i + 4].try_into().unwrap_or_default());
        offset_list.push(IndexLeafListElements {offset});
    }
    Ok(IndexLeafCell { elements: offset_list })
}

pub fn read_fast_leaf_cell(data :&[u8]) -> ForensicResult<FastLeafCell> {
    let signature = &data[0..2];
    if signature != FAST_LEAF_SIGNATURE {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let n_elements = u16::from_ne_bytes(data[2..4].try_into().unwrap_or_default());
    let total_size_elements = (n_elements as usize) * 8 + 4;
    if total_size_elements > data.len() {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let mut offset_list = Vec::with_capacity(n_elements.into());
    for i in (4..(4 + 8*n_elements as usize)).step_by(8) {
        let offset = u32::from_ne_bytes(data[i..i + 4].try_into().unwrap_or_default());
        offset_list.push(FastLeafListElements {offset, name_hint : [data[i], data[i + 1], data[i + 2], data[i + 3]]});
    }
    Ok(FastLeafCell { elements: offset_list })
}

pub fn read_hash_leaf_cell(data :&[u8]) -> ForensicResult<HashLeafCell> {
    let signature = &data[0..2];
    if signature != HASH_LEAF_SIGNATURE {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let n_elements = u16::from_ne_bytes(data[2..4].try_into().unwrap_or_default());
    let total_size_elements = (n_elements as usize) * 8 + 4;
    if total_size_elements > data.len() {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let mut offset_list = Vec::with_capacity(n_elements.into());
    for i in (4..total_size_elements).step_by(8) {
        let offset = u32::from_ne_bytes(data[i..i + 4].try_into().unwrap_or_default());
        offset_list.push(HashLeafListElements {offset, name_hint : [data[i + 4], data[i + 5], data[i + 6], data[i + 7]]});
    }
    Ok(HashLeafCell { elements: offset_list })
}

pub fn read_index_root_cell(data :&[u8]) -> ForensicResult<IndexRootCell> {
    let signature = &data[0..2];
    if signature != INDEX_ROOT_SIGNATURE {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let n_elements = u16::from_ne_bytes(data[2..4].try_into().unwrap_or_default());
    let total_size_elements = (n_elements as usize) * 8 + 4;
    if total_size_elements > data.len() {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let mut offset_list = Vec::with_capacity(n_elements.into());
    for i in (4..(4 + 4*n_elements as usize)).step_by(4) {
        let offset = u32::from_ne_bytes(data[i..i + 4].try_into().unwrap_or_default());
        offset_list.push(IndexRootSubkeyOffset { subkeys_list_offset : offset});
    }
    Ok(IndexRootCell { elements: offset_list })
}

pub fn read_key_node_cell(data :&[u8]) -> ForensicResult<KeyNodeCell> {
    let signature = &data[0..2];
    if signature != KEY_NODE_SIGNATURE {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let (head, body, tail) = unsafe { data[0..76].align_to::<KeyNodeCellPacked>() };
    if head.len() != 0 && tail.len() != 0{
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    let packed_cell = &body[0];
    let mut cell: KeyNodeCell = packed_cell.into();
    if 76 + cell.key_name_length as usize > data.len() {
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    cell.key_name = if cell.flags & KEY_COMP_NAME_FLAG == 0 {
        let mut arr = Vec::with_capacity(cell.key_name_length as usize);
        for i in (76..76 + (cell.key_name_length as usize)).step_by(2) {
            arr.push(u16::from_ne_bytes([data[i], data[i + 1]]));
        }
        String::from_utf16_lossy(&arr).to_string()
    }else {
        String::from_utf8_lossy(&data[76..76 + (cell.key_name_length as usize)]).to_string()
    };
    Ok(cell)
}

pub fn read_key_security_cell(data :&[u8]) -> ForensicResult<KeySecurityCell> {
    let signature = &data[0..2];
    if signature != KEY_SECURITY_SIGNATURE {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let (head, body, tail) = unsafe { data[0..76].align_to::<KeySecurityCellPacked>() };
    if head.len() != 0 && tail.len() != 0{
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    let packed_cell = &body[0];
    let mut cell: KeySecurityCell = packed_cell.into();
    let sec_end_pos = 20 + cell.sec_desc_size as usize;
    if sec_end_pos > data.len() {
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    for i in 20..sec_end_pos {
        cell.sec_desc.push(data[i]);
    }
    Ok(cell)
}

pub fn read_key_value_cell(data :&[u8]) -> ForensicResult<KeyValueCell> {
    let signature = &data[0..2];
    if signature != KEY_VALUE_SIGNATURE {
        return Err(forensic_rs::prelude::ForensicError::BadFormat)
    }
    let (head, body, tail) = unsafe { data[0..20].align_to::<KeyValueCellPacked>() };
    if head.len() != 0 && tail.len() != 0{
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    let packed_cell = &body[0];
    let mut cell: KeyValueCell = packed_cell.into();
    let value_name_end = 20 + cell.name_length as usize;
    if value_name_end > data.len() {
        return Err(forensic_rs::prelude::ForensicError::BadFormat);
    }
    if cell.name_length != 0 {
        cell.value_name = if cell.flags & VALUE_COMP_NAME_FLAG == 0 {
            let mut arr = Vec::with_capacity(cell.name_length as usize);
            for i in (20..20 + (cell.name_length as usize)).step_by(2) {
                arr.push(u16::from_ne_bytes([data[i], data[i + 1]]));
            }
            String::from_utf16_lossy(&arr).to_string()
        }else {
            String::from_utf8_lossy(&data[20..20 + (cell.name_length as usize)]).to_string()
        };
    }
    Ok(cell)
}

impl From<KeyNodeCellPacked> for KeyNodeCell {
    fn from(v: KeyNodeCellPacked) -> Self {
        KeyNodeCell {
            flags: v.flags,
            last_written_timestamp: v.last_written_timestamp,
            access_bits: v.access_bits,
            parent: v.parent,
            number_subkeys: v.number_subkeys,
            number_volatile_subkeys: v.number_volatile_subkeys,
            subkeys_list_offset: v.subkeys_list_offset,
            volatile_subkeys_list_offset: v.volatile_subkeys_list_offset,
            number_key_values: v.number_key_values,
            key_values_list_offset: v.key_values_list_offset,
            key_security_offset: v.key_security_offset,
            class_name_offset: v.class_name_offset,
            largest_subkey_class_name_length: v.largest_subkey_class_name_length,
            largest_subkey_name_length: v.largest_subkey_name_length,
            debug : v.debug,
            virt_and_user_flags : v.virt_and_user_flags,
            largest_value_name_length: v.largest_value_name_length,
            largest_value_data_size: v.largest_value_data_size,
            work_var: v.work_var,
            key_name_length: v.key_name_length,
            class_name_length: v.class_name_length,
            key_name: String::new(),
        }
    }
}
impl From<&KeyNodeCellPacked> for KeyNodeCell {
    fn from(v: &KeyNodeCellPacked) -> Self {
        KeyNodeCell {
            flags: v.flags,
            last_written_timestamp: v.last_written_timestamp,
            access_bits: v.access_bits,
            parent: v.parent,
            number_subkeys: v.number_subkeys,
            number_volatile_subkeys: v.number_volatile_subkeys,
            subkeys_list_offset: v.subkeys_list_offset,
            volatile_subkeys_list_offset: v.volatile_subkeys_list_offset,
            number_key_values: v.number_key_values,
            key_values_list_offset: v.key_values_list_offset,
            key_security_offset: v.key_security_offset,
            class_name_offset: v.class_name_offset,
            largest_subkey_class_name_length: v.largest_subkey_class_name_length,
            largest_subkey_name_length: v.largest_subkey_name_length,
            debug : v.debug,
            virt_and_user_flags : v.virt_and_user_flags,
            largest_value_name_length: v.largest_value_name_length,
            largest_value_data_size: v.largest_value_data_size,
            work_var: v.work_var,
            key_name_length: v.key_name_length,
            class_name_length: v.class_name_length,
            key_name: String::new(),
        }
    }
}

impl From<KeySecurityCellPacked> for KeySecurityCell {
    fn from(v: KeySecurityCellPacked) -> Self {
        KeySecurityCell {
            blink : v.blink,
            flink : v.flink,
            ref_count :v.ref_count,
            sec_desc : Vec::with_capacity(v.sec_desc_size as usize),
            sec_desc_size : v.sec_desc_size
        }
    }
}
impl From<&KeySecurityCellPacked> for KeySecurityCell {
    fn from(v: &KeySecurityCellPacked) -> Self {
        KeySecurityCell {
            blink : v.blink,
            flink : v.flink,
            ref_count :v.ref_count,
            sec_desc : Vec::with_capacity(v.sec_desc_size as usize),
            sec_desc_size : v.sec_desc_size
        }
    }
}
impl From<KeyValueCellPacked> for KeyValueCell {
    fn from(v: KeyValueCellPacked) -> Self {
        Self {
            name_length: v.name_length,
            data_size: v.data_size,
            data_offset: v.data_offset,
            data_type: v.data_type,
            flags: v.flags,
            value_name: String::new()
        }
    }
}
impl From<&KeyValueCellPacked> for KeyValueCell {
    fn from(v: &KeyValueCellPacked) -> Self {
        Self {
            name_length: v.name_length,
            data_size: v.data_size,
            data_offset: v.data_offset,
            data_type: v.data_type,
            flags: v.flags,
            value_name: String::new()
        }
    }
}