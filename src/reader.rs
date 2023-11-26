use std::{cell::RefCell, collections::BTreeMap, path::{PathBuf, Path}, borrow::BorrowMut};

use forensic_rs::{
    prelude::{ForensicError, ForensicResult, RegHiveKey, RegValue, RegistryReader, HKLM},
    traits::vfs::{VirtualFile, VirtualFileSystem, VDirEntry}, notifications::{self, NotificationType}, notify_informational, notify_low, trace,
};

use crate::{
    cell::{read_cell, HashLeafCell, HiveCell, IndexRootCell, KeyNodeCell},
    cell_cache::CellCache,
    hive::{read_base_block, read_cells, read_hive_bin_at_file_position, BaseBlock, HiveBinHeader},
};

const HIVE_TYPE_NONE : u16 = 0;
const HIVE_TYPE_SAM : u16 = 1;
const HIVE_TYPE_SECURITY : u16 = 2;
const HIVE_TYPE_SOFTWARE : u16 = 3;
const HIVE_TYPE_SYSTEM : u16 = 4;
const HIVE_TYPE_CACHED : u16 = 5;
const HIVE_TYPE_USER : u16 = 6;

const DATA_TYPE_NONE : u32 = 0x0;
const DATA_TYPE_REG_SZ : u32 = 0x1;
const DATA_TYPE_REG_EXPAND_SZ : u32 = 0x2;
const DATA_TYPE_REG_BINARY : u32 = 0x03;
const DATA_TYPE_REG_DWORD : u32 = 0x04;
const DATA_TYPE_REG_DWORD_BE : u32 = 0x05;
const DATA_TYPE_REG_LINK : u32 = 0x06;
const DATA_TYPE_REG_MULTI_SZ : u32 = 0x07;
const DATA_TYPE_REG_RESOURCE_LIST : u32 = 0x08;
const DATA_TYPE_REG_FULL_RESOURCE_DESCRIPTOR : u32 = 0x09;
const DATA_TYPE_REG_RESOURCE_REQUIREMENTS_LIST : u32 = 0x0a;
const DATA_TYPE_REG_QWORD : u32 = 0xb;


pub struct HiveRegistryReader {
    /// HKEY_CURRENT_CONFIG: System, System.alt, System.log, System.sav
    current_config: Option<RefCell<HiveFiles>>,
    /// HKEY_USERS Default, Default.log, Default.sav Ntuser.dat, Ntuser.dat.log
    /// List with the name of the user and the Hive files
    users: Vec<(String, RefCell<HiveFiles>)>,
    /// HKEY_LOCAL_MACHINE\SAM 	Sam, Sam.log, Sam.sav
    sam: Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\Security 	Security, Security.log, Security.sav
    security: Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\Software 	Software, Software.log, Software.sav
    software: Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\System 	System, System.alt, System.log, System.sav
    system: Option<RefCell<HiveFiles>>,
    /// Mount reg files
    mounted: RefCell<MountedMap>,
    /// Associate a hkey with a path for the mounted registry keys
    cached_keys: RefCell<BTreeMap<isize, String>>,
    key_counter: RefCell<isize>,
}
/// Mapa: HiveKey - Key - Value
pub type MountedMap = BTreeMap<String, BTreeMap<String, BTreeMap<String, RegValue>>>;

fn missing_key() -> ForensicError {
    ForensicError::Missing
}

pub struct HiveReader {
    pub files: HiveFiles,
    pub opened_keys: BTreeMap<RegHiveKey, RegValue>,
}

impl HiveRegistryReader {
    pub fn from_fs(mut fs: Box<dyn VirtualFileSystem>,
    ) -> ForensicResult<Box<dyn RegistryReader>> {
        let mut reader = Self::new();
        let config_folder = std::path::Path::new("C\\Windows\\System32\\Config");
        if let Some(hive) = open_hive_with_logs(&mut fs, config_folder, "SYSTEM") {
            reader.set_system(hive);
        }
        if let Some(hive) = open_hive_with_logs(&mut fs, config_folder, "SOFTWARE") {
            reader.set_software(hive);
        }
        if let Some(hive) = open_hive_with_logs(&mut fs, config_folder, "SECURITY") {
            reader.set_security(hive);
        }
        if let Some(hive) = open_hive_with_logs(&mut fs, config_folder, "SAM") {
            reader.set_sam(hive);
        }
        match reader.load_user_hives(&mut fs) {
            Ok(_) => {},
            Err(e) => {
                notify_low!(NotificationType::Informational,"Error loading user hives: {:?}",e);
            }
        };
        Ok(Box::new(reader))
    }
    
    pub fn new() -> Self {
        Self {
            current_config: None,
            users: Vec::new(),
            sam: None,
            security: None,
            software: None,
            system: None,
            mounted: RefCell::new(BTreeMap::new()),
            cached_keys: RefCell::new(BTreeMap::new()),
            key_counter: RefCell::new(-1),
        }
    }

    /// This method loads from the 
    pub fn load_user_hives(&mut self, fs : &mut Box<dyn VirtualFileSystem>) -> ForensicResult<()> {
        let system_root = match self.get_system_root() {
            Ok(v) => v,
            Err(_) => {
                notify_low!(NotificationType::Informational, "Cannot find SystemRoot environment variable");
                r"C:\Windows".into()
            }
        };
        let user_names_key = self.open_key(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")?;
        let guid_list = self.enumerate_keys(user_names_key)?;

        for user_guid in &guid_list {
            let profile = self.open_key(user_names_key, user_guid)?;
            let profile_path : String = match self.read_value(profile, "ProfileImagePath") {
                Ok(v) => {
                    match v.try_into() {
                        Ok(v) => v,
                        Err(_) => {
                            notify_low!(NotificationType::DeletedArtifact, "ProfileImagePath for user {} is not a String value", user_guid);
                            continue
                        }
                    }
                },
                Err(_) => {
                    notify_low!(NotificationType::DeletedArtifact, "Cannot find ProfileImagePath for user {}", user_guid);
                    continue
                }
            };
            let profile_path = profile_path.replace(":\\", "\\");
            let profile_path = if profile_path.contains("%systemroot%") {
                profile_path.replace("%systemroot%", &system_root)
            }else {
                profile_path
            };
            let user_profile_path = std::path::Path::new(&profile_path);
            let hive = match open_hive_with_logs(fs, user_profile_path, "NTUSER.DAT") {
                Some(v) => v,
                None => {
                    notify_low!(NotificationType::DeletedArtifact, "Cannot find hive {}\\NTUSER.DAT for user {}",profile_path, user_guid);
                    continue
                }
            };
            self.add_user(&user_guid, hive);
        }
        Ok(())
    }

    pub fn set_sam(&mut self, hive: HiveFiles) {
        trace!("Loaded SAM hive");
        self.sam = Some(RefCell::new(hive));
    }
    pub fn set_security(&mut self, hive: HiveFiles) {
        trace!("Loaded Security hive");
        self.security = Some(RefCell::new(hive));
    }
    pub fn set_software(&mut self, hive: HiveFiles) {
        trace!("Loaded Software hive");
        self.software = Some(RefCell::new(hive));
    }
    pub fn set_system(&mut self, hive: HiveFiles) {
        trace!("Loaded System hive");
        self.system = Some(RefCell::new(hive));
    }
    pub fn set_current_config(&mut self, hive: HiveFiles) {
        self.current_config = Some(RefCell::new(hive));
    }
    pub fn add_user(&mut self, user: &str, hive: HiveFiles) {
        trace!("Added user {} hive", user);
        self.users.push((user.into(), RefCell::new(hive)));
    }
    pub fn add_reg_key(&mut self, path: &str, value: &str, data: RegValue) {
        let mut mounted = self.mounted.borrow_mut();
        let (hkey, path) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return,
        };
        let path_map = mounted.entry(hkey.into()).or_insert(BTreeMap::new());
        let value_map = path_map.entry(path.into()).or_insert(BTreeMap::new());
        value_map.insert(value.into(), data);
    }
    pub fn add_reg_file(&mut self, _data: String) {
        todo!()
    }

    fn next_key(&self) -> isize {
        let mut ret: isize = *self.key_counter.borrow();
        loop {
            let borrow = self.cached_keys.borrow();
            if !borrow.contains_key(&ret) {
                break;
            }
            ret = ret - 1;
            if ret == isize::MIN {
                ret = -1;
            }
        }

        self.key_counter.replace(ret - 1);
        ret
    }
}

pub enum SelectedHive {
    None,
    Sam(u64),
    Security(u64),
    Software(u64),
    System(u64),
    Mounted(u64),
    User((u16, u64)),
}

pub struct HiveFiles {
    pub(crate) location: PathBuf,
    pub(crate) primary: Box<dyn VirtualFile>,
    pub(crate) base_block: BaseBlock,
    pub(crate) root_cell: KeyNodeCell,
    pub(crate) logs: Vec<Box<dyn VirtualFile>>,
    pub(crate) cell_cache: CellCache,
    pub(crate) buffer: Vec<u8>,
}

impl HiveFiles {
    pub fn new(location: PathBuf, mut primary: Box<dyn VirtualFile>) -> ForensicResult<Self> {
        let base_block = read_base_block(&mut primary)?;
        primary.seek(std::io::SeekFrom::Start(4096))?;
        let (_hive_bin, data) = read_hive_bin_at_file_position(&mut primary)?;
        let cells = read_cells(&data, 32)?;
        let mut cell_cache = CellCache::new(2048);
        for cell in cells {
            cell_cache.insert_fixed(cell);
        }
        let key_node_cell = cell_cache
            .get(base_block.root_cell_offset as u64)
            .ok_or_else(missing_key)?;
        let root_cell = match key_node_cell {
            HiveCell::KeyNode(v) => v.clone(),
            _ => return Err(missing_key()),
        };
        Ok(Self {
            location,
            base_block,
            primary,
            root_cell,
            logs: Vec::with_capacity(8),
            cell_cache,
            buffer: vec![0u8; 4096],
        })
    }

    pub fn scan_hive(primary: &mut Box<dyn VirtualFile>) -> Vec<(u64, u64)> {
        vec![]
    }

    pub fn open_key_from_offset(&mut self, key_name : &str, offset : u64) -> ForensicResult<isize> {
        let mut path_separator = key_name.split(|v| v == '/' || v == '\\');
        let root_cell = match self.get_cell_at_offset(offset)? {
            HiveCell::KeyNode(kn) => kn,
            _ => return Err(ForensicError::Missing)
        };
        let subkeys_offset = root_cell.subkeys_list_offset;
        let n_subkeys = root_cell.number_subkeys;
        let n_key_val = root_cell.number_key_values;
        let first = match path_separator.next() {
            Some(v) => v,
            None => return Ok(32), // Root Cell
        };
        if n_subkeys == 0 {
            return Err(ForensicError::Missing);
        }
        let mut next_offset = subkeys_offset;
        let mut actual_path = first;
        'out: loop {
            match self.get_cell_at_offset(next_offset as u64)? {
                HiveCell::HashLeaf(hl) => {
                    let path_hash = HashLeafCell::hash_name(actual_path);
                    for el in &hl.elements {
                        if path_hash == el.name_hash {
                            next_offset = el.offset;
                            continue 'out;
                        }
                    }
                    return Err(missing_key());
                }
                HiveCell::KeyNode(kn) => {
                    if kn.key_name != actual_path {
                        return Err(missing_key());
                    }
                    match path_separator.next() {
                        Some(v) => {
                            actual_path = v;
                            next_offset = kn.subkeys_list_offset;
                        }
                        None => break,
                    }
                }
                HiveCell::KeyValue(kv) => {
                    unimplemented!();
                }
                _ => unimplemented!(),
            };
        }
        Ok(next_offset as isize)
    }
    pub fn open_key(&mut self, key_name: &str) -> ForensicResult<isize> {
        let mut path_separator = key_name.split(|v| v == '/' || v == '\\');
        let root_cell = self.get_root_cell()?;
        let subkeys_offset = root_cell.subkeys_list_offset;
        let n_subkeys = root_cell.number_subkeys;
        let first = match path_separator.next() {
            Some(v) => v,
            None => return Ok(32), // Root Cell
        };
        if first.is_empty() {
            return Ok(32)
        }
        if n_subkeys == 0 {
            return Err(ForensicError::Missing);
        }
        let mut next_offset = subkeys_offset;
        let mut actual_path = first;
        'out: loop {
            match self.get_cell_at_offset(next_offset as u64)? {
                HiveCell::HashLeaf(hl) => {
                    let path_hash = HashLeafCell::hash_name(actual_path);
                    for el in &hl.elements {
                        if path_hash == el.name_hash {
                            next_offset = el.offset;
                            continue 'out;
                        }
                    }
                    return Err(missing_key());
                }
                HiveCell::KeyNode(kn) => {
                    if kn.key_name != actual_path {
                        return Err(missing_key());
                    }
                    match path_separator.next() {
                        Some(v) => {
                            actual_path = v;
                            next_offset = kn.subkeys_list_offset;
                        }
                        None => break,
                    }
                }
                _ => unimplemented!(),
            };
        }
        Ok(next_offset as isize)
    }

    pub fn get_root_cell(&self) -> ForensicResult<&KeyNodeCell> {
        let cell = self.cell_cache.get(32).ok_or_else(missing_key)?;

        let kn = match cell {
            HiveCell::KeyNode(ir) => ir,
            _ => return Err(missing_key()),
        };
        if kn.key_name != "ROOT" {
            return Err(ForensicError::Other("Cannot find ROOT cell".into()));
        }
        Ok(kn)
    }
    pub fn get_cell_at_offset(&mut self, offset: u64) -> ForensicResult<&HiveCell> {
        if self.cell_cache.contains(offset) {
            return Ok(self.cell_cache.get(offset).unwrap());
        }
        self.primary.seek(std::io::SeekFrom::Start(
            self.hive_bins_data_offset() + offset,
        ))?;
        let readed = self.primary.read(&mut self.buffer)?;
        let cell = read_cell(&self.buffer[0..readed], offset)?;
        self.cell_cache.insert(cell);
        match self.cell_cache.get(offset) {
            Some(cell) => return Ok(cell),
            None => return Err(ForensicError::Missing),
        };
    }
    pub fn get_cell_or_native_at_offset(&mut self, offset: u64) -> ForensicResult<&HiveCell> {
        if self.cell_cache.contains(offset) {
            return Ok(self.cell_cache.get(offset).unwrap());
        }
        self.primary.seek(std::io::SeekFrom::Start(
            self.hive_bins_data_offset() + offset,
        ))?;
        let readed = self.primary.read(&mut self.buffer)?;
        let cell = read_cell(&self.buffer[0..readed], offset)?;
        self.cell_cache.insert(cell);
        match self.cell_cache.get(offset) {
            Some(cell) => return Ok(cell),
            None => return Err(ForensicError::Missing),
        };
    }

    fn hive_bins_data_offset(&self) -> u64 {
        4096
    }
}

impl RegistryReader for HiveRegistryReader {
    fn from_file(&self, _file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn RegistryReader>> {
        Err(ForensicError::BadFormat)
    }

    fn from_fs(
        &self,
        fs: Box<dyn forensic_rs::traits::vfs::VirtualFileSystem>,
    ) -> ForensicResult<Box<dyn RegistryReader>> {
        HiveRegistryReader::from_fs(fs)
    }

    fn open_key(&self, hkey: RegHiveKey, mut key_name: &str) -> ForensicResult<RegHiveKey> {
        match hkey {
            RegHiveKey::HkeyLocalMachine => {
                let mut path_separator = key_name.split(|v| v == '/' || v == '\\');
                let first_key = path_separator.next().ok_or_else(missing_key)?;
                let (hive, hive_type) = if first_key == "SAM" {
                    (self.sam.as_ref().ok_or_else(missing_key)?, HIVE_TYPE_SAM)
                } else if first_key == "SECURITY" {
                    (self.security.as_ref().ok_or_else(missing_key)?, HIVE_TYPE_SECURITY)
                } else if first_key == "SOFTWARE" {
                    key_name = &key_name[9..];
                    (self.software.as_ref().ok_or_else(missing_key)?, HIVE_TYPE_SOFTWARE)
                } else if first_key == "SYSTEM" {
                    (self.system.as_ref().ok_or_else(missing_key)?, HIVE_TYPE_SYSTEM)
                } else {
                    let h = match self.mounted.try_borrow() {
                        Ok(v) => v,
                        Err(e) => {
                            return Err(forensic_rs::prelude::ForensicError::Other(format!(
                                "Error reading user key: {:?}",
                                e
                            )))
                        }
                    };
                    let lm = h.get("HKEY_LOCAL_MACHINE").ok_or_else(missing_key)?;
                    let _path_values = lm.get(key_name).ok_or_else(missing_key)?;
                    let new_key = self.next_key();
                    let mut cached = self.cached_keys.borrow_mut();
                    cached.insert(new_key, format!("HKEY_LOCAL_MACHINE\\{}", key_name));
                    return Ok(RegHiveKey::Hkey(new_key));
                };
                let mut hive = match hive.try_borrow_mut() {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(forensic_rs::prelude::ForensicError::Other(format!(
                            "Error reading user key: {:?}",
                            e
                        )))
                    }
                };
                let hive_key = hive.open_key(key_name)?;
                Ok(RegHiveKey::Hkey(transform_key_with_type_i(hive_key, hive_type)))
            }
            RegHiveKey::HkeyUsers => {
                let (username, rest_of_path) = match key_name.split_once(|v| v == '/' || v == '\\') {
                    Some(v) => v,
                    None => (key_name, "")
                };
                let position = self.users.iter().position(|v| v.0 == username).ok_or_else(missing_key)?;
                let (_user_id, user_hive) = self.users.get(position).ok_or_else(missing_key)?;
                let mut hive = match user_hive.try_borrow_mut() {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(forensic_rs::prelude::ForensicError::Other(format!(
                            "Error reading user key: {:?}",
                            e
                        )))
                    }
                };
                trace!("Opening user key");
                let hive_key = hive.open_key(rest_of_path)?;
                Ok(user_hive_by_position(position as u16, hive_key))
            },
            RegHiveKey::Hkey(hkey) => {
                let (hive, offset, hive_type) = match select_hive_by_hkey(RegHiveKey::Hkey(hkey)) {
                    SelectedHive::None => return Err(missing_key()),
                    SelectedHive::Sam(offset) => (self.sam.as_ref().ok_or_else(missing_key)?, offset, HIVE_TYPE_SAM),
                    SelectedHive::Security(offset) => (self.security.as_ref().ok_or_else(missing_key)?, offset, HIVE_TYPE_SECURITY),
                    SelectedHive::Software(offset) => (self.software.as_ref().ok_or_else(missing_key)?, offset, HIVE_TYPE_SOFTWARE),
                    SelectedHive::System(offset) => (self.system.as_ref().ok_or_else(missing_key)?, offset, HIVE_TYPE_SYSTEM),
                    SelectedHive::Mounted(_) => todo!(),
                    SelectedHive::User((position, offset)) => {
                        let (_user_id, hive) = self.users.get(position as usize).ok_or_else(missing_key)?;
                        (hive, offset, HIVE_TYPE_USER)
                    },
                };
                let mut hive = match hive.try_borrow_mut() {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(forensic_rs::prelude::ForensicError::Other(format!(
                            "Error reading user key: {:?}",
                            e
                        )))
                    }
                };
                let hive_key = hive.open_key_from_offset(key_name, offset)?;
                Ok(RegHiveKey::Hkey(transform_key_with_type_i(hive_key, hive_type)))
            },
            _ => Err(forensic_rs::prelude::ForensicError::Missing),
        }
    }

    fn read_value(&self, hkey: RegHiveKey, value_name: &str) -> ForensicResult<RegValue> {
        let hkey = match hkey {
            RegHiveKey::Hkey(v) => v,
            _ => return Err(missing_key()),
        };
        if hkey < 0 {
            // Cached
            let cached_keys = self.cached_keys.borrow();
            let cached = cached_keys.get(&hkey).ok_or_else(missing_key)?;
            let (hkey, path) = match cached.split_once(|v| v == '/' || v == '\\') {
                Some(v) => v,
                None => return Err(missing_key()),
            };
            let mounted = self.mounted.borrow();
            let path_map = mounted.get(hkey).ok_or_else(missing_key)?;
            let value_map = path_map.get(path).ok_or_else(missing_key)?;
            let value = value_map.get(value_name).ok_or_else(missing_key)?;
            return Ok(value.clone());
        }
        let (hive, offset, _hive_type) = match select_hive_by_hkey(RegHiveKey::Hkey(hkey)) {
            SelectedHive::None => return Err(missing_key()),
            SelectedHive::Sam(offset) => (self.sam.as_ref().ok_or_else(missing_key)?, offset, HIVE_TYPE_SAM),
            SelectedHive::Security(offset) => (self.security.as_ref().ok_or_else(missing_key)?, offset, HIVE_TYPE_SECURITY),
            SelectedHive::Software(offset) => (self.software.as_ref().ok_or_else(missing_key)?, offset, HIVE_TYPE_SOFTWARE),
            SelectedHive::System(offset) => (self.system.as_ref().ok_or_else(missing_key)?, offset, HIVE_TYPE_SYSTEM),
            SelectedHive::Mounted(_) => todo!(),
            SelectedHive::User((position, offset)) => {
                let (_user_id, hive) = self.users.get(position as usize).ok_or_else(missing_key)?;
                (hive, offset, HIVE_TYPE_USER)
            }
        };
        let mut borrow_hive = hive.borrow_mut();
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let kn= match cell {
            HiveCell::KeyNode(kn) => kn,
            _ => todo!()
        };
        let key_values_list_offset = kn.key_values_list_offset;
        let number_key_values = kn.number_key_values;
        let values_cell_list = borrow_hive.get_cell_or_native_at_offset(key_values_list_offset as u64)?;
        let mut offsets = Vec::with_capacity(number_key_values as usize);
        match values_cell_list {
            HiveCell::Invalid(ic) => {
                // Contains the list of offsets
                for i in (0..ic.content.len()).step_by(4) {
                    let offset = u32::from_ne_bytes(ic.content[i..i+4].try_into().unwrap());
                    if offset > 0 {
                        offsets.push(offset);
                    }
                }
            },
            _=> {}
        }
        let mut data = None;
        for offset in offsets {
            let value_cell = borrow_hive.get_cell_or_native_at_offset(offset as u64)?;
            match value_cell {
                HiveCell::KeyValue(kv) => {
                    if kv.value_name == value_name {
                        data = Some((kv.data_offset, kv.data_size, kv.data_type, kv.flags));
                    }
                },
                _ => continue
            }
        }
        let (data_offset, _data_size, data_type, flags) = match data {
            Some(v) => v,
            None => return Err(ForensicError::BadFormat)
        };
        let data_cell = borrow_hive.get_cell_or_native_at_offset(data_offset as u64)?;

        let reg_value = match data_type {
            DATA_TYPE_NONE => RegValue::DWord(0),
            DATA_TYPE_REG_SZ => {
                match data_cell {
                    HiveCell::Invalid(ic) => {
                        if flags & 1 == 0 {
                            RegValue::SZ(ic.into_reg_sz_ascii())
                        }else {
                            RegValue::SZ(ic.into_reg_sz_extended())
                        }
                    },
                    _ => todo!()
                }
            },
            DATA_TYPE_REG_BINARY => {
                match data_cell {
                    HiveCell::Invalid(ic) => RegValue::Binary(ic.content.clone()),
                    _ => todo!()
                }
            },
            DATA_TYPE_REG_DWORD => {
                match data_cell {
                    HiveCell::Invalid(ic) => RegValue::DWord(ic.into_dword_le()),
                    _ => todo!()
                }
            },
            DATA_TYPE_REG_DWORD_BE => {
                match data_cell {
                    HiveCell::Invalid(ic) => RegValue::DWord(ic.into_dword_be()),
                    _ => todo!()
                }
            },
            DATA_TYPE_REG_QWORD => {
                match data_cell {
                    HiveCell::Invalid(ic) => RegValue::QWord(ic.into_qword_le()),
                    _ => todo!()
                }
            },
            DATA_TYPE_REG_EXPAND_SZ => {
                match data_cell {
                    HiveCell::Invalid(ic) => {
                        if flags & 1 == 0 {
                            RegValue::SZ(ic.into_reg_sz_ascii())
                        }else {
                            RegValue::SZ(ic.into_reg_sz_extended())
                        }
                    },
                    _ => todo!()
                }
            },
            _ => {
                println!("Need to implement data type {:?}", data_type);
                todo!()
            }
        };
        Ok(reg_value)
    }

    fn enumerate_values(&self, hkey: RegHiveKey) -> ForensicResult<Vec<String>> {
        let (mut borrow_hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(missing_key()),
            SelectedHive::Sam(offset) => (self.sam.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Security(offset) => (self.security.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Software(offset) => (self.software.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::System(offset) => (self.system.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Mounted(key_id) => {
                let a = self.cached_keys.borrow_mut();
                let b = match a.get(&(key_id as isize)) {
                    Some(v) => v,
                    None => return Err(missing_key())
                };
                let value = self.mounted.borrow().get(b);
                todo!();
            },
            SelectedHive::User((usr, offset)) => {
                let (_user_id, hive) = self.users.get(usr as usize).ok_or_else(missing_key)?;
                (hive.borrow_mut(), offset)
            },
        };
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => return Err(missing_key())
        };
        let number_key_values = key_node.number_key_values;
        let key_values_list_offset = key_node.key_values_list_offset;
        let mut values_names = Vec::with_capacity(number_key_values as usize);
        let values_cell_list = borrow_hive.get_cell_or_native_at_offset(key_values_list_offset as u64)?;
        let mut offsets = Vec::with_capacity(number_key_values as usize);

        match values_cell_list {
            HiveCell::Invalid(ic) => {
                // Contains the list of offsets
                for i in (0..ic.content.len()).step_by(4) {
                    let offset = u32::from_ne_bytes(ic.content[i..i+4].try_into().unwrap());
                    if offset > 0 {
                        offsets.push(offset);
                    }
                }
            },
            _=> {}
        }
        for offset in offsets {
            let value_cell = borrow_hive.get_cell_or_native_at_offset(offset as u64)?;
            match value_cell {
                HiveCell::KeyValue(kv) => {
                    values_names.push(kv.value_name.clone());
                },
                _ => continue
            }
        }
        
        Ok(values_names)
    }

    fn enumerate_keys(&self, hkey: RegHiveKey) -> ForensicResult<Vec<String>> {
        let (mut borrow_hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(missing_key()),
            SelectedHive::Sam(offset) => (self.sam.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Security(offset) => (self.security.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Software(offset) => (self.software.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::System(offset) => (self.system.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Mounted(_) => todo!(),
            SelectedHive::User((usr, offset)) => {
                let (_user_id, hive) = self.users.get(usr as usize).ok_or_else(missing_key)?;
                (hive.borrow_mut(), offset)
            },
        };
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => return Err(missing_key())
        };
        let subkeys_list_offset = key_node.subkeys_list_offset;
        let mut subkeys = Vec::with_capacity(key_node.number_subkeys as usize);
        let subkey_list_cell = match borrow_hive.get_cell_at_offset(subkeys_list_offset as u64)? {
            HiveCell::HashLeaf(v) => v,
            _ => return Err(missing_key())
        };
        let offsets : Vec<u32> = subkey_list_cell.elements.iter().map(|v| v.offset).collect();
        for offset in offsets {
            let cell = match borrow_hive.get_cell_at_offset(offset.into()) {
                Ok(v) => v,
                Err(err) => {
                    notify_informational!(NotificationType::Informational, "Error loading cell at offset={}. {:?}", offset, err);
                    continue
                },
            };
            let knc = match cell {
                HiveCell::KeyNode(v) => v,
                _ => return Err(ForensicError::BadFormat)
            };
            subkeys.push(knc.key_name.clone());
        }
        Ok(subkeys)
    }

    fn key_at(&self, hkey: RegHiveKey, pos: u32) -> ForensicResult<String> {
        let (hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(missing_key()),
            SelectedHive::Sam(offset) => (self.sam.as_ref().ok_or_else(missing_key)?, offset),
            SelectedHive::Security(offset) => (self.security.as_ref().ok_or_else(missing_key)?, offset),
            SelectedHive::Software(offset) => (self.software.as_ref().ok_or_else(missing_key)?, offset),
            SelectedHive::System(offset) => (self.system.as_ref().ok_or_else(missing_key)?, offset),
            SelectedHive::Mounted(offset) => {
                todo!()
            },
            SelectedHive::User(_) => todo!(),
        };
        let mut borrow_hive = hive.borrow_mut();
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => return Err(missing_key())
        };
        let subkeys_list_offset = key_node.subkeys_list_offset;
        let number_subkeys = key_node.number_subkeys;
        if pos >= number_subkeys {
            return Err(ForensicError::Other("Invalid position".into()))
        }
        let subkey_list_cell = match borrow_hive.get_cell_at_offset(subkeys_list_offset as u64)? {
            HiveCell::HashLeaf(v) => v,
            _ => return Err(missing_key())
        };
        let offset = subkey_list_cell.elements[pos as usize].offset;
        let cell = match borrow_hive.get_cell_at_offset(offset.into()) {
            Ok(v) => v,
            Err(err) => {
                notify_informational!(NotificationType::Informational, "Error loading cell at offset={}. {:?}", offset, err);
                return Err(ForensicError::BadFormat)
            },
        };
        let knc = match cell {
            HiveCell::KeyNode(v) => v,
            _ => return Err(ForensicError::BadFormat)
        };
        Ok(knc.key_name.clone())
    }

    fn value_at(&self, hkey: RegHiveKey, pos: u32) -> ForensicResult<String> {
        let (mut borrow_hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(missing_key()),
            SelectedHive::Sam(offset) => (self.sam.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Security(offset) => (self.security.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Software(offset) => (self.software.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::System(offset) => (self.system.as_ref().ok_or_else(missing_key)?.borrow_mut(), offset),
            SelectedHive::Mounted(_) => todo!(),
            SelectedHive::User((usr, offset)) => {
                let (_user_id, hive) = self.users.get(usr as usize).ok_or_else(missing_key)?;
                (hive.borrow_mut(), offset)
            },
        };
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => return Err(ForensicError::BadFormat)
        };
        let number_key_values = key_node.number_key_values;
        let key_values_list_offset = key_node.key_values_list_offset;
        let values_cell_list = borrow_hive.get_cell_or_native_at_offset(key_values_list_offset as u64)?;
        if pos >= number_key_values{
            return Err(ForensicError::Other("Invalid position".into()))
        }
        let pos = pos as usize;
        let value_offset = match values_cell_list {
            HiveCell::Invalid(ic) => {
                u32::from_ne_bytes(ic.content[pos * 4.. (pos + 1) * 4].try_into().unwrap())
            },
            _=> return Err(ForensicError::BadFormat)
        };
        let value_cell = borrow_hive.get_cell_or_native_at_offset(value_offset as u64)?;
        match value_cell {
            HiveCell::KeyValue(kv) => {
                Ok(kv.value_name.clone())
            },
            _ =>  Err(missing_key())
        }
    }
    fn close_key(&self, hkey: RegHiveKey) {
        let hkey = match hkey {
            RegHiveKey::Hkey(v) => v,
            _ => return,
        };
        let mut cached = self.cached_keys.borrow_mut();
        cached.remove(&hkey);
    }
}

pub fn transform_key_with_type(key : u64, typ : u16) -> isize {
    ((key & 0xffffffffffff) | ((typ as u64 ) << 48)) as isize
}
pub fn transform_key_with_type_i(key : isize, typ : u16) -> isize {
    ((key & 0xffffffffffff) | ((typ as isize ) << 48)) as isize
}
pub(crate) fn select_hive_by_hkey(key : RegHiveKey) -> SelectedHive {
    // When positive, the 16 most significative bits indicate wich hive to load. The rest are used for offsets in the file.
    // 32768 posible hives loaded into the reader. More than enough
    // Max offset = 48 bits = 2.8147498e+14 bytes
    match key {
        RegHiveKey::Hkey(ikey) => {
            let key = ikey.abs() as u64;
            if ikey < 0 {
                return SelectedHive::Mounted(key)
            }
            let key_value = key & 0xffffffffffff;
            let key_type = (key >> 48) as u16;
            match key_type {
                HIVE_TYPE_NONE => SelectedHive::None,
                HIVE_TYPE_SAM => SelectedHive::Sam(key_value),
                HIVE_TYPE_SECURITY => SelectedHive::Security(key_value),
                HIVE_TYPE_SOFTWARE => SelectedHive::Software(key_value),
                HIVE_TYPE_SYSTEM => SelectedHive::System(key_value),
                HIVE_TYPE_CACHED => SelectedHive::Mounted(key_value),
                _ => SelectedHive::User((key_type - HIVE_TYPE_USER, key_value)),
            }
        },
        _ => SelectedHive::None
    }
}
pub(crate) fn user_hive_by_position(position : u16, offset : isize) -> RegHiveKey {
    RegHiveKey::Hkey(offset as isize | ((position + HIVE_TYPE_USER) as isize) << 48)
}

pub fn open_hive_with_logs(fs: &mut Box<dyn forensic_rs::traits::vfs::VirtualFileSystem>, base_path : &Path, name : &str) -> Option<HiveFiles> {
    let primary_path = base_path.join(name);
    let primary = fs.open(primary_path.as_path()).ok()?;
    let mut hive = HiveFiles::new(primary_path, primary).ok()?;
    let log_1 = base_path.join(&format!("{}.LOG1", name));
    match fs.open(log_1.as_path()) {
        Ok(v) => {
            hive.logs.push(v);
        },
        Err(_) => {}
    };
    let log_2 = base_path.join(&format!("{}.LOG2", name));
    match fs.open(log_2.as_path()) {
        Ok(v) => {
            hive.logs.push(v);
        },
        Err(_) => {}
    };
    Some(hive)
}

#[cfg(test)]
#[path="reader_tst.rs"]
mod tst;