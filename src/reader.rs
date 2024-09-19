use std::{
    cell::RefCell,
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use forensic_rs::{
    debug,
    notifications::NotificationType,
    notify_informational, notify_low,
    prelude::{ForensicError, ForensicResult, RegHiveKey, RegValue, RegistryReader, HKLM},
    trace,
    traits::{
        registry::RegistryKeyInfo,
        vfs::{VirtualFile, VirtualFileSystem},
    },
    utils::time::Filetime,
};

use crate::{
    cell::{peek_cell, read_cell, HashLeafCell, HiveCell, KeyNodeCell},
    cell_cache::CellCache,
    hive::{read_base_block, read_cells, read_hive_bin_at_file_position, BaseBlock},
    mounted_map::MountedMap,
};

const HIVE_TYPE_NONE: u16 = 0;
const HIVE_TYPE_SAM: u16 = 1;
const HIVE_TYPE_SECURITY: u16 = 2;
const HIVE_TYPE_SOFTWARE: u16 = 3;
const HIVE_TYPE_SYSTEM: u16 = 4;
const HIVE_TYPE_CACHED: u16 = 5;
const HIVE_TYPE_OTHERS: u16 = 6;
const HIVE_TYPE_USER: u16 = 7;

const DATA_TYPE_NONE: u32 = 0x0;
const DATA_TYPE_REG_SZ: u32 = 0x1;
const DATA_TYPE_REG_EXPAND_SZ: u32 = 0x2;
const DATA_TYPE_REG_BINARY: u32 = 0x03;
const DATA_TYPE_REG_DWORD: u32 = 0x04;
const DATA_TYPE_REG_DWORD_BE: u32 = 0x05;
#[allow(dead_code)]
const DATA_TYPE_REG_LINK: u32 = 0x06;
#[allow(dead_code)]
const DATA_TYPE_REG_MULTI_SZ: u32 = 0x07;
#[allow(dead_code)]
const DATA_TYPE_REG_RESOURCE_LIST: u32 = 0x08;
#[allow(dead_code)]
const DATA_TYPE_REG_FULL_RESOURCE_DESCRIPTOR: u32 = 0x09;
#[allow(dead_code)]
const DATA_TYPE_REG_RESOURCE_REQUIREMENTS_LIST: u32 = 0x0a;
const DATA_TYPE_REG_QWORD: u32 = 0xb;

/// Implements RegistryReader from Hive files.
///
/// ```
/// use forensic_rs::core::fs::{ChRootFileSystem, StdVirtualFS};
/// use frnsc_hive::reader::HiveRegistryReader;
/// // Initialize a ChRoot FS to make the folder ./artifacts/ the root folder
/// let fs = Box::new(ChRootFileSystem::new("./artifacts/", Box::new(StdVirtualFS::new())));
/// // The hive registry reader searchs for hives in C:\Windows\System32\Config that its translated into ./artifacts/C/Windows/System32/Config
/// let mut reader = HiveRegistryReader::from_fs(fs).unwrap();
/// ```
pub struct HiveRegistryReader {
    /// HKEY_CURRENT_CONFIG: System, System.alt, System.log, System.sav
    current_config: Option<RefCell<HiveFiles>>,
    /// HKEY_USERS Default, Default.log, Default.sav Ntuser.dat, Ntuser.dat.log
    /// List with the name of the user and the Hive files
    users: Vec<(String, RefCell<HiveFiles>)>,
    /// HKEY_LOCAL_MACHINE\SAM Sam, Sam.log, Sam.sav
    sam: Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\Security Security, Security.log, Security.sav
    security: Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\Software Software, Software.log, Software.sav
    software: Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\System System, System.alt, System.log, System.sav
    system: Option<RefCell<HiveFiles>>,
    /// Mount reg files
    mounted: RefCell<MountedMap>,
    /// Associate a hkey with a path for the mounted registry keys
    cached_keys: RefCell<BTreeMap<isize, String>>,
    key_counter: RefCell<usize>,
    /// Other mounted hives
    others: Vec<(String, RefCell<HiveFiles>)>,
}

pub struct HiveReader {
    pub files: HiveFiles,
    pub opened_keys: BTreeMap<RegHiveKey, RegValue>,
}

impl Default for HiveRegistryReader {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveRegistryReader {
    /// Loads all hives from the file system searching for its locations.
    /// It also search for the location of the hives of all the users using the SOFTWARE hive with the **ProfileList** key.
    /// ```
    /// use forensic_rs::core::fs::{ChRootFileSystem, StdVirtualFS};
    /// use frnsc_hive::reader::HiveRegistryReader;
    /// // Initialize a ChRoot FS to make the folder ./artifacts/ the root folder
    /// let fs = Box::new(ChRootFileSystem::new("./artifacts/", Box::new(StdVirtualFS::new())));
    /// // The hive registry reader searchs for hives in C:\Windows\System32\Config that its translated into ./artifacts/C/Windows/System32/Config
    /// let mut reader = HiveRegistryReader::from_fs(fs).unwrap();
    /// ```
    pub fn from_fs(mut fs: Box<dyn VirtualFileSystem>) -> ForensicResult<Box<dyn RegistryReader>> {
        let mut reader = Self::new();
        let config_folder = std::path::Path::new("C:\\Windows\\System32\\Config");
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
            Ok(_) => {}
            Err(e) => {
                notify_low!(
                    NotificationType::Informational,
                    "Error loading user hives: {:?}",
                    e
                );
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
            others: Vec::new(),
            mounted: RefCell::new(MountedMap::new()),
            cached_keys: RefCell::new(BTreeMap::new()),
            key_counter: RefCell::new(0),
        }
    }

    /// Searchs and loads all the users that have HIVES using the **ProfileList** registry key.
    pub fn load_user_hives(&mut self, fs: &mut Box<dyn VirtualFileSystem>) -> ForensicResult<()> {
        let system_root = match self.get_system_root() {
            Ok(v) => v,
            Err(_) => {
                notify_low!(
                    NotificationType::Informational,
                    "Cannot find SystemRoot environment variable"
                );
                r"C:\Windows".into()
            }
        };
        let user_names_key = self.open_key(
            HKLM,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        )?;
        let guid_list = self.enumerate_keys(user_names_key)?;
        for user_guid in &guid_list {
            let profile = self.open_key(user_names_key, user_guid)?;
            let profile_path: String = match self.read_value(profile, "ProfileImagePath") {
                Ok(v) => match v.try_into() {
                    Ok(v) => v,
                    Err(_) => {
                        notify_low!(
                            NotificationType::DeletedArtifact,
                            "ProfileImagePath for user {} is not a String value",
                            user_guid
                        );
                        continue;
                    }
                },
                Err(_) => {
                    notify_low!(
                        NotificationType::DeletedArtifact,
                        "Cannot find ProfileImagePath for user {}",
                        user_guid
                    );
                    continue;
                }
            };
            let profile_path = profile_path.replace(":\\", "\\");
            let profile_path = if profile_path.contains("%systemroot%") {
                profile_path.replace("%systemroot%", &system_root)
            } else {
                profile_path
            };
            let user_profile_path = std::path::Path::new(&profile_path);
            let hive = match open_hive_with_logs(fs, user_profile_path, "NTUSER.DAT") {
                Some(v) => v,
                None => {
                    notify_low!(
                        NotificationType::DeletedArtifact,
                        "Cannot find hive {}\\NTUSER.DAT for user {}",
                        profile_path,
                        user_guid
                    );
                    continue;
                }
            };
            self.add_user(user_guid, hive);
        }
        Ok(())
    }

    pub fn list_hklm_values(&self) -> ForensicResult<Vec<String>> {
        Ok(Vec::new())
    }

    pub fn list_hklm_keys(&self) -> ForensicResult<Vec<String>> {
        let mut ret = Vec::with_capacity(4);
        if self.system.is_some() {
            ret.push("SYSTEM".into());
        }
        if self.security.is_some() {
            ret.push("SECURITY".into());
        }
        if self.software.is_some() {
            ret.push("SOFTWARE".into());
        }
        if self.sam.is_some() {
            ret.push("SAM".into());
        }
        Ok(ret)
    }

    /// Sets the SAM HIVE
    pub fn set_sam(&mut self, hive: HiveFiles) {
        trace!("Loaded SAM hive");
        self.sam = Some(RefCell::new(hive));
    }
    /// Sets the SECURITY HIVE
    pub fn set_security(&mut self, hive: HiveFiles) {
        trace!("Loaded Security hive");
        self.security = Some(RefCell::new(hive));
    }
    /// Sets the SOFTWARE HIVE
    pub fn set_software(&mut self, hive: HiveFiles) {
        trace!("Loaded Software hive");
        self.software = Some(RefCell::new(hive));
    }
    /// Sets the SYSTEM HIVE
    pub fn set_system(&mut self, hive: HiveFiles) {
        trace!("Loaded System hive");
        self.system = Some(RefCell::new(hive));
    }
    /// Sets the CurrentConfig HIVE
    pub fn set_current_config(&mut self, hive: HiveFiles) {
        self.current_config = Some(RefCell::new(hive));
    }
    /// Adds a User HIVE. The user parameter must be the GUID of the user.
    pub fn add_user(&mut self, user: &str, hive: HiveFiles) {
        trace!("Added user {} hive", user);
        self.users.push((user.into(), RefCell::new(hive)));
    }
    /// Adds a any HIVE file. The user parameter must be the GUID of the user.
    pub fn add_other(&mut self, mount_path: &str, hive: HiveFiles) {
        trace!("Added other {} hive", mount_path);
        self.others.push((mount_path.into(), RefCell::new(hive)));
    }
    /// Adds a registry key extracted from a REG file
    /// ```
    /// use frnsc_hive::reader::HiveRegistryReader;
    /// use forensic_rs::prelude::{RegValue, RegistryReader, HKLM};
    /// let mut reader = HiveRegistryReader::new();
    /// reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System", r"Identifier", RegValue::SZ(r"AT/AT COMPATIBLE".into()));
    /// let key = reader.open_key(HKLM, r"HARDWARE\DESCRIPTION\System").unwrap();
    /// assert_eq!(RegValue::SZ(r"AT/AT COMPATIBLE".into()), reader.read_value(key, "Identifier").unwrap());
    /// ```
    pub fn add_reg_key(&mut self, full_path: &str, value: &str, data: RegValue) {
        let (hkey, path) = match full_path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return,
        };
        if hkey == "HKEY_LOCAL_MACHINE" {
            let mut splited = path.split(|v| v == '\\' || v == '/');
            if let Some(first_key) = splited.next() {
                if first_key == "SAM" && self.sam.is_some() {
                    self.sam.as_ref().map(|hive| {
                        hive.borrow_mut().add_mounted_value(full_path, value, data);
                        hive
                    });
                    return;
                } else if first_key == "SECURITY" && self.security.is_some() {
                    self.security.as_ref().map(|hive| {
                        hive.borrow_mut().add_mounted_value(full_path, value, data);
                        hive
                    });
                    return;
                } else if first_key == "SYSTEM" && self.system.is_some() {
                    self.system.as_ref().map(|hive| {
                        hive.borrow_mut().add_mounted_value(full_path, value, data);
                        hive
                    });
                    return;
                } else if first_key == "SOFTWARE" && self.software.is_some() {
                    self.software.as_ref().map(|hive| {
                        hive.borrow_mut().add_mounted_value(full_path, value, data);
                        hive
                    });
                    return;
                }
            }
        } else if hkey == "HKEY_USERS" {
            let mut splited = path.split(|v| v == '\\' || v == '/');
            if let Some(first_key) = splited.next() {
                for (guid, hive) in &self.users {
                    if first_key == guid {
                        return hive.borrow_mut().add_mounted_value(full_path, value, data);
                    }
                }
            }
        }
        let mut mounted = self.mounted.borrow_mut();
        mounted.add_value(full_path, value, data);
    }
    pub fn add_reg_file(&mut self, _data: String) {
        todo!()
    }

    fn next_key(&self) -> isize {
        let mut ret = *self.key_counter.borrow();
        let ret_transf = ret as isize;
        loop {
            let borrow = self.cached_keys.borrow();
            if !borrow.contains_key(&ret_transf) {
                break;
            }
            ret += 1;
            if ret == usize::MAX {
                ret = 0;
            }
        }

        self.key_counter.replace(ret + 1);
        ret as isize
    }
}

#[derive(Debug)]
pub enum SelectedHive {
    None,
    Sam(i64),
    Security(i64),
    Software(i64),
    System(i64),
    Mounted(i64),
    Other((u16, i64)),
    User((u16, i64)),
}

pub struct HiveFiles {
    pub(crate) location: PathBuf,
    pub(crate) primary: Box<dyn VirtualFile>,
    pub base_block: BaseBlock,
    pub(crate) root_cell: KeyNodeCell,
    pub(crate) logs: Vec<Box<dyn VirtualFile>>,
    pub(crate) cell_cache: CellCache,
    pub(crate) buffer: Vec<u8>,
    pub(crate) mounted: MountedMap,
    pub(crate) mounted_cache: BTreeMap<i64, (String, String)>,
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
            .ok_or_else(|| ForensicError::missing_str("Missing root cell"))?;
        let root_cell = match key_node_cell {
            HiveCell::KeyNode(v) => v.clone(),
            _ => {
                return Err(ForensicError::missing_str(
                    "Expected RootCell of type KeyNode",
                ))
            }
        };
        Ok(Self {
            location,
            base_block,
            primary,
            root_cell,
            logs: Vec::with_capacity(8),
            cell_cache,
            buffer: vec![0u8; 4096],
            mounted: MountedMap::new(),
            mounted_cache: BTreeMap::new(),
        })
    }

    pub fn scan_hive(_primary: &mut Box<dyn VirtualFile>) -> Vec<(u64, u64)> {
        vec![]
    }
    pub fn add_mounted_value(&mut self, path: &str, value: &str, data: RegValue) {
        self.mounted.add_value(path, value, data);
    }

    pub fn open_mounted_key(&mut self, _key_name: &str, _key_id: i64) -> ForensicResult<isize> {
        todo!()
    }
    pub fn read_mounted_value(&self, _key_id: i64) -> ForensicResult<RegValue> {
        todo!()
    }
    pub fn enumerate_mounted_keys(&self, _key_id: i64) -> ForensicResult<Vec<String>> {
        todo!()
    }
    pub fn enumerate_mounted_values(&self, _key_id: i64) -> ForensicResult<Vec<String>> {
        todo!()
    }
    pub fn get_mounted_key_at(&self, _key_id: i64) -> ForensicResult<String> {
        todo!()
    }
    pub fn get_mounted_value_at(&self, _key_id: i64) -> ForensicResult<String> {
        todo!()
    }

    pub fn open_key_from_offset(&mut self, key_name: &str, offset: i64) -> ForensicResult<isize> {
        if offset < 0 {
            return self.open_mounted_key(key_name, offset);
        }
        let offset = offset as u64;
        if offset == 32 && key_name.is_empty() {
            return Ok(32);
        }
        let mut path_separator = key_name.split(|v| v == '\\');
        let root_cell = match self.get_cell_at_offset(offset)? {
            HiveCell::KeyNode(kn) => kn,
            _ => return Err(ForensicError::missing_str("Missing root cell")),
        };
        let subkeys_offset = root_cell.subkeys_list_offset;
        let n_subkeys = root_cell.number_subkeys;
        let _n_key_val = root_cell.number_key_values;
        let first = match path_separator.next() {
            Some(v) => v,
            None => return Ok(32), // Root Cell
        };
        if n_subkeys == 0 {
            return Err(ForensicError::missing_str("Key not found"));
        }
        let mut next_offset = subkeys_offset;
        let mut subkey_last_index = 0;
        let mut actual_path = first;
        let mut offset_path = Vec::with_capacity(32);
        'out: loop {
            match self.get_cell_at_offset(next_offset as u64)? {
                HiveCell::HashLeaf(hl) => {
                    subkey_last_index = 0;
                    let path_hash = HashLeafCell::hash_name(actual_path);
                    for el in &hl.elements {
                        if path_hash == el.name_hash {
                            offset_path.push((next_offset, 0));
                            next_offset = el.offset;
                            continue 'out;
                        }
                    }
                    let (last_offset, counter) = match offset_path.pop() {
                        Some(v) => v,
                        None => return Err(ForensicError::missing_str("Cannot find registry key")),
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                HiveCell::KeyNode(kn) => {
                    if subkey_last_index > 0 {
                        return Err(ForensicError::missing_str("Cannot find registry key"));
                    }
                    if kn.key_name != actual_path {
                        let (last_offset, counter) = match offset_path.pop() {
                            Some(v) => v,
                            None => {
                                return Err(ForensicError::missing_str("Cannot find registry key"))
                            }
                        };
                        next_offset = last_offset;
                        subkey_last_index = counter + 1;
                        continue;
                    }
                    match path_separator.next() {
                        Some(v) => {
                            actual_path = v;
                            next_offset = kn.subkeys_list_offset;
                        }
                        None => break,
                    }
                }
                HiveCell::FastLeaf(fl) => {
                    let mut i = subkey_last_index;
                    for el in fl.elements.iter().skip(i) {
                        if actual_path.starts_with(&el.name_hint) {
                            offset_path.push((next_offset, i));
                            subkey_last_index = 0;
                            next_offset = el.offset;
                            continue 'out;
                        }
                        i += 1;
                    }
                    let (last_offset, counter) = match offset_path.pop() {
                        Some(v) => v,
                        None => return Err(ForensicError::missing_str("Cannot find registry key")),
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                HiveCell::IndexRoot(ir) => {
                    let i = subkey_last_index;
                    for el in ir.elements.iter().skip(i) {
                        offset_path.push((next_offset, i));
                        subkey_last_index = 0;
                        next_offset = el.subkeys_list_offset;
                        continue 'out;
                    }
                    let (last_offset, counter) = match offset_path.pop() {
                        Some(v) => v,
                        None => return Err(ForensicError::missing_str("Cannot find registry key")),
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                HiveCell::IndexLeaf(il) => {
                    let i = subkey_last_index;
                    for el in il.elements.iter().skip(i) {
                        offset_path.push((next_offset, i));
                        subkey_last_index = 0;
                        next_offset = el.offset;
                        continue 'out;
                    }
                    let (last_offset, counter) = match offset_path.pop() {
                        Some(v) => v,
                        None => return Err(ForensicError::missing_str("Cannot find registry key")),
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                _ => return Err(ForensicError::missing_str("Cannot find registry key")),
            };
        }
        Ok(next_offset as isize)
    }
    pub fn open_key(&mut self, key_name: &str) -> ForensicResult<isize> {
        self.mounted.contains(key_name);
        self.open_key_file(key_name)
    }
    pub fn open_key_file(&mut self, key_name: &str) -> ForensicResult<isize> {
        let mut path_separator = key_name.split(|v| v == '/' || v == '\\');
        let root_cell = self.get_root_cell()?;
        let subkeys_offset = root_cell.subkeys_list_offset;
        let n_subkeys = root_cell.number_subkeys;
        let first = match path_separator.next() {
            Some(v) => v,
            None => return Ok(32), // Root Cell
        };
        if first.is_empty() {
            return Ok(32);
        }
        if n_subkeys == 0 {
            return Err(ForensicError::missing_str("Key not found"));
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
                    return Err(ForensicError::missing_str("HashLeaf not found"));
                }
                HiveCell::KeyNode(kn) => {
                    if kn.key_name != actual_path {
                        return Err(ForensicError::missing_str(
                            "Key node path does not match key path",
                        ));
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
        let cell = self
            .cell_cache
            .get(32)
            .ok_or_else(|| ForensicError::missing_str("Root cell not found"))?;

        let kn = match cell {
            HiveCell::KeyNode(ir) => ir,
            _ => return Err(ForensicError::bad_format_str("Invalid RootCell type")),
        };
        Ok(kn)
    }
    pub fn get_cell_at_offset(&mut self, offset: u64) -> ForensicResult<&HiveCell> {
        if self.cell_cache.contains(offset) {
            return Ok(self.cell_cache.get(offset).unwrap());
        }
        self.primary.seek(std::io::SeekFrom::Start(
            self.hive_bins_data_offset() + offset,
        ))?;
        let mut readed = self.primary.read(&mut self.buffer)?;
        let cell_size = peek_cell(&self.buffer[0..readed]);
        if cell_size > readed {
            if cell_size
                > self
                    .base_block
                    .hive_bins_data_size
                    .try_into()
                    .unwrap_or_default()
            {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid cell size {} at offset {}",
                    cell_size, offset
                )));
            }
            if cell_size > self.buffer.len() {
                self.buffer = vec![0; ((cell_size / 1024) + 1) * 1024];
            }
            self.primary.seek(std::io::SeekFrom::Start(
                self.hive_bins_data_offset() + offset,
            ))?;
            self.primary.read_exact(&mut self.buffer[0..cell_size])?;
            readed = cell_size;
        }
        let cell = read_cell(&self.buffer[0..readed], offset)?;
        self.cell_cache.insert(cell);
        match self.cell_cache.get(offset) {
            Some(cell) => Ok(cell),
            None => Err(ForensicError::missing_str("Hive cell not found")),
        }
    }
    pub fn get_cell_or_native_at_offset(&mut self, offset: u64) -> ForensicResult<&HiveCell> {
        if self.cell_cache.contains(offset) {
            return Ok(self.cell_cache.get(offset).unwrap());
        }
        self.primary.seek(std::io::SeekFrom::Start(
            self.hive_bins_data_offset() + offset,
        ))?;
        let mut readed = self.primary.read(&mut self.buffer)?;
        let cell_size = peek_cell(&self.buffer[0..readed]);
        if cell_size > readed {
            if cell_size
                > self
                    .base_block
                    .hive_bins_data_size
                    .try_into()
                    .unwrap_or_default()
            {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid cell size {} at offset {}",
                    cell_size, offset
                )));
            }
            if cell_size > self.buffer.len() {
                self.buffer = vec![0; ((cell_size / 1024) + 1) * 1024];
            }
            self.primary.seek(std::io::SeekFrom::Start(
                self.hive_bins_data_offset() + offset,
            ))?;
            self.primary.read_exact(&mut self.buffer[0..cell_size])?;
            readed = cell_size;
        }
        let cell = read_cell(&self.buffer[0..readed], offset)?;
        self.cell_cache.insert(cell);
        match self.cell_cache.get(offset) {
            Some(cell) => Ok(cell),
            None => Err(ForensicError::missing_str("Hive cell not found")),
        }
    }

    fn hive_bins_data_offset(&self) -> u64 {
        4096
    }
}

impl RegistryReader for HiveRegistryReader {
    fn from_file(&self, _file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn RegistryReader>> {
        Err(ForensicError::bad_format_str(
            "Cannot create HiveRegistryReader from file",
        ))
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
                let (first_key, _rest) = match key_name.split_once(|v| v == '/' || v == '\\') {
                    Some(v) => v,
                    None => (key_name, ""),
                };
                let (hive, hive_type) = if first_key == "SAM" {
                    (
                        self.sam
                            .as_ref()
                            .ok_or_else(|| ForensicError::missing_str("Cannot find SAM hive"))?,
                        HIVE_TYPE_SAM,
                    )
                } else if first_key == "SECURITY" {
                    (
                        self.security.as_ref().ok_or_else(|| {
                            ForensicError::missing_str("Cannot find SECURITY hive")
                        })?,
                        HIVE_TYPE_SECURITY,
                    )
                } else if first_key == "SOFTWARE" {
                    key_name = &key_name[9..];
                    (
                        self.software.as_ref().ok_or_else(|| {
                            ForensicError::missing_str("Cannot find SOFTWARE hive")
                        })?,
                        HIVE_TYPE_SOFTWARE,
                    )
                } else if first_key == "SYSTEM" {
                    (
                        self.system
                            .as_ref()
                            .ok_or_else(|| ForensicError::missing_str("Cannot find SYSTEM hive"))?,
                        HIVE_TYPE_SYSTEM,
                    )
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
                    let full_path = format!("HKEY_LOCAL_MACHINE\\{}", key_name);
                    if h.contains(&full_path) {
                        let new_key = self.next_key();
                        self.cached_keys.borrow_mut().insert(new_key, full_path);
                        return Ok(RegHiveKey::Hkey(transform_key_with_type_i(
                            new_key,
                            HIVE_TYPE_CACHED,
                        )));
                    }
                    return Err(ForensicError::missing_str("Cannot find HKLM mounted hive"));
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
                Ok(RegHiveKey::Hkey(transform_key_with_type_i(
                    hive_key, hive_type,
                )))
            }
            RegHiveKey::HkeyUsers => {
                let (username, rest_of_path) = match key_name.split_once(|v| v == '/' || v == '\\')
                {
                    Some(v) => v,
                    None => (key_name, ""),
                };
                let position = self
                    .users
                    .iter()
                    .position(|v| v.0 == username)
                    .ok_or_else(|| ForensicError::missing_str("Cannot find HKU hive"))?;
                let (_user_id, user_hive) = self
                    .users
                    .get(position)
                    .ok_or_else(|| ForensicError::missing_str("Invalid HKU hive"))?;
                let mut hive = match user_hive.try_borrow_mut() {
                    Ok(v) => v,
                    Err(e) => {
                        return Err(forensic_rs::prelude::ForensicError::Other(format!(
                            "Error reading user key: {:?}",
                            e
                        )))
                    }
                };
                let hive_key = hive.open_key(rest_of_path)?;
                Ok(user_hive_by_position(position as u16, hive_key))
            }
            RegHiveKey::Hkey(hkey) => {
                let (hive, offset, hive_type) = match select_hive_by_hkey(RegHiveKey::Hkey(hkey)) {
                    SelectedHive::None => {
                        // Used to open mounted hives
                        let mut cell = None;
                        for (key, other_cell) in &self.others {
                            if key == key_name {
                                cell = Some(other_cell);
                                break;
                            }
                        }
                        let cell = match cell {
                            Some(v) => v,
                            None => {
                                return Err(ForensicError::missing_string(format!(
                                    "Cannot find mounted HVE file {}",
                                    key_name
                                )))
                            }
                        };
                        let root_cell_pos = match cell.try_borrow() {
                            Ok(v) => v.root_cell.offset,
                            Err(_) => 32,
                        };
                        let mut hive = match cell.try_borrow_mut() {
                            Ok(v) => v,
                            Err(e) => {
                                return Err(forensic_rs::prelude::ForensicError::Other(format!(
                                    "Error reading user key: {:?}",
                                    e
                                )))
                            }
                        };
                        let hive_key = hive.open_key_from_offset("", root_cell_pos as i64)?;
                        return Ok(RegHiveKey::Hkey(transform_key_with_type_i(
                            hive_key,
                            HIVE_TYPE_OTHERS,
                        )));
                    }
                    SelectedHive::Sam(offset) => (
                        self.sam
                            .as_ref()
                            .ok_or_else(|| ForensicError::missing_str("Invalid SAM hive"))?,
                        offset,
                        HIVE_TYPE_SAM,
                    ),
                    SelectedHive::Security(offset) => (
                        self.security
                            .as_ref()
                            .ok_or_else(|| ForensicError::missing_str("Invalid SECURITY hive"))?,
                        offset,
                        HIVE_TYPE_SECURITY,
                    ),
                    SelectedHive::Software(offset) => (
                        self.software
                            .as_ref()
                            .ok_or_else(|| ForensicError::missing_str("Invalid SOFTWARE hive"))?,
                        offset,
                        HIVE_TYPE_SOFTWARE,
                    ),
                    SelectedHive::System(offset) => (
                        self.system
                            .as_ref()
                            .ok_or_else(|| ForensicError::missing_str("Invalid SYSTEM hive"))?,
                        offset,
                        HIVE_TYPE_SYSTEM,
                    ),
                    SelectedHive::Mounted(_) => todo!(),
                    SelectedHive::Other((pos, offset)) => {
                        let pos = pos as usize;
                        let (_, cell) = self.others.get(pos).ok_or_else(|| {
                            ForensicError::missing_str("Invalid mounted hive HVE")
                        })?;
                        (cell, offset, HIVE_TYPE_OTHERS)
                    }
                    SelectedHive::User((position, offset)) => {
                        let (_user_id, hive) = self
                            .users
                            .get(position as usize)
                            .ok_or_else(|| ForensicError::missing_str("Invalid User hive"))?;
                        (hive, offset, HIVE_TYPE_USER)
                    }
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
                Ok(RegHiveKey::Hkey(transform_key_with_type_i(
                    hive_key, hive_type,
                )))
            }
            _ => Err(ForensicError::missing_str("Hive not found")),
        }
    }

    fn read_value(&self, hkey: RegHiveKey, value_name: &str) -> ForensicResult<RegValue> {
        let (hive, offset, _hive_type) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(ForensicError::missing_str("Invalid hive")),
            SelectedHive::Sam(offset) => (
                self.sam
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SAM hive"))?,
                offset,
                HIVE_TYPE_SAM,
            ),
            SelectedHive::Security(offset) => (
                self.security
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid Security hive"))?,
                offset,
                HIVE_TYPE_SECURITY,
            ),
            SelectedHive::Software(offset) => (
                self.software
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SOFTWARE hive"))?,
                offset,
                HIVE_TYPE_SOFTWARE,
            ),
            SelectedHive::System(offset) => (
                self.system
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SYSTEM hive"))?,
                offset,
                HIVE_TYPE_SYSTEM,
            ),
            SelectedHive::Mounted(key_id) => {
                let cached_keys = self.cached_keys.borrow();
                let key_id = key_id as isize;
                let cached = cached_keys
                    .get(&key_id)
                    .ok_or_else(|| ForensicError::missing_str("Invalid mounted hive hive"))?;
                let mounted = self.mounted.borrow();
                let path_map = mounted
                    .get_value(cached, value_name)
                    .ok_or_else(|| ForensicError::missing_str("Invalid handle"))?;
                return Ok(path_map);
            }
            SelectedHive::Other((position, offset)) => {
                let (_user_id, hive) = self
                    .others
                    .get(position as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid Other hive"))?;
                (hive, offset, HIVE_TYPE_OTHERS)
            }
            SelectedHive::User((position, offset)) => {
                let (_user_id, hive) = self
                    .users
                    .get(position as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid User hive"))?;
                (hive, offset, HIVE_TYPE_USER)
            }
        };
        let mut borrow_hive = hive.borrow_mut();
        let hive_bins_data_size = borrow_hive.base_block.hive_bins_data_size;
        if offset < 0 {
            return borrow_hive.read_mounted_value(offset);
        }
        let offset = offset as u64;
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let kn = match cell {
            HiveCell::KeyNode(kn) => kn,
            _ => todo!(),
        };
        let key_values_list_offset = kn.key_values_list_offset;
        let number_key_values = kn.number_key_values;
        let values_cell_list =
            borrow_hive.get_cell_or_native_at_offset(key_values_list_offset as u64)?;
        let mut offsets = Vec::with_capacity(number_key_values as usize);
        if let HiveCell::Invalid(ic) = values_cell_list {
            // Contains the list of offsets
            for i in (0..ic.content.len()).step_by(4) {
                let offset = u32::from_ne_bytes(ic.content[i..i + 4].try_into().unwrap());
                if offset > 32 && offset < hive_bins_data_size {
                    offsets.push(offset);
                }
            }
        }
        let mut data = None;
        for offset in offsets {
            let value_cell = match borrow_hive.get_cell_or_native_at_offset(offset as u64) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match value_cell {
                HiveCell::KeyValue(kv) => {
                    if kv.value_name == value_name {
                        data = Some((kv.data_offset, kv.data_size, kv.data_type, kv.flags));
                        break;
                    }
                }
                _ => continue,
            }
        }
        let (data_offset, data_size, data_type, flags) = match data {
            Some(v) => v,
            None => return Err(ForensicError::missing_str("Invalid data cell type")),
        };
        let cached_size = data_size as i32;
        if cached_size < 0 {
            let size = (i32::MIN - cached_size).abs() as usize;
            let value = data_offset;
            let data = value.to_le_bytes();
            let data = &data[0..size.min(data.len())];
            return Ok(match data_type {
                DATA_TYPE_REG_BINARY => RegValue::Binary(data.to_vec()),
                DATA_TYPE_REG_SZ => {
                    match (data.get(data.len() - 2), data.get(data.len() - 1)) {
                        (Some(0), Some(0)) => {
                            if data.len() == 2 {
                                // Empty utf16 string
                                RegValue::SZ(String::new())
                            } else {
                                RegValue::SZ(String::from_utf16_lossy(&[u16::from_le_bytes([
                                    data[0], data[1],
                                ])]))
                            }
                        }
                        (Some(_), Some(0)) => RegValue::SZ(
                            String::from_utf8_lossy(&data[..data.len() - 1]).to_string(),
                        ),
                        _ => RegValue::SZ(String::from_utf8_lossy(data).to_string()),
                    }
                }
                DATA_TYPE_REG_DWORD => RegValue::DWord(value),
                DATA_TYPE_REG_DWORD_BE => RegValue::DWord(value.to_be()),
                _ => RegValue::DWord(value),
            });
        }

        let data_cell = borrow_hive.get_cell_or_native_at_offset(data_offset as u64)?;

        let reg_value = match data_type {
            DATA_TYPE_NONE => RegValue::DWord(0),
            DATA_TYPE_REG_SZ => match data_cell {
                HiveCell::Invalid(ic) => {
                    if flags & 1 == 0 {
                        RegValue::SZ(ic.into_reg_sz_ascii())
                    } else {
                        RegValue::SZ(ic.into_reg_sz_extended())
                    }
                }
                HiveCell::Unallocated(_) => RegValue::SZ(String::new()),
                _ => todo!(),
            },
            DATA_TYPE_REG_BINARY => match data_cell {
                HiveCell::Invalid(ic) => RegValue::Binary(ic.content.clone()),
                HiveCell::Unallocated(_) => RegValue::Binary(Vec::new()),
                _ => todo!(),
            },
            DATA_TYPE_REG_DWORD => match data_cell {
                HiveCell::Invalid(ic) => RegValue::DWord(ic.into_dword_le()),
                HiveCell::Unallocated(_) => RegValue::DWord(0),
                _ => todo!(),
            },
            DATA_TYPE_REG_DWORD_BE => match data_cell {
                HiveCell::Invalid(ic) => RegValue::DWord(ic.into_dword_be()),
                HiveCell::Unallocated(_) => RegValue::DWord(0),
                _ => todo!(),
            },
            DATA_TYPE_REG_QWORD => match data_cell {
                HiveCell::Invalid(ic) => RegValue::QWord(ic.into_qword_le()),
                HiveCell::Unallocated(_) => RegValue::QWord(0),
                _ => todo!(),
            },
            DATA_TYPE_REG_EXPAND_SZ => match data_cell {
                HiveCell::Invalid(ic) => {
                    if flags & 1 == 0 {
                        RegValue::SZ(ic.into_reg_sz_ascii())
                    } else {
                        RegValue::SZ(ic.into_reg_sz_extended())
                    }
                }
                HiveCell::Unallocated(_) => RegValue::SZ(String::new()),
                _ => todo!(),
            },
            _ => {
                println!("Need to implement data type {:?}", data_type);
                todo!()
            }
        };
        Ok(reg_value)
    }

    fn enumerate_values(&self, hkey: RegHiveKey) -> ForensicResult<Vec<String>> {
        let hkey = match hkey {
            RegHiveKey::HkeyUsers => return Ok(Vec::new()),
            RegHiveKey::HkeyLocalMachine => return self.list_hklm_values(),
            RegHiveKey::Hkey(hkey) => RegHiveKey::Hkey(hkey),
            _ => self.open_key(hkey, "")?,
        };
        let (mut borrow_hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(ForensicError::missing_str("Invalid hive")),
            SelectedHive::Sam(offset) => (
                self.sam
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SAM hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Security(offset) => (
                self.security
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SECURITY hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Software(offset) => (
                self.software
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SOFTWARE hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::System(offset) => (
                self.system
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SYSTEM hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Mounted(key_id) => {
                let a = self.cached_keys.borrow_mut();
                let _b = match a.get(&(key_id as isize)) {
                    Some(v) => v,
                    None => return Err(ForensicError::missing_str("Invalid mounted hive hive")),
                };
                //let value = self.mounted.borrow().get(b);
                todo!();
            }
            SelectedHive::Other((pos, offset)) => {
                let (_user_id, hive) = self
                    .others
                    .get(pos as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid Other hive"))?;
                (hive.borrow_mut(), offset)
            }
            SelectedHive::User((usr, offset)) => {
                let (_user_id, hive) = self
                    .users
                    .get(usr as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid User hive"))?;
                (hive.borrow_mut(), offset)
            }
        };
        if offset < 0 {
            return borrow_hive.enumerate_mounted_values(offset);
        }
        let offset = offset as u64;
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid Cell type at offset={}. Expected KeyNode",
                    offset
                )))
            }
        };
        let number_key_values = key_node.number_key_values;
        let key_values_list_offset = key_node.key_values_list_offset;
        let mut values_names = Vec::with_capacity(number_key_values as usize);
        let values_cell_list =
            borrow_hive.get_cell_or_native_at_offset(key_values_list_offset as u64)?;
        let mut offsets = Vec::with_capacity(number_key_values as usize);

        if let HiveCell::Invalid(ic) = values_cell_list {
            // Contains the list of offsets
            for i in (0..ic.content.len()).step_by(4) {
                let offset = u32::from_ne_bytes(ic.content[i..i + 4].try_into().unwrap());
                if offset > 0 {
                    offsets.push(offset);
                }
            }
        }
        for offset in offsets {
            let value_cell = match borrow_hive.get_cell_or_native_at_offset(offset as u64) {
                Ok(v) => v,
                Err(_) => continue,
            };
            match value_cell {
                HiveCell::KeyValue(kv) => {
                    values_names.push(kv.value_name.clone());
                }
                _ => continue,
            }
        }
        if values_names.len() > number_key_values as usize {
            notify_low!(
                NotificationType::SuspiciousArtifact,
                "There are more elements ({}) than the key indicates ({})",
                values_names.len(),
                number_key_values
            );
        }

        Ok(values_names)
    }

    fn enumerate_keys(&self, hkey: RegHiveKey) -> ForensicResult<Vec<String>> {
        let hkey = match hkey {
            RegHiveKey::HkeyUsers => {
                return Ok(self.users.iter().map(|(v, _)| v.clone()).collect())
            }
            RegHiveKey::HkeyLocalMachine => return self.list_hklm_keys(),
            _ => hkey,
        };
        let (mut borrow_hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(ForensicError::missing_str("Invalid hive")),
            SelectedHive::Sam(offset) => (
                self.sam
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SAM hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Security(offset) => (
                self.security
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SECURITY hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Software(offset) => (
                self.software
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SOFTWARE hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::System(offset) => (
                self.system
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SYSTEM hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Mounted(_) => todo!(),
            SelectedHive::Other((oth, offset)) => {
                let (_, hive) = self
                    .others
                    .get(oth as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid User hive"))?;
                (hive.borrow_mut(), offset)
            }
            SelectedHive::User((usr, offset)) => {
                let (_, hive) = self
                    .users
                    .get(usr as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid User hive"))?;
                (hive.borrow_mut(), offset)
            }
        };
        if offset < 0 {
            return borrow_hive.enumerate_mounted_keys(offset);
        }
        let offset = offset as u64;
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid Cell type at offset={}. Expected KeyNode",
                    offset
                )))
            }
        };
        let subkeys_list_offset = key_node.subkeys_list_offset;
        let mut subkeys = Vec::with_capacity(key_node.number_subkeys as usize);
        let mut offsets: Vec<u32> = match borrow_hive
            .get_cell_at_offset(subkeys_list_offset as u64)?
        {
            HiveCell::HashLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
            HiveCell::FastLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
            HiveCell::IndexLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
            HiveCell::IndexRoot(v) => v.elements.iter().map(|v| v.subkeys_list_offset).collect(),
            _ => {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid Cell type at offset={}. Expected Leaf type",
                    offset
                )))
            }
        };
        let mut pos = 0;
        while pos < offsets.len() {
            let offset = match offsets.get(pos) {
                Some(v) => *v,
                None => continue,
            };
            let cell = match borrow_hive.get_cell_at_offset(offset.into()) {
                Ok(v) => v,
                Err(err) => {
                    notify_informational!(
                        NotificationType::Informational,
                        "Error loading cell at offset={}. {:?}",
                        offset,
                        err
                    );
                    continue;
                }
            };
            match cell {
                HiveCell::KeyNode(v) => subkeys.push(v.key_name.clone()),
                HiveCell::IndexLeaf(v) => {
                    for el in &v.elements {
                        offsets.push(el.offset);
                    }
                }
                _ => continue,
            };
            pos += 1;
        }
        Ok(subkeys)
    }

    fn key_at(&self, hkey: RegHiveKey, pos: u32) -> ForensicResult<String> {
        let (hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(ForensicError::missing_str("Invalid hive")),
            SelectedHive::Sam(offset) => (
                self.sam
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SAM hive"))?,
                offset,
            ),
            SelectedHive::Security(offset) => (
                self.security
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SECURITY hive"))?,
                offset,
            ),
            SelectedHive::Software(offset) => (
                self.software
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SOFTWARE hive"))?,
                offset,
            ),
            SelectedHive::System(offset) => (
                self.system
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SYSTEM hive"))?,
                offset,
            ),
            SelectedHive::Mounted(_offset) => {
                todo!()
            }
            SelectedHive::User((pos, offset)) => {
                let (_, hive) = self
                    .users
                    .get(pos as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid User hive"))?;
                (hive, offset)
            }
            SelectedHive::Other((pos, offset)) => {
                let (_, hive) = self
                    .others
                    .get(pos as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid Other hive"))?;
                (hive, offset)
            }
        };
        let mut borrow_hive = hive.borrow_mut();
        if offset < 0 {
            return borrow_hive.get_mounted_key_at(offset);
        }
        let offset = offset as u64;
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid Cell type at offset={}. Expected KeyNode",
                    offset
                )))
            }
        };
        let subkeys_list_offset = key_node.subkeys_list_offset;
        let number_subkeys = key_node.number_subkeys;
        if pos >= number_subkeys {
            return Err(ForensicError::Other("Invalid position".into()));
        }
        let mut offsets: Vec<u32> = match borrow_hive
            .get_cell_at_offset(subkeys_list_offset as u64)?
        {
            HiveCell::HashLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
            HiveCell::FastLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
            HiveCell::IndexLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
            HiveCell::IndexRoot(v) => v.elements.iter().map(|v| v.subkeys_list_offset).collect(),
            _ => {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid Cell type at offset={}. Expected Leaf type",
                    offset
                )))
            }
        };
        let mut pos = pos as usize;
        while pos < offsets.len() {
            let offset = match offsets.get(pos) {
                Some(v) => *v,
                None => continue,
            };
            let cell = match borrow_hive.get_cell_at_offset(offset.into()) {
                Ok(v) => v,
                Err(err) => {
                    notify_informational!(
                        NotificationType::Informational,
                        "Error loading cell at offset={}. {:?}",
                        offset,
                        err
                    );
                    continue;
                }
            };
            match cell {
                HiveCell::KeyNode(v) => return Ok(v.key_name.clone()),
                HiveCell::IndexLeaf(v) => {
                    for el in &v.elements {
                        offsets.push(el.offset);
                    }
                }
                _ => continue,
            };
            pos += 1;
        }
        Err(ForensicError::NoMoreData)
    }

    fn value_at(&self, hkey: RegHiveKey, pos: u32) -> ForensicResult<String> {
        let (mut borrow_hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(ForensicError::missing_str("Invalid hive")),
            SelectedHive::Sam(offset) => (
                self.sam
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SAM hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Security(offset) => (
                self.security
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SECURITY hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Software(offset) => (
                self.software
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SOFTWARE hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::System(offset) => (
                self.system
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SYSTEM hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Mounted(_) => todo!(),
            SelectedHive::Other(_) => todo!(),
            SelectedHive::User((usr, offset)) => {
                let (_user_id, hive) = self
                    .users
                    .get(usr as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid User hive"))?;
                (hive.borrow_mut(), offset)
            }
        };
        if offset < 0 {
            return borrow_hive.get_mounted_value_at(offset);
        }
        let offset = offset as u64;
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid Cell type at offset={}. Expected HashLeaf",
                    offset
                )))
            }
        };
        let number_key_values = key_node.number_key_values;
        let key_values_list_offset = key_node.key_values_list_offset;
        let values_cell_list =
            borrow_hive.get_cell_or_native_at_offset(key_values_list_offset as u64)?;
        if pos >= number_key_values {
            return Err(ForensicError::Other("Invalid position".into()));
        }
        let pos = pos as usize;
        let value_offset = match values_cell_list {
            HiveCell::Invalid(ic) => {
                u32::from_ne_bytes(ic.content[pos * 4..(pos + 1) * 4].try_into().unwrap())
            }
            _ => return Err(ForensicError::bad_format_str("Invalid cell type")),
        };
        let value_cell = borrow_hive.get_cell_or_native_at_offset(value_offset as u64)?;
        match value_cell {
            HiveCell::KeyValue(kv) => Ok(kv.value_name.clone()),
            _ => {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid Cell type at offset={}. Expected KeyValue",
                    value_offset
                )))
            }
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

    fn key_info(&self, hkey: RegHiveKey) -> ForensicResult<forensic_rs::prelude::RegistryKeyInfo> {
        let (mut borrow_hive, offset) = match select_hive_by_hkey(hkey) {
            SelectedHive::None => return Err(ForensicError::missing_str("Invalid hive")),
            SelectedHive::Sam(offset) => (
                self.sam
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SAM hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Security(offset) => (
                self.security
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SECURITY hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Software(offset) => (
                self.software
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SOFTWARE hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::System(offset) => (
                self.system
                    .as_ref()
                    .ok_or_else(|| ForensicError::missing_str("Invalid SYSTEM hive"))?
                    .borrow_mut(),
                offset,
            ),
            SelectedHive::Mounted(key_id) => {
                let a = self.cached_keys.borrow_mut();
                let _b = match a.get(&(key_id as isize)) {
                    Some(v) => v,
                    None => return Err(ForensicError::missing_str("Invalid mounted hive hive")),
                };
                //let value = self.mounted.borrow().get(b);
                todo!();
            }
            SelectedHive::Other((pos, offset)) => {
                let (_user_id, hive) = self
                    .others
                    .get(pos as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid Other hive"))?;
                (hive.borrow_mut(), offset)
            }
            SelectedHive::User((usr, offset)) => {
                let (_user_id, hive) = self
                    .users
                    .get(usr as usize)
                    .ok_or_else(|| ForensicError::missing_str("Invalid User hive"))?;
                (hive.borrow_mut(), offset)
            }
        };
        if offset < 0 {
            // TODO: data not available for mounted keys/values
            return Ok(RegistryKeyInfo::default());
        }
        let offset = offset as u64;
        let cell = borrow_hive.get_cell_at_offset(offset)?;
        let key_node = match cell {
            HiveCell::KeyNode(v) => v,
            _ => {
                return Err(ForensicError::bad_format_string(format!(
                    "Invalid Cell type at offset={}. Expected KeyNode",
                    offset
                )))
            }
        };
        Ok(RegistryKeyInfo {
            last_write_time: Filetime::new(key_node.last_written_timestamp),
            max_subkey_name_length: key_node.largest_subkey_name_length as u32,
            max_value_length: key_node.largest_value_data_size,
            max_value_name_length: key_node.largest_value_name_length,
            subkeys: key_node.number_subkeys,
            values: key_node.number_key_values,
        })
    }
}

pub fn transform_key_with_type(key: u64, typ: u16) -> isize {
    ((key & 0xffffffffffff) | ((typ as u64) << 48)) as isize
}
pub fn transform_key_with_type_i(key: isize, typ: u16) -> isize {
    (key & 0xffffffffffff) | ((typ as u64) << 48) as isize
}
pub(crate) fn select_hive_by_hkey(key: RegHiveKey) -> SelectedHive {
    // When positive, the 16 most significative bits indicate wich hive to load. The rest are used for offsets in the file.
    // 32768 posible hives loaded into the reader. More than enough
    // Max offset = 48 bits = 2.8147498e+14 bytes
    match key {
        RegHiveKey::Hkey(ikey) => {
            let key_value = ikey as u64 & 0xffffffffffff;
            let key_type = (ikey >> 48) as u16;
            let key_type_u = key_type & 0x7fff;
            let is_mounted = (key_type as u64 >> 15) << 63;
            let key_value: i64 = (is_mounted | key_value) as i64;
            match key_type_u {
                HIVE_TYPE_NONE => SelectedHive::None,
                HIVE_TYPE_SAM => SelectedHive::Sam(key_value),
                HIVE_TYPE_SECURITY => SelectedHive::Security(key_value),
                HIVE_TYPE_SOFTWARE => SelectedHive::Software(key_value),
                HIVE_TYPE_SYSTEM => SelectedHive::System(key_value),
                HIVE_TYPE_CACHED => SelectedHive::Mounted(key_value),
                _ => {
                    let key_id = (key_type_u >> 1) - HIVE_TYPE_OTHERS;
                    let is_user = key_type_u & 0x1;
                    if is_user == 0 {
                        SelectedHive::Other((key_id, key_value))
                    } else {
                        SelectedHive::User((key_id, key_value))
                    }
                }
            }
        }
        _ => SelectedHive::None,
    }
}
pub(crate) fn user_hive_by_position(position: u16, offset: isize) -> RegHiveKey {
    let key_id = (position + HIVE_TYPE_OTHERS) << 1;
    let key_id = key_id | 0x01;
    RegHiveKey::Hkey(offset | (key_id as isize) << 48)
}
pub(crate) fn others_hive_by_position(position: u16, offset: isize) -> RegHiveKey {
    let key_id = (position + HIVE_TYPE_OTHERS) << 1;
    RegHiveKey::Hkey(offset | (key_id as isize) << 48)
}

pub fn open_hive_with_logs(
    fs: &mut Box<dyn forensic_rs::traits::vfs::VirtualFileSystem>,
    base_path: &Path,
    name: &str,
) -> Option<HiveFiles> {
    let primary_path = base_path.join(name);
    let primary = fs.open(primary_path.as_path()).ok()?;
    let mut hive = HiveFiles::new(primary_path, primary).ok()?;
    let log_1 = base_path.join(format!("{}.LOG1", name));
    match fs.open(log_1.as_path()) {
        Ok(v) => {
            hive.logs.push(v);
        }
        Err(e) => {
            debug!(
                "Cannot open hive {}: {:?}",
                log_1.to_str().unwrap_or_default(),
                e
            );
        }
    };
    let log_2 = base_path.join(format!("{}.LOG2", name));
    match fs.open(log_2.as_path()) {
        Ok(v) => {
            hive.logs.push(v);
        }
        Err(e) => {
            debug!(
                "Cannot open hive {}: {:?}",
                log_2.to_str().unwrap_or_default(),
                e
            );
        }
    };
    Some(hive)
}

#[cfg(test)]
#[path = "reader_tst.rs"]
mod tst;
