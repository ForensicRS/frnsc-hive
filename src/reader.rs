use std::{collections::BTreeMap, path::PathBuf, cell::RefCell};

use forensic_rs::{traits::vfs::VirtualFile, prelude::{RegHiveKey, RegValue, RegistryReader, ForensicError, HKLM, ForensicResult}};

use crate::{hive::{BaseBlock, read_base_block, read_hive_bin_at_file_position, HiveBinHeader, read_cells}, cell::{HiveCell, IndexRootCell, read_cell, KeyNodeCell, HashLeafCell}, cell_cache::CellCache};

pub struct HiveRegistryReader {
    /// HKEY_CURRENT_CONFIG: System, System.alt, System.log, System.sav
    current_config : Option<RefCell<HiveFiles>>,
    /// HKEY_USERS Default, Default.log, Default.sav Ntuser.dat, Ntuser.dat.log
    users : RefCell<BTreeMap<String, HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\SAM 	Sam, Sam.log, Sam.sav
    sam : Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\Security 	Security, Security.log, Security.sav
    security : Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\Software 	Software, Software.log, Software.sav
    software : Option<RefCell<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\System 	System, System.alt, System.log, System.sav
    system : Option<RefCell<HiveFiles>>,
    /// Mount reg files
    mounted : RefCell<MountedMap>,
    cached_keys : RefCell<BTreeMap<isize, String>>,
    key_counter : RefCell<isize>

}

pub type MountedMap = BTreeMap<String, BTreeMap<String, BTreeMap<String, RegValue>>>;
fn missing_key() -> ForensicError{
    ForensicError::Missing
}

pub struct HiveReader {
    pub files : HiveFiles,
    pub opened_keys : BTreeMap<RegHiveKey, RegValue>
}

impl HiveRegistryReader {
    pub fn new() -> Self {
        Self {
            current_config: None,
            users: RefCell::new(BTreeMap::new()),
            sam: None,
            security: None,
            software: None,
            system: None,
            mounted : RefCell::new(BTreeMap::new()),
            cached_keys : RefCell::new(BTreeMap::new()),
            key_counter : RefCell::new(-1)
        }
    }
    
    pub fn set_sam(&mut self, hive : HiveFiles) {
        self.sam = Some(RefCell::new(hive));
    }
    pub fn set_security(&mut self, hive : HiveFiles) {
        self.security = Some(RefCell::new(hive));
    }
    pub fn set_software(&mut self, hive : HiveFiles) {
        self.software = Some(RefCell::new(hive));
    }
    pub fn set_system(&mut self, hive : HiveFiles) {
        self.system = Some(RefCell::new(hive));
    }
    pub fn set_current_config(&mut self, hive : HiveFiles) {
        self.current_config = Some(RefCell::new(hive));
    }
    pub fn add_user(&mut self, user : &str, hive: HiveFiles) {
        self.users.borrow_mut().insert(user.into(), hive);
    }
    pub fn add_reg_key(&mut self, path : &str, value : &str, data : RegValue) {
        let mut mounted = self.mounted.borrow_mut();
        let (hkey, path) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return
        };
        let path_map = mounted.entry(hkey.into()).or_insert(BTreeMap::new());
        let value_map = path_map.entry(path.into()).or_insert(BTreeMap::new());
        value_map.insert(value.into(), data);
    }
    pub fn add_reg_file(&mut self, _data : String) {
        todo!()
    }

    fn next_key(&self) -> isize {
        let mut ret : isize = *self.key_counter.borrow();
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

pub struct HiveFiles {
    pub(crate) location : PathBuf,
    pub(crate) primary : Box<dyn VirtualFile>,
    pub(crate) base_block : BaseBlock,
    pub(crate) root_cell : Option<IndexRootCell>,
    pub(crate) logs : Vec<Box<dyn VirtualFile>>,
    pub(crate) cell_cache : CellCache,
    pub(crate) buffer : Vec<u8>
}

impl HiveFiles {
    pub fn new(location : PathBuf, mut primary : Box<dyn VirtualFile>) -> ForensicResult<Self> {
        let base_block = read_base_block(&mut primary)?;
        let offset = 4096 + base_block.root_cell_offset as u64 - 32;
        let root_cell = primary.seek(std::io::SeekFrom::Start(offset))?;
        let (hive_bin, data) = read_hive_bin_at_file_position(&mut primary)?;
        let cells = read_cells(&data, 32)?;
        let mut cell_cache = CellCache::new(2048);
        for cell in cells {
            cell_cache.insert_fixed(cell);
        }
        Ok(Self {
            location,
            base_block,
            primary,
            root_cell : None,
            logs : Vec::with_capacity(8),
            cell_cache,
            buffer : vec![0u8; 4096]
        })
    }
    pub fn open_key(&mut self, key_name: &str) -> ForensicResult<isize> {
        let mut path_separator = key_name.split(|v| v == '/' || v == '\\');
        let root_cell = self.get_root_cell()?;
        println!("RootCell {:?}", root_cell);
        let subkeys_offset = root_cell.subkeys_list_offset;
        let n_subkeys = root_cell.number_subkeys;
        let n_key_val = root_cell.number_key_values;
        let first = match path_separator.next() {
            Some(v) => v,
            None => return Ok(32) // Root Cell
        };
        let first_hash = HashLeafCell::hash_name(first);
        if n_subkeys > 0 {
            let subkeys = self.get_cell_at_offset(subkeys_offset as u64)?;
            match subkeys {
                HiveCell::HashLeaf(hl) => {
                    for el in &hl.elements {
                        if first_hash == el.name_hash {
                            println!("Found {}", first_hash);
                        }
                    }
                },
                _=> return Err(missing_key())
            }
            println!("{:?}", subkeys);
        }

        Ok(0)
    }

    pub fn get_root_cell(&self) -> ForensicResult<&KeyNodeCell> {
        let cell = self.cell_cache.get(32).ok_or_else(missing_key)?;
        
        let kn = match cell {
            HiveCell::KeyNode(ir) => ir,
            _ => return Err(missing_key())
        };
        if kn.key_name != "ROOT" {
            return Err(ForensicError::Missing)
        }
        Ok(kn)
    }
    pub fn get_cell_at_offset(&mut self, offset : u64) -> ForensicResult<&HiveCell> {
        if self.cell_cache.contains(offset) {
            return Ok(self.cell_cache.get(offset).unwrap())
        }
        self.primary.seek(std::io::SeekFrom::Start(self.index_root_offset() + offset))?;
        let readed = self.primary.read(&mut self.buffer)?;
        let cell = read_cell(&self.buffer[0..readed], offset)?;
        self.cell_cache.insert(cell);
        match self.cell_cache.get(offset) {
            Some(cell) => {
                return Ok(cell)
            },
            None => return Err(ForensicError::Missing)
        };
    }

    fn index_root_offset(&self) -> u64 {
        4064 + self.base_block.root_cell_offset as u64
    }
}


impl RegistryReader for HiveRegistryReader {
    fn from_file(&self, file: Box<dyn VirtualFile>) -> ForensicResult<Box<dyn RegistryReader>> {
        todo!()
    }

    fn from_fs(&self, fs: Box<dyn forensic_rs::traits::vfs::VirtualFileSystem>) ->ForensicResult<Box<dyn RegistryReader>> {
        todo!()
    }

    fn open_key(&self, hkey: RegHiveKey, key_name: &str) -> ForensicResult<RegHiveKey> {
        match hkey {
            RegHiveKey::HkeyLocalMachine => {
                let mut path_separator = key_name.split(|v| v == '/' || v == '\\');
                let first_key =  path_separator.next().ok_or_else(missing_key)?;
                let hive = if first_key == "SAM" {
                    self.sam.as_ref().ok_or_else(missing_key)?
                }else if first_key == "SECURITY" {
                    self.security.as_ref().ok_or_else(missing_key)?
                }else if first_key == "SOFTWARE" {
                    self.software.as_ref().ok_or_else(missing_key)?
                }else if first_key == "SYSTEM" {
                    self.system.as_ref().ok_or_else(missing_key)?
                }else {
                    let h = match self.mounted.try_borrow() {
                        Ok(v) => v,
                        Err(e) => return Err(forensic_rs::prelude::ForensicError::Other(format!("Error reading user key: {:?}", e))),
                    };
                    let lm = h.get("HKEY_LOCAL_MACHINE").ok_or_else(missing_key)?;
                    let path_values = lm.get(key_name).ok_or_else(missing_key)?;
                    let new_key = self.next_key();
                    let mut cached = self.cached_keys.borrow_mut();
                    cached.insert(new_key, format!("HKEY_LOCAL_MACHINE\\{}", key_name));
                    return Ok(RegHiveKey::Hkey(new_key))
                };
                let mut hive = match hive.try_borrow_mut() {
                    Ok(v) => v,
                    Err(e) => return Err(forensic_rs::prelude::ForensicError::Other(format!("Error reading user key: {:?}", e))),
                };
                let hive_key = hive.open_key(key_name)?;
                Ok(RegHiveKey::Hkey(hive_key))
            },
            RegHiveKey::HkeyUsers => {
                let users = match self.users.try_borrow_mut() {
                    Ok(v) => v,
                    Err(e) => return Err(forensic_rs::prelude::ForensicError::Other(format!("Error reading user key: {:?}", e))),
                };
                let mut path_separator = key_name.split(|v| v == '/' || v == '\\');
                let username = path_separator.next().ok_or_else(||ForensicError::BadFormat)?;
                let user_data = users.get(username).ok_or_else(missing_key)?;

                Err(forensic_rs::prelude::ForensicError::Missing)
            },
            _ => Err(forensic_rs::prelude::ForensicError::Missing)
        }
    }

    fn read_value(&self, hkey: RegHiveKey, value_name: &str) ->ForensicResult<RegValue> {
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
                None => return Err(missing_key())
            };
            let mounted = self.mounted.borrow();
            let path_map = mounted.get(hkey).ok_or_else(missing_key)?;
            let value_map = path_map.get(path).ok_or_else(missing_key)?;
            let value = value_map.get(value_name).ok_or_else(missing_key)?;
            return Ok(value.clone())
        }else {
            // When positive, the 16 most significative bits indicate wich hive to load. The rest are used for offsets in the file.
            // 32768 posible hives loaded into the reader. More than enough
            // Max offset = 48 bits = 2.8147498e+14 bytes


        }
        
        todo!()
    }

    fn enumerate_values(&self, hkey: RegHiveKey) ->ForensicResult<Vec<String>> {
        todo!()
    }

    fn enumerate_keys(&self, hkey: RegHiveKey) ->ForensicResult<Vec<String>> {
        todo!()
    }

    fn key_at(&self, hkey: RegHiveKey, pos: u32) ->ForensicResult<String> {
        todo!()
    }

    fn value_at(&self, hkey: RegHiveKey, pos: u32) ->ForensicResult<String> {
        todo!()
    }
    fn close_key(&self, hkey : RegHiveKey) {
        let hkey = match hkey {
            RegHiveKey::Hkey(v) => v,
            _ => return,
        };
        let mut cached = self.cached_keys.borrow_mut();
        cached.remove(&hkey);
    }
}

#[cfg(test)]
mod tst {
    use super::*;
    use forensic_rs::notifications;

    use crate::{tst::*, hive::read_base_block};


    #[test]
    fn read_hive_bin() {
        let recv = notifications::testing_notifier_dummy();
        let mut fs = init_virtual_fs();
        let mut sam_file = read_sam_hive(&mut fs);
        let base_block = read_base_block(&mut sam_file).unwrap();
        sam_file.seek(std::io::SeekFrom::Start(4096 + base_block.root_cell_offset as u64)).unwrap();
        // Checksum is correct = Empty
        recv.try_recv().unwrap_err();
    }
    #[test]
    fn should_cache_reg_value() {
        let mut reader = HiveRegistryReader::new();
        reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System", r"Identifier", RegValue::SZ(r"AT/AT COMPATIBLE".into()));
        let key = reader.open_key(HKLM, r"HARDWARE\DESCRIPTION\System").unwrap();
        assert_eq!(RegHiveKey::Hkey(-1), key);
        assert_eq!(RegValue::SZ(r"AT/AT COMPATIBLE".into()), reader.read_value(key, "Identifier").unwrap());
        reader.close_key(key);
    }

    #[test]
    fn should_open_keys_in_sam_hive() {
        let mut reader = HiveRegistryReader::new();
        let mut fs = init_virtual_fs();
        let sam_file = read_sam_hive(&mut fs);
        reader.set_sam(HiveFiles::new(PathBuf::new(), sam_file).unwrap());
        let key = reader.open_key(HKLM, r"SAM").unwrap();
        reader.close_key(key);
    }
}

