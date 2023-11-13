use std::{collections::BTreeMap, path::PathBuf, cell::RefCell};

use forensic_rs::{traits::vfs::VirtualFile, prelude::{RegHiveKey, RegValue, RegistryReader, ForensicError, HKLM}};

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
            key_counter : RefCell::new(0)
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
        let ret : isize = *self.key_counter.borrow();
        self.key_counter.replace(ret + 1);
        ret
    }
}

pub struct HiveFiles {
    pub(crate) location : PathBuf,
    pub(crate) primary : Box<dyn VirtualFile>,
    pub(crate) logs : Vec<Box<dyn VirtualFile>>
}


impl RegistryReader for HiveRegistryReader {
    fn from_file(&self, file: Box<dyn VirtualFile>) -> forensic_rs::prelude::ForensicResult<Box<dyn RegistryReader>> {
        todo!()
    }

    fn from_fs(&self, fs: Box<dyn forensic_rs::traits::vfs::VirtualFileSystem>) -> forensic_rs::prelude::ForensicResult<Box<dyn RegistryReader>> {
        todo!()
    }

    fn open_key(&self, hkey: RegHiveKey, key_name: &str) -> forensic_rs::prelude::ForensicResult<RegHiveKey> {
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
                    let mut cached = self.cached_keys.borrow_mut();
                    let new_key = self.next_key();
                    cached.insert(new_key, format!("HKEY_LOCAL_MACHINE\\{}", key_name));
                    return Ok(RegHiveKey::Hkey(new_key))
                };
                let hive = match hive.try_borrow_mut() {
                    Ok(v) => v,
                    Err(e) => return Err(forensic_rs::prelude::ForensicError::Other(format!("Error reading user key: {:?}", e))),
                };
                
                Err(forensic_rs::prelude::ForensicError::Missing)
            },
            RegHiveKey::HkeyUsers => {
                let users = match self.users.try_borrow_mut() {
                    Ok(v) => v,
                    Err(e) => return Err(forensic_rs::prelude::ForensicError::Other(format!("Error reading user key: {:?}", e))),
                };
                let mut path_separator = key_name.split(|v| v == '/' || v == '\\');
                let username = path_separator.next().ok_or_else(|| forensic_rs::prelude::ForensicError::BadFormat)?;
                let user_data = users.get(username).ok_or_else(missing_key)?;

                Err(forensic_rs::prelude::ForensicError::Missing)
            },
            _ => Err(forensic_rs::prelude::ForensicError::Missing)
        }
    }

    fn read_value(&self, hkey: RegHiveKey, value_name: &str) -> forensic_rs::prelude::ForensicResult<RegValue> {
        todo!()
    }

    fn enumerate_values(&self, hkey: RegHiveKey) -> forensic_rs::prelude::ForensicResult<Vec<String>> {
        todo!()
    }

    fn enumerate_keys(&self, hkey: RegHiveKey) -> forensic_rs::prelude::ForensicResult<Vec<String>> {
        todo!()
    }

    fn key_at(&self, hkey: RegHiveKey, pos: u32) -> forensic_rs::prelude::ForensicResult<String> {
        todo!()
    }

    fn value_at(&self, hkey: RegHiveKey, pos: u32) -> forensic_rs::prelude::ForensicResult<String> {
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
        assert_eq!(RegHiveKey::Hkey(0), key);
        reader.close_key(key);
    }
}

