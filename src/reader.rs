//! Implements [forensic_rs::traits::registry::Registry] on top of parsed hive files.
//!
//! ## Layering
//!
//! [HiveRegistryReader] is the public entry point. It aggregates one [HiveFiles] per loaded
//! hive (SAM/SECURITY/SOFTWARE/SYSTEM, one per user's `NTUSER.DAT`, and any "other" mounted
//! `.hve` file), plus a [MountedMap] for keys/values injected from parsed REG files that don't
//! belong to any loaded hive. Each [HiveFiles] owns the open file handle, the parsed
//! [crate::hive::BaseBlock], the root [crate::cell::KeyNodeCell], and a [CellCache] that avoids
//! re-parsing cells already read from disk.
//!
//! ## Opaque key handles
//!
//! [forensic_rs::prelude::RawKey] is a plain opaque `u64` whose interpretation is entirely up to
//! this backend. [pack_raw_key]/[unpack_raw_key] bit-pack a [HiveKind] (which hive a key belongs
//! to) together with either a cell offset within that hive, or — for [HiveKind::User]/
//! [HiveKind::Other] — a position into [HiveRegistryReader::users]/`others`, or — for
//! [HiveKind::Cached] — an id into `cached_keys`. [HiveRegistryReader::hive_for_kind] is the
//! single place that turns a decoded real-hive [HiveKind] into the right [HiveFiles].
//!
//! ## Known gaps
//!
//! Mounted-key interaction *within* an already-open [HiveFiles] (as opposed to the top-level
//! [MountedMap]) is only partially wired: [HiveFiles::open_mounted_key] is a stub that returns a
//! "not implemented" error, and REG-file import (`add_reg_file`) is not implemented either. See
//! the crate README for the current feature-completeness caveats.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, MutexGuard},
};

use forensic_rs::prelude::*;

use crate::{
    cell::{peek_cell, read_cell, HashLeafCell, HiveCell, KeyNodeCell},
    cell_cache::CellCache,
    consts::{HIVE_BASE_BLOCK_SIZE, ROOT_CELL_OFFSET},
    hive::{read_base_block, read_cells, read_hive_bin_at_file_position, BaseBlock},
    mounted_map::MountedMap,
};

const DATA_TYPE_NONE: u32 = 0x0;
const DATA_TYPE_REG_SZ: u32 = 0x1;
const DATA_TYPE_REG_EXPAND_SZ: u32 = 0x2;
const DATA_TYPE_REG_BINARY: u32 = 0x03;
const DATA_TYPE_REG_DWORD: u32 = 0x04;
const DATA_TYPE_REG_DWORD_BE: u32 = 0x05;
const DATA_TYPE_REG_QWORD: u32 = 0xb;

/// Implements [Registry] from Hive files.
///
/// ```
/// use forensic_rs::prelude::*;
/// use frnsc_hive::reader::HiveRegistryReader;
/// use std::sync::Arc;
/// // Chroot at the fixture's `C:\` drive folder — `ChRootFileSystem` drops a path's leading
/// // drive/root component entirely, so an evidence path like `C:\Windows\System32\Config` still
/// // resolves under whatever this chroot is rooted at.
/// let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C/", Arc::new(StdVirtualFS::new())));
/// // The hive registry reader searches for hives in C:\Windows\System32\Config
/// let reader = HiveRegistryReader::from_fs(fs).unwrap();
/// ```
pub struct HiveRegistryReader {
    /// HKEY_CURRENT_CONFIG: System, System.alt, System.log, System.sav
    current_config: Option<Mutex<HiveFiles>>,
    /// HKEY_USERS Default, Default.log, Default.sav Ntuser.dat, Ntuser.dat.log
    /// List with the name of the user and the Hive files
    users: Vec<(String, Mutex<HiveFiles>)>,
    /// HKEY_LOCAL_MACHINE\SAM Sam, Sam.log, Sam.sav
    sam: Option<Mutex<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\Security Security, Security.log, Security.sav
    security: Option<Mutex<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\Software Software, Software.log, Software.sav
    software: Option<Mutex<HiveFiles>>,
    /// HKEY_LOCAL_MACHINE\System System, System.alt, System.log, System.sav
    system: Option<Mutex<HiveFiles>>,
    /// Mount reg files
    mounted: Mutex<MountedMap>,
    /// Associate a cached-key id with a path for the mounted registry keys
    cached_keys: Mutex<BTreeMap<u64, String>>,
    key_counter: Mutex<u64>,
    /// Other mounted hives
    others: Vec<(String, Mutex<HiveFiles>)>,
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
    /// use forensic_rs::prelude::*;
    /// use frnsc_hive::reader::HiveRegistryReader;
    /// use std::sync::Arc;
    /// let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C/", Arc::new(StdVirtualFS::new())));
    /// let reader = HiveRegistryReader::from_fs(fs).unwrap();
    /// ```
    pub fn from_fs(fs: Arc<dyn FileSystem>) -> ForensicResult<Box<dyn Registry>> {
        let config_folder = FPath::new("C:\\Windows\\System32\\Config");
        HiveRegistryReaderFactory.open(fs, config_folder)
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
            mounted: Mutex::new(MountedMap::new()),
            cached_keys: Mutex::new(BTreeMap::new()),
            key_counter: Mutex::new(0),
        }
    }

    /// Searches and loads all the users that have hives, using the SOFTWARE hive's
    /// **ProfileList** key correlated against `HKEY_USERS` (via
    /// [forensic_rs::traits::registry::windows::users]).
    pub fn load_user_hives(&mut self, fs: &Arc<dyn FileSystem>) -> ForensicResult<()> {
        let profiles = windows::users(&*self)?;
        for profile in profiles {
            if profile.profile_path.as_str().is_empty() {
                continue;
            }
            let hive = match open_hive_with_logs(fs, profile.profile_path.as_path(), "NTUSER.DAT") {
                Some(v) => v,
                None => {
                    warn!(
                        "Cannot find hive {}\\NTUSER.DAT for user {}",
                        profile.profile_path, profile.sid
                    );
                    continue;
                }
            };
            self.add_user(&profile.sid, hive);
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
        self.sam = Some(Mutex::new(hive));
    }
    /// Sets the SECURITY HIVE
    pub fn set_security(&mut self, hive: HiveFiles) {
        trace!("Loaded Security hive");
        self.security = Some(Mutex::new(hive));
    }
    /// Sets the SOFTWARE HIVE
    pub fn set_software(&mut self, hive: HiveFiles) {
        trace!("Loaded Software hive");
        self.software = Some(Mutex::new(hive));
    }
    /// Sets the SYSTEM HIVE
    pub fn set_system(&mut self, hive: HiveFiles) {
        trace!("Loaded System hive");
        self.system = Some(Mutex::new(hive));
    }
    /// Sets the CurrentConfig HIVE
    pub fn set_current_config(&mut self, hive: HiveFiles) {
        self.current_config = Some(Mutex::new(hive));
    }
    /// Adds a User HIVE. The user parameter must be the GUID of the user.
    pub fn add_user(&mut self, user: &str, hive: HiveFiles) {
        trace!("Added user {} hive", user);
        self.users.push((user.into(), Mutex::new(hive)));
    }
    /// Adds a any HIVE file. The user parameter must be the GUID of the user.
    pub fn add_other(&mut self, mount_path: &str, hive: HiveFiles) {
        trace!("Added other {} hive", mount_path);
        self.others.push((mount_path.into(), Mutex::new(hive)));
    }
    /// Adds a registry key extracted from a REG file
    /// ```
    /// use frnsc_hive::reader::HiveRegistryReader;
    /// use forensic_rs::prelude::{RegValue, RegistryExt};
    /// let mut reader = HiveRegistryReader::new();
    /// reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System", r"Identifier", RegValue::SZ(r"AT/AT COMPATIBLE".into()));
    /// let key = reader.key(r"HKLM\HARDWARE\DESCRIPTION\System").unwrap();
    /// assert_eq!(RegValue::SZ(r"AT/AT COMPATIBLE".into()), key.value("Identifier").unwrap());
    /// ```
    pub fn add_reg_key(&mut self, full_path: &str, value: &str, data: RegValue) {
        let (hkey, path) = match full_path.split_once(['/', '\\']) {
            Some(v) => v,
            None => return,
        };
        if hkey == "HKEY_LOCAL_MACHINE" {
            let mut splited = path.split(['/', '\\']);
            if let Some(first_key) = splited.next() {
                if first_key == "SAM" && self.sam.is_some() {
                    self.sam.as_ref().inspect(|hive| {
                        hive.lock().unwrap().add_mounted_value(full_path, value, data);
                    });
                    return;
                } else if first_key == "SECURITY" && self.security.is_some() {
                    self.security.as_ref().inspect(|hive| {
                        hive.lock().unwrap().add_mounted_value(full_path, value, data);
                    });
                    return;
                } else if first_key == "SYSTEM" && self.system.is_some() {
                    self.system.as_ref().inspect(|hive| {
                        hive.lock().unwrap().add_mounted_value(full_path, value, data);
                    });
                    return;
                } else if first_key == "SOFTWARE" && self.software.is_some() {
                    self.software.as_ref().inspect(|hive| {
                        hive.lock().unwrap().add_mounted_value(full_path, value, data);
                    });
                    return;
                }
            }
        } else if hkey == "HKEY_USERS" {
            let mut splited = path.split(['/', '\\']);
            if let Some(first_key) = splited.next() {
                for (guid, hive) in &self.users {
                    if first_key == guid {
                        return hive.lock().unwrap().add_mounted_value(full_path, value, data);
                    }
                }
            }
        }
        let mut mounted = self.mounted.lock().unwrap();
        mounted.add_value(full_path, value, data);
    }
    pub fn add_reg_file(&mut self, _data: String) -> ForensicResult<()> {
        Err(not_implemented("add_reg_file (REG file import)"))
    }

    /// Returns a [RawKey] for the root of a real hive file loaded via [Self::add_other],
    /// addressed by the mount path it was registered under. [PredefinedHive] has no raw-handle
    /// escape variant (unlike the legacy `RegHiveKey::Hkey`), so an "other" hive isn't reachable
    /// through [Registry::root] — this is a `HiveRegistryReader`-specific extension instead,
    /// usable by any caller holding a concrete `HiveRegistryReader` (not a generic `dyn Registry`).
    pub fn other_hive_root(&self, mount_path: &str) -> ForensicResult<RawKey> {
        let position = self
            .others
            .iter()
            .position(|(name, _)| name == mount_path)
            .ok_or_else(|| {
                ForensicError::missing_data("hive", format!("Cannot find mounted HVE file {mount_path}").into())
            })?;
        let (_, hive) = &self.others[position];
        let root_offset = match hive.try_lock() {
            Ok(v) => v.root_cell.offset,
            Err(_) => ROOT_CELL_OFFSET,
        };
        Ok(pack_raw_key(HiveKind::Other(position as u16), root_offset))
    }

    /// Confirms `id` refers to a currently-registered [MountedMap] path, returning the same
    /// "invalid handle" error every [HiveKind::Cached]-handling `Registry` method surfaces for an
    /// unregistered/stale id — checked *before* any "not implemented" response, so a caller can't
    /// tell an unregistered handle apart from a registered-but-unsupported operation by probing.
    fn require_cached_key(&self, id: u64) -> ForensicResult<()> {
        self.cached_keys
            .lock()
            .unwrap()
            .contains_key(&id)
            .then_some(())
            .ok_or_else(|| ForensicError::registry_invalid_handle(id as i64))
    }

    fn next_cached_id(&self) -> u64 {
        let mut counter = self.key_counter.lock().unwrap();
        loop {
            let candidate = *counter;
            *counter = counter.wrapping_add(1);
            if !self.cached_keys.lock().unwrap().contains_key(&candidate) {
                return candidate;
            }
        }
    }

    /// Resolves a real-hive-backed [HiveKind] (everything except the synthetic [HiveKind::LmRoot]/
    /// [HiveKind::UsersRoot]/[HiveKind::Cached]) to its underlying [HiveFiles].
    fn hive_for_kind(&self, kind: HiveKind) -> ForensicResult<&Mutex<HiveFiles>> {
        match kind {
            HiveKind::Sam => self
                .sam
                .as_ref()
                .ok_or_else(|| ForensicError::registry_key_not_found(PredefinedHive::LocalMachine, Some("SAM".into()))),
            HiveKind::Security => self.security.as_ref().ok_or_else(|| {
                ForensicError::registry_key_not_found(PredefinedHive::LocalMachine, Some("SECURITY".into()))
            }),
            HiveKind::Software => self.software.as_ref().ok_or_else(|| {
                ForensicError::registry_key_not_found(PredefinedHive::LocalMachine, Some("SOFTWARE".into()))
            }),
            HiveKind::System => self.system.as_ref().ok_or_else(|| {
                ForensicError::registry_key_not_found(PredefinedHive::LocalMachine, Some("SYSTEM".into()))
            }),
            HiveKind::CurrentConfig => self
                .current_config
                .as_ref()
                .ok_or_else(|| ForensicError::registry_key_not_found(PredefinedHive::CurrentConfig, None)),
            HiveKind::User(pos) => self
                .users
                .get(pos as usize)
                .map(|(_, h)| h)
                .ok_or_else(|| ForensicError::registry_invalid_handle(pos as i64)),
            HiveKind::Other(pos) => self
                .others
                .get(pos as usize)
                .map(|(_, h)| h)
                .ok_or_else(|| ForensicError::registry_invalid_handle(pos as i64)),
            HiveKind::LmRoot | HiveKind::UsersRoot | HiveKind::Cached => {
                Err(ForensicError::other("registry", "not a real-hive-backed key".to_string()))
            }
        }
    }

    /// Dispatches a key opened relative to [PredefinedHive::LocalMachine]: `SAM`/`SECURITY`/
    /// `SOFTWARE`/`SYSTEM` delegate into that hive's own tree (its root cell's single relevant
    /// child conventionally shares the hive's mount name — e.g. the SAM hive's true root has one
    /// child literally named `"SAM"` — so the un-stripped path is passed straight through for all
    /// but `SOFTWARE`, which historically strips its own leading segment); anything else falls
    /// back to a top-level REG-injected ([MountedMap]) key under `HKEY_LOCAL_MACHINE`.
    fn open_under_lm(&self, key_name: &str) -> ForensicResult<RawKey> {
        let (first_key, _rest) = key_name.split_once(['/', '\\']).unwrap_or((key_name, ""));
        if first_key == "SAM" {
            return self.open_in_kind(HiveKind::Sam, key_name);
        } else if first_key == "SECURITY" {
            return self.open_in_kind(HiveKind::Security, key_name);
        } else if first_key == "SOFTWARE" {
            let sub_path = key_name.get(first_key.len() + 1..).unwrap_or("");
            return self.open_in_kind(HiveKind::Software, sub_path);
        } else if first_key == "SYSTEM" {
            return self.open_in_kind(HiveKind::System, key_name);
        }
        let full_path = format!("HKEY_LOCAL_MACHINE\\{key_name}");
        let is_mounted = self
            .mounted
            .try_lock()
            .map_err(|e| ForensicError::other("registry", format!("Error reading mounted keys: {e:?}")))?
            .contains(&full_path);
        if is_mounted {
            let id = self.next_cached_id();
            self.cached_keys.lock().unwrap().insert(id, full_path);
            return Ok(pack_raw_key(HiveKind::Cached, id));
        }
        Err(ForensicError::registry_key_not_found(PredefinedHive::LocalMachine, Some(key_name.into())))
    }

    fn open_under_users(&self, key_name: &str) -> ForensicResult<RawKey> {
        let (username, rest_of_path) = key_name.split_once(['/', '\\']).unwrap_or((key_name, ""));
        let position = self
            .users
            .iter()
            .position(|(name, _)| name == username)
            .ok_or_else(|| ForensicError::registry_key_not_found(PredefinedHive::Users, Some(username.into())))?;
        let (_, hive) = &self.users[position];
        let mut h = try_lock_hive(hive)?;
        let offset = h.open_key_from_offset(rest_of_path, ROOT_CELL_OFFSET as i64)?;
        Ok(pack_raw_key(HiveKind::User(position as u16), offset as u64))
    }

    fn open_in_kind(&self, kind: HiveKind, key_name: &str) -> ForensicResult<RawKey> {
        let hive = self.hive_for_kind(kind)?;
        let mut h = try_lock_hive(hive)?;
        let offset = h.open_key_from_offset(key_name, ROOT_CELL_OFFSET as i64)?;
        Ok(pack_raw_key(kind, offset as u64))
    }
}

/// Marks a code path that is recognized but intentionally not yet implemented
/// (as opposed to malformed/missing data). Centralizes the wording so these
/// spots stay greppable until the feature is actually built.
fn not_implemented(feature: &str) -> ForensicError {
    ForensicError::other("registry", format!("{feature} is not implemented yet"))
}

/// Locks a hive without blocking (`try_lock`, not `lock`) so a re-entrant lock attempt (e.g. a
/// key or lazy iterator from the same hive still open elsewhere) returns a descriptive
/// [ForensicError] immediately instead of deadlocking — `std::sync::Mutex` is not reentrant, and
/// blocking here would silently hang instead of erroring.
fn try_lock_hive(hive: &Mutex<HiveFiles>) -> ForensicResult<MutexGuard<'_, HiveFiles>> {
    hive.try_lock()
        .map_err(|e| ForensicError::other("registry", format!("Error locking hive: {e:?}")))
}

/// Parses the raw bytes of a `KeyValue`s-list `Invalid` cell into the 4-byte-aligned `u32`
/// offsets it contains. A byte length that isn't a multiple of 4 means the cell's declared size
/// doesn't align to 4-byte offset entries — a corruption signal in its own right — so this
/// returns an `Err` rather than silently truncating the trailing partial entry.
fn parse_offsets_list(content: &[u8]) -> ForensicResult<Vec<u32>> {
    if !content.len().is_multiple_of(4) {
        return Err(ForensicError::registry_cell_error(
            "key_values_offsets_list",
            format!(
                "offsets-list cell length {} is not a multiple of 4 (declared size doesn't align to 4-byte entries)",
                content.len()
            ),
        ));
    }
    Ok(content
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

fn unallocated_value_error(data_type: u32, data_offset: u32) -> ForensicError {
    ForensicError::registry_cell_error(
        "key_value_data",
        format!(
            "data cell at offset={data_offset} for data_type={data_type} is unallocated (deleted/reused) - cannot reliably decode"
        ),
    )
}

/// Builds the error returned when a value's data cell isn't one of the cell types that can
/// actually hold decodable value data (`Invalid`/`Unallocated`) for the given `data_type`.
fn unexpected_value_cell(data_type: u32, data_offset: u32, cell: &HiveCell) -> ForensicError {
    ForensicError::registry_cell_error(
        "key_value_data",
        format!("cannot decode value of data_type={data_type} at data_offset={data_offset}: unexpected cell {cell:?}"),
    )
}

/// Decodes a value whose data is small enough to be stored "resident" — directly inside the
/// `data_offset` field of its `KeyValueCell`, rather than in a separate cell — as signaled by a
/// negative `data_size`.
fn decode_resident_value(data_type: u32, data_offset: u32, cached_size: i32) -> RegValue {
    let size = (i32::MIN - cached_size).unsigned_abs() as usize;
    let value = data_offset;
    let raw = value.to_le_bytes();
    let data = &raw[0..size.min(raw.len())];
    match data_type {
        DATA_TYPE_REG_BINARY => RegValue::Binary(data.to_vec()),
        DATA_TYPE_REG_SZ | DATA_TYPE_REG_EXPAND_SZ => {
            // `data.len().checked_sub(2)` (rather than the unchecked `data.len() - 2`) avoids a
            // subtract-with-overflow panic when a resident string value's declared size is 0 or 1.
            let s = match (data.len().checked_sub(2).and_then(|i| data.get(i)), data.last()) {
                (Some(0), Some(0)) => {
                    if data.len() == 2 {
                        String::new()
                    } else {
                        String::from_utf16_lossy(&[u16::from_le_bytes([data[0], data[1]])])
                    }
                }
                (Some(_), Some(0)) => String::from_utf8_lossy(&data[..data.len() - 1]).to_string(),
                _ => String::from_utf8_lossy(data).to_string(),
            };
            if data_type == DATA_TYPE_REG_EXPAND_SZ {
                RegValue::ExpandSZ(s)
            } else {
                RegValue::SZ(s)
            }
        }
        DATA_TYPE_REG_DWORD => RegValue::DWord(value),
        DATA_TYPE_REG_DWORD_BE => RegValue::DWord(value.to_be()),
        DATA_TYPE_REG_QWORD => RegValue::QWord(value as u64),
        _ => RegValue::Unknown {
            ty: data_type,
            data: data.to_vec(),
        },
    }
}

/// Decodes a `KeyValueCell`'s data given its already-extracted `data_type`/`data_offset`/
/// `data_size`/`flags` fields. Shared by the eager ([read_value_from_hive]/[values_from_hive])
/// and lazy ([HiveValuesIter]) enumeration paths.
fn decode_value_cell(
    hive: &mut HiveFiles,
    data_type: u32,
    data_offset: u32,
    data_size: u32,
    flags: u16,
) -> ForensicResult<RegValue> {
    if data_type == DATA_TYPE_NONE {
        return Ok(RegValue::None);
    }
    let cached_size = data_size as i32;
    if cached_size < 0 {
        return Ok(decode_resident_value(data_type, data_offset, cached_size));
    }
    let data_cell = hive.get_cell_at_offset(data_offset as u64)?;
    match data_type {
        DATA_TYPE_REG_SZ | DATA_TYPE_REG_EXPAND_SZ => match data_cell {
            HiveCell::Invalid(ic) => {
                let s = if flags & 1 == 0 {
                    ic.into_reg_sz_ascii()
                } else {
                    ic.into_reg_sz_extended()
                };
                Ok(if data_type == DATA_TYPE_REG_EXPAND_SZ {
                    RegValue::ExpandSZ(s)
                } else {
                    RegValue::SZ(s)
                })
            }
            HiveCell::Unallocated(_) => Err(unallocated_value_error(data_type, data_offset)),
            other => Err(unexpected_value_cell(data_type, data_offset, other)),
        },
        DATA_TYPE_REG_BINARY => match data_cell {
            HiveCell::Invalid(ic) => Ok(RegValue::Binary(ic.content.clone())),
            HiveCell::Unallocated(_) => Err(unallocated_value_error(data_type, data_offset)),
            other => Err(unexpected_value_cell(data_type, data_offset, other)),
        },
        DATA_TYPE_REG_DWORD => match data_cell {
            HiveCell::Invalid(ic) => Ok(RegValue::DWord(ic.into_dword_le())),
            HiveCell::Unallocated(_) => Err(unallocated_value_error(data_type, data_offset)),
            other => Err(unexpected_value_cell(data_type, data_offset, other)),
        },
        DATA_TYPE_REG_DWORD_BE => match data_cell {
            HiveCell::Invalid(ic) => Ok(RegValue::DWord(ic.into_dword_be())),
            HiveCell::Unallocated(_) => Err(unallocated_value_error(data_type, data_offset)),
            other => Err(unexpected_value_cell(data_type, data_offset, other)),
        },
        DATA_TYPE_REG_QWORD => match data_cell {
            HiveCell::Invalid(ic) => Ok(RegValue::QWord(ic.into_qword_le())),
            HiveCell::Unallocated(_) => Err(unallocated_value_error(data_type, data_offset)),
            other => Err(unexpected_value_cell(data_type, data_offset, other)),
        },
        _ => match data_cell {
            HiveCell::Invalid(ic) => Ok(RegValue::Unknown {
                ty: data_type,
                data: ic.content.clone(),
            }),
            HiveCell::Unallocated(_) => Err(unallocated_value_error(data_type, data_offset)),
            other => Err(unexpected_value_cell(data_type, data_offset, other)),
        },
    }
}

fn read_value_from_hive(hive: &mut HiveFiles, offset: u64, value_name: &str) -> ForensicResult<RegValue> {
    let hive_bins_data_size = hive.base_block.hive_bins_data_size;
    let cell = hive.get_cell_at_offset(offset)?;
    let kn = match cell {
        HiveCell::KeyNode(kn) => kn,
        _ => return Err(ForensicError::registry_cell_structure_error("key_node", offset, "KeyNode")),
    };
    let key_values_list_offset = kn.key_values_list_offset;
    let number_key_values = kn.number_key_values;
    let values_cell_list = hive.get_cell_at_offset(key_values_list_offset as u64)?;
    let mut offsets = Vec::with_capacity(number_key_values as usize);
    if let HiveCell::Invalid(ic) = values_cell_list {
        for o in parse_offsets_list(&ic.content)? {
            if o > ROOT_CELL_OFFSET as u32 && o < hive_bins_data_size {
                offsets.push(o);
            }
        }
    }
    let mut data = None;
    for offset in offsets {
        let value_cell = match hive.get_cell_at_offset(offset as u64) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let HiveCell::KeyValue(kv) = value_cell {
            if kv.value_name == value_name {
                data = Some((kv.data_offset, kv.data_size, kv.data_type, kv.flags));
                break;
            }
        }
    }
    let (data_offset, data_size, data_type, flags) = data
        .ok_or_else(|| ForensicError::registry_value_not_found(PredefinedHive::LocalMachine, None, value_name))?;
    decode_value_cell(hive, data_type, data_offset, data_size, flags)
}

fn values_from_hive(hive: &mut HiveFiles, offset: u64) -> ForensicResult<Vec<(String, RegValue)>> {
    let cell = hive.get_cell_at_offset(offset)?;
    let key_node = match cell {
        HiveCell::KeyNode(v) => v,
        _ => return Err(ForensicError::registry_cell_structure_error("key_node", offset, "KeyNode")),
    };
    let key_values_list_offset = key_node.key_values_list_offset;
    let number_key_values = key_node.number_key_values;
    let values_cell_list = hive.get_cell_at_offset(key_values_list_offset as u64)?;
    let mut offsets = Vec::with_capacity(number_key_values as usize);
    if let HiveCell::Invalid(ic) = values_cell_list {
        offsets.extend(parse_offsets_list(&ic.content)?.into_iter().filter(|&o| o > 0));
    }
    let mut results = Vec::with_capacity(offsets.len());
    for offset in offsets {
        let value_cell = match hive.get_cell_at_offset(offset as u64) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let (name, data_type, data_offset, data_size, flags) = match value_cell {
            HiveCell::KeyValue(kv) => (kv.value_name.clone(), kv.data_type, kv.data_offset, kv.data_size, kv.flags),
            _ => continue,
        };
        match decode_value_cell(hive, data_type, data_offset, data_size, flags) {
            Ok(v) => results.push((name, v)),
            Err(e) => warn!("skipping undecodable value {}: {:?}", name, e),
        }
    }
    if results.len() > number_key_values as usize {
        warn!(
            "There are more elements ({}) than the key indicates ({})",
            results.len(),
            number_key_values
        );
    }
    Ok(results)
}

fn keys_from_hive(hive: &mut HiveFiles, offset: u64) -> ForensicResult<Vec<KeyEntry>> {
    let cell = hive.get_cell_at_offset(offset)?;
    let key_node = match cell {
        HiveCell::KeyNode(v) => v,
        _ => return Err(ForensicError::registry_cell_structure_error("key_node", offset, "KeyNode")),
    };
    let subkeys_list_offset = key_node.subkeys_list_offset;
    let number_subkeys = key_node.number_subkeys;
    if number_subkeys == 0 {
        return Ok(Vec::new());
    }
    let mut offsets: Vec<u32> = match hive.get_cell_at_offset(subkeys_list_offset as u64)? {
        HiveCell::HashLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
        HiveCell::FastLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
        HiveCell::IndexLeaf(v) => v.elements.iter().map(|v| v.offset).collect(),
        HiveCell::IndexRoot(v) => v.elements.iter().map(|v| v.subkeys_list_offset).collect(),
        _ => {
            return Err(ForensicError::registry_cell_structure_error(
                "subkeys_list",
                subkeys_list_offset as u64,
                "leaf/index cell",
            ))
        }
    };
    let mut subkeys = Vec::with_capacity(number_subkeys as usize);
    let mut pos = 0;
    while pos < offsets.len() {
        let offset = offsets[pos];
        let cell = match hive.get_cell_at_offset(offset as u64) {
            Ok(v) => v,
            Err(e) => {
                warn!("Error loading cell at offset={}: {:?}", offset, e);
                pos += 1;
                continue;
            }
        };
        match cell {
            HiveCell::KeyNode(v) => subkeys.push(KeyEntry {
                name: v.key_name.clone(),
                last_write: Some(ForensicTimestamp::from_win_filetime(v.last_written_timestamp)),
                allocated: true,
            }),
            HiveCell::IndexLeaf(v) => offsets.extend(v.elements.iter().map(|e| e.offset)),
            _ => {}
        }
        pos += 1;
    }
    Ok(subkeys)
}

/// Bit layout of the [RawKey] this backend hands out: the low 48 bits are a cell offset (or, for
/// [HiveKind::Cached], an id into `HiveRegistryReader::cached_keys`); the next 6 bits are a
/// [HiveKind] tag; the top 10 bits are a position into `HiveRegistryReader::users`/`others`
/// (unused, zero, for every other kind). `u64`'s headroom means there's no need for anything like
/// the legacy `RegHiveKey::Hkey(isize)` scheme's negative-offset "mounted" sign trick.
const KIND_SHIFT: u32 = 48;
const POSITION_SHIFT: u32 = 54;
const PAYLOAD_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;
const KIND_MASK: u64 = 0x3F;
const POSITION_MASK: u64 = 0x3FF;

const KIND_LM_ROOT: u64 = 0;
const KIND_USERS_ROOT: u64 = 1;
const KIND_SAM: u64 = 2;
const KIND_SECURITY: u64 = 3;
const KIND_SOFTWARE: u64 = 4;
const KIND_SYSTEM: u64 = 5;
const KIND_CURRENT_CONFIG: u64 = 6;
const KIND_USER: u64 = 7;
const KIND_OTHER: u64 = 8;
const KIND_CACHED: u64 = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HiveKind {
    /// Virtual container for `SAM`/`SECURITY`/`SOFTWARE`/`SYSTEM` — no single cell backs it.
    LmRoot,
    /// Virtual container listing loaded per-user hives — no single cell backs it.
    UsersRoot,
    Sam,
    Security,
    Software,
    System,
    CurrentConfig,
    /// Position into `HiveRegistryReader::users`.
    User(u16),
    /// Position into `HiveRegistryReader::others`.
    Other(u16),
    /// A top-level REG-injected ([MountedMap]) key; the payload is an id into
    /// `HiveRegistryReader::cached_keys`, not a cell offset.
    Cached,
}

fn pack_raw_key(kind: HiveKind, payload: u64) -> RawKey {
    let (tag, position): (u64, u64) = match kind {
        HiveKind::LmRoot => (KIND_LM_ROOT, 0),
        HiveKind::UsersRoot => (KIND_USERS_ROOT, 0),
        HiveKind::Sam => (KIND_SAM, 0),
        HiveKind::Security => (KIND_SECURITY, 0),
        HiveKind::Software => (KIND_SOFTWARE, 0),
        HiveKind::System => (KIND_SYSTEM, 0),
        HiveKind::CurrentConfig => (KIND_CURRENT_CONFIG, 0),
        HiveKind::User(pos) => (KIND_USER, pos as u64),
        HiveKind::Other(pos) => (KIND_OTHER, pos as u64),
        HiveKind::Cached => (KIND_CACHED, 0),
    };
    let raw = (payload & PAYLOAD_MASK) | ((tag & KIND_MASK) << KIND_SHIFT) | ((position & POSITION_MASK) << POSITION_SHIFT);
    RawKey::from_raw(raw)
}

/// Decodes a [RawKey] back into which hive it refers to and its cell offset (or, for
/// [HiveKind::Cached], its `cached_keys` id) within it. Returns `Err` for a foreign/garbage key
/// rather than a sentinel variant that callers had to disambiguate by context.
fn unpack_raw_key(key: &RawKey) -> ForensicResult<(HiveKind, u64)> {
    let raw = key.raw();
    let payload = raw & PAYLOAD_MASK;
    let tag = (raw >> KIND_SHIFT) & KIND_MASK;
    let position = ((raw >> POSITION_SHIFT) & POSITION_MASK) as u16;
    let kind = match tag {
        KIND_LM_ROOT => HiveKind::LmRoot,
        KIND_USERS_ROOT => HiveKind::UsersRoot,
        KIND_SAM => HiveKind::Sam,
        KIND_SECURITY => HiveKind::Security,
        KIND_SOFTWARE => HiveKind::Software,
        KIND_SYSTEM => HiveKind::System,
        KIND_CURRENT_CONFIG => HiveKind::CurrentConfig,
        KIND_USER => HiveKind::User(position),
        KIND_OTHER => HiveKind::Other(position),
        KIND_CACHED => HiveKind::Cached,
        _ => return Err(ForensicError::registry_invalid_handle(raw as i64)),
    };
    Ok((kind, payload))
}

/// Lazy [Registry::keys_iter_raw] iterator: resolves one subkey at a time, only reading each
/// leaf/index-list cell and `KeyNodeCell` as `.next()` is actually called.
pub struct HiveKeysIter<'a> {
    hive: MutexGuard<'a, HiveFiles>,
    pending: VecDeque<u32>,
}
impl<'a> Iterator for HiveKeysIter<'a> {
    type Item = KeyEntry;
    fn next(&mut self) -> Option<KeyEntry> {
        loop {
            let offset = self.pending.pop_front()?;
            let cell = match self.hive.get_cell_at_offset(offset as u64) {
                Ok(c) => c,
                Err(e) => {
                    warn!("skipping subkey cell at offset={}: {:?}", offset, e);
                    continue;
                }
            };
            match cell {
                HiveCell::KeyNode(v) => {
                    return Some(KeyEntry {
                        name: v.key_name.clone(),
                        last_write: Some(ForensicTimestamp::from_win_filetime(v.last_written_timestamp)),
                        allocated: true,
                    });
                }
                HiveCell::HashLeaf(v) => self.pending.extend(v.elements.iter().map(|e| e.offset)),
                HiveCell::FastLeaf(v) => self.pending.extend(v.elements.iter().map(|e| e.offset)),
                HiveCell::IndexLeaf(v) => self.pending.extend(v.elements.iter().map(|e| e.offset)),
                HiveCell::IndexRoot(v) => self.pending.extend(v.elements.iter().map(|e| e.subkeys_list_offset)),
                _ => {}
            }
        }
    }
}

/// Lazy [Registry::values_iter_raw] iterator: the flat offsets-list cell is necessarily read once
/// up front (bootstrapped by [Registry::values_iter_raw] itself, not by this struct) — that's
/// bounded metadata, not per-record cost — but each value's `KeyValueCell` and data cell are only
/// read and decoded as `.next()` is actually called.
pub struct HiveValuesIter<'a> {
    hive: MutexGuard<'a, HiveFiles>,
    pending: VecDeque<u32>,
}
impl<'a> Iterator for HiveValuesIter<'a> {
    type Item = (String, RegValue);
    fn next(&mut self) -> Option<(String, RegValue)> {
        loop {
            let offset = self.pending.pop_front()?;
            let cell = match self.hive.get_cell_at_offset(offset as u64) {
                Ok(c) => c,
                Err(e) => {
                    warn!("skipping value cell at offset={}: {:?}", offset, e);
                    continue;
                }
            };
            let (name, data_type, data_offset, data_size, flags) = match cell {
                HiveCell::KeyValue(kv) => (kv.value_name.clone(), kv.data_type, kv.data_offset, kv.data_size, kv.flags),
                _ => continue,
            };
            match decode_value_cell(&mut self.hive, data_type, data_offset, data_size, flags) {
                Ok(v) => return Some((name, v)),
                Err(e) => {
                    warn!("skipping undecodable value {}: {:?}", name, e);
                    continue;
                }
            }
        }
    }
}

pub struct HiveFiles {
    pub(crate) location: FPathBuf,
    pub(crate) primary: Box<dyn VirtualFile>,
    pub base_block: BaseBlock,
    pub(crate) root_cell: KeyNodeCell,
    pub(crate) logs: Vec<Box<dyn VirtualFile>>,
    pub(crate) cell_cache: CellCache,
    pub(crate) buffer: Vec<u8>,
    pub(crate) mounted: MountedMap,
}

impl HiveFiles {
    pub fn new(location: FPathBuf, mut primary: Box<dyn VirtualFile>) -> ForensicResult<Self> {
        let base_block = read_base_block(&mut primary)?;
        primary.seek(std::io::SeekFrom::Start(HIVE_BASE_BLOCK_SIZE))?;
        let (_hive_bin, data) = read_hive_bin_at_file_position(&mut primary)?;
        let cells = read_cells(&data, ROOT_CELL_OFFSET)?;
        let mut cell_cache = CellCache::new(2048);
        for cell in cells {
            cell_cache.insert_fixed(cell);
        }
        let key_node_cell = cell_cache
            .get(base_block.root_cell_offset as u64)
            .ok_or_else(|| ForensicError::missing_data("hive_root_cell", "Missing root cell".into()))?;
        let root_cell = match key_node_cell {
            HiveCell::KeyNode(v) => v.clone(),
            _ => {
                return Err(ForensicError::registry_hive_error(
                    "hive_root_cell",
                    "expected root cell of type KeyNode",
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
            buffer: vec![0u8; HIVE_BASE_BLOCK_SIZE as usize],
            mounted: MountedMap::new(),
        })
    }

    pub fn scan_hive(_primary: &mut Box<dyn VirtualFile>) -> Vec<(u64, u64)> {
        vec![]
    }
    pub fn add_mounted_value(&mut self, path: &str, value: &str, data: RegValue) {
        self.mounted.add_value(path, value, data);
    }

    pub fn open_mounted_key(&mut self, _key_name: &str, _key_id: i64) -> ForensicResult<isize> {
        Err(not_implemented("HiveFiles::open_mounted_key"))
    }

    pub fn open_key_from_offset(&mut self, key_name: &str, offset: i64) -> ForensicResult<isize> {
        if offset < 0 {
            return self.open_mounted_key(key_name, offset);
        }
        let offset = offset as u64;
        if offset == ROOT_CELL_OFFSET && key_name.is_empty() {
            return Ok(ROOT_CELL_OFFSET as isize);
        }
        let mut path_separator = key_name.split(['/', '\\']);
        let root_cell = match self.get_cell_at_offset(offset)? {
            HiveCell::KeyNode(kn) => kn,
            _ => return Err(ForensicError::registry_cell_structure_error("key_node", offset, "KeyNode")),
        };
        let subkeys_offset = root_cell.subkeys_list_offset;
        let n_subkeys = root_cell.number_subkeys;
        let _n_key_val = root_cell.number_key_values;
        let first = match path_separator.next() {
            Some(v) => v,
            None => return Ok(ROOT_CELL_OFFSET as isize), // Root Cell
        };
        if n_subkeys == 0 {
            return Err(ForensicError::registry_key_not_found(PredefinedHive::LocalMachine, Some(first.into())));
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
                        None => {
                            return Err(ForensicError::registry_key_not_found(
                                PredefinedHive::LocalMachine,
                                Some(actual_path.into()),
                            ))
                        }
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                HiveCell::KeyNode(kn) => {
                    if subkey_last_index > 0 {
                        return Err(ForensicError::registry_key_not_found(
                            PredefinedHive::LocalMachine,
                            Some(actual_path.into()),
                        ));
                    }
                    if kn.key_name != actual_path {
                        let (last_offset, counter) = match offset_path.pop() {
                            Some(v) => v,
                            None => {
                                return Err(ForensicError::registry_key_not_found(
                                    PredefinedHive::LocalMachine,
                                    Some(actual_path.into()),
                                ))
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
                        None => {
                            return Err(ForensicError::registry_key_not_found(
                                PredefinedHive::LocalMachine,
                                Some(actual_path.into()),
                            ))
                        }
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                HiveCell::IndexRoot(ir) => {
                    let i = subkey_last_index;
                    if let Some(el) = ir.elements.get(i) {
                        offset_path.push((next_offset, i));
                        subkey_last_index = 0;
                        next_offset = el.subkeys_list_offset;
                        continue 'out;
                    }
                    let (last_offset, counter) = match offset_path.pop() {
                        Some(v) => v,
                        None => {
                            return Err(ForensicError::registry_key_not_found(
                                PredefinedHive::LocalMachine,
                                Some(actual_path.into()),
                            ))
                        }
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                HiveCell::IndexLeaf(il) => {
                    let i = subkey_last_index;
                    if let Some(el) = il.elements.get(i) {
                        offset_path.push((next_offset, i));
                        subkey_last_index = 0;
                        next_offset = el.offset;
                        continue 'out;
                    }
                    let (last_offset, counter) = match offset_path.pop() {
                        Some(v) => v,
                        None => {
                            return Err(ForensicError::registry_key_not_found(
                                PredefinedHive::LocalMachine,
                                Some(actual_path.into()),
                            ))
                        }
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                _ => {
                    return Err(ForensicError::registry_key_not_found(
                        PredefinedHive::LocalMachine,
                        Some(actual_path.into()),
                    ))
                }
            };
        }
        Ok(next_offset as isize)
    }
    pub fn open_key(&mut self, key_name: &str) -> ForensicResult<isize> {
        self.open_key_from_offset(key_name, ROOT_CELL_OFFSET as i64)
    }

    pub fn get_root_cell(&self) -> ForensicResult<&KeyNodeCell> {
        let cell = self
            .cell_cache
            .get(ROOT_CELL_OFFSET)
            .ok_or_else(|| ForensicError::missing_data("hive_root_cell", "Root cell not found".into()))?;

        let kn = match cell {
            HiveCell::KeyNode(ir) => ir,
            _ => return Err(ForensicError::registry_hive_error("hive_root_cell", "invalid root cell type")),
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
                return Err(ForensicError::registry_cell_error(
                    "cell",
                    format!("invalid cell size {cell_size} at offset {offset}"),
                ));
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
            None => Err(ForensicError::missing_data("hive_cell", "Hive cell not found".into())),
        }
    }
    fn hive_bins_data_offset(&self) -> u64 {
        HIVE_BASE_BLOCK_SIZE
    }
}

impl Registry for HiveRegistryReader {
    fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey> {
        match hive {
            PredefinedHive::LocalMachine => Ok(pack_raw_key(HiveKind::LmRoot, 0)),
            PredefinedHive::Users => Ok(pack_raw_key(HiveKind::UsersRoot, 0)),
            PredefinedHive::CurrentConfig => {
                if self.current_config.is_some() {
                    Ok(pack_raw_key(HiveKind::CurrentConfig, ROOT_CELL_OFFSET))
                } else {
                    Err(ForensicError::registry_key_not_found(PredefinedHive::CurrentConfig, None))
                }
            }
            other => Err(ForensicError::registry_key_not_found(other, None)),
        }
    }

    fn open_raw(&self, parent: &RawKey, name: &str) -> ForensicResult<RawKey> {
        let (kind, payload) = unpack_raw_key(parent)?;
        match kind {
            HiveKind::LmRoot => self.open_under_lm(name),
            HiveKind::UsersRoot => self.open_under_users(name),
            HiveKind::Cached => Err(not_implemented("Opening keys inside a mounted hive")),
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                let offset = h.open_key_from_offset(name, payload as i64)?;
                Ok(pack_raw_key(real_kind, offset as u64))
            }
        }
    }

    fn close_raw(&self, key: &RawKey) {
        if let Ok((HiveKind::Cached, payload)) = unpack_raw_key(key) {
            self.cached_keys.lock().unwrap().remove(&payload);
        }
    }

    fn read_raw(&self, key: &RawKey, value_name: &str) -> ForensicResult<RegValue> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                let cached_keys = self.cached_keys.lock().unwrap();
                let path = cached_keys
                    .get(&payload)
                    .ok_or_else(|| ForensicError::registry_invalid_handle(payload as i64))?;
                let mounted = self.mounted.lock().unwrap();
                mounted.get_value(path, value_name).ok_or_else(|| {
                    ForensicError::registry_value_not_found(
                        PredefinedHive::LocalMachine,
                        Some(path.as_str().into()),
                        value_name,
                    )
                })
            }
            HiveKind::LmRoot | HiveKind::UsersRoot => Err(ForensicError::registry_value_not_found(
                PredefinedHive::LocalMachine,
                None,
                value_name,
            )),
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                read_value_from_hive(&mut h, payload, value_name)
            }
        }
    }

    fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::LmRoot | HiveKind::UsersRoot => Ok(Vec::new()),
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                Err(not_implemented("Enumerating values of a mounted hive key"))
            }
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                values_from_hive(&mut h, payload)
            }
        }
    }

    fn keys_raw(&self, key: &RawKey) -> ForensicResult<Vec<KeyEntry>> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::LmRoot => Ok(self
                .list_hklm_keys()?
                .into_iter()
                .map(|name| KeyEntry {
                    name,
                    last_write: None,
                    allocated: true,
                })
                .collect()),
            HiveKind::UsersRoot => Ok(self
                .users
                .iter()
                .map(|(name, _)| KeyEntry {
                    name: name.clone(),
                    last_write: None,
                    allocated: true,
                })
                .collect()),
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                Err(not_implemented("Enumerating subkeys of a mounted hive key"))
            }
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                keys_from_hive(&mut h, payload)
            }
        }
    }

    fn info_raw(&self, key: &RawKey) -> ForensicResult<KeyInfo> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                Ok(KeyInfo::default())
            }
            HiveKind::LmRoot => Ok(KeyInfo {
                subkeys: self.list_hklm_keys()?.len() as u32,
                ..Default::default()
            }),
            HiveKind::UsersRoot => Ok(KeyInfo {
                subkeys: self.users.len() as u32,
                ..Default::default()
            }),
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                let cell = h.get_cell_at_offset(payload)?;
                let key_node = match cell {
                    HiveCell::KeyNode(v) => v,
                    _ => return Err(ForensicError::registry_cell_structure_error("key_node", payload, "KeyNode")),
                };
                Ok(KeyInfo {
                    last_write_time: Some(ForensicTimestamp::from_win_filetime(key_node.last_written_timestamp)),
                    max_subkey_name_length: key_node.largest_subkey_name_length as u32,
                    max_value_length: key_node.largest_value_data_size,
                    max_value_name_length: key_node.largest_value_name_length,
                    subkeys: key_node.number_subkeys,
                    values: key_node.number_key_values,
                })
            }
        }
    }

    fn values_iter_raw<'a>(&'a self, key: &RawKey) -> ForensicResult<Box<dyn Iterator<Item = (String, RegValue)> + 'a>> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::LmRoot | HiveKind::UsersRoot => Ok(Box::new(std::iter::empty())),
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                Err(not_implemented("Enumerating values of a mounted hive key"))
            }
            real_kind => {
                let hive_cell = self.hive_for_kind(real_kind)?;
                let mut hive = try_lock_hive(hive_cell)?;
                let cell = hive.get_cell_at_offset(payload)?;
                let key_node = match cell {
                    HiveCell::KeyNode(v) => v,
                    _ => return Err(ForensicError::registry_cell_structure_error("key_node", payload, "KeyNode")),
                };
                let key_values_list_offset = key_node.key_values_list_offset;
                let number_key_values = key_node.number_key_values;
                let mut pending = VecDeque::with_capacity(number_key_values as usize);
                if number_key_values > 0 {
                    let values_cell_list = hive.get_cell_at_offset(key_values_list_offset as u64)?;
                    if let HiveCell::Invalid(ic) = values_cell_list {
                        pending.extend(parse_offsets_list(&ic.content)?.into_iter().filter(|&o| o > 0));
                    }
                }
                Ok(Box::new(HiveValuesIter { hive, pending }))
            }
        }
    }

    fn keys_iter_raw<'a>(&'a self, key: &RawKey) -> ForensicResult<Box<dyn Iterator<Item = KeyEntry> + 'a>> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::LmRoot | HiveKind::UsersRoot | HiveKind::Cached => Ok(Box::new(self.keys_raw(key)?.into_iter())),
            real_kind => {
                let hive_cell = self.hive_for_kind(real_kind)?;
                let mut hive = try_lock_hive(hive_cell)?;
                let cell = hive.get_cell_at_offset(payload)?;
                let key_node = match cell {
                    HiveCell::KeyNode(v) => v,
                    _ => return Err(ForensicError::registry_cell_structure_error("key_node", payload, "KeyNode")),
                };
                let subkeys_list_offset = key_node.subkeys_list_offset;
                let number_subkeys = key_node.number_subkeys;
                let mut pending = VecDeque::new();
                if number_subkeys > 0 {
                    pending.push_back(subkeys_list_offset);
                }
                Ok(Box::new(HiveKeysIter { hive, pending }))
            }
        }
    }
}

/// Opens SAM/SECURITY/SOFTWARE/SYSTEM (and their user hives) from evidence, per
/// [RegistryReaderFactory]. Shared by [HiveRegistryReader::from_fs] (which hardcodes the
/// conventional `C:\Windows\System32\Config` path) and any pipeline that already knows where the
/// hive-container directory lives.
pub struct HiveRegistryReaderFactory;

impl RegistryReaderFactory for HiveRegistryReaderFactory {
    fn open(&self, filesystem: Arc<dyn FileSystem>, path: &FPath) -> ForensicResult<Box<dyn Registry>> {
        let mut reader = HiveRegistryReader::new();
        if let Some(hive) = open_hive_with_logs(&filesystem, path, "SYSTEM") {
            reader.set_system(hive);
        }
        if let Some(hive) = open_hive_with_logs(&filesystem, path, "SOFTWARE") {
            reader.set_software(hive);
        }
        if let Some(hive) = open_hive_with_logs(&filesystem, path, "SECURITY") {
            reader.set_security(hive);
        }
        if let Some(hive) = open_hive_with_logs(&filesystem, path, "SAM") {
            reader.set_sam(hive);
        }
        if let Err(e) = reader.load_user_hives(&filesystem) {
            warn!("Error loading user hives: {:?}", e);
        }
        Ok(Box::new(reader))
    }
}

pub fn open_hive_with_logs(fs: &Arc<dyn FileSystem>, base_path: &FPath, name: &str) -> Option<HiveFiles> {
    let primary_path = base_path.join(name);
    let primary = fs.open(primary_path.as_path()).ok()?;
    let mut hive = HiveFiles::new(primary_path.clone(), primary).ok()?;
    for i in 1..3 {
        let log_i = base_path.join(format!("{name}.LOG{i}"));
        match fs.open(log_i.as_path()) {
            Ok(v) => {
                hive.logs.push(v);
            }
            Err(e) => {
                debug!("Cannot open hive log {}: {:?}", log_i, e);
            }
        };
    }
    Some(hive)
}

#[cfg(test)]
#[path = "reader_tst.rs"]
mod tst;
