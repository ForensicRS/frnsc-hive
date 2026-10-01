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
    cell::{HashLeafCell, HiveCell, InvalidCell, KeyNodeCell, peek_cell, read_cell},
    cell_cache::CellCache,
    consts::{HIVE_BASE_BLOCK_SIZE, ROOT_CELL_OFFSET},
    hive::{BaseBlock, read_base_block, read_cells, read_hive_bin_at_file_position},
    log::{apply_entries, read_log_entries, select_entries_to_apply},
    mounted_map::{MountedCell, MountedMap},
    recovery,
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
    /// Analyst-relevant integrity signals accumulated while loading/replaying hives (checksum
    /// mismatches, dirty hives opened without a covering log, skipped log entries, unparseable
    /// hives) — in addition to, not instead of, the `warn!`/`debug!` log lines aimed at engineers.
    /// See [Self::findings].
    findings: Mutex<Vec<Finding>>,
}

impl Default for HiveRegistryReader {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveRegistryReader {
    /// Loads all hives from the file system searching for its locations.
    /// It also search for the location of the hives of all the users using the SOFTWARE hive with the **ProfileList** key.
    ///
    /// The integrity findings gathered while loading (checksum mismatches, dirty hives, hives that
    /// couldn't be parsed) stay on the reader, which this `Box<dyn Registry>` hides: use
    /// [Self::load_from_fs] to keep them.
    /// ```
    /// use forensic_rs::prelude::*;
    /// use frnsc_hive::reader::HiveRegistryReader;
    /// use std::sync::Arc;
    /// let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C/", Arc::new(StdVirtualFS::new())));
    /// let reader = HiveRegistryReader::from_fs(fs).unwrap();
    /// ```
    pub fn from_fs(fs: Arc<dyn FileSystem>) -> ForensicResult<Box<dyn Registry>> {
        let (reader, findings) = Self::load_from_fs(&fs);
        let reader = reader.unwrap_or_else(|| {
            let empty = HiveRegistryReader::new();
            empty.record_findings(findings);
            empty
        });
        Ok(Box::new(reader))
    }

    /// Loads the machine hives and the users' `NTUSER.DAT`, returning the reader with every
    /// integrity finding gathered on the way. `None` when no machine hive was found.
    ///
    /// Looks in `C:\Windows\System32\Config` first and finds user hives through `ProfileList`.
    /// Only when that folder holds no machine hive does it search the whole filesystem by name
    /// ([crate::discovery::find_hives]): a triage collection such as
    /// `CopiedFiles/registry/SYSTEM` + `<user>_NTUSER.DAT`. A user hive found that way is mapped
    /// to its SID through `ProfileList` by profile folder name; when nothing maps it, it is loaded
    /// under `HKU\<label>` and a finding says its SID is unresolved.
    pub fn load_from_fs(fs: &Arc<dyn FileSystem>) -> (Option<HiveRegistryReader>, Vec<Finding>) {
        let mut reader = HiveRegistryReader::new();
        let mut findings = Vec::new();
        let config_folder = FPath::new("C:\\Windows\\System32\\Config");
        let mut any = false;
        for name in crate::discovery::MACHINE_HIVES {
            if let Some(hive) = open_hive_with_logs(fs, config_folder, name, &mut findings) {
                reader.set_machine_hive(name, hive);
                any = true;
            }
        }
        if any {
            reader.record_findings(std::mem::take(&mut findings));
            if let Err(e) = reader.load_user_hives(fs) {
                reader.record_findings(vec![Finding::from_error("loading user hives", &e)]);
            }
            let all = reader.findings();
            return (Some(reader), all);
        }

        let found = crate::discovery::find_hives(fs.as_ref());
        findings.extend(found.findings);
        for e in &found.errors {
            findings.push(Finding::from_error("searching for hives", e));
        }
        for (name, path) in &found.machine {
            let (dir, file) = split(path.as_path());
            if let Some(hive) = open_hive_with_logs(fs, dir, file, &mut findings) {
                reader.set_machine_hive(name, hive);
                any = true;
            }
        }
        if !any {
            return (None, findings);
        }
        reader.record_findings(findings);
        reader.load_found_user_hives(fs, &found.users);
        let all = reader.findings();
        (Some(reader), all)
    }

    fn set_machine_hive(&mut self, name: &str, hive: HiveFiles) {
        match name {
            "SYSTEM" => self.set_system(hive),
            "SOFTWARE" => self.set_software(hive),
            "SECURITY" => self.set_security(hive),
            _ => self.set_sam(hive),
        }
    }

    /// Loads user hives found by name, keyed by the SID `ProfileList` gives their profile folder,
    /// or by their label when none does.
    fn load_found_user_hives(&mut self, fs: &Arc<dyn FileSystem>, users: &[crate::discovery::UserHive]) {
        let mut findings = Vec::new();
        let mut sid_of: BTreeMap<String, String> = BTreeMap::new();
        match windows::users_with_errors(&*self) {
            Ok((profiles, errors)) => {
                for e in &errors {
                    findings.push(Finding::from_error("reading ProfileList", e));
                }
                for p in profiles {
                    if let Some(folder) = p.profile_path.as_path().file_name() {
                        sid_of.insert(folder.to_ascii_lowercase(), p.sid);
                    }
                }
            }
            Err(e) => findings.push(Finding::from_error("reading ProfileList", &e)),
        }
        for user in users {
            let (dir, file) = split(user.path.as_path());
            let Some(hive) = open_hive_with_logs(fs, dir, file, &mut findings) else {
                continue;
            };
            match sid_of.get(&user.label.to_ascii_lowercase()) {
                Some(sid) => self.add_user(sid, hive),
                None => {
                    findings.push(
                        Finding::new(
                            FindingSeverity::Low,
                            FindingCategory::MissingData,
                            format!("User hive loaded without a SID: HKU\\{}", user.label),
                        )
                        .with_description(format!(
                            "{} was loaded under HKU\\{}: no ProfileList entry maps that profile \
                             folder to a SID, so records from it carry the label, not a SID.",
                            user.path, user.label
                        ))
                        .with_metadata(Text::Borrowed("hive.path"), Text::Owned(user.path.to_string())),
                    );
                    self.add_user(&user.label, hive);
                }
            }
        }
        self.record_findings(findings);
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
            findings: Mutex::new(Vec::new()),
        }
    }

    /// Analyst-relevant integrity signals accumulated so far — base-block checksum mismatches,
    /// dirty hives opened without a covering transaction log, skipped/malformed log entries, and
    /// hives that were found but could not be parsed — in insertion order. This is *in addition
    /// to*, not instead of, the `warn!`/`debug!` log lines emitted for the same conditions: those
    /// are for engineers debugging this crate, this is the analyst-facing channel (see the
    /// `forensic-rs-tool-review` skill's Finding/log/error split).
    pub fn findings(&self) -> Vec<Finding> {
        self.findings.lock().unwrap().clone()
    }

    /// Appends `new` onto the accumulated [Self::findings], preserving insertion order.
    pub(crate) fn record_findings(&self, new: Vec<Finding>) {
        if new.is_empty() {
            return;
        }
        self.findings.lock().unwrap().extend(new);
    }

    /// Searches and loads all the users that have hives, using the SOFTWARE hive's
    /// **ProfileList** key correlated against `HKEY_USERS` (via
    /// [forensic_rs::traits::registry::windows::users]).
    pub fn load_user_hives(&mut self, fs: &Arc<dyn FileSystem>) -> ForensicResult<()> {
        let profiles = windows::users(&*self)?;
        let mut findings = Vec::new();
        for profile in profiles {
            if profile.profile_path.as_str().is_empty() {
                continue;
            }
            // A mandatory profile's `NTUSER.MAN` is the hive Windows loads when it exists.
            let hive = match open_hive_with_logs(fs, profile.profile_path.as_path(), "NTUSER.MAN", &mut findings)
                .or_else(|| open_hive_with_logs(fs, profile.profile_path.as_path(), "NTUSER.DAT", &mut findings))
            {
                Some(v) => v,
                None => {
                    warn!(
                        "Cannot find hive {}\\NTUSER.DAT (or NTUSER.MAN) for user {}",
                        profile.profile_path, profile.sid
                    );
                    continue;
                }
            };
            self.add_user(&profile.sid, hive);
        }
        self.record_findings(findings);
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
                // Store using exactly the hive-relative path `open_under_lm` opens: the hive's
                // name stripped, and in SYSTEM `CurrentControlSet` resolved. A mismatch here would
                // make the value unreachable once stored, since `HiveFiles.mounted` and the
                // real-tree walk must agree on path shape.
                if let Some(kind) = lm_hive_kind(first_key) {
                    let rest = path.get(first_key.len() + 1..).unwrap_or("");
                    let rest = if kind == HiveKind::System {
                        match self.resolve_control_set(rest) {
                            Ok(rest) => rest,
                            Err(e) => {
                                warn!("REG value {full_path}\\{value} not mounted: {e}");
                                return;
                            }
                        }
                    } else {
                        rest.to_string()
                    };
                    let hive = match kind {
                        HiveKind::Sam => self.sam.as_ref(),
                        HiveKind::Security => self.security.as_ref(),
                        HiveKind::Software => self.software.as_ref(),
                        _ => self.system.as_ref(),
                    };
                    if let Some(hive) = hive {
                        hive.lock().unwrap().add_mounted_value(&rest, value, data);
                        return;
                    }
                }
            }
        } else if hkey == "HKEY_USERS" {
            let (username, rest_of_path) = path.split_once(['/', '\\']).unwrap_or((path, ""));
            for (guid, hive) in &self.users {
                if username == guid {
                    return hive.lock().unwrap().add_mounted_value(rest_of_path, value, data);
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

    /// Looks up the path registered for a [HiveKind::Cached] id, assuming it's already been
    /// validated via [Self::require_cached_key].
    fn cached_key_path(&self, id: u64) -> ForensicResult<String> {
        self.cached_keys
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or_else(|| ForensicError::registry_invalid_handle(id as i64))
    }

    fn cached_key_values(&self, id: u64) -> ForensicResult<Vec<(String, RegValue)>> {
        let path = self.cached_key_path(id)?;
        let mounted = self.mounted.lock().unwrap();
        Ok(match mounted.get_cell(&path) {
            Some(cell) => mounted_cell_values(cell),
            None => Vec::new(),
        })
    }

    fn cached_key_names(&self, id: u64) -> ForensicResult<Vec<KeyEntry>> {
        let path = self.cached_key_path(id)?;
        let mounted = self.mounted.lock().unwrap();
        Ok(match mounted.get_cell(&path) {
            Some(cell) => mounted_cell_keys(cell),
            None => Vec::new(),
        })
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
            HiveKind::LmRoot | HiveKind::UsersRoot | HiveKind::Cached => Err(ForensicError::other(
                "registry",
                "not a real-hive-backed key".to_string(),
            )),
        }
    }

    /// Dispatches a key opened relative to [PredefinedHive::LocalMachine]: `SAM`/`SECURITY`/
    /// `SOFTWARE`/`SYSTEM` (any case, as in Windows) are each a hive mounted there, so the rest of
    /// the path is opened from that hive's root: `HKLM\SYSTEM\Select` is the SYSTEM hive's
    /// `Select`, and `HKLM\SAM\SAM\Domains` the SAM hive's `SAM\Domains`. In SYSTEM,
    /// `CurrentControlSet` is resolved through `Select\Current` ([Self::resolve_control_set]), as
    /// Windows does when it creates that link. Anything else falls back to a top-level
    /// REG-injected ([MountedMap]) key under `HKEY_LOCAL_MACHINE`.
    fn open_under_lm(&self, key_name: &str) -> ForensicResult<RawKey> {
        let (first_key, rest) = key_name.split_once(['/', '\\']).unwrap_or((key_name, ""));
        if let Some(kind) = lm_hive_kind(first_key) {
            let rest = if kind == HiveKind::System {
                self.resolve_control_set(rest)?
            } else {
                rest.to_string()
            };
            return self.open_in_kind(kind, &rest);
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
        Err(ForensicError::registry_key_not_found(
            PredefinedHive::LocalMachine,
            Some(key_name.into()),
        ))
    }

    fn open_under_users(&self, key_name: &str) -> ForensicResult<RawKey> {
        let (username, rest_of_path) = key_name.split_once(['/', '\\']).unwrap_or((key_name, ""));
        let position = self
            .users
            .iter()
            .position(|(name, _)| name.eq_ignore_ascii_case(username))
            .ok_or_else(|| ForensicError::registry_key_not_found(PredefinedHive::Users, Some(username.into())))?;
        let (_, hive) = &self.users[position];
        let mut h = try_lock_hive(hive)?;
        let offset = h.open_key_from_offset(rest_of_path, ROOT_CELL_OFFSET as i64)?;
        Ok(pack_raw_key(HiveKind::User(position as u16), offset.to_payload()))
    }

    fn open_in_kind(&self, kind: HiveKind, key_name: &str) -> ForensicResult<RawKey> {
        let hive = self.hive_for_kind(kind)?;
        let mut h = try_lock_hive(hive)?;
        let offset = h.open_key_from_offset(key_name, ROOT_CELL_OFFSET as i64)?;
        Ok(pack_raw_key(kind, offset.to_payload()))
    }

    /// `path` inside the SYSTEM hive, with a leading `CurrentControlSet` replaced by the control
    /// set `Select\Current` names (`ControlSet001`). An offline SYSTEM hive has no
    /// `CurrentControlSet` key: Windows creates it as a link at boot. A hive with no usable
    /// `Select\Current` is an error that says so, never a guessed `ControlSet001`.
    fn resolve_control_set(&self, path: &str) -> ForensicResult<String> {
        let (first, rest) = path.split_once(['/', '\\']).unwrap_or((path, ""));
        if !first.eq_ignore_ascii_case("CurrentControlSet") {
            return Ok(path.to_string());
        }
        let current = self
            .value(r"HKLM\SYSTEM\Select", "Current")
            .map_err(|e| {
                ForensicError::other(
                    "registry",
                    format!("CurrentControlSet can't be resolved: reading SYSTEM\\Select\\Current: {e}"),
                )
            })?
            .as_dword()
            .ok_or_else(|| ForensicError::registry_invalid_type("REG_DWORD", "SYSTEM\\Select\\Current".to_string()))?;
        let control_set = format!("ControlSet{current:03}");
        Ok(if rest.is_empty() {
            control_set
        } else {
            format!("{control_set}\\{rest}")
        })
    }
}

/// The machine hive mounted under `HKLM` as `name`, compared case-insensitively.
fn lm_hive_kind(name: &str) -> Option<HiveKind> {
    [
        ("SAM", HiveKind::Sam),
        ("SECURITY", HiveKind::Security),
        ("SOFTWARE", HiveKind::Software),
        ("SYSTEM", HiveKind::System),
    ]
    .into_iter()
    .find(|(hive, _)| hive.eq_ignore_ascii_case(name))
    .map(|(_, kind)| kind)
}

/// Registry key names compare case-insensitively, as in Windows.
fn key_names_match(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b) || (!a.is_ascii() && a.to_uppercase() == b.to_uppercase())
}

/// Marks a code path that is recognized but intentionally not yet implemented
/// (as opposed to malformed/missing data). Centralizes the wording so these
/// spots stay greppable until the feature is actually built.
fn not_implemented(feature: &str) -> ForensicError {
    ForensicError::other("registry", format!("{feature} is not implemented yet"))
}

/// Shared mapping from a [crate::mounted_map::MountedCell]'s values to the `(String, RegValue)`
/// shape [Registry::values_raw] expects — used by both the reader-level [HiveKind::Cached] arms
/// and (once implemented) the per-hive mounted-key arms, so the mapping only lives in one place.
fn mounted_cell_values(cell: &crate::mounted_map::MountedCell) -> Vec<(String, RegValue)> {
    cell.value_entries().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

/// Shared mapping from a [crate::mounted_map::MountedCell]'s child key names to [KeyEntry] —
/// mounted keys have no real on-disk timestamp, so `last_write` is always `None`, matching the
/// synthetic [HiveKind::LmRoot]/[HiveKind::UsersRoot] entries.
fn mounted_cell_keys(cell: &crate::mounted_map::MountedCell) -> Vec<KeyEntry> {
    cell.key_names()
        .map(|name| KeyEntry {
            name: name.to_string(),
            last_write: None,
            allocated: true,
        })
        .collect()
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
    if content.len() % 4 != 0 {
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
pub(crate) fn decode_value_cell(
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
    // Exactly the value's bytes: a cell is padded to 8 bytes, and a value larger than one cell
    // holds is a big-data (`db`) record of segments. Both used to reach callers raw.
    let data_cell = &HiveCell::Invalid(InvalidCell {
        offset: data_offset as u64,
        content: value_data(hive, data_type, data_offset, data_size)?,
    });
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
            HiveCell::Invalid(ic) => Ok(RegValue::DWord(ic.into_dword_le()?)),
            HiveCell::Unallocated(_) => Err(unallocated_value_error(data_type, data_offset)),
            other => Err(unexpected_value_cell(data_type, data_offset, other)),
        },
        DATA_TYPE_REG_DWORD_BE => match data_cell {
            HiveCell::Invalid(ic) => Ok(RegValue::DWord(ic.into_dword_be()?)),
            HiveCell::Unallocated(_) => Err(unallocated_value_error(data_type, data_offset)),
            other => Err(unexpected_value_cell(data_type, data_offset, other)),
        },
        DATA_TYPE_REG_QWORD => match data_cell {
            HiveCell::Invalid(ic) => Ok(RegValue::QWord(ic.into_qword_le()?)),
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

/// The most data one big-data segment holds, and so the size past which a value is stored as a
/// big-data (`db`) record instead of in one cell (hive format 1.4 and later).
const BIG_DATA_SEGMENT_SIZE: usize = 16_344;

/// The `data_size` bytes of a non-resident value at `data_offset`: the start of its data cell,
/// or, for a big-data record, its segments joined. A cell or record holding less than the value
/// declares is an error, never a short value.
fn value_data(hive: &mut HiveFiles, data_type: u32, data_offset: u32, data_size: u32) -> ForensicResult<Vec<u8>> {
    let size = data_size as usize;
    let content = match hive.get_cell_at_offset(data_offset as u64)? {
        HiveCell::Invalid(ic) => ic.content.clone(),
        HiveCell::Unallocated(_) => return Err(unallocated_value_error(data_type, data_offset)),
        other => return Err(unexpected_value_cell(data_type, data_offset, other)),
    };
    let big_data = size > BIG_DATA_SEGMENT_SIZE && hive.base_block.minor_version >= 4 && content.starts_with(b"db");
    if !big_data {
        return content.get(..size).map(<[u8]>::to_vec).ok_or_else(|| {
            ForensicError::registry_cell_error(
                "key_value_data",
                format!(
                    "data cell at offset={data_offset} holds {} bytes, the value declares {size}",
                    content.len()
                ),
            )
        });
    }
    let header = |range: std::ops::Range<usize>| {
        content.get(range).ok_or_else(|| {
            ForensicError::registry_cell_error("big_data", format!("record at offset={data_offset} is truncated"))
        })
    };
    let segments = u16::from_le_bytes(header(2..4)?.try_into().unwrap_or_default()) as usize;
    let list_offset = u32::from_le_bytes(header(4..8)?.try_into().unwrap_or_default());
    let list = match hive.get_cell_at_offset(list_offset as u64)? {
        HiveCell::Invalid(ic) => ic.content.clone(),
        other => return Err(unexpected_value_cell(data_type, list_offset, other)),
    };
    let list = list.get(..segments * 4).ok_or_else(|| {
        ForensicError::registry_cell_error(
            "big_data",
            format!("segment list at offset={list_offset} holds fewer than {segments} entries"),
        )
    })?;
    let mut out = Vec::with_capacity(size);
    for segment_offset in parse_offsets_list(list)? {
        if out.len() >= size {
            break;
        }
        let segment = match hive.get_cell_at_offset(segment_offset as u64)? {
            HiveCell::Invalid(ic) => ic.content.clone(),
            other => return Err(unexpected_value_cell(data_type, segment_offset, other)),
        };
        let take = BIG_DATA_SEGMENT_SIZE.min(size - out.len()).min(segment.len());
        out.extend_from_slice(&segment[..take]);
    }
    if out.len() < size {
        return Err(ForensicError::registry_cell_error(
            "big_data",
            format!(
                "record at offset={data_offset}: {segments} segment(s) hold {} bytes, the value declares {size}",
                out.len()
            ),
        ));
    }
    Ok(out)
}

fn read_value_from_hive(hive: &mut HiveFiles, offset: u64, value_name: &str) -> ForensicResult<RegValue> {
    let hive_bins_data_size = hive.base_block.hive_bins_data_size;
    let cell = hive.get_cell_at_offset(offset)?;
    let kn = match cell {
        HiveCell::KeyNode(kn) => kn,
        _ => {
            return Err(ForensicError::registry_cell_structure_error(
                "key_node", offset, "KeyNode",
            ));
        }
    };
    let key_values_list_offset = kn.key_values_list_offset;
    let number_key_values = kn.number_key_values;
    let mut offsets = Vec::with_capacity(number_key_values as usize);
    // A key with no values has no values list: its offset is unset (0xFFFFFFFF), not a cell.
    if number_key_values > 0 {
        let values_cell_list = hive.get_cell_at_offset(key_values_list_offset as u64)?;
        if let HiveCell::Invalid(ic) = values_cell_list {
            for o in parse_offsets_list(&ic.content)? {
                if o > ROOT_CELL_OFFSET as u32 && o < hive_bins_data_size {
                    offsets.push(o);
                }
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
            // Value names compare case-insensitively, as in Windows.
            if key_names_match(&kv.value_name, value_name) {
                data = Some((kv.data_offset, kv.data_size, kv.data_type, kv.flags));
                break;
            }
        }
    }
    let (data_offset, data_size, data_type, flags) = match data {
        Some(v) => v,
        None => {
            // Not among this key's real values — check for a value mounted directly on this same
            // (real) key's hive-relative path, if known (see HiveFiles::merge_mounted_values).
            if let Some(path) = hive.real_key_paths.get(&offset) {
                if let Some(v) = hive.mounted.get_value(path, value_name) {
                    return Ok(v);
                }
            }
            return Err(ForensicError::registry_value_not_found(
                PredefinedHive::LocalMachine,
                None,
                value_name,
            ));
        }
    };
    decode_value_cell(hive, data_type, data_offset, data_size, flags)
}

fn values_from_hive(hive: &mut HiveFiles, offset: u64) -> ForensicResult<Vec<(String, RegValue)>> {
    let cell = hive.get_cell_at_offset(offset)?;
    let key_node = match cell {
        HiveCell::KeyNode(v) => v,
        _ => {
            return Err(ForensicError::registry_cell_structure_error(
                "key_node", offset, "KeyNode",
            ));
        }
    };
    let key_values_list_offset = key_node.key_values_list_offset;
    let number_key_values = key_node.number_key_values;
    let mut offsets = Vec::with_capacity(number_key_values as usize);
    // A key with no values has no values list: its offset is unset (0xFFFFFFFF), not a cell.
    if number_key_values > 0 {
        let values_cell_list = hive.get_cell_at_offset(key_values_list_offset as u64)?;
        if let HiveCell::Invalid(ic) = values_cell_list {
            offsets.extend(parse_offsets_list(&ic.content)?.into_iter().filter(|&o| o > 0));
        }
    }
    let mut results = Vec::with_capacity(offsets.len());
    for offset in offsets {
        let value_cell = match hive.get_cell_at_offset(offset as u64) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let (name, data_type, data_offset, data_size, flags) = match value_cell {
            HiveCell::KeyValue(kv) => (
                kv.value_name.clone(),
                kv.data_type,
                kv.data_offset,
                kv.data_size,
                kv.flags,
            ),
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
    hive.merge_mounted_values(offset, &mut results);
    Ok(results)
}

fn keys_from_hive(hive: &mut HiveFiles, offset: u64) -> ForensicResult<Vec<KeyEntry>> {
    let cell = hive.get_cell_at_offset(offset)?;
    let key_node = match cell {
        HiveCell::KeyNode(v) => v,
        _ => {
            return Err(ForensicError::registry_cell_structure_error(
                "key_node", offset, "KeyNode",
            ));
        }
    };
    let subkeys_list_offset = key_node.subkeys_list_offset;
    let number_subkeys = key_node.number_subkeys;
    if number_subkeys == 0 {
        let mut subkeys = Vec::new();
        hive.merge_mounted_children(offset, &mut subkeys);
        return Ok(subkeys);
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
            ));
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
    hive.merge_mounted_children(offset, &mut subkeys);
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
    let raw =
        (payload & PAYLOAD_MASK) | ((tag & KIND_MASK) << KIND_SHIFT) | ((position & POSITION_MASK) << POSITION_SHIFT);
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

/// Marks bit 47 of a real-hive-kind [RawKey]'s 48-bit payload to distinguish a genuine on-disk
/// cell offset ([HiveOffset::Real]) from an id into a [HiveFiles]'s own `mounted_keys` table
/// ([HiveOffset::Mounted]). Real cell offsets are always `u32`-bounded (`hive_bins_data_size:
/// u32`), so they can never reach `2^47` — this flag is collision-free without touching
/// `pack_raw_key`/`unpack_raw_key`'s existing tag/position bits, and it stays in unsigned
/// arithmetic throughout (unlike the dead `if offset < 0` convention this replaces, which lost
/// its sign the moment it was masked by `PAYLOAD_MASK`).
const MOUNTED_PAYLOAD_FLAG: u64 = 1 << 47;

/// A cell offset resolved by [HiveFiles::open_key_from_offset]/[HiveFiles::open_mounted_child]:
/// either a genuine on-disk cell offset, or an id into that [HiveFiles]'s own `mounted_keys`
/// table for a REG-injected key mounted underneath this (otherwise real) hive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiveOffset {
    Real(u64),
    Mounted(u64),
}

impl HiveOffset {
    fn to_payload(self) -> u64 {
        match self {
            HiveOffset::Real(offset) => offset & PAYLOAD_MASK,
            HiveOffset::Mounted(id) => (id & PAYLOAD_MASK) | MOUNTED_PAYLOAD_FLAG,
        }
    }
    fn from_payload(payload: u64) -> Self {
        if payload & MOUNTED_PAYLOAD_FLAG != 0 {
            HiveOffset::Mounted(payload & !MOUNTED_PAYLOAD_FLAG)
        } else {
            HiveOffset::Real(payload)
        }
    }
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
                HiveCell::KeyValue(kv) => (
                    kv.value_name.clone(),
                    kv.data_type,
                    kv.data_offset,
                    kv.data_size,
                    kv.flags,
                ),
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
    pub(crate) cell_cache: CellCache,
    pub(crate) buffer: Vec<u8>,
    /// REG-injected keys/values mounted underneath this (otherwise real, on-disk) hive. Keyed by
    /// hive-relative paths — no leading `HKEY_LOCAL_MACHINE\<HIVE>\` or `HKEY_USERS\<guid>\`
    /// prefix — matching exactly what [Self::open_key_from_offset] receives as `key_name`. See
    /// [Self::add_mounted_value].
    pub(crate) mounted: MountedMap,
    /// Associates a [HiveOffset::Mounted] id with the hive-relative path it was opened for, so a
    /// later value/key-enumeration call on that id can look the path back up in `mounted`.
    pub(crate) mounted_keys: BTreeMap<u64, String>,
    pub(crate) mounted_key_counter: u64,
    /// Associates a *real* cell offset with the hive-relative path it was opened through (seeded
    /// with `ROOT_CELL_OFFSET -> ""`), populated as [Self::open_key_from_offset] resolves paths.
    /// Lets a real key's value/key enumeration also look up (and merge in) any values/subkeys
    /// mounted directly underneath that same path in `mounted`, not just keys reachable by
    /// falling back to `mounted` wholesale when the real tree walk fails outright. Only offsets
    /// actually reached via a path-based open are known here — a real key never opened by name
    /// (e.g. only ever reached by raw offset) won't have mounted overlays merged, which is a
    /// narrower, accepted version of the "chained opens into non-root real keys" limitation noted
    /// on [Self::open_key_from_offset].
    pub(crate) real_key_paths: BTreeMap<u64, String>,
    /// An in-memory, log-replay-patched copy of the hive-bins-data region, populated only when
    /// [Self::new_with_logs] actually applied at least one log entry. When `Some`,
    /// [Self::get_cell_at_offset] reads from here instead of seeking `primary` — clean hives and
    /// hives opened without logs never populate this, so they pay zero extra cost.
    pub(crate) patched_bins: Option<Vec<u8>>,
    /// The sequence number [Self::new_with_logs] recovered up to, if log replay applied anything.
    pub(crate) recovered_sequence: Option<u32>,
}

impl HiveFiles {
    /// Like [Self::new_with_findings], but for callers that don't need the integrity findings
    /// collected during the parse (e.g. tests, or a caller constructing a [HiveFiles] to hand to
    /// [HiveRegistryReader::set_sam]/[HiveRegistryReader::set_software]/etc. directly).
    pub fn new(location: FPathBuf, primary: Box<dyn VirtualFile>) -> ForensicResult<Self> {
        Self::new_with_findings(location, primary, &mut Vec::new())
    }

    /// Parses a primary hive file's base block and root hive bin. `findings` collects
    /// analyst-relevant integrity signals encountered while parsing (base-block checksum
    /// mismatch, unparseable cells) — see [crate::hive::read_base_block]/[crate::hive::read_cells].
    pub fn new_with_findings(
        location: FPathBuf,
        mut primary: Box<dyn VirtualFile>,
        findings: &mut Vec<Finding>,
    ) -> ForensicResult<Self> {
        let base_block = read_base_block(&mut primary, findings)?;
        primary.seek(std::io::SeekFrom::Start(HIVE_BASE_BLOCK_SIZE))?;
        let (_hive_bin, data) = read_hive_bin_at_file_position(&mut primary)?;
        let cells = read_cells(&data, ROOT_CELL_OFFSET, findings)?;
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
                ));
            }
        };
        Ok(Self {
            location,
            base_block,
            primary,
            root_cell,
            cell_cache,
            buffer: vec![0u8; HIVE_BASE_BLOCK_SIZE as usize],
            mounted: MountedMap::new(),
            mounted_keys: BTreeMap::new(),
            mounted_key_counter: 0,
            real_key_paths: BTreeMap::from([(ROOT_CELL_OFFSET, String::new())]),
            patched_bins: None,
            recovered_sequence: None,
        })
    }

    /// Like [Self::new_with_logs], but for callers that don't need the integrity findings
    /// collected during the parse and replay.
    pub fn new_with_logs(
        location: FPathBuf,
        primary: Box<dyn VirtualFile>,
        log1: Option<Box<dyn VirtualFile>>,
        log2: Option<Box<dyn VirtualFile>>,
    ) -> ForensicResult<Self> {
        Self::new_with_logs_and_findings(location, primary, log1, log2, &mut Vec::new())
    }

    /// Like [Self::new_with_findings], but additionally attempts transaction-log replay
    /// (`.LOG1`/`.LOG2`, new format) if the primary hive is dirty (`prim_sequence != sec_sequence`)
    /// and at least one of `log1`/`log2` is available. Clean hives, and dirty hives with no usable
    /// log, pay zero extra cost — [Self::patched_bins] stays `None` and [Self::get_cell_at_offset]
    /// behaves exactly as [Self::new_with_findings]'s result would. Never fails just because
    /// recovery didn't help: any read/parse error while replaying is logged via `warn!` — and, when
    /// it means reads may reflect stale/unpatched bytes, also recorded as an `IntegrityIssue`
    /// [Finding] in `findings` — and the hive still opens with its original, unpatched bytes.
    pub fn new_with_logs_and_findings(
        location: FPathBuf,
        primary: Box<dyn VirtualFile>,
        log1: Option<Box<dyn VirtualFile>>,
        log2: Option<Box<dyn VirtualFile>>,
        findings: &mut Vec<Finding>,
    ) -> ForensicResult<Self> {
        let mut hive = Self::new_with_findings(location, primary, findings)?;
        if hive.base_block.prim_sequence == hive.base_block.sec_sequence {
            return Ok(hive);
        }
        // Bound the eventual replay-buffer allocation against the primary file's actual size
        // before trusting `hive_bins_data_size` (an unvalidated u32 read straight from evidence)
        // as an allocation length — a hostile few-KiB file could otherwise claim a
        // multi-gigabyte hive-bins-data size and force an unbounded allocation. Checked up front
        // (rather than only right before the allocation) so an implausible header value is
        // reported the same way regardless of whether any log files happen to be available.
        let declared_size = hive.base_block.hive_bins_data_size as u64;
        let file_size = hive.primary.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
        if declared_size > file_size {
            warn!(
                "Hive at {} declares hive_bins_data_size={} larger than the file itself ({} bytes); opening with unpatched bytes",
                hive.location, declared_size, file_size
            );
            findings.push(
                Finding::new(
                    FindingSeverity::High,
                    FindingCategory::IntegrityIssue,
                    "Implausible hive_bins_data_size in base block",
                )
                .with_description(format!(
                    "Hive at {} declares a hive_bins_data_size of {declared_size} bytes, larger \
                     than the primary file itself ({file_size} bytes); this is inconsistent with \
                     a genuine hive and log replay was skipped to avoid an unbounded allocation.",
                    hive.location
                )),
            );
            return Ok(hive);
        }
        // Deliberately does NOT short-circuit on `log1.is_none() && log2.is_none()` — a dirty
        // hive opened with no logs at all is exactly the same forensic concern (stale/unpatched
        // reads) as one opened with logs that don't cover the gap, and must fall through to the
        // same `to_apply.is_empty()` Finding below rather than returning silently.
        let read_log = |f: Option<Box<dyn VirtualFile>>, name: &str, findings: &mut Vec<Finding>| match f {
            Some(mut file) => read_log_entries(&mut file, findings).unwrap_or_else(|e| {
                warn!("Error reading {name}: {:?}", e);
                findings.push(Finding::from_error(format!("reading {name}"), &e));
                Vec::new()
            }),
            None => Vec::new(),
        };
        let entries1 = read_log(log1, ".LOG1", findings);
        let entries2 = read_log(log2, ".LOG2", findings);
        let to_apply = select_entries_to_apply(hive.base_block.prim_sequence, &entries1, &entries2);
        if to_apply.is_empty() {
            warn!(
                "Hive at {} is dirty (sequence {} != {}) but no log entries cover the gap; opening with unpatched bytes",
                hive.location, hive.base_block.prim_sequence, hive.base_block.sec_sequence
            );
            findings.push(
                Finding::new(
                    FindingSeverity::High,
                    FindingCategory::IntegrityIssue,
                    "Dirty hive opened without log replay",
                )
                .with_description(format!(
                    "Hive at {} is dirty (primary sequence {} != secondary sequence {}) but no \
                     available .LOG1/.LOG2 entries cover the gap; it was opened using its \
                     original, unpatched bytes, so reads may reflect stale/pre-crash state.",
                    hive.location, hive.base_block.prim_sequence, hive.base_block.sec_sequence
                )),
            );
            return Ok(hive);
        }
        let mut bins = vec![0u8; declared_size as usize];
        if let Err(e) = hive
            .primary
            .seek(std::io::SeekFrom::Start(HIVE_BASE_BLOCK_SIZE))
            .and_then(|_| hive.primary.read_exact(&mut bins))
        {
            warn!("Error reading hive-bins-data for log replay: {:?}", e);
            findings.push(Finding::from_error(
                "reading hive-bins-data for log replay",
                &ForensicError::io_error_with_source(e, "hive-bins-data read for log replay"),
            ));
            return Ok(hive);
        }
        let Some(last_applied) = apply_entries(&mut bins, &to_apply, findings) else {
            warn!(
                "No log entries applied cleanly for hive at {}; opening with unpatched bytes",
                hive.location
            );
            findings.push(
                Finding::new(
                    FindingSeverity::High,
                    FindingCategory::IntegrityIssue,
                    "No transaction log entries applied cleanly",
                )
                .with_description(format!(
                    "Hive at {} is dirty, log entries were available, but none applied cleanly; \
                     it was opened using its original, unpatched bytes, so reads may reflect \
                     stale/pre-crash state.",
                    hive.location
                )),
            );
            return Ok(hive);
        };

        hive.base_block.prim_sequence = last_applied;
        hive.base_block.sec_sequence = last_applied;
        hive.base_block.hive_bins_data_size = bins.len() as u32;
        hive.cell_cache = CellCache::new(2048);
        hive.patched_bins = Some(bins);
        hive.recovered_sequence = Some(last_applied);
        let root_cell = match hive.get_cell_at_offset(hive.base_block.root_cell_offset as u64)? {
            HiveCell::KeyNode(v) => v.clone(),
            _ => {
                return Err(ForensicError::registry_hive_error(
                    "hive_root_cell",
                    "expected root cell of type KeyNode after log replay",
                ));
            }
        };
        hive.root_cell = root_cell;
        Ok(hive)
    }

    /// The sequence number log replay recovered up to, if [Self::new_with_logs] applied at least
    /// one log entry (`None` for a clean hive, a hive opened without logs, or one where no log
    /// entry covered the dirty gap — all of which leave the original on-disk bytes untouched).
    pub fn log_recovery_applied(&self) -> Option<u32> {
        self.recovered_sequence
    }

    pub fn scan_hive(_primary: &mut Box<dyn VirtualFile>) -> Vec<(u64, u64)> {
        vec![]
    }
    /// Adds a REG-injected value mounted underneath this hive. `path` must be hive-relative (see
    /// the [Self::mounted] field doc) — the caller (`HiveRegistryReader::add_reg_key`) is
    /// responsible for stripping the `HKEY_LOCAL_MACHINE\<HIVE>\`/`HKEY_USERS\<guid>\` prefix
    /// before calling this, matching the same stripping `open_under_lm`/`open_under_users` apply
    /// on the read side (SOFTWARE strips its own `SOFTWARE\` segment, user hives strip the user's
    /// GUID) — a mismatch here means a mounted value can be stored but never found again.
    pub fn add_mounted_value(&mut self, path: &str, value: &str, data: RegValue) {
        self.mounted.add_value(path, value, data);
    }

    fn next_mounted_id(&mut self) -> u64 {
        loop {
            let candidate = self.mounted_key_counter;
            self.mounted_key_counter = self.mounted_key_counter.wrapping_add(1);
            if !self.mounted_keys.contains_key(&candidate) {
                return candidate;
            }
        }
    }

    /// Resolves `key_name` (hive-relative, same convention as [Self::mounted]) against this
    /// hive's mounted map, minting a fresh [HiveOffset::Mounted] id on success. Used both as the
    /// fallback when [Self::open_key_from_offset]'s real-tree walk fails, and directly when the
    /// parent key is already known to be mounted (see [Self::open_mounted_child]).
    pub fn open_mounted_key(&mut self, key_name: &str) -> ForensicResult<HiveOffset> {
        if !self.mounted.contains(key_name) {
            return Err(ForensicError::registry_key_not_found(
                PredefinedHive::LocalMachine,
                Some(key_name.into()),
            ));
        }
        let id = self.next_mounted_id();
        self.mounted_keys.insert(id, key_name.to_string());
        Ok(HiveOffset::Mounted(id))
    }

    /// Resolves a [HiveOffset::Mounted] id to its [MountedCell], for value/key enumeration.
    fn mounted_cell(&self, id: u64) -> ForensicResult<Option<&MountedCell>> {
        let path = self
            .mounted_keys
            .get(&id)
            .ok_or_else(|| ForensicError::registry_invalid_handle(id as i64))?;
        Ok(self.mounted.get_cell(path))
    }

    /// Opens `name` as a child of an already-open mounted key `parent_id` — i.e. a mounted key
    /// nested underneath another mounted key, both underneath this real hive. Skips the real
    /// on-disk tree entirely, since the parent is already known not to be a real cell.
    pub fn open_mounted_child(&mut self, parent_id: u64, name: &str) -> ForensicResult<HiveOffset> {
        let parent_path = self
            .mounted_keys
            .get(&parent_id)
            .ok_or_else(|| ForensicError::registry_invalid_handle(parent_id as i64))?;
        let child_path = format!("{parent_path}\\{name}");
        self.open_mounted_key(&child_path)
    }

    /// Opens `key_name` relative to the real on-disk cell at `offset`. On success returns
    /// [HiveOffset::Real] and records the resolved path in [Self::real_key_paths] (so a later
    /// enumeration of that key can merge in mounted overlays, see [Self::merge_mounted_children]/
    /// [Self::merge_mounted_values]). On any failure, retries the *whole* `key_name` against this
    /// hive's [Self::mounted] map (see [Self::open_mounted_key]) and returns [HiveOffset::Mounted]
    /// if found there instead — preserving the original real-tree error if the mounted retry also
    /// fails. This covers "real path prefix, then a fully-mounted subtree" (the natural shape for
    /// injecting a synthetic subtree) but not real/mounted children interleaved at every level of
    /// one multi-segment path. `real_key_paths` only knows offsets reached through a path-based
    /// open (via this function or [Self::record_real_path]'s callers) — an offset only ever
    /// reached directly (bypassing name-based lookup) won't have mounted overlays merged.
    pub fn open_key_from_offset(&mut self, key_name: &str, offset: i64) -> ForensicResult<HiveOffset> {
        let base_offset = offset as u64;
        match self.open_key_from_offset_real(key_name, base_offset) {
            Ok(real_offset) => {
                self.record_real_path(base_offset, key_name, real_offset);
                Ok(HiveOffset::Real(real_offset))
            }
            Err(e) => self.open_mounted_key(key_name).map_err(|_| e),
        }
    }

    /// Like [`open_key_from_offset`], but opens `key_name` as a single literal child — see
    /// [`open_child_key_from_offset_real`].
    pub fn open_child_key_from_offset(&mut self, key_name: &str, offset: i64) -> ForensicResult<HiveOffset> {
        let base_offset = offset as u64;
        match self.open_child_key_from_offset_real(key_name, base_offset) {
            Ok(real_offset) => {
                self.record_real_path(base_offset, key_name, real_offset);
                Ok(HiveOffset::Real(real_offset))
            }
            Err(e) => self.open_mounted_key(key_name).map_err(|_| e),
        }
    }

    /// Records that `result_offset` (the outcome of resolving `key_name` relative to
    /// `base_offset`) corresponds to the hive-relative path `real_key_paths[base_offset] +
    /// key_name`, if `base_offset`'s own path is already known (a no-op otherwise — degrades
    /// gracefully rather than guessing). A no-op for an empty `key_name` (root re-open), since
    /// `result_offset == base_offset` then and there's nothing new to record.
    fn record_real_path(&mut self, base_offset: u64, key_name: &str, result_offset: u64) {
        if key_name.is_empty() {
            return;
        }
        let Some(base_path) = self.real_key_paths.get(&base_offset) else {
            return;
        };
        let full_path = if base_path.is_empty() {
            key_name.to_string()
        } else {
            format!("{base_path}\\{key_name}")
        };
        self.real_key_paths.insert(result_offset, full_path);
    }

    /// If `offset` was reached through a path-based open, appends any children mounted directly
    /// under that same path (see [Self::real_key_paths]) to `keys` — real subkeys always take
    /// precedence, so a mounted name that collides with an already-listed real subkey is skipped.
    fn merge_mounted_children(&self, offset: u64, keys: &mut Vec<KeyEntry>) {
        let Some(path) = self.real_key_paths.get(&offset) else {
            return;
        };
        let Some(cell) = self.mounted.get_cell(path) else {
            return;
        };
        for entry in mounted_cell_keys(cell) {
            if !keys.iter().any(|k| k.name == entry.name) {
                keys.push(entry);
            }
        }
    }

    /// If `offset` was reached through a path-based open, appends any values mounted directly
    /// under that same path to `values` — real values always take precedence over a same-named
    /// mounted value.
    fn merge_mounted_values(&self, offset: u64, values: &mut Vec<(String, RegValue)>) {
        let Some(path) = self.real_key_paths.get(&offset) else {
            return;
        };
        let Some(cell) = self.mounted.get_cell(path) else {
            return;
        };
        for entry in mounted_cell_values(cell) {
            if !values.iter().any(|(name, _)| *name == entry.0) {
                values.push(entry);
            }
        }
    }

    fn open_key_from_offset_real(&mut self, key_name: &str, offset: u64) -> ForensicResult<u64> {
        if offset == ROOT_CELL_OFFSET && key_name.is_empty() {
            return Ok(ROOT_CELL_OFFSET);
        }
        self.resolve_path_from_offset(key_name.split(['/', '\\']), offset)
    }

    /// Like [`open_key_from_offset_real`], but treats `key_name` as a single literal child name,
    /// never split into path segments — even one containing `/` or `\`. Needed for registry data
    /// (e.g. AmCache's `InventoryDriverBinary`) whose enumerated child names are themselves full
    /// file paths, not a hierarchy to descend. See [`Registry::open_child_raw`] for the public
    /// contract this backs.
    fn open_child_key_from_offset_real(&mut self, key_name: &str, offset: u64) -> ForensicResult<u64> {
        if offset == ROOT_CELL_OFFSET && key_name.is_empty() {
            return Ok(ROOT_CELL_OFFSET);
        }
        self.resolve_path_from_offset(std::iter::once(key_name), offset)
    }

    /// Shared walk behind [`open_key_from_offset_real`] and
    /// [`open_child_key_from_offset_real`] — descends one hive level per item `path_separator`
    /// yields, so the two callers differ only in whether `key_name` is pre-split into segments or
    /// passed through as a single segment.
    fn resolve_path_from_offset<'a>(
        &mut self,
        mut path_separator: impl Iterator<Item = &'a str>,
        offset: u64,
    ) -> ForensicResult<u64> {
        let root_cell = match self.get_cell_at_offset(offset)? {
            HiveCell::KeyNode(kn) => kn,
            _ => {
                return Err(ForensicError::registry_cell_structure_error(
                    "key_node", offset, "KeyNode",
                ));
            }
        };
        let subkeys_offset = root_cell.subkeys_list_offset;
        let n_subkeys = root_cell.number_subkeys;
        let _n_key_val = root_cell.number_key_values;
        let first = match path_separator.next() {
            Some(v) => v,
            None => return Ok(ROOT_CELL_OFFSET), // Root Cell
        };
        if n_subkeys == 0 {
            return Err(ForensicError::registry_key_not_found(
                PredefinedHive::LocalMachine,
                Some(first.into()),
            ));
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
                            ));
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
                    if !key_names_match(&kn.key_name, actual_path) {
                        let (last_offset, counter) = match offset_path.pop() {
                            Some(v) => v,
                            None => {
                                return Err(ForensicError::registry_key_not_found(
                                    PredefinedHive::LocalMachine,
                                    Some(actual_path.into()),
                                ));
                            }
                        };
                        next_offset = last_offset;
                        subkey_last_index = counter + 1;
                        continue;
                    }
                    match path_separator.next() {
                        // A key with no subkeys has no subkeys list (its offset is unset), so a
                        // child of it doesn't exist: not found, not a cell error.
                        Some(v) if kn.number_subkeys == 0 => {
                            return Err(ForensicError::registry_key_not_found(
                                PredefinedHive::LocalMachine,
                                Some(v.into()),
                            ));
                        }
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
                        if actual_path
                            .get(..el.name_hint.len())
                            .is_some_and(|prefix| key_names_match(prefix, &el.name_hint))
                        {
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
                            ));
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
                            ));
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
                            ));
                        }
                    };
                    next_offset = last_offset;
                    subkey_last_index = counter + 1;
                }
                _ => {
                    return Err(ForensicError::registry_key_not_found(
                        PredefinedHive::LocalMachine,
                        Some(actual_path.into()),
                    ));
                }
            };
        }
        Ok(next_offset as u64)
    }
    pub fn open_key(&mut self, key_name: &str) -> ForensicResult<HiveOffset> {
        self.open_key_from_offset(key_name, ROOT_CELL_OFFSET as i64)
    }

    pub fn get_root_cell(&self) -> ForensicResult<&KeyNodeCell> {
        let cell = self
            .cell_cache
            .get(ROOT_CELL_OFFSET)
            .ok_or_else(|| ForensicError::missing_data("hive_root_cell", "Root cell not found".into()))?;

        let kn = match cell {
            HiveCell::KeyNode(ir) => ir,
            _ => {
                return Err(ForensicError::registry_hive_error(
                    "hive_root_cell",
                    "invalid root cell type",
                ));
            }
        };
        Ok(kn)
    }
    pub fn get_cell_at_offset(&mut self, offset: u64) -> ForensicResult<&HiveCell> {
        if self.cell_cache.contains(offset) {
            return Ok(self.cell_cache.get(offset).unwrap());
        }
        if let Some(bins) = self.patched_bins.as_ref() {
            let start = offset as usize;
            let slice = bins.get(start..).ok_or_else(|| {
                ForensicError::registry_cell_error("cell", format!("offset {offset} beyond patched hive-bins-data"))
            })?;
            let cell = read_cell(slice, offset)?;
            self.cell_cache.insert(cell);
            return self.cached_cell_or_missing(offset);
        }
        self.primary
            .seek(std::io::SeekFrom::Start(self.hive_bins_data_offset() + offset))?;
        let mut readed = self.primary.read(&mut self.buffer)?;
        let cell_size = peek_cell(&self.buffer[0..readed]);
        if cell_size > readed {
            // `u32 as usize` never truncates on any platform this crate targets (usize is at
            // least 32 bits) — unlike `try_into().unwrap_or_default()`, it can't silently
            // collapse a legitimate `hive_bins_data_size` down to 0 and make every cell look
            // oversized.
            if cell_size > self.base_block.hive_bins_data_size as usize {
                return Err(ForensicError::registry_cell_error(
                    "cell",
                    format!("invalid cell size {cell_size} at offset {offset}"),
                ));
            }
            if cell_size > self.buffer.len() {
                self.buffer = vec![0; ((cell_size / 1024) + 1) * 1024];
            }
            self.primary
                .seek(std::io::SeekFrom::Start(self.hive_bins_data_offset() + offset))?;
            self.primary.read_exact(&mut self.buffer[0..cell_size])?;
            readed = cell_size;
        }
        let cell = read_cell(&self.buffer[0..readed], offset)?;
        self.cell_cache.insert(cell);
        self.cached_cell_or_missing(offset)
    }

    fn cached_cell_or_missing(&self, offset: u64) -> ForensicResult<&HiveCell> {
        match self.cell_cache.get(offset) {
            Some(cell) => Ok(cell),
            None => Err(ForensicError::missing_data("hive_cell", "Hive cell not found".into())),
        }
    }
    fn hive_bins_data_offset(&self) -> u64 {
        HIVE_BASE_BLOCK_SIZE
    }

    /// Returns the full hive-bins-data region as an owned buffer: [Self::patched_bins] if log
    /// replay populated it, otherwise a fresh read from [Self::primary]. Used by
    /// [crate::recovery]'s unallocated-cell walk, which needs to scan contiguous raw bytes rather
    /// than the cell-by-cell, cache-backed access [Self::get_cell_at_offset] provides. Bounds the
    /// read against the primary file's actual size first, same rationale as the log-replay
    /// allocation guard in [Self::new_with_logs_and_findings].
    pub(crate) fn hive_bins_data(&mut self) -> ForensicResult<Vec<u8>> {
        if let Some(bins) = &self.patched_bins {
            return Ok(bins.clone());
        }
        let declared_size = self.base_block.hive_bins_data_size as u64;
        let file_size = self.primary.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
        if declared_size > file_size {
            return Err(ForensicError::registry_hive_error(
                "hive_bins_data",
                format!(
                    "declared hive_bins_data_size={declared_size} exceeds the file's actual size ({file_size} bytes)"
                ),
            ));
        }
        let mut bins = vec![0u8; declared_size as usize];
        self.primary.seek(std::io::SeekFrom::Start(HIVE_BASE_BLOCK_SIZE))?;
        self.primary.read_exact(&mut bins)?;
        Ok(bins)
    }
}

impl Registry for HiveRegistryReader {
    /// Deleted-key/value carving is implemented — see [RecoverDeleted for HiveRegistryReader].
    fn as_recovery(&self) -> Option<&dyn RecoverDeleted> {
        Some(self)
    }

    fn root(&self, hive: PredefinedHive) -> ForensicResult<RawKey> {
        match hive {
            PredefinedHive::LocalMachine => Ok(pack_raw_key(HiveKind::LmRoot, 0)),
            PredefinedHive::Users => Ok(pack_raw_key(HiveKind::UsersRoot, 0)),
            PredefinedHive::CurrentConfig => {
                if self.current_config.is_some() {
                    Ok(pack_raw_key(HiveKind::CurrentConfig, ROOT_CELL_OFFSET))
                } else {
                    Err(ForensicError::registry_key_not_found(
                        PredefinedHive::CurrentConfig,
                        None,
                    ))
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
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                let cached_keys = self.cached_keys.lock().unwrap();
                let parent_path = cached_keys
                    .get(&payload)
                    .ok_or_else(|| ForensicError::registry_invalid_handle(payload as i64))?
                    .clone();
                drop(cached_keys);
                let child_path = format!("{parent_path}\\{name}");
                let is_mounted = self.mounted.lock().unwrap().contains(&child_path);
                if !is_mounted {
                    return Err(ForensicError::registry_key_not_found(
                        PredefinedHive::LocalMachine,
                        Some(name.into()),
                    ));
                }
                let id = self.next_cached_id();
                self.cached_keys.lock().unwrap().insert(id, child_path);
                Ok(pack_raw_key(HiveKind::Cached, id))
            }
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                let child = match HiveOffset::from_payload(payload) {
                    HiveOffset::Real(offset) => h.open_key_from_offset(name, offset as i64)?,
                    HiveOffset::Mounted(id) => h.open_mounted_child(id, name)?,
                };
                Ok(pack_raw_key(real_kind, child.to_payload()))
            }
        }
    }

    /// Overrides the default (which would delegate to [`Self::open_raw`] and re-split `name`):
    /// only the real-hive-tree branch actually needs single-literal-child semantics — HKLM/HKU's
    /// synthetic roots and the REG-injected `Cached` overlay have no equivalent "flat name with
    /// embedded separators" case, so they fall back to [`Self::open_raw`] unchanged.
    fn open_child_raw(&self, parent: &RawKey, name: &str) -> ForensicResult<RawKey> {
        let (kind, payload) = unpack_raw_key(parent)?;
        match kind {
            HiveKind::LmRoot | HiveKind::UsersRoot | HiveKind::Cached => self.open_raw(parent, name),
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                let child = match HiveOffset::from_payload(payload) {
                    HiveOffset::Real(offset) => h.open_child_key_from_offset(name, offset as i64)?,
                    HiveOffset::Mounted(id) => h.open_mounted_child(id, name)?,
                };
                Ok(pack_raw_key(real_kind, child.to_payload()))
            }
        }
    }

    fn close_raw(&self, key: &RawKey) {
        let Ok((kind, payload)) = unpack_raw_key(key) else {
            return;
        };
        match kind {
            HiveKind::Cached => {
                self.cached_keys.lock().unwrap().remove(&payload);
            }
            HiveKind::LmRoot | HiveKind::UsersRoot => {}
            real_kind => {
                if let HiveOffset::Mounted(id) = HiveOffset::from_payload(payload) {
                    if let Ok(hive) = self.hive_for_kind(real_kind) {
                        if let Ok(mut h) = try_lock_hive(hive) {
                            h.mounted_keys.remove(&id);
                        }
                    }
                }
            }
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
                match HiveOffset::from_payload(payload) {
                    HiveOffset::Real(offset) => read_value_from_hive(&mut h, offset, value_name),
                    HiveOffset::Mounted(id) => match h.mounted_cell(id)? {
                        Some(cell) => cell
                            .value_entries()
                            .find(|(name, _)| *name == value_name)
                            .map(|(_, v)| v.clone())
                            .ok_or_else(|| {
                                ForensicError::registry_value_not_found(PredefinedHive::LocalMachine, None, value_name)
                            }),
                        None => Err(ForensicError::registry_value_not_found(
                            PredefinedHive::LocalMachine,
                            None,
                            value_name,
                        )),
                    },
                }
            }
        }
    }

    fn values_raw(&self, key: &RawKey) -> ForensicResult<Vec<(String, RegValue)>> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::LmRoot | HiveKind::UsersRoot => Ok(Vec::new()),
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                Ok(self.cached_key_values(payload)?)
            }
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                match HiveOffset::from_payload(payload) {
                    HiveOffset::Real(offset) => values_from_hive(&mut h, offset),
                    HiveOffset::Mounted(id) => Ok(match h.mounted_cell(id)? {
                        Some(cell) => mounted_cell_values(cell),
                        None => Vec::new(),
                    }),
                }
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
                Ok(self.cached_key_names(payload)?)
            }
            real_kind => {
                let hive = self.hive_for_kind(real_kind)?;
                let mut h = try_lock_hive(hive)?;
                match HiveOffset::from_payload(payload) {
                    HiveOffset::Real(offset) => keys_from_hive(&mut h, offset),
                    HiveOffset::Mounted(id) => Ok(match h.mounted_cell(id)? {
                        Some(cell) => mounted_cell_keys(cell),
                        None => Vec::new(),
                    }),
                }
            }
        }
    }

    fn info_raw(&self, key: &RawKey) -> ForensicResult<KeyInfo> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                let path = self.cached_key_path(payload)?;
                let mounted = self.mounted.lock().unwrap();
                Ok(match mounted.get_cell(&path) {
                    Some(cell) => KeyInfo {
                        subkeys: cell.key_names().count() as u32,
                        values: cell.value_entries().count() as u32,
                        ..Default::default()
                    },
                    None => KeyInfo::default(),
                })
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
                match HiveOffset::from_payload(payload) {
                    HiveOffset::Real(offset) => {
                        let cell = h.get_cell_at_offset(offset)?;
                        let key_node = match cell {
                            HiveCell::KeyNode(v) => v,
                            _ => {
                                return Err(ForensicError::registry_cell_structure_error(
                                    "key_node", offset, "KeyNode",
                                ));
                            }
                        };
                        Ok(KeyInfo {
                            last_write_time: Some(ForensicTimestamp::from_win_filetime(
                                key_node.last_written_timestamp,
                            )),
                            max_subkey_name_length: key_node.largest_subkey_name_length as u32,
                            max_value_length: key_node.largest_value_data_size,
                            max_value_name_length: key_node.largest_value_name_length,
                            subkeys: key_node.number_subkeys,
                            values: key_node.number_key_values,
                        })
                    }
                    HiveOffset::Mounted(id) => Ok(match h.mounted_cell(id)? {
                        Some(cell) => KeyInfo {
                            subkeys: cell.key_names().count() as u32,
                            values: cell.value_entries().count() as u32,
                            ..Default::default()
                        },
                        None => KeyInfo::default(),
                    }),
                }
            }
        }
    }

    fn values_iter_raw<'a>(
        &'a self,
        key: &RawKey,
    ) -> ForensicResult<Box<dyn Iterator<Item = (String, RegValue)> + 'a>> {
        let (kind, payload) = unpack_raw_key(key)?;
        match kind {
            HiveKind::LmRoot | HiveKind::UsersRoot => Ok(Box::new(std::iter::empty())),
            HiveKind::Cached => {
                self.require_cached_key(payload)?;
                Ok(Box::new(self.cached_key_values(payload)?.into_iter()))
            }
            real_kind => {
                let hive_cell = self.hive_for_kind(real_kind)?;
                let mut hive = try_lock_hive(hive_cell)?;
                let offset = match HiveOffset::from_payload(payload) {
                    HiveOffset::Real(offset) => offset,
                    HiveOffset::Mounted(id) => {
                        let values = match hive.mounted_cell(id)? {
                            Some(cell) => mounted_cell_values(cell),
                            None => Vec::new(),
                        };
                        return Ok(Box::new(values.into_iter()));
                    }
                };
                let cell = hive.get_cell_at_offset(offset)?;
                let key_node = match cell {
                    HiveCell::KeyNode(v) => v,
                    _ => {
                        return Err(ForensicError::registry_cell_structure_error(
                            "key_node", offset, "KeyNode",
                        ));
                    }
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
                let offset = match HiveOffset::from_payload(payload) {
                    HiveOffset::Real(offset) => offset,
                    HiveOffset::Mounted(id) => {
                        let keys = match hive.mounted_cell(id)? {
                            Some(cell) => mounted_cell_keys(cell),
                            None => Vec::new(),
                        };
                        return Ok(Box::new(keys.into_iter()));
                    }
                };
                let cell = hive.get_cell_at_offset(offset)?;
                let key_node = match cell {
                    HiveCell::KeyNode(v) => v,
                    _ => {
                        return Err(ForensicError::registry_cell_structure_error(
                            "key_node", offset, "KeyNode",
                        ));
                    }
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

    /// Overrides the default (which delegates to [Registry::values_raw] and extends `out` from
    /// the resulting `Vec`) to instead drive [Self::values_iter_raw] directly, avoiding that
    /// intermediate allocation.
    fn values_raw_into(&self, key: &RawKey, out: &mut Vec<(String, RegValue)>) -> ForensicResult<()> {
        out.extend(self.values_iter_raw(key)?);
        Ok(())
    }

    /// Like [Self::values_raw_into]; see its doc comment for the buffer-reuse rationale.
    fn keys_raw_into(&self, key: &RawKey, out: &mut Vec<KeyEntry>) -> ForensicResult<()> {
        out.extend(self.keys_iter_raw(key)?);
        Ok(())
    }
}

impl HiveRegistryReader {
    /// Every currently-loaded hive paired with a human-readable label identifying it (used for
    /// `warn!` context and as the [RecoveredKey::parent_hint]/[RecoveredValue::key_hint]
    /// provenance placeholder — see [crate::recovery]'s module doc — not a real key path).
    fn all_hives(&self) -> Vec<(String, &Mutex<HiveFiles>)> {
        let mut all = Vec::new();
        if let Some(h) = &self.sam {
            all.push(("SAM".to_string(), h));
        }
        if let Some(h) = &self.security {
            all.push(("SECURITY".to_string(), h));
        }
        if let Some(h) = &self.software {
            all.push(("SOFTWARE".to_string(), h));
        }
        if let Some(h) = &self.system {
            all.push(("SYSTEM".to_string(), h));
        }
        if let Some(h) = &self.current_config {
            all.push(("CurrentConfig".to_string(), h));
        }
        for (sid, h) in &self.users {
            all.push((format!("User:{sid}"), h));
        }
        for (mount_path, h) in &self.others {
            all.push((format!("Other:{mount_path}"), h));
        }
        all
    }
}

/// Deleted-key/value recovery, carving unallocated hive cells — see [crate::recovery]'s module
/// doc comment for the validation applied and its known limitations. Aggregates across every
/// currently-loaded hive (the trait itself takes no hive parameter); a hive this can't lock (e.g.
/// concurrently borrowed by an in-progress read elsewhere) or that fails to scan is skipped with a
/// `warn!`, not treated as a fatal error for the whole aggregate result — recovery is inherently
/// best-effort, and one uncooperative hive shouldn't hide what every other hive still yielded.
impl RecoverDeleted for HiveRegistryReader {
    fn deleted_keys(&self) -> ForensicResult<Vec<Recovered<RecoveredKey>>> {
        let mut all = Vec::new();
        for (label, hive) in self.all_hives() {
            let mut guard = match try_lock_hive(hive) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Cannot lock hive {label} to scan for deleted keys: {:?}", e);
                    continue;
                }
            };
            match recovery::scan_deleted_keys(&mut guard) {
                // `.map()` transforms the recovered value in place while carrying its
                // `Recovery`/`Locus` through unchanged — `Recovered` has no `Deref`, so this is
                // the sanctioned way to touch the inner value without dropping the recovery mode.
                Ok(found) => all.extend(found.into_iter().map(|r| {
                    r.map(|mut k| {
                        if k.parent_hint.is_none() {
                            k.parent_hint = Some(format!("<{label}>"));
                        }
                        k
                    })
                })),
                Err(e) => warn!("Error scanning hive {label} for deleted keys: {:?}", e),
            }
        }
        Ok(all)
    }

    fn deleted_values(&self) -> ForensicResult<Vec<Recovered<RecoveredValue>>> {
        let mut all = Vec::new();
        for (label, hive) in self.all_hives() {
            let mut guard = match try_lock_hive(hive) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Cannot lock hive {label} to scan for deleted values: {:?}", e);
                    continue;
                }
            };
            match recovery::scan_deleted_values(&mut guard) {
                Ok(found) => all.extend(found.into_iter().map(|r| {
                    r.map(|mut v| {
                        v.key_hint = Some(format!("<{label}>"));
                        v
                    })
                })),
                Err(e) => warn!("Error scanning hive {label} for deleted values: {:?}", e),
            }
        }
        Ok(all)
    }
}

/// `path`'s directory and file name, for [open_hive_with_logs].
fn split(path: &FPath) -> (&FPath, &str) {
    (
        path.parent().unwrap_or(FPath::new("")),
        path.file_name().unwrap_or(path.as_str()),
    )
}

/// Opens `name` (plus any discoverable `.LOG1`/`.LOG2` companions) under `base_path` and parses
/// it into a [HiveFiles]. Returns `None` both when the primary file simply doesn't exist (a
/// routine, expected outcome — not every hive kind is present in every filesystem) and when it
/// exists but fails to parse — but only the latter additionally records a `ProcessingError`
/// [Finding] in `findings`, since a hive that was found but couldn't be read means evidence went
/// unexamined, not merely evidence that was never there.
pub fn open_hive_with_logs(
    fs: &Arc<dyn FileSystem>,
    base_path: &FPath,
    name: &str,
    findings: &mut Vec<Finding>,
) -> Option<HiveFiles> {
    let primary_path = base_path.join(name);
    let primary = fs.open(primary_path.as_path()).ok()?;
    let mut logs: [Option<Box<dyn VirtualFile>>; 2] = [None, None];
    for (i, log) in logs.iter_mut().enumerate() {
        let log_i = base_path.join(format!("{name}.LOG{}", i + 1));
        match fs.open(log_i.as_path()) {
            Ok(v) => *log = Some(v),
            Err(e) => debug!("Cannot open hive log {}: {:?}", log_i, e),
        };
    }
    let [log1, log2] = logs;
    let path_display = primary_path.to_string();
    match HiveFiles::new_with_logs_and_findings(primary_path, primary, log1, log2, findings) {
        Ok(hive) => Some(hive),
        Err(e) => {
            warn!("Cannot parse hive {}: {:?}", path_display, e);
            findings.push(Finding::from_error(format!("parsing hive {path_display}"), &e));
            None
        }
    }
}

#[cfg(test)]
#[path = "reader_tst.rs"]
mod tst;
