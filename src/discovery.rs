//! Finds hives by name anywhere on a filesystem, for evidence that isn't laid out like a Windows
//! volume: a triage collection (`CopiedFiles/registry/SYSTEM`,
//! `CopiedFiles/registry/<user>_NTUSER.DAT`), a folder of exported hives, a KAPE target tree.
//!
//! Names alone are not trusted: every candidate must carry the `regf` magic, and a file named like
//! a machine hive whose own header names a different hive is rejected, with a finding.

use std::collections::BTreeMap;
use std::io::Read;

use forensic_rs::core::fs::walk::WalkOptions;
use forensic_rs::core::path::Component;
use forensic_rs::prelude::*;

use crate::hive::is_valid_base_block;

/// Machine hives, by the file name they're exported under.
pub const MACHINE_HIVES: [&str; 4] = ["SAM", "SECURITY", "SOFTWARE", "SYSTEM"];
/// A user hive's file name, lowercase: `NTUSER.DAT`, or `NTUSER.MAN` for a mandatory profile.
/// Matched as a suffix, so an export's `<user>_NTUSER.DAT` is one too. Same length, on purpose:
/// [user_label] strips either.
const USER_HIVE_NAMES: [&str; 2] = ["ntuser.dat", "ntuser.man"];
/// A user's class hive's file name, lowercase, matched as a suffix like [USER_HIVE_NAMES]. In a
/// profile it lives at `AppData\Local\Microsoft\Windows\UsrClass.dat` and is loaded by Windows as
/// `HKU\<sid>_Classes`.
const CLASS_HIVE_NAME: &str = "usrclass.dat";

/// Default walk depth: deep enough for `<collection>/<host>/CopiedFiles/registry/<hive>`.
pub const MAX_DEPTH: u32 = 8;

/// A user hive found by name, and the label it was found under: the profile folder for a bare
/// `NTUSER.DAT`, or the prefix of `<user>_NTUSER.DAT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserHive {
    pub label: String,
    pub path: FPathBuf,
}

/// What [find_hives] found. Every list is sorted, so output doesn't depend on walk order.
#[derive(Debug, Default)]
pub struct HiveCandidates {
    /// One path per machine hive name (`SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM`).
    pub machine: BTreeMap<&'static str, FPathBuf>,
    pub users: Vec<UserHive>,
    /// Users' `UsrClass.dat`, labelled by the profile folder they're under (or the prefix of
    /// `<user>_UsrClass.dat`), so a label matches the same user's [Self::users] entry.
    pub classes: Vec<UserHive>,
    pub amcache: Vec<FPathBuf>,
    /// Candidates set aside: duplicates, and files whose header names another hive.
    pub findings: Vec<Finding>,
    /// Directories or files the walk could not read.
    pub errors: Vec<ForensicError>,
}

/// Walks `fs` (up to [MAX_DEPTH] below its root) for hives by file name, case-insensitively.
///
/// When a machine hive name appears more than once, the copy under `Windows\System32\config` (not
/// `RegBack`) wins, then the shallowest, then the first by path; every other copy is reported as a
/// finding.
pub fn find_hives(fs: &dyn FileSystem) -> HiveCandidates {
    let mut out = HiveCandidates::default();
    let mut machine: BTreeMap<&'static str, Vec<FPathBuf>> = BTreeMap::new();
    let opts = WalkOptions::default()
        .with_max_depth(Some(MAX_DEPTH))
        .with_skip_errors(false);
    for item in fs.walk(FPath::new(""), &opts) {
        let entry = match item {
            Ok(entry) => entry,
            Err(e) => {
                out.errors.push(e);
                continue;
            }
        };
        if entry.file_type != VFileType::File {
            continue;
        }
        let Some(name) = entry.path.as_path().file_name().map(str::to_string) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if let Some(hive) = MACHINE_HIVES.iter().find(|h| h.eq_ignore_ascii_case(&name)) {
            match header_hint(fs, entry.path.as_path()) {
                Ok(Some(hint)) if names_other_hive(&hint, hive) => out.findings.push(set_aside(
                    &entry.path,
                    format!("its header names another hive ({hint})"),
                )),
                Ok(Some(_)) => machine.entry(hive).or_default().push(entry.path),
                Ok(None) => {} // not a hive at all: a file that happens to be called SYSTEM
                Err(e) => out.errors.push(e),
            }
        } else if USER_HIVE_NAMES.iter().any(|n| lower.ends_with(n)) {
            match header_hint(fs, entry.path.as_path()) {
                Ok(Some(_)) => out.users.push(UserHive {
                    label: user_label(entry.path.as_path(), &name),
                    path: entry.path,
                }),
                Ok(None) => {}
                Err(e) => out.errors.push(e),
            }
        } else if lower.ends_with(CLASS_HIVE_NAME) {
            match header_hint(fs, entry.path.as_path()) {
                Ok(Some(_)) => out.classes.push(UserHive {
                    label: class_label(entry.path.as_path(), &name),
                    path: entry.path,
                }),
                Ok(None) => {}
                Err(e) => out.errors.push(e),
            }
        } else if lower == "amcache.hve" {
            match header_hint(fs, entry.path.as_path()) {
                Ok(Some(_)) => out.amcache.push(entry.path),
                Ok(None) => {}
                Err(e) => out.errors.push(e),
            }
        }
    }
    for (hive, mut paths) in machine {
        paths.sort_by_key(|p| rank(p.as_path()));
        let mut paths = paths.into_iter();
        if let Some(best) = paths.next() {
            for other in paths {
                out.findings
                    .push(set_aside(&other, format!("another {hive} hive was preferred: {best}")));
            }
            out.machine.insert(hive, best);
        }
    }
    out.users.sort_by(|a, b| a.path.cmp(&b.path));
    // Windows loads `NTUSER.MAN` instead of `NTUSER.DAT` when a profile has both, and both would
    // load under the same label: keep the one Windows uses, report the other.
    let mandatory: Vec<(Option<String>, String)> = out
        .users
        .iter()
        .filter(|u| u.path.as_str().to_ascii_lowercase().ends_with("ntuser.man"))
        .map(|u| (u.path.parent().map(|p| p.as_str().to_string()), u.label.clone()))
        .collect();
    let (kept, shadowed): (Vec<UserHive>, Vec<UserHive>) = std::mem::take(&mut out.users).into_iter().partition(|u| {
        !u.path.as_str().to_ascii_lowercase().ends_with("ntuser.dat")
            || !mandatory
                .iter()
                .any(|(dir, label)| *dir == u.path.parent().map(|p| p.as_str().to_string()) && *label == u.label)
    });
    for user in shadowed {
        out.findings.push(set_aside(
            &user.path,
            "NTUSER.MAN in the same folder is the profile's hive (a mandatory profile)".to_string(),
        ));
    }
    out.users = kept;
    out.classes.sort_by(|a, b| a.path.cmp(&b.path));
    out.amcache.sort();
    out
}

/// The hive name a base block records for itself (`\??\C:\Windows\System32\config\SYSTEM`), empty
/// when unset. `None` when the bytes are not a hive base block.
pub fn file_name_hint(base_block: &[u8]) -> Option<String> {
    if !is_valid_base_block(base_block) {
        return None;
    }
    Some(decode_hint(base_block.get(0x30..0x30 + 64)?))
}

/// The base block's 64-byte UTF-16LE `file_name` field, up to its first NUL.
pub(crate) fn decode_hint(raw: &[u8]) -> String {
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

fn header_hint(fs: &dyn FileSystem, path: &FPath) -> ForensicResult<Option<String>> {
    let mut file = fs.open(path)?;
    let mut block = vec![0u8; 4096];
    if file.read_exact(&mut block).is_err() {
        return Ok(None); // shorter than a base block: not a hive
    }
    Ok(file_name_hint(&block))
}

/// Whether a non-empty `hint` names one of the other machine hives than `expected`.
fn names_other_hive(hint: &str, expected: &str) -> bool {
    let last = hint.rsplit(['\\', '/']).next().unwrap_or_default().to_ascii_uppercase();
    MACHINE_HIVES.contains(&last.as_str()) && !last.eq_ignore_ascii_case(expected)
}

/// `(0 for a live config folder copy, depth, path)`, smallest first.
fn rank(path: &FPath) -> (u8, usize, String) {
    let lower = path.as_str().replace('/', "\\").to_ascii_lowercase();
    let live = lower.contains("\\system32\\config\\") || lower.starts_with("system32\\config\\");
    let preferred = if live && !lower.contains("regback") { 0 } else { 1 };
    let depth = lower.matches('\\').count();
    (preferred, depth, path.as_str().to_string())
}

fn user_label(path: &FPath, name: &str) -> String {
    let prefix = &name[..name.len() - USER_HIVE_NAMES[0].len()];
    let prefix = prefix.trim_end_matches(['_', '-', '.', ' ']);
    if prefix.is_empty() {
        path.parent()
            .and_then(|p| p.file_name())
            .unwrap_or("MountedUser")
            .to_string()
    } else {
        prefix.to_string()
    }
}

/// The prefix of `<user>_UsrClass.dat`, else the profile folder: the folder holding the
/// `AppData` the hive is under, else the hive's own folder.
fn class_label(path: &FPath, name: &str) -> String {
    let prefix = &name[..name.len() - CLASS_HIVE_NAME.len()];
    let prefix = prefix.trim_end_matches(['_', '-', '.', ' ']);
    if !prefix.is_empty() {
        return prefix.to_string();
    }
    let folders: Vec<&str> = path
        .parent()
        .map(|p| {
            p.components()
                .filter_map(|c| match c {
                    Component::Normal(n) => Some(n),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    folders
        .iter()
        .rposition(|f| f.eq_ignore_ascii_case("AppData"))
        .and_then(|i| i.checked_sub(1))
        .or_else(|| folders.len().checked_sub(1))
        .map(|i| folders[i].to_string())
        .unwrap_or_else(|| "MountedUser".to_string())
}

fn set_aside(path: &FPathBuf, why: String) -> Finding {
    Finding::new(
        FindingSeverity::Info,
        FindingCategory::MissingData,
        format!("Hive candidate not loaded: {path}"),
    )
    .with_description(format!("{path} was not loaded: {why}."))
    .with_metadata(Text::Borrowed("hive.path"), Text::Owned(path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;

    /// A minimal valid base block whose file-name hint is `hint`, keeping its last 31 UTF-16
    /// units the way Windows does.
    pub(crate) fn base_block(hint: &str) -> Vec<u8> {
        let mut b = vec![0u8; 4096];
        b[0..4].copy_from_slice(b"regf");
        let units: Vec<u16> = hint.encode_utf16().collect();
        let tail = &units[units.len().saturating_sub(31)..];
        for (i, u) in tail.iter().enumerate() {
            b[0x30 + 2 * i..0x30 + 2 * i + 2].copy_from_slice(&u.to_le_bytes());
        }
        b
    }

    #[test]
    fn finds_a_triage_layout_and_prefers_the_live_config_copy() {
        let fs = InMemoryVirtualFileSystem::new()
            .with_file(
                "host/CopiedFiles/registry/SYSTEM",
                base_block(r"\??\C:\Windows\System32\config\SYSTEM"),
            )
            .with_file("C/Windows/System32/config/RegBack/SYSTEM", base_block("SYSTEM"))
            .with_file("C/Windows/System32/config/SYSTEM", base_block(""))
            .with_file(
                "host/CopiedFiles/registry/bob_NTUSER.DAT",
                base_block(r"\??\C:\Users\bob\ntuser.dat"),
            )
            .with_file("C/Users/alice/NTUSER.DAT", base_block(""))
            .with_file("host/CopiedFiles/Amcache.hve", base_block(""))
            // Named like a hive, but its header says SOFTWARE; and one that isn't a hive at all.
            .with_file(
                "host/CopiedFiles/registry/SAM",
                base_block(r"\??\C:\Windows\System32\config\SOFTWARE"),
            )
            .with_file("notes/SECURITY", b"not a hive".to_vec());
        let found = find_hives(&fs);
        assert!(found.errors.is_empty(), "{:?}", found.errors);
        assert_eq!(
            found.machine.get("SYSTEM").map(|p| p.as_str()),
            Some("C/Windows/System32/config/SYSTEM")
        );
        assert!(!found.machine.contains_key("SAM"));
        assert!(!found.machine.contains_key("SECURITY"));
        let labels: Vec<_> = found.users.iter().map(|u| u.label.as_str()).collect();
        assert_eq!(labels, ["alice", "bob"]);
        assert_eq!(found.amcache.len(), 1);
        // Two SYSTEM copies set aside, one SAM rejected by its header.
        assert_eq!(found.findings.len(), 3, "{:?}", found.findings);
    }

    #[test]
    fn finds_class_hives_labelled_like_their_user_hive() {
        let fs = InMemoryVirtualFileSystem::new()
            .with_file("C/Users/alice/NTUSER.DAT", base_block(""))
            .with_file(
                "C/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat",
                base_block(r"\??\C:\Users\alice\AppData\Local\Microsoft\Windows\UsrClass.dat"),
            )
            .with_file("host/CopiedFiles/registry/bob_UsrClass.dat", base_block(""))
            .with_file("exports/usrclass.dat", base_block(""))
            .with_file(
                "C/Users/eve/AppData/Local/Microsoft/Windows/UsrClass.dat",
                b"short".to_vec(),
            );
        let found = find_hives(&fs);
        assert!(found.errors.is_empty(), "{:?}", found.errors);
        let classes: Vec<(&str, &str)> = found
            .classes
            .iter()
            .map(|u| (u.label.as_str(), u.path.as_str()))
            .collect();
        assert_eq!(
            classes,
            [
                ("alice", "C/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat"),
                ("exports", "exports/usrclass.dat"),
                ("bob", "host/CopiedFiles/registry/bob_UsrClass.dat"),
            ]
        );
        let users: Vec<&str> = found.users.iter().map(|u| u.label.as_str()).collect();
        assert_eq!(users, ["alice"]);
    }

    #[test]
    fn a_mandatory_profile_s_ntuser_man_is_a_user_hive_and_wins_over_ntuser_dat() {
        let fs = InMemoryVirtualFileSystem::new()
            .with_file("C/Windows/System32/config/SYSTEM", base_block(""))
            .with_file("C/Users/kiosk/NTUSER.MAN", base_block(""))
            .with_file("C/Users/kiosk/NTUSER.DAT", base_block(""))
            .with_file("C/Users/carol/NTUSER.MAN", base_block(""))
            .with_file("C/Users/dave/NTUSER.DAT", base_block(""));
        let found = find_hives(&fs);
        let users: Vec<(&str, &str)> = found
            .users
            .iter()
            .map(|u| (u.label.as_str(), u.path.as_str()))
            .collect();
        assert_eq!(
            users,
            [
                ("carol", "C/Users/carol/NTUSER.MAN"),
                ("dave", "C/Users/dave/NTUSER.DAT"),
                ("kiosk", "C/Users/kiosk/NTUSER.MAN"),
            ]
        );
        // The shadowed NTUSER.DAT is reported, not silently dropped.
        assert_eq!(found.findings.len(), 1, "{:?}", found.findings);
        assert!(
            found.findings[0].title.contains("C/Users/kiosk/NTUSER.DAT"),
            "{:?}",
            found.findings
        );
    }
}
