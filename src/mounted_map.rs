//! An in-memory trie of registry keys/values that don't come from a parsed hive file — e.g. keys
//! injected from a REG file via `HiveRegistryReader::add_reg_key`. Each path segment (split on
//! `/` or `\`) becomes one level of nested [MountedCell]s; [MountedCell::values] holds the leaf
//! values for that key.
//!
//! There are two separate uses of [MountedMap] in this crate, and they are not interchangeable:
//! one lives directly on `HiveRegistryReader` for paths that don't belong to any loaded hive at
//! all, and one lives on each `HiveFiles` (via `HiveFiles::add_mounted_value`) for values mounted
//! "underneath" an otherwise real, on-disk hive. The latter's consumers
//! (`HiveFiles::open_mounted_key` and friends) are currently unimplemented stubs — see
//! [crate::reader]'s module docs.

use std::collections::BTreeMap;

use forensic_rs::traits::registry::RegValue;

pub struct MountedMap {
    pub cell: BTreeMap<String, MountedCell>,
}

impl MountedMap {
    pub fn new() -> Self {
        Self {
            cell: BTreeMap::new(),
        }
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        let (hkey, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => {
                return self
                    .cell
                    .entry(path.to_string())
                    .or_insert(MountedCell::new(path))
                    .add_value("", value, data)
            }
        };
        self.cell
            .entry(hkey.to_string())
            .or_insert(MountedCell::new(hkey))
            .add_value(rest, value, data);
    }
    pub fn contains(&self, path: &str) -> bool {
        let (hkey, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return self.cell.contains_key(path),
        };
        let hive = match self.cell.get(hkey) {
            Some(v) => v,
            None => return false,
        };
        hive.contains_key(rest)
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        let (hkey, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return None,
        };
        let hive = match self.cell.get(hkey) {
            Some(v) => v,
            None => return None,
        };
        hive.get_value(rest, value)
    }
}

pub struct MountedCell {
    pub name: String,
    pub keys: BTreeMap<String, MountedCell>,
    pub values: BTreeMap<String, RegValue>,
}
impl MountedCell {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            keys: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }
    pub fn contains_key(&self, path: &str) -> bool {
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return self.keys.contains_key(path),
        };
        let hive = match self.keys.get(first) {
            Some(v) => v,
            None => return false,
        };
        hive.contains_key(rest)
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        if path.is_empty() {
            self.values.insert(value.into(), data);
            return;
        }
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => {
                self.keys
                    .entry(path.to_string())
                    .or_insert(MountedCell::new(path))
                    .add_value("", value, data);
                return;
            }
        };
        self.keys
            .entry(first.to_string())
            .or_insert(MountedCell::new(first))
            .add_value(rest, value, data);
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        if path.is_empty() {
            return self.values.get(value).cloned();
        }
        let (first, rest) = match path.split_once(|v| v == '/' || v == '\\') {
            Some(v) => v,
            None => return self.keys.get(path)?.get_value("", value),
        };
        self.keys.get(first)?.get_value(rest, value)
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn should_round_trip_add_and_get_value_on_nested_path() {
        let mut map = MountedMap::new();
        map.add_value(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo",
            "Bar",
            RegValue::SZ("baz".into()),
        );
        assert_eq!(
            Some(RegValue::SZ("baz".into())),
            map.get_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Bar")
        );
    }

    #[test]
    fn should_treat_forward_and_back_slash_separators_the_same() {
        let mut map = MountedMap::new();
        map.add_value(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo",
            "Bar",
            RegValue::SZ("baz".into()),
        );
        assert_eq!(
            Some(RegValue::SZ("baz".into())),
            map.get_value("HKEY_LOCAL_MACHINE/SOFTWARE/Foo", "Bar")
        );
    }

    #[test]
    fn contains_reports_exact_and_missing_paths() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Bar", RegValue::DWord(1));
        assert!(map.contains(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo"));
        assert!(!map.contains(r"HKEY_LOCAL_MACHINE\SOFTWARE\DoesNotExist"));
        assert!(!map.contains(r"HKEY_LOCAL_MACHINE\OTHER\Foo"));
    }

    #[test]
    fn get_value_returns_none_for_wrong_value_name_or_missing_path() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Bar", RegValue::DWord(1));
        assert_eq!(None, map.get_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "OtherValue"));
        assert_eq!(None, map.get_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Missing", "Bar"));
        assert_eq!(None, map.get_value(r"HKEY_USERS\SOFTWARE\Foo", "Bar"));
    }

    #[test]
    fn sibling_keys_do_not_collide_on_same_value_name() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Version", RegValue::DWord(1));
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Bar", "Version", RegValue::DWord(2));
        assert_eq!(
            Some(RegValue::DWord(1)),
            map.get_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Version")
        );
        assert_eq!(
            Some(RegValue::DWord(2)),
            map.get_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Bar", "Version")
        );
    }

    #[test]
    fn mounted_cell_add_value_with_empty_path_inserts_directly() {
        let mut cell = MountedCell::new("Foo");
        cell.add_value("", "Bar", RegValue::DWord(42));
        assert_eq!(Some(RegValue::DWord(42)), cell.get_value("", "Bar"));
    }
}
