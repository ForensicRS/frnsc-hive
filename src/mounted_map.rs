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
        Self { cell: BTreeMap::new() }
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        let Some((hkey, rest)) = path.split_once(['/', '\\']) else {
            return self
                .cell
                .entry(path.to_string())
                .or_insert(MountedCell::new())
                .add_value("", value, data);
        };
        self.cell
            .entry(hkey.to_string())
            .or_insert(MountedCell::new())
            .add_value(rest, value, data);
    }
    pub fn contains(&self, path: &str) -> bool {
        let Some((hkey, rest)) = path.split_once(['/', '\\']) else {
            return self.cell.contains_key(path);
        };
        let Some(hive) = self.cell.get(hkey) else {
            return false;
        };
        hive.contains_key(rest)
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        let (hkey, rest) = path.split_once(['/', '\\'])?;
        self.cell.get(hkey)?.get_value(rest, value)
    }
    /// Resolves `path` to the [MountedCell] at that path, whether it's a value-bearing key or a
    /// pure intermediate node (e.g. `Foo` in a trie that only ever had `Foo\Bar\Baz` added) —
    /// mirrors what [MountedMap::contains] already treats as "exists".
    pub fn get_cell(&self, path: &str) -> Option<&MountedCell> {
        let Some((hkey, rest)) = path.split_once(['/', '\\']) else {
            return self.cell.get(path);
        };
        self.cell.get(hkey)?.get_cell(rest)
    }
}

pub struct MountedCell {
    pub keys: BTreeMap<String, MountedCell>,
    pub values: BTreeMap<String, RegValue>,
}
impl MountedCell {
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }
    pub fn contains_key(&self, path: &str) -> bool {
        let Some((first, rest)) = path.split_once(['/', '\\']) else {
            return self.keys.contains_key(path);
        };
        let Some(hive) = self.keys.get(first) else {
            return false;
        };
        hive.contains_key(rest)
    }
    pub fn add_value(&mut self, path: &str, value: &str, data: RegValue) {
        if path.is_empty() {
            self.values.insert(value.into(), data);
            return;
        }
        let Some((first, rest)) = path.split_once(['/', '\\']) else {
            self.keys
                .entry(path.to_string())
                .or_insert(MountedCell::new())
                .add_value("", value, data);
            return;
        };
        self.keys
            .entry(first.to_string())
            .or_insert(MountedCell::new())
            .add_value(rest, value, data);
    }
    pub fn get_value(&self, path: &str, value: &str) -> Option<RegValue> {
        if path.is_empty() {
            return self.values.get(value).cloned();
        }
        let Some((first, rest)) = path.split_once(['/', '\\']) else {
            return self.keys.get(path)?.get_value("", value);
        };
        self.keys.get(first)?.get_value(rest, value)
    }
    /// Resolves `path` (relative to this cell) to the [MountedCell] at that path. An empty
    /// `path` resolves to `self`.
    pub fn get_cell(&self, path: &str) -> Option<&MountedCell> {
        if path.is_empty() {
            return Some(self);
        }
        let Some((first, rest)) = path.split_once(['/', '\\']) else {
            return self.keys.get(path);
        };
        self.keys.get(first)?.get_cell(rest)
    }
    /// Names of the immediate child keys of this cell (not recursive).
    pub fn key_names(&self) -> impl Iterator<Item = &str> {
        self.keys.keys().map(String::as_str)
    }
    /// The values directly on this cell (not recursive into subkeys).
    pub fn value_entries(&self) -> impl Iterator<Item = (&str, &RegValue)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v))
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    #[test]
    fn should_round_trip_add_and_get_value_on_nested_path() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Bar", RegValue::SZ("baz".into()));
        assert_eq!(
            Some(RegValue::SZ("baz".into())),
            map.get_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Bar")
        );
    }

    #[test]
    fn should_treat_forward_and_back_slash_separators_the_same() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Bar", RegValue::SZ("baz".into()));
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
        let mut cell = MountedCell::new();
        cell.add_value("", "Bar", RegValue::DWord(42));
        assert_eq!(Some(RegValue::DWord(42)), cell.get_value("", "Bar"));
    }

    #[test]
    fn get_cell_returns_intermediate_node_with_no_direct_value() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo\Bar", "V", RegValue::DWord(1));
        let cell = map
            .get_cell(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo")
            .expect("intermediate node should exist");
        assert_eq!(
            Vec::<(&str, &RegValue)>::new(),
            cell.value_entries().collect::<Vec<_>>()
        );
        assert_eq!(vec!["Bar"], cell.key_names().collect::<Vec<_>>());
    }

    #[test]
    fn get_cell_returns_none_for_missing_path() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Bar", RegValue::DWord(1));
        assert!(map.get_cell(r"HKEY_LOCAL_MACHINE\SOFTWARE\DoesNotExist").is_none());
        assert!(map.get_cell(r"HKEY_LOCAL_MACHINE\OTHER\Foo").is_none());
    }

    #[test]
    fn key_names_lists_immediate_children_only() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo\Bar", "V", RegValue::DWord(1));
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo\Baz\Deep", "V", RegValue::DWord(2));
        let cell = map.get_cell(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo").unwrap();
        let mut names: Vec<&str> = cell.key_names().collect();
        names.sort();
        assert_eq!(vec!["Bar", "Baz"], names);
    }

    #[test]
    fn value_entries_lists_all_values_on_a_cell() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "A", RegValue::DWord(1));
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "B", RegValue::DWord(2));
        let cell = map.get_cell(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo").unwrap();
        let mut values: Vec<(&str, &RegValue)> = cell.value_entries().collect();
        values.sort_by_key(|(name, _)| *name);
        assert_eq!(vec![("A", &RegValue::DWord(1)), ("B", &RegValue::DWord(2))], values);
    }

    #[test]
    fn sibling_cells_enumerate_independently() {
        let mut map = MountedMap::new();
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo", "Version", RegValue::DWord(1));
        map.add_value(r"HKEY_LOCAL_MACHINE\SOFTWARE\Bar", "Version", RegValue::DWord(2));
        let foo = map.get_cell(r"HKEY_LOCAL_MACHINE\SOFTWARE\Foo").unwrap();
        let bar = map.get_cell(r"HKEY_LOCAL_MACHINE\SOFTWARE\Bar").unwrap();
        assert_eq!(
            vec![("Version", &RegValue::DWord(1))],
            foo.value_entries().collect::<Vec<_>>()
        );
        assert_eq!(
            vec![("Version", &RegValue::DWord(2))],
            bar.value_entries().collect::<Vec<_>>()
        );
    }
}
