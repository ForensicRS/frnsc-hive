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
