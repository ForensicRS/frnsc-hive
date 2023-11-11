pub mod hive;
pub mod reader;

#[cfg(test)]
pub(crate) mod tst;

use std::path::PathBuf;

use forensic_rs::prelude::RegHiveKey;

pub fn load_hive(hive : RegHiveKey, path : PathBuf) {

}

