pub mod hive;
pub mod reader;
pub mod cell;

#[cfg(test)]
pub(crate) mod tst;

use std::path::PathBuf;

use forensic_rs::prelude::RegHiveKey;

pub fn load_hive(hive : RegHiveKey, path : PathBuf) {

}

