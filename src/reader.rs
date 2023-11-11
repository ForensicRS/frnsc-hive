use std::{collections::BTreeMap, path::PathBuf};

use forensic_rs::{traits::vfs::VirtualFile, prelude::{RegHiveKey, RegValue}};

pub struct HiveRegistryReader {
    hives : BTreeMap<RegHiveKey,HiveFiles>
}

pub struct HiveReader {
    pub files : HiveFiles,
    pub opened_keys : BTreeMap<RegHiveKey, RegValue>
}

pub struct HiveFiles {
    pub(crate) location : PathBuf,
    pub(crate) primary : Box<dyn VirtualFile>,
    pub(crate) logs : Vec<Box<dyn VirtualFile>>
}


#[cfg(test)]
mod tst {
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
}

