use std::sync::Arc;

use forensic_rs::prelude::{FPath, FileSystem, StdVirtualFS, VirtualFile};

/// Chroots one level *below* the checked-in `./artifacts/` fixture folder, at its `C/`
/// subdirectory. `ChRootFileSystem` (0.14) drops a path's leading drive/root component entirely
/// rather than folding it into a folder name, so an absolute, drive-prefixed evidence path like
/// `C:\Windows\System32\Config\SAM` resolves relative to *this* root as `Windows/System32/Config/SAM`
/// — landing on `./artifacts/C/Windows/System32/Config/SAM`, exactly the fixture's real layout.
pub(crate) fn init_virtual_fs() -> Arc<dyn FileSystem> {
    Arc::new(forensic_rs::core::fs::ChRootFileSystem::new(
        "./artifacts/C/",
        Arc::new(StdVirtualFS::new()),
    ))
}

pub(crate) fn read_sam_hive(fs: &Arc<dyn FileSystem>) -> Box<dyn VirtualFile> {
    fs.open(FPath::new("C:\\Windows\\System32\\Config\\SAM"))
        .unwrap()
}
pub(crate) fn read_sec_hive(fs: &Arc<dyn FileSystem>) -> Box<dyn VirtualFile> {
    fs.open(FPath::new("C:\\Windows\\System32\\Config\\SECURITY"))
        .unwrap()
}
pub(crate) fn read_software_hive(fs: &Arc<dyn FileSystem>) -> Box<dyn VirtualFile> {
    fs.open(FPath::new("C:\\Windows\\System32\\Config\\SOFTWARE"))
        .unwrap()
}
pub(crate) fn read_supersecretadmin_hive(fs: &Arc<dyn FileSystem>) -> Box<dyn VirtualFile> {
    fs.open(FPath::new("C:\\Users\\SuperSecretAdmin\\NTUSER.DAT"))
        .unwrap()
}

#[allow(dead_code)]
pub(crate) fn read_hive_from_path(path: &FPath, fs: &Arc<dyn FileSystem>) -> Box<dyn VirtualFile> {
    fs.open(path).unwrap()
}

pub fn str_to_unicode_with_ending(txt: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(txt.len() * 2 + 2);
    for c in txt {
        v.push(*c);
        v.push(0);
    }
    v.push(0);
    v.push(0);
    v
}
