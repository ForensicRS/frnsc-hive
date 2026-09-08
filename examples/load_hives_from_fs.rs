//! Loads the standard set of registry hives (SYSTEM/SOFTWARE/SECURITY/SAM, plus per-user
//! `NTUSER.DAT`) from a filesystem, then reads and enumerates keys through the resulting
//! `Registry` the same way you would against a live Windows registry.
//!
//! Demonstrates:
//! - `ChRootFileSystem` rooting evidence paths (`C:\Windows\System32\Config\...`) at a local
//!   folder — this crate's tests and examples use it to point at the checked-in `artifacts/`
//!   fixture, but the same code works unmodified against a live filesystem or a mounted image.
//! - `HiveRegistryReader::from_fs`, which discovers and loads every hive it can find.
//! - `RegistryExt::key`/`RegKey::keys`, the ergonomic path-based read API.
//!
//! Run with: `cargo run --example load_hives_from_fs`

use std::sync::Arc;

use forensic_rs::prelude::*;
use frnsc_hive::reader::HiveRegistryReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Root a standard filesystem at the fixture's `C:\` drive folder. `ChRootFileSystem` drops
    //    a path's leading drive/root component entirely, so `C:\Windows\System32\Config\SAM`
    //    resolves under `./artifacts/C/Windows/System32/Config/SAM` on disk.
    let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C/", Arc::new(StdVirtualFS::new())));

    // 2. `from_fs` searches the standard hive locations (`C:\Windows\System32\Config\...`) and
    //    loads whatever it finds — only SAM/SECURITY are guaranteed present in a fresh checkout
    //    (SOFTWARE/SYSTEM are large and gitignored locally), and `from_fs` degrades gracefully
    //    when some hives are missing rather than failing outright.
    let reader = HiveRegistryReader::from_fs(fs)?;

    // 3. Read through the standard `RegistryExt` path API, exactly as you would for a live
    //    registry: `HKLM\SAM\Domains\Account\Users\Names` lists every local user account by SID
    //    subkey name resolved to a display name.
    let user_names_key = reader.key(r"HKLM\SAM\Domains\Account\Users\Names")?;
    let users: Vec<String> = user_names_key.keys()?.into_iter().map(|k| k.name).collect();
    println!("Local users found in the SAM fixture: {users:?}");

    // 4. Values work the same way. `SAM\Domains\Builtin`'s `F`/`V` values hold binary account
    //    data, so this prints their type and size rather than dumping raw bytes.
    let builtin = reader.key(r"HKLM\SAM\Domains\Builtin")?;
    for (name, value) in builtin.values()? {
        let size = match &value {
            RegValue::Binary(b) => b.len(),
            _ => 0,
        };
        println!(
            "HKLM\\SAM\\Domains\\Builtin\\{name}: {:?} ({size} bytes)",
            value.value_type()
        );
    }

    Ok(())
}
