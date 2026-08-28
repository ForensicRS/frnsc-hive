# Hive Reader [Beta]

[![crates.io](https://img.shields.io/crates/v/frnsc-hive.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/frnsc-hive) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/frnsc-hive) [![MIT License](https://img.shields.io/crates/l/frnsc-hive?style=for-the-badge)](https://github.com/ForensicRS/frnsc-hive/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/frnsc-hive/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/frnsc-hive/workflows/Rust/badge.svg?branch=main)


Open Hive registry for forensic purpouses. Uses [ForensicRs](https://github.com/ForensicRS/frnsc-hive) framework.

## Status
Production ready with certain conditions:
* Implements the `Registry`/`RegistryExt` traits (forensic-rs 0.14+), but the way `HiveRegistryReader` is initialized may change in the future.
* Mounted keys/values can't interact with hives at the moment.
* LOG files are not currently implemented.

https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

## Working with Hives

### Load Hives from FS

```rust
use forensic_rs::prelude::*;
use frnsc_hive::reader::HiveRegistryReader;
use std::sync::Arc;
// Initialize a Chroot filesystem inside the artifacts folder's `C:\` drive with the standard
// filesystem. `ChRootFileSystem` drops a path's leading drive/root component entirely, so
// evidence paths like `C:\Windows\System32\Config\SAM` still resolve under whatever this chroot
// is rooted at.
let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C/", Arc::new(StdVirtualFS::new())));
// Initialize the Hive registry reader loading the Hives from the standard locations of the filesystem: C:\Windows\Config\...
let reader = HiveRegistryReader::from_fs(fs).unwrap();

let user_names_key = reader.key(r"HKLM\SAM\Domains\Account\Users\Names").expect("Should list all user names");
let users: Vec<String> = user_names_key.keys().expect("Should enumerate users").into_iter().map(|k| k.name).collect();

println!("Users: {:?}", users);
assert_eq!("Administrador", users[0]);
assert_eq!("DefaultAccount", users[1]);
assert_eq!("Invitado", users[2]);
assert_eq!("maria.feliz.secret", users[3]);
assert_eq!("pepe.contento.secret", users[4]);
assert_eq!("SuperSecretAdmin", users[5]);
```

### Mounted keys

```rust
use frnsc_hive::reader::HiveRegistryReader;
use forensic_rs::prelude::{RegValue, RegistryExt};

let mut reader = HiveRegistryReader::new();
// Add a registry key extracted from a REG file
reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System", r"Identifier", RegValue::SZ(r"AT/AT COMPATIBLE".into()));
// Now the key is mounted and can be accessed like it's in a Hive
let key = reader.key(r"HKLM\HARDWARE\DESCRIPTION\System").unwrap();
assert_eq!(RegValue::SZ(r"AT/AT COMPATIBLE".into()), key.value("Identifier").unwrap());
// `key` closes automatically when it goes out of scope
```
