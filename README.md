# Hive Reader [Beta]

[![crates.io](https://img.shields.io/crates/v/frnsc-hive.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/frnsc-hive) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/frnsc-hive) [![MIT License](https://img.shields.io/crates/l/frnsc-hive?style=for-the-badge)](https://github.com/ForensicRS/frnsc-hive/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/frnsc-hive/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/frnsc-hive/workflows/Rust/badge.svg?branch=main)


Open Hive registry for forensic purpouses. Uses [ForensicRs](https://github.com/ForensicRS/frnsc-hive) framework.

## Status
Production ready with certain conditions:
* The RegistryReader trait is stable, but the way HiveReader is initialized may change in the future.
* Mounted keys/values can't interact with hives at the moment.
* LOG files are not currently implemented.

https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

## Working with Hives

### Load Hives from FS

```rust
use forensic_rs::prelude::*;
use frnsc_hive::reader::HiveRegistryReader;
// Initialize a Chroot filesystem inside the artifacts folder with the standard filesystem
let fs = Box::new(forensic_rs::core::fs::ChRootFileSystem::new("./artifacts/", Box::new(forensic_rs::core::fs::StdVirtualFS::new())));
// Initialize the Hive registry reader loading the Hives from the standard locations of the filesystem: C:\Windows\Config\...
let mut reader = HiveRegistryReader::new().from_fs(fs).unwrap();

let user_names_key = reader.open_key(HKLM, r"SAM\Domains\Account\Users\Names").expect("Should list all user names");
let users = reader.enumerate_keys(user_names_key).expect("Should enumerate users");

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
let mut reader = HiveRegistryReader::new();
// Add a registry key extracted from a REG file
reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System", r"Identifier", RegValue::SZ(r"AT/AT COMPATIBLE".into()));
// Now the key is mounted and can be accesses like its in a Hive
let key = reader.open_key(HKLM, r"HARDWARE\DESCRIPTION\System").unwrap();
assert_eq!(RegHiveKey::Hkey(1407374883553280), key); // Cache -1 and type 5 => Mounted
assert_eq!(RegValue::SZ(r"AT/AT COMPATIBLE".into()), reader.read_value(key, "Identifier").unwrap());
reader.close_key(key);
```