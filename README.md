# Hive Reader [Alpha]

[![crates.io](https://img.shields.io/crates/v/frnsc-hive.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/frnsc-hive) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/frnsc-hive) [![MIT License](https://img.shields.io/crates/l/frnsc-hive?style=for-the-badge)](https://github.com/ForensicRS/frnsc-hive/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/frnsc-hive/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/frnsc-hive/workflows/Rust/badge.svg?branch=main)


Open Hive registry for forensic purpouses. Uses [ForensicRs](https://github.com/ForensicRS/frnsc-hive) framework.

## Status
Still not usable, and a WIP.

https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

## Working with Hives

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