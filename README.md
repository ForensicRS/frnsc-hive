# Hive Reader [Beta]

[![crates.io](https://img.shields.io/crates/v/frnsc-hive.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/frnsc-hive) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/frnsc-hive) [![MIT License](https://img.shields.io/crates/l/frnsc-hive?style=for-the-badge)](https://github.com/ForensicRS/frnsc-hive/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/frnsc-hive/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/frnsc-hive/workflows/Rust/badge.svg?branch=main)


Open Hive registry for forensic purpouses. Uses [ForensicRs](https://github.com/ForensicRS/frnsc-hive) framework.

## Status
Production ready with certain conditions:
* Implements the `Registry`/`RegistryExt` traits (forensic-rs 0.14+), but the way `HiveRegistryReader` is initialized may change in the future.
* Mounted keys/values can be navigated (opened, enumerated) like real hive keys, including when mounted underneath an already-loaded real hive. Chaining multiple `.open()` calls into a mounted grandchild of an already-open *non-root* real key that wasn't itself reached by name is not covered; real/mounted children interleaved at every level of one multi-segment path aren't either — see [HiveFiles::open_key_from_offset](src/reader.rs) for details.
* Transaction log replay (`.LOG1`/`.LOG2`, new format, Windows 8.1+) is implemented for SYSTEM/SOFTWARE/SECURITY/SAM and per-user `NTUSER.DAT` hives opened via `HiveRegistryReader::from_fs`/`HiveFormatFactory` — a dirty hive (`prim_sequence != sec_sequence` in its base block) has its pending log entries replayed in memory before being parsed, so reads reflect the recovered state rather than the stale on-disk bytes. If no log entry covers the dirty gap, the hive still opens using its original (uncorrected) bytes, with a warning logged and an `IntegrityIssue` finding recorded — recovery never blocks opening a hive. The pre-Windows-8.1 old-format `.LOG` (single file, bitmap-based) is not supported, and hives loaded via `HiveRegistryReader::add_other` (arbitrary mounted `.hve` files) don't go through log discovery/replay at all.
* Analyst-relevant integrity signals (checksum mismatches, unreplayed dirty hives, skipped/malformed log entries, unparseable hives) are recorded as `forensic_rs::pipeline::finding::Finding`s, retrievable via `HiveRegistryReader::findings`, in addition to the `warn!`-level log lines meant for engineers.
* `factory::HiveFormatFactory` implements `forensic_rs::traits::format::FormatFactory`, so this crate can plug into `forensic_rs::core::resolver::MountResolver` and mount a single hive file (found through its `probe`/`mount` contract) as `Mounted::Registry`, in addition to the crate-specific `HiveRegistryReader::from_fs`/`add_other` entry points.
* `HiveRegistryReader` implements `RecoverDeleted` (reachable via `Registry::as_recovery`), carving deleted keys/values out of unallocated hive cells with strict plausibility validation to guard against false positives — see [src/recovery.rs](src/recovery.rs)'s module doc for exactly what's checked and its known limitations (a recovered value's owning key generally can't be identified, and a recovered key's parent is only named when it's still live).

https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md

## Examples

Runnable versions of everything below (and more) live in [`examples/`](examples/) — run any of them with `cargo run --example <name>` from the crate root:

* [`load_hives_from_fs`](examples/load_hives_from_fs.rs) — load the standard hive layout from a filesystem and read/enumerate keys.
* [`mounted_registry_keys`](examples/mounted_registry_keys.rs) — build a purely in-memory registry by injecting keys/values, no hive file involved.
* [`format_factory_mount`](examples/format_factory_mount.rs) — mount a hive file through the forensic-rs 0.14 `FormatFactory`/`MountResolver` sniff-and-mount contract.
* [`integrity_findings`](examples/integrity_findings.rs) — surface a base-block checksum mismatch as a `Finding`, not just a log line.
* [`carve_deleted_keys`](examples/carve_deleted_keys.rs) — recover a deleted registry key from unallocated hive cells via `RecoverDeleted`.

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

Mounted keys are fully navigable, not just readable as a single flat value — a parent mounted key can be opened and its subkeys enumerated:

```rust
use frnsc_hive::reader::HiveRegistryReader;
use forensic_rs::prelude::{RegValue, RegistryExt};

let mut reader = HiveRegistryReader::new();
reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\DSDT", r"Signature", RegValue::SZ("DSDT".into()));
reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\FADT", r"Signature", RegValue::SZ("FACP".into()));

let acpi = reader.key(r"HKLM\HARDWARE\ACPI").unwrap();
let subkeys: Vec<String> = acpi.keys().unwrap().into_iter().map(|k| k.name).collect();
assert_eq!(vec!["DSDT", "FADT"], subkeys);
```

A mounted key can also be injected underneath an already-loaded real hive (e.g. a synthetic/volatile value under `HKLM\SOFTWARE`) — it shows up alongside the hive's real subkeys:

```rust,ignore
// Assuming `reader` already has the SOFTWARE hive loaded via `set_software`/`from_fs`:
reader.add_reg_key(
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\InjectedVolatileEntry",
    r"ImagePath",
    RegValue::SZ(r"C:\example.exe".into()),
);
let run_key = reader.key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run").unwrap();
// `InjectedVolatileEntry` appears alongside the real subkeys read from the SOFTWARE hive file.
let names: Vec<String> = run_key.keys().unwrap().into_iter().map(|k| k.name).collect();
assert!(names.contains(&"InjectedVolatileEntry".to_string()));
```
