//! Builds a purely in-memory registry — no hive file at all — by injecting ("mounting") keys and
//! values directly, e.g. the way you'd reconstruct volatile or REG-file-exported data during
//! triage. Mounted keys are fully navigable: readable, openable, and their subkeys enumerable,
//! exactly like keys read from a real hive.
//!
//! Demonstrates:
//! - `HiveRegistryReader::new` + `add_reg_key`, with no filesystem or hive file involved.
//! - Reading a single mounted value back through the standard `RegistryExt` API.
//! - Enumerating a mounted key's subkeys.
//!
//! Run with: `cargo run --example mounted_registry_keys`

use forensic_rs::prelude::{RegValue, RegistryExt};
use frnsc_hive::reader::HiveRegistryReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = HiveRegistryReader::new();

    // 1. Inject a single value under a key that doesn't exist in any loaded hive — e.g. the kind
    //    of fact you might reconstruct from a `.reg` export or a live-response artifact.
    reader.add_reg_key(
        r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System",
        r"Identifier",
        RegValue::SZ(r"AT/AT COMPATIBLE".into()),
    );
    {
        let key = reader.key(r"HKLM\HARDWARE\DESCRIPTION\System")?;
        println!("Identifier = {:?}", key.value("Identifier")?);
        // `key` borrows `reader`; closing it here (rather than at the end of `main`) frees
        // `reader` up for the mutable `add_reg_key` calls below.
    }

    // 2. Mounted keys form a real tree, not just flat leaves: two values injected under sibling
    //    paths show up as enumerable subkeys of their shared parent.
    reader.add_reg_key(
        r"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\DSDT",
        r"Signature",
        RegValue::SZ("DSDT".into()),
    );
    reader.add_reg_key(
        r"HKEY_LOCAL_MACHINE\HARDWARE\ACPI\FADT",
        r"Signature",
        RegValue::SZ("FACP".into()),
    );

    let acpi = reader.key(r"HKLM\HARDWARE\ACPI")?;
    let subkeys: Vec<String> = acpi.keys()?.into_iter().map(|k| k.name).collect();
    println!("HKLM\\HARDWARE\\ACPI subkeys: {subkeys:?}");
    for name in &subkeys {
        let subkey = acpi.open(name)?;
        println!("  {name}\\Signature = {:?}", subkey.value("Signature")?);
    }

    Ok(())
}
