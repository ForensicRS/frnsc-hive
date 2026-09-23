use super::*;
use crate::{
    hive::read_base_block,
    log::{MARVIN32_SEED, marvin32},
    tst::*,
};

#[test]
fn read_hive_bin() {
    let fs = init_virtual_fs();
    let mut sam_file = read_sam_hive(&fs);
    let base_block = read_base_block(&mut sam_file, &mut Vec::new()).unwrap();
    sam_file
        .seek(std::io::SeekFrom::Start(4096 + base_block.root_cell_offset as u64))
        .unwrap();
}

#[test]
fn should_cache_reg_value() {
    let mut reader = HiveRegistryReader::new();
    reader.add_reg_key(
        r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System",
        r"Identifier",
        RegValue::SZ(r"AT/AT COMPATIBLE".into()),
    );
    let key = reader.key(r"HKLM\HARDWARE\DESCRIPTION\System").unwrap();
    assert_eq!(
        RegValue::SZ(r"AT/AT COMPATIBLE".into()),
        key.value("Identifier").unwrap()
    );
}

fn prepare_sam_reader() -> HiveRegistryReader {
    let mut reader = HiveRegistryReader::new();
    let fs = init_virtual_fs();
    let sam_file = read_sam_hive(&fs);
    reader.set_sam(HiveFiles::new(FPathBuf::new(), sam_file).unwrap());
    reader
}

fn prepare_software_reader() -> HiveRegistryReader {
    let mut reader = HiveRegistryReader::new();
    let fs = init_virtual_fs();
    let sftw_file = read_software_hive(&fs);
    reader.set_software(HiveFiles::new(FPathBuf::new(), sftw_file).unwrap());
    reader
}
fn prepare_full_reader() -> Box<dyn Registry> {
    HiveRegistryReader::from_fs(init_virtual_fs()).unwrap()
}

#[test]
fn should_open_keys_in_sam_hive() {
    let reader = prepare_sam_reader();
    open_keys_sam_hive(&reader);
}

#[test]
fn should_enumerate_values_in_sam_hive() {
    let reader = prepare_sam_reader();
    enumerate_keys_test(&reader);
}

#[test]
#[ignore = "requires the large ./artifacts/.../SOFTWARE fixture"]
fn should_enumerate_values_in_software_hive() {
    // SOFTWARE is a Big file, should be migrated to Git LFS
    let reader = prepare_software_reader();
    enumerate_software_keys_test(&reader);
}

#[test]
#[ignore = "requires the large ./artifacts/.../SOFTWARE fixture"]
fn should_not_panic_on_unexistent_key() {
    let reader = prepare_full_reader();
    let reader: &dyn Registry = &*reader;
    let _ = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunUnexistent")
        .unwrap_err();
    let winlogon = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
        .unwrap();
    println!("{:?}", winlogon.values().unwrap());
    let run_key = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        .unwrap();
    let _ = run_key.value("NonExistent").unwrap_err();
    let ifeo = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
        .unwrap();
    for key in ifeo.keys().unwrap() {
        let subkey = ifeo.open(&key.name).unwrap();
        for (value_name, value) in subkey.values().unwrap() {
            println!(
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{}\\{}={:?}",
                key.name, value_name, value
            );
        }
    }
    let hku = reader.key("HKU").unwrap();
    for user in hku.keys().unwrap() {
        println!("User: {}", user.name);
        let winlogon_path = format!(
            "{}\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            user.name
        );
        let ukey = match hku.open(&winlogon_path) {
            Ok(v) => v,
            Err(_) => continue,
        };
        for (name, value) in ukey.values().unwrap() {
            println!("HKU\\{}.{} = {:?}", winlogon_path, name, value);
        }
    }
}

#[test]
fn should_load_hives_from_fs() {
    let reader = HiveRegistryReader::from_fs(init_virtual_fs()).unwrap();
    let reader: &dyn Registry = &*reader;
    enumerate_keys_test(reader);
    enumerate_keys_local_machine(reader);
}
#[test]
#[ignore]
fn should_load_hives_from_fs_in_local() {
    let reader = HiveRegistryReader::from_fs(init_virtual_fs()).unwrap();
    let reader: &dyn Registry = &*reader;
    enumerate_keys_test(reader);
    open_keys_user_super_secret_admin(reader);
}

fn enumerate_keys_test(reader: &dyn Registry) {
    let builtin = reader.key(r"HKLM\SAM\Domains\Builtin").unwrap();
    let values = builtin.values().unwrap();
    assert_eq!("F", values[0].0);
    assert_eq!("V", values[1].0);
    let aliases = reader.key(r"HKLM\SAM\Domains\Builtin\Aliases").unwrap();
    let names = aliases.keys().unwrap();
    assert_eq!(26, names.len());
}

fn enumerate_keys_local_machine(reader: &dyn Registry) {
    let hklm = reader.key("HKLM").expect("Should open HKLM");
    let subkeys = hklm.keys().expect("Should enumerate HKLM subkeys");
    println!("{:?}", subkeys.iter().map(|k| &k.name).collect::<Vec<_>>());
    assert!(!subkeys.is_empty());
    let values = hklm.values().expect("Should enumerate HKLM values");
    assert!(values.is_empty());
}

fn open_keys_sam_hive(reader: &dyn Registry) {
    let key_pairs: [(&str, u64); 9] = [
        (r"SAM\Domains", 976),
        (r"SAM\Domains\Builtin", 1112),
        (r"SAM\Domains\Builtin\Aliases", 2472),
        (r"SAM\Domains\Builtin\Users", 1944),
        (r"SAM\Domains\Builtin\Groups", 2208),
        (r"SAM\Domains\Builtin\Users\Names", 2072),
        (r"SAM\Domains\Account", 9336),
        (r"SAM\Domains\Account\Users", 10248),
        (r"SAM\Domains\Account\Users\Names", 10376),
    ];
    let lm_root = reader.root(PredefinedHive::LocalMachine).unwrap();
    for (key_name, offset) in key_pairs {
        let raw = reader
            .open_raw(&lm_root, key_name)
            .unwrap_or_else(|e| panic!("Error with key: {key_name}: {e:?}"));
        assert_eq!(pack_raw_key(HiveKind::Sam, offset), raw, "mismatch for {key_name}");
        reader.close_raw(&raw);
    }
    let user_names_key = reader
        .key(r"HKLM\SAM\Domains\Account\Users\Names")
        .expect("Should list all user names");
    let _admin = user_names_key.open("Administrador").unwrap();
    let users: Vec<String> = user_names_key
        .keys()
        .expect("Should enumerate users")
        .into_iter()
        .map(|k| k.name)
        .collect();
    println!("Users: {:?}", users);
    assert_eq!("Administrador", users[0]);
    assert_eq!("DefaultAccount", users[1]);
    assert_eq!("Invitado", users[2]);
    assert_eq!("maria.feliz.secret", users[3]);
    assert_eq!("pepe.contento.secret", users[4]);
    assert_eq!("SuperSecretAdmin", users[5]);
}

fn open_keys_user_super_secret_admin(reader: &dyn Registry) {
    let user_key = reader
        .key(r"HKU\S-1-5-21-3656677704-2377210397-1510584988-1004")
        .expect("Should open SuperSecretAdmin profile");
    let admin_keys: Vec<String> = user_key
        .keys()
        .expect("Should enumerate all user profiles")
        .into_iter()
        .map(|k| k.name)
        .collect();
    assert_eq!(
        vec![
            "AppEvents",
            "Console",
            "Control Panel",
            "Environment",
            "EUDC",
            "Keyboard Layout",
            "Network",
            "Printers",
            "SOFTWARE",
            "System"
        ],
        admin_keys
    );
    // Volatile Environment is populated when logon
}

fn enumerate_software_keys_test(reader: &dyn Registry) {
    let current_version_run = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        .unwrap();
    let values = current_version_run.values().unwrap();
    assert_eq!(2, values.len());
    assert_eq!("SecurityHealth", values[0].0);
    assert_eq!("VBoxTray", values[1].0);
}

// --- RawKey bit-packing round-trip tests -----------------------------------------------------
//
// `unpack_raw_key` is the inverse of `pack_raw_key`. These are hand-crafted, fixture-independent
// tests covering the exact bit-packing scheme those functions implement.

#[test]
fn should_round_trip_sam_security_software_system_hkeys() {
    match unpack_raw_key(&pack_raw_key(HiveKind::Sam, 1234)) {
        Ok((HiveKind::Sam, offset)) => assert_eq!(1234, offset),
        other => panic!("expected Sam, got {:?}", other),
    }
    match unpack_raw_key(&pack_raw_key(HiveKind::Security, 5678)) {
        Ok((HiveKind::Security, offset)) => assert_eq!(5678, offset),
        other => panic!("expected Security, got {:?}", other),
    }
    match unpack_raw_key(&pack_raw_key(HiveKind::Software, 91011)) {
        Ok((HiveKind::Software, offset)) => assert_eq!(91011, offset),
        other => panic!("expected Software, got {:?}", other),
    }
    match unpack_raw_key(&pack_raw_key(HiveKind::System, 121314)) {
        Ok((HiveKind::System, offset)) => assert_eq!(121314, offset),
        other => panic!("expected System, got {:?}", other),
    }
}

#[test]
fn should_round_trip_mounted_hkey() {
    match unpack_raw_key(&pack_raw_key(HiveKind::Cached, 42)) {
        Ok((HiveKind::Cached, offset)) => assert_eq!(42, offset),
        other => panic!("expected Cached, got {:?}", other),
    }
}

#[test]
fn should_round_trip_user_and_other_hkeys_by_position() {
    for position in [0u16, 1, 500] {
        match unpack_raw_key(&pack_raw_key(HiveKind::User(position), 4096)) {
            Ok((HiveKind::User(pos), offset)) => {
                assert_eq!(position, pos);
                assert_eq!(4096, offset);
            }
            other => panic!("expected User, got {:?}", other),
        }
        match unpack_raw_key(&pack_raw_key(HiveKind::Other(position), 8192)) {
            Ok((HiveKind::Other(pos), offset)) => {
                assert_eq!(position, pos);
                assert_eq!(8192, offset);
            }
            other => panic!("expected Other, got {:?}", other),
        }
    }
}

#[test]
fn unpack_raw_key_rejects_foreign_garbage_key() {
    // Tag value 63 (the max representable in 6 bits) doesn't correspond to any `HiveKind`
    // variant — must error rather than silently mapping to some `HiveKind`.
    let garbage = RawKey::from_raw(0x3Fu64 << KIND_SHIFT);
    assert!(unpack_raw_key(&garbage).is_err());
}

// --- mounted/other keys with no matching entry return Err, not panic -----------------------

#[test]
fn should_error_not_panic_when_mounted_hkey_is_unregistered() {
    let reader = HiveRegistryReader::new();
    let hkey = pack_raw_key(HiveKind::Cached, 0);
    assert!(reader.values_raw(&hkey).is_err());
    assert!(reader.keys_raw(&hkey).is_err());
    assert!(reader.info_raw(&hkey).is_err());
    assert!(reader.read_raw(&hkey, "AnyValue").is_err());
}

#[test]
fn should_error_not_panic_when_other_hkey_is_unregistered() {
    let reader = HiveRegistryReader::new();
    let hkey = pack_raw_key(HiveKind::Other(0), 32);
    assert!(reader.values_raw(&hkey).is_err());
    assert!(reader.keys_raw(&hkey).is_err());
    assert!(reader.info_raw(&hkey).is_err());
    assert!(reader.read_raw(&hkey, "AnyValue").is_err());
}

// --- Mounted key traversal (reader-level HiveKind::Cached) -------------------------------------

#[test]
fn should_open_and_enumerate_subkeys_of_a_mounted_key() {
    let mut reader = HiveRegistryReader::new();
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A\X", "V", RegValue::DWord(1));
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A\Y", "V", RegValue::DWord(2));
    let a = reader
        .key(r"HKLM\HARDWARE\A")
        .expect("mounted intermediate key should open");
    let mut names: Vec<String> = a
        .keys()
        .expect("should enumerate subkeys")
        .into_iter()
        .map(|k| k.name)
        .collect();
    names.sort();
    assert_eq!(vec!["X", "Y"], names);
}

#[test]
fn should_read_values_of_a_mounted_key_via_values_raw() {
    let mut reader = HiveRegistryReader::new();
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A", "One", RegValue::DWord(1));
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A", "Two", RegValue::DWord(2));
    let a = reader.key(r"HKLM\HARDWARE\A").unwrap();
    let mut values = a.values().expect("should enumerate values");
    values.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        vec![
            ("One".to_string(), RegValue::DWord(1)),
            ("Two".to_string(), RegValue::DWord(2))
        ],
        values
    );
}

#[test]
fn values_into_and_keys_into_match_the_vec_returning_methods() {
    let reader = prepare_sam_reader();
    let key = reader.key(r"HKLM\SAM\Domains\Builtin\Aliases").unwrap();

    let mut via_values = key.values().unwrap();
    let mut via_values_into = Vec::new();
    key.values_into(&mut via_values_into).unwrap();
    via_values.sort_by(|a, b| a.0.cmp(&b.0));
    via_values_into.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(via_values, via_values_into);

    let mut via_keys = key.keys().unwrap();
    let mut via_keys_into = Vec::new();
    key.keys_into(&mut via_keys_into).unwrap();
    via_keys.sort_by(|a, b| a.name.cmp(&b.name));
    via_keys_into.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(
        via_keys.iter().map(|k| &k.name).collect::<Vec<_>>(),
        via_keys_into.iter().map(|k| &k.name).collect::<Vec<_>>()
    );
    assert!(!via_keys_into.is_empty());
}

#[test]
fn values_raw_into_appends_rather_than_replacing_the_callers_buffer() {
    let reader = prepare_sam_reader();
    // `SAM\Domains\Builtin` has "F"/"V" values, per `enumerate_keys_test`.
    let builtin = reader.key(r"HKLM\SAM\Domains\Builtin").unwrap();
    let expected = builtin.values().unwrap();

    let mut out = vec![("preexisting".to_string(), RegValue::DWord(0))];
    builtin.values_into(&mut out).unwrap();
    assert_eq!(
        "preexisting", out[0].0,
        "values_into must append, not clear, the caller's buffer"
    );
    assert_eq!(1 + expected.len(), out.len());
}

#[test]
fn should_navigate_into_intermediate_mounted_node_with_no_own_value() {
    let mut reader = HiveRegistryReader::new();
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A\B\C", "V", RegValue::DWord(1));
    let a = reader
        .key(r"HKLM\HARDWARE\A")
        .expect("intermediate node with no direct value should still open");
    let names: Vec<String> = a.keys().unwrap().into_iter().map(|k| k.name).collect();
    assert_eq!(vec!["B"], names);
    assert!(a.values().unwrap().is_empty());
}

#[test]
fn sibling_mounted_keys_do_not_collide_when_opened_through_registry_trait() {
    let mut reader = HiveRegistryReader::new();
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\Foo", "Ver", RegValue::DWord(1));
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\Bar", "Ver", RegValue::DWord(2));
    let foo = reader.key(r"HKLM\HARDWARE\Foo").unwrap();
    let bar = reader.key(r"HKLM\HARDWARE\Bar").unwrap();
    assert_eq!(RegValue::DWord(1), foo.value("Ver").unwrap());
    assert_eq!(RegValue::DWord(2), bar.value("Ver").unwrap());
}

#[test]
fn should_error_not_panic_opening_nonexistent_child_of_mounted_key() {
    let mut reader = HiveRegistryReader::new();
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A", "V", RegValue::DWord(1));
    let a = reader.key(r"HKLM\HARDWARE\A").unwrap();
    assert!(a.open("DoesNotExist").is_err());
}

#[test]
fn info_raw_reports_subkey_and_value_counts_for_mounted_key() {
    let mut reader = HiveRegistryReader::new();
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A\B", "V", RegValue::DWord(1));
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A\C", "V", RegValue::DWord(1));
    reader.add_reg_key(r"HKEY_LOCAL_MACHINE\HARDWARE\A", "Own", RegValue::DWord(1));
    let a = reader.key(r"HKLM\HARDWARE\A").unwrap();
    let info = a.info().unwrap();
    assert_eq!(2, info.subkeys);
    assert_eq!(1, info.values);
}

// --- Mounted key traversal under a real, already-loaded hive (HiveOffset / per-hive mounted) ---

#[test]
fn should_round_trip_mounted_offset_flag() {
    match HiveOffset::from_payload(HiveOffset::Mounted(7).to_payload()) {
        HiveOffset::Mounted(id) => assert_eq!(7, id),
        other => panic!("expected Mounted, got {:?}", other),
    }
    // A real offset near u32::MAX must not collide with the mounted flag bit (bit 47).
    let near_max_real = HiveOffset::Real(u32::MAX as u64 - 1);
    match HiveOffset::from_payload(near_max_real.to_payload()) {
        HiveOffset::Real(offset) => assert_eq!(u32::MAX as u64 - 1, offset),
        other => panic!("expected Real, got {:?}", other),
    }
}

#[test]
#[ignore = "requires the large ./artifacts/.../SOFTWARE fixture"]
fn should_open_mounted_child_under_a_real_key() {
    let mut reader = prepare_software_reader();
    reader.add_reg_key(
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\InjectedMalware",
        "ImagePath",
        RegValue::SZ(r"C:\evil.exe".into()),
    );
    let injected = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\InjectedMalware")
        .expect("mounted child under a real key should open");
    assert_eq!(
        RegValue::SZ(r"C:\evil.exe".into()),
        injected.value("ImagePath").unwrap()
    );
}

#[test]
#[ignore = "requires the large ./artifacts/.../SOFTWARE fixture"]
fn mounted_child_key_appears_in_real_parents_keys_enumeration() {
    let mut reader = prepare_software_reader();
    reader.add_reg_key(
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\InjectedMalware",
        "ImagePath",
        RegValue::SZ(r"C:\evil.exe".into()),
    );
    let run_key = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        .unwrap();
    let names: Vec<String> = run_key.keys().unwrap().into_iter().map(|k| k.name).collect();
    assert!(
        names.iter().any(|n| n == "InjectedMalware"),
        "expected InjectedMalware in {:?}",
        names
    );
}

#[test]
#[ignore = "requires the large ./artifacts/.../SOFTWARE fixture"]
fn real_key_lookup_still_wins_when_no_mounted_override_exists() {
    let reader = prepare_software_reader();
    let reader: &dyn Registry = &reader;
    enumerate_software_keys_test(reader);
}

#[test]
#[ignore = "requires the large ./artifacts/.../SOFTWARE fixture"]
fn mounted_grandchild_under_mounted_child_of_real_key() {
    let mut reader = prepare_software_reader();
    reader.add_reg_key(
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\InjectedMalware\SubKey",
        "V",
        RegValue::DWord(42),
    );
    let injected = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\InjectedMalware")
        .unwrap();
    let sub = injected
        .open("SubKey")
        .expect("mounted grandchild of a mounted child should open");
    assert_eq!(RegValue::DWord(42), sub.value("V").unwrap());
}

#[test]
#[ignore = "requires the large ./artifacts/.../SOFTWARE fixture"]
fn should_error_not_panic_opening_unmounted_and_unreal_child() {
    let reader = prepare_software_reader();
    let run_key = reader
        .key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        .unwrap();
    assert!(run_key.open("TotallyMadeUp").is_err());
}

// --- LOG replay integration (synthetic .LOG1 patching a real hive fixture's own bytes) ---------
//
// No real Windows-produced .LOG1/.LOG2 fixtures are available (see src/log.rs's module doc), so
// this builds a synthetic HvLE entry (using the same `marvin32`/framing validated by log.rs's own
// unit tests) and marks a real fixture hive's in-memory copy "dirty", to exercise the full
// HiveFiles::new_with_logs -> apply_entries -> get_cell_at_offset(patched) path end-to-end.

fn build_hvle_entry(sequence_number: u32, hive_bins_data_size: u32, page_offset: u32, page_data: &[u8]) -> Vec<u8> {
    let mut refs = Vec::new();
    refs.extend_from_slice(&page_offset.to_le_bytes());
    refs.extend_from_slice(&(page_data.len() as u32).to_le_bytes());

    let header_size = 40usize;
    let unpadded_len = header_size + refs.len() + page_data.len();
    let padded_len = unpadded_len.div_ceil(512) * 512;

    let mut body_after_hashes = Vec::new();
    body_after_hashes.extend_from_slice(&refs);
    body_after_hashes.extend_from_slice(page_data);
    body_after_hashes.resize(padded_len - header_size, 0);
    let hash1 = marvin32(MARVIN32_SEED, &body_after_hashes);

    let mut entry = Vec::with_capacity(padded_len);
    entry.extend_from_slice(b"HvLE");
    entry.extend_from_slice(&(padded_len as u32).to_le_bytes());
    entry.extend_from_slice(&0u32.to_le_bytes()); // flags
    entry.extend_from_slice(&sequence_number.to_le_bytes());
    entry.extend_from_slice(&hive_bins_data_size.to_le_bytes());
    entry.extend_from_slice(&1u32.to_le_bytes()); // dirty_pages_count
    entry.extend_from_slice(&hash1.to_le_bytes());
    let hash2 = marvin32(MARVIN32_SEED, &entry[0..32]);
    entry.extend_from_slice(&hash2.to_le_bytes());
    entry.extend_from_slice(&body_after_hashes);
    entry
}

#[test]
fn log_replay_patches_root_cell_timestamp_of_a_real_hive() {
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;

    let fs = init_virtual_fs();
    let mut original = read_sam_hive(&fs);
    let mut raw = Vec::new();
    original.read_to_end(&mut raw).unwrap();

    let base_block = read_base_block(&mut read_sam_hive(&fs), &mut Vec::new()).unwrap();
    let original_sec_sequence = base_block.sec_sequence;
    let new_prim_sequence = original_sec_sequence.wrapping_add(1);

    // Mark the in-memory copy "dirty": prim_sequence (file bytes 4..8) != sec_sequence (bytes
    // 8..12, left untouched) — see hive::read_base_block_wxp/w10's field order.
    raw[4..8].copy_from_slice(&new_prim_sequence.to_le_bytes());

    // Root cell (offset ROOT_CELL_OFFSET=32) layout: 4-byte length prefix, 2-byte "nk" signature,
    // 2-byte flags, then an 8-byte last_written_timestamp (see cell::KeyNodeCell's FromBytes impl)
    // — i.e. hive-bins-data offset 32+4+2+2=40.
    let new_timestamp: u64 = 0x01D9_ABCD_1234_5678;
    let entry = build_hvle_entry(
        new_prim_sequence,
        base_block.hive_bins_data_size,
        40,
        &new_timestamp.to_le_bytes(),
    );
    // Real .LOG1/.LOG2 files carry their own 512-byte first sector before entries begin at
    // LOG_ENTRIES_START_OFFSET (see log.rs) — pad with zeros here since read_log_entries doesn't
    // validate the log's own base block, only seeks past it.
    let mut log1_bytes = vec![0u8; 512];
    log1_bytes.extend_from_slice(&entry);

    let mem_fs = InMemoryVirtualFileSystem::new()
        .with_file("primary", raw)
        .with_file("log1", log1_bytes);
    let primary_file = mem_fs.open(FPath::new("primary")).unwrap();
    let log1_file = mem_fs.open(FPath::new("log1")).unwrap();

    let hive = HiveFiles::new_with_logs(FPathBuf::new(), primary_file, Some(log1_file), None).unwrap();
    assert_eq!(Some(new_prim_sequence), hive.log_recovery_applied());
    assert_eq!(new_timestamp, hive.get_root_cell().unwrap().last_written_timestamp);
}

#[test]
fn log_replay_is_a_noop_for_a_clean_hive() {
    let fs = init_virtual_fs();
    let sam_file = read_sam_hive(&fs);
    let hive = HiveFiles::new_with_logs(FPathBuf::new(), sam_file, None, None).unwrap();
    assert_eq!(None, hive.log_recovery_applied());
}

#[test]
fn log_replay_leaves_hive_unpatched_when_dirty_but_no_log_covers_the_gap() {
    let fs = init_virtual_fs();
    let mut original = read_sam_hive(&fs);
    let mut raw = Vec::new();
    original.read_to_end(&mut raw).unwrap();
    // Mark dirty (prim_sequence != sec_sequence) but supply no logs at all.
    raw[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    let mem_fs = forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new().with_file("primary", raw);
    let primary_file = mem_fs.open(FPath::new("primary")).unwrap();
    let hive = HiveFiles::new_with_logs(FPathBuf::new(), primary_file, None, None).unwrap();
    assert_eq!(None, hive.log_recovery_applied());
    // Still opens successfully with the (uncorrected) original root cell reachable.
    assert!(hive.get_root_cell().is_ok());
}

// --- parse_offsets_list ------------------------------------------------------------------------

#[test]
fn parse_offsets_list_empty() {
    assert_eq!(Vec::<u32>::new(), parse_offsets_list(&[]).unwrap());
}

#[test]
fn parse_offsets_list_well_formed() {
    let content = vec![1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0];
    assert_eq!(vec![1u32, 2, 3], parse_offsets_list(&content).unwrap());
}

#[test]
fn parse_offsets_list_rejects_trailing_partial_entry() {
    // One full u32 (little-endian 1) followed by a stray, incomplete byte: the offsets-list
    // cell's declared size doesn't align to 4-byte entries — a corruption signal in its own
    // right — so this must error rather than silently dropping the trailing byte.
    let content = vec![0x01, 0x00, 0x00, 0x00, 0xAA];
    assert!(parse_offsets_list(&content).is_err());
}

// --- Findings channel: analyst-relevant integrity signals, not just warn! log lines ------------

#[test]
fn checksum_mismatch_is_recorded_as_an_invalid_checksum_finding() {
    let fs = init_virtual_fs();
    let mut original = read_sam_hive(&fs);
    let mut raw = Vec::new();
    original.read_to_end(&mut raw).unwrap();
    // Flip a byte inside the checksummed region (bytes 0..508) without updating the stored
    // checksum at 508..512, so `checksum_is_correct` fails.
    raw[16] ^= 0xFF;

    let mem_fs = forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new().with_file("primary", raw);
    let primary_file = mem_fs.open(FPath::new("primary")).unwrap();
    let mut findings = Vec::new();
    // The base block is still structurally valid (only the checksum is wrong), so parsing succeeds.
    HiveFiles::new_with_findings(FPathBuf::new(), primary_file, &mut findings).unwrap();

    assert!(
        findings.iter().any(|f| f.category == FindingCategory::InvalidChecksum),
        "expected an InvalidChecksum finding, got {findings:?}"
    );
}

#[test]
fn dirty_hive_with_no_covering_log_is_recorded_as_an_integrity_issue_finding() {
    let fs = init_virtual_fs();
    let mut original = read_sam_hive(&fs);
    let mut raw = Vec::new();
    original.read_to_end(&mut raw).unwrap();
    // Mark dirty (prim_sequence != sec_sequence) but supply no logs at all.
    raw[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    let mem_fs = forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new().with_file("primary", raw);
    let primary_file = mem_fs.open(FPath::new("primary")).unwrap();
    let mut findings = Vec::new();
    let hive = HiveFiles::new_with_logs_and_findings(FPathBuf::new(), primary_file, None, None, &mut findings).unwrap();

    assert_eq!(None, hive.log_recovery_applied());
    assert!(
        hive.get_root_cell().is_ok(),
        "hive should still open with unpatched bytes"
    );
    assert!(
        findings.iter().any(|f| f.category == FindingCategory::IntegrityIssue
            && f.title.contains("Dirty hive opened without log replay")),
        "expected an IntegrityIssue finding about the unreplayed dirty hive, got {findings:?}"
    );
}

#[test]
fn a_declared_hive_bins_data_size_larger_than_the_file_is_rejected_not_allocated() {
    let fs = init_virtual_fs();
    let mut original = read_sam_hive(&fs);
    let mut raw = Vec::new();
    original.read_to_end(&mut raw).unwrap();
    // Mark dirty so replay is attempted, and claim an implausibly large hive_bins_data_size
    // (signature(4) + prim_sequence(4) + sec_sequence(4) + last_written_timestamp(8) +
    // major_version(4) + minor_version(4) + file_type(4) + file_format(4) + root_cell_offset(4)
    // lands hive_bins_data_size at file offset 40..44 — see
    // hive::read_base_block_wxp/w10's field order) — this must be rejected against the actual
    // file size rather than driving a multi-gigabyte `vec![0u8; ..]` allocation.
    raw[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    raw[40..44].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    let mem_fs = forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new().with_file("primary", raw);
    let primary_file = mem_fs.open(FPath::new("primary")).unwrap();
    let mut findings = Vec::new();
    let hive = HiveFiles::new_with_logs_and_findings(FPathBuf::new(), primary_file, None, None, &mut findings).unwrap();

    assert_eq!(None, hive.log_recovery_applied());
    assert!(
        findings
            .iter()
            .any(|f| f.category == FindingCategory::IntegrityIssue
                && f.title.contains("Implausible hive_bins_data_size")),
        "expected an IntegrityIssue finding about the implausible size, got {findings:?}"
    );
}

#[test]
fn a_hive_that_exists_but_fails_to_parse_is_reported_not_silently_dropped() {
    // A file that exists at the expected path but isn't a valid hive at all (wrong magic) used
    // to vanish via `HiveFiles::new_with_logs(..).ok()` with no record it was ever seen.
    let mem_fs =
        forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new().with_file("Config/GARBAGE", vec![0u8; 4096]);
    let mut findings = Vec::new();
    let result = open_hive_with_logs(
        &(Arc::new(mem_fs) as Arc<dyn FileSystem>),
        FPath::new("Config"),
        "GARBAGE",
        &mut findings,
    );

    assert!(result.is_none());
    assert!(
        findings.iter().any(|f| f.category == FindingCategory::ProcessingError),
        "expected a ProcessingError finding recording the failed parse, got {findings:?}"
    );
}

#[test]
fn open_hive_with_logs_reports_no_finding_when_the_file_is_simply_absent() {
    // A hive kind that genuinely isn't present (e.g. no SECURITY hive in this filesystem) is a
    // routine outcome, not a processing failure — it must not be reported as one.
    let mem_fs = forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new();
    let mut findings = Vec::new();
    let result = open_hive_with_logs(
        &(Arc::new(mem_fs) as Arc<dyn FileSystem>),
        FPath::new("Config"),
        "SAM",
        &mut findings,
    );

    assert!(result.is_none());
    assert!(
        findings.is_empty(),
        "expected no findings for a simply-absent hive, got {findings:?}"
    );
}

#[test]
fn reader_findings_start_empty_and_accumulate_in_insertion_order() {
    let reader = HiveRegistryReader::new();
    assert!(reader.findings().is_empty());

    reader.record_findings(vec![Finding::new(
        FindingSeverity::Low,
        FindingCategory::ProcessingError,
        "first",
    )]);
    reader.record_findings(vec![Finding::new(
        FindingSeverity::High,
        FindingCategory::IntegrityIssue,
        "second",
    )]);

    let findings = reader.findings();
    assert_eq!(2, findings.len());
    assert_eq!("first", findings[0].title);
    assert_eq!("second", findings[1].title);
}

// --- RecoverDeleted: end-to-end through HiveRegistryReader --------------------------------------

/// Builds a full REGF cell buffer (4-byte length prefix, negative/allocated, padded to a
/// multiple of 8 bytes) wrapping `content`, matching what [crate::cell::read_cell] parses.
fn wrap_cell_padded(content: &[u8]) -> Vec<u8> {
    let unpadded = 4 + content.len();
    let padded = unpadded.div_ceil(8) * 8;
    let mut buf = Vec::with_capacity(padded);
    buf.extend_from_slice(&(-(padded as i32)).to_le_bytes());
    buf.extend_from_slice(content);
    buf.resize(padded, 0);
    buf
}

/// Builds a minimal `nk` cell's content (ASCII name, matching [crate::cell::KEY_COMP_NAME_FLAG]).
fn key_node_content(name: &str, last_written_timestamp: u64, parent: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"nk");
    buf.extend_from_slice(&crate::cell::KEY_COMP_NAME_FLAG.to_le_bytes());
    buf.extend_from_slice(&last_written_timestamp.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // access_bits
    buf.extend_from_slice(&parent.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // number_subkeys
    buf.extend_from_slice(&0u32.to_le_bytes()); // number_volatile_subkeys
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // subkeys_list_offset
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // volatile_subkeys_list_offset
    buf.extend_from_slice(&0u32.to_le_bytes()); // number_key_values
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // key_values_list_offset
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // key_security_offset
    buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // class_name_offset
    buf.extend_from_slice(&0u32.to_le_bytes()); // largest_subkey_class_name_length
    buf.extend_from_slice(&0u16.to_le_bytes()); // largest_subkey_name_length
    buf.push(0); // virt_and_user_flags
    buf.push(0); // debug
    buf.extend_from_slice(&0u32.to_le_bytes()); // largest_value_name_length
    buf.extend_from_slice(&0u32.to_le_bytes()); // largest_value_data_size
    buf.extend_from_slice(&0u32.to_le_bytes()); // work_var
    let name_bytes = name.as_bytes();
    buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes()); // key_name_length
    buf.extend_from_slice(&0u16.to_le_bytes()); // class_name_length
    buf.extend_from_slice(name_bytes);
    buf
}

/// Builds a minimal, synthetic, single-hbin hive: an allocated root `nk` cell (satisfying
/// `HiveFiles::new`'s "root_cell_offset must resolve to a KeyNode" requirement) followed by
/// trailing unallocated space holding one deleted `nk` cell's still-present leftover bytes.
fn build_synthetic_hive_with_a_deleted_key() -> Vec<u8> {
    const BIN_SIZE: usize = 4096;
    let root_cell = wrap_cell_padded(&key_node_content("ROOT", 0, 0xFFFF_FFFF));
    let deleted_cell = wrap_cell_padded(&key_node_content(
        "RecoveredKeyName",
        130_000_000_000_000_000, // a plausible FILETIME, well within recovery's accepted range
        0xFFFF_FFFF,             // no live parent to resolve
    ));

    let mut hbin = Vec::with_capacity(BIN_SIZE);
    hbin.extend_from_slice(b"hbin");
    hbin.extend_from_slice(&0u32.to_le_bytes());
    hbin.extend_from_slice(&(BIN_SIZE as u32).to_le_bytes());
    hbin.extend_from_slice(&[0u8; 16]);
    hbin.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(32, hbin.len());
    hbin.extend_from_slice(&root_cell);

    let free_span_start = hbin.len(); // already 8-aligned: root_cell.len() is a multiple of 8
    let free_len = BIN_SIZE - free_span_start;
    hbin.extend_from_slice(&(free_len as i32).to_le_bytes()); // positive => unallocated
    hbin.resize(free_span_start + 8, 0); // slack landing deleted_cell on an 8-aligned offset
    hbin.extend_from_slice(&deleted_cell);
    hbin.resize(BIN_SIZE, 0);

    let mut raw = vec![0u8; 4096];
    raw[0..4].copy_from_slice(b"regf"); // prim_sequence == sec_sequence (both 0) => clean hive
    raw[36..40].copy_from_slice(&(ROOT_CELL_OFFSET as u32).to_le_bytes());
    raw[40..44].copy_from_slice(&(BIN_SIZE as u32).to_le_bytes());
    raw.extend_from_slice(&hbin);
    raw
}

#[test]
fn recover_deleted_key_end_to_end_through_hive_registry_reader() {
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;

    let mem_fs = InMemoryVirtualFileSystem::new().with_file("primary", build_synthetic_hive_with_a_deleted_key());
    let primary_file = mem_fs.open(FPath::new("primary")).unwrap();
    let hive = HiveFiles::new(FPathBuf::new(), primary_file).unwrap();

    let mut reader = HiveRegistryReader::new();
    reader.set_sam(hive);
    let reader: Box<dyn Registry> = Box::new(reader);

    let recovery = reader
        .as_recovery()
        .expect("HiveRegistryReader implements RecoverDeleted");
    let deleted = recovery.deleted_keys().unwrap();
    let found = deleted.iter().find(|k| k.value().name == "RecoveredKeyName");
    assert!(found.is_some(), "expected to recover RecoveredKeyName, got {deleted:?}");
    let found = found.unwrap();
    // No live parent resolves for this synthetic key, so the hive-provenance placeholder applies.
    assert_eq!(Some("<SAM>".to_string()), found.value().parent_hint);
    // A carved key is not a live read, and it must say so: an unlabelled recovery grades as
    // trustworthy as an allocated read, which is exactly the false claim `Recovered` exists to
    // prevent.
    assert_eq!(found.recovery(), Recovery::DeletedMetadata);
    assert!(matches!(found.locus(), Locus::Hive { .. }));
}

#[test]
fn from_fs_reports_no_findings_for_well_formed_fixture_hives() {
    // The checked-in fixture hives are well-formed, so `from_fs` shouldn't manufacture any
    // findings — pins down that the findings collected while loading are actually wired into the
    // reader (not just into a local `Vec` that gets dropped).
    let fs = init_virtual_fs();
    let config_folder = FPath::new("C:\\Windows\\System32\\Config");
    let mut reader = HiveRegistryReader::new();
    let mut findings = Vec::new();
    if let Some(hive) = open_hive_with_logs(&fs, config_folder, "SAM", &mut findings) {
        reader.set_sam(hive);
    }
    reader.record_findings(findings);
    assert!(reader.findings().is_empty());
}
