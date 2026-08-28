use super::*;
use crate::{hive::read_base_block, tst::*};

#[test]
fn read_hive_bin() {
    let fs = init_virtual_fs();
    let mut sam_file = read_sam_hive(&fs);
    let base_block = read_base_block(&mut sam_file).unwrap();
    sam_file
        .seek(std::io::SeekFrom::Start(
            4096 + base_block.root_cell_offset as u64,
        ))
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
