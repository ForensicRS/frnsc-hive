use super::*;
use forensic_rs::{
    notifications,
    traits::registry::HKU,
};

use crate::{hive::read_base_block, tst::*};

#[test]
fn read_hive_bin() {
    let recv = notifications::testing_notifier_dummy();
    let mut fs = init_virtual_fs();
    let mut sam_file = read_sam_hive(&mut fs);
    let base_block = read_base_block(&mut sam_file).unwrap();
    sam_file
        .seek(std::io::SeekFrom::Start(
            4096 + base_block.root_cell_offset as u64,
        ))
        .unwrap();
    // Checksum is correct = Empty
    recv.try_recv().unwrap_err();
}
#[test]
fn should_cache_reg_value() {
    let mut reader = HiveRegistryReader::new();
    reader.add_reg_key(
        r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System",
        r"Identifier",
        RegValue::SZ(r"AT/AT COMPATIBLE".into()),
    );
    let key = reader
        .open_key(HKLM, r"HARDWARE\DESCRIPTION\System")
        .unwrap();
    assert_eq!(RegHiveKey::Hkey(1407374883553280), key);
    assert_eq!(
        RegValue::SZ(r"AT/AT COMPATIBLE".into()),
        reader.read_value(key, "Identifier").unwrap()
    );
    reader.close_key(key);
}

fn prepare_sam_reader() -> Box<dyn RegistryReader> {
    let mut reader = HiveRegistryReader::new();
    let mut fs = init_virtual_fs();
    let sam_file = read_sam_hive(&mut fs);
    reader.set_sam(HiveFiles::new(PathBuf::new(), sam_file).unwrap());
    Box::new(reader)
}

#[test]
fn should_open_keys_in_sam_hive() {
    let mut reader = prepare_sam_reader();
    open_keys_sam_hive(&mut reader);
}

#[test]
fn should_enumerate_values_in_sam_hive() {
    let mut reader = prepare_sam_reader();
    enumerate_keys_test(&mut reader);
}

#[test]
fn should_load_hives_from_fs() {
    init_tst_with_notifier();
    let mut reader = HiveRegistryReader::new()
        .from_fs(init_virtual_fs())
        .unwrap();
    enumerate_keys_test(&mut reader);
}
#[test]
#[ignore]
fn should_load_hives_from_fs_in_local() {
    init_tst_with_notifier();
    let mut reader = HiveRegistryReader::new()
        .from_fs(init_virtual_fs())
        .unwrap();
    enumerate_keys_test(&mut reader);
    open_keys_user_super_secret_admin(&mut reader);
}

fn enumerate_keys_test(reader: &mut Box<dyn RegistryReader>) {
    let builtin = reader.open_key(HKLM, r"SAM\Domains\Builtin").unwrap();
    //let pepe_contento = reader.open_key(user_names, "pepe.contento.secret").unwrap();
    let names = reader.enumerate_values(builtin).unwrap();
    assert_eq!("F", names[0]);
    assert_eq!("V", names[1]);
    assert_eq!("F", reader.value_at(builtin, 0).unwrap());
    assert_eq!("V", reader.value_at(builtin, 1).unwrap());
    let aliases = reader
        .open_key(HKLM, r"SAM\Domains\Builtin\Aliases")
        .unwrap();
    let names = reader.enumerate_keys(aliases).unwrap();
    assert_eq!(26, names.len());
}

fn open_keys_sam_hive(reader: &mut Box<dyn RegistryReader>) {
    let key_pairs = [
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
    for (key_name, offset) in key_pairs {
        let offset = transform_key_with_type(offset, HIVE_TYPE_SAM);
        let key = reader
            .open_key(HKLM, key_name)
            .expect(&format!("Error with key: {}", key_name));
        assert_eq!(RegHiveKey::Hkey(offset), key);
        reader.close_key(key);
    }
    let user_names_key = reader
        .open_key(HKLM, r"SAM\Domains\Account\Users\Names")
        .expect("Should list all user names");
    let _admin = reader.open_key(user_names_key, "Administrador").unwrap();
    let users = reader
        .enumerate_keys(user_names_key)
        .expect("Should enumerate users");
    println!("Users: {:?}", users);
    assert_eq!("Administrador", users[0]);
    assert_eq!("DefaultAccount", users[1]);
    assert_eq!("Invitado", users[2]);
    assert_eq!("maria.feliz.secret", users[3]);
    assert_eq!("pepe.contento.secret", users[4]);
    assert_eq!("SuperSecretAdmin", users[5]);
}

fn open_keys_user_super_secret_admin(reader: &mut Box<dyn RegistryReader>) {
    let user_names_key = reader
        .open_key(HKU, r"S-1-5-21-3656677704-2377210397-1510584988-1004")
        .expect("Should open SuperSecretAdmin profile");
    let admin_keys = reader
        .enumerate_keys(user_names_key)
        .expect("Should enumerate all user profiles");
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
