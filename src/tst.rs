use std::path::Path;
use std::cell::RefCell;

use forensic_rs::{traits::vfs::{VirtualFileSystem, VirtualFile}, core::fs::StdVirtualFS, notifications::Notifier, channel::Receiver, prelude::{Notification, Message}};

pub(crate) fn init_virtual_fs() -> Box<dyn VirtualFileSystem> {
    Box::new(forensic_rs::core::fs::ChRootFileSystem::new("./artifacts", Box::new(StdVirtualFS::new())))
}

pub(crate) fn read_sam_hive(fs : &mut Box<dyn VirtualFileSystem>) -> Box<dyn VirtualFile> {
    fs.open(Path::new("SAM")).unwrap()
}
pub(crate) fn read_sec_hive(fs : &mut Box<dyn VirtualFileSystem>) -> Box<dyn VirtualFile> {
    fs.open(Path::new("SECURITY")).unwrap()
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

thread_local! {
    pub static RECEIVER : RefCell<Receiver<Notification>> = RefCell::new(def_recv());
    pub static LOGGER : RefCell<Receiver<Message>> = RefCell::new(def_log());
}

pub fn assert_no_notifications() {
    let _ = RECEIVER.with(|v| {
        v.borrow().try_recv().unwrap_err();
    });
}



fn def_recv() -> Receiver<Notification> {
    let (_send, recv) = forensic_rs::channel::channel();
    recv
}
fn def_log() -> Receiver<Message> {
    let (_send, recv) = forensic_rs::channel::channel();
    recv
}


pub fn init_tst() {
    let rcv = forensic_rs::notifications::testing_notifier_dummy();
    initialize_receiver(rcv);
    let rcv = forensic_rs::logging::testing_logger_dummy();
    initialize_logger(rcv);
}

/// Initializes the Receiver to simplify testing
pub fn initialize_receiver(recv: Receiver<Notification>) {
    let _ = RECEIVER.with(|v| {
        let mut brw = v.borrow_mut();
        *brw = recv;
        Ok::<(), ()>(())
    });
    // Wait for local_key_cell_methods
}
/// Initializes the Receiver to simplify testing
pub fn initialize_logger(recv: Receiver<Message>) {
    let _ = LOGGER.with(|v| {
        let mut brw = v.borrow_mut();
        *brw = recv;
        Ok::<(), ()>(())
    });
    // Wait for local_key_cell_methods
}