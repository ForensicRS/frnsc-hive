//! Mounts a single hive file through forensic-rs's generic sniff-and-mount contract
//! (`FormatFactory`/`MountResolver`) instead of the crate-specific `HiveRegistryReader::from_fs`
//! entry point. This is the integration point a triage pipeline uses when it doesn't know ahead
//! of time what kind of evidence a file is — it just asks every registered `FormatFactory`
//! "can you make sense of this?" and lets the highest-confidence one mount it.
//!
//! Demonstrates:
//! - `HiveFormatFactory`, this crate's `forensic_rs::traits::format::FormatFactory` impl.
//! - `MountResolver`, which drives `probe`/`mount` across registered factories and hands back a
//!   `Mounted::Registry` on success.
//! - Reading through the resulting `Arc<dyn Registry>` — identical to reading through the
//!   `Box<dyn Registry>` `HiveRegistryReader::from_fs` returns.
//!
//! Run with: `cargo run --example format_factory_mount`

use std::sync::Arc;

use forensic_rs::prelude::*;
use frnsc_hive::factory::HiveFormatFactory;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Same fixture filesystem as the other examples.
    let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new("./artifacts/C/", Arc::new(StdVirtualFS::new())));
    let path = FPath::new("C:\\Windows\\System32\\Config\\SAM");
    let file = fs.open(path)?;

    // 2. A resolver with `HiveFormatFactory` registered. In a real pipeline you'd register every
    //    format factory you have (ZIP, SQLite, EVTX, hive, ...) once, up front, and let
    //    `MountResolver` pick whichever one's `probe` scores highest for a given file.
    let resolver = MountResolver::builder()
        .factory(Arc::new(HiveFormatFactory::new()))
        .build();

    // 3. `EvidenceLocator` records *where* this file is, so `HiveFormatFactory::mount` can find
    //    `.LOG1`/`.LOG2` companions beside it, and so the resolver can cache by location.
    let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(path)));
    let cancellation = CancellationToken::new();

    let mounted = resolver.resolve(&fs, &locator, file, Some(MountKind::Registry), &cancellation)?;

    // 4. `Mounted::Registry` wraps an `Arc<dyn Registry>` — read through it exactly like any
    //    other `Registry` this crate hands back.
    let registry = mounted.as_registry().expect("we asked for MountKind::Registry");
    let user_names_key = registry.key(r"HKLM\SAM\Domains\Account\Users\Names")?;
    let users: Vec<String> = user_names_key.keys()?.into_iter().map(|k| k.name).collect();
    println!("Mounted SAM via HiveFormatFactory; local users found: {users:?}");

    Ok(())
}
