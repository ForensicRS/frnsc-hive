//! `forensic_rs::traits::format::FormatFactory` implementation — sniffs and mounts a REGF hive
//! file (plus any discoverable `.LOG1`/`.LOG2` transaction-log companions) as a
//! [`forensic_rs::traits::format::Mounted::Registry`], the 0.14 replacement for the removed
//! `RegistryReaderFactory` trait. This is what plugs [HiveRegistryReader] into
//! `forensic_rs::core::resolver::MountResolver`, rather than only being usable via the
//! crate-specific [HiveRegistryReader::from_fs]/[HiveRegistryReader::add_other] entry points.

use std::sync::Arc;

use forensic_rs::core::locator::LocatorSegment;
use forensic_rs::prelude::*;
use forensic_rs::traits::format::{FormatFactory, MountContext, MountKind, Mounted, ProbeScore};

use crate::hive::{checksum_is_correct, is_valid_base_block};
use crate::reader::{HiveFiles, HiveRegistryReader};

/// A discovered (or absent) `.LOG1`/`.LOG2` companion file — matches the parameter type
/// [HiveFiles::new_with_logs_and_findings] takes for each log slot.
type OptVirtualFile = Option<Box<dyn VirtualFile>>;

/// Sniffs and mounts a single REGF hive file. Unlike [HiveRegistryReader::from_fs] (which looks
/// for a whole `C:\Windows\System32\Config` layout up front), this mounts exactly one file at a
/// time — the shape `MountResolver` expects — and uses the hive's own internal
/// [BaseBlock::file_name](crate::hive::BaseBlock::file_name) hint (not the on-disk file name,
/// which a mounted/extracted/renamed hive may not preserve) to decide where in the resulting
/// [HiveRegistryReader] it belongs.
#[derive(Debug, Default, Clone, Copy)]
pub struct HiveFormatFactory;

impl HiveFormatFactory {
    pub fn new() -> Self {
        Self
    }

    /// Best-effort decode of [`crate::hive::BaseBlock::file_name`] (a fixed 64-byte UTF-16LE
    /// field, e.g. `\SystemRoot\System32\Config\SAM`, null-padded) into a lossy `String`,
    /// stopping at the first NUL code unit. Never panics on odd/garbage content — worst case it
    /// decodes past the intended terminator into a string this factory then simply fails to
    /// recognize, falling back to [Self::mount]'s "other" branch.
    fn decode_file_name_hint(raw: &[u8; 64]) -> String {
        crate::discovery::decode_hint(raw)
    }

    /// The plain filesystem path this hop resolves to, if `ctx`'s locator ends in one — the
    /// common case for a hive reached by opening a file directly (as opposed to, say, a hive
    /// carved from inside another container without its own path). Returns an owned [FPathBuf]
    /// rather than a borrowed [FPath] — [MountContext::locator]'s signature ties its return's
    /// lifetime to the `&self` borrow, not to `MountContext`'s own `'a`, so a borrowed result
    /// here couldn't outlive this function call anyway.
    fn locator_path(ctx: &MountContext<'_>) -> Option<FPathBuf> {
        match ctx.locator().last()? {
            LocatorSegment::Path(p) => Some(p.clone()),
            _ => None,
        }
    }

    /// Locates `.LOG1`/`.LOG2` companions beside the target, the same way
    /// [crate::reader::open_hive_with_logs] does for a known-layout `C:\Windows\...\Config`
    /// folder — but derived from wherever `ctx`'s locator says the target actually is, so it
    /// works for a hive reached through an arbitrary path (e.g. a user profile's `NTUSER.DAT`).
    fn discover_companion_logs(ctx: &MountContext<'_>) -> (OptVirtualFile, OptVirtualFile) {
        let Some(path) = Self::locator_path(ctx) else {
            return (None, None);
        };
        let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
            return (None, None);
        };
        let log1 = ctx.fs().open(parent.join(format!("{name}.LOG1")).as_path()).ok();
        let log2 = ctx.fs().open(parent.join(format!("{name}.LOG2")).as_path()).ok();
        (log1, log2)
    }
}

impl FormatFactory for HiveFormatFactory {
    fn name(&self) -> &'static str {
        "frnsc-hive"
    }

    fn yields(&self) -> MountKind {
        MountKind::Registry
    }

    /// Reads the 4096-byte base block and checks the `regf` magic plus its base-block checksum.
    /// Per [FormatFactory::probe]'s contract, restores the stream position before returning on
    /// every path, including an error return.
    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let initial_pos = file.stream_position().unwrap_or(0);
        let mut buffer = vec![0u8; 4096];
        let read_result = file.read_exact(&mut buffer);
        let seek_result = file
            .seek(std::io::SeekFrom::Start(initial_pos))
            .map_err(|e| ForensicError::io_error_with_source(e, "restoring stream position after probing"));
        // A short/truncated file is simply "not this format", not a probe failure — restore the
        // position (best-effort; nothing further to seek back from if even that fails) and report
        // `No` rather than propagating the read error.
        if read_result.is_err() {
            seek_result.ok();
            return Ok(ProbeScore::No);
        }
        seek_result?;
        if !is_valid_base_block(&buffer) {
            return Ok(ProbeScore::No);
        }
        if checksum_is_correct(&buffer) {
            Ok(ProbeScore::Exact)
        } else {
            // Magic matches but the checksum doesn't — still very likely a hive (corrupted,
            // truncated, or mid-write), just not verifiable as cleanly as `Exact`.
            Ok(ProbeScore::Strong)
        }
    }

    /// Parses `file` as a hive (replaying any discovered `.LOG1`/`.LOG2` companions if it's
    /// dirty) and wraps it in a fresh [HiveRegistryReader]. The hive's own internal `file_name`
    /// header hint decides where it's mounted: recognized SAM/SECURITY/SOFTWARE/SYSTEM hives
    /// become directly reachable under `HKLM\<HIVE>\...`; a hint ending in `ntuser.dat` is
    /// mounted as a user hive (reachable under `HKU\<profile-folder-name>\...`, using the
    /// containing folder's name as a stand-in for a real SID, since the hive's own bytes don't
    /// carry one); anything else is mounted via [HiveRegistryReader::add_other] and reachable
    /// only through [HiveRegistryReader::other_hive_root] — [PredefinedHive] has no matching
    /// variant, so it isn't reachable through the generic [Registry::root] a caller holding only
    /// `Mounted::Registry`'s `Arc<dyn Registry>` would use.
    fn mount(&self, file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let (log1, log2) = Self::discover_companion_logs(ctx);
        let locator_path = Self::locator_path(ctx);
        let location = locator_path.clone().unwrap_or_default();
        let mut findings = Vec::new();
        let hive = HiveFiles::new_with_logs_and_findings(location, file, log1, log2, &mut findings)?;

        let hint = Self::decode_file_name_hint(&hive.base_block.file_name).to_ascii_lowercase();
        let hint = hint.replace('/', "\\");
        let mut reader = HiveRegistryReader::new();
        if hint.ends_with("\\sam") {
            reader.set_sam(hive);
        } else if hint.ends_with("\\security") {
            reader.set_security(hive);
        } else if hint.ends_with("\\software") {
            reader.set_software(hive);
        } else if hint.ends_with("\\system") {
            reader.set_system(hive);
        } else if hint.ends_with("ntuser.dat") {
            let profile_name = locator_path
                .as_ref()
                .and_then(|p| p.parent())
                .and_then(|p| p.file_name())
                .unwrap_or("MountedUser");
            reader.add_user(profile_name, hive);
        } else {
            let mount_name = locator_path.as_ref().map(|p| p.as_str()).unwrap_or("mounted");
            reader.add_other(mount_name, hive);
        }
        reader.record_findings(findings);
        Ok(Mounted::Registry(Arc::new(reader)))
    }
}

#[cfg(test)]
mod tst {
    use forensic_rs::core::limits::{Limits, MemorySpillStore};
    use forensic_rs::prelude::testing::InMemoryVirtualFileSystem;

    use super::*;
    use crate::tst::init_virtual_fs;

    fn probe_ctx<'a>(
        fs: &'a Arc<dyn FileSystem>,
        locator: &'a EvidenceLocator,
        limits: &'a Limits,
        spill: &'a MemorySpillStore,
        cancellation: &'a forensic_rs::bridge::CancellationToken,
    ) -> MountContext<'a> {
        MountContext::new(fs, locator, limits, 0, spill, None, cancellation)
    }

    #[test]
    fn probe_scores_exact_on_a_well_formed_fixture_hive() {
        let fs = init_virtual_fs();
        let mut sam_file = fs.open(FPath::new("C:\\Windows\\System32\\Config\\SAM")).unwrap();
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::new()));
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let ctx = probe_ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = HiveFormatFactory::new();
        let pos_before = sam_file.stream_position().unwrap();
        let score = factory.probe(sam_file.as_mut(), &ctx).unwrap();
        assert_eq!(ProbeScore::Exact, score);
        assert_eq!(
            pos_before,
            sam_file.stream_position().unwrap(),
            "probe must restore stream position"
        );
    }

    #[test]
    fn probe_scores_no_on_a_non_hive_file() {
        let mem_fs: Arc<dyn FileSystem> =
            Arc::new(InMemoryVirtualFileSystem::new().with_file("not_a_hive", b"just some bytes".to_vec()));
        let mut file = mem_fs.open(FPath::new("not_a_hive")).unwrap();
        let locator = EvidenceLocator::root();
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let ctx = probe_ctx(&mem_fs, &locator, &limits, &spill, &cancellation);

        let factory = HiveFormatFactory::new();
        let pos_before = file.stream_position().unwrap();
        let score = factory.probe(file.as_mut(), &ctx).unwrap();
        assert_eq!(ProbeScore::No, score);
        assert_eq!(
            pos_before,
            file.stream_position().unwrap(),
            "probe must restore stream position"
        );
    }

    #[test]
    fn mount_recognizes_the_sam_hive_via_its_internal_file_name_hint() {
        let fs = init_virtual_fs();
        let sam_path = FPath::new("C:\\Windows\\System32\\Config\\SAM");
        let sam_file = fs.open(sam_path).unwrap();
        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from(sam_path)));
        let limits = Limits::default();
        let spill = MemorySpillStore::default();
        let cancellation = forensic_rs::bridge::CancellationToken::default();
        let ctx = probe_ctx(&fs, &locator, &limits, &spill, &cancellation);

        let factory = HiveFormatFactory::new();
        let mounted = factory.mount(sam_file, &ctx).unwrap();
        let registry = mounted.as_registry().expect("factory declares MountKind::Registry");

        // Reachable the same way a directly-constructed HiveRegistryReader would expose it.
        let names_key = registry.key(r"HKLM\SAM\Domains\Account\Users\Names").unwrap();
        let users: Vec<String> = names_key.keys().unwrap().into_iter().map(|k| k.name).collect();
        assert_eq!("Administrador", users[0]);
    }
}
