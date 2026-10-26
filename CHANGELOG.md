# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Users' class hives: `UsrClass.dat` is loaded next to each `NTUSER.DAT` as `HKU\<sid>_Classes`
  (from `<ProfileImagePath>\AppData\Local\Microsoft\Windows` through `ProfileList`, or found by
  name as `discovery::HiveCandidates::classes`, then `HKU\<label>_Classes` when no SID maps it),
  with its `.LOG1`/`.LOG2` replayed like the other hives.
- `load_from_fs` loads a collection of user hives alone (no machine hive, e.g. a per-user
  registry collection) instead of returning `None`; the users are loaded under their labels.
- `value` module: the registry value type codes and the decoding of a value's bytes
  (`value::decode`, `decode_resident_value`, `parse_offsets_list`, `BIG_DATA_SEGMENT_SIZE`),
  moved out of `reader` and made public so other sources of hive cells (a hive read from
  memory) decode values exactly as the file reader does. The file reader's behaviour is
  unchanged.
- `HiveRegistryReader::load_from_fs`, returning the reader together with its integrity findings
  (`from_fs` returns a `Box<dyn Registry>`, which hides them). When `C:\Windows\System32\Config`
  holds no machine hive, it searches the whole filesystem by name
  (`discovery::find_hives`: `SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `*NTUSER.DAT`,
  `Amcache.hve`), so triage collections such as `CopiedFiles/registry/<user>_NTUSER.DAT` load.
  Candidates must carry the `regf` magic, one whose header names another hive is rejected, and
  duplicates (e.g. `RegBack`) are set aside with a finding. A user hive found by name is mapped to
  its SID through `ProfileList` by profile folder; when nothing maps it, it is loaded under
  `HKU\<label>` with a finding. A failure loading user hives is now a finding, not a `warn!`.
- `HiveRegistryReader::findings`: accumulated `forensic_rs::pipeline::finding::Finding`s for
  analyst-relevant integrity signals (checksum mismatches, unreplayed dirty hives, skipped/malformed
  log entries, unparseable hives) that were previously only visible via `warn!` log lines.
- `HiveFormatFactory`, implementing `forensic_rs::traits::format::FormatFactory` — probes a file for
  the `regf` magic and base-block checksum, and mounts it (plus any discoverable `.LOG1`/`.LOG2`
  companions) as `Mounted::Registry`. Supersedes the never-implemented `RegistryReaderFactory` this
  crate's README referred to before forensic-rs 0.14 removed that trait.
- `RecoverDeleted` implementation on `HiveRegistryReader`, carving deleted keys/values out of
  unallocated hive cells, exposed generically via `Registry::as_recovery`. Strict plausibility
  filtering (structural parse, in-range `FILETIME`, sane counts/flags) guards against false
  positives — see `src/recovery.rs`'s module doc for the validation applied and its known
  limitations (`RecoveredValue::key_hint` is always `None`; `RecoveredKey::parent_hint` falls back
  to a `<HIVE>` provenance placeholder when no live parent can be resolved). Follows
  `forensic-rs`'s `RecoverDeleted::deleted_keys()`/`deleted_values()` returning
  `Recovered<RecoveredKey>`/`Recovered<RecoveredValue>`: every carved key/value now carries its own
  `Recovery::DeletedMetadata` and a `Locus::Hive { cell, value_index }` naming the exact absolute
  hive-bins-data offset `carve_span` found it at — a carved cell was previously indistinguishable
  from a live read to any generic caller, which is exactly the false-confidence claim `Recovered`
  exists to prevent. `value_index` is always `0` for a value carved independently of any key's
  enumeration; there is no list position to report honestly.
- `cell::UnallocatedCell::size`: the free cell's declared length, needed by the deleted-cell
  recovery scan (`UnallocatedCell::offset` alone wasn't enough to know how far to scan).
- `Registry::values_raw_into`/`keys_raw_into` overrides, avoiding the intermediate `Vec` the default
  implementations allocate.
- `examples/`: five runnable examples (`load_hives_from_fs`, `mounted_registry_keys`,
  `format_factory_mount`, `integrity_findings`, `carve_deleted_keys`) covering loading hives from a
  filesystem, building a purely in-memory mounted registry, `HiveFormatFactory`/`MountResolver`,
  `findings()`, and `RecoverDeleted`-based deleted-key carving, all runnable via `cargo run
  --example <name>` from the crate root without requiring the gitignored SOFTWARE/SYSTEM fixtures.

### Changed

- Transaction-log replay failures (dirty hive with no covering log, malformed log entries,
  out-of-bounds dirty pages) and base-block checksum mismatches now also record a `Finding` in
  addition to the existing `warn!` line.
- `HiveFiles::new_with_logs`/`open_hive_with_logs` no longer silently discard an unparseable hive —
  the failure is recorded as a `ProcessingError` finding instead of vanishing via `.ok()`.
- Truncated resident registry values (fewer bytes than their declared type requires) now return an
  error instead of decoding as a fabricated `0`.
- `hive_bins_data_size` (and other evidence-controlled length fields) are validated against the
  actual file size before being used to size an allocation.
- Bumped `edition` to `2024` and `rust-version` to `1.85`, matching forensic-rs 0.14.
- `Cargo.toml` description no longer refers to the removed `RegistryReader` type.

### Fixed

- `hive::checksum_is_correct` now bounds-checks its input instead of indexing directly, avoiding a
  panic on a shorter-than-expected buffer (relevant now that `HiveFormatFactory::probe` feeds it
  arbitrary files).
- `HashLeafCell::uppercase` checked membership in the exclusive range `b'a'..b'z'`, which never
  matches `b'z'` — a subkey name's case-insensitive `HashLeaf` lookup hash differed depending on
  whether it ended in a lowercase or uppercase `Z`, breaking lookups for such names.
- `cell::InvalidCell::into_dword`/`into_dword_le`/`into_dword_be`/`into_qword_le` now return
  `ForensicResult<_>` instead of silently decoding a truncated/oversized value as `0`.

## [0.13.4] - 2025-02-18

### Added

- Support for MacOS in Github CI

### Fixed

- Mounted and user hives HKEY offset
