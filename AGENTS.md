# frnsc-hive Agent Guide

## Project Overview

frnsc-hive implements the `forensic-rs` `Registry`, `RecoverDeleted`, and `FormatFactory` traits for
Windows registry hive files (`SYSTEM`, `SOFTWARE`, `SECURITY`, `SAM`, per-user `NTUSER.DAT`),
including `.LOG1`/`.LOG2` transaction log replay and best-effort deleted key/value carving from
unallocated cells, plus a purely in-memory "mounted" key/value tree that layers on top of (or
stands in for) real hive-backed keys.

**Depends on:** [`forensic-rs`](https://github.com/ForensicRS/forensic-rs) 0.14

## Module structure

- [`src/hive.rs`](src/hive.rs) — base block (header) parsing, checksum verification, hbin/cell-list
  walking (`read_cells`), and `HiveBinHeader`.
- [`src/cell.rs`](src/cell.rs) — the seven hive cell types (`IndexLeaf`, `FastLeaf`, `HashLeaf`,
  `IndexRoot`, `KeyNode`, `KeyValue`, `KeySecurity`) plus `Unallocated`/`Invalid`, each via
  `FromBytes`/`ByteReader`.
- [`src/cell_cache.rs`](src/cell_cache.rs) — LRU-ish cache of parsed cells by file offset, so
  `Registry` calls don't re-parse the same cell repeatedly.
- [`src/log.rs`](src/log.rs) — `.LOG1`/`.LOG2` (new-format) transaction log parsing and replay:
  `read_log_entries`, `select_entries_to_apply`, `apply_entries`.
- [`src/mounted_map.rs`](src/mounted_map.rs) — `MountedMap`/`MountedCell`: an in-memory key/value
  tree for keys injected via `add_reg_key` (not backed by any hive file), keyed by path segment.
- [`src/reader.rs`](src/reader.rs) — `HiveRegistryReader` (the public `Registry`/`RecoverDeleted`
  impl), `HiveFiles` (one loaded hive + its cached cells/logs), the `RawKey` bit-packing scheme,
  mounted/real key merging logic, and the `Finding`-accumulation wiring (`findings`/
  `record_findings`).
- [`src/value.rs`](src/value.rs) — value type codes and decoding a value's bytes into a
  `RegValue` (resident data, cell data, offsets lists); shared by the file reader and other cell
  sources such as frnsc-memory's in-memory hives.
- [`src/factory.rs`](src/factory.rs) — `HiveFormatFactory`, the `forensic_rs::traits::format::
  FormatFactory` impl that sniffs/mounts a single hive file (plus discoverable `.LOG1`/`.LOG2`
  companions) as `Mounted::Registry`, for use with `forensic_rs::core::resolver::MountResolver`.
- [`src/recovery.rs`](src/recovery.rs) — deleted-key/value carving out of unallocated hive cells,
  backing `HiveRegistryReader`'s `RecoverDeleted` impl. See its module doc comment for the
  plausibility-validation rules and known limitations before changing anything here — a false
  positive here means a fabricated key/value in a case report.
- [`src/tst.rs`](src/tst.rs) — shared test fixture helpers (`init_virtual_fs`, `StdVirtualFS`-backed).

## Error handling

Use `ForensicResult<T>`/`ForensicError` from `forensic-rs` throughout — no `unwrap()`/`panic!` on
bytes sourced from a hive file. Prefer the `ForensicError::registry_*`/`registry_cell_error` /
`registry_hive_error` constructors already used across the crate over building variants by hand.

Analyst-relevant integrity signals (checksum mismatch, unreplayed dirty hive, skipped log entries,
an unparseable hive) are *additionally* recorded as `forensic_rs::pipeline::finding::Finding`s,
retrievable via `HiveRegistryReader::findings()` — this is on top of, not instead of, the existing
`warn!`/`debug!` log lines aimed at engineers. See the review skill's Finding/log/error three-way
split.

## `RawKey` bit layout

See the doc comment at [`reader.rs`](src/reader.rs) above `KIND_SHIFT`: low 48 bits are a cell
offset (or, for `HiveKind::Cached`, an id into `cached_keys`); next 6 bits are a `HiveKind` tag; top
10 bits are a position into `users`/`others`. This is a from-scratch scheme, not the pre-0.14
`RegHiveKey::Hkey(isize)` layout.

## Testing

- Unit tests live in `#[cfg(test)] mod tst`/`mod tests` at the bottom of the relevant file
  (`hive.rs`, `cell.rs`), or in a separate `*_tst.rs` file included via `#[path = "..."] mod tst`
  (`reader.rs` → `reader_tst.rs`) for larger suites.
- Use `forensic_rs::prelude::testing::InMemoryVirtualFileSystem` for synthetic fixtures and the
  real fixture hives under `artifacts/` (gitignored via `exclude` in `Cargo.toml`; large-fixture
  tests are `#[ignore]`d when the fixture isn't present) — not a mocking library or the live OS.
- The sibling `../forensic-rs` checkout, patched in via `.cargo/config.toml`'s
  `[patch.crates-io]` (gitignored — dev-only), is required to build against an unreleased
  forensic-rs API. CI builds against the published `forensic-rs` crate instead.
