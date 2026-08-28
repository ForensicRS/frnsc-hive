//! Shared numeric constants for the REGF hive file format.

/// Size, in bytes, of the REGF base block (the first structure in every hive file).
/// The hive bins data area begins immediately after it, at this file offset.
pub const HIVE_BASE_BLOCK_SIZE: u64 = 4096;

/// Relative offset (from the start of the hive bins data) of the root cell.
/// It sits immediately after the first `HiveBinHeader` (32 bytes).
pub const ROOT_CELL_OFFSET: u64 = 32;
