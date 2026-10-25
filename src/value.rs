//! Registry value data: the type codes, and decoding a value's bytes into a [RegValue].
//!
//! The decoding is independent of where the bytes come from, so the file reader
//! ([crate::reader]) and other cell sources (a hive held in memory) share it.

use forensic_rs::prelude::*;

use crate::cell::InvalidCell;

pub const DATA_TYPE_NONE: u32 = 0x0;
pub const DATA_TYPE_REG_SZ: u32 = 0x1;
pub const DATA_TYPE_REG_EXPAND_SZ: u32 = 0x2;
pub const DATA_TYPE_REG_BINARY: u32 = 0x03;
pub const DATA_TYPE_REG_DWORD: u32 = 0x04;
pub const DATA_TYPE_REG_DWORD_BE: u32 = 0x05;
pub const DATA_TYPE_REG_LINK: u32 = 0x6;
pub const DATA_TYPE_REG_MULTI_SZ: u32 = 0x7;
pub const DATA_TYPE_REG_RESOURCE_LIST: u32 = 0x8;
pub const DATA_TYPE_REG_FULL_RESOURCE_DESCRIPTOR: u32 = 0x9;
pub const DATA_TYPE_REG_RESOURCE_REQUIREMENTS_LIST: u32 = 0xa;
pub const DATA_TYPE_REG_QWORD: u32 = 0xb;

/// The UTF-16LE code units of `data` (a trailing odd byte is dropped).
pub(crate) fn utf16_units(data: &[u8]) -> Vec<u16> {
    data.chunks_exact(2).map(|p| u16::from_le_bytes([p[0], p[1]])).collect()
}

/// A `REG_MULTI_SZ`: its NUL-separated strings, without the empty one(s) that end the list. An
/// empty string *inside* the list is kept: it was stored.
pub fn decode_multi_sz(data: &[u8]) -> Vec<String> {
    let units = utf16_units(data);
    let mut strings: Vec<String> = units.split(|&u| u == 0).map(String::from_utf16_lossy).collect();
    while strings.last().is_some_and(String::is_empty) {
        strings.pop();
    }
    strings
}

/// A NUL-terminated UTF-16LE string (`REG_LINK`).
pub fn decode_utf16_string(data: &[u8]) -> String {
    let units = utf16_units(data);
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// The types whose data is plain bytes or UTF-16 text, decoded the same whether the data is
/// resident or in a cell. `None` for the types decoded elsewhere.
pub(crate) fn decode_bytes_value(data_type: u32, data: &[u8]) -> Option<RegValue> {
    Some(match data_type {
        DATA_TYPE_REG_LINK => RegValue::Link(decode_utf16_string(data)),
        DATA_TYPE_REG_MULTI_SZ => RegValue::MultiSZ(decode_multi_sz(data)),
        DATA_TYPE_REG_RESOURCE_LIST => RegValue::ResourceList(data.to_vec()),
        DATA_TYPE_REG_FULL_RESOURCE_DESCRIPTOR => RegValue::FullResourceDescriptor(data.to_vec()),
        DATA_TYPE_REG_RESOURCE_REQUIREMENTS_LIST => RegValue::ResourceRequirementsList(data.to_vec()),
        _ => return None,
    })
}

/// Parses the raw bytes of a `KeyValue`s-list `Invalid` cell into the 4-byte-aligned `u32`
/// offsets it contains. A byte length that isn't a multiple of 4 means the cell's declared size
/// doesn't align to 4-byte offset entries — a corruption signal in its own right — so this
/// returns an `Err` rather than silently truncating the trailing partial entry.
pub fn parse_offsets_list(content: &[u8]) -> ForensicResult<Vec<u32>> {
    if content.len() % 4 != 0 {
        return Err(ForensicError::registry_cell_error(
            "key_values_offsets_list",
            format!(
                "offsets-list cell length {} is not a multiple of 4 (declared size doesn't align to 4-byte entries)",
                content.len()
            ),
        ));
    }
    Ok(content
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect())
}

/// Decodes a value whose data is small enough to be stored "resident" — directly inside the
/// `data_offset` field of its `KeyValueCell`, rather than in a separate cell — as signaled by a
/// negative `data_size`.
pub fn decode_resident_value(data_type: u32, data_offset: u32, cached_size: i32) -> RegValue {
    let size = (i32::MIN - cached_size).unsigned_abs() as usize;
    let value = data_offset;
    let raw = value.to_le_bytes();
    let data = &raw[0..size.min(raw.len())];
    if let Some(value) = decode_bytes_value(data_type, data) {
        return value;
    }
    match data_type {
        DATA_TYPE_REG_BINARY => RegValue::Binary(data.to_vec()),
        DATA_TYPE_REG_SZ | DATA_TYPE_REG_EXPAND_SZ => {
            // `data.len().checked_sub(2)` (rather than the unchecked `data.len() - 2`) avoids a
            // subtract-with-overflow panic when a resident string value's declared size is 0 or 1.
            let s = match (data.len().checked_sub(2).and_then(|i| data.get(i)), data.last()) {
                (Some(0), Some(0)) => {
                    if data.len() == 2 {
                        String::new()
                    } else {
                        String::from_utf16_lossy(&[u16::from_le_bytes([data[0], data[1]])])
                    }
                }
                (Some(_), Some(0)) => String::from_utf8_lossy(&data[..data.len() - 1]).to_string(),
                _ => String::from_utf8_lossy(data).to_string(),
            };
            if data_type == DATA_TYPE_REG_EXPAND_SZ {
                RegValue::ExpandSZ(s)
            } else {
                RegValue::SZ(s)
            }
        }
        DATA_TYPE_REG_DWORD => RegValue::DWord(value),
        DATA_TYPE_REG_DWORD_BE => RegValue::DWord(value.to_be()),
        DATA_TYPE_REG_QWORD => RegValue::QWord(value as u64),
        _ => RegValue::Unknown {
            ty: data_type,
            data: data.to_vec(),
        },
    }
}

/// The most data one big-data segment holds, and so the size past which a value is stored as a
/// big-data (`db`) record instead of in one cell (hive format 1.4 and later).
pub const BIG_DATA_SEGMENT_SIZE: usize = 16_344;

/// Decodes a non-resident value's data, `data` being exactly its `data_size` bytes (the start of
/// its data cell, or a big-data record's segments joined). `flags` is the `KeyValueCell`'s: bit 0
/// set means a `REG_SZ`/`REG_EXPAND_SZ` is UTF-16, clear means it is stored as ASCII.
///
/// Shared by the file reader and any other source of cells (a hive read from memory): fetching
/// the bytes is the caller's, decoding them is the same everywhere.
pub fn decode(data_type: u32, flags: u16, data: &[u8]) -> ForensicResult<RegValue> {
    let cell = InvalidCell {
        offset: 0,
        content: data.to_vec(),
    };
    Ok(match data_type {
        DATA_TYPE_NONE => RegValue::None,
        DATA_TYPE_REG_SZ | DATA_TYPE_REG_EXPAND_SZ => {
            let s = if flags & 1 == 0 {
                cell.into_reg_sz_ascii()
            } else {
                cell.into_reg_sz_extended()
            };
            if data_type == DATA_TYPE_REG_EXPAND_SZ {
                RegValue::ExpandSZ(s)
            } else {
                RegValue::SZ(s)
            }
        }
        DATA_TYPE_REG_BINARY => RegValue::Binary(cell.content),
        DATA_TYPE_REG_DWORD => RegValue::DWord(cell.into_dword_le()?),
        DATA_TYPE_REG_DWORD_BE => RegValue::DWord(cell.into_dword_be()?),
        DATA_TYPE_REG_QWORD => RegValue::QWord(cell.into_qword_le()?),
        _ => decode_bytes_value(data_type, data).unwrap_or(RegValue::Unknown {
            ty: data_type,
            data: cell.content,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn decodes_each_type_from_its_bytes() {
        assert_eq!(
            decode(DATA_TYPE_REG_SZ, 1, &utf16("abc\0")).unwrap(),
            RegValue::SZ("abc".into())
        );
        assert_eq!(
            decode(DATA_TYPE_REG_SZ, 0, b"abc\0").unwrap(),
            RegValue::SZ("abc".into())
        );
        assert_eq!(
            decode(DATA_TYPE_REG_EXPAND_SZ, 1, &utf16("%x%\0")).unwrap(),
            RegValue::ExpandSZ("%x%".into())
        );
        assert_eq!(
            decode(DATA_TYPE_REG_DWORD, 0, &[1, 0, 0, 0]).unwrap(),
            RegValue::DWord(1)
        );
        assert_eq!(
            decode(DATA_TYPE_REG_DWORD_BE, 0, &[0, 0, 0, 1]).unwrap(),
            RegValue::DWord(1)
        );
        assert_eq!(
            decode(DATA_TYPE_REG_QWORD, 0, &7u64.to_le_bytes()).unwrap(),
            RegValue::QWord(7)
        );
        assert_eq!(
            decode(DATA_TYPE_REG_BINARY, 0, &[9, 8]).unwrap(),
            RegValue::Binary(vec![9, 8])
        );
        assert_eq!(
            decode(DATA_TYPE_REG_MULTI_SZ, 0, &utf16("a\0b\0\0")).unwrap(),
            RegValue::MultiSZ(vec!["a".into(), "b".into()])
        );
        assert_eq!(decode(DATA_TYPE_NONE, 0, &[1]).unwrap(), RegValue::None);
        assert_eq!(
            decode(0x1234, 0, &[1, 2]).unwrap(),
            RegValue::Unknown {
                ty: 0x1234,
                data: vec![1, 2]
            }
        );
    }

    #[test]
    fn short_numbers_are_errors_not_zero() {
        assert!(decode(DATA_TYPE_REG_DWORD, 0, &[1, 0]).is_err());
        assert!(decode(DATA_TYPE_REG_QWORD, 0, &[1, 0, 0, 0]).is_err());
    }
}
