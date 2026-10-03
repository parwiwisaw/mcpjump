//! Splitting a record across keyring entries and joining it back. Pure
//! functions, so every size boundary is tested on every OS.
//!
//! A record that fits one entry is stored as is. A larger one is written as
//! chunks `<account>@<slot>#<index>`, then a manifest in the main entry
//! names the slot, the count and a SHA-256 of the record. Slots alternate
//! between writes, so the committed chunks are never touched until the new
//! manifest is written, and at most two generations exist at once.

use sha2::{Digest, Sha256};

/// Bytes per chunk, below Windows' 2560-byte entry limit.
pub const CHUNK_BYTES: usize = 2000;

/// Most chunks one record may use.
pub const MAX_CHUNKS: usize = 16;

/// Starts every manifest. A NUL byte cannot start JSON text, so a manifest
/// is never mistaken for a record.
const MAGIC: &[u8] = b"\0mcpjump-chunks/1 ";

/// Which of the two chunk generations a manifest points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Chunks `@0#…`.
    Zero,
    /// Chunks `@1#…`.
    One,
}

impl Slot {
    /// The slot the next chunked write uses.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Zero => Self::One,
            Self::One => Self::Zero,
        }
    }

    const fn digit(self) -> char {
        match self {
            Self::Zero => '0',
            Self::One => '1',
        }
    }
}

/// Where a chunked record lives and how to check it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The chunk generation.
    pub slot: Slot,
    /// Number of chunks, 1 to [`MAX_CHUNKS`].
    pub count: usize,
    /// SHA-256 of the whole record.
    pub sha256: [u8; 32],
}

impl Manifest {
    /// The manifest for `record` written as chunks in `slot`.
    #[must_use]
    pub fn describe(record: &[u8], slot: Slot) -> Self {
        Self {
            slot,
            count: record.len().div_ceil(CHUNK_BYTES),
            sha256: Sha256::digest(record).into(),
        }
    }

    /// The main entry's value.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let hex: String = self
            .sha256
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0xf])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
            .collect();
        let text = format!("{} {} {hex}", self.slot.digit(), self.count);
        [MAGIC, text.as_bytes()].concat()
    }
}

/// What the main entry holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Head {
    /// The record itself.
    Inline(Vec<u8>),
    /// A manifest pointing at chunks.
    Chunked(Manifest),
}

/// A manifest or chunk set that does not check out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Corrupt;

/// Reads the main entry's value.
///
/// # Errors
/// [`Corrupt`] for a manifest that does not parse.
pub fn parse_head(value: Vec<u8>) -> Result<Head, Corrupt> {
    match value.strip_prefix(MAGIC) {
        None => Ok(Head::Inline(value)),
        Some(text) => parse_manifest(text).map(Head::Chunked).ok_or(Corrupt),
    }
}

fn parse_manifest(text: &[u8]) -> Option<Manifest> {
    let text = std::str::from_utf8(text).ok()?;
    let mut fields = text.split(' ');
    let slot = match fields.next() {
        Some("0") => Slot::Zero,
        Some("1") => Slot::One,
        _ => return None,
    };
    let count = fields.next()?.parse::<usize>().ok()?;
    let sha256 = decode_hex(fields.next()?)?;
    let fits = (1..=MAX_CHUNKS).contains(&count);
    (fits && fields.next().is_none()).then_some(Manifest {
        slot,
        count,
        sha256,
    })
}

/// 64 hex digits as 32 bytes. Each character must be a hex digit: no sign,
/// as `from_str_radix` would allow.
fn decode_hex(text: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if text.len() != 2 * out.len() {
        return None;
    }
    let nibbles: Vec<u32> = text
        .chars()
        .map(|c| c.to_digit(16))
        .collect::<Option<_>>()?;
    for (byte, [high, low]) in out.iter_mut().zip(nibbles.as_chunks::<2>().0) {
        let value = high << 4 | low;
        *byte = u8::try_from(value).unwrap_or_default();
    }
    Some(out)
}

/// Joins the chunks a manifest names, checking each size and the checksum.
///
/// # Errors
/// [`Corrupt`] if the count, a size or the checksum is wrong.
pub fn join(manifest: &Manifest, parts: &[Vec<u8>]) -> Result<Vec<u8>, Corrupt> {
    let (last, full) = parts.split_last().ok_or(Corrupt)?;
    let sizes_ok = parts.len() == manifest.count
        && full.iter().all(|part| part.len() == CHUNK_BYTES)
        && (1..=CHUNK_BYTES).contains(&last.len());
    let record = parts.concat();
    let digest: [u8; 32] = Sha256::digest(&record).into();
    (sizes_ok && digest == manifest.sha256)
        .then_some(record)
        .ok_or(Corrupt)
}

/// The account of chunk `index` in `slot`.
#[must_use]
pub fn chunk_account(account: &str, slot: Slot, index: usize) -> String {
    format!("{account}@{}#{index}", slot.digit())
}
