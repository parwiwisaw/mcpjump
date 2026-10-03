//! Splitting and joining chunked records, at every boundary.

use mcpjump::store::chunk::{
    self, CHUNK_BYTES, Corrupt, Head, MAX_CHUNKS, Manifest, Slot, chunk_account,
};
use sha2::{Digest, Sha256};

const MAGIC: &str = "\0mcpjump-chunks/1 ";

fn hex_of(record: &[u8]) -> String {
    Sha256::digest(record)
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0xf])
        .map(|nibble| char::from_digit(u32::from(nibble), 16).unwrap())
        .collect()
}

fn head(text: &str) -> Result<Head, Corrupt> {
    chunk::parse_head(text.as_bytes().to_vec())
}

#[test]
fn slots_alternate() {
    assert_eq!(Slot::Zero.other(), Slot::One);
    assert_eq!(Slot::One.other(), Slot::Zero);
}

#[test]
fn chunk_accounts_name_the_slot_and_index() {
    assert_eq!(
        chunk_account("demo/tokens", Slot::Zero, 0),
        "demo/tokens@0#0"
    );
    assert_eq!(
        chunk_account("demo/tokens", Slot::One, 15),
        "demo/tokens@1#15"
    );
}

#[test]
fn a_manifest_counts_whole_and_partial_chunks() {
    for (len, count) in [
        (1, 1),
        (CHUNK_BYTES, 1),
        (CHUNK_BYTES + 1, 2),
        (2560, 2),
        (2561, 2),
    ] {
        assert_eq!(
            Manifest::describe(&vec![b'x'; len], Slot::Zero).count,
            count
        );
    }
    let largest = vec![b'x'; CHUNK_BYTES * MAX_CHUNKS];
    assert_eq!(Manifest::describe(&largest, Slot::One).count, MAX_CHUNKS);
}

#[test]
fn a_manifest_round_trips_through_its_encoding() {
    let record = vec![b'y'; 4500];
    for slot in [Slot::Zero, Slot::One] {
        let manifest = Manifest::describe(&record, slot);
        let encoded = manifest.encode();
        let digit = if slot == Slot::Zero { '0' } else { '1' };
        let expected = format!("{MAGIC}{digit} 3 {}", hex_of(&record));
        assert_eq!(encoded, expected.as_bytes());
        assert_eq!(chunk::parse_head(encoded), Ok(Head::Chunked(manifest)));
    }
}

#[test]
fn anything_without_the_magic_is_an_inline_record() {
    for value in ["{\"a\":1}", "", "mcpjump-chunks/1 0 1 00", "\0other"] {
        assert_eq!(head(value), Ok(Head::Inline(value.as_bytes().to_vec())));
    }
}

#[test]
fn a_malformed_manifest_is_corrupt() {
    let hex = hex_of(b"x");
    let cases = [
        MAGIC.to_owned(),
        format!("{MAGIC}2 1 {hex}"),
        format!("{MAGIC}0"),
        format!("{MAGIC}0 x {hex}"),
        format!("{MAGIC}0 0 {hex}"),
        format!("{MAGIC}0 17 {hex}"),
        format!("{MAGIC}0 1"),
        format!("{MAGIC}0 1 {}", &hex[1..]),
        format!("{MAGIC}0 1 {hex}0"),
        format!("{MAGIC}0 1 zz{}", &hex[2..]),
        format!("{MAGIC}0 1 +f{}", &hex[2..]),
        format!("{MAGIC}0 1 {hex} extra"),
    ];
    for case in cases {
        assert_eq!(head(&case), Err(Corrupt), "{case:?}");
    }
    let mut not_utf8 = MAGIC.as_bytes().to_vec();
    not_utf8.extend_from_slice(b"0 1 \xff");
    assert_eq!(chunk::parse_head(not_utf8), Err(Corrupt));
    let mut split_char = format!("{MAGIC}0 1 ").into_bytes();
    split_char.extend_from_slice("é".as_bytes());
    split_char.extend_from_slice(&hex.as_bytes()[..62]);
    assert_eq!(chunk::parse_head(split_char), Err(Corrupt));
}

fn split(record: &[u8]) -> Vec<Vec<u8>> {
    record.chunks(CHUNK_BYTES).map(<[u8]>::to_vec).collect()
}

#[test]
fn chunks_join_back_into_the_record() {
    for len in [1, CHUNK_BYTES, 2561, CHUNK_BYTES * MAX_CHUNKS] {
        let record: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let manifest = Manifest::describe(&record, Slot::Zero);
        assert_eq!(chunk::join(&manifest, &split(&record)), Ok(record));
    }
}

#[test]
fn chunks_that_do_not_match_the_manifest_are_corrupt() {
    let record = vec![b'z'; 4500];
    let manifest = Manifest::describe(&record, Slot::Zero);
    let parts = split(&record);

    assert_eq!(chunk::join(&manifest, &[]), Err(Corrupt));
    assert_eq!(chunk::join(&manifest, &parts[..2]), Err(Corrupt));

    let mut short_middle = parts.clone();
    short_middle[0].pop();
    short_middle[2].push(b'z');
    assert_eq!(chunk::join(&manifest, &short_middle), Err(Corrupt));

    let mut empty_last = parts.clone();
    empty_last[2].clear();
    assert_eq!(chunk::join(&manifest, &empty_last), Err(Corrupt));

    let mut checksum = parts.clone();
    checksum[1][7] = b'q';
    assert_eq!(chunk::join(&manifest, &checksum), Err(Corrupt));

    let long = vec![b'z'; 2 * CHUNK_BYTES + 1];
    let long_last = vec![long[..CHUNK_BYTES].to_vec(), long[CHUNK_BYTES..].to_vec()];
    let two = Manifest::describe(&long, Slot::Zero);
    assert_eq!(
        chunk::join(&Manifest { count: 2, ..two }, &long_last),
        Err(Corrupt)
    );
}
