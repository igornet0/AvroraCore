use dmc_vault::crypto::{decrypt, encrypt};
use dmc_vault::key::{KeyMaterial, KeyPath};
use dmc_vault::KeyNodeMeta;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::types::{
    canonical_path, journal_aad, JournalEntry, JournalEntryDraft, JournalEventKind, Operation,
    ENTRY_PREFIX_LEN, FORMAT_VERSION, MAGIC_FOOTER, MAGIC_HEADER, MAX_PATH_LEN, MAX_ROLE_LEN,
    SCHEMA_VERSION, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN,
};

pub struct SegmentHeader {
    pub segment_id: u64,
    pub first_sequence: u64,
    pub created_unix_ms: u64,
    pub journal_key_id: [u8; 16],
}

pub fn encode_segment_header(h: &SegmentHeader) -> [u8; SEGMENT_HEADER_LEN] {
    let mut buf = [0u8; SEGMENT_HEADER_LEN];
    buf[0..4].copy_from_slice(MAGIC_HEADER);
    buf[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    buf[6..8].copy_from_slice(&0u16.to_le_bytes());
    buf[8..16].copy_from_slice(&h.segment_id.to_le_bytes());
    buf[16..24].copy_from_slice(&h.first_sequence.to_le_bytes());
    buf[24..32].copy_from_slice(&h.created_unix_ms.to_le_bytes());
    buf[32..48].copy_from_slice(&h.journal_key_id);
    buf
}

pub fn decode_segment_header(buf: &[u8]) -> Result<SegmentHeader> {
    if buf.len() < SEGMENT_HEADER_LEN {
        return Err(Error::format("short segment header"));
    }
    if &buf[0..4] != MAGIC_HEADER {
        return Err(Error::format("bad segment magic"));
    }
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if version != FORMAT_VERSION {
        return Err(Error::format(format!("unsupported journal version {version}")));
    }
    let mut journal_key_id = [0u8; 16];
    journal_key_id.copy_from_slice(&buf[32..48]);
    Ok(SegmentHeader {
        segment_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        first_sequence: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        created_unix_ms: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        journal_key_id,
    })
}

pub fn encode_footer(last_sequence: u64, entry_count: u64) -> [u8; SEGMENT_FOOTER_LEN] {
    let mut buf = [0u8; SEGMENT_FOOTER_LEN];
    buf[0..8].copy_from_slice(&last_sequence.to_le_bytes());
    buf[8..16].copy_from_slice(&entry_count.to_le_bytes());
    let crc = crc32c::crc32c(&buf[0..16]);
    buf[16..20].copy_from_slice(&crc.to_le_bytes());
    buf[20..24].copy_from_slice(MAGIC_FOOTER);
    buf
}

use std::cell::Cell;

thread_local! {
    static TEST_TIMESTAMP_MS: Cell<Option<u64>> = const { Cell::new(None) };
}

/// Test hook: override journal entry timestamps. Not persisted.
pub fn set_test_timestamp_ms(ts: Option<u64>) {
    TEST_TIMESTAMP_MS.with(|c| c.set(ts));
}

pub fn now_unix_ms() -> u64 {
    TEST_TIMESTAMP_MS.with(|c| {
        c.get().unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        })
    })
}

/// Encoded on-disk entry: [entry_len BE][crc LE][body]
pub fn encode_entry(
    draft: &JournalEntryDraft,
    sequence: u64,
    path_dek: &KeyMaterial,
) -> Result<(Vec<u8>, [u8; 16])> {
    let path = canonical_path(&draft.path);
    if path.len() > MAX_PATH_LEN {
        return Err(Error::format("path too long"));
    }
    if draft.actor_role.len() > MAX_ROLE_LEN {
        return Err(Error::format("role too long"));
    }
    let event_id = Uuid::now_v7();
    let ts = now_unix_ms();
    let event_kind = draft.event_kind.as_u16();
    let aad = journal_aad(&path, sequence, draft.key_version, event_kind);
    let blob = encrypt(path_dek, &draft.payload, &aad).map_err(|_| Error::Crypto("encrypt".into()))?;
    let node_bundle = serde_json::to_vec(&draft.node_bundle).map_err(|e| Error::format(e))?;

    let mut prefix = [0u8; ENTRY_PREFIX_LEN];
    prefix[0..8].copy_from_slice(&sequence.to_le_bytes());
    prefix[8..24].copy_from_slice(event_id.as_bytes());
    prefix[24..32].copy_from_slice(&ts.to_le_bytes());
    prefix[32..34].copy_from_slice(&event_kind.to_le_bytes());
    prefix[34..36].copy_from_slice(&draft.operation.as_u16().to_le_bytes());
    prefix[36..44].copy_from_slice(&draft.key_version.to_le_bytes());
    prefix[44..60].copy_from_slice(&draft.actor_session);
    prefix[60..62].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
    prefix[62..66].copy_from_slice(&(draft.payload.len() as u32).to_le_bytes());
    prefix[66..68].copy_from_slice(&(path.len() as u16).to_le_bytes());
    prefix[68] = draft.actor_role.len() as u8;

    let mut body = Vec::new();
    body.extend_from_slice(&prefix);
    body.extend_from_slice(path.as_bytes());
    body.extend_from_slice(draft.actor_role.as_bytes());
    body.extend_from_slice(&(node_bundle.len() as u32).to_le_bytes());
    body.extend_from_slice(&node_bundle);
    body.extend_from_slice(&blob.nonce);
    body.extend_from_slice(&blob.ciphertext);

    let crc = crc32c::crc32c(&body);
    let entry_len = (4 + body.len()) as u32;
    let mut out = Vec::with_capacity(4 + 4 + body.len());
    out.extend_from_slice(&entry_len.to_be_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&body);
    Ok((out, *event_id.as_bytes()))
}

#[derive(Clone)]
pub struct ScannedEntry {
    pub sequence: u64,
    pub event_id: [u8; 16],
    pub timestamp_unix_ms: u64,
    pub path: String,
    pub event_kind: u16,
    pub operation: u16,
    pub key_version: u64,
    pub actor_session: [u8; 16],
    pub actor_role: String,
    pub node_bundle: Vec<KeyNodeMeta>,
    pub payload_len: u32,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Parse body after CRC. Used by recover (no decrypt) and replay.
pub fn parse_entry_body(body: &[u8]) -> Result<ScannedEntry> {
    if body.len() < ENTRY_PREFIX_LEN + 4 + 12 {
        return Err(Error::format("short entry body"));
    }
    let sequence = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let mut event_id = [0u8; 16];
    event_id.copy_from_slice(&body[8..24]);
    let timestamp_unix_ms = u64::from_le_bytes(body[24..32].try_into().unwrap());
    let event_kind = u16::from_le_bytes(body[32..34].try_into().unwrap());
    let operation = u16::from_le_bytes(body[34..36].try_into().unwrap());
    let key_version = u64::from_le_bytes(body[36..44].try_into().unwrap());
    let mut actor_session = [0u8; 16];
    actor_session.copy_from_slice(&body[44..60]);
    let payload_len = u32::from_le_bytes(body[62..66].try_into().unwrap());
    let path_len = u16::from_le_bytes(body[66..68].try_into().unwrap()) as usize;
    let role_len = body[68] as usize;
    let mut off = ENTRY_PREFIX_LEN;
    if body.len() < off + path_len + role_len + 4 {
        return Err(Error::format("short path/role"));
    }
    let path = String::from_utf8(body[off..off + path_len].to_vec())
        .map_err(|_| Error::format("path utf8"))?;
    off += path_len;
    let actor_role = String::from_utf8(body[off..off + role_len].to_vec())
        .map_err(|_| Error::format("role utf8"))?;
    off += role_len;
    let node_len = u32::from_le_bytes(body[off..off + 4].try_into().unwrap()) as usize;
    off += 4;
    if body.len() < off + node_len + 12 {
        return Err(Error::format("short node bundle"));
    }
    let node_bundle: Vec<KeyNodeMeta> =
        serde_json::from_slice(&body[off..off + node_len]).map_err(|e| Error::format(e))?;
    off += node_len;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&body[off..off + 12]);
    off += 12;
    let ciphertext = body[off..].to_vec();
    Ok(ScannedEntry {
        sequence,
        event_id,
        timestamp_unix_ms,
        path,
        event_kind,
        operation,
        key_version,
        actor_session,
        actor_role,
        node_bundle,
        payload_len,
        nonce,
        ciphertext,
    })
}

pub fn decrypt_scanned(scanned: &ScannedEntry, path_dek: &KeyMaterial) -> Result<Vec<u8>> {
    let aad = journal_aad(
        &scanned.path,
        scanned.sequence,
        scanned.key_version,
        scanned.event_kind,
    );
    let blob = dmc_vault::crypto::AeadBlob {
        nonce: scanned.nonce,
        ciphertext: scanned.ciphertext.clone(),
    };
    let plain = decrypt(path_dek, &blob, &aad).map_err(|_| Error::Crypto("decrypt".into()))?;
    if plain.len() != scanned.payload_len as usize {
        return Err(Error::format("payload length mismatch"));
    }
    Ok(plain)
}

pub fn scanned_to_entry(scanned: ScannedEntry, payload: Vec<u8>) -> Result<JournalEntry> {
    let path = if scanned.path == "/" {
        KeyPath::root()
    } else {
        KeyPath::parse(scanned.path.trim_start_matches('/')).map_err(Error::from)?
    };
    let event_kind =
        JournalEventKind::from_u16(scanned.event_kind).ok_or_else(|| Error::format("bad event kind"))?;
    let operation =
        Operation::from_u16(scanned.operation).ok_or_else(|| Error::format("bad operation"))?;
    Ok(JournalEntry {
        sequence: scanned.sequence,
        event_id: scanned.event_id,
        timestamp_unix_ms: scanned.timestamp_unix_ms,
        path,
        event_kind,
        operation,
        key_version: scanned.key_version,
        actor_session: scanned.actor_session,
        actor_role: scanned.actor_role,
        node_bundle: scanned.node_bundle,
        payload,
    })
}

pub fn decode_segment_footer(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() < SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN {
        return None;
    }
    let footer = &bytes[bytes.len() - SEGMENT_FOOTER_LEN..];
    if &footer[20..24] != MAGIC_FOOTER {
        return None;
    }
    let crc = crc32c::crc32c(&footer[0..16]);
    let stored = u32::from_le_bytes(footer[16..20].try_into().ok()?);
    if crc != stored {
        return None;
    }
    let last_sequence = u64::from_le_bytes(footer[0..8].try_into().ok()?);
    let entry_count = u64::from_le_bytes(footer[8..16].try_into().ok()?);
    Some((last_sequence, entry_count))
}

/// Raw on-disk record bytes: `[entry_len BE][crc LE][body]`.
pub fn scan_segment_raw_records(bytes: &[u8]) -> Result<(usize, Vec<Vec<u8>>, u64)> {
    if bytes.len() < SEGMENT_HEADER_LEN {
        return Err(Error::format("segment shorter than header"));
    }
    decode_segment_header(&bytes[..SEGMENT_HEADER_LEN])?;
    let mut offset = SEGMENT_HEADER_LEN;
    let mut last_good = SEGMENT_HEADER_LEN;
    let mut records = Vec::new();
    let mut last_seq = 0u64;
    while offset + 4 <= bytes.len() {
        let entry_len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if offset + 4 + entry_len > bytes.len() {
            break;
        }
        if entry_len < 4 {
            break;
        }
        let crc_stored = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let body = &bytes[offset + 8..offset + 4 + entry_len];
        if crc32c::crc32c(body) != crc_stored {
            break;
        }
        match parse_entry_body(body) {
            Ok(scanned) => {
                last_seq = last_seq.max(scanned.sequence);
                records.push(bytes[offset..offset + 4 + entry_len].to_vec());
            }
            Err(_) => break,
        }
        last_good = offset + 4 + entry_len;
        offset = last_good;
    }
    Ok((last_good, records, last_seq))
}

/// Validate a sealed segment and return raw record bytes (5.6.2 compaction input).
pub fn validate_sealed_segment(
    bytes: &[u8],
    expected_id: u64,
) -> Result<(u64, u64, u64, Vec<Vec<u8>>)> {
    if bytes.len() < SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN {
        return Err(Error::format("sealed segment too short"));
    }
    let header = decode_segment_header(&bytes[..SEGMENT_HEADER_LEN])?;
    if header.segment_id != expected_id {
        return Err(Error::format(format!(
            "segment id mismatch: expected {expected_id}, got {}",
            header.segment_id
        )));
    }
    let (last_sequence, entry_count) =
        decode_segment_footer(bytes).ok_or_else(|| Error::format("missing or corrupt segment footer"))?;
    let data_end = bytes.len() - SEGMENT_FOOTER_LEN;
    let (last_good, records, last_scanned_seq) = scan_segment_raw_records(bytes)?;
    if last_good != data_end {
        return Err(Error::format(format!(
            "segment {expected_id} corrupt: invalid bytes before footer"
        )));
    }
    if records.len() as u64 != entry_count {
        return Err(Error::format(format!(
            "segment {expected_id} footer entry_count mismatch"
        )));
    }
    if entry_count > 0 && last_scanned_seq != last_sequence {
        return Err(Error::format(format!(
            "segment {expected_id} footer last_sequence mismatch"
        )));
    }
    Ok((header.first_sequence, last_sequence, entry_count, records))
}

/// Scan a segment file. Returns valid prefix length (from file start) and entries.
pub fn scan_segment(bytes: &[u8]) -> Result<(usize, Vec<ScannedEntry>, u64)> {
    if bytes.len() < SEGMENT_HEADER_LEN {
        return Err(Error::format("segment shorter than header"));
    }
    decode_segment_header(&bytes[..SEGMENT_HEADER_LEN])?;
    let mut offset = SEGMENT_HEADER_LEN;
    let mut last_good = SEGMENT_HEADER_LEN;
    let mut entries = Vec::new();
    let mut last_seq = 0u64;
    while offset + 4 <= bytes.len() {
        let entry_len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if offset + 4 + entry_len > bytes.len() {
            break;
        }
        if entry_len < 4 {
            break;
        }
        let crc_stored = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        let body = &bytes[offset + 8..offset + 4 + entry_len];
        if crc32c::crc32c(body) != crc_stored {
            break;
        }
        match parse_entry_body(body) {
            Ok(scanned) => {
                last_seq = last_seq.max(scanned.sequence);
                entries.push(scanned);
            }
            Err(_) => break,
        }
        last_good = offset + 4 + entry_len;
        offset = last_good;
    }
    Ok((last_good, entries, last_seq))
}
