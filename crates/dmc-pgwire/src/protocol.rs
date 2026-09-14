use dmc_sql::{QueryResult, SqlType, SqlValue};

pub const SSL_REQUEST_CODE: i32 = 80877103;
pub const PROTOCOL_VERSION_3: i32 = 196608;

pub fn encode_auth_ok() -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(b'R');
    buf.extend_from_slice(&8i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf
}

pub fn encode_parameter(name: &str, value: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(value.as_bytes());
    payload.push(0);
    wrap(b'S', &payload)
}

pub fn encode_backend_key() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1i32.to_be_bytes());
    payload.extend_from_slice(&1i32.to_be_bytes());
    wrap(b'K', &payload)
}

pub fn encode_ready(in_txn: bool) -> Vec<u8> {
    wrap(b'Z', &[if in_txn { b'T' } else { b'I' }])
}

pub fn encode_empty_query() -> Vec<u8> {
    wrap(b'I', &[])
}

pub fn encode_command_complete(tag: &str) -> Vec<u8> {
    let mut payload = tag.as_bytes().to_vec();
    payload.push(0);
    wrap(b'C', &payload)
}

pub fn encode_error(sqlstate: &str, message: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(b'S');
    payload.extend_from_slice(b"ERROR\0");
    payload.push(b'C');
    payload.extend_from_slice(sqlstate.as_bytes());
    payload.push(0);
    payload.push(b'M');
    payload.extend_from_slice(message.as_bytes());
    payload.push(0);
    payload.push(0);
    wrap(b'E', &payload)
}

pub fn encode_query_result(result: &QueryResult) -> Vec<u8> {
    let mut out = Vec::new();
    if !result.columns.is_empty() {
        out.extend(encode_row_description(result));
        for row in &result.rows {
            out.extend(encode_data_row(row));
        }
    }
    let tag = if result.command_tag.is_empty() {
        "OK"
    } else {
        &result.command_tag
    };
    out.extend(encode_command_complete(tag));
    out
}

fn encode_row_description(result: &QueryResult) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(result.columns.len() as i16).to_be_bytes());
    for (i, name) in result.columns.iter().enumerate() {
        payload.extend_from_slice(name.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&0i32.to_be_bytes()); // table oid
        payload.extend_from_slice(&((i as i16) + 1).to_be_bytes());
        let ty = result.column_types.get(i).copied().unwrap_or(SqlType::Text);
        payload.extend_from_slice(&ty.pg_oid().to_be_bytes());
        payload.extend_from_slice(&(-1i16).to_be_bytes()); // typlen
        payload.extend_from_slice(&(-1i32).to_be_bytes()); // typmod
        payload.extend_from_slice(&0i16.to_be_bytes()); // text format
    }
    wrap(b'T', &payload)
}

fn encode_data_row(row: &[SqlValue]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(row.len() as i16).to_be_bytes());
    for val in row {
        match val.to_text() {
            None => payload.extend_from_slice(&(-1i32).to_be_bytes()),
            Some(s) => {
                payload.extend_from_slice(&(s.len() as i32).to_be_bytes());
                payload.extend_from_slice(s.as_bytes());
            }
        }
    }
    wrap(b'D', &payload)
}

fn wrap(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + payload.len());
    buf.push(tag);
    buf.extend_from_slice(&((payload.len() + 4) as i32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub fn parse_startup_params(body: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = body;
    while rest.first() != Some(&0) && !rest.is_empty() {
        let Some(k_end) = rest.iter().position(|b| *b == 0) else {
            break;
        };
        let key = String::from_utf8_lossy(&rest[..k_end]).into_owned();
        rest = &rest[k_end + 1..];
        let Some(v_end) = rest.iter().position(|b| *b == 0) else {
            break;
        };
        let value = String::from_utf8_lossy(&rest[..v_end]).into_owned();
        rest = &rest[v_end + 1..];
        out.push((key, value));
    }
    out
}

pub fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
