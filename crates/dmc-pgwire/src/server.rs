use std::net::SocketAddr;
use std::sync::Arc;

use dmc_sql::SqlEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::protocol::{
    cstr, encode_auth_ok, encode_backend_key, encode_empty_query, encode_error, encode_parameter,
    encode_query_result, encode_ready, parse_startup_params, PROTOCOL_VERSION_3, SSL_REQUEST_CODE,
};

pub const DEFAULT_ADDR: &str = "127.0.0.1:15432";

pub async fn listen(addr: SocketAddr, engine: SqlEngine) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    println!("dmc-pgwire SQL (Simple Query) listening on {addr}");
    serve(listener, engine).await
}

pub async fn serve(listener: TcpListener, engine: SqlEngine) -> std::io::Result<()> {
    let engine = Arc::new(Mutex::new(engine));
    loop {
        let (stream, peer) = listener.accept().await?;
        let engine = Arc::clone(&engine);
        tokio::spawn(async move {
            if let Err(err) = handle_conn(stream, engine).await {
                eprintln!("pgwire {peer}: {err}");
            }
        });
    }
}

async fn handle_conn(mut stream: TcpStream, engine: Arc<Mutex<SqlEngine>>) -> std::io::Result<()> {
    loop {
        let len = match read_i32(&mut stream).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if len < 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "startup too short",
            ));
        }
        let proto = read_i32(&mut stream).await?;
        if proto == SSL_REQUEST_CODE {
            stream.write_all(b"N").await?;
            continue;
        }
        if proto != PROTOCOL_VERSION_3 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported protocol {proto}"),
            ));
        }
        let mut params = vec![0u8; (len as usize).saturating_sub(8)];
        stream.read_exact(&mut params).await?;
        let _ = parse_startup_params(&params);
        break;
    }

    let mut startup = Vec::new();
    startup.extend(encode_auth_ok());
    startup.extend(encode_parameter("server_version", "16.0"));
    startup.extend(encode_parameter("client_encoding", "UTF8"));
    startup.extend(encode_parameter("server_encoding", "UTF8"));
    startup.extend(encode_parameter("DateStyle", "ISO, MDY"));
    startup.extend(encode_parameter("integer_datetimes", "on"));
    startup.extend(encode_backend_key());
    startup.extend(encode_ready(false));
    stream.write_all(&startup).await?;

    loop {
        let mut tag = [0u8; 1];
        match stream.read_exact(&mut tag).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let len = read_i32(&mut stream).await?;
        let payload_len = (len as usize).saturating_sub(4);
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            stream.read_exact(&mut payload).await?;
        }
        match tag[0] {
            b'X' => return Ok(()),
            b'Q' => {
                let sql = cstr(&payload);
                let mut buf = Vec::new();
                {
                    let mut eng = engine.lock().await;
                    if sql.trim().is_empty() {
                        buf.extend(encode_empty_query());
                    } else {
                        match eng.execute(&sql) {
                            Ok(results) => {
                                for r in &results {
                                    buf.extend(encode_query_result(r));
                                }
                            }
                            Err(err) => {
                                buf.extend(encode_error(err.state().0, &err.message()));
                            }
                        }
                    }
                    buf.extend(encode_ready(eng.in_txn()));
                }
                stream.write_all(&buf).await?;
            }
            b'S' => {
                let eng = engine.lock().await;
                stream.write_all(&encode_ready(eng.in_txn())).await?;
            }
            other => {
                let msg = format!(
                    "message type {} is not supported (Simple Query only)",
                    other as char
                );
                let mut buf = encode_error("0A000", &msg);
                let eng = engine.lock().await;
                buf.extend(encode_ready(eng.in_txn()));
                stream.write_all(&buf).await?;
            }
        }
    }
}

async fn read_i32(stream: &mut TcpStream) -> std::io::Result<i32> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;
    Ok(i32::from_be_bytes(buf))
}
