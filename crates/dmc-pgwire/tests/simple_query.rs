use dmc_pgwire::serve;
use dmc_sql::SqlEngine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn startup_message() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&196608i32.to_be_bytes());
    body.extend_from_slice(b"user\0dbs\0database\0main\0\0");
    let mut msg = Vec::new();
    msg.extend_from_slice(&((body.len() + 4) as i32).to_be_bytes());
    msg.extend(body);
    msg
}

fn query_message(sql: &str) -> Vec<u8> {
    let mut payload = sql.as_bytes().to_vec();
    payload.push(0);
    let mut msg = Vec::new();
    msg.push(b'Q');
    msg.extend_from_slice(&((payload.len() + 4) as i32).to_be_bytes());
    msg.extend(payload);
    msg
}

async fn read_until_ready(stream: &mut TcpStream) -> Vec<u8> {
    let mut all = Vec::new();
    loop {
        let mut tag = [0u8; 1];
        stream.read_exact(&mut tag).await.unwrap();
        all.push(tag[0]);
        let mut lenb = [0u8; 4];
        stream.read_exact(&mut lenb).await.unwrap();
        all.extend_from_slice(&lenb);
        let len = i32::from_be_bytes(lenb) as usize;
        let mut payload = vec![0u8; len.saturating_sub(4)];
        if !payload.is_empty() {
            stream.read_exact(&mut payload).await.unwrap();
            all.extend_from_slice(&payload);
        }
        if tag[0] == b'Z' {
            break;
        }
    }
    all
}

#[tokio::test]
async fn simple_query_create_and_select() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.dbs.json");
    let (engine, _master) = SqlEngine::create(&path).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve(listener, engine).await;
    });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&startup_message()).await.unwrap();
    let startup = read_until_ready(&mut stream).await;
    assert!(startup.contains(&b'Z'));

    stream
        .write_all(&query_message(
            "CREATE TABLE users (id UUID PRIMARY KEY, name TEXT NOT NULL);",
        ))
        .await
        .unwrap();
    let created = read_until_ready(&mut stream).await;
    assert!(created.contains(&b'C'), "expected CommandComplete: {created:?}");

    stream
        .write_all(&query_message(
            "INSERT INTO users (id, name) VALUES ('11111111-1111-1111-1111-111111111111', 'Ada');",
        ))
        .await
        .unwrap();
    read_until_ready(&mut stream).await;

    stream
        .write_all(&query_message("SELECT name FROM users;"))
        .await
        .unwrap();
    let selected = read_until_ready(&mut stream).await;
    let text = String::from_utf8_lossy(&selected);
    assert!(text.contains("Ada"), "{text}");
    assert!(selected.contains(&b'T'));
    assert!(selected.contains(&b'D'));
    assert!(selected.contains(&b'C'));
}
