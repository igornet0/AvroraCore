//! Production pgwire through the real `dmc serve --pgwire` (D4): loopback only, never on
//! the dev bootstrap, SASL `AVRORA-ED25519-V1` only, on the encrypted SQL plane.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn serve(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_dmc"));
    c.arg("serve")
        .args(args)
        .env_remove("AVRORA_DEV")
        .env_remove("DMC_KEYPASS_PASSWORD")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

fn startup_packet() -> Vec<u8> {
    let mut body = 196608i32.to_be_bytes().to_vec();
    body.extend_from_slice(b"user\0probe\0\0");
    let mut out = ((body.len() + 4) as i32).to_be_bytes().to_vec();
    out.extend(body);
    out
}

fn read_msg(s: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0u8; 5];
    s.read_exact(&mut head).ok()?;
    let len = i32::from_be_bytes(head[1..5].try_into().unwrap()) as usize;
    let mut body = vec![0u8; len - 4];
    s.read_exact(&mut body).ok()?;
    Some((head[0], body))
}

#[test]
fn non_loopback_pgwire_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let out = serve(&["--data-dir", data.to_str().unwrap(), "--pgwire"])
        .arg(format!("0.0.0.0:{}", free_port()))
        .arg("--socket")
        .arg(dir.path().join("s.sock"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("loopback"));
    assert!(!data.exists(), "refused before any storage is created");
}

#[test]
fn pgwire_is_never_hosted_on_the_dev_bootstrap() {
    let dir = tempfile::tempdir().unwrap();
    let out = serve(&["--dev", "--data-dir"])
        .arg(dir.path().join("data"))
        .arg("--socket")
        .arg(dir.path().join("s.sock"))
        .arg("--pgwire")
        .arg(format!("127.0.0.1:{}", free_port()))
        .env("AVRORA_DEV", "1")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("production-only"));
}

#[test]
fn production_serve_hosts_sql_plane_pgwire() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let port = free_port();
    let _server = Server(
        serve(&["--data-dir", data.to_str().unwrap()])
            .arg("--socket")
            .arg(dir.path().join("s.sock"))
            .arg("--pgwire")
            .arg(format!("127.0.0.1:{port}"))
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut s = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("pgwire did not come up: {e}"),
        }
    };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(&startup_packet()).unwrap();
    // only AVRORA-ED25519-V1 is offered — no AuthenticationOk without a check
    let (tag, body) = read_msg(&mut s).unwrap();
    assert_eq!(tag, b'R');
    assert_eq!(body[..4], 10i32.to_be_bytes());
    assert_eq!(&body[4..], b"AVRORA-ED25519-V1\0\0");
    // a cleartext password is refused
    let mut pw = vec![b'p'];
    pw.extend_from_slice(&13i32.to_be_bytes());
    pw.extend_from_slice(b"password\0");
    s.write_all(&pw).unwrap();
    let (tag, body) = read_msg(&mut s).unwrap();
    assert_eq!(tag, b'E');
    assert!(String::from_utf8_lossy(&body).contains("28000"));
    assert!(read_msg(&mut s).is_none(), "closed after the refusal");
    // the production data root is the encrypted SQL plane, no legacy store
    assert!(data.join("encrypted-storage.json").is_file());
    assert!(!data.join("sql.dbs.json").exists());
}
