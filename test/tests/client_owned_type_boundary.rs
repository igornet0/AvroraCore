//! Architectural boundary: server-side crates cannot even name a client private key.
//!
//! * Walk every workspace crate's `[dependencies]` (not dev-dependencies) starting from
//!   the server crates: `dmc-client-crypto` (the only crate with private-key types and
//!   HPKE open) must be unreachable.
//! * In `Cargo.lock`, `hpke` / `x25519-dalek` must be depended on only by
//!   `dmc-client-crypto` (and test crates).
//! * The wire protocol has no variant carrying private material: every field of the
//!   key-management messages is a public/wrapped type (checked by construction below).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

/// crate name → normal path dependencies (names), from each crate's Cargo.toml.
fn path_deps() -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let crates = workspace_root().join("crates");
    for entry in std::fs::read_dir(&crates).unwrap().flatten() {
        let manifest = entry.path().join("Cargo.toml");
        let Ok(text) = std::fs::read_to_string(&manifest) else { continue };
        let name = entry.file_name().to_string_lossy().to_string();
        let mut deps = Vec::new();
        let mut in_deps = false;
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with('[') {
                in_deps = l == "[dependencies]";
                continue;
            }
            if in_deps && l.contains("path =") {
                if let Some((dep, _)) = l.split_once('=') {
                    deps.push(dep.trim().to_string());
                }
            }
        }
        out.insert(name, deps);
    }
    out
}

fn reachable(from: &str, graph: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut seen = BTreeSet::new();
    let mut q = VecDeque::from([from.to_string()]);
    while let Some(c) = q.pop_front() {
        if !seen.insert(c.clone()) {
            continue;
        }
        for d in graph.get(&c).into_iter().flatten() {
            q.push_back(d.clone());
        }
    }
    seen
}

#[test]
fn server_crates_cannot_link_client_private_key_code() {
    let graph = path_deps();
    assert!(graph.contains_key("dmc-client-crypto"));
    // non-vacuity: the parser does see the server's real path dependencies
    let server = reachable("dmc-server", &graph);
    assert!(server.contains("dmc-security") && server.contains("dmc-vault"), "{server:?}");
    assert!(reachable("dmc-client-crypto", &graph).contains("dmc-vault"));
    for server in [
        "dmc-server",
        "dmc-core",
        "dmc-ops",
        "dmc-protocol",
        "dmc-security",
        "dmc-vault",
        "dmc-materialized",
        "dmc-backup",
        "dmc-storage",
        "dmc-ipc",
        "dmc-pgwire",
    ] {
        let r = reachable(server, &graph);
        assert!(
            !r.contains("dmc-client-crypto"),
            "{server} (normal deps) reaches dmc-client-crypto: {r:?}"
        );
    }
}

#[test]
fn hpke_and_x25519_are_used_only_by_the_client_crate() {
    let lock = std::fs::read_to_string(workspace_root().join("Cargo.lock")).unwrap();
    let mut dependents: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for block in lock.split("[[package]]") {
        let name = block
            .lines()
            .find_map(|l| l.strip_prefix("name = \""))
            .map(|n| n.trim_end_matches('"').to_string());
        let Some(name) = name else { continue };
        let mut in_deps = false;
        for line in block.lines() {
            let l = line.trim();
            if l.starts_with("dependencies = [") {
                in_deps = true;
                continue;
            }
            if in_deps {
                if l == "]" {
                    break;
                }
                let dep = l.trim_matches(|c| c == '"' || c == ',').split(' ').next().unwrap();
                dependents.entry(dep.to_string()).or_default().insert(name.clone());
            }
        }
    }
    for secret_crate in ["hpke", "x25519-dalek"] {
        let users = dependents.get(secret_crate).cloned().unwrap_or_default();
        let allowed: BTreeSet<String> = ["dmc-client-crypto", "dmc-integration-tests", "hpke"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(
            users.is_subset(&allowed),
            "{secret_crate} used by {users:?} — only the client crate may do HPKE/X25519"
        );
    }
}

#[test]
fn key_management_messages_carry_only_public_or_wrapped_types() {
    use dmc_protocol::ControlRequest;
    use dmc_vault::ownership::auth::KeyRotationProof;
    use dmc_vault::ownership::{ClientKeyEnvelope, ClientPublicKey, SubjectId};
    // Exhaustive destructuring: adding a field to these variants fails compilation here,
    // forcing a review of what the new field carries.
    fn fields(req: &ControlRequest) -> &'static str {
        match req {
            ControlRequest::ClientKeyRegister { session_id: _, key } => {
                let _: &ClientPublicKey = key;
                "public key"
            }
            ControlRequest::ClientKeyRotate { session_id: _, key, proof } => {
                let _: &ClientPublicKey = key;
                let _: &KeyRotationProof = proof; // signatures only
                "public key + signatures"
            }
            ControlRequest::IdentityInviteCreate {
                session_id: _,
                name: _,
                tenant: _,
                ttl_ms: _,
            } => "names",
            ControlRequest::IdentityEnroll {
                invite_id: _,
                token,
                key,
                signature,
            } => {
                // invite token: operator-issued one-time secret, not client key material
                let _: &Vec<u8> = token;
                let _: &ClientPublicKey = key;
                let _: &Vec<u8> = signature;
                "public key + signature"
            }
            ControlRequest::ClientAuthBegin { subject, tenant: _ } => {
                let _: &SubjectId = subject;
                "subject id"
            }
            ControlRequest::ClientAuthFinish { nonce: _, signature: _ } => "signature",
            ControlRequest::ClientKeyGet { session_id: _, subject } => {
                let _: &SubjectId = subject;
                "subject id"
            }
            ControlRequest::KeyEnvelopePut { session_id: _, envelope } => {
                let _: &ClientKeyEnvelope = envelope;
                "HPKE envelope"
            }
            ControlRequest::KeyEnvelopeGet { session_id: _ } => "none",
            ControlRequest::GrantCreate { session_id: _, grantee, expires_at_ms: _ } => {
                let _: &SubjectId = grantee;
                "subject id"
            }
            ControlRequest::GrantList { session_id: _ } => "none",
            ControlRequest::GrantRevoke { session_id: _, grantee } => {
                let _: &SubjectId = grantee;
                "subject id"
            }
            ControlRequest::SealedColumnDeclare {
                session_id: _,
                schema: _,
                table: _,
                column: _,
                owner_column: _,
            } => "names",
            _ => "other",
        }
    }
    let r = ControlRequest::KeyEnvelopeGet { session_id: "s".into() };
    assert_eq!(fields(&r), "none");
}

/// D1: the server verifies Ed25519 signatures with public keys only. No server crate
/// source mentions a signing-key type (signing happens in `dmc-client-crypto`).
#[test]
fn server_crates_have_no_signing_key_type() {
    let crates = workspace_root().join("crates");
    let mut offenders = Vec::new();
    for entry in std::fs::read_dir(&crates).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "dmc-client-crypto" {
            continue;
        }
        let mut stack = vec![entry.path().join("src")];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    if text.contains("SigningKey") {
                        offenders.push(p.display().to_string());
                    }
                }
            }
        }
    }
    assert!(offenders.is_empty(), "signing keys in server-side crates: {offenders:?}");
}
