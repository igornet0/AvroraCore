//! Independent derivation of CLIENT_OWNED secrets (mirrors the documented KDFs, not the
//! client API) and a raw/hex scanner. Shared by the transport confidentiality tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use dmc_client_crypto::RecoveryCode;
use dmc_vault::ownership::ClientKeyEnvelope;

pub fn root_of(code: &RecoveryCode) -> [u8; 32] {
    let parts: Vec<&str> = code.as_str().split('-').collect();
    hex::decode(parts[1..9].concat()).unwrap().try_into().unwrap()
}

/// X25519 (HPKE KEM) private key of `version`.
pub fn kem_private_key(root: &[u8; 32], version: u32) -> Vec<u8> {
    use hpke::{Kem, Serializable};
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, root);
    let info = if version == 1 {
        b"avrora/client-kem/v1".to_vec()
    } else {
        format!("avrora/client-kem/v1/kv{version}").into_bytes()
    };
    let mut ikm = [0u8; 32];
    hk.expand(&info, &mut ikm).unwrap();
    let (sk, _) = hpke::kem::X25519HkdfSha256::derive_keypair(&ikm);
    sk.to_bytes().to_vec()
}

/// Ed25519 auth key seed (the private key) of `version`.
pub fn auth_seed(root: &[u8; 32], version: u32) -> Vec<u8> {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, root);
    let mut seed = [0u8; 32];
    hk.expand(format!("avrora/client-owned/ed25519/v1/kv{version}").as_bytes(), &mut seed)
        .unwrap();
    seed.to_vec()
}

/// DEK inside `env`, opened with the recipient's independently derived KEM key.
pub fn dek_from(env: &ClientKeyEnvelope, root: &[u8; 32], kem_version: u32) -> Vec<u8> {
    use hpke::{Deserializable, OpModeR};
    type K = hpke::kem::X25519HkdfSha256;
    let sk = <K as hpke::Kem>::PrivateKey::from_bytes(&kem_private_key(root, kem_version)).unwrap();
    let enc = <K as hpke::Kem>::EncappedKey::from_bytes(&env.enc).unwrap();
    let b = env.binding();
    hpke::single_shot_open::<hpke::aead::AesGcm256, hpke::kdf::HkdfSha256, K>(&OpModeR::Base, &sk, &enc, &b, &env.ciphertext, &b)
        .unwrap()
}

#[derive(Default)]
pub struct Secrets(pub Vec<(String, Vec<u8>)>);

impl Secrets {
    /// Raw, lowercase hex and uppercase hex encodings.
    pub fn add(&mut self, label: &str, bytes: &[u8]) {
        self.0.push((format!("{label}(raw)"), bytes.to_vec()));
        self.0.push((format!("{label}(hex)"), hex::encode(bytes).into_bytes()));
        self.0.push((format!("{label}(HEX)"), hex::encode_upper(bytes).into_bytes()));
    }

    pub fn add_text(&mut self, label: &str, s: &str) {
        self.0.push((label.to_string(), s.as_bytes().to_vec()));
    }

    /// Every client secret of an identity: root, recovery code, X25519 and Ed25519
    /// private keys of versions `1..=versions`.
    pub fn add_identity(&mut self, name: &str, code: &RecoveryCode, versions: u32) {
        let root = root_of(code);
        self.add(&format!("{name}-root"), &root);
        self.add_text(&format!("{name}-recovery-code"), code.as_str());
        for v in 1..=versions {
            self.add(&format!("{name}-x25519-v{v}"), &kem_private_key(&root, v));
            self.add(&format!("{name}-ed25519-v{v}"), &auth_seed(&root, v));
        }
    }

    pub fn find_in(&self, hay: &[u8]) -> Vec<String> {
        self.0
            .iter()
            .filter(|(_, n)| hay.windows(n.len()).any(|w| w == n.as_slice()))
            .map(|(l, _)| l.clone())
            .collect()
    }
}

pub fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

pub fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}
