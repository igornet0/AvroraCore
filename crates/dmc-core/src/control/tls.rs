use std::path::Path;
use std::sync::Arc;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};

use super::init::write_secret_file;

pub fn fingerprint_der(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

pub fn generate_tls_material(data_dir: &Path) -> Result<(), String> {
    generate_tls_material_for_hosts(data_dir, &[])
}

/// Issue the control-plane CA + server cert. Extra hosts (DNS or IP) are added
/// as SANs so remote invite hostnames pass post-bootstrap mTLS name checks.
pub fn generate_tls_material_for_hosts(data_dir: &Path, extra_hosts: &[&str]) -> Result<(), String> {
    let tls = data_dir.join("tls");
    let ca_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut ca_params =
        CertificateParams::new(vec!["Avrora Control CA".into()]).map_err(|e| e.to_string())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Avrora Control CA");
        dn
    };
    let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| e.to_string())?;
    let ca_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();

    let server_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut names = vec!["localhost".to_string()];
    for host in extra_hosts {
        let host = host.trim();
        if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
            continue;
        }
        if !names.iter().any(|n| n.eq_ignore_ascii_case(host)) {
            names.push(host.to_string());
        }
    }
    let mut server_params = CertificateParams::new(names).map_err(|e| e.to_string())?;
    server_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "avrora");
        dn
    };
    server_params.subject_alt_names = server_sans(extra_hosts)?;
    let issuer = Issuer::from_ca_cert_pem(
        &ca_pem,
        KeyPair::from_pem(&ca_key_pem).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let server_cert = server_params
        .signed_by(&server_key, &issuer)
        .map_err(|e| e.to_string())?;

    fs_write(tls.join("ca.crt"), ca_pem)?;
    write_secret_file(&tls.join("ca.key"), ca_key_pem.as_bytes())?;
    fs_write(tls.join("server.crt"), server_cert.pem())?;
    write_secret_file(
        &tls.join("server.key"),
        server_key.serialize_pem().as_bytes(),
    )?;
    Ok(())
}

fn fs_write(path: std::path::PathBuf, s: String) -> Result<(), String> {
    std::fs::write(path, s).map_err(|e| e.to_string())
}

pub fn load_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    rustls_pemfile::certs(&mut raw.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

pub fn load_pem_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    rustls_pemfile::private_key(&mut raw.as_slice())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no private key in {}", path.display()))
}

pub fn load_server_tls(data_dir: &Path) -> Result<ServerConfig, String> {
    let tls = data_dir.join("tls");
    let ca_certs = load_pem_certs(&tls.join("ca.crt"))?;
    let server_certs = load_pem_certs(&tls.join("server.crt"))?;
    let server_key = load_pem_key(&tls.join("server.key"))?;

    let mut roots = RootCertStore::empty();
    for c in &ca_certs {
        roots.add(c.clone()).map_err(|e| e.to_string())?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .map_err(|e| e.to_string())?;

    let mut cfg = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, server_key)
        .map_err(|e| e.to_string())?;
    cfg.alpn_protocols = vec![b"avrora-control/1".to_vec()];
    Ok(cfg)
}

pub fn issue_client_cert(
    data_dir: &Path,
    device_id: &str,
) -> Result<(String, String, String, String), String> {
    let tls = data_dir.join("tls");
    let ca_pem = std::fs::read_to_string(tls.join("ca.crt")).map_err(|e| e.to_string())?;
    let ca_key_pem = std::fs::read_to_string(tls.join("ca.key")).map_err(|e| e.to_string())?;
    let ca_key = KeyPair::from_pem(&ca_key_pem).map_err(|e| e.to_string())?;
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).map_err(|e| e.to_string())?;

    let client_key = KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = CertificateParams::new(vec![device_id.into()]).map_err(|e| e.to_string())?;
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_id);
        dn
    };
    let client_cert = params
        .signed_by(&client_key, &issuer)
        .map_err(|e| e.to_string())?;
    let cert_pem = client_cert.pem();
    let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .ok_or("client cert encode")?
        .map_err(|e| e.to_string())?;
    let fp = fingerprint_der(der.as_ref());
    Ok((cert_pem, client_key.serialize_pem(), ca_pem, fp))
}

fn server_sans(extra_hosts: &[&str]) -> Result<Vec<SanType>, String> {
    let mut sans = vec![
        SanType::DnsName(
            "localhost"
                .try_into()
                .map_err(|e: rcgen::Error| e.to_string())?,
        ),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
    ];
    for host in extra_hosts {
        let host = host.trim();
        if host.is_empty() {
            continue;
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if !sans.iter().any(|s| matches!(s, SanType::IpAddress(x) if *x == ip)) {
                sans.push(SanType::IpAddress(ip));
            }
            continue;
        }
        if host.eq_ignore_ascii_case("localhost") {
            continue;
        }
        let dns = SanType::DnsName(
            host.try_into()
                .map_err(|e: rcgen::Error| e.to_string())?,
        );
        if !sans.contains(&dns) {
            sans.push(dns);
        }
    }
    Ok(sans)
}

pub fn cert_covers_host(der: &[u8], host: &str) -> Result<bool, String> {
    use x509_parser::prelude::*;
    let host = host.trim();
    if host.is_empty() {
        return Ok(false);
    }
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| e.to_string())?;
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(n) => dns.push((*n).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ip_from_san_bytes(bytes) {
                        ips.push(ip);
                    }
                }
                _ => {}
            }
        }
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ips.iter().any(|x| *x == ip));
    }
    Ok(dns.iter().any(|d| d.eq_ignore_ascii_case(host)))
}

fn ip_from_san_bytes(bytes: &[u8]) -> Option<std::net::IpAddr> {
    match bytes.len() {
        4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let mut oct = [0u8; 16];
            oct.copy_from_slice(bytes);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(oct)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_material_covers_localhost() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("control");
        std::fs::create_dir_all(data.join("tls")).unwrap();
        generate_tls_material(&data).unwrap();
        let certs = load_pem_certs(&data.join("tls/server.crt")).unwrap();
        assert!(cert_covers_host(certs[0].as_ref(), "localhost").unwrap());
        assert!(cert_covers_host(certs[0].as_ref(), "127.0.0.1").unwrap());
    }

    #[test]
    fn extra_dns_host_is_in_server_san() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("control");
        std::fs::create_dir_all(data.join("tls")).unwrap();
        generate_tls_material_for_hosts(&data, &["db.example.com"]).unwrap();
        let certs = load_pem_certs(&data.join("tls/server.crt")).unwrap();
        let der = certs[0].as_ref();
        assert!(cert_covers_host(der, "db.example.com").unwrap());
        assert!(cert_covers_host(der, "localhost").unwrap());
        assert!(cert_covers_host(der, "127.0.0.1").unwrap());
        assert!(!cert_covers_host(der, "other.example.com").unwrap());
    }

    #[test]
    fn extra_ip_host_is_in_server_san() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("control");
        std::fs::create_dir_all(data.join("tls")).unwrap();
        generate_tls_material_for_hosts(&data, &["10.8.0.4"]).unwrap();
        let certs = load_pem_certs(&data.join("tls/server.crt")).unwrap();
        assert!(cert_covers_host(certs[0].as_ref(), "10.8.0.4").unwrap());
        assert!(cert_covers_host(certs[0].as_ref(), "127.0.0.1").unwrap());
    }
}
