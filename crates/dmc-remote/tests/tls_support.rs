use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, SanType,
};
use time::{Duration, OffsetDateTime};

use dmc_remote::{TlsClientConfig, TlsMaterial, TlsServerConfig};

pub struct DevTlsStack {
    pub material: TlsMaterial,
    pub server: TlsServerConfig,
    pub client: TlsClientConfig,
}

pub fn dev_tls_stack(server_hostname: &str) -> DevTlsStack {
    let material = issue_material(server_hostname, None, None);
    let server = TlsServerConfig::from_material(&material).unwrap();
    let client = TlsClientConfig::from_material(&material, server_hostname).unwrap();
    DevTlsStack {
        material,
        server,
        client,
    }
}

pub fn expired_tls_stack(server_hostname: &str) -> DevTlsStack {
    let not_before = OffsetDateTime::now_utc() - Duration::days(30);
    let not_after = OffsetDateTime::now_utc() - Duration::days(1);
    let material = issue_material(server_hostname, Some(not_before), Some(not_after));
    let server = TlsServerConfig::from_material(&material).unwrap();
    let client = TlsClientConfig::from_material(&material, server_hostname).unwrap();
    DevTlsStack {
        material,
        server,
        client,
    }
}

pub fn untrusted_ca_stack(server_hostname: &str) -> (DevTlsStack, TlsClientConfig) {
    let server_stack = dev_tls_stack(server_hostname);
    let other_ca = issue_ca_only();
    let wrong_client =
        TlsClientConfig::from_ca_pem(&other_ca.ca_cert_pem, server_hostname).unwrap();
    (server_stack, wrong_client)
}

pub fn not_yet_valid_tls_stack(server_hostname: &str) -> DevTlsStack {
    let not_before = OffsetDateTime::now_utc() + Duration::days(1);
    let not_after = OffsetDateTime::now_utc() + Duration::days(30);
    let material = issue_material(server_hostname, Some(not_before), Some(not_after));
    let server = TlsServerConfig::from_material(&material).unwrap();
    let client = TlsClientConfig::from_material(&material, server_hostname).unwrap();
    DevTlsStack {
        material,
        server,
        client,
    }
}

struct CaMaterial {
    ca_cert_pem: Vec<u8>,
    ca_key_pem: String,
}

fn issue_ca_only() -> CaMaterial {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params =
        CertificateParams::new(vec!["Avrora Test CA".into()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Avrora Test CA");
        dn
    };
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    CaMaterial {
        ca_cert_pem: ca_cert.pem().into_bytes(),
        ca_key_pem: ca_key.serialize_pem(),
    }
}

fn issue_material(
    server_hostname: &str,
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
) -> TlsMaterial {
    let ca = issue_ca_only();
    let server_key = KeyPair::generate().unwrap();
    let server_cert_pem = sign_server_cert(
        &ca,
        &server_key,
        server_hostname,
        not_before,
        not_after,
    );
    TlsMaterial {
        ca_cert_pem: ca.ca_cert_pem,
        server_cert_pem,
        server_key_pem: server_key.serialize_pem().into_bytes(),
    }
}

fn sign_server_cert(
    ca: &CaMaterial,
    server_key: &KeyPair,
    server_hostname: &str,
    not_before: Option<OffsetDateTime>,
    not_after: Option<OffsetDateTime>,
) -> Vec<u8> {
    let mut names = vec!["localhost".to_string(), server_hostname.to_string()];
    if server_hostname != "127.0.0.1" {
        names.push("127.0.0.1".into());
    }
    let mut params = CertificateParams::new(names).expect("server params");
    params.distinguished_name = {
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "avrora-remote-test");
        dn
    };
    params.subject_alt_names = if server_hostname.parse::<std::net::IpAddr>().is_ok() {
        vec![SanType::IpAddress(
            server_hostname.parse().expect("ip san"),
        )]
    } else {
        vec![
            SanType::DnsName(
                server_hostname
                    .try_into()
                    .expect("dns san"),
            ),
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        ]
    };
    if let Some(nb) = not_before {
        params.not_before = nb;
    }
    if let Some(na) = not_after {
        params.not_after = na;
    }
    let issuer = Issuer::from_ca_cert_pem(
        std::str::from_utf8(&ca.ca_cert_pem).expect("ca pem"),
        KeyPair::from_pem(&ca.ca_key_pem).expect("ca key"),
    )
    .expect("issuer");
    params
        .signed_by(server_key, &issuer)
        .expect("server cert")
        .pem()
        .into_bytes()
}