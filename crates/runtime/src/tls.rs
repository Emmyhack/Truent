//! TLS observations: certificate trust, expiry, self-signature, hostname
//! match, and whether the server can negotiate a modern protocol at all.
//!
//! [`analyze`] and [`analyze_failure`] are pure and tested offline;
//! [`observe`] performs the handshakes.
//!
//! Two handshakes may be made. The first verifies the chain against the
//! Mozilla root store (via `webpki-roots`). If — and only if — that fails on
//! the *certificate*, a second handshake with verification disabled retrieves
//! the certificate so the report can say *why* (expired, self-signed, wrong
//! name). No application data is ever sent on the unverified connection.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use serde::Serialize;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use truent_core::{Finding, Severity};
use x509_parser::prelude::*;

use crate::finding;

/// What the handshake and the leaf certificate showed.
#[derive(Debug, Clone, Serialize)]
pub struct TlsObservation {
    pub host: String,
    pub port: u16,
    /// e.g. `TLSv1_3`.
    pub protocol: String,
    pub cipher: String,
    /// Validated against the Mozilla root store, name included.
    pub chain_verified: bool,
    pub verify_error: Option<String>,
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    /// Unix seconds.
    pub not_before: i64,
    pub not_after: i64,
    pub self_signed: bool,
    pub hostname_matches: bool,
}

/// Why a handshake could not complete.
#[derive(Debug, Clone, Serialize)]
pub enum TlsFailure {
    /// The server offers no protocol or cipher this probe will speak: nothing
    /// at or above TLS 1.2 with a modern suite. That is itself a finding.
    Incompatible(String),
    /// Connection refused, timeout, DNS — no conclusion about TLS.
    Other(String),
}

impl std::fmt::Display for TlsFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsFailure::Incompatible(s) => write!(f, "no modern protocol negotiable: {s}"),
            TlsFailure::Other(s) => write!(f, "{s}"),
        }
    }
}

const DAY: i64 = 86_400;

/// Evaluate a completed handshake at time `now` (Unix seconds).
pub fn analyze(obs: &TlsObservation, location: &str, now: i64) -> Vec<Finding> {
    let mut out = Vec::new();

    if now > obs.not_after {
        out.push(finding(
            "rt_tls_expired",
            Severity::High,
            location,
            format!(
                "Certificate expired {} day(s) ago: every client that validates will refuse the \
                 connection, and users who click through are training themselves to accept an \
                 attacker's certificate too",
                (now - obs.not_after) / DAY
            ),
            format!("notAfter={} subject={}", iso(obs.not_after), obs.subject),
        ));
    } else if obs.not_after - now < 14 * DAY {
        out.push(finding(
            "rt_tls_expired",
            Severity::Medium,
            location,
            format!(
                "Certificate expires in {} day(s); renew before clients start refusing it",
                (obs.not_after - now) / DAY
            ),
            format!("notAfter={} subject={}", iso(obs.not_after), obs.subject),
        ));
    }

    if !obs.chain_verified && now <= obs.not_after {
        let (why, evidence) = if obs.self_signed {
            (
                "Certificate is self-signed: clients cannot distinguish this server from an \
                 on-path attacker presenting their own self-signed certificate",
                format!("issuer == subject: {}", obs.subject),
            )
        } else if !obs.hostname_matches {
            (
                "Certificate is not issued for this hostname: a valid certificate for the wrong \
                 name is what an attacker who has any certificate would present",
                format!("host={} sans={:?}", obs.host, obs.sans),
            )
        } else {
            (
                "Certificate chain does not validate against the Mozilla root store: an \
                 untrusted or incomplete chain gives clients no basis to trust the server",
                format!(
                    "issuer={} error={}",
                    obs.issuer,
                    obs.verify_error.as_deref().unwrap_or("unknown")
                ),
            )
        };
        out.push(finding(
            "rt_tls_untrusted_cert",
            Severity::High,
            location,
            why.to_string(),
            evidence,
        ));
    }

    out
}

/// A failed handshake is a finding when the cause is the server's protocol
/// support, and only an error otherwise.
pub fn analyze_failure(failure: &TlsFailure, location: &str) -> Vec<Finding> {
    match failure {
        TlsFailure::Incompatible(detail) => vec![finding(
            "rt_tls_weak_protocol",
            Severity::High,
            location,
            "Server negotiates neither TLS 1.3 nor TLS 1.2 with a modern cipher suite: only \
             deprecated protocols with known attacks (BEAST, POODLE, RC4) remain"
                .into(),
            format!("handshake with TLS 1.2/1.3 + AEAD suites failed: {detail}"),
        )],
        TlsFailure::Other(_) => Vec::new(),
    }
}

fn iso(unix: i64) -> String {
    // Enough for a report line without pulling a date crate.
    let days = unix.div_euclid(DAY);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Howard Hinnant's algorithm: days since 1970-01-01 → (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Wildcard-aware hostname match against SANs (or the CN when there are none).
pub fn hostname_matches(host: &str, sans: &[String], subject: &str) -> bool {
    let host = host.to_ascii_lowercase();
    let names: Vec<String> = if sans.is_empty() {
        subject
            .split(',')
            .filter_map(|p| p.trim().strip_prefix("CN="))
            .map(|s| s.to_ascii_lowercase())
            .collect()
    } else {
        sans.iter().map(|s| s.to_ascii_lowercase()).collect()
    };
    names.iter().any(|n| {
        if n == &host {
            return true;
        }
        if let Some(suffix) = n.strip_prefix("*.") {
            if let Some((_, rest)) = host.split_once('.') {
                return rest == suffix;
            }
        }
        false
    })
}

// ---------------- network ---------------------------------------------------

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn verified_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("ring supports TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Accepts any certificate. Used only to *read* a certificate the verified
/// handshake rejected, and by the HTTP layer to read headers from a host
/// whose untrusted certificate has already been reported. Signatures are
/// still checked, so the peer at least holds the key for the certificate it
/// presents.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A client config that accepts any certificate. See [`NoVerify`].
pub fn permissive_config() -> Arc<ClientConfig> {
    let p = provider();
    Arc::new(
        ClientConfig::builder_with_provider(p.clone())
            .with_safe_default_protocol_versions()
            .expect("ring supports TLS 1.2 and 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(p)))
            .with_no_client_auth(),
    )
}

struct Handshake {
    protocol: String,
    cipher: String,
    leaf: Option<Vec<u8>>,
}

/// Run a handshake to completion and close. No application data.
fn handshake(
    cfg: Arc<ClientConfig>,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Handshake, rustls::Error> {
    let name = ServerName::try_from(host.to_string())
        .map_err(|e| rustls::Error::General(format!("invalid server name: {e}")))?;
    // A name may resolve to several addresses (`localhost` → `::1`, then
    // `127.0.0.1`); the service may listen on only one. Try each.
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| rustls::Error::General(format!("resolve: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(rustls::Error::General("resolve: no address".into()));
    }
    let mut tcp = None;
    let mut last = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(t) => {
                tcp = Some(t);
                break;
            }
            Err(e) => last = e.to_string(),
        }
    }
    let mut tcp = tcp.ok_or_else(|| rustls::Error::General(format!("connect: {last}")))?;
    let _ = tcp.set_read_timeout(Some(timeout));
    let _ = tcp.set_write_timeout(Some(timeout));
    let mut conn = ClientConnection::new(cfg, name)?;
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut tcp) {
            // rustls errors surface wrapped in io::Error; unwrap to classify.
            if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
                return Err(inner.clone());
            }
            return Err(rustls::Error::General(format!("io: {e}")));
        }
    }
    let out = Handshake {
        protocol: conn
            .protocol_version()
            .map(|v| format!("{v:?}"))
            .unwrap_or_default(),
        cipher: conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()))
            .unwrap_or_default(),
        leaf: conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| c.as_ref().to_vec()),
    };
    conn.send_close_notify();
    let _ = conn.complete_io(&mut tcp);
    Ok(out)
}

fn is_incompatible(e: &rustls::Error) -> bool {
    use rustls::AlertDescription as A;
    matches!(
        e,
        rustls::Error::PeerIncompatible(_)
            | rustls::Error::AlertReceived(A::ProtocolVersion)
            | rustls::Error::AlertReceived(A::HandshakeFailure)
            | rustls::Error::AlertReceived(A::InsufficientSecurity)
    )
}

/// Observe the TLS endpoint at `host:port`.
pub fn observe(host: &str, port: u16, timeout: Duration) -> Result<TlsObservation, TlsFailure> {
    let (hs, verified, verify_error) = match handshake(verified_config(), host, port, timeout) {
        Ok(hs) => (hs, true, None),
        Err(e) if is_incompatible(&e) => return Err(TlsFailure::Incompatible(e.to_string())),
        Err(rustls::Error::InvalidCertificate(cert_err)) => {
            // Read the certificate the verified path rejected.
            match handshake(permissive_config(), host, port, timeout) {
                Ok(hs) => (hs, false, Some(format!("{cert_err:?}"))),
                Err(e) if is_incompatible(&e) => {
                    return Err(TlsFailure::Incompatible(e.to_string()))
                }
                Err(e) => return Err(TlsFailure::Other(e.to_string())),
            }
        }
        Err(e) => return Err(TlsFailure::Other(e.to_string())),
    };

    let leaf = hs
        .leaf
        .ok_or_else(|| TlsFailure::Other("server presented no certificate".into()))?;
    let (_, cert) = X509Certificate::from_der(&leaf)
        .map_err(|e| TlsFailure::Other(format!("certificate parse: {e}")))?;
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let sans: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(d) => Some(d.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let matches = verified || hostname_matches(host, &sans, &subject);
    Ok(TlsObservation {
        host: host.to_string(),
        port,
        protocol: hs.protocol,
        cipher: hs.cipher,
        chain_verified: verified,
        verify_error,
        self_signed: subject == issuer,
        hostname_matches: matches,
        subject,
        issuer,
        sans,
        not_before: cert.validity().not_before.timestamp(),
        not_after: cert.validity().not_after.timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(not_after: i64, verified: bool, self_signed: bool, host_ok: bool) -> TlsObservation {
        TlsObservation {
            host: "example.com".into(),
            port: 443,
            protocol: "TLSv1_3".into(),
            cipher: "TLS13_AES_256_GCM_SHA384".into(),
            chain_verified: verified,
            verify_error: (!verified).then(|| "UnknownIssuer".into()),
            subject: "CN=example.com".into(),
            issuer: if self_signed {
                "CN=example.com".into()
            } else {
                "CN=Some CA".into()
            },
            sans: vec![if host_ok { "example.com" } else { "other.com" }.into()],
            not_before: 0,
            not_after,
            self_signed,
            hostname_matches: host_ok,
        }
    }
    fn ids(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.invariant_id.as_str()).collect()
    }
    const NOW: i64 = 1_700_000_000;

    #[test]
    fn valid_certificate_is_clean() {
        assert!(analyze(&obs(NOW + 90 * DAY, true, false, true), "x", NOW).is_empty());
    }

    #[test]
    fn expired_is_high_and_expiring_soon_is_medium() {
        let f = analyze(&obs(NOW - 3 * DAY, true, false, true), "x", NOW);
        assert_eq!(ids(&f), vec!["rt_tls_expired"]);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].message.contains("3 day(s) ago"));
        let f = analyze(&obs(NOW + 5 * DAY, true, false, true), "x", NOW);
        assert_eq!(f[0].severity, Severity::Medium);
        assert!(f[0].message.contains("expires in 5 day(s)"));
    }

    #[test]
    fn untrusted_reasons_are_distinguished() {
        let f = analyze(&obs(NOW + 90 * DAY, false, true, true), "x", NOW);
        assert_eq!(ids(&f), vec!["rt_tls_untrusted_cert"]);
        assert!(f[0].message.contains("self-signed"));
        let f = analyze(&obs(NOW + 90 * DAY, false, false, false), "x", NOW);
        assert!(f[0].message.contains("not issued for this hostname"));
        let f = analyze(&obs(NOW + 90 * DAY, false, false, true), "x", NOW);
        assert!(f[0].message.contains("does not validate"));
    }

    #[test]
    fn expired_and_untrusted_reports_expiry_not_both() {
        // An expired self-signed cert: expiry is the actionable fact; piling
        // an "untrusted" finding on top double-counts one certificate.
        let f = analyze(&obs(NOW - DAY, false, true, true), "x", NOW);
        assert_eq!(ids(&f), vec!["rt_tls_expired"]);
    }

    #[test]
    fn incompatible_handshake_is_a_weak_protocol_finding() {
        let f = analyze_failure(&TlsFailure::Incompatible("peer incompatible".into()), "x");
        assert_eq!(ids(&f), vec!["rt_tls_weak_protocol"]);
        assert!(analyze_failure(&TlsFailure::Other("timeout".into()), "x").is_empty());
    }

    #[test]
    fn hostname_matching_handles_wildcards_and_cn_fallback() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert!(hostname_matches(
            "a.example.com",
            &s(&["*.example.com"]),
            ""
        ));
        assert!(!hostname_matches(
            "a.b.example.com",
            &s(&["*.example.com"]),
            ""
        ));
        assert!(!hostname_matches("example.com", &s(&["*.example.com"]), ""));
        assert!(hostname_matches("Example.COM", &s(&["example.com"]), ""));
        assert!(hostname_matches("x.org", &[], "O=Acme, CN=x.org"));
        assert!(
            !hostname_matches("x.org", &s(&["y.org"]), "CN=x.org"),
            "SANs override CN"
        );
    }

    #[test]
    fn dates_render() {
        assert_eq!(iso(0), "1970-01-01");
        assert_eq!(iso(1_700_000_000), "2023-11-14");
    }

    #[test]
    fn configs_build() {
        // The rustls builders panic on an impossible provider/version combo;
        // constructing both here keeps that out of the live path.
        let _ = verified_config();
        let _ = permissive_config();
    }
}
