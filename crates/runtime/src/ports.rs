//! TCP connect check of a small port set.
//!
//! A connect is the least intrusive probe there is — it is what any client
//! does to talk to the service. Nothing is sent after the connection opens.

use serde::Serialize;
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use truent_core::{Finding, Severity};

use crate::finding;

/// Ports checked by default: the web ports a target is expected to have,
/// plus the services that are most often exposed by accident.
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 80, 110, 143, 443, 445, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200,
    11211, 27017,
];

/// One port.
#[derive(Debug, Clone, Serialize)]
pub struct PortObservation {
    pub port: u16,
    pub open: bool,
    pub service: &'static str,
}

/// Conventional service name for a port.
pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "smb",
        2375 => "docker-api",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        9200 => "elasticsearch",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "unknown",
    }
}

/// Severity of finding a service reachable from wherever the probe runs.
///
/// `None` means the port is expected and produces no finding. The high tier
/// is services that ship with no authentication by default: reachable is
/// usually owned.
fn exposure(port: u16, target_port: u16) -> Option<Severity> {
    if port == target_port {
        return None;
    }
    Some(match port {
        80 | 443 | 8080 | 8443 => return None,
        23 | 2375 | 6379 | 9200 | 11211 | 27017 => Severity::High,
        21 | 445 | 3306 | 3389 | 5432 | 5900 => Severity::Medium,
        _ => Severity::Low,
    })
}

/// Evaluate a port sweep against `host`; `target_port` is the one the probe
/// was pointed at and is never reported.
pub fn analyze(obs: &[PortObservation], host: &str, target_port: u16) -> Vec<Finding> {
    obs.iter()
        .filter(|p| p.open)
        .filter_map(|p| {
            let sev = exposure(p.port, target_port)?;
            Some(finding(
                "rt_open_port",
                sev,
                &format!("{host}:{}", p.port),
                format!(
                    "{} ({}) accepts connections from the probe's network position — {}",
                    p.service,
                    p.port,
                    match sev {
                        Severity::High => "this service has no authentication by default; if this is the internet, treat it as compromised",
                        Severity::Medium => "administrative or database access should not be reachable from here; restrict to a management network or VPN",
                        _ => "confirm it is intended to be reachable and is patched",
                    }
                ),
                format!("tcp/{} open ({})", p.port, p.service),
            ))
        })
        .collect()
}

/// Connect to each port in turn. DNS is resolved once.
pub fn observe(host: &str, ports: &[u16], timeout: Duration) -> Vec<PortObservation> {
    // Per-port budget is short: a filtered port only ever times out.
    let per_port = timeout.min(Duration::from_secs(2));
    // Every address the name resolves to: a service bound to 127.0.0.1 is
    // invisible on `::1`.
    let ips: Vec<IpAddr> = (host, 0u16)
        .to_socket_addrs()
        .map(|a| a.map(|a| a.ip()).collect())
        .unwrap_or_default();
    ports
        .iter()
        .map(|&port| {
            let open = ips
                .iter()
                .any(|ip| TcpStream::connect_timeout(&(*ip, port).into(), per_port).is_ok());
            PortObservation {
                port,
                open,
                service: service_name(port),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(port: u16) -> PortObservation {
        PortObservation {
            port,
            open: true,
            service: service_name(port),
        }
    }

    #[test]
    fn expected_web_ports_are_not_findings() {
        let obs = vec![open(80), open(443), open(8443)];
        assert!(analyze(&obs, "h", 443).is_empty());
    }

    #[test]
    fn unauthenticated_services_are_high() {
        let f = analyze(&[open(6379), open(27017), open(22)], "h", 443);
        assert_eq!(f.len(), 3);
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::High && f.file == "h:6379"));
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::Low && f.file == "h:22"));
        assert!(f
            .iter()
            .all(|f| f.invariant_id == "rt_open_port" && f.is_proven()));
    }

    #[test]
    fn closed_ports_are_silent() {
        let closed = PortObservation {
            port: 6379,
            open: false,
            service: "redis",
        };
        assert!(analyze(&[closed], "h", 443).is_empty());
    }

    #[test]
    fn the_target_port_itself_is_never_reported() {
        assert!(analyze(&[open(3306)], "h", 3306).is_empty());
    }

    #[test]
    fn unresolvable_host_reports_every_port_closed() {
        let obs = observe(
            "nonexistent.invalid",
            &[80, 443],
            Duration::from_millis(200),
        );
        assert_eq!(obs.len(), 2);
        assert!(obs.iter().all(|p| !p.open));
    }
}
