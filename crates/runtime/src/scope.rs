//! Scope allow-list for the probe.
//!
//! `--authorized` records that the operator *asserts* permission. A scope
//! file goes one step further and makes it a deterministic gate: the probe
//! refuses any target not explicitly listed, matched by IP, CIDR or domain,
//! in code rather than by convention. Loopback is always allowed so local
//! testing needs no entry.
//!
//! The format is one entry per line, `#` begins a comment:
//!
//! ```text
//! example.com            # the domain and every subdomain
//! 10.0.0.0/24            # a CIDR block
//! 203.0.113.7            # a single host
//! 2001:db8::/32          # an IPv6 block
//! ```

use std::net::IpAddr;

#[derive(Debug, Clone)]
enum Entry {
    /// IPv4 network and mask, as `u32`.
    V4(u32, u32),
    /// IPv6 network and mask, as `u128`.
    V6(u128, u128),
    /// A domain; matches itself and any subdomain.
    Domain(String),
}

/// A parsed allow-list. An empty scope constrains nothing (see [`Scope::is_empty`]);
/// the caller decides whether to enforce it.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    entries: Vec<Entry>,
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)
    }
}

fn parse_entry(line: &str) -> Option<Entry> {
    let (addr_part, prefix_part) = match line.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (line, None),
    };
    // IP or CIDR?
    if let Ok(ip) = addr_part.parse::<IpAddr>() {
        return Some(match ip {
            IpAddr::V4(v4) => {
                let prefix = match prefix_part {
                    None => 32,
                    Some(p) => p.parse::<u8>().ok()?,
                };
                if prefix > 32 {
                    return None;
                }
                let mask = v4_mask(prefix);
                Entry::V4(u32::from(v4) & mask, mask)
            }
            IpAddr::V6(v6) => {
                let prefix = match prefix_part {
                    None => 128,
                    Some(p) => p.parse::<u8>().ok()?,
                };
                if prefix > 128 {
                    return None;
                }
                let mask = v6_mask(prefix);
                Entry::V6(u128::from(v6) & mask, mask)
            }
        });
    }
    // A CIDR suffix on something that is not an IP is malformed; a bare token
    // is a domain.
    if prefix_part.is_some() {
        return None;
    }
    Some(Entry::Domain(
        addr_part.trim_end_matches('.').to_ascii_lowercase(),
    ))
}

impl Scope {
    /// Parse a scope file's contents. Malformed lines are skipped.
    pub fn parse(text: &str) -> Self {
        let entries = text
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| !l.is_empty())
            .filter_map(parse_entry)
            .collect();
        Self { entries }
    }

    /// No entries: the scope constrains nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Number of parsed entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether `host` (an IP string or a hostname) is in scope. Loopback is
    /// always in scope. An empty scope allows nothing — callers that mean
    /// "no constraint" should check [`is_empty`](Self::is_empty) first.
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host == "localhost" {
            return true;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            if ip.is_loopback() || ip.is_unspecified() {
                return true;
            }
            return self.entries.iter().any(|e| match (e, ip) {
                (Entry::V4(net, mask), IpAddr::V4(v4)) => u32::from(v4) & mask == *net,
                (Entry::V6(net, mask), IpAddr::V6(v6)) => u128::from(v6) & mask == *net,
                _ => false,
            });
        }
        self.entries.iter().any(|e| match e {
            Entry::Domain(d) => host == *d || host.ends_with(&format!(".{d}")),
            _ => false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_is_always_in_scope() {
        let scope = Scope::parse("example.com");
        assert!(scope.allows("127.0.0.1"));
        assert!(scope.allows("localhost"));
        assert!(scope.allows("::1"));
    }

    #[test]
    fn domain_matches_itself_and_subdomains_only() {
        let scope = Scope::parse("example.com\n");
        assert!(scope.allows("example.com"));
        assert!(scope.allows("api.example.com"));
        assert!(scope.allows("API.Example.com"));
        assert!(!scope.allows("notexample.com"));
        assert!(!scope.allows("example.com.evil.test"));
        assert!(!scope.allows("other.test"));
    }

    #[test]
    fn cidr_and_single_host() {
        let scope = Scope::parse("10.0.0.0/24\n203.0.113.7\n");
        assert!(scope.allows("10.0.0.1"));
        assert!(scope.allows("10.0.0.255"));
        assert!(!scope.allows("10.0.1.1"));
        assert!(scope.allows("203.0.113.7"));
        assert!(!scope.allows("203.0.113.8"));
    }

    #[test]
    fn ipv6_cidr() {
        let scope = Scope::parse("2001:db8::/32\n");
        assert!(scope.allows("2001:db8::1"));
        assert!(scope.allows("2001:db8:dead:beef::1"));
        assert!(!scope.allows("2001:db9::1"));
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let scope = Scope::parse("# hosts\n\n  example.com  # prod\n");
        assert_eq!(scope.len(), 1);
        assert!(scope.allows("example.com"));
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let scope = Scope::parse("not a host/24\n10.0.0.0/999\nexample.com\n");
        assert_eq!(scope.len(), 1);
        assert!(scope.allows("example.com"));
    }

    #[test]
    fn empty_scope_allows_only_loopback() {
        let scope = Scope::parse("# nothing\n");
        assert!(scope.is_empty());
        assert!(scope.allows("127.0.0.1"));
        assert!(!scope.allows("example.com"));
    }
}
