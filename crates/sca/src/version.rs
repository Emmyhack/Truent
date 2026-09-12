//! Version comparison across ecosystems.
//!
//! Lockfiles pin concrete versions, so only ordering is needed — no range
//! syntax. Numeric dot-separated cores compare numerically, a pre-release
//! sorts before its release, and a `v` prefix or build metadata is ignored.

use std::cmp::Ordering;

/// A parsed version.
///
/// Equality follows ordering, so `1.2` == `1.2.0`.
#[derive(Debug, Clone)]
pub struct Version {
    core: Vec<u64>,
    pre: Option<String>,
}

impl Version {
    /// Numeric components (`1.2.3` → `[1, 2, 3]`).
    pub fn core(&self) -> &[u64] {
        &self.core
    }

    /// Parse leniently: `1.2.3`, `v1.2.3`, `1.2`, `2024.1.1`, `1.0.0-beta.1`,
    /// `0.9.34+deprecated`, `4.2`, `1.2.3.post1`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().trim_start_matches('v').trim_start_matches('=');
        let s = s.split('+').next().unwrap_or(s);
        let (core_str, pre) = match s.find('-') {
            Some(i) => (&s[..i], Some(s[i + 1..].to_string())),
            None => (s, None),
        };
        let mut core = Vec::new();
        let mut pre = pre;
        for part in core_str.split('.') {
            if part.is_empty() {
                return None;
            }
            match part.parse::<u64>() {
                Ok(n) => core.push(n),
                Err(_) => {
                    // `1.2.3rc1`: numeric prefix then a tag. `1.2.3.post1`: a
                    // whole segment that is the tag. Either way the tag ends
                    // the core; only a version with no numeric core at all is
                    // unparseable.
                    let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if digits.is_empty() {
                        if core.is_empty() {
                            return None;
                        }
                        if pre.is_none() {
                            pre = Some(part.to_string());
                        }
                        break;
                    }
                    core.push(digits.parse().ok()?);
                    if pre.is_none() {
                        pre = Some(part[digits.len()..].to_string());
                    }
                    break;
                }
            }
        }
        if core.is_empty() {
            return None;
        }
        Some(Self { core, pre })
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.core.len().max(other.core.len());
        for i in 0..n {
            let a = self.core.get(i).copied().unwrap_or(0);
            let b = other.core.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                o => return o,
            }
        }
        // `.post1` sorts after its release; any other tag sorts before.
        let rank = |p: &Option<String>| match p {
            None => 1,
            Some(t) if t.starts_with("post") => 2,
            Some(_) => 0,
        };
        match rank(&self.pre).cmp(&rank(&other.pre)) {
            Ordering::Equal => self.pre.cmp(&other.pre),
            o => o,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn ordering() {
        assert!(v("1.0.102") < v("1.0.103"));
        assert!(v("1.2") < v("1.2.1"));
        assert!(v("1.2.0") == v("1.2"));
        assert!(v("2.0.0-beta.1") < v("2.0.0"));
        assert!(v("1.2.3.post1") > v("1.2.3"));
        assert!(v("v1.10.0") > v("1.9.9"));
        assert!(v("0.9.34+deprecated") == v("0.9.34"));
        assert!(v("1.2.3rc1") < v("1.2.3"));
    }
}
