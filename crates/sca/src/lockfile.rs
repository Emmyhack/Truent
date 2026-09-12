//! Lockfile discovery and parsing.

use lazy_static::lazy_static;
use regex::Regex;
use std::path::{Path, PathBuf};

/// A package ecosystem, named as OSV names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ecosystem {
    CratesIo,
    Npm,
    PyPI,
    Go,
}

impl Ecosystem {
    /// OSV ecosystem string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CratesIo => "crates.io",
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
            Self::Go => "Go",
        }
    }

    /// Package URL type.
    pub fn purl_type(&self) -> &'static str {
        match self {
            Self::CratesIo => "cargo",
            Self::Npm => "npm",
            Self::PyPI => "pypi",
            Self::Go => "golang",
        }
    }

    /// Parse an OSV ecosystem string.
    pub fn from_osv(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "crates.io" => Some(Self::CratesIo),
            "npm" => Some(Self::Npm),
            "pypi" => Some(Self::PyPI),
            "go" => Some(Self::Go),
            _ => None,
        }
    }
}

/// A pinned dependency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// Lockfile it came from, relative to the scan root.
    pub source_file: String,
}

impl Package {
    /// `pkg:cargo/serde@1.0.0`
    pub fn purl(&self) -> String {
        format!(
            "pkg:{}/{}@{}",
            self.ecosystem.purl_type(),
            self.name,
            self.version
        )
    }
}

/// Lockfile names this crate understands.
pub const LOCKFILE_NAMES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "go.sum",
];

/// Find lockfiles under `root`, skipping dependency and build trees.
pub fn discover_lockfiles(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(root, &mut out, 0);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 12 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir() {
            if matches!(
                name,
                "node_modules"
                    | "target"
                    | ".git"
                    | "vendor"
                    | ".venv"
                    | "venv"
                    | "dist"
                    | "build"
                    | ".next"
                    | "__pycache__"
            ) {
                continue;
            }
            walk(&p, out, depth + 1);
        } else if LOCKFILE_NAMES.contains(&name)
            || name.starts_with("requirements") && name.ends_with(".txt")
        {
            out.push(p);
        }
    }
}

lazy_static! {
    static ref CARGO_PKG: Regex =
        Regex::new(r#"(?m)^\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)""#).unwrap();
    static ref REQ_LINE: Regex =
        Regex::new(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.+!\-]+)").unwrap();
    static ref POETRY_PKG: Regex =
        Regex::new(r#"(?m)^\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)""#).unwrap();
    static ref GO_SUM: Regex = Regex::new(r"(?m)^(\S+)\s+v([^\s/]+)(/go\.mod)?\s+h1:").unwrap();
    static ref YARN_ENTRY: Regex = Regex::new(
        r#"(?m)^"?(@?[^@"\n]+)@[^\n]*:\n(?:\s+[^\n]*\n)*?\s+version(?:\s|:)+"?([^"\n]+)"?"#
    )
    .unwrap();
}

/// Parse a lockfile by name into packages.
pub fn parse_lockfile(path: &Path, text: &str) -> Vec<Package> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let src = path.to_string_lossy().replace('\\', "/");
    let mut out = Vec::new();

    match name {
        "Cargo.lock" => {
            for c in CARGO_PKG.captures_iter(text) {
                out.push(pkg(Ecosystem::CratesIo, &c[1], &c[2], &src));
            }
        }
        "package-lock.json" | "npm-shrinkwrap.json" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                // v2/v3: "packages": { "node_modules/x": { "version": … } }
                if let Some(pk) = v.get("packages").and_then(|p| p.as_object()) {
                    for (key, val) in pk {
                        if key.is_empty() {
                            continue;
                        }
                        let n = key.rsplit("node_modules/").next().unwrap_or(key);
                        if let Some(ver) = val.get("version").and_then(|x| x.as_str()) {
                            out.push(pkg(Ecosystem::Npm, n, ver, &src));
                        }
                    }
                }
                // v1: "dependencies": { "x": { "version": …, "dependencies": {…} } }
                if out.is_empty() {
                    fn v1(map: &serde_json::Value, src: &str, out: &mut Vec<Package>) {
                        if let Some(m) = map.as_object() {
                            for (n, val) in m {
                                if let Some(ver) = val.get("version").and_then(|x| x.as_str()) {
                                    out.push(pkg(Ecosystem::Npm, n, ver, src));
                                }
                                if let Some(d) = val.get("dependencies") {
                                    v1(d, src, out);
                                }
                            }
                        }
                    }
                    if let Some(d) = v.get("dependencies") {
                        v1(d, &src, &mut out);
                    }
                }
            }
        }
        "yarn.lock" => {
            for c in YARN_ENTRY.captures_iter(text) {
                out.push(pkg(
                    Ecosystem::Npm,
                    c[1].trim().trim_matches('"'),
                    c[2].trim(),
                    &src,
                ));
            }
        }
        "poetry.lock" => {
            for c in POETRY_PKG.captures_iter(text) {
                out.push(pkg(Ecosystem::PyPI, &c[1], &c[2], &src));
            }
        }
        "Pipfile.lock" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                for section in ["default", "develop"] {
                    if let Some(m) = v.get(section).and_then(|s| s.as_object()) {
                        for (n, val) in m {
                            if let Some(ver) = val.get("version").and_then(|x| x.as_str()) {
                                out.push(pkg(
                                    Ecosystem::PyPI,
                                    n,
                                    ver.trim_start_matches("=="),
                                    &src,
                                ));
                            }
                        }
                    }
                }
            }
        }
        "go.sum" => {
            for c in GO_SUM.captures_iter(text) {
                if c.get(3).is_some() {
                    continue;
                } // the /go.mod line duplicates the module line
                out.push(pkg(Ecosystem::Go, &c[1], &c[2], &src));
            }
        }
        n if n.starts_with("requirements") && n.ends_with(".txt") => {
            for line in text.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if let Some(c) = REQ_LINE.captures(line) {
                    let name = c[1].split('[').next().unwrap_or(&c[1]);
                    out.push(pkg(Ecosystem::PyPI, name, &c[2], &src));
                }
            }
        }
        _ => {}
    }
    out
}

fn pkg(eco: Ecosystem, name: &str, version: &str, src: &str) -> Package {
    // PyPI names are case-insensitive and treat `_`/`-`/`.` alike.
    let name = if eco == Ecosystem::PyPI {
        name.to_lowercase().replace(['_', '.'], "-")
    } else {
        name.to_string()
    };
    Package {
        ecosystem: eco,
        name,
        version: version.trim().to_string(),
        source_file: src.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock() {
        let t = "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.228\"\nsource = \"registry\"\n\n[[package]]\nname = \"anyhow\"\nversion = \"1.0.104\"\n";
        let p = parse_lockfile(Path::new("Cargo.lock"), t);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].purl(), "pkg:cargo/serde@1.0.228");
    }

    #[test]
    fn package_lock_v3_and_v1() {
        let v3 = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.20"},"node_modules/a/node_modules/b":{"version":"1.0.0"}}}"#;
        let p = parse_lockfile(Path::new("package-lock.json"), v3);
        assert_eq!(p.len(), 2);
        assert!(p
            .iter()
            .any(|x| x.name == "lodash" && x.version == "4.17.20"));
        assert!(p.iter().any(|x| x.name == "b"));
        let v1 = r#"{"lockfileVersion":1,"dependencies":{"lodash":{"version":"4.17.20","dependencies":{"x":{"version":"2.0.0"}}}}}"#;
        assert_eq!(parse_lockfile(Path::new("package-lock.json"), v1).len(), 2);
    }

    #[test]
    fn requirements_poetry_pipfile_go_yarn() {
        let r = "Django==4.2.1  # web\nrequests>=2.0\n-e .\nPyYAML == 6.0.1\n";
        let p = parse_lockfile(Path::new("requirements.txt"), r);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "django");
        assert_eq!(p[1].name, "pyyaml");

        let po = "[[package]]\nname = \"Jinja2\"\nversion = \"3.1.2\"\n";
        assert_eq!(
            parse_lockfile(Path::new("poetry.lock"), po)[0].name,
            "jinja2"
        );

        let pf = r#"{"default":{"flask":{"version":"==2.3.0"}},"develop":{}}"#;
        assert_eq!(
            parse_lockfile(Path::new("Pipfile.lock"), pf)[0].version,
            "2.3.0"
        );

        let g = "golang.org/x/crypto v0.17.0 h1:abc=\ngolang.org/x/crypto v0.17.0/go.mod h1:def=\n";
        let p = parse_lockfile(Path::new("go.sum"), g);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].version, "0.17.0");

        let y = "\"@babel/core@^7.0.0\":\n  version \"7.23.0\"\n  resolved \"x\"\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n";
        let p = parse_lockfile(Path::new("yarn.lock"), y);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].name, "@babel/core");
    }
}
