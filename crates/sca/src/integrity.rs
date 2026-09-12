//! Supply-chain integrity: dependency confusion, typosquatting, lockfile
//! integrity hashes, and install scripts.
//!
//! - **Dependency confusion** — a private package name resolvable from a
//!   public registry. pip with `--extra-index-url` searches *both* indexes
//!   and takes the higher version; an npm scope with no registry mapping in
//!   `.npmrc` resolves from npmjs.com.
//! - **Typosquat candidates** — a dependency within edit distance 1 of a
//!   popular package that is not itself that package (`reqeusts`, `lodahs`).
//!   Reported as a candidate for a human to confirm; the lists here are the
//!   most-downloaded names, not a blocklist.
//! - **Missing integrity hashes** — lockfile entries with no `integrity` /
//!   `checksum`, so a substituted tarball would install silently.
//! - **Install scripts** — packages that run code at install time
//!   (`hasInstallScript`), the vector every recent npm worm used.

use std::path::Path;
use truent_core::{Finding, Severity};

fn f(id: &str, sev: Severity, file: &str, line: usize, msg: String, snippet: String) -> Finding {
    Finding::new(id.to_string(), sev, file.to_string(), line, 0, msg, snippet)
        .with_metadata("chain".to_string(), "supply-chain".to_string())
}

/// Most-depended-on names per ecosystem. Used only as a similarity target.
const POPULAR_NPM: &[&str] = &[
    "react",
    "react-dom",
    "lodash",
    "express",
    "axios",
    "chalk",
    "commander",
    "debug",
    "moment",
    "request",
    "typescript",
    "webpack",
    "babel",
    "eslint",
    "prettier",
    "jest",
    "mocha",
    "vue",
    "next",
    "angular",
    "redux",
    "rxjs",
    "socket.io",
    "mongoose",
    "sequelize",
    "knex",
    "pg",
    "mysql",
    "redis",
    "jsonwebtoken",
    "bcrypt",
    "passport",
    "dotenv",
    "uuid",
    "yargs",
    "minimist",
    "glob",
    "fs-extra",
    "rimraf",
    "mkdirp",
    "semver",
    "colors",
    "inquirer",
    "ora",
    "cors",
    "helmet",
    "morgan",
    "body-parser",
    "cookie-parser",
    "multer",
    "nodemon",
    "ts-node",
    "tslib",
    "core-js",
    "bluebird",
    "async",
    "underscore",
    "ramda",
    "immutable",
    "classnames",
    "prop-types",
    "styled-components",
    "tailwindcss",
    "postcss",
    "autoprefixer",
    "sass",
    "less",
    "vite",
    "esbuild",
    "rollup",
    "parcel",
    "graphql",
    "apollo-server",
    "ws",
    "node-fetch",
    "got",
    "superagent",
    "cheerio",
    "puppeteer",
    "playwright",
    "cypress",
    "vitest",
    "sinon",
    "chai",
    "supertest",
    "winston",
    "pino",
    "bunyan",
    "log4js",
    "date-fns",
    "dayjs",
    "luxon",
    "validator",
    "joi",
    "yup",
    "zod",
    "ajv",
    "electron",
    "cross-env",
    "concurrently",
    "husky",
    "lint-staged",
    "crypto-js",
    "js-yaml",
    "xml2js",
    "csv-parse",
    "sharp",
    "jimp",
    "nodemailer",
    "stripe",
    "aws-sdk",
    "firebase",
    "preact",
    "mysql2",
    "react-native",
    "reactstrap",
    "ioredis",
    "vuex",
    "nuxt",
];
const POPULAR_PYPI: &[&str] = &[
    "requests",
    "urllib3",
    "numpy",
    "pandas",
    "boto3",
    "botocore",
    "setuptools",
    "pip",
    "wheel",
    "six",
    "python-dateutil",
    "pyyaml",
    "certifi",
    "idna",
    "charset-normalizer",
    "cryptography",
    "django",
    "flask",
    "fastapi",
    "sqlalchemy",
    "psycopg2",
    "pymysql",
    "redis",
    "celery",
    "pytest",
    "coverage",
    "tox",
    "black",
    "flake8",
    "pylint",
    "mypy",
    "jinja2",
    "markupsafe",
    "werkzeug",
    "click",
    "typer",
    "rich",
    "tqdm",
    "pillow",
    "matplotlib",
    "scipy",
    "scikit-learn",
    "torch",
    "tensorflow",
    "keras",
    "transformers",
    "openai",
    "httpx",
    "aiohttp",
    "starlette",
    "uvicorn",
    "gunicorn",
    "pydantic",
    "attrs",
    "cffi",
    "pycparser",
    "packaging",
    "pyparsing",
    "protobuf",
    "grpcio",
    "paramiko",
    "pyjwt",
    "bcrypt",
    "passlib",
    "itsdangerous",
    "lxml",
    "beautifulsoup4",
    "selenium",
    "scrapy",
    "colorama",
    "termcolor",
    "python-dotenv",
    "pyopenssl",
    "pynacl",
    "docker",
    "kubernetes",
    "ansible",
    "awscli",
    "google-api-python-client",
    "sentry-sdk",
];
const POPULAR_CRATES: &[&str] = &[
    "serde",
    "serde_json",
    "tokio",
    "rand",
    "syn",
    "quote",
    "proc-macro2",
    "libc",
    "log",
    "regex",
    "clap",
    "anyhow",
    "thiserror",
    "futures",
    "hyper",
    "reqwest",
    "bytes",
    "chrono",
    "lazy_static",
    "once_cell",
    "itertools",
    "cfg-if",
    "bitflags",
    "num-traits",
    "parking_lot",
    "crossbeam",
    "rayon",
    "tracing",
    "env_logger",
    "url",
    "uuid",
    "base64",
    "hex",
    "sha2",
    "ring",
    "rustls",
    "openssl",
    "mio",
    "tempfile",
    "walkdir",
    "toml",
    "indexmap",
    "hashbrown",
    "smallvec",
    "memchr",
    "aho-corasick",
    "unicode-width",
    "strsim",
    "nom",
    "pin-project",
    "async-trait",
    "axum",
    "actix-web",
    "tower",
    "tonic",
    "prost",
    "sqlx",
    "diesel",
    "rusqlite",
    "redis",
];

/// Damerau–Levenshtein distance (with adjacent transposition), capped at 2.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());
    if n.abs_diff(m) > 2 {
        return 3;
    }
    let mut d = vec![vec![0usize; m + 1]; n + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=n {
        for j in 1..=m {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[n][m]
}

/// A popular name this one is one edit away from, if any — and only when the
/// name is not itself in the popular list and is long enough that one edit
/// is meaningful.
pub fn typosquat_target(name: &str, popular: &[&'static str]) -> Option<&'static str> {
    let n = name.to_ascii_lowercase().replace('_', "-");
    if n.len() < 5 || popular.iter().any(|p| *p == n) {
        return None;
    }
    popular
        .iter()
        .filter(|p| {
            // `mysql2`, `pg8000`: a trailing digit is how rewrites and
            // major versions are named, not how squats are.
            let q = p.replace('_', "-");
            !(n.starts_with(&q) && n[q.len()..].chars().all(|c| c.is_ascii_digit()))
        })
        .find(|p| edit_distance(&n, &p.replace('_', "-")) == 1)
        .copied()
}

fn popular_for(eco: &super::Ecosystem) -> &'static [&'static str] {
    match eco {
        super::Ecosystem::Npm => POPULAR_NPM,
        super::Ecosystem::PyPI => POPULAR_PYPI,
        super::Ecosystem::CratesIo => POPULAR_CRATES,
        _ => &[],
    }
}

/// Typosquat candidates among resolved packages.
pub fn typosquats(packages: &[super::Package]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for p in packages {
        if !seen.insert((p.ecosystem.as_str(), p.name.clone())) {
            continue;
        }
        if let Some(target) = typosquat_target(&p.name, popular_for(&p.ecosystem)) {
            out.push(f(
                "sca_typosquat_candidate",
                Severity::Low,
                &p.source_file,
                1,
                format!(
                    "{} `{}` is one edit away from the popular package `{target}`: typosquatted names are how malicious packages get installed by mistake. Confirm this is the package you meant",
                    p.ecosystem.as_str(),
                    p.name
                ),
                format!("{} {} (≈ {target})", p.name, p.version),
            ));
        }
    }
    out
}

/// Lockfile-content checks: missing integrity hashes and install scripts.
pub fn lockfile_checks(path: &Path, text: &str, rel: &str) -> Vec<Finding> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut out = Vec::new();
    match name {
        "package-lock.json" | "npm-shrinkwrap.json" => {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
                return out;
            };
            let Some(pk) = v.get("packages").and_then(|p| p.as_object()) else {
                return out;
            };
            let mut no_integrity = 0usize;
            let mut total = 0usize;
            let mut scripts: Vec<String> = Vec::new();
            for (key, val) in pk {
                if key.is_empty() || val.get("link").and_then(|l| l.as_bool()) == Some(true) {
                    continue;
                }
                // Workspace / file: entries carry no tarball to hash.
                if val
                    .get("resolved")
                    .and_then(|r| r.as_str())
                    .map(|r| r.starts_with("file:"))
                    .unwrap_or(false)
                {
                    continue;
                }
                total += 1;
                if val.get("integrity").is_none() && val.get("resolved").is_some() {
                    no_integrity += 1;
                }
                if val.get("hasInstallScript").and_then(|b| b.as_bool()) == Some(true) {
                    let n = key.rsplit("node_modules/").next().unwrap_or(key);
                    scripts.push(n.to_string());
                }
            }
            if no_integrity > 0 {
                out.push(f(
                    "sca_lockfile_missing_integrity",
                    Severity::Medium,
                    rel,
                    1,
                    format!(
                        "{no_integrity} of {total} locked package(s) have a resolved URL but no `integrity` hash: a substituted tarball at that URL installs without any check. Regenerate the lockfile with a current npm (`npm install --package-lock-only`)"
                    ),
                    format!("{no_integrity} entries without integrity"),
                ));
            }
            if !scripts.is_empty() {
                scripts.sort();
                out.push(f(
                    "sca_install_script_dependency",
                    Severity::Info,
                    rel,
                    1,
                    format!(
                        "{} dependenc{} run code at install time (hasInstallScript): a compromised release executes on every developer machine and CI runner before the app runs. Review them and consider `npm ci --ignore-scripts` with an allowlist: {}",
                        scripts.len(),
                        if scripts.len() == 1 { "y" } else { "ies" },
                        scripts.join(", ")
                    ),
                    format!("{} install script(s)", scripts.len()),
                ));
            }
        }
        "Cargo.lock" => {
            // Every registry package carries a checksum; a registry entry
            // without one was edited or produced by a broken tool.
            let mut missing = Vec::new();
            for block in text.split("[[package]]").skip(1) {
                let name = block
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("name = "))
                    .map(|v| v.trim_matches('"'))
                    .unwrap_or("?");
                let registry = block.contains("source = \"registry+");
                if registry && !block.contains("checksum = ") {
                    missing.push(name.to_string());
                }
            }
            if !missing.is_empty() {
                out.push(f(
                    "sca_lockfile_missing_integrity",
                    Severity::Medium,
                    rel,
                    1,
                    format!(
                        "{} registry crate(s) have no checksum in Cargo.lock: {}",
                        missing.len(),
                        missing.join(", ")
                    ),
                    format!("{} entries without checksum", missing.len()),
                ));
            }
        }
        "yarn.lock" => {
            let entries = text.matches("\n  version ").count();
            let hashed =
                text.matches("\n  integrity ").count() + text.matches("\n  checksum: ").count();
            if entries > 0 && hashed < entries {
                out.push(f(
                    "sca_lockfile_missing_integrity",
                    Severity::Medium,
                    rel,
                    1,
                    format!(
                        "{} of {entries} yarn.lock entries have no integrity/checksum field",
                        entries - hashed
                    ),
                    format!("{} entries without integrity", entries - hashed),
                ));
            }
        }
        _ => {}
    }
    out
}

/// Dependency-confusion vectors in manifests and registry config.
pub fn confusion(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut dirs = Vec::new();
    walk(root, &mut dirs, 0);
    let rel = |p: &Path| {
        p.strip_prefix(root)
            .unwrap_or(p)
            .to_string_lossy()
            .replace('\\', "/")
    };
    for dir in dirs {
        // pip: --extra-index-url makes pip consult PyPI too and prefer the
        // higher version, whoever published it.
        for m in [
            "requirements.txt",
            "requirements-dev.txt",
            "pip.conf",
            "pip.ini",
        ] {
            let p = dir.join(m);
            let Ok(t) = std::fs::read_to_string(&p) else {
                continue;
            };
            for (i, line) in t.lines().enumerate() {
                let l = line.trim();
                if l.starts_with("--extra-index-url") || l.starts_with("extra-index-url") {
                    out.push(f(
                        "sca_dependency_confusion",
                        Severity::High,
                        &rel(&p),
                        i + 1,
                        "`--extra-index-url` makes pip search this index *and* PyPI and install whichever has the higher version: anyone who publishes your private package's name on PyPI with a big version number gets installed instead. Use `--index-url` to a proxy that serves both, and pin with hashes".to_string(),
                        l.to_string(),
                    ));
                }
            }
        }
        // npm: scoped packages with no registry mapping resolve from npmjs.com.
        let pj = dir.join("package.json");
        if let Ok(t) = std::fs::read_to_string(&pj) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) {
                let mut scopes = std::collections::BTreeSet::new();
                for sect in ["dependencies", "devDependencies", "optionalDependencies"] {
                    if let Some(m) = v.get(sect).and_then(|d| d.as_object()) {
                        for (name, spec) in m {
                            // `file:`/`link:`/`workspace:` specs are local.
                            let spec = spec.as_str().unwrap_or("");
                            if spec.starts_with("file:")
                                || spec.starts_with("link:")
                                || spec.starts_with("workspace:")
                                || spec.starts_with("git")
                            {
                                continue;
                            }
                            if let Some(scope) =
                                name.strip_prefix('@').and_then(|s| s.split('/').next())
                            {
                                scopes.insert(scope.to_string());
                            }
                        }
                    }
                }
                // A scope every locked entry of which resolves from the
                // public registry is a public scope by construction; only
                // scopes with no lockfile evidence or private-registry
                // resolutions can be confused.
                let public_resolved: std::collections::BTreeSet<String> =
                    std::fs::read_to_string(dir.join("package-lock.json"))
                        .ok()
                        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
                        .and_then(|v| v.get("packages").and_then(|p| p.as_object()).cloned())
                        .map(|pk| {
                            let mut by_scope: std::collections::BTreeMap<String, (usize, usize)> =
                                Default::default();
                            for (key, val) in pk {
                                let n = key.rsplit("node_modules/").next().unwrap_or(&key);
                                let Some(scope) =
                                    n.strip_prefix('@').and_then(|s| s.split('/').next())
                                else {
                                    continue;
                                };
                                let e = by_scope.entry(scope.to_string()).or_default();
                                e.0 += 1;
                                let resolved =
                                    val.get("resolved").and_then(|r| r.as_str()).unwrap_or("");
                                if resolved.starts_with("https://registry.npmjs.org/")
                                    || resolved.starts_with("https://registry.yarnpkg.com/")
                                {
                                    e.1 += 1;
                                }
                            }
                            by_scope
                                .into_iter()
                                .filter(|(_, (n, pubn))| n == pubn && *n > 0)
                                .map(|(s, _)| s)
                                .collect()
                        })
                        .unwrap_or_default();
                scopes.retain(|s| !public_resolved.contains(s));
                if !scopes.is_empty() {
                    let npmrc = [dir.join(".npmrc"), root.join(".npmrc")]
                        .iter()
                        .filter_map(|p| std::fs::read_to_string(p).ok())
                        .collect::<Vec<_>>()
                        .join("\n");
                    let unmapped: Vec<String> = scopes
                        .into_iter()
                        .filter(|s| !npmrc.contains(&format!("@{s}:registry")))
                        // Well-known public scopes are meant to resolve publicly.
                        .filter(|s| {
                            !matches!(
                                s.as_str(),
                                "types"
                                    | "babel"
                                    | "typescript-eslint"
                                    | "angular"
                                    | "vue"
                                    | "nestjs"
                                    | "mui"
                                    | "emotion"
                                    | "testing-library"
                                    | "storybook"
                                    | "aws-sdk"
                                    | "google-cloud"
                                    | "azure"
                                    | "opentelemetry"
                                    | "sentry"
                                    | "prisma"
                                    | "trpc"
                                    | "tanstack"
                                    | "radix-ui"
                                    | "headlessui"
                                    | "reduxjs"
                                    | "apollo"
                                    | "graphql-codegen"
                                    | "vitejs"
                                    | "rollup"
                                    | "swc"
                                    | "next"
                                    | "vercel"
                                    | "clerk"
                                    | "supabase"
                                    | "solana"
                                    | "coral-xyz"
                                    | "openzeppelin"
                                    | "nomicfoundation"
                                    | "stellar"
                                    | "ethersproject"
                                    | "chainlink"
                                    | "layerzerolabs"
                                    | "uniswap"
                                    | "aave"
                                    | "safe-global"
                                    | "web3-react"
                                    | "rainbow-me"
                                    | "wagmi"
                                    | "tailwindcss"
                                    | "eslint"
                                    | "jest"
                                    | "playwright"
                                    | "cypress"
                                    | "docusaurus"
                                    | "mdx-js"
                                    | "remix-run"
                                    | "sveltejs"
                                    | "octokit"
                                    | "actions"
                                    | "slack"
                                    | "stripe"
                                    | "sendgrid"
                                    | "twilio"
                                    | "hookform"
                                    | "dnd-kit"
                                    | "react-three"
                                    | "types-react"
                            )
                        })
                        .collect();
                    if !unmapped.is_empty() {
                        out.push(f(
                            "sca_dependency_confusion",
                            Severity::Low,
                            &rel(&pj),
                            1,
                            format!(
                                "Scoped dependencies under @{} have no registry mapping in .npmrc: if any of these scopes is private, npm resolves them from the public registry, where anyone can claim the name. Map each private scope (`@scope:registry=https://…`)",
                                unmapped.join(", @")
                            ),
                            format!("@{}", unmapped.join(", @")),
                        ));
                    }
                }
            }
        }
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>, depth: usize) {
    if depth > 6 {
        return;
    }
    out.push(dir.to_path_buf());
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let n = e.file_name();
        let n = n.to_string_lossy();
        if p.is_dir()
            && !matches!(
                n.as_ref(),
                "node_modules" | "target" | ".git" | "vendor" | "dist" | "build" | ".venv" | "venv"
            )
        {
            walk(&p, out, depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Ecosystem, Package};

    #[test]
    fn edit_distance_handles_transpositions() {
        assert_eq!(edit_distance("reqeusts", "requests"), 1);
        assert_eq!(edit_distance("lodahs", "lodash"), 1);
        assert_eq!(edit_distance("react", "react"), 0);
        assert!(edit_distance("react", "angular") > 2);
    }

    #[test]
    fn typosquat_targets() {
        assert_eq!(typosquat_target("reqeusts", POPULAR_PYPI), Some("requests"));
        assert_eq!(
            typosquat_target("requests", POPULAR_PYPI),
            None,
            "the real one"
        );
        assert_eq!(typosquat_target("lodahs", POPULAR_NPM), Some("lodash"));
        assert_eq!(
            typosquat_target("serde_jsom", POPULAR_CRATES),
            Some("serde_json")
        );
        assert_eq!(
            typosquat_target("pg", POPULAR_NPM),
            None,
            "too short to judge"
        );
        assert_eq!(typosquat_target("express-session", POPULAR_NPM), None);
        assert_eq!(
            typosquat_target("mysql2", POPULAR_NPM),
            None,
            "versioned sibling"
        );
        assert_eq!(
            typosquat_target("preact", POPULAR_NPM),
            None,
            "a real package in the list"
        );
    }

    #[test]
    fn typosquat_findings_dedup_per_package() {
        let p = |n: &str| Package {
            ecosystem: Ecosystem::PyPI,
            name: n.into(),
            version: "1.0".into(),
            source_file: "requirements.txt".into(),
        };
        let f = typosquats(&[p("reqeusts"), p("reqeusts"), p("numpy")]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].invariant_id, "sca_typosquat_candidate");
    }

    #[test]
    fn npm_lock_integrity_and_install_scripts() {
        let lock = r#"{"lockfileVersion":3,"packages":{"":{"name":"a"},
          "node_modules/x":{"version":"1.0.0","resolved":"https://r/x.tgz","integrity":"sha512-AAA"},
          "node_modules/y":{"version":"1.0.0","resolved":"https://r/y.tgz"},
          "node_modules/z":{"version":"1.0.0","resolved":"https://r/z.tgz","integrity":"sha512-BBB","hasInstallScript":true},
          "node_modules/local":{"version":"1.0.0","resolved":"file:../local"}}}"#;
        let f = lockfile_checks(Path::new("package-lock.json"), lock, "package-lock.json");
        let ids: Vec<&str> = f.iter().map(|f| f.invariant_id.as_str()).collect();
        assert!(ids.contains(&"sca_lockfile_missing_integrity"));
        assert!(ids.contains(&"sca_install_script_dependency"));
        assert!(f.iter().any(|f| f.message.contains("1 of 3")));
        assert!(f.iter().any(|f| f.message.ends_with(": z")));
    }

    #[test]
    fn cargo_lock_checksums() {
        let ok = "[[package]]\nname = \"a\"\nversion = \"1\"\nsource = \"registry+https://x\"\nchecksum = \"abc\"\n\n[[package]]\nname = \"local\"\nversion = \"1\"\n";
        assert!(lockfile_checks(Path::new("Cargo.lock"), ok, "Cargo.lock").is_empty());
        let bad = "[[package]]\nname = \"a\"\nversion = \"1\"\nsource = \"registry+https://x\"\n";
        assert_eq!(
            lockfile_checks(Path::new("Cargo.lock"), bad, "Cargo.lock").len(),
            1
        );
    }

    #[test]
    fn confusion_vectors() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("requirements.txt"),
            "--extra-index-url https://pypi.corp/simple\nrequests==2.0\n",
        )
        .unwrap();
        std::fs::write(
            d.path().join("package.json"),
            r#"{"dependencies":{"@acme/auth":"1.0.0","@types/node":"20","@local/x":"file:../x"}}"#,
        )
        .unwrap();
        let f = confusion(d.path());
        assert_eq!(f.len(), 2, "{f:?}");
        assert!(f
            .iter()
            .any(|f| f.severity == Severity::High && f.file == "requirements.txt"));
        assert!(f
            .iter()
            .any(|f| f.file == "package.json" && f.snippet == "@acme"));
        std::fs::write(
            d.path().join(".npmrc"),
            "@acme:registry=https://npm.corp/\n",
        )
        .unwrap();
        assert_eq!(confusion(d.path()).len(), 1, "mapped scope is fine");
    }
}
