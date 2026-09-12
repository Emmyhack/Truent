//! Pinning and lockfile presence.
//!
//! An unpinned requirement resolves to whatever is newest at install time — a
//! different build every day and a direct route for a malicious release. A
//! manifest with no lockfile is the same problem for the whole tree.

use std::path::Path;
use truent_core::{Finding, Severity};

/// Manifest → the lockfiles that would pin it.
const MANIFESTS: &[(&str, &[&str])] = &[
    (
        "package.json",
        &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lockb",
            "bun.lock",
        ],
    ),
    (
        "pyproject.toml",
        &[
            "poetry.lock",
            "pdm.lock",
            "uv.lock",
            "requirements.txt",
            "Pipfile.lock",
        ],
    ),
    ("Pipfile", &["Pipfile.lock"]),
    ("go.mod", &["go.sum"]),
];

pub fn detect(root: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut dirs = Vec::new();
    walk(root, &mut dirs, 0);

    for dir in dirs {
        let rel = |p: &Path| {
            p.strip_prefix(root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/")
        };

        for (manifest, locks) in MANIFESTS {
            let m = dir.join(manifest);
            if !m.is_file() {
                continue;
            }
            // A package.json that is not itself an installable project
            // (no dependencies) needs no lockfile.
            if *manifest == "package.json" {
                if let Ok(t) = std::fs::read_to_string(&m) {
                    if !t.contains("\"dependencies\"") && !t.contains("\"devDependencies\"") {
                        continue;
                    }
                }
            }
            if !locks.iter().any(|l| dir.join(l).is_file()) {
                out.push(Finding::new(
                    "sca_missing_lockfile".to_string(), Severity::Medium, rel(&m), 1, 0,
                    format!("{manifest} has no lockfile beside it: installs are not reproducible and resolve to whatever is newest"),
                    manifest.to_string(),
                ).with_metadata("analyzer".to_string(), "sca".to_string()));
            }
        }

        // requirements*.txt lines that are not `==`-pinned.
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !(name.starts_with("requirements") && name.ends_with(".txt")) {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&p) else {
                    continue;
                };
                for (i, raw) in text.lines().enumerate() {
                    let line = raw.split('#').next().unwrap_or("").trim();
                    if line.is_empty()
                        || line.starts_with('-')
                        || line.contains("==")
                        || line.contains(" @ ")
                        || line.contains("://")
                    {
                        continue;
                    }
                    out.push(
                        Finding::new(
                            "sca_unpinned_dependency".to_string(),
                            Severity::Low,
                            rel(&p),
                            i + 1,
                            0,
                            format!("`{line}` is not pinned to an exact version"),
                            raw.trim().to_string(),
                        )
                        .with_metadata("analyzer".to_string(), "sca".to_string()),
                    );
                }
            }
        }
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<std::path::PathBuf>, depth: usize) {
    if depth > 10 {
        return;
    }
    out.push(dir.to_path_buf());
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if p.is_dir()
            && !matches!(
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
            )
        {
            walk(&p, out, depth + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_lockfile_and_unpinned_requirements() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(
            t.path().join("package.json"),
            r#"{"dependencies":{"x":"^1"}}"#,
        )
        .unwrap();
        std::fs::write(
            t.path().join("requirements.txt"),
            "django==4.2\nrequests>=2\nflask\n# note\n-r base.txt\n",
        )
        .unwrap();
        let ids: Vec<String> = detect(t.path())
            .into_iter()
            .map(|f| f.invariant_id)
            .collect();
        assert_eq!(
            ids.iter().filter(|i| *i == "sca_missing_lockfile").count(),
            1
        );
        assert_eq!(
            ids.iter()
                .filter(|i| *i == "sca_unpinned_dependency")
                .count(),
            2
        );
    }

    #[test]
    fn locked_project_is_clean() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(
            t.path().join("package.json"),
            r#"{"dependencies":{"x":"^1"}}"#,
        )
        .unwrap();
        std::fs::write(t.path().join("package-lock.json"), "{}").unwrap();
        std::fs::write(t.path().join("go.mod"), "module x").unwrap();
        std::fs::write(t.path().join("go.sum"), "").unwrap();
        assert!(detect(t.path()).is_empty());
    }
}
