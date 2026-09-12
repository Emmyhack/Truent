//! Registered skill sources: where skill libraries come from, and how they are
//! kept up to date.
//!
//! Sources are **cloned, not vendored**. A library stays in its own repository
//! under its own licence, and `truent skills source update` pulls upstream
//! changes. Copying 818 third-party skills into Truent would fork them on day
//! one and leave Truent shipping a stale, relicensed snapshot.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::SkillError;

/// A registered skill library.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSource {
    /// Short local name used to refer to it, e.g. `cybersecurity`.
    pub name: String,
    /// Git URL it was cloned from.
    pub url: String,
    /// Subdirectory within the repository holding skill directories.
    #[serde(default = "default_skills_dir")]
    pub skills_dir: String,
}

fn default_skills_dir() -> String {
    "skills".to_string()
}

/// Longest accepted source name.
const MAX_NAME_LEN: usize = 64;

/// Validate a source name.
///
/// A name becomes a **path segment** under the cache root, and `source remove`
/// recursively deletes that path. A name of `../../x` therefore escaped the
/// cache and deleted an arbitrary directory. Names are consequently restricted
/// to a single safe segment: no separators, no `..`, no leading dot or dash.
///
/// Enforced both when a source is added and when the registry is loaded, so a
/// hand-edited or shared `sources.json` cannot traverse either.
pub fn validate_name(name: &str) -> Result<(), SkillError> {
    if name.is_empty() {
        return Err(SkillError::InvalidName(
            name.to_string(),
            "must not be empty".into(),
        ));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(SkillError::InvalidName(
            name.to_string(),
            format!("must be at most {MAX_NAME_LEN} characters"),
        ));
    }
    if name.starts_with('.') || name.starts_with('-') {
        return Err(SkillError::InvalidName(
            name.to_string(),
            "must not start with '.' or '-'".into(),
        ));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(SkillError::InvalidName(
            name.to_string(),
            "may contain only ASCII letters, digits, '.', '_' and '-'".into(),
        ));
    }
    Ok(())
}

/// Validate the in-repository skills subdirectory.
///
/// Joined onto the checkout path, so it must stay inside it. Multi-segment
/// relative paths are fine (`library/skills`); `..` and absolute paths are not.
pub fn validate_skills_dir(dir: &str) -> Result<(), SkillError> {
    if dir.is_empty() {
        return Err(SkillError::InvalidName(
            dir.to_string(),
            "skills_dir must not be empty".into(),
        ));
    }
    let p = Path::new(dir);
    if p.is_absolute() {
        return Err(SkillError::InvalidName(
            dir.to_string(),
            "skills_dir must be relative".into(),
        ));
    }
    for component in p.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(SkillError::InvalidName(
                dir.to_string(),
                "skills_dir must not contain '..', '.' or a root".into(),
            ));
        }
    }
    Ok(())
}

impl SkillSource {
    /// Expand a shorthand into a clone URL.
    ///
    /// `owner/repo` means GitHub; anything containing `://` or `git@` is taken
    /// as a full URL and passed through untouched.
    pub fn resolve_url(spec: &str) -> Result<String, SkillError> {
        // A spec beginning with '-' would reach `git clone` as an option
        // rather than a URL (`--upload-pack=...` executes an arbitrary
        // command). Reject it before it becomes an argument.
        if spec.starts_with('-') {
            return Err(SkillError::InvalidSource(spec.to_string()));
        }
        if spec.contains("://") || spec.starts_with("git@") {
            return Ok(spec.to_string());
        }
        let parts: Vec<&str> = spec.split('/').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            return Ok(format!("https://github.com/{}/{}.git", parts[0], parts[1]));
        }
        Err(SkillError::InvalidSource(spec.to_string()))
    }

    /// Default local name for a spec: the repository name, lowercased.
    pub fn default_name(spec: &str) -> String {
        let raw = spec
            .trim_end_matches(".git")
            .trim_end_matches('/')
            .rsplit(['/', ':'])
            .next()
            .unwrap_or(spec)
            .to_lowercase();
        // Derived from a URL, so sanitised rather than trusted: anything not
        // allowed in a name becomes '-'.
        let cleaned: String = raw
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let bounded: String = cleaned
            .trim_start_matches(['.', '-'])
            .chars()
            .take(MAX_NAME_LEN)
            .collect();
        if bounded.is_empty() {
            "source".to_string()
        } else {
            bounded
        }
    }

    /// Check that this source's name and skills directory are safe to join
    /// onto a filesystem path.
    pub fn validate(&self) -> Result<(), SkillError> {
        validate_name(&self.name)?;
        validate_skills_dir(&self.skills_dir)
    }

    /// Where this source is checked out.
    pub fn checkout_dir(&self, root: &Path) -> PathBuf {
        root.join("sources").join(&self.name)
    }

    /// Directory containing the individual skill directories.
    pub fn skills_root(&self, root: &Path) -> PathBuf {
        self.checkout_dir(root).join(&self.skills_dir)
    }
}

/// The set of registered sources, persisted as JSON.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceRegistry {
    #[serde(default)]
    pub sources: Vec<SkillSource>,
}

impl SourceRegistry {
    /// Load the registry, returning an empty one if it does not exist yet.
    pub fn load(root: &Path) -> Result<Self, SkillError> {
        let path = Self::path(root);
        if !path.is_file() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| SkillError::Io(path.clone(), e.to_string()))?;
        let registry: Self = serde_json::from_str(&text)
            .map_err(|e| SkillError::Malformed(path.clone(), e.to_string()))?;
        // The registry is a file on disk: hand-editable, copyable between
        // machines, committable to a shared repo. Validate on the way in so a
        // hostile entry cannot traverse out of the cache.
        for source in &registry.sources {
            source.validate().map_err(|e| {
                SkillError::Malformed(path.clone(), format!("source '{}': {e}", source.name))
            })?;
        }
        Ok(registry)
    }

    /// Persist the registry.
    pub fn save(&self, root: &Path) -> Result<(), SkillError> {
        let path = Self::path(root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SkillError::Io(parent.to_path_buf(), e.to_string()))?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| SkillError::Malformed(path.clone(), e.to_string()))?;
        std::fs::write(&path, text + "\n").map_err(|e| SkillError::Io(path, e.to_string()))
    }

    fn path(root: &Path) -> PathBuf {
        root.join("sources.json")
    }

    /// Look up a source by name.
    pub fn get(&self, name: &str) -> Option<&SkillSource> {
        self.sources.iter().find(|s| s.name == name)
    }

    /// Add a source, replacing any existing one with the same name.
    pub fn upsert(&mut self, source: SkillSource) -> Result<(), SkillError> {
        source.validate()?;
        self.sources.retain(|s| s.name != source.name);
        self.sources.push(source);
        self.sources.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(())
    }

    /// Remove a source by name. Returns whether it was present.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.sources.len();
        self.sources.retain(|s| s.name != name);
        self.sources.len() != before
    }
}

/// Clone a source into the cache.
pub fn clone_source(source: &SkillSource, root: &Path) -> Result<(), SkillError> {
    source.validate()?;
    let dest = source.checkout_dir(root);
    if dest.exists() {
        return update_source(source, root);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SkillError::Io(parent.to_path_buf(), e.to_string()))?;
    }
    // `--depth 1`: skill libraries are large and their history is not what
    // makes them useful here.
    // `--` terminates option parsing: even if a URL slipped past validation,
    // git treats what follows as operands rather than flags.
    run_git(
        &[
            "clone",
            "--depth",
            "1",
            "--",
            &source.url,
            &dest.to_string_lossy(),
        ],
        None,
    )
}

/// Fast-forward an existing checkout.
pub fn update_source(source: &SkillSource, root: &Path) -> Result<(), SkillError> {
    source.validate()?;
    let dir = source.checkout_dir(root);
    if !dir.is_dir() {
        return clone_source(source, root);
    }
    run_git(&["fetch", "--depth", "1", "origin"], Some(&dir))?;
    // Reset rather than merge: the checkout is a cache, never an edit surface,
    // so local divergence is a corruption to discard, not a change to preserve.
    run_git(&["reset", "--hard", "origin/HEAD"], Some(&dir))
        .or_else(|_| run_git(&["reset", "--hard", "FETCH_HEAD"], Some(&dir)))
}

/// The commit a source is currently pinned at.
pub fn source_revision(source: &SkillSource, root: &Path) -> Option<String> {
    let dir = source.checkout_dir(root);
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(&dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn run_git(args: &[&str], cwd: Option<&Path>) -> Result<(), SkillError> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd
        .output()
        .map_err(|e| SkillError::Git(format!("running git: {e}")))?;
    if !out.status.success() {
        return Err(SkillError::Git(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_shorthand_and_full_urls() {
        assert_eq!(
            SkillSource::resolve_url("mukul975/Anthropic-Cybersecurity-Skills").unwrap(),
            "https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git"
        );
        assert_eq!(
            SkillSource::resolve_url("https://gitlab.com/x/y.git").unwrap(),
            "https://gitlab.com/x/y.git"
        );
        assert_eq!(
            SkillSource::resolve_url("git@github.com:x/y.git").unwrap(),
            "git@github.com:x/y.git"
        );
        assert!(SkillSource::resolve_url("not-a-repo").is_err());
        assert!(SkillSource::resolve_url("a/b/c").is_err());
    }

    #[test]
    fn derives_a_sensible_default_name() {
        assert_eq!(
            SkillSource::default_name("mukul975/Anthropic-Cybersecurity-Skills"),
            "anthropic-cybersecurity-skills"
        );
        assert_eq!(
            SkillSource::default_name("https://github.com/a/My-Repo.git"),
            "my-repo"
        );
    }

    #[test]
    fn registry_round_trips_and_upserts_without_duplicating() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let mut reg = SourceRegistry::load(root).unwrap();
        assert!(reg.sources.is_empty(), "absent registry loads as empty");

        reg.upsert(SkillSource {
            name: "cyber".into(),
            url: "https://example.com/a.git".into(),
            skills_dir: "skills".into(),
        })
        .unwrap();
        reg.upsert(SkillSource {
            name: "cyber".into(),
            url: "https://example.com/b.git".into(),
            skills_dir: "skills".into(),
        })
        .unwrap();
        assert_eq!(
            reg.sources.len(),
            1,
            "same name must replace, not duplicate"
        );
        assert_eq!(reg.get("cyber").unwrap().url, "https://example.com/b.git");

        reg.save(root).unwrap();
        let reloaded = SourceRegistry::load(root).unwrap();
        assert_eq!(reloaded.sources.len(), 1);
        assert_eq!(
            reloaded.get("cyber").unwrap().url,
            "https://example.com/b.git"
        );

        let mut reloaded = reloaded;
        assert!(reloaded.remove("cyber"));
        assert!(!reloaded.remove("cyber"), "removing twice reports absence");
    }

    // -----------------------------------------------------------------
    // Path-traversal and argument-injection regressions
    //
    // A source name becomes a path segment under the cache root, and
    // `source remove` deletes that path recursively. Before these checks,
    // `--name ../../X` deleted an arbitrary directory outside the cache.
    // -----------------------------------------------------------------

    #[test]
    fn traversal_names_are_rejected() {
        for bad in [
            "../../PRECIOUS",
            "..",
            "a/b",
            "a\\b",
            "./x",
            "-rf",
            "",
            "/abs",
        ] {
            assert!(
                validate_name(bad).is_err(),
                "{bad:?} must be rejected as a source name"
            );
        }
        for good in ["cyber", "my-source", "src_1", "a.b", "A9"] {
            assert!(validate_name(good).is_ok(), "{good:?} should be accepted");
        }
    }

    #[test]
    fn over_long_names_are_rejected() {
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN)).is_ok());
        assert!(validate_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
    }

    #[test]
    fn skills_dir_must_stay_inside_the_checkout() {
        for bad in ["../../../etc", "..", "/etc", "a/../../b", ""] {
            assert!(
                validate_skills_dir(bad).is_err(),
                "{bad:?} must be rejected as a skills_dir"
            );
        }
        for good in ["skills", "library/skills", "a/b/c"] {
            assert!(
                validate_skills_dir(good).is_ok(),
                "{good:?} should be accepted"
            );
        }
    }

    #[test]
    fn a_hostile_registry_file_fails_to_load() {
        // sources.json is hand-editable and may be copied between machines,
        // so validation cannot live only on the `source add` path.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("sources.json"),
            r#"{"sources":[{"name":"../../PRECIOUS","url":"u","skills_dir":"skills"}]}"#,
        )
        .unwrap();
        let err = SourceRegistry::load(tmp.path()).unwrap_err();
        assert!(
            err.to_string().contains("invalid name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn upsert_refuses_an_unsafe_name() {
        let mut reg = SourceRegistry::default();
        assert!(reg
            .upsert(SkillSource {
                name: "../evil".into(),
                url: "u".into(),
                skills_dir: "skills".into(),
            })
            .is_err());
        assert!(reg.sources.is_empty(), "nothing invalid may be persisted");
    }

    #[test]
    fn flag_shaped_specs_are_not_passed_to_git() {
        // `git clone --upload-pack=<cmd>` executes <cmd>. A spec beginning
        // with '-' must never reach the argument list.
        for bad in ["--upload-pack=touch /tmp/pwned", "-c", "--config=x"] {
            assert!(
                SkillSource::resolve_url(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn default_name_sanitises_rather_than_trusts_the_url() {
        // The name is derived from a URL the user supplied, so it has to come
        // out as a safe segment no matter what went in.
        for spec in [
            "https://github.com/a/../../evil.git",
            "git@host:weird~name!.git",
            "https://x/..",
            "https://x/---",
        ] {
            let name = SkillSource::default_name(spec);
            assert!(
                validate_name(&name).is_ok(),
                "default_name({spec:?}) produced unsafe {name:?}"
            );
        }
    }

    #[test]
    fn checkout_paths_are_namespaced_by_source() {
        let s = SkillSource {
            name: "cyber".into(),
            url: "u".into(),
            skills_dir: "skills".into(),
        };
        let root = Path::new("/cache");
        assert_eq!(s.checkout_dir(root), Path::new("/cache/sources/cyber"));
        assert_eq!(
            s.skills_root(root),
            Path::new("/cache/sources/cyber/skills")
        );
    }
}
