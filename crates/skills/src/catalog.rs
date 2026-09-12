//! The catalog: every skill Truent can reach, across its built-ins and every
//! registered source.

use std::path::{Path, PathBuf};

use crate::skill::{Skill, Trust};
use crate::source::{SkillSource, SourceRegistry};
use crate::SkillError;

/// Name reserved for Truent's own, engine-backed skills.
pub const BUILTIN_SOURCE: &str = "truent";

/// Every reachable skill, indexed for search.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    skills: Vec<Skill>,
    /// Directories that looked like skills but failed to parse.
    ///
    /// Surfaced rather than swallowed: a source with fifty unreadable skills
    /// is a broken source, and silently indexing the other 768 hides that.
    pub errors: Vec<(PathBuf, String)>,
}

impl Catalog {
    /// Build a catalog from the cache root, including built-ins if given.
    ///
    /// `builtin_dir` is Truent's own `skills/` directory when it can be
    /// located; pass `None` when running from an installed binary with no
    /// repository alongside it.
    pub fn load(root: &Path, builtin_dir: Option<&Path>) -> Result<Self, SkillError> {
        let mut catalog = Self::default();

        if let Some(dir) = builtin_dir {
            catalog.absorb(dir, BUILTIN_SOURCE, Trust::EngineBacked);
        }

        let registry = SourceRegistry::load(root)?;
        for source in &registry.sources {
            let dir = source.skills_root(root);
            if !dir.is_dir() {
                catalog.errors.push((
                    dir,
                    format!(
                        "source '{}' is registered but not checked out — run: truent skills source update {}",
                        source.name, source.name
                    ),
                ));
                continue;
            }
            catalog.absorb(&source.skills_root(root), &source.name, Trust::Advisory);
        }

        catalog.skills.sort_by(|a, b| {
            // Built-ins first, then alphabetically. An engine-backed skill
            // should be what the operator sees before an advisory one that
            // happens to sort earlier.
            (a.trust != Trust::EngineBacked, &a.name)
                .cmp(&(b.trust != Trust::EngineBacked, &b.name))
        });
        Ok(catalog)
    }

    /// Index every skill directory directly under `dir`.
    fn absorb(&mut self, dir: &Path, source: &str, trust: Trust) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            self.errors
                .push((dir.to_path_buf(), "cannot read directory".to_string()));
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || !path.join("SKILL.md").is_file() {
                continue;
            }
            match Skill::load(&path, source, trust) {
                Ok(s) => self.skills.push(s),
                Err(e) => self.errors.push((path, e.to_string())),
            }
        }
    }

    /// Every indexed skill.
    pub fn skills(&self) -> &[Skill] {
        &self.skills
    }

    /// Number of indexed skills.
    pub fn len(&self) -> usize {
        self.skills.len()
    }

    /// Whether the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.skills.is_empty()
    }

    /// Look a skill up by exact name.
    ///
    /// Names can collide across sources; `source:name` disambiguates.
    pub fn get(&self, name: &str) -> Option<&Skill> {
        if let Some((source, bare)) = name.split_once(':') {
            return self
                .skills
                .iter()
                .find(|s| s.source == source && s.name == bare);
        }
        self.skills.iter().find(|s| s.name == name)
    }

    /// Every skill whose name is `name`, across sources.
    pub fn get_all(&self, name: &str) -> Vec<&Skill> {
        self.skills.iter().filter(|s| s.name == name).collect()
    }

    /// Skills matching every term in `terms` (AND), optionally narrowed by
    /// source and subdomain.
    pub fn search(
        &self,
        terms: &[String],
        source: Option<&str>,
        subdomain: Option<&str>,
    ) -> Vec<&Skill> {
        self.skills
            .iter()
            .filter(|s| source.is_none_or(|src| s.source == src))
            .filter(|s| subdomain.is_none_or(|sd| s.subdomain.as_deref() == Some(sd)))
            .filter(|s| terms.iter().all(|t| s.matches(t)))
            .collect()
    }

    /// Skill counts per subdomain, most populous first.
    pub fn subdomain_counts(&self) -> Vec<(String, usize)> {
        let mut map: std::collections::BTreeMap<String, usize> = Default::default();
        for s in &self.skills {
            *map.entry(s.subdomain.clone().unwrap_or_else(|| "—".into()))
                .or_default() += 1;
        }
        let mut v: Vec<(String, usize)> = map.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    /// Skill counts per source.
    pub fn source_counts(&self) -> Vec<(String, usize)> {
        let mut map: std::collections::BTreeMap<String, usize> = Default::default();
        for s in &self.skills {
            *map.entry(s.source.clone()).or_default() += 1;
        }
        map.into_iter().collect()
    }
}

/// Default cache root: `$TRUENT_HOME/skills`, else `~/.truent/skills`.
pub fn default_root() -> PathBuf {
    if let Some(home) = std::env::var_os("TRUENT_HOME") {
        return PathBuf::from(home).join("skills");
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".truent").join("skills")
}

/// Locate Truent's **own** `skills/` directory.
///
/// Skills found here are labelled [`Trust::EngineBacked`], which is Truent
/// asserting that it stands behind them — so the directory has to be proven to
/// be Truent's, not merely named `skills`. An earlier version accepted
/// `./skills` unconditionally, which meant running Truent inside any project
/// that happened to have a `skills/` directory laundered that project's
/// content as engine-backed.
///
/// A candidate qualifies only if its parent carries Truent's plugin manifest.
/// Returns `None` when Truent is installed standalone with no repository
/// alongside it — built-ins are then simply absent rather than faked.
pub fn builtin_skills_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("skills"));
        // Also allow running from a subdirectory of the repo.
        for ancestor in cwd.ancestors().skip(1).take(4) {
            candidates.push(ancestor.join("skills"));
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        // target/{debug,release}/truent -> repo root is 3 levels up; an
        // installed binary is nowhere near one, which the marker check below
        // is what actually settles.
        for up in [2usize, 3, 4] {
            if let Some(base) = exe.ancestors().nth(up) {
                candidates.push(base.join("skills"));
            }
        }
    }

    candidates
        .into_iter()
        .find(|p| p.is_dir() && is_truent_repo(p.parent().unwrap_or(p)))
}

/// Whether `dir` is the root of Truent's own repository.
///
/// Identified by the plugin manifest naming Truent. A directory called
/// `skills` proves nothing on its own.
fn is_truent_repo(dir: &Path) -> bool {
    let manifest = dir.join(".claude-plugin").join("plugin.json");
    let Ok(text) = std::fs::read_to_string(&manifest) else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return false;
    };
    value.get("name").and_then(|n| n.as_str()) == Some("truent")
}

/// Convenience: the source Truent recommends for general security coverage.
pub fn suggested_sources() -> &'static [(&'static str, &'static str)] {
    &[(
        "mukul975/Anthropic-Cybersecurity-Skills",
        "818 skills across 46 security subdomains — cloud, DFIR, threat hunting, \
         SOC, malware, red team (Apache-2.0, community project)",
    )]
}

/// Register a source without cloning it (used by tests and by `source add`
/// after a successful clone).
pub fn register(root: &Path, source: SkillSource) -> Result<(), SkillError> {
    let mut reg = SourceRegistry::load(root)?;
    reg.upsert(source)?;
    reg.save(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_skill(dir: &Path, name: &str, extra: &str) {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: Does {name}.\n{extra}\n---\n# {name}\n"),
        )
        .unwrap();
    }

    /// A cache root with one registered source containing `names`.
    fn fixture(names: &[(&str, &str)]) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let skills = root.join("sources/cyber/skills");
        std::fs::create_dir_all(&skills).unwrap();
        for (n, extra) in names {
            write_skill(&skills, n, extra);
        }
        register(
            root,
            SkillSource {
                name: "cyber".into(),
                url: "https://example.com/c.git".into(),
                skills_dir: "skills".into(),
            },
        )
        .unwrap();
        tmp
    }

    #[test]
    fn indexes_registered_sources() {
        let tmp = fixture(&[
            ("hunting-dns", "subdomain: threat-hunting"),
            ("cloud-posture", "subdomain: cloud-security"),
        ]);
        let cat = Catalog::load(tmp.path(), None).unwrap();
        assert_eq!(cat.len(), 2);
        assert!(cat.errors.is_empty(), "{:?}", cat.errors);
        assert_eq!(cat.get("hunting-dns").unwrap().source, "cyber");
        assert_eq!(cat.get("hunting-dns").unwrap().trust, Trust::Advisory);
    }

    #[test]
    fn builtins_are_engine_backed_and_sort_first() {
        let tmp = fixture(&[("aaa-external", "subdomain: cloud-security")]);
        let builtin = tmp.path().join("builtin");
        std::fs::create_dir_all(&builtin).unwrap();
        write_skill(&builtin, "zzz-truent", "subdomain: audit");

        let cat = Catalog::load(tmp.path(), Some(&builtin)).unwrap();
        assert_eq!(cat.len(), 2);
        assert_eq!(
            cat.skills()[0].name,
            "zzz-truent",
            "engine-backed skills must be listed before advisory ones"
        );
        assert_eq!(cat.skills()[0].trust, Trust::EngineBacked);
        assert_eq!(cat.skills()[1].trust, Trust::Advisory);
    }

    #[test]
    fn search_is_conjunctive_and_filterable() {
        let tmp = fixture(&[
            (
                "dns-tunnel",
                "subdomain: threat-hunting\ntags:\n  - dns\n  - exfiltration",
            ),
            (
                "dns-sinkhole",
                "subdomain: network-security\ntags:\n  - dns",
            ),
        ]);
        let cat = Catalog::load(tmp.path(), None).unwrap();

        assert_eq!(cat.search(&["dns".into()], None, None).len(), 2);
        // AND, not OR.
        assert_eq!(
            cat.search(&["dns".into(), "exfiltration".into()], None, None)
                .len(),
            1
        );
        assert_eq!(cat.search(&[], None, Some("network-security")).len(), 1);
        assert_eq!(cat.search(&[], Some("nope"), None).len(), 0);
    }

    #[test]
    fn source_qualified_lookup_disambiguates_collisions() {
        let tmp = fixture(&[("shared-name", "subdomain: a")]);
        let builtin = tmp.path().join("builtin");
        std::fs::create_dir_all(&builtin).unwrap();
        write_skill(&builtin, "shared-name", "subdomain: b");

        let cat = Catalog::load(tmp.path(), Some(&builtin)).unwrap();
        assert_eq!(cat.get_all("shared-name").len(), 2);
        assert_eq!(
            cat.get("truent:shared-name").unwrap().subdomain.as_deref(),
            Some("b")
        );
        assert_eq!(
            cat.get("cyber:shared-name").unwrap().subdomain.as_deref(),
            Some("a")
        );
    }

    #[test]
    fn a_registered_but_missing_checkout_is_reported_not_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        register(
            tmp.path(),
            SkillSource {
                name: "ghost".into(),
                url: "https://example.com/g.git".into(),
                skills_dir: "skills".into(),
            },
        )
        .unwrap();

        let cat = Catalog::load(tmp.path(), None).unwrap();
        assert!(cat.is_empty());
        assert_eq!(cat.errors.len(), 1);
        assert!(cat.errors[0].1.contains("not checked out"));
    }

    #[test]
    fn unparseable_skills_are_collected_rather_than_dropped() {
        let tmp = fixture(&[("good", "subdomain: a")]);
        let bad = tmp.path().join("sources/cyber/skills/bad");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("SKILL.md"), "no frontmatter\n").unwrap();

        let cat = Catalog::load(tmp.path(), None).unwrap();
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.errors.len(), 1, "the broken skill must be surfaced");
    }

    #[test]
    fn only_a_real_truent_repo_yields_engine_backed_builtins() {
        // The ENGINE-BACKED label is Truent vouching for a skill. A directory
        // merely *named* `skills` must never earn it — otherwise running
        // Truent inside any project with a skills/ folder launders that
        // project's content as engine-verified.
        let tmp = tempfile::tempdir().unwrap();
        let imposter = tmp.path().join("imposter");
        std::fs::create_dir_all(&imposter).unwrap();
        assert!(!super::is_truent_repo(&imposter), "no manifest: not Truent");

        // A manifest for some other plugin is still not Truent.
        std::fs::create_dir_all(imposter.join(".claude-plugin")).unwrap();
        std::fs::write(
            imposter.join(".claude-plugin/plugin.json"),
            r#"{"name":"something-else"}"#,
        )
        .unwrap();
        assert!(!super::is_truent_repo(&imposter), "wrong name: not Truent");

        // Malformed JSON must fail closed, not panic or pass.
        std::fs::write(imposter.join(".claude-plugin/plugin.json"), "{not json").unwrap();
        assert!(!super::is_truent_repo(&imposter), "malformed: not Truent");

        // The real thing.
        std::fs::write(
            imposter.join(".claude-plugin/plugin.json"),
            r#"{"name":"truent","version":"0.6.0"}"#,
        )
        .unwrap();
        assert!(super::is_truent_repo(&imposter));
    }

    #[test]
    fn counts_group_by_subdomain_and_source() {
        let tmp = fixture(&[
            ("a", "subdomain: cloud-security"),
            ("b", "subdomain: cloud-security"),
            ("c", "subdomain: threat-hunting"),
        ]);
        let cat = Catalog::load(tmp.path(), None).unwrap();
        assert_eq!(cat.subdomain_counts()[0], ("cloud-security".to_string(), 2));
        assert_eq!(cat.source_counts(), vec![("cyber".to_string(), 3)]);
    }
}
