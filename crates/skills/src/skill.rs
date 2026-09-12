//! A single skill, parsed from a `SKILL.md` following the agentskills.io standard.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::preflight::detect_required_tools;
use crate::SkillError;

/// How much Truent can vouch for a skill's output.
///
/// This is the same distinction the engine draws between a `Proven` finding and
/// a `Lead`, carried up to the skill layer. Truent's premise is that it never
/// presents something as verified that nothing verified — and that promise has
/// to survive the introduction of third-party skills, or it stops meaning
/// anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Trust {
    /// Ships with Truent and is backed by the compiled engine. Findings can be
    /// reproduced deterministically.
    EngineBacked,

    /// Comes from a third-party source. Truent can run it and relay what it
    /// says, but cannot reproduce or check the result. Always labelled.
    Advisory,
}

impl Trust {
    /// Short label for output.
    pub fn label(&self) -> &'static str {
        match self {
            Self::EngineBacked => "ENGINE-BACKED",
            Self::Advisory => "ADVISORY",
        }
    }
}

impl std::fmt::Display for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// An executable entry point shipped alongside a skill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillScript {
    /// Path relative to the skill directory, e.g. `scripts/agent.py`.
    pub relative_path: String,
    /// Absolute path on disk.
    pub path: PathBuf,
    /// Interpreter inferred from the extension (`python3`, `bash`, `pwsh`).
    pub interpreter: Option<String>,
}

/// A skill: its metadata, its scripts, and what it needs in order to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    /// Skill name — equals the directory name for a conformant skill.
    pub name: String,
    /// What it does and when to use it.
    pub description: String,
    /// The source this skill came from (`"truent"` for built-ins).
    pub source: String,
    /// Directory containing `SKILL.md`.
    pub path: PathBuf,
    /// How far Truent can vouch for its output.
    pub trust: Trust,

    /// Broad domain, e.g. `cybersecurity`, `smart-contract-security`.
    pub domain: Option<String>,
    /// Narrower category, e.g. `digital-forensics`, `audit`.
    pub subdomain: Option<String>,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Declared license.
    pub license: Option<String>,
    /// Declared version.
    pub version: Option<String>,

    /// Framework identifiers declared in frontmatter, keyed by framework
    /// (`mitre_attack`, `nist_csf`, `atlas_techniques`, …). Kept verbatim —
    /// these are the source's claims, not Truent's.
    pub frameworks: BTreeMap<String, Vec<String>>,

    /// Executable entry points shipped with the skill.
    pub scripts: Vec<SkillScript>,

    /// External commands the skill body references (`aws`, `kubectl`, …).
    ///
    /// **Detected, not declared.** agentskills.io has no requirements field, so
    /// this is inferred by scanning the instructions for known tool names. It
    /// is a useful preflight signal and not a contract — treat a missing entry
    /// as "not detected", never as "not needed".
    pub detected_tools: Vec<String>,
}

impl Skill {
    /// Parse a skill from a directory containing `SKILL.md`.
    pub fn load(dir: &Path, source: &str, trust: Trust) -> Result<Self, SkillError> {
        let skill_md = dir.join("SKILL.md");
        let text = std::fs::read_to_string(&skill_md)
            .map_err(|e| SkillError::Io(skill_md.clone(), e.to_string()))?;

        let (frontmatter, body) = split_frontmatter(&text)
            .ok_or_else(|| SkillError::Malformed(skill_md.clone(), "no YAML frontmatter".into()))?;

        // A real YAML parser, never a regex. A regex that grabs
        // `^description:\s*(.+)$` silently truncates every folded or
        // multi-line description to its first line, and nothing errors — the
        // skill just stops being selectable.
        let raw: serde_yaml_ng::Value = serde_yaml_ng::from_str(frontmatter)
            .map_err(|e| SkillError::Malformed(skill_md.clone(), e.to_string()))?;

        let name = str_field(&raw, "name")
            .ok_or_else(|| SkillError::Malformed(skill_md.clone(), "no `name`".into()))?;
        let description = str_field(&raw, "description").unwrap_or_default();

        // Metadata may sit at the top level (common) or nested under
        // `metadata` (strict agentskills.io compliance). Accept both, so a
        // library written either way indexes correctly.
        let meta = raw.get("metadata");
        let pick = |key: &str| -> Option<String> {
            meta.and_then(|m| str_field(m, key))
                .or_else(|| str_field(&raw, key))
        };
        let pick_list = |key: &str| -> Vec<String> {
            meta.and_then(|m| list_field(m, key))
                .or_else(|| list_field(&raw, key))
                .unwrap_or_default()
        };

        // Framework mappings, wherever they live.
        let mut frameworks = BTreeMap::new();
        for key in FRAMEWORK_KEYS {
            let ids = pick_list(key);
            if !ids.is_empty() {
                frameworks.insert((*key).to_string(), ids);
            }
        }

        Ok(Self {
            name,
            description,
            source: source.to_string(),
            path: dir.to_path_buf(),
            trust,
            domain: pick("domain"),
            subdomain: pick("subdomain"),
            tags: pick_list("tags"),
            license: str_field(&raw, "license").or_else(|| pick("license")),
            version: pick("version"),
            frameworks,
            scripts: discover_scripts(dir),
            detected_tools: detect_required_tools(body),
        })
    }

    /// Whether any of `terms` matches this skill's searchable text.
    ///
    /// Matching is case-insensitive and substring-based across name,
    /// description, subdomain, tags and framework IDs, so `truent skills
    /// search T1059` and `search "memory forensics"` both work.
    pub fn matches(&self, term: &str) -> bool {
        let needle = term.to_lowercase();
        let hay = [
            self.name.to_lowercase(),
            self.description.to_lowercase(),
            self.subdomain.clone().unwrap_or_default().to_lowercase(),
            self.domain.clone().unwrap_or_default().to_lowercase(),
            self.tags.join(" ").to_lowercase(),
            self.frameworks
                .values()
                .flatten()
                .cloned()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase(),
        ];
        hay.iter().any(|h| h.contains(&needle))
    }

    /// The script Truent would run for this skill, if it has exactly one
    /// obvious entry point.
    ///
    /// Returns `None` when there is no script (an instructions-only skill) or
    /// when there are several and the choice is the caller's to make.
    pub fn primary_script(&self) -> Option<&SkillScript> {
        match self.scripts.len() {
            1 => self.scripts.first(),
            _ => self
                .scripts
                .iter()
                .find(|s| {
                    let stem = Path::new(&s.relative_path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("");
                    matches!(stem, "agent" | "main" | "run")
                })
                .or(None),
        }
    }
}

/// Frontmatter keys that carry framework identifier lists.
const FRAMEWORK_KEYS: &[&str] = &[
    "mitre_attack",
    "nist_csf",
    "atlas_techniques",
    "d3fend_techniques",
    "nist_ai_rmf",
    "mitre_f3",
    "taxonomy",
];

/// Split `---\n...\n---\n` frontmatter from the body.
fn split_frontmatter(text: &str) -> Option<(&str, &str)> {
    let rest = text.strip_prefix("---\n")?;
    let end = rest.find("\n---")?;
    let frontmatter = &rest[..end];
    let body = rest[end..].strip_prefix("\n---").unwrap_or("");
    Some((frontmatter, body.trim_start_matches('\n')))
}

fn str_field(v: &serde_yaml_ng::Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(|s| s.trim().to_string())
}

fn list_field(v: &serde_yaml_ng::Value, key: &str) -> Option<Vec<String>> {
    let seq = v.get(key)?.as_sequence()?;
    Some(
        seq.iter()
            .filter_map(|x| x.as_str().map(|s| s.trim().to_string()))
            .collect(),
    )
}

/// Find executable entry points under `scripts/`.
fn discover_scripts(dir: &Path) -> Vec<SkillScript> {
    let scripts_dir = dir.join("scripts");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&scripts_dir) else {
        return out;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    paths.sort();

    for path in paths {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let interpreter = match ext {
            "py" => Some("python3".to_string()),
            "sh" | "bash" => Some("bash".to_string()),
            "ps1" => Some("pwsh".to_string()),
            _ => None,
        };
        if interpreter.is_none() {
            continue;
        }
        let relative_path = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        out.push(SkillScript {
            relative_path,
            path,
            interpreter,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_skill(dir: &Path, name: &str, frontmatter: &str, body: &str) {
        let d = dir.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("SKILL.md"),
            format!("---\n{frontmatter}\n---\n{body}"),
        )
        .unwrap();
    }

    #[test]
    fn parses_top_level_metadata_layout() {
        // The layout the cybersecurity library uses: metadata at top level.
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "analyzing-dns-logs",
            "name: analyzing-dns-logs\ndescription: Detect DNS tunneling.\n\
             domain: cybersecurity\nsubdomain: soc-operations\n\
             tags:\n  - dns\n  - exfiltration\nmitre_attack:\n  - T1048.003\n  - T1071.004",
            "# Body\n```bash\ntshark -r capture.pcap\n```\n",
        );

        let s = Skill::load(
            &tmp.path().join("analyzing-dns-logs"),
            "cyber",
            Trust::Advisory,
        )
        .unwrap();
        assert_eq!(s.name, "analyzing-dns-logs");
        assert_eq!(s.subdomain.as_deref(), Some("soc-operations"));
        assert_eq!(s.tags, vec!["dns", "exfiltration"]);
        assert_eq!(s.frameworks["mitre_attack"], vec!["T1048.003", "T1071.004"]);
        assert_eq!(s.trust, Trust::Advisory);
        assert!(s.detected_tools.contains(&"tshark".to_string()));
    }

    #[test]
    fn parses_nested_metadata_layout() {
        // Strict agentskills.io: everything under `metadata`. Truent's own
        // skills use this, and both layouts must index identically.
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "truent-audit",
            concat!(
                "name: truent-audit\n",
                "description: Audit contracts.\n",
                "license: MIT\n",
                "metadata:\n",
                "  version: \"0.1.0\"\n",
                "  domain: smart-contract-security\n",
                "  subdomain: audit\n",
                "  tags:\n    - evm\n    - audit",
            ),
            "# Body\n",
        );

        let s = Skill::load(
            &tmp.path().join("truent-audit"),
            "truent",
            Trust::EngineBacked,
        )
        .unwrap();
        assert_eq!(s.domain.as_deref(), Some("smart-contract-security"));
        assert_eq!(s.subdomain.as_deref(), Some("audit"));
        assert_eq!(s.version.as_deref(), Some("0.1.0"));
        assert_eq!(s.license.as_deref(), Some("MIT"));
        assert_eq!(s.tags, vec!["evm", "audit"]);
    }

    #[test]
    fn multiline_descriptions_survive_intact() {
        // The failure this parser exists to avoid: a regex reader truncates a
        // folded description to its first line and nothing errors.
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "multi",
            concat!(
                "name: multi\n",
                "description: >-\n",
                "  First line of the description.\n",
                "  Second line that a regex parser would drop.\n",
                "tags:\n  - a\n  - b",
            ),
            "# Body\n",
        );
        let s = Skill::load(&tmp.path().join("multi"), "x", Trust::Advisory).unwrap();
        assert!(
            s.description.contains("Second line"),
            "description was truncated: {:?}",
            s.description
        );
    }

    #[test]
    fn search_matches_across_fields_including_framework_ids() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill(
            tmp.path(),
            "hunt",
            "name: hunt\ndescription: Hunt for things.\nsubdomain: threat-hunting\n\
             tags:\n  - sigma\nmitre_attack:\n  - T1059.001",
            "# Body\n",
        );
        let s = Skill::load(&tmp.path().join("hunt"), "x", Trust::Advisory).unwrap();
        assert!(s.matches("threat-hunting"));
        assert!(s.matches("SIGMA"), "matching must be case-insensitive");
        assert!(s.matches("T1059"), "framework IDs must be searchable");
        assert!(!s.matches("kubernetes"));
    }

    #[test]
    fn missing_frontmatter_is_an_error_not_a_default() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("bad");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("SKILL.md"), "# No frontmatter here\n").unwrap();
        assert!(Skill::load(&d, "x", Trust::Advisory).is_err());
    }

    #[test]
    fn discovers_scripts_and_picks_a_primary() {
        let tmp = tempfile::tempdir().unwrap();
        write_skill(tmp.path(), "s", "name: s\ndescription: d", "# Body\n");
        let d = tmp.path().join("s");
        std::fs::create_dir_all(d.join("scripts")).unwrap();
        std::fs::write(d.join("scripts/agent.py"), "print(1)").unwrap();
        std::fs::write(d.join("scripts/helper.py"), "print(2)").unwrap();
        std::fs::write(d.join("scripts/notes.txt"), "ignored").unwrap();

        let s = Skill::load(&d, "x", Trust::Advisory).unwrap();
        assert_eq!(s.scripts.len(), 2, "non-executable files must be skipped");
        assert_eq!(
            s.primary_script().unwrap().relative_path,
            "scripts/agent.py"
        );
        assert_eq!(
            s.primary_script().unwrap().interpreter.as_deref(),
            Some("python3")
        );
    }

    #[test]
    fn ambiguous_scripts_have_no_primary() {
        // Two scripts, neither named agent/main/run: Truent must not guess
        // which one to execute.
        let tmp = tempfile::tempdir().unwrap();
        write_skill(tmp.path(), "s", "name: s\ndescription: d", "# Body\n");
        let d = tmp.path().join("s");
        std::fs::create_dir_all(d.join("scripts")).unwrap();
        std::fs::write(d.join("scripts/alpha.py"), "").unwrap();
        std::fs::write(d.join("scripts/beta.py"), "").unwrap();

        let s = Skill::load(&d, "x", Trust::Advisory).unwrap();
        assert!(s.primary_script().is_none());
    }
}
