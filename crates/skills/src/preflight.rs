//! Detecting what a skill needs, and whether this machine has it.
//!
//! A skill library is only as useful as the tools it can actually drive. A
//! cloud-posture skill that shells out to `gcloud` is inert on a laptop with no
//! `gcloud`, and discovering that *after* running it wastes the operator's
//! time. `truent skills doctor` answers the question up front.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// External commands worth detecting in skill instructions.
///
/// Deliberately a fixed list rather than "any word before a flag": the latter
/// produces noise from prose and example output. Missing a tool here degrades
/// the preflight to "not detected", which is the safe direction — Truent never
/// claims a skill is runnable, only that nothing it looked for was missing.
const KNOWN_TOOLS: &[&str] = &[
    // cloud
    "aws",
    "az",
    "gcloud",
    "kubectl",
    "helm",
    "terraform",
    "eksctl",
    // network
    "nmap",
    "tshark",
    "tcpdump",
    "zeek",
    "suricata",
    "masscan",
    "dig",
    "whois",
    // containers / supply chain
    "docker",
    "podman",
    "trivy",
    "grype",
    "syft",
    "cosign",
    "snyk",
    // forensics / malware
    "volatility3",
    "vol.py",
    "yara",
    "clamscan",
    "binwalk",
    "radare2",
    "r2",
    "strings",
    "exiftool",
    "sleuthkit",
    "autopsy",
    "chainsaw",
    "hayabusa",
    // offensive
    "msfconsole",
    "hydra",
    "hashcat",
    "john",
    "sqlmap",
    "impacket-smbserver",
    "bloodhound-python",
    "crackmapexec",
    "netexec",
    "responder",
    "subfinder",
    "amass",
    "httpx",
    "nuclei",
    "ffuf",
    // siem / detection
    "splunk",
    "elastic-agent",
    "filebeat",
    "sigma",
    "sigmac",
    // platform
    "git",
    "python3",
    "pip",
    "jq",
    "curl",
    "openssl",
    "ssh",
    "osquery",
];

/// Scan a skill body for external commands it appears to need.
///
/// Only fenced code blocks are considered — prose mentions a tool far more
/// often than it invokes one, and a preflight that flags every name in the
/// narrative is one operators learn to ignore.
pub fn detect_required_tools(body: &str) -> Vec<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut in_fence = false;

    for line in body.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            continue;
        }
        // A command is the first word of a line, or the first word after a
        // pipe or `&&`. Anything else is an argument.
        for segment in trimmed.split(['|', ';']).flat_map(|s| s.split("&&")) {
            let Some(word) = segment.split_whitespace().next() else {
                continue;
            };
            let word = word.trim_start_matches('$').trim();
            if KNOWN_TOOLS.contains(&word) {
                found.insert(word.to_string());
            }
        }
    }
    found.into_iter().collect()
}

/// Whether `tool` is executable on this machine.
///
/// Resolved by walking `PATH` directly rather than shelling out to `which`,
/// which is itself not guaranteed to exist (and is a builtin, not a binary, in
/// some shells).
pub fn tool_available(tool: &str) -> bool {
    which(tool).is_some()
}

/// Resolve `tool` against `PATH`, returning the first match.
pub fn which(tool: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    // On Windows a bare name needs an extension to be executable.
    let candidates: Vec<String> = if cfg!(windows) {
        vec![
            tool.to_string(),
            format!("{tool}.exe"),
            format!("{tool}.cmd"),
            format!("{tool}.bat"),
        ]
    } else {
        vec![tool.to_string()]
    };

    for dir in std::env::split_paths(&path) {
        for candidate in &candidates {
            let full = dir.join(candidate);
            if is_executable(&full) {
                return Some(full);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(p: &std::path::Path) -> bool {
    p.is_file()
}

/// The result of checking one skill's tool requirements.
#[derive(Debug, Clone)]
pub struct Preflight {
    /// Tools detected in the skill and present on this machine.
    pub present: Vec<String>,
    /// Tools detected in the skill and missing from this machine.
    pub missing: Vec<String>,
}

impl Preflight {
    /// Check a skill's detected tools against this machine.
    pub fn check(detected_tools: &[String]) -> Self {
        let (present, missing) = detected_tools
            .iter()
            .cloned()
            .partition(|t| tool_available(t));
        Self { present, missing }
    }

    /// Whether every detected tool is available.
    ///
    /// True does **not** mean the skill will succeed — detection is a
    /// heuristic over the instructions, not a declared manifest.
    pub fn is_satisfied(&self) -> bool {
        self.missing.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_commands_only_inside_code_fences() {
        let body = "\
Prose that mentions nmap and kubectl without running them.

```bash
aws s3 ls
kubectl get pods
```
More prose about terraform.
";
        let tools = detect_required_tools(body);
        assert_eq!(tools, vec!["aws".to_string(), "kubectl".to_string()]);
        assert!(
            !tools.contains(&"nmap".to_string()),
            "prose mentions must not count"
        );
        assert!(!tools.contains(&"terraform".to_string()));
    }

    #[test]
    fn detects_commands_after_pipes_and_and() {
        let body = "```bash\ncat f | jq '.x'\ndig +short a.com && curl https://x\n```";
        let tools = detect_required_tools(body);
        for expected in ["jq", "dig", "curl"] {
            assert!(tools.contains(&expected.to_string()), "missing {expected}");
        }
        assert!(!tools.contains(&"cat".to_string()), "cat is not tracked");
    }

    #[test]
    fn arguments_are_not_mistaken_for_commands() {
        // `git` appears as an argument here, not as the command.
        let body = "```bash\ndocker run --rm alpine git\n```";
        let tools = detect_required_tools(body);
        assert_eq!(tools, vec!["docker".to_string()]);
    }

    #[test]
    fn unterminated_fence_does_not_swallow_the_document() {
        let body = "```bash\naws s3 ls\n";
        assert_eq!(detect_required_tools(body), vec!["aws".to_string()]);
    }

    #[test]
    fn resolves_a_tool_that_certainly_exists() {
        // `sh` is present on every platform Truent builds for except Windows.
        if !cfg!(windows) {
            assert!(tool_available("sh"), "sh should resolve on PATH");
        }
        assert!(!tool_available("truent-definitely-not-a-real-binary-xyz"));
    }

    #[test]
    fn preflight_partitions_present_and_missing() {
        let detected = vec![
            "truent-definitely-not-a-real-binary-xyz".to_string(),
            if cfg!(windows) {
                "cmd".into()
            } else {
                "sh".to_string()
            },
        ];
        let p = Preflight::check(&detected);
        assert_eq!(p.missing.len(), 1);
        assert_eq!(p.present.len(), 1);
        assert!(!p.is_satisfied());

        assert!(Preflight::check(&[]).is_satisfied());
    }
}
