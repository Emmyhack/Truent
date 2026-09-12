//! Dockerfile and Kubernetes / docker-compose hardening.

use lazy_static::lazy_static;
use regex::Regex;
use truent_core::{Finding, Severity};

use crate::finding;
use crate::text::strip_hash_comment;

lazy_static! {
    static ref FROM: Regex =
        Regex::new(r"(?i)^\s*FROM\s+(--platform=\S+\s+)?(\S+)(\s+AS\s+\S+)?").unwrap();
    static ref USER: Regex = Regex::new(r"(?i)^\s*USER\s+(\S+)").unwrap();
    static ref PIPE_TO_SHELL: Regex =
        Regex::new(r"(?i)\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b").unwrap();
    static ref ADD_URL: Regex = Regex::new(r"(?i)^\s*ADD\s+https?://").unwrap();
    static ref PRIVILEGED: Regex = Regex::new(r"(?m)^\s*(-\s*)?privileged\s*:\s*true\b").unwrap();
    static ref HOST_NS: Regex =
        Regex::new(r"(?m)^\s*(hostNetwork|hostPID|hostIPC)\s*:\s*true\b").unwrap();
    static ref PRIV_ESC: Regex =
        Regex::new(r"(?m)^\s*allowPrivilegeEscalation\s*:\s*true\b").unwrap();
    static ref RUN_AS_ROOT: Regex = Regex::new(r"(?m)^\s*runAsUser\s*:\s*0\b").unwrap();
    static ref HOST_NET_MODE: Regex =
        Regex::new(r#"(?m)^\s*network_mode\s*:\s*["']?host["']?"#).unwrap();
    static ref DOCKER_SOCK: Regex = Regex::new(r"/var/run/docker\.sock").unwrap();
}

pub fn detect_dockerfile(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<String> = source.lines().map(strip_hash_comment).collect();

    let mut has_user = false;
    let mut last_from_is_distroless_or_scratch = false;
    let mut stage_names: Vec<String> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        if let Some(c) = FROM.captures(line) {
            let image = c[2].to_string();
            let lower = image.to_lowercase();
            if let Some(alias) = c.get(3) {
                stage_names.push(
                    alias
                        .as_str()
                        .split_whitespace()
                        .last()
                        .unwrap_or("")
                        .to_lowercase(),
                );
            }
            last_from_is_distroless_or_scratch =
                lower == "scratch" || lower.contains("distroless") && lower.contains("nonroot");
            // A stage referencing an earlier stage is not a base image.
            if stage_names.contains(&lower) || lower == "scratch" {
                continue;
            }
            let unpinned = !lower.contains(':') || lower.ends_with(":latest");
            if unpinned && !lower.contains('@') {
                findings.push(finding(
                    "gen_docker_unpinned_base",
                    Severity::Low,
                    file_path,
                    idx,
                    format!("Base image `{image}` is not pinned: builds are not reproducible and silently pick up whatever the tag points to"),
                    line,
                ));
            }
        }
        if let Some(c) = USER.captures(line) {
            if !matches!(&c[1], "root" | "0") {
                has_user = true;
            }
        }
        if PIPE_TO_SHELL.is_match(line) || ADD_URL.is_match(line) {
            findings.push(finding(
                "gen_pipe_to_shell",
                Severity::High,
                file_path,
                idx,
                "Remote content is fetched and executed without integrity verification: a compromised or spoofed source runs arbitrary code in the build",
                line,
            ));
        }
    }

    if !has_user && !last_from_is_distroless_or_scratch && !lines.is_empty() {
        // Anchor at the last FROM, which is the image that actually runs.
        let anchor = lines.iter().rposition(|l| FROM.is_match(l)).unwrap_or(0);
        findings.push(finding(
            "gen_docker_root_user",
            Severity::Medium,
            file_path,
            anchor,
            "Image runs as root: no USER instruction switches to an unprivileged account before the entrypoint",
            &lines[anchor],
        ));
    }

    findings
}

pub fn detect_manifest(source: &str, file_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lines: Vec<String> = source.lines().map(strip_hash_comment).collect();
    let joined = lines.join("\n");

    // Only a manifest that describes workloads. A random YAML file with a
    // `privileged` key is not a cluster.
    let is_workload =
        joined.contains("kind:") || joined.contains("services:") || joined.contains("containers:");
    if !is_workload {
        return findings;
    }

    for (idx, line) in lines.iter().enumerate() {
        let msg = if PRIVILEGED.is_match(line) {
            Some("Container runs privileged: it has every capability and unrestricted device access on the host")
        } else if HOST_NS.is_match(line) {
            Some("Container shares a host namespace: it can see or interfere with host processes and network")
        } else if PRIV_ESC.is_match(line) {
            Some("allowPrivilegeEscalation is enabled: a process in the container can gain more privileges than its parent")
        } else if RUN_AS_ROOT.is_match(line) {
            Some("Container explicitly runs as UID 0")
        } else if HOST_NET_MODE.is_match(line) {
            Some("Service uses the host network namespace")
        } else if DOCKER_SOCK.is_match(line) {
            Some("The Docker socket is mounted into the container: that is root on the host")
        } else {
            None
        };
        if let Some(m) = msg {
            findings.push(finding(
                "gen_container_privileged",
                Severity::High,
                file_path,
                idx,
                m,
                line,
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_dockerfile_is_clean() {
        let d = "FROM golang:1.22.3 AS build\nWORKDIR /src\nRUN go build -o app .\nFROM gcr.io/distroless/static-debian12:nonroot\nCOPY --from=build /src/app /app\nUSER nonroot\nENTRYPOINT [\"/app\"]\n";
        assert!(detect_dockerfile(d, "Dockerfile").is_empty());
    }

    #[test]
    fn root_latest_and_pipe_to_shell_are_flagged() {
        let d = "FROM ubuntu:latest\nRUN curl -sSL https://get.example.com | sh\nCMD [\"app\"]\n";
        let findings = detect_dockerfile(d, "Dockerfile");
        let ids: Vec<&str> = findings.iter().map(|f| f.invariant_id.as_str()).collect();
        assert!(ids.contains(&"gen_docker_root_user"));
        assert!(ids.contains(&"gen_docker_unpinned_base"));
        assert!(ids.contains(&"gen_pipe_to_shell"));
    }

    #[test]
    fn privileged_pod_flagged_and_hardened_pod_clean() {
        let bad = "kind: Pod\nspec:\n  containers:\n    - name: a\n      securityContext:\n        privileged: true\n";
        assert_eq!(detect_manifest(bad, "pod.yaml").len(), 1);
        let good = "kind: Pod\nspec:\n  securityContext:\n    runAsNonRoot: true\n    runAsUser: 1000\n  containers:\n    - name: a\n      securityContext:\n        allowPrivilegeEscalation: false\n        readOnlyRootFilesystem: true\n";
        assert!(detect_manifest(good, "pod.yaml").is_empty());
    }

    #[test]
    fn a_non_workload_yaml_is_ignored() {
        assert!(detect_manifest("privileged: true\n", "settings.yml").is_empty());
    }
}
