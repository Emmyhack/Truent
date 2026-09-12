//! The pathway table.

/// Where in the lifecycle a pathway's controls mostly live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Design,
    Build,
    Deploy,
    Runtime,
    Response,
    Recovery,
}

/// How one control within a pathway is realised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum Coverage {
    /// A detector `invariant_id`, engine-verified.
    Native(&'static str),
    /// A skill subdomain in a hosted library.
    Hosted(&'static str),
    /// A checklist item for the assessor.
    Assess(&'static str),
}

/// One class from the security model.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Pathway {
    pub id: &'static str,
    pub name: &'static str,
    pub purpose: &'static str,
    pub stage: Stage,
    pub controls: &'static [Coverage],
}

use Coverage::{Assess as A, Hosted as H, Native as N};
use Stage::*;

/// Every class in the model. Keep alphabetical by `id`.
pub static PATHWAYS: &[Pathway] = &[
    Pathway { id: "api-security", name: "API Security", purpose: "Protect application interfaces", stage: Build, controls: &[
        N("gen_object_level_auth_missing"), N("gen_mass_assignment"), N("gen_missing_rate_limit"), N("gen_unbounded_query_limit"), N("gen_graphql_unrestricted"), N("gen_websocket_no_origin_check"), N("gen_open_redirect"),
        N("gen_web_jwt_unverified"), N("gen_web_cors_wildcard"), N("gen_web_ssrf"), N("gen_sql_injection"), N("gen_hardcoded_secret"),
        H("api-security"), A("Object-level authorization is enforced on every resource route"), A("Rate limits and quotas are applied per principal"), A("Webhooks and inter-service requests are signed and replay-protected"), A("An API inventory exists and unknown routes are alerted on"),
    ]},
    Pathway { id: "application-security", name: "Application Security", purpose: "Protect application code and behaviour", stage: Build, controls: &[
        N("gen_upload_unvalidated"), N("gen_xxe"), N("gen_regex_dos"), N("gen_error_detail_exposed"), N("gen_toctou_file"), N("gen_insecure_temp_file"), N("gen_insecure_file_permissions"), N("gen_non_atomic_multi_write"),
        N("gen_command_injection"), N("gen_code_injection"), N("gen_sql_injection"), N("gen_xss_sink"), N("gen_unsafe_deserialization"), N("gen_web_path_traversal"), N("gen_web_ssrf"), N("gen_web_csrf_disabled"), N("gen_web_insecure_cookie"), N("gen_web_debug_enabled"), N("gen_weak_hash"), N("gen_insecure_randomness"), N("gen_hardcoded_secret"),
        H("application-security"), H("web-application-security"), A("File uploads are validated by type, size and content and stored outside the web root"), A("Error handling never returns stack traces or internal identifiers to clients"),
    ]},
    Pathway { id: "architecture-security", name: "Architecture Security", purpose: "Build secure systems by design", stage: Design, controls: &[
        N("gen_container_privileged"), N("gen_iac_open_ingress"), N("gen_iac_wildcard_iam"),
        H("zero-trust-architecture"), H("zero-trust"), A("Trust boundaries are drawn and every crossing authenticates and authorizes (truent threat-model)"), A("Blast radius is bounded: one compromised component cannot reach the data store directly"), A("Defaults fail closed; a missing config denies rather than allows"),
    ]},
    Pathway { id: "attack-surface-management", name: "Attack Surface Management", purpose: "Find exposed assets", stage: Runtime, controls: &[
        N("gen_iac_open_ingress"), N("gen_iac_public_storage"), N("gen_iac_public_database"), N("rt_open_port"), N("rt_exposed_sensitive_path"), N("rt_server_banner"),
        H("vulnerability-management"), H("network-security"), A("Internet-facing assets, subdomains and certificates are enumerated continuously and diffed"), A("Shadow infrastructure is reconciled against the asset inventory"),
    ]},
    Pathway { id: "backup-recovery", name: "Backup and Recovery", purpose: "Restore systems and data", stage: Recovery, controls: &[
        H("ransomware-defense"), A("Backups are automated, immutable, versioned and geographically separated"), A("Restores are tested on a schedule and the last test date is recorded"), A("Database snapshots are taken before every migration"),
    ]},
    Pathway { id: "cloud-security", name: "Cloud Security", purpose: "Protect cloud environments", stage: Deploy, controls: &[
        N("gen_iac_public_storage"), N("gen_iac_open_ingress"), N("gen_iac_unencrypted_storage"), N("gen_iac_wildcard_iam"), N("gen_iac_public_database"), N("gen_hardcoded_secret"),
        H("cloud-security"), A("CSPM continuously evaluates the live account against a benchmark (CIS); IaC findings here are the pre-deploy half"), A("Cloud IAM permissions are reviewed for excess and unused grants (CIEM)"), A("Cloud audit logging is enabled in every account and region and shipped off-account"),
    ]},
    Pathway { id: "container-security", name: "Container Security", purpose: "Protect containerized workloads", stage: Deploy, controls: &[
        N("gen_docker_root_user"), N("gen_docker_unpinned_base"), N("gen_pipe_to_shell"), N("gen_container_privileged"),
        H("container-security"), A("Images are scanned for CVEs and signed before admission (cosign/sigstore)"), A("Runtime profiles (seccomp, AppArmor) and read-only root filesystems are enforced"),
    ]},
    Pathway { id: "data-security", name: "Data Security", purpose: "Protect sensitive information", stage: Build, controls: &[
        N("gen_iac_unencrypted_storage"), N("gen_tls_verification_disabled"), N("gen_weak_hash"), N("gen_private_key_committed"),
        H("data-protection"), H("cryptography"), H("privacy-compliance"), A("Data is classified and the classification drives encryption, retention and access"), A("Field-level encryption or tokenization covers regulated fields"), A("DLP controls cover endpoints, email and cloud storage for classified data"),
    ]},
    Pathway { id: "database-security", name: "Database Security", purpose: "Protect stored application data", stage: Build, controls: &[
        N("gen_sql_injection"), N("gen_iac_public_database"), N("gen_iac_unencrypted_storage"), N("gen_hardcoded_secret"),
        A("Database roles follow least privilege; the application role cannot alter schema"), A("Row-level security or tenant scoping is enforced in the database, not only the application"), A("Database activity is audited and backups are encrypted"),
    ]},
    Pathway { id: "detection-engineering", name: "Detection Engineering", purpose: "Identify malicious activity", stage: Runtime, controls: &[
        N("gen_missing_security_logging"), N("gen_log_sensitive_data"), N("gen_log_injection"),
        H("threat-detection"), H("threat-hunting"), H("soc-operations"), H("security-operations"), H("threat-intelligence"), A("Detections exist for suspicious login, privilege escalation, credential abuse, exfiltration, persistence and lateral movement, each mapped to ATT&CK"), A("Every detection has a tested, documented response"),
    ]},
    Pathway { id: "devsecops", name: "DevSecOps", purpose: "Integrate security into development", stage: Build, controls: &[
        N("gen_ci_pwn_request"), N("gen_ci_script_injection"), N("gen_ci_secret_exposed"), N("gen_ci_unpinned_action"), N("gen_hardcoded_secret"), N("sca_vulnerable_dependency"), N("sca_missing_lockfile"),
        H("devsecops"), A("truent scan --chain auto, truent deps and truent gate run on every pull request and block on Critical/High"), A("Branch protection requires review and passing checks; force-push to protected branches is disabled"),
    ]},
    Pathway { id: "identity-security", name: "Identity and Access Management", purpose: "Protect users and machine identities", stage: Design, controls: &[
        N("gen_missing_rate_limit"), N("gen_object_level_auth_missing"),
        N("gen_web_jwt_unverified"), N("gen_hardcoded_secret"), N("gen_iac_wildcard_iam"), N("evm_single_eoa_admin"), N("evm_insufficient_multisig_threshold"),
        H("identity-access-management"), H("identity-and-access-management"), H("identity-security"), A("MFA or passkeys are required for every human account; privileged access is just-in-time"), A("Service accounts and workload identities use short-lived credentials, not static keys"), A("RBAC/ABAC policies are reviewed quarterly for excess privilege"),
    ]},
    Pathway { id: "incident-response", name: "Incident Response", purpose: "Contain and recover from attacks", stage: Response, controls: &[
        H("incident-response"), H("digital-forensics"), H("malware-analysis"), A("Isolation, credential revocation and attacker blocking each have a rehearsed runbook and an owner"), A("Evidence is preserved before remediation (logs, images, traces)"), A("truent-ir covers on-chain incidents; SOAR playbooks cover accounts, endpoints and containers"),
    ]},
    Pathway { id: "kubernetes-security", name: "Kubernetes Security", purpose: "Protect orchestrated workloads", stage: Deploy, controls: &[
        N("gen_container_privileged"),
        H("container-security"), A("Pod Security Standards (restricted) are enforced by an admission controller"), A("NetworkPolicies default-deny between namespaces"), A("Kubernetes RBAC grants no cluster-admin to workloads; service-account tokens are not auto-mounted"), A("Secrets are stored in an external manager, not in plain Secret objects"),
    ]},
    Pathway { id: "network-security", name: "Network Security", purpose: "Protect network communication", stage: Runtime, controls: &[
        N("gen_iac_open_ingress"), N("gen_tls_verification_disabled"), N("rt_tls_expired"), N("rt_tls_untrusted_cert"), N("rt_tls_weak_protocol"), N("rt_missing_hsts"), N("rt_no_https_redirect"),
        H("network-security"), H("zero-trust-architecture"), A("Egress is restricted by allowlist; workloads cannot reach arbitrary internet hosts"), A("Service-to-service traffic is mutually authenticated (mTLS / service mesh)"), A("IDS/IPS or flow monitoring covers every network segment"),
    ]},
    Pathway { id: "penetration-testing", name: "Penetration Testing", purpose: "Simulate attacks", stage: Runtime, controls: &[
        N("rt_exposed_sensitive_path"), N("rt_tls_untrusted_cert"), N("rt_tls_weak_protocol"), N("rt_open_port"), N("rt_no_https_redirect"),
        H("penetration-testing"), H("red-teaming"), H("red-team"), H("offensive-security"), H("purple-team"), A("Web, API, cloud and internal tests are performed at least annually and after major changes; findings feed the regression corpus"),
    ]},
    Pathway { id: "resilience", name: "Availability and Resilience", purpose: "Keep systems available", stage: Runtime, controls: &[
        N("evm_unbounded_loop"), N("evm_push_payment_in_loop"), N("evm_missing_pause_mechanism"), N("gen_regex_dos"), N("gen_missing_rate_limit"),
        N("evm_division_by_zero"), N("sor_unhandled_panic"), N("sol_rent_exemption_check"),
        A("Rate limiting, circuit breakers and backpressure protect every public entry point"), A("DDoS protection (CDN/anycast/scrubbing) fronts public services"), A("Failover is automated and RTO/RPO are measured, not assumed"),
    ]},
    Pathway { id: "runtime-security", name: "Runtime Security", purpose: "Detect attacks during execution", stage: Runtime, controls: &[
        N("rt_missing_csp"), N("rt_missing_frame_options"), N("rt_missing_content_type_options"), N("rt_insecure_cookie"),
        H("endpoint-security"), H("container-security"), H("soc-operations"), A("EDR covers servers and developer machines; container runtime security (Falco/Tetragon) alerts on shells, unexpected processes and outbound connections"), A("WAF/RASP fronts web applications with rules tuned to the application"),
    ]},
    Pathway { id: "supply-chain-security", name: "Supply-Chain Security", purpose: "Protect dependencies and build pipelines", stage: Build, controls: &[
        N("sca_dependency_confusion"), N("sca_typosquat_candidate"), N("sca_lockfile_missing_integrity"), N("sca_install_script_dependency"), N("gen_ci_unsigned_release"),
        N("sca_vulnerable_dependency"), N("sca_unmaintained_dependency"), N("sca_unpinned_dependency"), N("sca_missing_lockfile"), N("gen_ci_unpinned_action"), N("gen_docker_unpinned_base"), N("gen_pipe_to_shell"), N("gen_ci_pwn_request"),
        H("supply-chain-security"), H("devsecops"), A("Artifacts are signed and carry build provenance (SLSA); an SBOM ships with every release (truent deps --sbom)"), A("Commits are signed and builds are reproducible"),
    ]},
    Pathway { id: "vulnerability-management", name: "Vulnerability Management", purpose: "Find and remediate weaknesses", stage: Runtime, controls: &[
        N("sca_vulnerable_dependency"), N("gen_docker_unpinned_base"), N("rt_server_banner"), N("rt_tls_expired"),
        H("vulnerability-management"), A("Findings are prioritized by exploitability (EPSS/KEV) and tracked to closure with SLAs by severity"), A("Patches are verified by re-scan, not by ticket state"),
    ]},
    Pathway { id: "web-security", name: "Web Security", purpose: "Protect browser-facing applications", stage: Build, controls: &[
        N("gen_xss_sink"), N("gen_web_cors_wildcard"), N("gen_web_insecure_cookie"), N("gen_web_csrf_disabled"), N("gen_web_debug_enabled"), N("gen_tls_verification_disabled"),
        H("web-application-security"), A("HSTS, CSP and the standard security headers are set and verified in production responses"), A("A WAF and bot/DDoS protection front the site"),
    ]},
];

/// Every pathway.
pub fn pathways() -> &'static [Pathway] {
    PATHWAYS
}

/// One pathway by id.
pub fn pathway(id: &str) -> Option<&'static Pathway> {
    PATHWAYS.iter().find(|p| p.id == id)
}

/// Subdomains that exist in the reference hosted library. A pathway may only
/// route to one of these.
pub const KNOWN_SKILL_SUBDOMAINS: &[&str] = &[
    "ai-security",
    "api-security",
    "application-security",
    "blockchain-security",
    "cloud-security",
    "compliance-governance",
    "container-security",
    "cryptography",
    "data-protection",
    "deception-technology",
    "devsecops",
    "digital-forensics",
    "endpoint-security",
    "firmware-analysis",
    "firmware-security",
    "governance-risk-compliance",
    "hardware-firmware-security",
    "identity-access-management",
    "identity-and-access-management",
    "identity-security",
    "incident-response",
    "malware-analysis",
    "mobile-security",
    "network-security",
    "offensive-security",
    "ot-ics-security",
    "ot-security",
    "penetration-testing",
    "phishing-defense",
    "privacy-compliance",
    "purple-team",
    "ransomware-defense",
    "red-team",
    "red-teaming",
    "security-operations",
    "soc-operations",
    "social-engineering-defense",
    "supply-chain-security",
    "threat-detection",
    "threat-hunting",
    "threat-intelligence",
    "vulnerability-management",
    "web-application-security",
    "wireless-security",
    "zero-trust",
    "zero-trust-architecture",
];

#[cfg(test)]
mod tests {
    use super::*;
    use truent_core::taxonomy::taxonomy_for;

    #[test]
    fn every_native_control_is_a_known_detector() {
        for p in PATHWAYS {
            for c in p.controls {
                if let Coverage::Native(id) = c {
                    assert!(
                        taxonomy_for(id).is_some(),
                        "{}: native control {id} is not a detector the taxonomy knows",
                        p.id
                    );
                }
            }
        }
    }

    #[test]
    fn every_hosted_control_is_a_real_subdomain() {
        for p in PATHWAYS {
            for c in p.controls {
                if let Coverage::Hosted(s) = c {
                    assert!(
                        KNOWN_SKILL_SUBDOMAINS.contains(s),
                        "{}: hosted subdomain {s} does not exist",
                        p.id
                    );
                }
            }
        }
    }

    #[test]
    fn pathways_are_sorted_unique_and_non_empty() {
        let ids: Vec<&str> = PATHWAYS.iter().map(|p| p.id).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted);
        assert_eq!(
            ids.len(),
            ids.iter().collect::<std::collections::BTreeSet<_>>().len()
        );
        for p in PATHWAYS {
            assert!(!p.controls.is_empty(), "{} has no controls", p.id);
            assert!(
                p.controls.iter().any(|c| !matches!(c, Coverage::Assess(_))),
                "{}: every control is manual — nothing routes to Truent",
                p.id
            );
        }
    }

    #[test]
    fn the_model_is_complete() {
        // The 21 classes of the security model, plus resilience.
        for id in [
            "application-security",
            "web-security",
            "api-security",
            "identity-security",
            "architecture-security",
            "devsecops",
            "supply-chain-security",
            "cloud-security",
            "container-security",
            "kubernetes-security",
            "network-security",
            "data-security",
            "database-security",
            "runtime-security",
            "detection-engineering",
            "vulnerability-management",
            "attack-surface-management",
            "penetration-testing",
            "resilience",
            "incident-response",
            "backup-recovery",
        ] {
            assert!(pathway(id).is_some(), "missing pathway {id}");
        }
    }
}
