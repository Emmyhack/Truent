//! Attack chains: combinations of findings that together form a known attack
//! path.
//!
//! A single finding is a weakness. Two or three in the right shape are an
//! *attack*: a session cookie without `Secure` is a hardening gap, but the
//! same cookie on a site that also serves plain HTTP without redirecting is
//! session hijacking by anyone on the path. This module names those shapes
//! so a report can say "these findings compose" instead of listing them side
//! by side and leaving the composition to the reader.
//!
//! Each [`Chain`] is a sequence of steps; a step is satisfied by *any* of its
//! detector IDs being present in the finding set. A chain is reported when
//! every step is satisfied. This is set logic over what the engines
//! observed, not exploitation — the narrative describes the attack the
//! findings enable, and the `break_at` step is where the cheapest
//! preventive fix cuts it.

use truent_core::Finding;

/// One step of a chain: satisfied by any of the listed detectors.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Step {
    pub role: &'static str,
    pub any_of: &'static [&'static str],
}

/// A named attack path.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct Chain {
    pub id: &'static str,
    pub name: &'static str,
    /// What the attacker does, step by step, if nothing is fixed.
    pub narrative: &'static str,
    /// MITRE ATT&CK tactic sequence.
    pub tactics: &'static [&'static str],
    pub steps: &'static [Step],
    /// Index into `steps` of the cheapest place to break the chain.
    pub break_at: usize,
}

/// A chain whose every step is satisfied by the findings.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainHit {
    pub chain: &'static Chain,
    /// For each step, the detector(s) that satisfied it and how many findings.
    pub satisfied_by: Vec<Vec<(String, usize)>>,
    /// Worst exploitability among the contributing findings.
    pub exploitability: Option<truent_core::exposure::Exploitability>,
}

const fn s(role: &'static str, any_of: &'static [&'static str]) -> Step {
    Step { role, any_of }
}

/// Every chain Truent knows.
pub static CHAINS: &[Chain] = &[
    Chain {
        id: "session-hijack-cleartext",
        name: "Session hijack over cleartext",
        narrative: "An attacker on the path (public Wi-Fi, a compromised router) waits for the victim to load the site over plain HTTP, which is served without redirecting; the session cookie, lacking Secure, is sent in the clear and replayed.",
        tactics: &["Credential Access", "Defense Evasion"],
        steps: &[
            s("cleartext reachable", &["rt_no_https_redirect", "rt_missing_hsts"]),
            s("cookie leaks", &["rt_insecure_cookie", "gen_web_insecure_cookie"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "credential-file-exposure",
        name: "Credentials served to the internet",
        narrative: "A configuration or repository file is fetched anonymously from the web root; it contains credentials that the attacker uses directly against the database, cloud account or third-party API.",
        tactics: &["Reconnaissance", "Credential Access", "Initial Access"],
        steps: &[
            s("file exposed", &["rt_exposed_sensitive_path"]),
            s("credentials in files", &["gen_hardcoded_secret", "gen_private_key_committed"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "injection-to-data-exfiltration",
        name: "Injection reaching a reachable database",
        narrative: "Untrusted input reaches a query; the database it runs against is publicly addressable or unencrypted, so the injection turns into bulk read of the store rather than a single-row leak.",
        tactics: &["Initial Access", "Collection", "Exfiltration"],
        steps: &[
            s("injection", &["gen_sql_injection"]),
            s("data store exposed", &["gen_iac_public_database", "gen_iac_unencrypted_storage"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "ci-takeover-to-supply-chain",
        name: "CI takeover becomes a supply-chain compromise",
        narrative: "A pull request from a fork runs with repository secrets (pwn request / script injection); the attacker exfiltrates the publishing token, or edits an unpinned action, and ships a poisoned release to every downstream user.",
        tactics: &["Initial Access", "Credential Access", "Persistence", "Impact"],
        steps: &[
            s("CI code execution", &["gen_ci_pwn_request", "gen_ci_script_injection"]),
            s("secrets or publish path in reach", &["gen_ci_secret_exposed", "gen_ci_unpinned_action", "gen_hardcoded_secret"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "xss-to-account-takeover",
        name: "Stored/reflected XSS to account takeover",
        narrative: "Script injected through an HTML sink runs in the victim's browser unrestricted by a CSP; the session cookie is readable by script (no HttpOnly) and is sent to the attacker.",
        tactics: &["Execution", "Credential Access"],
        steps: &[
            s("script injection", &["gen_xss_sink"]),
            s("no CSP", &["rt_missing_csp"]),
            s("cookie readable", &["rt_insecure_cookie", "gen_web_insecure_cookie"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "ssrf-to-cloud-credentials",
        name: "SSRF to cloud metadata credentials",
        narrative: "A server-side fetch of an attacker-chosen URL is pointed at the cloud metadata service; the returned role credentials are used with a wildcard IAM policy to take over the account.",
        tactics: &["Initial Access", "Credential Access", "Privilege Escalation"],
        steps: &[
            s("SSRF", &["gen_web_ssrf"]),
            s("over-broad cloud role", &["gen_iac_wildcard_iam"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "container-escape",
        name: "Command injection to host compromise",
        narrative: "A command injection gives code execution inside the container; the container runs as root and privileged (or with host namespaces), so the process escapes to the node.",
        tactics: &["Execution", "Privilege Escalation", "Lateral Movement"],
        steps: &[
            s("code execution", &["gen_command_injection", "gen_code_injection", "gen_unsafe_deserialization"]),
            s("privileged container", &["gen_container_privileged", "gen_docker_root_user"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "exposed-service-no-auth",
        name: "Unauthenticated service reachable from the internet",
        narrative: "A database or cache port is open to the world (observed live) and the infrastructure code that allowed it is in the repository; default-unauthenticated services are read and written directly.",
        tactics: &["Reconnaissance", "Initial Access", "Collection"],
        steps: &[
            s("port open", &["rt_open_port"]),
            s("ingress allowed by IaC", &["gen_iac_open_ingress", "gen_iac_public_database"]),
        ],
        break_at: 1,
    },
    Chain {
        id: "mitm-to-credential-theft",
        name: "Adversary-in-the-middle on a client that skips TLS verification",
        narrative: "A client disables certificate verification; an on-path attacker presents any certificate, terminates TLS, and reads the credentials or tokens the client sends.",
        tactics: &["Credential Access", "Collection"],
        steps: &[
            s("verification disabled", &["gen_tls_verification_disabled"]),
            s("secrets in transit", &["gen_hardcoded_secret", "gen_web_jwt_unverified", "rt_tls_untrusted_cert"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "oracle-manipulation-drain",
        name: "Flash-loan oracle manipulation to protocol drain",
        narrative: "A flash loan moves the spot price the contract reads in the same transaction; with no post-state solvency check, the attacker borrows or mints against the inflated value and repays the loan with the protocol's funds.",
        tactics: &["Impact"],
        steps: &[
            s("manipulable price", &["evm_oracle_spot_price", "evm_oracle_self_trade", "evm_token_balance_manipulation", "sol_oracle_self_trade", "move_oracle_spot_price", "sor_thin_liquidity_oracle_price"]),
            s("no solvency guard", &["evm_missing_post_state_health_check", "evm_conservation_check_absent", "evm_unbacked_synthetic_mint", "move_liquidity_conservation"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "reentrancy-drain",
        name: "Reentrancy with unchecked external calls",
        narrative: "An external call is made before state is updated and its return value is not checked; a malicious receiver re-enters and withdraws repeatedly.",
        tactics: &["Impact"],
        steps: &[
            s("reentrant call", &["evm_reentrancy_classic", "evm_reentrancy_erc20", "evm_reentrancy_via_whitelisted", "evm_readonly_reentrancy", "sor_reentrancy_external_call"]),
            s("unchecked result or ordering", &["evm_unchecked_returns", "evm_state_mutation_ordering"]),
        ],
        break_at: 0,
    },
    Chain {
        id: "admin-key-takeover",
        name: "Single admin key to full protocol control",
        narrative: "One externally-owned key controls upgrades or privileged functions with no timelock; the key is phished or leaked (it may already be in the repository) and the attacker upgrades to a draining implementation instantly.",
        tactics: &["Credential Access", "Persistence", "Impact"],
        steps: &[
            s("single key / no delay", &["evm_single_eoa_admin", "evm_insufficient_multisig_threshold", "sol_admin_no_timelock", "sol_treasury_single_authority", "move_admin_no_timelock"]),
            s("upgrade or privileged path", &["evm_upgrade_path_verification", "evm_unprotected_initializer", "sor_unprotected_upgrade", "sor_no_unprotected_upgrade", "unauthorized_privileged_mutation", "gen_private_key_committed"]),
        ],
        break_at: 0,
    },
];

/// All chains.
pub fn chains() -> &'static [Chain] {
    CHAINS
}

/// Chains whose every step is satisfied by the findings.
pub fn detect(findings: &[Finding]) -> Vec<ChainHit> {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut worst: BTreeMap<&str, truent_core::exposure::Exploitability> = BTreeMap::new();
    for f in findings {
        *counts.entry(f.invariant_id.as_str()).or_default() += 1;
        if let Some(r) = f.exploitability() {
            worst
                .entry(f.invariant_id.as_str())
                .and_modify(|w| {
                    if r.exploitability > *w {
                        *w = r.exploitability
                    }
                })
                .or_insert(r.exploitability);
        }
    }
    let mut hits = Vec::new();
    for chain in CHAINS {
        let mut satisfied_by = Vec::with_capacity(chain.steps.len());
        let mut ok = true;
        for step in chain.steps {
            let by: Vec<(String, usize)> = step
                .any_of
                .iter()
                .filter_map(|id| counts.get(id).map(|n| (id.to_string(), *n)))
                .collect();
            if by.is_empty() {
                ok = false;
                break;
            }
            satisfied_by.push(by);
        }
        if ok {
            let exploitability = satisfied_by
                .iter()
                .flatten()
                .filter_map(|(id, _)| worst.get(id.as_str()).copied())
                .max();
            hits.push(ChainHit {
                chain,
                satisfied_by,
                exploitability,
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use truent_core::taxonomy::taxonomy_for;
    use truent_core::{Finding, Severity};

    fn f(id: &str) -> Finding {
        Finding::new(
            id.into(),
            Severity::High,
            "x".into(),
            1,
            0,
            "m".into(),
            "s".into(),
        )
    }

    #[test]
    fn every_step_names_real_detectors() {
        for c in CHAINS {
            assert!(!c.steps.is_empty(), "{}", c.id);
            assert!(
                c.break_at < c.steps.len(),
                "{}: break_at out of range",
                c.id
            );
            for st in c.steps {
                assert!(!st.any_of.is_empty(), "{}: empty step", c.id);
                for id in st.any_of {
                    assert!(
                        taxonomy_for(id).is_some(),
                        "{}: unknown detector {id}",
                        c.id
                    );
                }
            }
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<&str> = CHAINS.iter().map(|c| c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), CHAINS.len());
    }

    #[test]
    fn chain_requires_every_step() {
        assert!(detect(&[f("rt_no_https_redirect")]).is_empty());
        let hits = detect(&[f("rt_no_https_redirect"), f("rt_insecure_cookie")]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].chain.id, "session-hijack-cleartext");
        assert_eq!(hits[0].satisfied_by[1][0].0, "rt_insecure_cookie");
    }

    #[test]
    fn any_of_semantics_and_counts() {
        let hits = detect(&[
            f("gen_ci_script_injection"),
            f("gen_ci_unpinned_action"),
            f("gen_ci_unpinned_action"),
        ]);
        let h = hits
            .iter()
            .find(|h| h.chain.id == "ci-takeover-to-supply-chain")
            .unwrap();
        assert_eq!(
            h.satisfied_by[1],
            vec![("gen_ci_unpinned_action".to_string(), 2)]
        );
    }

    #[test]
    fn exploitability_is_the_worst_contributor() {
        let hits = detect(&[
            f("rt_no_https_redirect").proven(),
            f("rt_insecure_cookie").proven(),
        ]);
        assert_eq!(
            hits[0].exploitability,
            Some(truent_core::exposure::Exploitability::Likely)
        );
    }

    #[test]
    fn unrelated_findings_form_no_chain() {
        assert!(detect(&[f("gen_weak_hash"), f("rt_server_banner")]).is_empty());
    }
}
