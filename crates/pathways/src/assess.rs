//! Assessment: findings + installed skills → per-pathway coverage report.

use std::collections::{BTreeMap, BTreeSet};

use truent_core::Finding;

use crate::map::{Coverage, PATHWAYS};

/// One pathway's assessed state.
#[derive(Debug, serde::Serialize)]
pub struct PathwayResult {
    pub id: &'static str,
    pub name: &'static str,
    pub stage: crate::map::Stage,
    /// Native detectors that ran, and how many findings each produced.
    pub native: Vec<(&'static str, usize)>,
    /// Hosted subdomains, and how many installed skills each has.
    pub hosted: Vec<(&'static str, usize)>,
    /// Manual checklist.
    pub assess: Vec<&'static str>,
    pub total_findings: usize,
}

/// The whole assessment.
#[derive(Debug, serde::Serialize)]
pub struct Assessment {
    pub pathways: Vec<PathwayResult>,
    pub native_detectors: usize,
    pub hosted_subdomains: usize,
    pub hosted_subdomains_installed: usize,
    pub manual_controls: usize,
}

/// Build the assessment from scan findings and the installed-skill counts by
/// subdomain (`None` when no skill catalog is available).
pub fn assess(
    findings: &[Finding],
    skills_by_subdomain: Option<&BTreeMap<String, usize>>,
) -> Assessment {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(f.invariant_id.as_str()).or_default() += 1;
    }

    let mut all_native = BTreeSet::new();
    let mut all_hosted = BTreeSet::new();
    let mut manual = 0usize;
    let mut out = Vec::new();

    for p in PATHWAYS {
        let mut r = PathwayResult {
            id: p.id,
            name: p.name,
            stage: p.stage,
            native: vec![],
            hosted: vec![],
            assess: vec![],
            total_findings: 0,
        };
        for c in p.controls {
            match c {
                Coverage::Native(id) => {
                    let n = counts.get(id).copied().unwrap_or(0);
                    r.native.push((id, n));
                    r.total_findings += n;
                    all_native.insert(*id);
                }
                Coverage::Hosted(s) => {
                    let n = skills_by_subdomain
                        .and_then(|m| m.get(*s))
                        .copied()
                        .unwrap_or(0);
                    r.hosted.push((s, n));
                    all_hosted.insert(*s);
                }
                Coverage::Assess(text) => {
                    r.assess.push(text);
                    manual += 1;
                }
            }
        }
        out.push(r);
    }

    let installed = skills_by_subdomain
        .map(|m| {
            all_hosted
                .iter()
                .filter(|s| m.get(**s).copied().unwrap_or(0) > 0)
                .count()
        })
        .unwrap_or(0);

    Assessment {
        pathways: out,
        native_detectors: all_native.len(),
        hosted_subdomains: all_hosted.len(),
        hosted_subdomains_installed: installed,
        manual_controls: manual,
    }
}

impl Assessment {
    /// Markdown report.
    pub fn to_markdown(&self, target: &str) -> String {
        let mut s = String::new();
        s.push_str(&format!("# Security assessment — {target}\n\n"));
        s.push_str("Every pathway in the software / web / system / cloud security model, and how it is covered here.\n\n");
        s.push_str(&format!(
            "- **Native**: {} engine-verified detectors ran over the repository.\n",
            self.native_detectors
        ));
        s.push_str(&format!("- **Hosted**: {} skill subdomains route to expert workflows; {} have skills installed (`truent skills source suggest`).\n", self.hosted_subdomains, self.hosted_subdomains_installed));
        s.push_str(&format!("- **Manual**: {} controls can only be verified against the live system and are listed for the assessor.\n\n", self.manual_controls));
        s.push_str("| Pathway | Stage | Native findings | Hosted skills | Manual controls |\n|---|---|---|---|---|\n");
        for p in &self.pathways {
            let hosted: usize = p.hosted.iter().map(|(_, n)| *n).sum();
            s.push_str(&format!(
                "| {} | {:?} | {} | {} | {} |\n",
                p.name,
                p.stage,
                p.total_findings,
                hosted,
                p.assess.len()
            ));
        }
        for p in &self.pathways {
            s.push_str(&format!("\n## {} — {:?}\n\n", p.name, p.stage));
            if !p.native.is_empty() {
                s.push_str("**Native (engine-verified)**\n\n");
                for (id, n) in &p.native {
                    s.push_str(&format!("- `{id}` — {n} finding(s)\n"));
                }
                s.push('\n');
            }
            if !p.hosted.is_empty() {
                s.push_str("**Hosted skills**\n\n");
                for (sd, n) in &p.hosted {
                    s.push_str(&format!("- `{sd}` — {n} installed\n"));
                }
                s.push('\n');
            }
            if !p.assess.is_empty() {
                s.push_str("**Verify against the live system**\n\n");
                for a in &p.assess {
                    s.push_str(&format!("- [ ] {a}\n"));
                }
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use truent_core::{Finding, Severity};

    #[test]
    fn findings_are_attributed_to_every_pathway_that_lists_the_detector() {
        let f = vec![Finding::new(
            "gen_sql_injection".into(),
            Severity::High,
            "a.py".into(),
            1,
            0,
            "m".into(),
            "s".into(),
        )];
        let a = assess(&f, None);
        let api = a.pathways.iter().find(|p| p.id == "api-security").unwrap();
        let db = a
            .pathways
            .iter()
            .find(|p| p.id == "database-security")
            .unwrap();
        assert_eq!(api.total_findings, 1);
        assert_eq!(db.total_findings, 1);
        assert!(a.manual_controls > 20);
        assert!(a.to_markdown("x").contains("| API Security |"));
    }
}
