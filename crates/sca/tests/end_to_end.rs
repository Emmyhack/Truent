use std::path::Path;
use truent_sca::{analyze, AdvisoryDb};

fn fx(p: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(p)
}

#[test]
fn matches_known_vulnerable_pins_and_nothing_else() {
    let db = AdvisoryDb::load_dir(&fx("advisories")).unwrap();
    assert_eq!(db.len(), 2);
    let r = analyze(&fx("project"), Some(&db));
    assert_eq!(r.lockfiles.len(), 2, "{:?}", r.lockfiles);
    let vulns: Vec<&truent_core::Finding> = r
        .findings
        .iter()
        .filter(|f| f.invariant_id == "sca_vulnerable_dependency")
        .collect();
    assert_eq!(vulns.len(), 2, "{:?}", r.findings);
    assert!(vulns
        .iter()
        .any(|f| f.message.contains("lodash 4.17.20") && f.message.contains("CVE-2020-8203")));
    assert!(vulns.iter().any(
        |f| f.message.contains("django 4.2.5") && f.severity == truent_core::Severity::Critical
    ));
    // express 4.18.2 and requests 2.31.0 have no advisory in this DB.
    assert!(!r
        .findings
        .iter()
        .any(|f| f.message.contains("express") || f.message.contains("requests")));
    // pins are exact and the lockfile exists: no pinning findings.
    assert!(!r
        .findings
        .iter()
        .any(|f| f.invariant_id.starts_with("sca_unpinned")
            || f.invariant_id == "sca_missing_lockfile"));
}

#[test]
fn without_a_database_no_vulnerability_claims_are_made() {
    let r = analyze(&fx("project"), None);
    assert!(r.advisory_source.is_none());
    assert!(r
        .findings
        .iter()
        .all(|f| f.invariant_id != "sca_vulnerable_dependency"));
    assert_eq!(r.packages.len(), 4);
}

#[test]
fn sbom_lists_every_package() {
    let r = analyze(&fx("project"), None);
    let doc = truent_sca::sbom::cyclonedx(&r.packages, "fixture", "0.6.0");
    assert_eq!(doc["components"].as_array().unwrap().len(), 4);
}
