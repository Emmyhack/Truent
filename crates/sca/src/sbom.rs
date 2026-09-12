//! CycloneDX 1.5 SBOM generation.

use serde_json::json;

use crate::lockfile::Package;

/// Render packages as a CycloneDX 1.5 JSON document.
pub fn cyclonedx(packages: &[Package], root_name: &str, tool_version: &str) -> serde_json::Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{ "vendor": "Truent", "name": "truent", "version": tool_version }],
            "component": { "type": "application", "name": root_name }
        },
        "components": packages.iter().map(|p| json!({
            "type": "library",
            "name": p.name,
            "version": p.version,
            "purl": p.purl(),
            "bom-ref": p.purl(),
            "properties": [{ "name": "truent:lockfile", "value": p.source_file }]
        })).collect::<Vec<_>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::Ecosystem;

    #[test]
    fn valid_cyclonedx_shape() {
        let p = vec![Package {
            ecosystem: Ecosystem::Npm,
            name: "lodash".into(),
            version: "4.17.21".into(),
            source_file: "package-lock.json".into(),
        }];
        let doc = cyclonedx(&p, "app", "0.6.0");
        assert_eq!(doc["bomFormat"], "CycloneDX");
        assert_eq!(doc["specVersion"], "1.5");
        assert_eq!(doc["components"][0]["purl"], "pkg:npm/lodash@4.17.21");
    }
}
