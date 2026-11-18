//! Unified detector metadata assembled from taxonomy and exposure profiles.
//!
//! The source tables remain focused on different concerns, but consumers
//! should not repeatedly perform and interpret the join themselves.

use crate::exposure::{exposure_for, Exposure};
use crate::taxonomy::{self, taxonomy_for, Taxonomy};

/// The complete descriptive and remediation metadata for one detector.
#[derive(Debug, Clone, Copy)]
pub struct DetectorMetadata {
    pub taxonomy: &'static Taxonomy,
    pub exposure: &'static Exposure,
}

/// Look up the complete metadata for a detector.
pub fn metadata_for(invariant_id: &str) -> Option<DetectorMetadata> {
    Some(DetectorMetadata {
        taxonomy: taxonomy_for(invariant_id)?,
        exposure: exposure_for(invariant_id)?,
    })
}

/// Iterate over every detector with its exposure profile.
///
/// Completeness is a build invariant enforced by the table tests. Panicking
/// here, instead of silently dropping a row, makes a broken registry visible
/// to every consumer even in a test configuration that skipped those tests.
pub fn all_metadata() -> impl ExactSizeIterator<Item = DetectorMetadata> {
    taxonomy::all().iter().map(|taxonomy| DetectorMetadata {
        taxonomy,
        exposure: exposure_for(taxonomy.invariant_id)
            .unwrap_or_else(|| panic!("{} has no exposure profile", taxonomy.invariant_id)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_view_covers_every_taxonomy_row() {
        let metadata: Vec<_> = all_metadata().collect();
        assert_eq!(metadata.len(), taxonomy::all().len());
        assert!(metadata
            .iter()
            .all(|row| row.taxonomy.invariant_id == row.exposure.invariant_id));
    }

    #[test]
    fn lookup_requires_both_sides_of_the_registry() {
        let row = metadata_for("evm_reentrancy_classic").unwrap();
        assert_eq!(row.taxonomy.primary_cwe().id, 841);
        assert!(row.exposure.fix.contains("state"));
        assert!(metadata_for("not_a_detector").is_none());
    }
}
