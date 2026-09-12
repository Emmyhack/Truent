#![deny(unsafe_code)]

//! The security-pathway map.
//!
//! Modern software security is not one discipline; it is a couple of dozen
//! that a team has to cover across design, build, deploy, runtime, response
//! and recovery. This crate makes Truent the *entry point* for all of them by
//! being honest about how each is covered:
//!
//! - [`Coverage::Native`] — an engine-verified detector runs over the repo.
//! - [`Coverage::Hosted`] — a skill subdomain in a hosted library drives the
//!   real tool (`aws`, `kubectl`, a SIEM) that a static engine cannot replace.
//! - [`Coverage::Assess`] — a control only a person with access to the live
//!   system can verify; listed as a checklist item, never silently skipped.
//!
//! `tests` fail the build if a pathway names a detector the taxonomy does not
//! know, or a skill subdomain that does not exist in the reference library,
//! so a pathway can never claim coverage it does not have.

pub mod acceptance;
pub mod assess;
pub mod chains;
pub mod checklist;
pub mod harden;
pub mod map;
pub mod signals;
pub mod threat_model;

pub use acceptance::{apply as apply_acceptances, load as load_acceptances, Acceptance, Accepted};
pub use assess::{assess, Assessment};
pub use chains::{chains, detect as detect_chains, Chain, ChainHit};
pub use checklist::{
    evaluate as release_check, Inputs as ReleaseInputs, RepoScope, Report as ReleaseReport,
    SECTIONS,
};
pub use harden::{plan as harden_plan, profile as harden_profile, Artifact, Profile};
pub use map::{pathway, pathways, Coverage, Pathway, Stage, PATHWAYS};
pub use signals::{evaluate as repo_signals, RepoView, Signal, SignalResult};
pub use threat_model::{threat_model, ThreatModel};
