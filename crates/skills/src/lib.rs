#![deny(unsafe_code)]

//! Truent's skill runtime.
//!
//! Truent's own analysis is deterministic: the engine runs the contract and
//! reports what it observed. Most security work is not like that — triaging a
//! cloud breach or hunting DNS tunnelling means driving `aws`, `kubectl`,
//! `tshark` and a SIEM, and no compiled analyzer replaces that.
//!
//! This crate lets Truent **host** those capabilities instead of pretending to
//! implement them. A skill library following the [agentskills.io] standard is
//! registered as a *source*, cloned into a cache, indexed, preflighted against
//! the tools actually installed, and run on request.
//!
//! Two properties are deliberate:
//!
//! 1. **Sources are cloned, never vendored.** The library stays in its own
//!    repository under its own licence and updates with `git pull`. Copying a
//!    third-party catalogue into Truent would fork it on day one.
//! 2. **Third-party output is [`Trust::Advisory`], never engine-backed.**
//!    Truent's whole claim is that it does not present as verified anything it
//!    did not verify. Running someone else's script does not make its output
//!    reproducible, and the label says so every time.
//!
//! [agentskills.io]: https://agentskills.io

pub mod catalog;
pub mod preflight;
pub mod skill;
pub mod source;

use std::path::PathBuf;

pub use catalog::{builtin_skills_dir, default_root, register, suggested_sources, Catalog};
pub use preflight::{tool_available, which, Preflight};
pub use skill::{Skill, SkillScript, Trust};
pub use source::{
    clone_source, source_revision, update_source, validate_name, validate_skills_dir, SkillSource,
    SourceRegistry,
};

/// Errors from loading, registering or running skills.
#[derive(Debug, thiserror::Error)]
pub enum SkillError {
    /// Filesystem failure at a path.
    #[error("{0}: {1}")]
    Io(PathBuf, String),

    /// A file exists but could not be understood.
    #[error("{0}: {1}")]
    Malformed(PathBuf, String),

    /// A git invocation failed.
    #[error("git: {0}")]
    Git(String),

    /// A source spec was neither `owner/repo` nor a URL.
    #[error("'{0}' is not a repository — use owner/repo or a full git URL")]
    InvalidSource(String),

    /// A source name or skills directory could escape the cache root.
    ///
    /// These values are joined onto a filesystem path that `source remove`
    /// deletes recursively, so they are validated rather than trusted.
    #[error("invalid name '{0}': {1}")]
    InvalidName(String, String),

    /// No skill by that name.
    #[error("no skill named '{0}'")]
    NotFound(String),

    /// The name matched skills in more than one source.
    #[error("'{name}' exists in {sources:?} — qualify it as <source>:{name}")]
    Ambiguous {
        /// The bare skill name that matched more than once.
        name: String,
        /// The sources it was found in.
        sources: Vec<String>,
    },

    /// The skill has no single obvious entry point to run.
    #[error("{0}")]
    NotRunnable(String),
}
