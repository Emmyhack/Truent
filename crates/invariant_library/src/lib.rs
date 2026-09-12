#![deny(unsafe_code)]
#![allow(missing_docs)]

//! Invariant library: Load invariants from TOML files.

pub mod coverage;
pub mod library;
pub mod loader;

pub use coverage::{advisory_only, coverage_for, Coverage, COVERAGE};
pub use library::InvariantLibrary;
pub use loader::LibraryLoader;
