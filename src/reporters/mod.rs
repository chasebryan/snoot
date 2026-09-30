//! Reporters: render a [`ScanReport`](crate::scanner::ScanReport) for humans and machines.
//!
//! - [`console`] — colored human output with grouping + summary (functional)
//! - [`json`] — plain JSON for piping (functional)
//! - [`sarif`] — SARIF 2.1.0 for GitHub code scanning / PR annotations
//! - [`cbom`] — CycloneDX 1.6 CBOM, the compliance artifact auditors want

pub mod cbom;
pub mod console;
pub mod json;
pub mod sarif;
