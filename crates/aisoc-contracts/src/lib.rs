#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

//! P0 authority for all contracts crossing an AI-SOC trust or service boundary.
//!
//! The Rust types in this crate are the source of truth. JSON Schema files are
//! derived from these types; services must not maintain private DTO copies.

pub mod agent;
pub mod ai;
pub mod audit;
pub mod common;
pub mod control;
pub mod detection;
pub mod error;
pub mod event;
pub mod evidence;
pub mod ids;
pub mod incident;
pub mod response;
pub mod schema;
pub mod web;

pub use agent::*;
pub use ai::*;
pub use audit::*;
pub use common::*;
pub use control::*;
pub use detection::*;
pub use error::*;
pub use event::*;
pub use evidence::*;
pub use ids::*;
pub use incident::*;
pub use response::*;
pub use web::*;

/// Initial frozen contract generation. Breaking changes require a new major
/// schema version and an architecture decision record.
pub const CONTRACT_SCHEMA_VERSION: &str = "1.0.0";
