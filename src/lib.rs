//! BoomLeft family shared network-layer.
//!
//! Sibling crate to [`privacysuite-core-sdk`](https://github.com/BoomLeft/PrivacySuite-Core-SDK).
//! The SDK supplies the cryptographic foundation and tracking-parameter
//! blocklist; this crate supplies parsers and utilities above the crypto
//! layer but below app-specific UI.
//!
//! # Modules
//!
//! - [`feed_parser`] — RSS 2.0 + Podcast Namespace 2.0 parser.
//! - [`podcast_ns2`] — Podcast Namespace 2.0 XML extension extraction.
//! - [`url_sanitizer`] — URL sanitisation, SSRF guards, tracking-prefix stripping.

#![forbid(unsafe_code)]
#![deny(warnings)]
// Pedantic lint allow list — each entry suppresses a false positive or
// a lint whose "fix" would reduce readability.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::module_name_repetitions,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::map_unwrap_or,
    clippy::manual_range_contains,
    clippy::doc_lazy_continuation,
    clippy::unreadable_literal,
    clippy::needless_pass_by_value
)]

pub mod feed_parser;

pub mod podcast_ns2;
pub mod url_sanitizer;
