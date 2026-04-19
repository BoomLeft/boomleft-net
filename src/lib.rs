//! BoomLeft family shared network-layer.
//!
//! Sibling crate to [`privacysuite-core-sdk`](https://github.com/mkfnch/PrivacySuite-Core-SDK)
//! consolidating higher-level network-facing parsers and utilities used
//! by multiple BoomLeft applications. The SDK supplies the cryptographic
//! foundation and the canonical tracking-parameter blocklist;
//! `boomleft-net` supplies everything above the crypto layer but below
//! the app-specific UI.
//!
//! # Scope (v0.1.0)
//!
//! - [`feed_parser`] — RSS 2.0 + Podcast Namespace 2.0 parser. Ported
//!   from `boomleft-podcasts` as the canonical family-wide feed parser.
//!
//! # Future scope
//!
//! - `opml` — OPML v1/v2 import/export (Phase 3 Wave 1, from
//!   boomleft-rss).
//! - `geo` — coordinate truncation + haversine distance (Phase 3+, from
//!   boomleft-weather / Shadow-Atlas).
//!
//! # Discipline
//!
//! - `#![forbid(unsafe_code)]`, `#![deny(warnings)]`.
//! - All dependencies `=`-pinned.
//! - Same `deny.toml` ban list as the SDK (no telemetry, no openssl,
//!   no unmaintained crypto).

#![forbid(unsafe_code)]
#![deny(warnings)]
// Crate-wide `clippy::pedantic` allow list. Each entry is motivated:
//
// * `doc_markdown` — docs contain protocol acronyms (HTTPS, SSRF, RFC-1918,
//   MIME, SRT, VTT, APIPA, CGN, XSS, ...) that aren't backticked. Back-
//   ticking them all would bury the prose in markup for no reader benefit.
// * `too_many_lines` — `parse_bytes` fans out over every field of
//   `ParsedPodcast`; splitting it would hurt readability of the single
//   linear transformation.
// * `similar_names` — the XML scanner uses `content_start`/`close_start`
//   and similar pairs; they describe distinct boundaries.
// * `module_name_repetitions` — `feed_parser::ParsedPodcast` exposes types
//   whose names deliberately include the module's subject matter.
#![allow(
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::module_name_repetitions
)]

pub mod feed_parser;

// Re-export modules that feed_parser publicly references, so consumers
// that only `use boomleft_net::feed_parser` can still name the types
// that end up on `ParsedPodcast` / `ParsedEpisode`.
pub mod podcast_ns2;
pub mod url_sanitizer;
