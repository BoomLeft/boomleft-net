//! Canonical BoomLeft RSS 2.0 + Podcast Namespace 2.0 feed parser.
//!
//! This is the family-wide feed parser, ported from
//! `boomleft-podcasts/src-tauri/src/feed_parser.rs` (488 LOC). It is
//! the single source of truth for how the BoomLeft apps interpret
//! podcast / syndication feeds.
//!
//! # Podcast Namespace 2.0 support
//!
//! The parser surfaces every Podcast Namespace 2.0 tag that the upstream
//! Podcasts app understood, via [`crate::podcast_ns2`]:
//!
//! - `<podcast:chapters>` — external chapter marker file URL + MIME type.
//! - `<podcast:transcript>` — transcript file URL + MIME type (SRT / VTT / JSON).
//! - `<podcast:season>` — season number.
//! - `<podcast:episode>` — episode number.
//! - `<podcast:value>` — value-for-value (Lightning / etc.) payment metadata.
//! - `<podcast:soundbite>` — highlight clips (start + duration + optional title).
//!
//! The Podcast Namespace 2.0 handling is the biggest value-add over
//! vanilla `feed-rs`, which does not expose `podcast:*` extensions.
//!
//! # Expected consumers
//!
//! - **Podcasts** — primary consumer. Ships on SDK `v0.2.0` and will
//!   switch to this module in Phase 3 Wave 1.
//! - **RSS** — migrates from its own parser in Phase 3 Wave 1.
//! - **Music** — MusicBrainz's RSS feed is a different, non-podcast
//!   format (no enclosures, no NS2 extensions). That feed is **not**
//!   consumed by this parser; it has its own typed-XML deserialiser
//!   inside `boomleft-music`.
//!
//! # Port notes (Phase 2, v0.1.0)
//!
//! The upstream `fetch_and_parse` async function — which wrapped
//! `parse_bytes` in the Podcasts app's per-podcast privacy-tier HTTP
//! router — is intentionally NOT ported here. It depended on
//! `crate::privacy::*`, `crate::ohttp::*`, `reqwest`, `tokio`, and
//! `futures_util::StreamExt`, none of which `boomleft-net` 0.1.0 is
//! permitted to introduce. Fetch responsibility belongs to the SDK's
//! forthcoming `PrivacyClient` (gap G1); this parser takes bytes the
//! caller already fetched. See the `PHASE 2 PORT` comment near
//! [`parse_bytes`].

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::podcast_ns2;
use crate::url_sanitizer::{sanitize_audio_url, sanitize_text, strip_tracking_pixels};

// ── Domain Types ──────────────────────────────────────────────────────────────

/// A parsed podcast feed: channel-level metadata plus a list of episodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPodcast {
    /// HTML-escaped podcast title.
    pub title: String,
    /// HTML-escaped author name, if present.
    pub author: Option<String>,
    /// HTML-escaped channel description (with tracking pixels stripped).
    pub description: Option<String>,
    /// Sanitised artwork URL (HTTPS only, http upgraded, no private hosts).
    pub artwork_url: Option<String>,
    /// Language code from `<language>`.
    pub language: Option<String>,
    /// First category term, if any.
    pub category: Option<String>,
    /// Parsed episodes in feed order.
    pub episodes: Vec<ParsedEpisode>,
    /// Podcast Namespace 2.0: `<podcast:value>` payment metadata.
    pub value_tag: Option<podcast_ns2::ValueTag>,
}

/// A parsed episode within a [`ParsedPodcast`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedEpisode {
    /// Stable episode identifier (truncated to 2048 chars).
    pub guid: String,
    /// HTML-escaped title.
    pub title: String,
    /// HTML-escaped description (with tracking pixels stripped).
    pub description: Option<String>,
    /// Sanitised audio URL (analytics prefixes removed, HTTPS-only).
    pub audio_url: String,
    /// Raw audio URL before sanitisation — stored encrypted for debugging.
    pub raw_audio_url: String,
    /// Episode duration in milliseconds, if the media element declared one.
    pub duration_ms: Option<u64>,
    /// Declared enclosure size in bytes (capped at `u32::MAX` to reject
    /// implausibly-large declarations).
    pub file_size: Option<u64>,
    /// `<podcast:chapters>` URL.
    pub chapter_url: Option<String>,
    /// `<podcast:transcript>` URL.
    pub transcript_url: Option<String>,
    /// `<podcast:transcript>` MIME type.
    pub transcript_type: Option<String>,
    /// `<podcast:season>` number.
    pub season: Option<u32>,
    /// `<podcast:episode>` number.
    pub episode_number: Option<u32>,
    /// Published timestamp (unix seconds).
    pub published_at: Option<i64>,
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse already-fetched feed bytes into a [`ParsedPodcast`].
///
/// PHASE 2 PORT: This is the only public entry point in v0.1.0. The
/// upstream `fetch_and_parse` variant (async, uses
/// `privacy::build_client_builder`) was not ported; network fetches are
/// the caller's responsibility. See the module-level doc for details.
///
/// # Errors
///
/// Returns `Err` when `bytes` is not a parseable RSS/Atom feed.
pub fn parse_bytes(bytes: &[u8]) -> Result<ParsedPodcast> {
    let feed = feed_rs::parser::parse(bytes).context("RSS/Atom parse error")?;

    // Also parse the raw XML for Podcast Namespace 2.0 extensions that
    // feed-rs doesn't expose (chapters, transcripts, soundbites, value tags).
    // Strip entity declarations first to prevent Billion Laughs / XXE attacks.
    let raw_xml = std::str::from_utf8(bytes).unwrap_or("");
    let clean_xml = podcast_ns2::strip_entity_declarations(raw_xml);
    let item_blocks = podcast_ns2::split_items(&clean_xml);
    let channel_ns2 = podcast_ns2::parse_podcast_ns2(&clean_xml);

    // All text fields from untrusted feeds are HTML-escaped to prevent XSS
    // when rendered in the WebView.
    let title = sanitize_text(
        &feed.title.as_ref().map(|t| t.content.clone()).unwrap_or_default()
    );

    let description = feed
        .description
        .as_ref()
        .map(|d| sanitize_text(&strip_tracking_pixels(&d.content)));

    let artwork_url = feed
        .logo
        .as_ref()
        .map(|l| l.uri.clone())
        .or_else(|| feed.icon.as_ref().map(|i| i.uri.clone()))
        .and_then(|u| sanitize_optional_url(&u));

    let author = feed
        .authors
        .first()
        .map(|a| a.name.clone())
        .filter(|n| !n.is_empty())
        .map(|n| sanitize_text(&n));

    let language = feed.language.clone();

    let category = feed.categories.first().map(|c| c.term.clone());

    // Pair each feed-rs entry with its raw XML <item> block for NS2 extraction.
    let episodes: Vec<ParsedEpisode> = feed
        .entries
        .into_iter()
        .enumerate()
        .filter_map(|(i, entry)| {
            let ns2_xml = item_blocks.get(i).copied().unwrap_or("");
            parse_episode(entry, ns2_xml)
        })
        .collect();

    Ok(ParsedPodcast {
        title,
        author,
        description,
        artwork_url,
        language,
        category,
        episodes,
        value_tag: channel_ns2.value,
    })
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "duration_ms truncates Duration.as_millis() (u128) to u64; a u64-ms duration covers >500 million years, which is safely beyond any audio file."
)]
fn parse_episode(entry: feed_rs::model::Entry, ns2_xml: &str) -> Option<ParsedEpisode> {
    let enclosure = entry
        .media
        .iter()
        .flat_map(|m| m.content.iter())
        .find(|c| {
            c.content_type
                .as_ref()
                .is_some_and(|ct| ct.ty().as_str() == "audio")
                || c.url
                    .as_ref()
                    .is_some_and(|u| {
                        let s = u.as_str().to_lowercase();
                        s.ends_with(".mp3")
                            || s.ends_with(".m4a")
                            || s.ends_with(".ogg")
                            || s.ends_with(".opus")
                            || s.ends_with(".aac")
                    })
        })?;

    let raw_audio_url = enclosure.url.as_ref().map(ToString::to_string)?;
    let audio_url = sanitize_audio_url(&raw_audio_url);

    let guid = if entry.id.is_empty() {
        audio_url.clone()
    } else {
        entry.id.clone()
    };

    // Truncate GUIDs that are unreasonably long.
    let guid = if guid.len() > 2048 {
        guid.get(..2048).unwrap_or(&guid).to_string()
    } else {
        guid
    };

    let title = sanitize_text(
        &entry.title.as_ref().map(|t| t.content.clone()).unwrap_or_else(|| guid.clone())
    );

    let description = entry
        .summary
        .as_ref()
        .map(|s| sanitize_text(&strip_tracking_pixels(&s.content)));

    let duration_ms = entry
        .media
        .iter()
        .flat_map(|m| m.duration)
        .next()
        .map(|d| d.as_millis() as u64);

    // Guard against implausible file sizes (> 2 GiB cast to i64 would overflow).
    let file_size = enclosure
        .size
        .filter(|&s| s <= u64::from(u32::MAX));

    let published_at = entry
        .published
        .or(entry.updated)
        .map(|dt| dt.timestamp());

    // Podcast Namespace 2.0 fields — extracted from raw XML since feed-rs
    // does not yet surface podcast:* namespace extensions.
    let ns2 = podcast_ns2::parse_episode_ns2(ns2_xml);

    Some(ParsedEpisode {
        guid,
        title,
        description,
        audio_url,
        raw_audio_url,
        duration_ms,
        file_size,
        chapter_url: ns2.chapter_url,
        transcript_url: ns2.transcript_url,
        transcript_type: ns2.transcript_type,
        season: ns2.season,
        episode_number: ns2.episode_number,
        published_at,
    })
}

/// Sanitise an optional artwork / image URL from the feed.
/// Only HTTPS public URLs are accepted; others return None.
fn sanitize_optional_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    let url_str = if parsed.scheme() == "http" {
        url.replacen("http://", "https://", 1)
    } else if parsed.scheme() == "https" {
        url.to_string()
    } else {
        return None;
    };

    // Enforce the SSRF guard on artwork URLs — a malicious feed could
    // point artwork to 169.254.169.254 or a local service, and the
    // webview would make a request to it when rendering the <img> tag.
    if let Some(host) = parsed.host_str() {
        if crate::url_sanitizer::is_private_host(host) {
            return None;
        }
    }

    Some(url_str)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// Minimal RSS 2.0 feed with one audio episode + NS2 extensions for testing.
    fn minimal_rss_feed() -> &'static [u8] {
        br#"<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0" xmlns:podcast="https://podcastindex.org/namespace/1.0">
          <channel>
            <title>Test Podcast</title>
            <description>A test feed</description>
            <language>en</language>
            <podcast:value type="lightning" method="keysend" suggested="500"/>
            <item>
              <title>Episode 1</title>
              <guid>ep-001</guid>
              <description>First episode notes</description>
              <enclosure url="https://cdn.example.com/ep1.mp3" type="audio/mpeg" length="12345678"/>
              <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
              <podcast:chapters url="https://cdn.example.com/ep1-chapters.json" type="application/json+chapters"/>
              <podcast:transcript url="https://cdn.example.com/ep1.srt" type="application/srt"/>
              <podcast:season>2</podcast:season>
              <podcast:episode>5</podcast:episode>
              <podcast:soundbite startTime="30.5" duration="60">Best part</podcast:soundbite>
            </item>
          </channel>
        </rss>"#
    }

    #[test]
    fn test_parse_bytes_extracts_podcast_metadata() {
        let podcast = parse_bytes(minimal_rss_feed()).unwrap();
        assert_eq!(podcast.title, "Test Podcast");
        assert_eq!(podcast.description.as_deref(), Some("A test feed"));
        assert_eq!(podcast.language.as_deref(), Some("en"));
    }

    #[test]
    fn test_parse_bytes_extracts_episodes() {
        let podcast = parse_bytes(minimal_rss_feed()).unwrap();
        assert_eq!(podcast.episodes.len(), 1);
        let ep = &podcast.episodes[0];
        assert_eq!(ep.title, "Episode 1");
        assert_eq!(ep.guid, "ep-001");
        assert_eq!(ep.audio_url, "https://cdn.example.com/ep1.mp3");
        assert!(ep.published_at.is_some());
    }

    #[test]
    fn test_parse_bytes_extracts_ns2_fields() {
        let podcast = parse_bytes(minimal_rss_feed()).unwrap();
        assert!(podcast.value_tag.is_some(), "should extract podcast:value");
        let v = podcast.value_tag.unwrap();
        assert_eq!(v.value_type, "lightning");
        assert_eq!(v.method, "keysend");

        let ep = &podcast.episodes[0];
        assert_eq!(ep.chapter_url.as_deref(), Some("https://cdn.example.com/ep1-chapters.json"));
        assert_eq!(ep.transcript_url.as_deref(), Some("https://cdn.example.com/ep1.srt"));
        assert_eq!(ep.transcript_type.as_deref(), Some("application/srt"));
        assert_eq!(ep.season, Some(2));
        assert_eq!(ep.episode_number, Some(5));
    }

    #[test]
    fn test_parse_bytes_sanitises_audio_url() {
        let feed = br#"<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Tracker Podcast</title>
            <item>
              <title>Tracked Episode</title>
              <guid>ep-track</guid>
              <enclosure url="https://chtbl.com/track/ABC/https://cdn.example.com/ep.mp3" type="audio/mpeg"/>
            </item>
          </channel>
        </rss>"#;
        let podcast = parse_bytes(feed).unwrap();
        assert_eq!(podcast.episodes.len(), 1);
        // The Chartable prefix should be stripped.
        assert_eq!(podcast.episodes[0].audio_url, "https://cdn.example.com/ep.mp3");
        // The raw URL should still contain the original.
        assert!(podcast.episodes[0].raw_audio_url.contains("chtbl.com"));
    }

    #[test]
    fn test_parse_bytes_strips_tracking_pixels_from_description() {
        let feed = br#"<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Pixel Podcast</title>
            <description>Notes<img src="https://tracker.com/px" width="1" height="1"/>end</description>
            <item>
              <title>Ep</title>
              <guid>ep-px</guid>
              <enclosure url="https://cdn.example.com/ep.mp3" type="audio/mpeg"/>
            </item>
          </channel>
        </rss>"#;
        let podcast = parse_bytes(feed).unwrap();
        let desc = podcast.description.unwrap();
        assert!(!desc.contains("tracker.com"), "tracking pixel should be stripped from channel description");
        assert!(desc.contains("Notes"));
    }

    #[test]
    fn test_parse_bytes_skips_non_audio_enclosures() {
        let feed = br#"<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Video Podcast</title>
            <item>
              <title>Video Ep</title>
              <guid>ep-vid</guid>
              <enclosure url="https://cdn.example.com/ep.mp4" type="video/mp4"/>
            </item>
          </channel>
        </rss>"#;
        let podcast = parse_bytes(feed).unwrap();
        assert_eq!(podcast.episodes.len(), 0, "video enclosures should be skipped");
    }

    #[test]
    fn test_parse_bytes_guid_truncation() {
        let long_guid = "x".repeat(3000);
        let feed = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
            <rss version="2.0">
              <channel>
                <title>Long GUID Podcast</title>
                <item>
                  <title>Ep</title>
                  <guid>{long_guid}</guid>
                  <enclosure url="https://cdn.example.com/ep.mp3" type="audio/mpeg"/>
                </item>
              </channel>
            </rss>"#,
        );
        let podcast = parse_bytes(feed.as_bytes()).unwrap();
        assert_eq!(podcast.episodes.len(), 1);
        assert_eq!(podcast.episodes[0].guid.len(), 2048, "GUID should be truncated to 2048");
    }

    #[test]
    fn test_parse_bytes_empty_feed_no_episodes() {
        let feed = br#"<?xml version="1.0" encoding="UTF-8"?>
        <rss version="2.0">
          <channel>
            <title>Empty Podcast</title>
          </channel>
        </rss>"#;
        let podcast = parse_bytes(feed).unwrap();
        assert_eq!(podcast.title, "Empty Podcast");
        assert_eq!(podcast.episodes.len(), 0);
    }

    #[test]
    fn test_sanitize_optional_url_https_passthrough() {
        let result = sanitize_optional_url("https://cdn.example.com/art.jpg");
        assert_eq!(result, Some("https://cdn.example.com/art.jpg".to_string()));
    }

    #[test]
    fn test_sanitize_optional_url_http_upgraded() {
        let result = sanitize_optional_url("http://cdn.example.com/art.jpg");
        assert_eq!(result, Some("https://cdn.example.com/art.jpg".to_string()));
    }

    #[test]
    fn test_sanitize_optional_url_ftp_rejected() {
        let result = sanitize_optional_url("ftp://cdn.example.com/art.jpg");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_bytes_invalid_xml_returns_error() {
        let result = parse_bytes(b"this is not xml at all");
        assert!(result.is_err());
    }
}
