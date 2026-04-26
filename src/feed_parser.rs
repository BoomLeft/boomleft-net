//! RSS 2.0 + Podcast Namespace 2.0 feed parser.
//!
//! Parses already-fetched feed bytes into [`ParsedPodcast`] with episodes.
//! Podcast Namespace 2.0 extensions (chapters, transcripts, seasons,
//! episodes, value tags, soundbites) are extracted via [`crate::podcast_ns2`]
//! since `feed-rs` does not expose `podcast:*` extensions.
//!
//! All text fields are HTML-escaped, URLs are HTTPS-validated with SSRF
//! guards, and tracking prefixes/pixels are stripped.

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
/// # Errors
///
/// Returns `Err` when `bytes` is not a parseable RSS/Atom feed.
pub fn parse_bytes(bytes: &[u8]) -> Result<ParsedPodcast> {
    let feed = feed_rs::parser::parse(bytes).context("RSS/Atom parse error")?;

    let raw_xml = std::str::from_utf8(bytes).unwrap_or("");
    let clean_xml = podcast_ns2::strip_entity_declarations(raw_xml);
    let item_blocks = podcast_ns2::split_items(&clean_xml);
    let channel_ns2 = podcast_ns2::parse_podcast_ns2(&clean_xml);

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

    let language = feed.language.as_deref().map(|l| sanitize_text(l));

    let category = feed.categories.first().map(|c| sanitize_text(&c.term));

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

    let guid = if guid.len() > 2048 {
        guid.get(..2048).unwrap_or(&guid).to_string()
    } else {
        guid
    };
    let guid = sanitize_text(&guid);

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

    let file_size = enclosure
        .size
        .filter(|&s| s <= u64::from(u32::MAX));

    let published_at = entry
        .published
        .or(entry.updated)
        .map(|dt| dt.timestamp());

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
/// Only HTTPS public URLs are accepted; HTTP is upgraded; others return None.
fn sanitize_optional_url(url: &str) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    match parsed.scheme() {
        "http" => {
            if parsed.set_scheme("https").is_err() {
                return None;
            }
        }
        "https" => {}
        _ => return None,
    }

    if let Some(host) = parsed.host_str() {
        if crate::url_sanitizer::is_private_host(host) {
            return None;
        }
    }

    Some(parsed.to_string())
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
