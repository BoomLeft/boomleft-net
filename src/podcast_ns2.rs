//! Podcast Namespace 2.0 extension parser.
//!
//! Extracts `podcast:*` elements that `feed-rs` does not surface, using
//! minimal string scanning on the raw XML. All URLs are HTTPS-validated
//! with SSRF guards, text is HTML-escaped, and attribute lengths are
//! capped.

use serde::{Deserialize, Serialize};

use crate::url_sanitizer::sanitize_text;

const MAX_ATTR_LEN: usize = 4096;
const MAX_ITEM_LEN: usize = 1024 * 1024;

/// Podcast-level Namespace 2.0 metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PodcastNs2 {
    /// `<podcast:value>` payment information.
    pub value: Option<ValueTag>,
}

/// Episode-level Namespace 2.0 metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpisodeNs2 {
    /// `<podcast:chapters url="..." type="..."/>` — external chapter file.
    pub chapter_url: Option<String>,
    /// MIME type of the chapter file (`application/json+chapters` is the common one).
    pub chapter_type: Option<String>,
    /// `<podcast:transcript url="..." type="..."/>` — external transcript.
    pub transcript_url: Option<String>,
    /// MIME type of the transcript file (`application/srt`, `text/vtt`, etc.).
    pub transcript_type: Option<String>,
    /// `<podcast:season>N</podcast:season>`
    pub season: Option<u32>,
    /// `<podcast:episode>N</podcast:episode>`
    pub episode_number: Option<u32>,
    /// `<podcast:soundbite startTime="..." duration="...">label</podcast:soundbite>`
    pub soundbites: Vec<Soundbite>,
}

/// A single `<podcast:soundbite>` highlight clip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soundbite {
    /// Start offset inside the episode, in milliseconds.
    pub start_ms: u64,
    /// Duration of the clip, in milliseconds.
    pub duration_ms: u64,
    /// Optional human-readable label (already sanitised for HTML interpolation).
    pub title: Option<String>,
}

/// `<podcast:value>` — value-for-value (Lightning / Boostagram / etc.) payment metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValueTag {
    /// Payment network name (`lightning`, `nostr`, etc.).
    pub value_type: String,
    /// Protocol-level routing method (`keysend`, `amp`, `lnaddress`, ...).
    pub method: String,
    /// Suggested payment amount, raw string to avoid lossy decimal conversion.
    pub suggested: Option<String>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Extract Podcast Namespace 2.0 episode extensions from the raw XML of a
/// single `<item>` block.
#[must_use]
pub fn parse_episode_ns2(item_xml: &str) -> EpisodeNs2 {
    let mut ns2 = EpisodeNs2::default();

    if let Some(tag) = find_tag(item_xml, "podcast:chapters") {
        ns2.chapter_url = get_attr(&tag, "url")
            .and_then(|u| sanitize_ns2_url(&u));
        ns2.chapter_type = get_attr(&tag, "type").map(|t| sanitize_text(&t));
    }

    if let Some(tag) = find_tag(item_xml, "podcast:transcript") {
        ns2.transcript_url = get_attr(&tag, "url")
            .and_then(|u| sanitize_ns2_url(&u));
        ns2.transcript_type = get_attr(&tag, "type").map(|t| sanitize_text(&t));
    }

    if let Some(text) = find_tag_text(item_xml, "podcast:season") {
        ns2.season = text.trim().parse().ok();
    }

    if let Some(text) = find_tag_text(item_xml, "podcast:episode") {
        ns2.episode_number = text.trim().parse().ok();
    }

    for tag_match in find_all_tags(item_xml, "podcast:soundbite") {
        if let (Some(start), Some(dur)) = (
            get_attr(&tag_match.full_tag, "startTime")
                .and_then(|s| parse_seconds_to_ms(&s)),
            get_attr(&tag_match.full_tag, "duration")
                .and_then(|s| parse_seconds_to_ms(&s)),
        ) {
            ns2.soundbites.push(Soundbite {
                start_ms: start,
                duration_ms: dur,
                title: tag_match.inner_text.clone()
                    .filter(|t| !t.is_empty())
                    .map(|t| sanitize_text(&t)),
            });
        }
    }

    ns2
}

/// Extract Podcast Namespace 2.0 channel-level extensions.
#[must_use]
pub fn parse_podcast_ns2(channel_xml: &str) -> PodcastNs2 {
    let mut ns2 = PodcastNs2::default();

    if let Some(tag) = find_tag(channel_xml, "podcast:value") {
        ns2.value = Some(ValueTag {
            value_type: sanitize_text(&get_attr(&tag, "type").unwrap_or_default()),
            method: sanitize_text(&get_attr(&tag, "method").unwrap_or_default()),
            suggested: get_attr(&tag, "suggested").map(|s| sanitize_text(&s)),
        });
    }

    ns2
}

/// Strip dangerous XML constructs (DOCTYPE, ENTITY, comments, CDATA)
/// before the NS2 string scanner processes the raw XML.
#[must_use]
pub fn strip_entity_declarations(xml: &str) -> String {
    let mut result = String::with_capacity(xml.len());
    let lower = xml.to_lowercase();
    let mut i = 0;
    while i < xml.len() {
        let lower_tail = lower.get(i..).unwrap_or("");
        if lower_tail.starts_with("<!doctype") || lower_tail.starts_with("<!entity") {
            if let Some(tail) = xml.get(i..) {
                if let Some(end) = tail.find('>') {
                    i += end + 1;
                    continue;
                }
            }
        }
        if lower_tail.starts_with("<!--") {
            if let Some(tail) = xml.get(i..) {
                if let Some(end) = tail.find("-->") {
                    i += end + 3;
                    continue;
                }
            }
        }
        if lower_tail.starts_with("<![cdata[") {
            if let Some(tail) = xml.get(i..) {
                if let Some(end) = tail.find("]]>") {
                    i += end + 3;
                    continue;
                }
            }
        }
        let Some(rest) = xml.get(i..) else { break };
        if let Some(ch) = rest.chars().next() {
            result.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    result
}

/// Split feed XML into per-`<item>` blocks. Items larger than 1 MiB are skipped.
#[must_use]
pub fn split_items(xml: &str) -> Vec<&str> {
    let lower = xml.to_lowercase();
    let mut items = Vec::new();
    let mut search_from = 0;

    while let Some(lower_tail) = lower.get(search_from..) {
        let Some(start) = lower_tail.find("<item") else { break };
        let abs_start = search_from + start;
        let Some(tail) = lower.get(abs_start..) else { break };
        if let Some(end_offset) = tail.find("</item>") {
            let abs_end = abs_start + end_offset + 7; // len("</item>")
            let item_len = abs_end - abs_start;
            if abs_end <= xml.len() && item_len <= MAX_ITEM_LEN {
                if let Some(slice) = xml.get(abs_start..abs_end) {
                    items.push(slice);
                }
            }
            search_from = abs_end;
        } else {
            break;
        }
    }

    items
}

// ── Private helpers ──────────────────────────────────────────────────────────

struct TagMatch {
    full_tag: String,
    inner_text: Option<String>,
}

fn find_tag(xml: &str, tag_name: &str) -> Option<String> {
    let lower = xml.to_lowercase();
    let needle = format!("<{}", tag_name.to_lowercase());
    let start = lower.find(&needle)?;
    let rest = xml.get(start..)?;
    let end = rest.find('>')? + 1;
    let tag = rest.get(..end)?;
    if tag.len() > MAX_ATTR_LEN {
        return None;
    }
    Some(tag.to_string())
}

fn find_tag_text(xml: &str, tag_name: &str) -> Option<String> {
    let lower = xml.to_lowercase();
    let open = format!("<{}", tag_name.to_lowercase());
    let close = format!("</{}>", tag_name.to_lowercase());

    let open_start = lower.find(&open)?;
    let from_open = xml.get(open_start..)?;
    let content_start = from_open.find('>')? + open_start + 1;
    let lower_content = lower.get(content_start..)?;
    let close_start = lower_content.find(&close)? + content_start;

    let text = xml.get(content_start..close_start)?;
    if text.len() > MAX_ATTR_LEN {
        return None;
    }
    Some(text.to_string())
}

fn find_all_tags(xml: &str, tag_name: &str) -> Vec<TagMatch> {
    let lower = xml.to_lowercase();
    let needle = format!("<{}", tag_name.to_lowercase());
    let close = format!("</{}>", tag_name.to_lowercase());
    let mut results = Vec::new();
    let mut search_from = 0;

    while let Some(lower_tail) = lower.get(search_from..) {
        let Some(start) = lower_tail.find(&needle) else { break };
        let abs_start = search_from + start;
        let Some(rest) = xml.get(abs_start..) else { break };

        if let Some(tag_end) = rest.find('>') {
            let Some(full_tag_slice) = rest.get(..=tag_end) else { break };
            let full_tag = full_tag_slice.to_string();
            if full_tag.len() > MAX_ATTR_LEN {
                search_from = abs_start + tag_end + 1;
                continue;
            }

            // Check for inner text (non-self-closing tag).
            let inner_text = if full_tag.ends_with("/>") {
                None
            } else {
                let content_start = abs_start + tag_end + 1;
                lower.get(content_start..).and_then(|lc| lc.find(&close)).map(|close_offset| {
                    let text = xml
                        .get(content_start..content_start + close_offset)
                        .unwrap_or("");
                    if text.len() <= MAX_ATTR_LEN {
                        text.to_string()
                    } else {
                        String::new()
                    }
                })
            };

            results.push(TagMatch { full_tag, inner_text });
            search_from = abs_start + tag_end + 1;
        } else {
            break;
        }
    }

    results
}

fn get_attr(tag: &str, attr_name: &str) -> Option<String> {
    let lower = tag.to_lowercase();
    let attr_lower = attr_name.to_lowercase();

    for quote in ['"', '\''] {
        let needle = format!("{attr_lower}={quote}");
        if let Some(pos) = lower.find(&needle) {
            let start = pos + needle.len();
            let rest = tag.get(start..)?;
            if let Some(end) = rest.find(quote) {
                let value = rest.get(..end)?;
                if value.len() <= MAX_ATTR_LEN {
                    return Some(value.to_string());
                }
            }
        }
    }

    None
}

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "Soundbite offsets are bounded by the 100_000_000 s guard above, which is well within u64 range after the *1000 scaling."
)]
fn parse_seconds_to_ms(s: &str) -> Option<u64> {
    let secs: f64 = s.trim().parse().ok()?;
    if secs < 0.0 || secs > 100_000_000.0 {
        return None;
    }
    Some((secs * 1000.0) as u64)
}

fn sanitize_ns2_url(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    if let Some(host) = parsed.host_str() {
        if crate::url_sanitizer::is_private_host(host) {
            return None;
        }
    }
    Some(parsed.to_string())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_parse_chapters() {
        let xml = r#"<item><podcast:chapters url="https://example.com/ch.json" type="application/json+chapters"/></item>"#;
        let ns2 = parse_episode_ns2(xml);
        assert_eq!(ns2.chapter_url.as_deref(), Some("https://example.com/ch.json"));
        assert_eq!(ns2.chapter_type.as_deref(), Some("application/json+chapters"));
    }

    #[test]
    fn test_parse_transcript() {
        let xml = r#"<item><podcast:transcript url="https://example.com/ep.srt" type="application/srt"/></item>"#;
        let ns2 = parse_episode_ns2(xml);
        assert_eq!(ns2.transcript_url.as_deref(), Some("https://example.com/ep.srt"));
        assert_eq!(ns2.transcript_type.as_deref(), Some("application/srt"));
    }

    #[test]
    fn test_parse_season_episode() {
        let xml = r#"<item><podcast:season>3</podcast:season><podcast:episode>12</podcast:episode></item>"#;
        let ns2 = parse_episode_ns2(xml);
        assert_eq!(ns2.season, Some(3));
        assert_eq!(ns2.episode_number, Some(12));
    }

    #[test]
    fn test_parse_soundbites() {
        let xml = r#"<item>
            <podcast:soundbite startTime="33.8" duration="60.0">Best moment</podcast:soundbite>
            <podcast:soundbite startTime="120" duration="45"/>
        </item>"#;
        let ns2 = parse_episode_ns2(xml);
        assert_eq!(ns2.soundbites.len(), 2);
        assert_eq!(ns2.soundbites[0].start_ms, 33800);
        assert_eq!(ns2.soundbites[0].duration_ms, 60000);
        assert_eq!(ns2.soundbites[0].title.as_deref(), Some("Best moment"));
        assert_eq!(ns2.soundbites[1].start_ms, 120000);
        assert!(ns2.soundbites[1].title.is_none());
    }

    #[test]
    fn test_parse_value_tag() {
        let xml = r#"<channel><podcast:value type="lightning" method="keysend" suggested="100"/></channel>"#;
        let ns2 = parse_podcast_ns2(xml);
        assert!(ns2.value.is_some());
        let v = ns2.value.unwrap();
        assert_eq!(v.value_type, "lightning");
        assert_eq!(v.method, "keysend");
        assert_eq!(v.suggested.as_deref(), Some("100"));
    }

    #[test]
    fn test_http_urls_rejected() {
        let xml = r#"<item><podcast:chapters url="http://insecure.com/ch.json" type="application/json"/></item>"#;
        let ns2 = parse_episode_ns2(xml);
        assert!(ns2.chapter_url.is_none(), "HTTP URLs must be rejected");
    }

    #[test]
    fn test_private_ip_urls_rejected() {
        let xml = r#"<item><podcast:transcript url="https://192.168.1.1/t.srt" type="application/srt"/></item>"#;
        let ns2 = parse_episode_ns2(xml);
        assert!(ns2.transcript_url.is_none(), "Private IP URLs must be rejected");
    }

    #[test]
    fn test_split_items() {
        let xml = r#"<rss><channel><item><title>A</title></item><item><title>B</title></item></channel></rss>"#;
        let items = split_items(xml);
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn test_xml_comment_stripped() {
        let xml = r#"<item><!-- <podcast:chapters url="https://example.com/evil.json" type="application/json"/> --><podcast:season>3</podcast:season></item>"#;
        let clean = strip_entity_declarations(xml);
        let ns2 = parse_episode_ns2(&clean);
        assert!(ns2.chapter_url.is_none(), "tags inside XML comments must be ignored");
        assert_eq!(ns2.season, Some(3));
    }

    #[test]
    fn test_cdata_stripped() {
        let xml = r#"<item><![CDATA[<podcast:chapters url="https://example.com/evil.json" type="application/json"/>]]><podcast:season>5</podcast:season></item>"#;
        let clean = strip_entity_declarations(xml);
        let ns2 = parse_episode_ns2(&clean);
        assert!(ns2.chapter_url.is_none(), "tags inside CDATA must be ignored");
        assert_eq!(ns2.season, Some(5));
    }

    #[test]
    fn test_oversized_attribute_rejected() {
        let huge_url = format!("https://example.com/{}", "x".repeat(MAX_ATTR_LEN + 1));
        let xml = format!(r#"<item><podcast:chapters url="{huge_url}" type="application/json"/></item>"#);
        let ns2 = parse_episode_ns2(&xml);
        assert!(ns2.chapter_url.is_none(), "Oversized attributes must be rejected");
    }
}
