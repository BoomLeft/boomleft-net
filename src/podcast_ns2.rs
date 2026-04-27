//! Podcast Namespace 2.0 extension parser.
//!
//! Extracts `podcast:*` elements that `feed-rs` does not yet surface:
//!   - `<podcast:chapters>` — external chapter marker file URL
//!   - `<podcast:transcript>` — transcript file URL + type (SRT/VTT/JSON)
//!   - `<podcast:season>` — season number
//!   - `<podcast:episode>` — episode number
//!   - `<podcast:value>` — value-for-value payment metadata
//!   - `<podcast:soundbite>` — highlight clips (start + duration)
//!
//! This module operates on the raw XML bytes *after* `feed-rs` has parsed
//! the standard RSS fields. It uses minimal string scanning (no full XML
//! parser dependency) to extract the well-defined namespace attributes.
//!
//! # Security
//!
//! - All URLs extracted are passed through `sanitize_ns2_url` (HTTPS-only,
//!   no private IPs).
//! - Tag and attribute matches require a name boundary, so
//!   `<podcast:value>` does not match `<podcast:valueRecipient>` and
//!   `url="…"` does not match `extraurl="…"`. (This was a real bypass
//!   in earlier versions.)
//! - Per-attribute, per-item, per-collection size caps prevent memory
//!   exhaustion from adversarial feeds.
//! - No `unsafe` code.

use serde::{Deserialize, Serialize};

use crate::url_sanitizer::sanitize_text;

/// Maximum attribute/text-content length we'll accept (prevents DoS via multi-MB attributes).
const MAX_ATTR_LEN: usize = 4096;
/// Maximum size for a single `<item>` XML block (prevents DoS from entity expansion).
const MAX_ITEM_LEN: usize = 1024 * 1024; // 1 MiB
/// Maximum number of `<item>` blocks we will surface from a single feed.
/// Caps `parse_bytes` work and downstream `Vec` growth on adversarial feeds.
pub(crate) const MAX_ITEMS: usize = 5_000;
/// Maximum number of soundbites we will collect from a single item.
const MAX_SOUNDBITES: usize = 100;

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
    /// Payment network name (`lightning`, `nostr`, etc.) — HTML-escaped.
    pub value_type: String,
    /// Protocol-level routing method (`keysend`, `amp`, `lnaddress`, ...) — HTML-escaped.
    pub method: String,
    /// Suggested payment amount, raw string to avoid lossy decimal conversion — HTML-escaped.
    pub suggested: Option<String>,
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Extract Podcast Namespace 2.0 episode extensions from the raw XML of a
/// single `<item>` block.
#[must_use]
pub fn parse_episode_ns2(item_xml: &str) -> EpisodeNs2 {
    // Single ASCII-lowercase pass — every helper below reuses this rather
    // than allocating its own. NS2 tag/attribute names are pure ASCII so
    // `make_ascii_lowercase` is byte-aligned with the original string and
    // safe to use as the search index.
    let lower = item_xml.to_ascii_lowercase();
    let mut ns2 = EpisodeNs2::default();

    if let Some(tag) = find_tag(item_xml, &lower, "podcast:chapters") {
        ns2.chapter_url = get_attr(&tag, "url").and_then(|u| sanitize_ns2_url(&u));
        ns2.chapter_type = get_attr(&tag, "type").map(|s| sanitize_text(&s));
    }

    if let Some(tag) = find_tag(item_xml, &lower, "podcast:transcript") {
        ns2.transcript_url = get_attr(&tag, "url").and_then(|u| sanitize_ns2_url(&u));
        ns2.transcript_type = get_attr(&tag, "type").map(|s| sanitize_text(&s));
    }

    if let Some(text) = find_tag_text(item_xml, &lower, "podcast:season") {
        ns2.season = text.trim().parse().ok();
    }

    if let Some(text) = find_tag_text(item_xml, &lower, "podcast:episode") {
        ns2.episode_number = text.trim().parse().ok();
    }

    for tag_match in find_all_tags(item_xml, &lower, "podcast:soundbite", MAX_SOUNDBITES) {
        if let (Some(start), Some(dur)) = (
            get_attr(&tag_match.full_tag, "startTime").and_then(|s| parse_seconds_to_ms(&s)),
            get_attr(&tag_match.full_tag, "duration").and_then(|s| parse_seconds_to_ms(&s)),
        ) {
            ns2.soundbites.push(Soundbite {
                start_ms: start,
                duration_ms: dur,
                title: tag_match
                    .inner_text
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
    let lower = channel_xml.to_ascii_lowercase();
    let mut ns2 = PodcastNs2::default();

    if let Some(tag) = find_tag(channel_xml, &lower, "podcast:value") {
        ns2.value = Some(ValueTag {
            value_type: sanitize_text(&get_attr(&tag, "type").unwrap_or_default()),
            method: sanitize_text(&get_attr(&tag, "method").unwrap_or_default()),
            suggested: get_attr(&tag, "suggested").map(|s| sanitize_text(&s)),
        });
    }

    ns2
}

/// Strip `<!DOCTYPE` and `<!ENTITY` declarations from XML to prevent
/// Billion Laughs / XXE entity expansion attacks. The `feed-rs` parser
/// may have already expanded entities; we strip them from the raw XML
/// to ensure the NS2 string scanner cannot be confused by expanded content.
#[must_use]
pub fn strip_entity_declarations(xml: &str) -> String {
    // ASCII-only directive names — `to_ascii_lowercase` is byte-aligned
    // with `xml`, so positions in `lower` are valid byte offsets in `xml`.
    let lower = xml.to_ascii_lowercase();
    let bytes = xml.as_bytes();
    let mut result = String::with_capacity(xml.len());
    let mut i = 0;

    while i < bytes.len() {
        let tail = lower.get(i..).unwrap_or("");
        if tail.starts_with("<!doctype") || tail.starts_with("<!entity") {
            if let Some(end) = xml.get(i..).and_then(|t| t.find('>')) {
                i += end + 1;
                continue;
            }
        }
        let Some(rest) = xml.get(i..) else { break };
        let Some(ch) = rest.chars().next() else { break };
        result.push(ch);
        i += ch.len_utf8();
    }
    result
}

/// Split feed XML into per-`<item>` blocks for per-episode NS2 parsing.
///
/// Returns up to [`MAX_ITEMS`] item slices. Items larger than
/// [`MAX_ITEM_LEN`] are skipped. Tag matches require a boundary character
/// after `item`, so e.g. `<itemRoot>` is not treated as an item.
#[must_use]
pub fn split_items(xml: &str) -> Vec<&str> {
    let lower = xml.to_ascii_lowercase();
    let mut items = Vec::new();
    let mut search_from = 0;

    while items.len() < MAX_ITEMS {
        let Some(abs_start) = find_open_tag(&lower, search_from, "item") else { break };
        let Some(tail_lower) = lower.get(abs_start..) else { break };
        let Some(end_offset) = tail_lower.find("</item>") else { break };
        let abs_end = abs_start + end_offset + "</item>".len();
        let item_len = abs_end - abs_start;
        if abs_end <= xml.len() && item_len <= MAX_ITEM_LEN {
            if let Some(slice) = xml.get(abs_start..abs_end) {
                items.push(slice);
            }
        }
        search_from = abs_end;
    }

    items
}

// ── Private helpers ──────────────────────────────────────────────────────────

struct TagMatch {
    full_tag: String,
    inner_text: Option<String>,
}

/// True if the byte at `lower[idx]` is a valid character to follow a tag
/// or attribute name (whitespace, `>`, `/`, `=`). Anything else means the
/// match is a *prefix* of a longer name and must be rejected — this is
/// the boundary check that prevents `<podcast:value>` from matching
/// `<podcast:valueRecipient>` and `url="…"` from matching `extraurl="…"`.
fn is_name_boundary(b: u8) -> bool {
    b.is_ascii_whitespace() || b == b'>' || b == b'/' || b == b'='
}

/// Find the byte offset of the next `<tag_name` in `lower` starting from
/// `from`, requiring a name boundary after `tag_name`. Returns the offset
/// of the `<` (so the caller can slice the original string).
fn find_open_tag(lower: &str, from: usize, tag_name_lower: &str) -> Option<usize> {
    let needle = format!("<{tag_name_lower}");
    let bytes = lower.as_bytes();
    let mut search = from;
    while let Some(rel) = lower.get(search..)?.find(&needle) {
        let abs = search + rel;
        let after = abs + needle.len();
        let &next = bytes.get(after)?;
        if is_name_boundary(next) {
            return Some(abs);
        }
        // Prefix match (`<itemFoo`, `<podcast:valueRecipient`); skip past it.
        search = after;
    }
    None
}

/// Find the first occurrence of a self-closing or open tag with the given
/// name and return the full tag string (e.g.,
/// `<podcast:chapters url="..." type="..."/>`).
fn find_tag(xml: &str, lower: &str, tag_name: &str) -> Option<String> {
    let tag_lower = tag_name.to_ascii_lowercase();
    let start = find_open_tag(lower, 0, &tag_lower)?;
    let rest = xml.get(start..)?;
    let end = rest.find('>')? + 1;
    let tag = rest.get(..end)?;
    if tag.len() > MAX_ATTR_LEN {
        return None;
    }
    Some(tag.to_string())
}

/// Find the text content between `<tag>text</tag>`.
fn find_tag_text(xml: &str, lower: &str, tag_name: &str) -> Option<String> {
    let tag_lower = tag_name.to_ascii_lowercase();
    let close = format!("</{tag_lower}>");

    let open_start = find_open_tag(lower, 0, &tag_lower)?;
    let from_open = xml.get(open_start..)?;
    let content_start = from_open.find('>')? + open_start + 1;
    let close_start = lower.get(content_start..)?.find(&close)? + content_start;

    let text = xml.get(content_start..close_start)?;
    if text.len() > MAX_ATTR_LEN {
        return None;
    }
    Some(text.to_string())
}

/// Find up to `cap` occurrences of a tag (for repeating elements like soundbites).
fn find_all_tags(xml: &str, lower: &str, tag_name: &str, cap: usize) -> Vec<TagMatch> {
    let tag_lower = tag_name.to_ascii_lowercase();
    let close = format!("</{tag_lower}>");
    let mut results = Vec::new();
    let mut search_from = 0;

    while results.len() < cap {
        let Some(abs_start) = find_open_tag(lower, search_from, &tag_lower) else { break };
        let Some(rest) = xml.get(abs_start..) else { break };
        let Some(tag_end) = rest.find('>') else { break };
        let Some(full_tag_slice) = rest.get(..=tag_end) else { break };
        let full_tag = full_tag_slice.to_string();

        if full_tag.len() > MAX_ATTR_LEN {
            search_from = abs_start + tag_end + 1;
            continue;
        }

        let inner_text = if full_tag.ends_with("/>") {
            None
        } else {
            let content_start = abs_start + tag_end + 1;
            lower.get(content_start..).and_then(|lc| lc.find(&close)).map(|close_off| {
                xml.get(content_start..content_start + close_off)
                    .filter(|t| t.len() <= MAX_ATTR_LEN)
                    .unwrap_or("")
                    .to_string()
            })
        };

        results.push(TagMatch { full_tag, inner_text });
        search_from = abs_start + tag_end + 1;
    }

    results
}

/// Extract a named attribute value from a tag string.
///
/// Handles double-quoted (`attr="val"`) and single-quoted (`attr='val'`)
/// values. Attribute matches require a whitespace boundary before the
/// name, so `url="…"` does not match `extraurl="…"`. Names are matched
/// case-insensitively against ASCII attribute identifiers.
fn get_attr(tag: &str, attr_name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let attr_lower = attr_name.to_ascii_lowercase();
    let lower_bytes = lower.as_bytes();

    for quote in ['"', '\''] {
        let needle = format!("{attr_lower}={quote}");
        let mut search = 0;
        while let Some(rel) = lower.get(search..)?.find(&needle) {
            let pos = search + rel;
            // Boundary check: the byte before the attribute name must be
            // whitespace or the `<tag` separator. Position 0 cannot be an
            // attribute (it's part of the tag name itself).
            let boundary_ok = pos > 0 && lower_bytes.get(pos - 1).is_some_and(u8::is_ascii_whitespace);
            if !boundary_ok {
                search = pos + needle.len();
                continue;
            }

            let value_start = pos + needle.len();
            let rest = tag.get(value_start..)?;
            let end = rest.find(quote)?;
            let value = rest.get(..end)?;
            if value.len() <= MAX_ATTR_LEN {
                return Some(value.to_string());
            }
            search = value_start + end;
        }
    }

    None
}

/// Parse a seconds value (possibly fractional) to milliseconds.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "Soundbite offsets are bounded by the 100_000_000 s guard above, which is well within u64 range after the *1000 scaling."
)]
fn parse_seconds_to_ms(s: &str) -> Option<u64> {
    let secs: f64 = s.trim().parse().ok()?;
    if !secs.is_finite() || secs < 0.0 || secs > 100_000_000.0 {
        return None;
    }
    Some((secs * 1000.0) as u64)
}

/// Sanitise a URL from a Namespace 2.0 attribute — HTTPS only, no private IPs.
fn sanitize_ns2_url(url: &str) -> Option<String> {
    if url.contains('\0') || url.len() > MAX_ATTR_LEN {
        return None;
    }
    let parsed = url::Url::parse(url).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    let host = parsed.host_str()?;
    if crate::url_sanitizer::is_private_host(host) {
        return None;
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
    fn test_oversized_attribute_rejected() {
        let huge_url = format!("https://example.com/{}", "x".repeat(MAX_ATTR_LEN + 1));
        let xml = format!(r#"<item><podcast:chapters url="{huge_url}" type="application/json"/></item>"#);
        let ns2 = parse_episode_ns2(&xml);
        assert!(ns2.chapter_url.is_none(), "Oversized attributes must be rejected");
    }

    // ── Regression: attribute-name confusion ────────────────────────────────

    /// A malicious feed declaring `extraurl="…"` BEFORE `url="…"` must not
    /// fool `get_attr("url")` into returning the attacker-controlled value.
    #[test]
    fn test_attribute_name_boundary_url_vs_extraurl() {
        let xml = r#"<item><podcast:chapters extraurl="https://attacker.example/c.json" url="https://legit.example/c.json" type="application/json"/></item>"#;
        let ns2 = parse_episode_ns2(xml);
        assert_eq!(
            ns2.chapter_url.as_deref(),
            Some("https://legit.example/c.json"),
            "must select the real `url` attribute, not a suffix-match against `extraurl`"
        );
    }

    /// `type="…"` must not match against a hypothetical `subtype="…"` etc.
    #[test]
    fn test_attribute_name_boundary_type_vs_subtype() {
        let xml = r#"<item><podcast:transcript subtype="evil" url="https://example.com/t.srt" type="application/srt"/></item>"#;
        let ns2 = parse_episode_ns2(xml);
        assert_eq!(ns2.transcript_type.as_deref(), Some("application/srt"));
    }

    // ── Regression: tag-name confusion ──────────────────────────────────────

    /// `<podcast:value>` must not match `<podcast:valueRecipient>`.
    #[test]
    fn test_tag_name_boundary_value_vs_valuerecipient() {
        let xml = r#"<channel>
            <podcast:valueRecipient name="alice" address="01"/>
            <podcast:value type="lightning" method="keysend" suggested="50"/>
        </channel>"#;
        let ns2 = parse_podcast_ns2(xml);
        let v = ns2.value.expect("must find the real value tag");
        assert_eq!(v.value_type, "lightning");
        assert_eq!(v.method, "keysend");
    }

    /// A feed containing only `<podcast:valueRecipient>` (no real `value`)
    /// must yield None — not an empty placeholder built from the recipient.
    #[test]
    fn test_tag_name_boundary_value_recipient_alone_yields_none() {
        let xml = r#"<channel><podcast:valueRecipient name="alice"/></channel>"#;
        let ns2 = parse_podcast_ns2(xml);
        assert!(ns2.value.is_none());
    }

    /// `split_items` must not treat `<itemRoot>` as an `<item>`.
    #[test]
    fn test_split_items_boundary_vs_itemroot() {
        let xml = r#"<rss><itemRoot><something/></itemRoot><item><title>real</title></item></rss>"#;
        let items = split_items(xml);
        assert_eq!(items.len(), 1);
        assert!(items[0].contains("real"));
    }

    // ── DoS bounds ─────────────────────────────────────────────────────────

    #[test]
    fn test_split_items_caps_at_max_items() {
        let mut xml = String::from("<rss><channel>");
        for _ in 0..(MAX_ITEMS + 50) {
            xml.push_str("<item><title>x</title></item>");
        }
        xml.push_str("</channel></rss>");
        let items = split_items(&xml);
        assert_eq!(items.len(), MAX_ITEMS);
    }

    #[test]
    fn test_soundbites_capped() {
        let mut xml = String::from("<item>");
        for _ in 0..200 {
            xml.push_str(r#"<podcast:soundbite startTime="0" duration="1"/>"#);
        }
        xml.push_str("</item>");
        let ns2 = parse_episode_ns2(&xml);
        assert!(ns2.soundbites.len() <= 100);
    }

    // ── Sanitisation of NS2 type attributes ────────────────────────────────

    /// Well-formed XML never contains a literal `<` in an attribute value
    /// (it would be encoded as `&lt;`), but feed-rs may accept trickier
    /// inputs. Verify HTML-special characters that *can* survive XML
    /// parsing — `&`, `'`, `"` — are escaped before they reach a sink.
    #[test]
    fn test_chapter_type_html_escaped() {
        let xml = r#"<item><podcast:chapters url='https://example.com/c.json' type='a&amp;b'/></item>"#;
        let ns2 = parse_episode_ns2(xml);
        let t = ns2.chapter_type.unwrap();
        // The raw attribute byte is `a&amp;b` (we don't decode XML entities);
        // the ampersand must still be HTML-escaped to `&amp;` so the value
        // is safe to interpolate into a text node.
        assert!(t.starts_with("a&amp;"), "ampersand must be HTML-escaped: {t}");
    }

    #[test]
    fn test_transcript_type_html_escaped() {
        // `&` inside the attribute is not literal `"` (XML rejects that),
        // but it can be `&quot;` which must remain HTML-safe.
        let xml = r#"<item><podcast:transcript url="https://example.com/t.srt" type="text/&quot;a"/></item>"#;
        let ns2 = parse_episode_ns2(xml);
        let t = ns2.transcript_type.unwrap();
        assert!(!t.contains('"'), "any raw double quote must be escaped: {t}");
        assert!(t.contains("&amp;quot;"), "ampersand of `&quot;` entity must itself be escaped: {t}");
    }

    // ── Additional URL hygiene ─────────────────────────────────────────────

    #[test]
    fn test_ns2_url_null_byte_rejected() {
        let xml = "<item><podcast:chapters url=\"https://example.com/\0evil\" type=\"application/json\"/></item>";
        let ns2 = parse_episode_ns2(xml);
        assert!(ns2.chapter_url.is_none());
    }

    #[test]
    fn test_parse_seconds_rejects_nan_and_inf() {
        assert!(parse_seconds_to_ms("nan").is_none());
        assert!(parse_seconds_to_ms("inf").is_none());
        assert!(parse_seconds_to_ms("-0.001").is_none());
    }
}
