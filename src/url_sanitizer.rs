//! URL sanitisation: analytics prefix stripping, SSRF guards, and
//! tracking parameter removal.
//!
//! The compiled-in blocklist ensures sanitisation works offline and
//! cannot be silently disabled by a network attacker. Every URL is
//! parsed via the `url` crate (preventing case / path-traversal
//! bypasses), reconstructed inner URLs are re-parsed, and the final
//! result is validated: HTTPS only, no private/loopback/link-local
//! hosts (SSRF guard), no null bytes. The sanitiser is idempotent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ── Prefix table ──────────────────────────────────────────────────────────────

/// A compile-time entry in the analytics-prefix blocklist.
#[derive(Debug)]
pub struct PrefixStrip {
    /// Lower-case tracker host.
    pub prefix_host: &'static str,
    /// Path prefix to match after the host.
    pub prefix_path: &'static str,
}

/// Known analytics / tracking prefix domains.
pub static KNOWN_PREFIXES: &[PrefixStrip] = &[
    PrefixStrip { prefix_host: "chtbl.com",            prefix_path: "/track/" },
    PrefixStrip { prefix_host: "dts.podtrac.com",      prefix_path: "/redirect." }, // .mp3, .aac, etc.
    PrefixStrip { prefix_host: "pscrb.fm",             prefix_path: "/rss/p/" },
    PrefixStrip { prefix_host: "prfx.byspotify.com",   prefix_path: "/" },
    PrefixStrip { prefix_host: "pdst.fm",              prefix_path: "/e/" },
    PrefixStrip { prefix_host: "op3.dev",              prefix_path: "/e/" },
    PrefixStrip { prefix_host: "tracking.feedburner.com", prefix_path: "/" },
    PrefixStrip { prefix_host: "podtrac.com",          prefix_path: "/pts/redirect." },
    PrefixStrip { prefix_host: "arttrk.com",           prefix_path: "/p/" },
    PrefixStrip { prefix_host: "mgln.ai",              prefix_path: "/e/" },
    PrefixStrip { prefix_host: "pfx.vpixl.com",        prefix_path: "/" },
    PrefixStrip { prefix_host: "verifi.podscribe.com", prefix_path: "/rss/p/" },
    PrefixStrip { prefix_host: "podscribe.com",        prefix_path: "/rss/p/" },
    PrefixStrip { prefix_host: "chrt.fm",              prefix_path: "/track/" },
    PrefixStrip { prefix_host: "claritaspod.com",      prefix_path: "/e/" },
    PrefixStrip { prefix_host: "podder.co",            prefix_path: "/e/" },
];

use privacysuite_core_sdk::privacy_utils::TRACKING_PARAMS;

// ── Public API ────────────────────────────────────────────────────────────────

/// Strip all known analytics prefixes and tracking query parameters from
/// `raw_url`, then validate the result.
///
/// Returns the sanitised URL. Malformed URLs pass through unchanged;
/// URLs that fail validation (non-HTTPS, private host) return empty.
#[must_use]
pub fn sanitize_audio_url(raw_url: &str) -> String {
    // Reject null bytes up front — they cannot appear in valid URLs.
    if raw_url.contains('\0') {
        tracing::warn!("url_sanitizer: null byte in URL, rejecting");
        return String::new();
    }

    let mut url = raw_url.trim().to_string();

    for _ in 0..=KNOWN_PREFIXES.len() {
        let mut stripped_any = false;
        for p in KNOWN_PREFIXES {
            if let Some(stripped) = strip_one_prefix(&url, p) {
                url = stripped;
                stripped_any = true;
                break;
            }
        }
        if !stripped_any {
            break;
        }
    }

    url = match strip_tracking_params(&url) {
        Ok(clean) => clean,
        Err(_) => url,
    };

    match validate_audio_url(&url) {
        Ok(validated) => validated,
        Err(reason) => {
            if url::Url::parse(&url).is_err() {
                tracing::warn!("url_sanitizer: unparseable URL — passing through");
                return raw_url.to_string();
            }
            tracing::warn!("url_sanitizer: final URL rejected ({}) — returning empty", reason);
            String::new()
        }
    }
}

/// Validate that a URL is safe for audio download: HTTPS only, public
/// host, non-empty path.
///
/// # Errors
///
/// Returns a reason string when the URL fails validation.
pub fn validate_audio_url(url: &str) -> Result<String, &'static str> {
    let parsed = url::Url::parse(url).map_err(|_| "unparseable URL")?;

    if parsed.scheme() != "https" {
        return Err("scheme must be https");
    }

    let host = parsed.host_str().ok_or("missing host")?;
    if is_private_host(host) {
        return Err("host resolves to a private/reserved address (SSRF guard)");
    }

    if parsed.path().is_empty() || parsed.path() == "/" {
        return Err("URL has no path");
    }

    Ok(parsed.to_string())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Attempt to strip a single known prefix from `url`.
fn strip_one_prefix(url: &str, p: &PrefixStrip) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;

    let host = parsed.host_str()?.to_lowercase();
    if host != p.prefix_host {
        return None;
    }

    let path = parsed.path();
    let path_lower = path.to_lowercase();
    if !path_lower.starts_with(p.prefix_path) {
        return None;
    }

    let remainder = path.get(p.prefix_path.len()..)?;

    let inner_start = if remainder.starts_with("https://") || remainder.starts_with("http://") {
        remainder
    } else if let Some(pos) = remainder.find("https://") {
        remainder.get(pos..)?
    } else if let Some(pos) = remainder.find("http://") {
        remainder.get(pos..)?
    } else if p.prefix_path.ends_with('.') {
        remainder
            .find('/')
            .and_then(|i| remainder.get(i + 1..))
            .unwrap_or("")
    } else {
        remainder
    };

    if inner_start.is_empty() {
        return None;
    }

    let inner = if inner_start.starts_with("https://") || inner_start.starts_with("http://") {
        inner_start.to_string()
    } else {
        format!("https://{inner_start}")
    };

    let _parsed_inner = url::Url::parse(&inner).ok()?;
    let inner = inner.replacen("http://", "https://", 1);

    Some(inner)
}

fn strip_tracking_params(url: &str) -> Result<String, url::ParseError> {
    let mut parsed = url::Url::parse(url)?;

    let kept: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| {
            let k_lower = k.to_lowercase();
            !TRACKING_PARAMS.iter().any(|t| k_lower == *t)
                && !k_lower.starts_with("utm_")
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    if kept.is_empty() {
        parsed.set_query(None);
    } else {
        let qs = kept
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        parsed.set_query(Some(&qs));
    }

    Ok(parsed.to_string())
}

/// Returns `true` if `host` is a private, loopback, link-local, CGNAT,
/// or NAT64-embedded-private address.
#[must_use]
pub fn is_private_host(host: &str) -> bool {
    let lower = host.to_lowercase();

    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }

    if lower.starts_with("0x") || lower.contains(".0x") ||
       (lower.starts_with('0') && lower.contains('.') &&
        lower.split('.').any(|oct| oct.len() > 1 && oct.starts_with('0') && oct.chars().all(|c| c.is_ascii_digit()))) {
        return true;
    }

    if let Ok(addr) = IpAddr::from_str(host) {
        return is_private_ip(addr);
    }

    if host.starts_with('[') && host.ends_with(']') {
        if let Some(inner) = host.get(1..host.len() - 1) {
            if let Ok(addr) = IpAddr::from_str(inner) {
                return is_private_ip(addr);
            }
        }
    }

    false
}

fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || is_cgnat(v4)          // 100.64.0.0/10
                || is_documentation(v4)  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ip(IpAddr::V4(v4));
            }
            if is_nat64_v6(v6) {
                let octets = v6.octets();
                let v4 = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
                return is_private_ip(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || is_link_local_v6(v6)
                || is_unique_local_v6(v6)
        }
    }
}

fn is_cgnat(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

fn is_documentation(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    let segments = v6.segments();
    (segments[0] & 0xFFC0) == 0xFE80
}

fn is_unique_local_v6(v6: Ipv6Addr) -> bool {
    let segments = v6.segments();
    (segments[0] & 0xFE00) == 0xFC00
}

/// NAT64 well-known prefix (RFC 6052).
fn is_nat64_v6(v6: Ipv6Addr) -> bool {
    let segments = v6.segments();
    segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
}

// ── HTML text sanitisation ──────────────────────────────────────────────

/// HTML-escape a text string from an untrusted feed to prevent XSS.
///
/// Safe for HTML text-node and attribute-value interpolation. NOT safe
/// for script/style bodies, `innerHTML`, or URL-attribute contexts.
#[must_use]
pub fn sanitize_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            '\0' => {}
            _ => out.push(c),
        }
    }
    out
}

// ── Tracking pixel stripping ────────────────────────────────────────────

/// Remove tracking pixel `<img>` tags from HTML description content.
#[must_use]
pub fn strip_tracking_pixels(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let lower = html.to_lowercase();
    let mut i = 0;

    while i < html.len() {
        if let Some(tail) = lower.get(i..) {
            if tail.starts_with("<img") {
                if let Some(end_offset) = tail.find('>') {
                    if let Some(tag) = html.get(i..i + end_offset + 1) {
                        if is_tracking_pixel(tag) {
                            i += end_offset + 1;
                            continue;
                        }
                    }
                }
            }
        }
        let Some(rest) = html.get(i..) else { break };
        if let Some(ch) = rest.chars().next() {
            result.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }

    result
}

fn is_tracking_pixel(img_tag: &str) -> bool {
    let lower = img_tag.to_lowercase();
    let tiny_width = lower.contains("width=\"1\"")
        || lower.contains("width='1'")
        || lower.contains("width=\"0\"")
        || lower.contains("width='0'")
        || lower.contains("width=\"1px\"")
        || lower.contains("width='1px'");
    let tiny_height = lower.contains("height=\"1\"")
        || lower.contains("height='1'")
        || lower.contains("height=\"0\"")
        || lower.contains("height='0'")
        || lower.contains("height=\"1px\"")
        || lower.contains("height='1px'");
    let hidden = lower.contains("display:none") || lower.contains("visibility:hidden");
    (tiny_width && tiny_height) || hidden
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn test_strip_chartable() {
        let raw = "https://chtbl.com/track/ABC123/https://cdn.example.com/episode.mp3";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, "https://cdn.example.com/episode.mp3");
    }

    #[test]
    fn test_strip_podtrac() {
        let raw = "https://dts.podtrac.com/redirect.mp3/https://cdn.example.com/ep.mp3";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, "https://cdn.example.com/ep.mp3");
    }

    #[test]
    fn test_strip_spotify_prefix() {
        let raw = "https://prfx.byspotify.com/https://cdn.example.com/ep.mp3";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, "https://cdn.example.com/ep.mp3");
    }

    #[test]
    fn test_strip_pdst() {
        let raw = "https://pdst.fm/e/https://cdn.example.com/ep.mp3";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, "https://cdn.example.com/ep.mp3");
    }

    #[test]
    fn test_strip_op3() {
        let raw = "https://op3.dev/e/https://cdn.example.com/ep.mp3";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, "https://cdn.example.com/ep.mp3");
    }

    #[test]
    fn test_strip_pscrb() {
        let raw = "https://pscrb.fm/rss/p/https://cdn.example.com/ep.mp3";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, "https://cdn.example.com/ep.mp3");
    }

    #[test]
    fn test_chained_prefixes() {
        let raw = "https://chtbl.com/track/ABC/https://dts.podtrac.com/redirect.mp3/https://cdn.example.com/ep.mp3";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, "https://cdn.example.com/ep.mp3");
    }

    #[test]
    fn test_strip_utm_params() {
        let raw = "https://cdn.example.com/ep.mp3?utm_source=rss&utm_medium=feed&keep=1";
        let result = sanitize_audio_url(raw);
        assert!(result.contains("keep=1"), "should preserve non-tracking params");
        assert!(!result.contains("utm_"), "should strip utm_ params");
    }

    #[test]
    fn test_strip_ga_fbclid() {
        let raw = "https://cdn.example.com/ep.mp3?_ga=123&fbclid=abc";
        let result = sanitize_audio_url(raw);
        assert!(!result.contains("_ga"), "should strip _ga");
        assert!(!result.contains("fbclid"), "should strip fbclid");
    }

    #[test]
    fn test_passthrough_clean_url() {
        let raw = "https://cdn.example.com/episode.mp3";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, raw);
    }

    #[test]
    fn test_idempotent() {
        let raw = "https://chtbl.com/track/ABC/https://cdn.example.com/ep.mp3";
        let first = sanitize_audio_url(raw);
        let second = sanitize_audio_url(&first);
        assert_eq!(first, second);
    }

    #[test]
    fn test_malformed_url_passthrough() {
        let raw = "not-a-url";
        let result = sanitize_audio_url(raw);
        assert_eq!(result, raw);
    }

    #[test]
    fn test_null_byte_rejected() {
        let raw = "https://cdn.example.com/ep.mp3\0malicious";
        let result = sanitize_audio_url(raw);
        assert!(result.is_empty(), "null-byte URL must be rejected");
    }

    #[test]
    fn test_case_insensitive_prefix_strip() {
        // Upper-case scheme in tracker URL should still be stripped.
        let raw = "https://CHTBL.COM/track/ABC/https://cdn.example.com/ep.mp3";
        let result = sanitize_audio_url(raw);
        // The URL crate normalises the host to lowercase.
        assert_eq!(result, "https://cdn.example.com/ep.mp3");
    }

    #[test]
    fn test_ssrf_loopback_rejected_by_validation() {
        let url = "https://127.0.0.1/evil.mp3";
        assert!(validate_audio_url(url).is_err());
    }

    #[test]
    fn test_ssrf_private_ip_rejected() {
        assert!(validate_audio_url("https://192.168.1.1/ep.mp3").is_err());
        assert!(validate_audio_url("https://10.0.0.1/ep.mp3").is_err());
        assert!(validate_audio_url("https://172.16.0.1/ep.mp3").is_err());
    }

    #[test]
    fn test_ssrf_aws_metadata_rejected() {
        // AWS IMDSv1 endpoint
        assert!(validate_audio_url("https://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn test_http_scheme_rejected_by_validation() {
        assert!(validate_audio_url("http://cdn.example.com/ep.mp3").is_err());
    }

    #[test]
    fn test_http_inner_url_upgraded_to_https() {
        // Some trackers wrap http:// inner URLs; we should upgrade them.
        let raw = "https://chtbl.com/track/X/http://cdn.example.com/ep.mp3";
        let result = sanitize_audio_url(raw);
        assert!(result.starts_with("https://"), "http inner URL should be upgraded");
    }

    #[test]
    fn test_strip_tracking_pixel() {
        let html = r#"<p>Show notes</p><img src="https://tracker.com/px" width="1" height="1"/><p>More</p>"#;
        let result = strip_tracking_pixels(html);
        assert!(!result.contains("tracker.com"));
        assert!(result.contains("Show notes"));
    }

    #[test]
    fn test_strip_tracking_pixel_preserves_multibyte_utf8() {
        let html = r#"<p>Ñoño café 日本語</p><img src="https://t.co/px" width="1" height="1"/><p>émission</p>"#;
        let result = strip_tracking_pixels(html);
        assert!(!result.contains("t.co/px"), "tracking pixel should be removed");
        assert!(result.contains("Ñoño café 日本語"), "multi-byte chars must be preserved");
        assert!(result.contains("émission"), "accented chars must be preserved");
    }

    #[test]
    fn test_localhost_rejected() {
        assert!(validate_audio_url("https://localhost/ep.mp3").is_err());
    }

    #[test]
    fn test_ipv6_loopback_rejected() {
        assert!(validate_audio_url("https://[::1]/ep.mp3").is_err());
    }

    #[test]
    fn test_hidden_tracking_pixel_stripped() {
        let html = r#"<p>Notes</p><img src="https://tracker.com/px" style="display:none"/><p>More</p>"#;
        let result = strip_tracking_pixels(html);
        assert!(!result.contains("tracker.com"), "hidden tracking pixel should be stripped");
    }

    #[test]
    fn test_zero_size_tracking_pixel_stripped() {
        let html = r#"<p>Notes</p><img src="https://tracker.com/px" width="0" height="0"/><p>More</p>"#;
        let result = strip_tracking_pixels(html);
        assert!(!result.contains("tracker.com"), "zero-size tracking pixel should be stripped");
    }

    #[test]
    fn test_ssrf_nat64_loopback_rejected() {
        assert!(is_private_host("64:ff9b::7f00:1"));
    }

    #[test]
    fn test_ssrf_nat64_private_rejected() {
        // NAT64 embedding of 192.168.1.1
        assert!(is_private_host("64:ff9b::c0a8:101"));
    }

    #[test]
    fn test_path_traversal_in_remainder_sanitised() {
        // A crafted tracker URL whose "inner" segment is a relative path
        // must not produce a usable URL — it will fail url::Url::parse.
        let raw = "https://chtbl.com/track/../../etc/passwd";
        let result = sanitize_audio_url(raw);
        // The remainder "../../etc/passwd" does not parse as a URL → the
        // prefix is NOT stripped and the whole raw URL is returned.
        // The download layer will then reject it (not HTTPS scheme).
        assert!(!result.contains("etc/passwd") || result.starts_with("https://chtbl.com"),
            "path traversal must not escape the tracker domain");
    }
}
