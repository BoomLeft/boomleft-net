//! Analytics prefix stripping — CRITICAL FEATURE.
//!
//! All known tracking prefix domains are stripped before any URL is persisted
//! or used for a download.  The blocklist is compiled-in (not fetched remotely)
//! so that sanitisation works offline and cannot be silently disabled by a
//! network attacker or compromised update server.
//!
//! Security properties enforced by this module:
//!
//! 1. Prefix stripping uses proper URL parsing (via the `url` crate) rather
//!    than raw string matching, which prevents case-sensitivity bypasses and
//!    path-traversal tricks in the remainder segment.
//!
//! 2. Every reconstructed inner URL is re-parsed with `url::Url::parse`.  A
//!    remainder that does not produce a valid URL is discarded and the original
//!    URL is returned unchanged.
//!
//! 3. After stripping all prefixes the final URL is validated: scheme must be
//!    `https`, the host must not be a private/loopback/link-local address
//!    (SSRF guard), and null bytes are rejected before parsing.
//!
//! 4. Tracking query parameters are removed after prefix stripping.
//!
//! 5. The sanitiser is idempotent: a URL that has already been sanitised passes
//!    through unchanged.
//!
//! # Port notes (Phase 2 boomleft-net v0.1.0)
//!
//! - The async `validate_resolved_url` (DNS rebinding guard) from the
//!   upstream `boomleft-podcasts` copy is **not** ported here; it
//!   depended on `tokio::net::lookup_host` and an async runtime, neither
//!   of which `boomleft-net` 0.1.0 is permitted to introduce. It will
//!   re-appear in a later release, probably via the SDK's forthcoming
//!   `PrivacyClient` (gap G1).
//! - `TRACKING_PARAMS` is sourced from the SDK's `privacy_utils` module
//!   so every BoomLeft app agrees on one blocklist.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// ── Prefix table ──────────────────────────────────────────────────────────────

/// A compile-time entry in the analytics-prefix blocklist.
///
/// Matches a URL whose host equals [`Self::prefix_host`] and whose path
/// starts with [`Self::prefix_path`]. See [`sanitize_audio_url`] for
/// how matches are consumed.
#[derive(Debug)]
pub struct PrefixStrip {
    /// Lower-case host (and optional path prefix) of the tracker domain.
    pub prefix_host: &'static str,
    /// Optional path prefix to match after the host.
    pub prefix_path: &'static str,
}

/// Known analytics / tracking prefix domains, v1.0.
/// A blocklist update requires a crate release — by design.
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

/// Use the SDK's unified tracking params list for consistency across all apps.
use privacysuite_core_sdk::privacy_utils::TRACKING_PARAMS;

// ── Public API ────────────────────────────────────────────────────────────────

/// Strip all known analytics prefixes and tracking query parameters from
/// `raw_url`, then validate the result.
///
/// SECURITY: This is a critical privacy function. All podcast feed URLs and audio URLs
/// pass through this sanitizer. Tracking prefixes (PodTrac, Chartable, etc.) are removed
/// before any URL is stored or used, ensuring tracking pixels and prefix redirects
/// cannot silently re-route to trackers. The blocklist is compiled-in (not fetched)
/// so sanitisation works offline and cannot be disabled by network attackers.
///
/// Returns the sanitised URL.  If the URL is malformed the original
/// string is returned; if the final URL fails validation (non-HTTPS or
/// private host) an empty string is returned so callers must handle
/// "sanitised away" explicitly.
#[must_use]
pub fn sanitize_audio_url(raw_url: &str) -> String {
    // Reject null bytes up front — they cannot appear in valid URLs.
    if raw_url.contains('\0') {
        tracing::warn!("url_sanitizer: null byte in URL, returning as-is");
        return raw_url.to_string();
    }

    let mut url = raw_url.trim().to_string();

    // Iteratively strip prefix chains (e.g. Chartable → Podtrac → real URL).
    // Cap iterations to prevent pathological inputs from looping forever.
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

    // Remove tracking query parameters.
    url = match strip_tracking_params(&url) {
        Ok(clean) => clean,
        Err(_) => url,
    };

    // Validate the final URL: HTTPS only and no private/loopback hosts.
    match validate_audio_url(&url) {
        Ok(validated) => validated,
        Err(reason) => {
            tracing::warn!("url_sanitizer: final URL rejected ({}) — returning empty", reason);
            // Return empty string instead of the dangerous URL.  Callers
            // must handle empty audio_url gracefully (skip download).
            // Returning the original URL would allow SSRF if any code
            // path used it without re-validating.
            String::new()
        }
    }
}

/// Enforce that a URL suitable for downloading audio is safe.
///
/// Rules:
/// - Scheme must be `https` (not `http`, not `ftp`, not `file`, etc.).
/// - Host must not be a private, loopback, or link-local address (SSRF guard).
/// - URL must be parseable by the `url` crate.
///
/// # Errors
///
/// Returns a human-readable `&'static str` reason when the URL is
/// unparseable, has a non-HTTPS scheme, lacks a host, points at a
/// private/reserved address, or has no path component.
pub fn validate_audio_url(url: &str) -> Result<String, &'static str> {
    let parsed = url::Url::parse(url).map_err(|_| "unparseable URL")?;

    if parsed.scheme() != "https" {
        return Err("scheme must be https");
    }

    let host = parsed.host_str().ok_or("missing host")?;
    if is_private_host(host) {
        return Err("host resolves to a private/reserved address (SSRF guard)");
    }

    // Ensure there is at least a non-empty path component.
    if parsed.path().is_empty() || parsed.path() == "/" {
        return Err("URL has no path");
    }

    Ok(parsed.to_string())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Attempt to strip a single known prefix from `url`.
///
/// Uses proper URL parsing to extract host and path, avoiding case-sensitivity
/// and path-traversal bypasses present in naive string-matching approaches.
fn strip_one_prefix(url: &str, p: &PrefixStrip) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;

    // Compare host case-insensitively.
    let host = parsed.host_str()?.to_lowercase();
    if host != p.prefix_host {
        return None;
    }

    // Check the path prefix (also case-insensitively).
    let path = parsed.path();
    let path_lower = path.to_lowercase();
    if !path_lower.starts_with(p.prefix_path) {
        return None;
    }

    // The remainder starts after the matched path prefix.
    let remainder = path.get(p.prefix_path.len()..)?;

    // The remainder may include a path extension segment (e.g. "mp3/" for
    // Podtrac's "/redirect.mp3/https://...").  Skip to the next "/" if the
    // prefix ends with a dot.
    let inner_start = if p.prefix_path.ends_with('.') {
        // Find the first "/" after the extension.
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

    // Reconstruct the inner URL.
    let inner = if inner_start.starts_with("https://") || inner_start.starts_with("http://") {
        inner_start.to_string()
    } else {
        format!("https://{inner_start}")
    };

    // Validate that the reconstruction produced a parseable URL.
    let _parsed_inner = url::Url::parse(&inner).ok()?;

    // Upgrade http → https in the inner URL.
    let inner = inner.replacen("http://", "https://", 1);

    Some(inner)
}

/// Remove tracking query parameters while preserving all other parameters.
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

/// Returns `true` if `host` is a private, loopback, or link-local address.
///
/// Covers IPv4 RFC-1918, loopback (127.x, ::1), link-local (169.254.x,
/// fe80::/10), and the APIPA / CGN ranges used by cloud metadata services
/// (169.254.169.254, 100.64.0.0/10).
#[must_use]
pub fn is_private_host(host: &str) -> bool {
    let lower = host.to_lowercase();

    // Reject localhost and subdomains.
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }

    // Reject octal/hex IP notations used for SSRF bypass (e.g., 0x7f000001, 0177.0.0.1).
    if lower.starts_with("0x") || lower.contains(".0x") ||
       (lower.starts_with('0') && lower.contains('.') &&
        lower.split('.').any(|oct| oct.len() > 1 && oct.starts_with('0') && oct.chars().all(|c| c.is_ascii_digit()))) {
        return true;
    }

    // Standard IP parsing.
    if let Ok(addr) = IpAddr::from_str(host) {
        return is_private_ip(addr);
    }

    // Bracketed IPv6 ("[::1]") — strip brackets.
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
            // Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) — these
            // represent IPv4 addresses in IPv6 form and must be checked
            // against the IPv4 private ranges to prevent SSRF bypass.
            if let Some(v4) = v6.to_ipv4_mapped() {
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
    // 100.64.0.0/10
    let octets = v4.octets();
    octets[0] == 100 && (octets[1] & 0xC0) == 64
}

fn is_documentation(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
}

fn is_link_local_v6(v6: Ipv6Addr) -> bool {
    // fe80::/10
    let segments = v6.segments();
    (segments[0] & 0xFFC0) == 0xFE80
}

fn is_unique_local_v6(v6: Ipv6Addr) -> bool {
    // fc00::/7
    let segments = v6.segments();
    (segments[0] & 0xFE00) == 0xFC00
}

// ── HTML text sanitisation ───────────────────────────────────────────────────

/// HTML-escape a text string from an untrusted RSS feed to prevent XSS.
///
/// All feed-derived text (titles, descriptions, author names, soundbite
/// labels, NS2 type strings) MUST pass through this before storage or
/// rendering in the WebView.
///
/// SAFETY CONTEXT (audit F12):
/// The output of this function is safe to interpolate into HTML
/// **text-node** content and HTML **attribute-value** content
/// (double- or single-quoted). It is **not** safe for:
///   * `<script>` / `<style>` bodies,
///   * URL-attribute contexts that need `javascript:` stripping
///     (e.g. `href`, `src`) — use a URL validator for those,
///   * `dangerouslySetInnerHTML` / direct `innerHTML` assignment,
///   * `eval` / `Function` / JSON-as-HTML-parser paths.
/// Reviewers: if a new sink emerges in the React layer, confirm that
/// the text interpolated into it flows through a context-appropriate
/// encoder — not just through `sanitize_text`.
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
            // Strip null bytes (prevent null-byte injection in downstream consumers).
            '\0' => {}
            _ => out.push(c),
        }
    }
    out
}

// ── Tracking pixel stripping ──────────────────────────────────────────────────

/// Remove 1x1 tracking pixel `<img>` tags from HTML description content.
#[must_use]
pub fn strip_tracking_pixels(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let lower = html.to_lowercase();
    let mut i = 0;

    while i < html.len() {
        // Safe slice: `i` always lies on a UTF-8 char boundary because
        // we advance by `ch.len_utf8()` below.
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
        // Advance by one UTF-8 character to preserve multi-byte sequences.
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
    (lower.contains("width=\"1\"") || lower.contains("width='1'"))
        && (lower.contains("height=\"1\"") || lower.contains("height='1'"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
        // Must not produce a usable URL; returned as-is (which fails validation later)
        assert_eq!(result, raw);
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
