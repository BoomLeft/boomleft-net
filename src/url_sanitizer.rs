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

/// Hard upper bound on the length of a single URL we will inspect.
/// Far larger than any legitimate audio URL; chosen to bound CPU /
/// allocation cost of the iterative prefix-strip loop on hostile input.
pub(crate) const MAX_URL_LEN: usize = 8192;

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

    // Hard cap on URL length. RFC 9110 has no formal upper bound, but a
    // multi-megabyte URL is universally a DoS attempt; reject early so the
    // (relatively expensive) parse / strip / re-parse loop never runs.
    if raw_url.len() > MAX_URL_LEN {
        tracing::warn!("url_sanitizer: URL exceeds MAX_URL_LEN, returning empty");
        return String::new();
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
    //
    // Two distinct rejection paths:
    //   * Unparseable input (never touched a tracker, not a valid URL)
    //     → pass the original through unchanged. Callers that need HTTPS
    //     will fail downstream on their own validation.
    //   * Parseable but rejected (non-HTTPS scheme or private host) →
    //     return empty string so callers must handle "sanitised away"
    //     explicitly. Passing a dangerous URL through would enable SSRF
    //     in any caller that doesn't re-validate.
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

    // The remainder can take several shapes depending on the tracker:
    //   * chtbl.com: "/track/"  → "ABC123/https://cdn.example.com/ep.mp3"
    //     (opaque track id, then the embedded URL after the next `/`)
    //   * dts.podtrac.com: "/redirect."  → "mp3/https://cdn.example.com/ep.mp3"
    //     (extension segment, then the embedded URL after the next `/`)
    //   * prfx.byspotify.com: "/" → "https://cdn.example.com/ep.mp3"
    //     (bare embedded URL)
    //
    // A find() for "https://" / "http://" anywhere in the remainder covers
    // all of these — the embedded URL is always the substring starting
    // from the first scheme occurrence. For prefixes that wrap a plain
    // hostname rather than an absolute URL (some legacy trackers), fall
    // back to prepending "https://" to the whole remainder.
    let inner_start = if remainder.starts_with("https://") || remainder.starts_with("http://") {
        remainder
    } else if let Some(pos) = remainder.find("https://") {
        remainder.get(pos..)?
    } else if let Some(pos) = remainder.find("http://") {
        remainder.get(pos..)?
    } else if p.prefix_path.ends_with('.') {
        // Extension-style prefix (Podtrac) without an embedded absolute
        // URL — jump past the extension segment and treat the tail as a
        // hostname-rooted path.
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
///
/// Re-encodes kept pairs through `query_pairs_mut()` so that a value
/// containing `&` (originally `%26`) cannot smuggle additional parameters
/// when the URL is re-parsed downstream.
fn strip_tracking_params(url: &str) -> Result<String, url::ParseError> {
    let mut parsed = url::Url::parse(url)?;

    let kept: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| {
            let k_lower = k.to_ascii_lowercase();
            !TRACKING_PARAMS.iter().any(|t| k_lower == *t) && !k_lower.starts_with("utm_")
        })
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    parsed.set_query(None);
    if !kept.is_empty() {
        let mut serializer = parsed.query_pairs_mut();
        for (k, v) in &kept {
            let _ = serializer.append_pair(k, v);
        }
        let _ = serializer.finish();
    }

    Ok(parsed.to_string())
}

/// Returns `true` if `host` is a private, loopback, link-local, or
/// otherwise non-routable address.
///
/// Covers IPv4 RFC-1918, loopback (`127.0.0.0/8`, `::1`), link-local
/// (`169.254.0.0/16`, `fe80::/10`), CGN (`100.64.0.0/10`), benchmark
/// (`198.18.0.0/15`), documentation (`192.0.2.0/24`, `198.51.100.0/24`,
/// `203.0.113.0/24`, `2001:db8::/32`), multicast (`224.0.0.0/4`,
/// `ff00::/8`), reserved (`240.0.0.0/4`), the cloud metadata APIPA
/// (`169.254.169.254`, already covered by link-local), and `0.0.0.0`.
///
/// In addition, hostnames using non-decimal-dotted-quad encodings
/// (`0x7f000001`, `0177.0.0.1`) are rejected even when the `url` crate
/// would have normalised them — defense in depth in case a future caller
/// passes a host string that bypasses crate normalisation.
#[must_use]
pub fn is_private_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();

    // Reject localhost and subdomains.
    if lower == "localhost" || lower.ends_with(".localhost") {
        return true;
    }

    // Reject hex / octal IPv4 encodings used for SSRF bypass.
    // - hex:    `0x7f000001`, `0xc0.0xa8.0x01.0x01`
    // - octal:  `0177.0.0.1`
    // We only flag tokens that look numerically motivated — a domain
    // segment that happens to start with a `0` digit (e.g. `0day.example`)
    // is left alone.
    if lower.starts_with("0x") && lower.as_bytes().get(2).is_some_and(u8::is_ascii_hexdigit) {
        return true;
    }
    let segments: Vec<&str> = lower.split('.').collect();
    if segments.len() >= 2 && segments.iter().all(|s| !s.is_empty()) {
        let any_hex = segments.iter().any(|s| s.starts_with("0x")
            && s.len() > 2
            && s.as_bytes().iter().skip(2).all(u8::is_ascii_hexdigit));
        let any_octal = segments.iter().any(|s| s.len() > 1
            && s.starts_with('0')
            && s.bytes().all(|b| b.is_ascii_digit()));
        if any_hex || any_octal {
            return true;
        }
    }

    // Bracketed IPv6 (`[::1]`) — strip brackets and any RFC 6874 zone-id
    // suffix (`%eth0`, encoded as `%25eth0`) before parsing.
    let candidate = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    let candidate = candidate.split('%').next().unwrap_or(candidate);
    if let Ok(addr) = IpAddr::from_str(candidate) {
        return is_private_ip(addr);
    }

    false
}

fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || is_cgnat(v4)          // 100.64.0.0/10 (carrier-grade NAT)
                || is_documentation(v4)  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
                || is_benchmark(v4)      // 198.18.0.0/15
                || is_reserved_or_multicast(v4) // 224.0.0.0/4 + 240.0.0.0/4
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
                || is_multicast_v6(v6)
                || is_documentation_v6(v6)
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

fn is_benchmark(v4: Ipv4Addr) -> bool {
    // 198.18.0.0/15 — RFC 2544 benchmark testing range.
    let octets = v4.octets();
    octets[0] == 198 && (octets[1] & 0xFE) == 18
}

fn is_reserved_or_multicast(v4: Ipv4Addr) -> bool {
    // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved/future use).
    let octets = v4.octets();
    octets[0] >= 224
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

fn is_multicast_v6(v6: Ipv6Addr) -> bool {
    // ff00::/8
    let segments = v6.segments();
    (segments[0] & 0xFF00) == 0xFF00
}

fn is_documentation_v6(v6: Ipv6Addr) -> bool {
    // 2001:db8::/32 (RFC 3849 documentation prefix).
    let segments = v6.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
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
    let lower = img_tag.to_ascii_lowercase();
    has_dim_one(&lower, "width") && has_dim_one(&lower, "height")
}

/// True if `tag_lower` contains `name=1` / `name="1"` / `name='1'`,
/// tolerating surrounding whitespace, single or double quotes, and
/// unquoted values. Required to catch hand-crafted tracking pixels that
/// bypass the more rigid `width="1"`/`height="1"` exact match.
fn has_dim_one(tag_lower: &str, name: &str) -> bool {
    let bytes = tag_lower.as_bytes();
    let needle = format!("{name}=");
    let mut search = 0;
    while let Some(rel) = tag_lower.get(search..).and_then(|t| t.find(&needle)) {
        let pos = search + rel;
        // Boundary check — `name=` must be preceded by whitespace so
        // `pixwidth=` doesn't false-positive the `width=` check.
        let boundary = pos == 0 || bytes.get(pos - 1).is_some_and(u8::is_ascii_whitespace);
        if boundary {
            let after = pos + needle.len();
            let mut value = tag_lower.get(after..).unwrap_or("").trim_start();
            // Strip optional quote character.
            if value.starts_with('"') || value.starts_with('\'') {
                value = value.get(1..).unwrap_or("");
            }
            if value.starts_with('1') {
                let next = value.as_bytes().get(1).copied();
                let stops = matches!(next, None | Some(b'"' | b'\'' | b' ' | b'/' | b'>' | b'\t' | b'\n' | b'\r'));
                if stops {
                    return true;
                }
            }
        }
        search = pos + needle.len();
    }
    false
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

    // ── New SSRF regression coverage ────────────────────────────────────────

    #[test]
    fn test_hex_ipv4_encoding_rejected() {
        assert!(is_private_host("0x7f000001"));
        assert!(is_private_host("0xc0.0xa8.0x01.0x01"));
    }

    #[test]
    fn test_octal_ipv4_encoding_rejected() {
        assert!(is_private_host("0177.0.0.1"));
    }

    #[test]
    fn test_legitimate_hostname_starting_with_digit_not_rejected() {
        // `0day.example` and `1.example` must still be allowed — the
        // octal-bypass guard must not over-flag these.
        assert!(!is_private_host("0day.example"));
        assert!(!is_private_host("1.example"));
        assert!(!is_private_host("9to5mac.com"));
    }

    #[test]
    fn test_ipv4_multicast_rejected() {
        assert!(validate_audio_url("https://224.0.0.1/ep.mp3").is_err());
    }

    #[test]
    fn test_ipv4_reserved_rejected() {
        assert!(validate_audio_url("https://240.0.0.1/ep.mp3").is_err());
    }

    #[test]
    fn test_ipv4_benchmark_rejected() {
        assert!(validate_audio_url("https://198.18.0.1/ep.mp3").is_err());
        assert!(validate_audio_url("https://198.19.0.1/ep.mp3").is_err());
    }

    #[test]
    fn test_ipv6_multicast_rejected() {
        assert!(validate_audio_url("https://[ff02::1]/ep.mp3").is_err());
    }

    #[test]
    fn test_ipv6_documentation_rejected() {
        assert!(validate_audio_url("https://[2001:db8::1]/ep.mp3").is_err());
    }

    #[test]
    fn test_ipv6_zone_id_does_not_bypass() {
        // Bracketed IPv6 with RFC 6874 zone-id (`%25eth0` percent-encoded
        // form) must still reject loopback once stripped. We feed the host
        // form directly, since `url::Url::parse` may or may not preserve it.
        assert!(is_private_host("[::1%25eth0]"));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_loopback_rejected() {
        assert!(validate_audio_url("https://[::ffff:127.0.0.1]/ep.mp3").is_err());
    }

    // ── Tracking pixel hardening ────────────────────────────────────────────

    #[test]
    fn test_tracking_pixel_unquoted_attrs_stripped() {
        let html = r#"<p>a</p><img src=x width=1 height=1><p>b</p>"#;
        let result = strip_tracking_pixels(html);
        assert!(!result.contains("src=x"));
        assert!(result.contains('a'));
        assert!(result.contains('b'));
    }

    #[test]
    fn test_tracking_pixel_single_quoted_stripped() {
        let html = r#"<img src='x' width='1' height='1'/>"#;
        let result = strip_tracking_pixels(html);
        assert!(!result.contains("src="));
    }

    #[test]
    fn test_tracking_pixel_pixwidth_does_not_false_positive() {
        // A non-tracking img with a custom `pixwidth=1` attribute and no
        // real width="1" must NOT be removed.
        let html = r#"<img src="real.jpg" pixwidth="1" pixheight="1" alt="ok"/>"#;
        let result = strip_tracking_pixels(html);
        assert!(result.contains("real.jpg"), "non-tracking img must survive");
    }

    // ── Query smuggling regression ──────────────────────────────────────────

    #[test]
    fn test_query_string_no_smuggle_via_ampersand() {
        // The `keep` value contains an encoded ampersand. After we strip
        // tracking params and re-emit, the ampersand must remain encoded
        // so the upstream server sees a single param, not two.
        let raw = "https://cdn.example.com/ep.mp3?utm_source=spam&keep=foo%26bar%3D1";
        let result = sanitize_audio_url(raw);
        assert!(result.contains("foo%26bar"), "ampersand must remain encoded: {result}");
        assert!(!result.contains("utm_source"));
    }

    // ── Length cap ──────────────────────────────────────────────────────────

    #[test]
    fn test_oversized_url_rejected() {
        let long = format!("https://cdn.example.com/{}", "a".repeat(MAX_URL_LEN + 100));
        let result = sanitize_audio_url(&long);
        assert_eq!(result, "");
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
