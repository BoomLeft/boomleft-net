# boomleft-net

> BoomLeft family shared network-layer — feed parsing, OPML, geo utilities. Sibling crate to [`privacysuite-core-sdk`](https://github.com/mkfnch/PrivacySuite-Core-SDK).

`boomleft-net` consolidates the network-layer code that the BoomLeft app
family (Music, Podcasts, RSS, Weather, Shadow-Atlas, ...) keeps re-implementing.
It depends on `privacysuite-core-sdk` for the cryptographic foundation and
the canonical tracking-parameter blocklist, and is consumed alongside it.

Keeping `boomleft-net` in its own repository preserves the SDK's audit
posture (pure-Rust cryptographic core, no higher-level parsers) while
giving the shared network-layer room to iterate.

---

## Scope

### v0.1.0 — what's in the box

- **`feed_parser`** — RSS 2.0 + Podcast Namespace 2.0 feed parser ported
  verbatim from `boomleft-podcasts/src-tauri/src/feed_parser.rs`. Covers
  the following Podcast Namespace 2.0 tags:
  - `<podcast:chapters>` — external chapter marker file URL
  - `<podcast:transcript>` — transcript file URL + type (SRT / VTT / JSON)
  - `<podcast:season>` — season number
  - `<podcast:episode>` — episode number
  - `<podcast:value>` — value-for-value payment metadata
  - `<podcast:soundbite>` — highlight clips (start + duration)

  The parser is fetch-free: callers supply feed bytes (fetched with
  whatever privacy tier they prefer). The async `fetch_and_parse`
  variant from `boomleft-podcasts` is intentionally **not** ported into
  0.1.0; it depended on the app's per-podcast privacy-tier router,
  which belongs to SDK gap G1 (`PrivacyClient`). Once G1 lands in SDK
  Phase 1, a thin `fetch_and_parse` will re-appear in a later release.

### Future scope (Phase 3+)

- **`opml`** — OPML v1/v2 import/export ported from
  `boomleft-rss/lib/services/opml_service.dart` (depth / file-cap
  guards, feed validation hooks).
- **`geo`** — coordinate truncation and haversine distance ported from
  the shared bits of `boomleft-weather` and `Shadow-Atlas`.

---

## Consuming `boomleft-net`

Add as a git dependency, pinned to the tagged release:

```toml
[dependencies]
boomleft-net = { git = "https://github.com/mkfnch/boomleft-net", tag = "v0.1.0" }
```

`boomleft-net` does not opt into any SDK feature flags. If the consumer
also depends on `privacysuite-core-sdk` with `features = ["full"]` (as
most BoomLeft apps do), Cargo unifies the feature set and the SDK ships
its full feature surface through the shared dep graph.

### Minimal usage

```rust,ignore
use boomleft_net::feed_parser;

// `bytes` is a `&[u8]` you fetched with your own HTTP client.
let podcast = feed_parser::parse_bytes(bytes)?;
for episode in &podcast.episodes {
    println!("{}: {}", episode.title, episode.audio_url);
}
```

---

## Supply-chain / audit posture

`boomleft-net` inherits the SDK's discipline:

- `#![forbid(unsafe_code)]`, `#![deny(warnings)]`.
- Every dependency is `=`-pinned to an exact version.
- `rust-toolchain.toml` pins channel `1.93`.
- `deny.toml` is copied verbatim from the SDK, with one addition:
  the SDK's git repo is allow-listed in `[sources]` so we can depend
  on its tagged release without it being on crates.io.
- `#[deny(missing_docs)]` and the SDK's full Clippy discipline
  (`unwrap_used`, `expect_used`, `panic`, `print_stdout`,
  `print_stderr`, `indexing_slicing`, `pedantic`, ...) are enforced
  at the crate level.

See [`deny.toml`](./deny.toml) for the full ban list.

---

## Development

```bash
cargo check          # fast type-check
cargo test           # unit tests (29 ported from boomleft-podcasts)
cargo clippy -- -D warnings
cargo deny check
cargo audit
```

---

## License

Proprietary. Copyright (c) 2026 BoomLeft LLC. All rights reserved.
See [`LICENSE`](./LICENSE).
