//! Formatting shared by the account pages: timestamps (a machine-readable ISO 8601 form for
//! `<time datetime>` and a short human form, both in UTC and labelled so) and a readable device
//! summary of a session's user agent ("Firefox on Linux", U-M16).

use time::{OffsetDateTime, UtcOffset};

/// `YYYY-MM-DDTHH:MM:SSZ` in UTC.
pub(crate) fn iso(t: OffsetDateTime) -> String {
    let t = t.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

/// `YYYY-MM-DD HH:MM UTC`.
pub(crate) fn human(t: OffsetDateTime) -> String {
    let t = t.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} UTC",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    )
}

/// The browser and operating system families a user agent names, from a small allowlist (no
/// version, no device model: the raw string is never shown). `None` where it names none of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Device {
    pub(crate) browser: Option<&'static str>,
    pub(crate) os: Option<&'static str>,
}

/// Maps a user agent to [`Device`]. The order matters: Edge and Opera also say "Chrome", Chrome
/// also says "Safari", and iOS also says "Mac OS X", Android also says "Linux".
pub(crate) fn device(user_agent: &str) -> Device {
    let ua = user_agent;
    let has = |needle: &str| ua.contains(needle);
    let browser = if has("Edg/") || has("EdgA/") || has("EdgiOS/") || has("Edge/") {
        Some("Edge")
    } else if has("OPR/") || has("Opera") {
        Some("Opera")
    } else if has("Firefox/") || has("FxiOS/") {
        Some("Firefox")
    } else if has("Chrome/") || has("CriOS/") || has("Chromium/") {
        Some("Chrome")
    } else if has("Safari/") && (has("Version/") || has("iPhone") || has("iPad")) {
        Some("Safari")
    } else {
        None
    };
    let os = if has("iPhone") || has("iPad") || has("iPod") {
        Some("iOS")
    } else if has("Android") {
        Some("Android")
    } else if has("Windows") {
        Some("Windows")
    } else if has("Macintosh") || has("Mac OS X") {
        Some("macOS")
    } else if has("Linux") || has("X11") || has("CrOS") {
        Some("Linux")
    } else {
        None
    };
    Device { browser, os }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{datetime, offset};

    #[test]
    fn user_agents_map_to_browser_and_os_families() {
        for (ua, browser, os) in [
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
                Some("Firefox"),
                Some("Linux"),
            ),
            (
                "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
                Some("Chrome"),
                Some("Android"),
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Mobile/15E148 Safari/604.1",
                Some("Safari"),
                Some("iOS"),
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
                Some("Edge"),
                Some("Windows"),
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 OPR/120.0.0.0",
                Some("Opera"),
                Some("macOS"),
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15",
                Some("Safari"),
                Some("macOS"),
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 19_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/142.0 Mobile/15E148 Safari/604.1",
                Some("Chrome"),
                Some("iOS"),
            ),
            ("curl/8.11.0", None, None),
            ("<script>alert(1)</script>", None, None),
            ("", None, None),
            (
                "Mozilla/5.0 (X11; Linux x86_64) Unknown/1.0",
                None,
                Some("Linux"),
            ),
        ] {
            assert_eq!(device(ua), Device { browser, os }, "{ua}");
        }
    }

    #[test]
    fn timestamps_are_formatted_in_utc() {
        let t = datetime!(2026-11-25 12:03:04 UTC);
        assert_eq!(iso(t), "2026-11-25T12:03:04Z");
        assert_eq!(human(t), "2026-11-25 12:03 UTC");
    }

    #[test]
    fn non_utc_offsets_are_converted() {
        let t = datetime!(2026-11-25 14:03:04 UTC).to_offset(offset!(+2));
        assert_eq!(iso(t), "2026-11-25T14:03:04Z");
        assert_eq!(human(t), "2026-11-25 14:03 UTC");
    }
}
