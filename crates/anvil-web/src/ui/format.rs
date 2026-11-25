//! Timestamp formatting shared by the account pages: a machine-readable ISO 8601 form (for
//! `<time datetime>`) and a short human form, both in UTC.

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

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::{datetime, offset};

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
