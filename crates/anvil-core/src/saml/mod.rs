//! SAML 2.0 service provider, pure part (ORG-03, decision D4).
//!
//! - [`request`]: the SP-initiated `AuthnRequest`, the RelayState format and the SP metadata,
//!   all written from escaped templates.
//! - [`validate`]: the condition checks on the values the web adapter extracted from the
//!   signature-verified assertion (SAML profile checks 3 and 6 of the phase research).
//!
//! No XML parsing and no signature verification happen here: the adapter (06-09) parses with
//! one parser, pre-checks the signature profile, verifies, and hands core only the extracted
//! values. Time comes from the caller's `now`.

use time::{OffsetDateTime, UtcOffset};

pub mod request;
pub mod validate;

/// SAML protocol namespace.
pub const NS_PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
/// SAML assertion namespace.
pub const NS_ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
/// SAML metadata namespace.
pub const NS_METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
/// The HTTP-POST binding (where the IdP sends the Response).
pub const BINDING_HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/// Escapes text or an attribute value for XML: `& < > " '` become entity references, and
/// characters XML 1.0 cannot carry at all (C0 controls other than tab, LF and CR) become
/// U+FFFD, so no input can end an attribute or element early.
pub(crate) fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{FFFE}' || c == '\u{FFFF}' => out.push('\u{FFFD}'),
            c => out.push(c),
        }
    }
    out
}

/// An `xs:dateTime` in UTC with second precision, as SAML instants are written
/// (`2026-11-26T09:30:00Z`).
pub fn saml_instant(t: OffsetDateTime) -> String {
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

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn escapes_markup_and_quotes() {
        assert_eq!(xml_escape(r#"a"<&'>b"#), "a&quot;&lt;&amp;&apos;&gt;b");
        assert_eq!(xml_escape("plain text"), "plain text");
        assert_eq!(xml_escape("ü\t\n"), "ü\t\n");
    }

    #[test]
    fn replaces_characters_xml_cannot_carry() {
        assert_eq!(xml_escape("a\u{0}b\u{1b}c"), "a\u{FFFD}b\u{FFFD}c");
    }

    #[test]
    fn instants_are_utc_seconds() {
        assert_eq!(
            saml_instant(datetime!(2026-11-26 09:30:05.789 UTC)),
            "2026-11-26T09:30:05Z"
        );
        assert_eq!(
            saml_instant(datetime!(2026-11-26 11:30:05 +02:00)),
            "2026-11-26T09:30:05Z"
        );
    }
}
