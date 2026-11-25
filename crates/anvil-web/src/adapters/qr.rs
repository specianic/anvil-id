//! Server-side QR codes for TOTP enrolment (AUTH-05): an `otpauth://` URI rendered as an inline
//! SVG string with qrcodegen. No raster image crate and no `data:` URL, so the strict CSP
//! (`img-src 'self'`) needs no exception.
//!
//! The SVG is one `<path>` of dark modules with `fill="currentColor"`: the theme stylesheet sets
//! the colour (and the light background) of the surrounding element. No inline `style`
//! attributes, so `style-src 'self'` holds.

use std::fmt::Write as _;

use anvil_core::error::CoreError;
use qrcodegen::{QrCode, QrCodeEcc};

/// Longest input accepted (an `otpauth://` URI is well under this).
pub const MAX_QR_INPUT: usize = 1024;

/// Quiet zone in modules on every side (ISO/IEC 18004 recommends 4).
const BORDER: i32 = 4;

/// Renders `data` as an SVG QR code (error correction at least medium, 4-module quiet zone).
pub fn qr_svg(data: &str) -> Result<String, CoreError> {
    if data.is_empty() || data.len() > MAX_QR_INPUT {
        return Err(CoreError::Validation {
            field: "qr",
            message: format!("QR input must be 1..={MAX_QR_INPUT} bytes"),
        });
    }
    let qr = QrCode::encode_text(data, QrCodeEcc::Medium)
        .map_err(|_| CoreError::Internal("QR input too long to encode".to_owned()))?;
    let size = qr.size();
    let dim = size + BORDER * 2;

    let mut path = String::with_capacity((size as usize) * (size as usize));
    for y in 0..size {
        let mut x = 0;
        while x < size {
            if !qr.get_module(x, y) {
                x += 1;
                continue;
            }
            let start = x;
            while x < size && qr.get_module(x, y) {
                x += 1;
            }
            let run = x - start;
            // Infallible: writing to a String.
            let _ = write!(
                path,
                "M{},{}h{}v1h-{}z",
                start + BORDER,
                y + BORDER,
                run,
                run
            );
        }
    }

    Ok(format!(
        concat!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" role="img" "#,
            r#"aria-label="QR code for authenticator setup" viewBox="0 0 {dim} {dim}" "#,
            r#"shape-rendering="crispEdges"><path fill="currentColor" d="{path}"/></svg>"#
        ),
        dim = dim,
        path = path
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/Acme:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA1&digits=6&period=30";

    #[test]
    fn renders_svg_with_viewbox_and_single_path() {
        let svg = qr_svg(URI).unwrap();
        assert!(svg.starts_with("<svg"), "{svg}");
        assert!(svg.ends_with("</svg>"));
        assert!(svg.contains("viewBox=\"0 0 "));
        assert!(svg.contains(r#"role="img""#));
        assert!(svg.contains(r#"aria-label="QR code for authenticator setup""#));
        assert!(svg.contains(r#"fill="currentColor""#));
        assert_eq!(svg.matches("<path").count(), 1);
        assert!(
            !svg.contains("style"),
            "no inline style under the strict CSP"
        );
        assert!(!svg.contains("data:"));
        assert!(!svg.contains("<script"));
    }

    #[test]
    fn viewbox_includes_quiet_zone() {
        let qr = QrCode::encode_text(URI, QrCodeEcc::Medium).unwrap();
        let dim = qr.size() + 2 * BORDER;
        let svg = qr_svg(URI).unwrap();
        assert!(
            svg.contains(&format!("viewBox=\"0 0 {dim} {dim}\"")),
            "{svg}"
        );
        // Finder pattern top-left starts at the quiet-zone offset.
        assert!(svg.contains(&format!("M{BORDER},{BORDER}h7")), "{svg}");
    }

    #[test]
    fn deterministic_for_same_input() {
        assert_eq!(qr_svg(URI).unwrap(), qr_svg(URI).unwrap());
        assert_ne!(
            qr_svg(URI).unwrap(),
            qr_svg("otpauth://totp/other").unwrap()
        );
    }

    #[test]
    fn rejects_oversized_and_empty_input() {
        let big = "a".repeat(MAX_QR_INPUT + 1);
        assert!(matches!(qr_svg(&big), Err(CoreError::Validation { .. })));
        assert!(matches!(qr_svg(""), Err(CoreError::Validation { .. })));
        assert!(qr_svg(&"a".repeat(MAX_QR_INPUT)).is_ok());
    }

    #[test]
    fn markup_characters_in_input_do_not_reach_the_svg() {
        let svg = qr_svg(r#"otpauth://totp/"><script>alert(1)</script>"#).unwrap();
        assert!(!svg.contains("<script"));
        assert!(!svg.contains("alert"));
    }
}
