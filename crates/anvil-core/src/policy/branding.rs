//! Branding policy: validation of theme tokens, logos and custom CSS sanitisation (UI-03).
//!
//! RED: signatures only (plan 04-09).

use serde::Serialize;

use crate::model::{ThemeColors, ThemeTokens};

pub const MAX_CUSTOM_CSS_BYTES: usize = 32 * 1024;
pub const MAX_LOGO_BYTES: usize = 256 * 1024;
pub const MAX_RADIUS_PX: u8 = 32;
pub const MAX_FONT_FAMILY_LEN: usize = 200;
pub const MIN_CONTRAST: f64 = 3.0;
pub const AA_CONTRAST: f64 = 4.5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColorScheme {
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContrastPair {
    TextOnBackground,
    TextOnSurface,
    PrimaryText,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThemeWarning {
    pub scheme: ColorScheme,
    pub pair: ContrastPair,
    pub ratio: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct CssError {
    pub line: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ThemeError {
    #[error("{field} must be a hex colour")]
    Color { field: String },
    #[error("radius {value} out of range")]
    Radius { value: u8 },
    #[error("font family invalid")]
    FontFamily,
    #[error("contrast too low")]
    Contrast {
        scheme: ColorScheme,
        pair: ContrastPair,
        ratio: f64,
    },
    #[error("custom CSS: {0}")]
    Css(CssError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LogoError {
    #[error("empty")]
    Empty,
    #[error("too large")]
    TooLarge,
    #[error("unsupported")]
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    pub fn parse(_s: &str) -> Option<Self> {
        todo!("04-09 GREEN")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeCss {
    pub css: String,
    pub hash: String,
}

pub fn is_hex_color(_s: &str) -> bool {
    todo!("04-09 GREEN")
}

pub fn contrast_ratio(_a: Rgb, _b: Rgb) -> f64 {
    todo!("04-09 GREEN")
}

pub fn validate_tokens(_t: &ThemeTokens) -> Result<Vec<ThemeWarning>, ThemeError> {
    todo!("04-09 GREEN")
}

pub fn validate_custom_css(_css: &str) -> Result<(), CssError> {
    todo!("04-09 GREEN")
}

pub fn merge_tokens(
    _default: &ThemeTokens,
    _tenant: Option<&ThemeTokens>,
    _client: Option<&ThemeTokens>,
) -> ThemeTokens {
    todo!("04-09 GREEN")
}

pub fn theme_stylesheet(
    _tokens: &ThemeTokens,
    _custom_css: Option<&str>,
) -> Result<ThemeCss, ThemeError> {
    todo!("04-09 GREEN")
}

pub fn sniff_logo(_bytes: &[u8]) -> Result<&'static str, LogoError> {
    todo!("04-09 GREEN")
}

#[allow(dead_code)]
const LIGHT_DEFAULTS: &[(&str, &str)] = &[];
#[allow(dead_code)]
const DARK_DEFAULTS: &[(&str, &str)] = &[];
#[allow(dead_code)]
fn _unused(_c: &ThemeColors) {}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rgb(s: &str) -> Rgb {
        Rgb::parse(s).unwrap()
    }

    fn s(v: &str) -> Option<String> {
        Some(v.to_owned())
    }

    fn colors(f: impl FnOnce(&mut ThemeColors)) -> ThemeColors {
        let mut c = ThemeColors::default();
        f(&mut c);
        c
    }

    fn light(f: impl FnOnce(&mut ThemeColors)) -> ThemeTokens {
        ThemeTokens {
            colors: colors(f),
            ..ThemeTokens::default()
        }
    }

    fn field_mut<'a>(c: &'a mut ThemeColors, name: &str) -> &'a mut Option<String> {
        match name {
            "primary" => &mut c.primary,
            "primary_text" => &mut c.primary_text,
            "bg" => &mut c.bg,
            "surface" => &mut c.surface,
            "text" => &mut c.text,
            "muted" => &mut c.muted,
            "border" => &mut c.border,
            "focus" => &mut c.focus,
            "danger" => &mut c.danger,
            other => panic!("unknown field {other}"),
        }
    }

    const FIELDS: [&str; 9] = [
        "primary",
        "primary_text",
        "bg",
        "surface",
        "text",
        "muted",
        "border",
        "focus",
        "danger",
    ];

    // ---------------------------------------------------------------- colours and tokens

    #[test]
    fn color_syntax_accepts_only_hex_forms() {
        for ok in ["#abc", "#ABC", "#a1b2c3", "#A1B2C3ff", "#000", "#ffffff"] {
            assert!(is_hex_color(ok), "{ok}");
        }
        for bad in [
            "red",
            "#12",
            "#1234",
            "#12345",
            "#1234567",
            "#123456789",
            "rgb(0,0,0)",
            "#ggg",
            "",
            "#",
            "123456",
            " #123456",
            "#123456 ",
            "#12345;}",
            "#ab\u{0}",
            "#ａｂｃ",
        ] {
            assert!(!is_hex_color(bad), "{bad:?}");
        }
    }

    #[test]
    fn validate_tokens_rejects_bad_colors_with_field() {
        for bad in ["red", "#12", "rgb(1,2,3)", "#1234567"] {
            let t = light(|c| c.primary = s(bad));
            assert_eq!(
                validate_tokens(&t),
                Err(ThemeError::Color {
                    field: "colors.primary".into()
                }),
                "{bad}"
            );
        }
        let t = ThemeTokens {
            colors_dark: Some(colors(|c| c.danger = s("blue"))),
            ..ThemeTokens::default()
        };
        assert_eq!(
            validate_tokens(&t),
            Err(ThemeError::Color {
                field: "colors_dark.danger".into()
            })
        );
    }

    #[test]
    fn every_color_field_is_checked() {
        for name in FIELDS {
            let mut c = ThemeColors::default();
            *field_mut(&mut c, name) = s("#12345;}a{");
            let t = ThemeTokens {
                colors: c.clone(),
                ..ThemeTokens::default()
            };
            assert_eq!(
                validate_tokens(&t),
                Err(ThemeError::Color {
                    field: format!("colors.{name}")
                })
            );
            let t = ThemeTokens {
                colors_dark: Some(c),
                ..ThemeTokens::default()
            };
            assert_eq!(
                validate_tokens(&t),
                Err(ThemeError::Color {
                    field: format!("colors_dark.{name}")
                })
            );
        }
    }

    #[test]
    fn radius_bounds() {
        for ok in [0, 1, 16, 32] {
            let t = ThemeTokens {
                radius_px: Some(ok),
                ..ThemeTokens::default()
            };
            assert_eq!(validate_tokens(&t), Ok(vec![]));
        }
        for bad in [33, 100, 255] {
            let t = ThemeTokens {
                radius_px: Some(bad),
                ..ThemeTokens::default()
            };
            assert_eq!(validate_tokens(&t), Err(ThemeError::Radius { value: bad }));
        }
    }

    #[test]
    fn font_family_charset() {
        let font = |f: &str| ThemeTokens {
            font_family: s(f),
            ..ThemeTokens::default()
        };
        for ok in [
            "system-ui, -apple-system, \"Segoe UI\", Roboto, sans-serif",
            "Inter",
            "'Open Sans', Arial",
            &"a".repeat(200),
        ] {
            assert_eq!(validate_tokens(&font(ok)), Ok(vec![]), "{ok}");
        }
        for bad in [
            "Arial; } body{",
            "x url(evil)",
            "",
            "   ",
            &"a".repeat(201),
            "\"Unclosed",
            "'mixed\"",
            "Arial\n",
            "Ar<ial",
            "Arial\\",
            "Arial/*",
            "Arial:x",
            "Ärial",
        ] {
            assert_eq!(
                validate_tokens(&font(bad)),
                Err(ThemeError::FontFamily),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn contrast_ratio_matches_wcag() {
        assert!((contrast_ratio(rgb("#000"), rgb("#fff")) - 21.0).abs() < 1e-9);
        assert!((contrast_ratio(rgb("#fff"), rgb("#000")) - 21.0).abs() < 1e-9);
        assert!((contrast_ratio(rgb("#777"), rgb("#777777")) - 1.0).abs() < 1e-12);
        // The alpha channel is ignored.
        assert_eq!(
            contrast_ratio(rgb("#00000000"), rgb("#ffffff")),
            contrast_ratio(rgb("#000"), rgb("#fff"))
        );
        // Reference value: #767676 on white is 4.54:1.
        let r = contrast_ratio(rgb("#767676"), rgb("#ffffff"));
        assert!((r - 4.54).abs() < 0.01, "{r}");
    }

    fn on_white(text: &str) -> ThemeTokens {
        light(|c| {
            c.text = s(text);
            c.bg = s("#ffffff");
            c.surface = s("#ffffff");
        })
    }

    #[test]
    fn text_contrast_thresholds() {
        let low = contrast_ratio(rgb("#999999"), rgb("#ffffff"));
        assert!(low > 2.8 && low < 3.0, "{low}");
        match validate_tokens(&on_white("#999999")) {
            Err(ThemeError::Contrast {
                scheme: ColorScheme::Light,
                pair: ContrastPair::TextOnBackground,
                ratio,
            }) => assert!((ratio - low).abs() < 1e-9),
            other => panic!("{other:?}"),
        }

        let mid = contrast_ratio(rgb("#808080"), rgb("#ffffff"));
        assert!((3.0..4.5).contains(&mid), "{mid}");
        let warnings = validate_tokens(&on_white("#808080")).unwrap();
        assert!(warnings.iter().any(|w| w.pair == ContrastPair::TextOnBackground
            && w.scheme == ColorScheme::Light
            && (w.ratio - mid).abs() < 1e-9));

        let high = contrast_ratio(rgb("#595959"), rgb("#ffffff"));
        assert!(high > 6.9, "{high}");
        assert_eq!(validate_tokens(&on_white("#595959")), Ok(vec![]));
    }

    #[test]
    fn primary_text_contrast_thresholds() {
        let t = light(|c| {
            c.primary = s("#ffffff");
            c.primary_text = s("#999999");
        });
        assert!(matches!(
            validate_tokens(&t),
            Err(ThemeError::Contrast {
                pair: ContrastPair::PrimaryText,
                ..
            })
        ));
        let t = light(|c| {
            c.primary = s("#ffffff");
            c.primary_text = s("#808080");
        });
        let w = validate_tokens(&t).unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].pair, ContrastPair::PrimaryText);
    }

    #[test]
    fn contrast_uses_defaults_for_uncustomised_colors() {
        assert_eq!(validate_tokens(&ThemeTokens::default()), Ok(vec![]));
        // A custom background equal to the default text colour.
        assert!(matches!(
            validate_tokens(&light(|c| c.bg = s("#1c1f24"))),
            Err(ThemeError::Contrast {
                pair: ContrastPair::TextOnBackground,
                ..
            })
        ));
        assert!(matches!(
            validate_tokens(&light(|c| c.surface = s("#1c1f24"))),
            Err(ThemeError::Contrast {
                pair: ContrastPair::TextOnSurface,
                ..
            })
        ));
    }

    #[test]
    fn dark_set_contrast_is_checked_against_dark_defaults() {
        let t = ThemeTokens {
            colors_dark: Some(colors(|c| c.text = s("#333333"))),
            ..ThemeTokens::default()
        };
        assert!(matches!(
            validate_tokens(&t),
            Err(ThemeError::Contrast {
                scheme: ColorScheme::Dark,
                pair: ContrastPair::TextOnBackground,
                ..
            })
        ));
        // Light text that is fine on the dark defaults is fine.
        let t = ThemeTokens {
            colors_dark: Some(colors(|c| c.text = s("#ffffff"))),
            ..ThemeTokens::default()
        };
        assert_eq!(validate_tokens(&t), Ok(vec![]));
        // A dark primary_text warning is tagged Dark.
        let t = ThemeTokens {
            colors_dark: Some(colors(|c| {
                c.primary = s("#ffffff");
                c.primary_text = s("#808080");
            })),
            ..ThemeTokens::default()
        };
        let w = validate_tokens(&t).unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].scheme, ColorScheme::Dark);
    }

    // ---------------------------------------------------------------- custom CSS

    #[test]
    fn css_accepts_plain_rules() {
        for ok in [
            "",
            "a{color:red}",
            ".anvil-card{border-radius:4px}",
            "/* brand */\n.anvil-card {\n  box-shadow: 0 1px 2px rgb(0 0 0 / 10%);\n}\n",
            "@media (max-width: 30rem) { .anvil-card { padding: 1rem } }",
            ":root{--anvil-primary:#123456}",
            ".x:not(.y){color:var(--anvil-text)}",
            "a{background:linear-gradient(90deg, #fff, #000)}",
            "a{content:\"hi\"}",
            "a[data-x='1']{color:red}",
            "a{color:red}\r\nb{color:blue}",
            "\ta{color:red}",
            "@keyframes f{from{opacity:0}to{opacity:1}}",
            "@supports (display:grid){a{display:grid}}",
            "a{width:calc(100% - 2rem)}",
        ] {
            assert_eq!(validate_custom_css(ok), Ok(()), "{ok:?}");
        }
    }

    #[test]
    fn css_forbidden_constructs_report_their_line() {
        for bad in [
            "@import 'x.css';",
            "@IMPORT 'x';",
            "@font-face{font-family:x}",
            "@namespace svg x;",
            "a{background:url(https://t.example/p.gif)}",
            "a{background:URL(x)}",
            "a{background:Url('x')}",
            "a{background:image-set(\"x\" 1x)}",
            "a{background:-webkit-image-set(\"x\" 1x)}",
            "a{width:expression(alert(1))}",
            "a{-moz-binding:x}",
            "a{behavior:x}",
            "a{behavior : x}",
            "a{color:javascript:x}",
            "a{content:\"\\75 rl(\"}",
            "a{x:'</style><script>'}",
            "a{color:red}<",
            "</style>",
            "/* url(x) */",
            "/* @import */",
            "a{content:'url('}",
            "a{background:u/**/rl(x)}",
            // Allow-listed functions and at-rules only.
            "a{background:src(\"x\")}",
            "a{x:attr(href)}",
            "a{x:image(\"y\")}",
            "a{x:cross-fade(a,b)}",
            "a{x:element(#a)}",
            "a{x:paint(a)}",
            "@charset \"utf-8\";",
            "@page{margin:0}",
            "@document x{}",
            "@{}",
        ] {
            let css = format!("a{{color:red}}\n/* ok */\n{bad}\nb{{color:blue}}\n");
            let err = validate_custom_css(&css).expect_err(bad);
            assert_eq!(err.line, 3, "{bad:?}: {err}");
            assert!(!err.message.is_empty());
        }
    }

    #[test]
    fn css_structure_errors() {
        for (bad, line) in [
            ("a{color:red", 1),
            ("a{color:red}}", 1),
            ("a{\n}\n}", 3),
            ("}a{", 1),
            ("a{}\n/* open", 2),
            ("a{content:'x}", 1),
            ("a{content:\"x\ny\"}", 1),
            ("a{color:rgb(0,0,0}", 1),
            ("a[x{}", 1),
            ("@media (x{}", 1),
            ("a{color:red)", 1),
        ] {
            let err = validate_custom_css(bad).expect_err(bad);
            assert_eq!(err.line, line, "{bad:?}: {err}");
        }
    }

    #[test]
    fn css_size_cap() {
        let fits = format!("/*{}*/", "x".repeat(MAX_CUSTOM_CSS_BYTES - 4));
        assert_eq!(fits.len(), MAX_CUSTOM_CSS_BYTES);
        assert_eq!(validate_custom_css(&fits), Ok(()));
        let over = format!("/*{}*/", "x".repeat(MAX_CUSTOM_CSS_BYTES - 3));
        assert!(validate_custom_css(&over).is_err());
    }

    #[test]
    fn css_control_characters_refused() {
        for bad in [
            "a{color:red}\u{0}",
            "a{color:red}\u{7}",
            "a{color:red}\u{c}",
            "a{color:red}\u{1b}",
            "a{color:red}\u{7f}",
            "a{color:red}\u{85}",
            "a{}\rb{}",
        ] {
            assert!(validate_custom_css(bad).is_err(), "{bad:?}");
        }
        assert_eq!(validate_custom_css("a{}\n\u{0}").unwrap_err().line, 2);
    }

    // ---------------------------------------------------------------- merge

    #[test]
    fn merge_precedence_per_field() {
        let default = ThemeTokens {
            colors: colors(|c| {
                c.primary = s("#111111");
                c.text = s("#222222");
            }),
            colors_dark: None,
            font_family: s("A"),
            radius_px: Some(4),
        };
        let tenant = ThemeTokens {
            colors: colors(|c| {
                c.primary = s("#333333");
                c.bg = s("#444444");
            }),
            colors_dark: Some(colors(|c| c.text = s("#555555"))),
            font_family: None,
            radius_px: Some(8),
        };
        let client = ThemeTokens {
            colors: colors(|c| c.primary = s("#666666")),
            colors_dark: Some(colors(|c| c.bg = s("#777777"))),
            font_family: s("B"),
            radius_px: None,
        };

        assert_eq!(merge_tokens(&default, None, None), default);

        let m = merge_tokens(&default, Some(&tenant), None);
        assert_eq!(m.colors.primary.as_deref(), Some("#333333"));
        assert_eq!(m.colors.text.as_deref(), Some("#222222"));
        assert_eq!(m.colors.bg.as_deref(), Some("#444444"));
        assert_eq!(m.radius_px, Some(8));
        assert_eq!(m.font_family.as_deref(), Some("A"));
        assert_eq!(m.colors_dark, Some(colors(|c| c.text = s("#555555"))));

        let m = merge_tokens(&default, Some(&tenant), Some(&client));
        assert_eq!(m.colors.primary.as_deref(), Some("#666666"));
        assert_eq!(m.colors.text.as_deref(), Some("#222222"));
        assert_eq!(m.colors.bg.as_deref(), Some("#444444"));
        assert_eq!(m.radius_px, Some(8));
        assert_eq!(m.font_family.as_deref(), Some("B"));
        assert_eq!(
            m.colors_dark,
            Some(colors(|c| {
                c.text = s("#555555");
                c.bg = s("#777777");
            }))
        );

        let m = merge_tokens(&default, None, Some(&client));
        assert_eq!(m.colors.primary.as_deref(), Some("#666666"));
        assert_eq!(m.radius_px, Some(4));
        assert_eq!(m.colors_dark, Some(colors(|c| c.bg = s("#777777"))));
    }

    // ---------------------------------------------------------------- stylesheet

    #[test]
    fn stylesheet_for_defaults_is_empty() {
        let c = theme_stylesheet(&ThemeTokens::default(), None).unwrap();
        assert_eq!(c.css, "");
        // SHA-256 of the empty string.
        assert_eq!(
            c.hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn stylesheet_snapshot() {
        let t = ThemeTokens {
            colors: colors(|c| {
                c.primary = s("#2F5BD3");
                c.primary_text = s("#fff");
            }),
            colors_dark: Some(colors(|c| c.primary = s("#6d8ef0"))),
            font_family: s("Inter, sans-serif"),
            radius_px: Some(8),
        };
        let c = theme_stylesheet(&t, Some("a{color:red}")).unwrap();
        assert_eq!(
            c.css,
            ":root{--anvil-primary:#2f5bd3;--anvil-primary-text:#fff;\
             --anvil-font:Inter, sans-serif;--anvil-radius:8px}\n\
             @media (prefers-color-scheme: dark){:root{--anvil-primary:#6d8ef0}}\n\
             a{color:red}"
        );
        assert_eq!(c.hash.len(), 64);
        assert!(c.hash.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn stylesheet_is_deterministic() {
        let t = light(|c| {
            c.primary = s("#123456");
            c.danger = s("#aa0000");
        });
        let a = theme_stylesheet(&t, Some(".x{color:red}")).unwrap();
        let b = theme_stylesheet(&t.clone(), Some(".x{color:red}")).unwrap();
        assert_eq!(a, b);
        let c = theme_stylesheet(&t, Some(".x{color:blue}")).unwrap();
        assert_ne!(a.hash, c.hash);
    }

    #[test]
    fn custom_light_colors_without_dark_variant_pin_light_scheme() {
        let c = theme_stylesheet(&light(|c| c.primary = s("#123456")), None).unwrap();
        assert!(c.css.contains(":root{color-scheme: light}"), "{}", c.css);
        let dark = c
            .css
            .split("@media (prefers-color-scheme: dark){:root{")
            .nth(1)
            .expect("dark block pins the light palette");
        // The brand colour and every default light colour override the theme's dark block.
        assert!(dark.contains("--anvil-primary:#123456"));
        for (var, value) in LIGHT_DEFAULTS {
            if *var != "--anvil-primary" {
                assert!(dark.contains(&format!("{var}:{value}")), "{var}");
            }
        }

        // Only fonts/radius customised: nothing about colour schemes.
        let t = ThemeTokens {
            radius_px: Some(2),
            ..ThemeTokens::default()
        };
        let c = theme_stylesheet(&t, None).unwrap();
        assert!(!c.css.contains("color-scheme"));
        assert!(!c.css.contains("@media"));

        // A dark variant: no light pinning.
        let t = ThemeTokens {
            colors: colors(|c| c.primary = s("#123456")),
            colors_dark: Some(colors(|c| c.primary = s("#abcdef"))),
            ..ThemeTokens::default()
        };
        let c = theme_stylesheet(&t, None).unwrap();
        assert!(!c.css.contains("color-scheme"));
        assert!(c.css.contains("--anvil-primary:#abcdef"));
    }

    #[test]
    fn stylesheet_refuses_invalid_input() {
        assert_eq!(
            theme_stylesheet(&light(|c| c.primary = s("red;}")), None),
            Err(ThemeError::Color {
                field: "colors.primary".into()
            })
        );
        let t = ThemeTokens {
            font_family: s("x}body{"),
            ..ThemeTokens::default()
        };
        assert_eq!(theme_stylesheet(&t, None), Err(ThemeError::FontFamily));
        assert!(matches!(
            theme_stylesheet(&ThemeTokens::default(), Some("a{")),
            Err(ThemeError::Css(_))
        ));
    }

    #[test]
    fn default_tables_match_anvil_css() {
        let css = include_str!("../../../../themes/default/static/anvil.css");
        let (light_part, rest) = css.split_once("@media (prefers-color-scheme: dark)").unwrap();
        let dark_part = &rest[..rest.find("\n}\n").unwrap()];
        for (table, part) in [(LIGHT_DEFAULTS, light_part), (DARK_DEFAULTS, dark_part)] {
            assert!(table.len() >= 15);
            for (var, value) in table {
                assert!(part.contains(&format!("{var}: {value};")), "{var}: {value}");
            }
        }
    }

    // ---------------------------------------------------------------- logo

    fn padded(prefix: &[u8], len: usize) -> Vec<u8> {
        let mut v = prefix.to_vec();
        v.resize(len, 0);
        v
    }

    #[test]
    fn logo_sniffing() {
        let png: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        let jpeg: &[u8] = &[0xff, 0xd8, 0xff, 0xe0];
        let webp: &[u8] = b"RIFF\x24\0\0\0WEBPVP8 ";
        assert_eq!(sniff_logo(&padded(png, 64)), Ok("image/png"));
        assert_eq!(sniff_logo(&padded(jpeg, 64)), Ok("image/jpeg"));
        assert_eq!(sniff_logo(&padded(webp, 64)), Ok("image/webp"));
        assert_eq!(sniff_logo(&padded(png, MAX_LOGO_BYTES)), Ok("image/png"));
        assert_eq!(
            sniff_logo(&padded(png, MAX_LOGO_BYTES + 1)),
            Err(LogoError::TooLarge)
        );
        assert_eq!(sniff_logo(b""), Err(LogoError::Empty));
        for bad in [
            &b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"[..],
            b"<?xml version='1.0'?><svg/>",
            b"  <svg/>",
            b"GIF89a\x01\0\x01\0",
            b"RIFF\x24\0\0\0WAVEfmt ",
            b"RIFF\x24\0\0",
            &png[..7],
            &jpeg[..2],
            b"\0\0\0\0",
        ] {
            assert_eq!(sniff_logo(bad), Err(LogoError::Unsupported), "{bad:?}");
        }
    }

    // ---------------------------------------------------------------- properties

    /// Independent bracket/comment/string scanner used to check that accepted output never escapes.
    #[derive(Debug, PartialEq)]
    struct Scan {
        /// Byte offsets where depth returned to zero.
        closes: Vec<usize>,
        balanced: bool,
    }

    fn scan(css: &str) -> Scan {
        let b = css.as_bytes();
        let (mut i, mut depth, mut closes, mut ok) = (0usize, 0i64, Vec::new(), true);
        while i < b.len() {
            match b[i] {
                b'/' if b.get(i + 1) == Some(&b'*') => match css[i + 2..].find("*/") {
                    Some(end) => i += end + 3,
                    None => {
                        ok = false;
                        break;
                    }
                },
                q @ (b'"' | b'\'') => match css[i + 1..].find(q as char) {
                    Some(end) => i += end + 1,
                    None => {
                        ok = false;
                        break;
                    }
                },
                b'{' | b'(' | b'[' => depth += 1,
                b'}' | b')' | b']' => {
                    depth -= 1;
                    if depth < 0 {
                        ok = false;
                        break;
                    }
                    if depth == 0 {
                        closes.push(i);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        Scan {
            closes,
            balanced: ok && depth == 0,
        }
    }

    fn fragment() -> impl Strategy<Value = &'static str> {
        prop::sample::select(vec![
            "a", ".x", "{", "}", "color:red;", "/*", "*/", "\"", "'", "(", ")", "[", "]", "@media",
            "@import", " ", "\n", "rgb(", "url(", "uRl(", "<", "</style>", "\\", ":root", "--anvil-x:1",
            "var(", "@x", "\r", "\u{0}", ";", ":", "behavior", "expression(",
        ])
    }

    proptest! {
        #[test]
        fn url_in_any_casing_is_rejected(
            prefix in ".{0,64}",
            suffix in ".{0,64}",
            mask in any::<[bool; 3]>(),
        ) {
            let word: String = "url"
                .chars()
                .zip(mask)
                .map(|(c, up)| if up { c.to_ascii_uppercase() } else { c })
                .collect();
            let css = format!("{prefix}{word}({suffix}");
            prop_assert!(validate_custom_css(&css).is_err());
        }

        #[test]
        fn accepted_css_never_escapes_its_context(
            parts in prop::collection::vec(fragment(), 0..24),
            noise in "[a-z{}()\\[\\]\"'/*;:@ \n<\\\\-]{0,40}",
        ) {
            for css in [parts.concat(), noise] {
                if validate_custom_css(&css).is_err() {
                    continue;
                }
                let lower = css.to_ascii_lowercase();
                prop_assert!(!lower.contains('<') && !lower.contains('\\'));
                prop_assert!(!lower.contains("url(") && !lower.contains("@import"));
                prop_assert!(scan(&css).balanced, "{:?}", css);

                let tokens = light(|c| c.primary = s("#123456"));
                let sheet = theme_stylesheet(&tokens, Some(&css)).unwrap();
                let base = theme_stylesheet(&tokens, None).unwrap();
                // The generated part is a prefix whose blocks all close before the custom CSS.
                prop_assert!(sheet.css.starts_with(&base.css));
                let full = scan(&sheet.css);
                prop_assert!(full.balanced);
                let generated = scan(&base.css);
                prop_assert!(generated.balanced);
                prop_assert_eq!(&full.closes[..generated.closes.len()], &generated.closes[..]);
            }
        }

        #[test]
        fn accepted_tokens_stay_in_their_declaration(
            color in "[#a-fA-F0-9;{}()<>\"' ]{0,10}",
            font in "[A-Za-z ,'\"{};:()<\\\\-]{0,20}",
            radius in any::<u8>(),
        ) {
            let t = ThemeTokens {
                colors: colors(|c| c.primary = Some(color.clone())),
                font_family: Some(font.clone()),
                radius_px: Some(radius),
                ..ThemeTokens::default()
            };
            if let Ok(sheet) = theme_stylesheet(&t, None) {
                let v = validate_tokens(&t);
                prop_assert!(matches!(v, Ok(_) | Err(ThemeError::Contrast { .. })), "{:?}", v);
                let first = sheet.css.lines().next().unwrap();
                let sc = scan(first);
                prop_assert!(sc.balanced, "{:?}", first);
                // The :root block closes exactly at the end of its line.
                prop_assert_eq!(sc.closes, vec![first.len() - 1]);
                prop_assert!(!first.contains('<') && !first.contains('\\'));
                // Exactly three declarations (primary, font, radius).
                let inner = &first[":root{".len()..first.len() - 1];
                let semis = inner.bytes().filter(|b| *b == b';').count();
                prop_assert_eq!(semis, 2, "{:?}", first);
            }
        }
    }
}
