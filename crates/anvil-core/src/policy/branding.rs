//! Branding policy (UI-03): validation of theme tokens, custom CSS and logos, per-scope token
//! merging and deterministic generation of the theme stylesheet. Pure functions, std only.
//!
//! # Threat model
//!
//! The only author of theme input is a tenant administrator. That person already controls what their
//! users see, so the goal is not to contain a hostile admin. The validators exist to:
//!
//! - stop accidental tracking pixels and external loads (`url(`, `@import`, `image-set(`, ...);
//! - keep a branding record from breaking out of its place in the generated stylesheet (unbalanced
//!   braces, strings or comments, `</style>`, escape obfuscation with backslashes);
//! - keep the login pages at the UI-02 AA commitment (contrast below 3:1 is refused, below 4.5:1 is a
//!   warning the console shows).
//!
//! CSS is served per tenant only, so one tenant's CSS can never reach another tenant's pages. The strict
//! page CSP (`default-src 'none'; style-src 'self'; font-src 'self'; img-src 'self'`) stays the real
//! control: even a validator bypass cannot load an external resource or run script. The custom CSS
//! validator is an allow-list for at-rules and functions, plus a deny-list of known-dangerous
//! substrings that is matched case-insensitively both in the raw text (including comments and strings)
//! and in a view with comments and whitespace removed.
//!
//! SVG logos are refused: navigating to an SVG served from our origin would execute its script.

use serde::Serialize;

use crate::model::{ThemeColors, ThemeTokens};

/// Maximum size of custom CSS in bytes (32 KiB).
pub const MAX_CUSTOM_CSS_BYTES: usize = 32 * 1024;
/// Maximum size of a logo in bytes (256 KiB).
pub const MAX_LOGO_BYTES: usize = 256 * 1024;
/// Largest accepted corner radius in px.
pub const MAX_RADIUS_PX: u8 = 32;
/// Longest accepted font-family value in characters.
pub const MAX_FONT_FAMILY_LEN: usize = 200;
/// Contrast below this ratio is refused.
pub const MIN_CONTRAST: f64 = 3.0;
/// Contrast below this ratio (WCAG AA for normal text) yields a warning.
pub const AA_CONTRAST: f64 = 4.5;

/// The colour scheme a contrast finding belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ColorScheme {
    Light,
    Dark,
}

impl std::fmt::Display for ColorScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Light => "light",
            Self::Dark => "dark",
        })
    }
}

/// A foreground/background pair whose contrast is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContrastPair {
    /// `text` on `bg`.
    TextOnBackground,
    /// `text` on `surface` (the card the forms sit on).
    TextOnSurface,
    /// `primary_text` on `primary` (buttons).
    PrimaryText,
}

impl std::fmt::Display for ContrastPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TextOnBackground => "text on background",
            Self::TextOnSurface => "text on surface",
            Self::PrimaryText => "primary text on primary",
        })
    }
}

/// A contrast between 3:1 and 4.5:1: accepted, but shown to the admin.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ThemeWarning {
    pub scheme: ColorScheme,
    pub pair: ContrastPair,
    pub ratio: f64,
}

/// Why custom CSS was refused; `line` is 1-based.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct CssError {
    pub line: u32,
    pub message: String,
}

/// Why theme input was refused.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ThemeError {
    #[error("{field} must be a hex colour (#rgb, #rrggbb or #rrggbbaa)")]
    Color { field: String },
    #[error("radius {value} px is out of range (0 to 32 px)")]
    Radius { value: u8 },
    #[error(
        "font family may only contain letters, digits, spaces, commas, hyphens and balanced quotes \
         (1 to 200 characters)"
    )]
    FontFamily,
    #[error("{scheme} {pair} contrast is {ratio:.2}:1, below the minimum of 3:1")]
    Contrast {
        scheme: ColorScheme,
        pair: ContrastPair,
        ratio: f64,
    },
    #[error("custom CSS: {0}")]
    Css(CssError),
}

/// Why a logo was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LogoError {
    #[error("the logo is empty")]
    Empty,
    #[error("the logo is larger than 256 KiB")]
    TooLarge,
    #[error("the logo must be a PNG, JPEG or WebP image")]
    Unsupported,
}

/// An sRGB colour parsed from `#rgb`, `#rrggbb` or `#rrggbbaa`. The alpha channel is accepted for
/// styling but ignored for contrast (the page background is opaque in every theme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Rgb {
    /// Parses `#rgb`, `#rrggbb` or `#rrggbbaa` (hex digits in any case); `None` otherwise.
    pub fn parse(s: &str) -> Option<Self> {
        let hex = s.strip_prefix('#')?.as_bytes();
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let nib = |b: u8| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => b - b'A' + 10,
        };
        match hex.len() {
            3 => {
                let [r, g, b] = [hex[0], hex[1], hex[2]].map(|c| nib(c) * 17);
                Some(Self { r, g, b })
            }
            6 | 8 => {
                let byte = |i: usize| nib(hex[i]) << 4 | nib(hex[i + 1]);
                Some(Self {
                    r: byte(0),
                    g: byte(2),
                    b: byte(4),
                })
            }
            _ => None,
        }
    }

    /// WCAG 2.x relative luminance.
    fn luminance(self) -> f64 {
        let lin = |c: u8| {
            let c = f64::from(c) / 255.0;
            if c <= 0.04045 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(self.r) + 0.7152 * lin(self.g) + 0.0722 * lin(self.b)
    }
}

/// The generated theme stylesheet and the lowercase hex SHA-256 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemeCss {
    pub css: String,
    pub hash: String,
}

/// Whether `s` is `#rgb`, `#rrggbb` or `#rrggbbaa`.
pub fn is_hex_color(s: &str) -> bool {
    Rgb::parse(s).is_some()
}

/// WCAG contrast ratio between two colours (1.0 to 21.0, order-independent).
pub fn contrast_ratio(a: Rgb, b: Rgb) -> f64 {
    let (la, lb) = (a.luminance(), b.luminance());
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

// ---------------------------------------------------------------------------------------------
// Defaults (mirrors themes/default/static/anvil.css; a test keeps them in sync)

/// Light palette of the default theme (Specianic), in output order.
const LIGHT_DEFAULTS: &[(&str, &str)] = &[
    ("--anvil-bg", "#fafaf9"),
    ("--anvil-surface", "#ffffff"),
    ("--anvil-text", "#0f0f10"),
    ("--anvil-muted", "#5c5a56"),
    ("--anvil-border", "#e5e3df"),
    ("--anvil-input-border", "#8f8c86"),
    ("--anvil-primary", "#ff5a1f"),
    ("--anvil-primary-text", "#0f0f10"),
    ("--anvil-danger", "#b42318"),
    ("--anvil-focus", "#c2410c"),
    ("--anvil-link", "#c2410c"),
    ("--anvil-success", "#1a7f4b"),
    ("--anvil-danger-bg", "#fef3f2"),
    ("--anvil-warning-bg", "#fffaeb"),
    ("--anvil-warning-border", "#b54708"),
    ("--anvil-warning-text", "#7a2e0e"),
    ("--anvil-code-bg", "#f3f2f0"),
];

/// Dark palette of the default theme (Specianic).
const DARK_DEFAULTS: &[(&str, &str)] = &[
    ("--anvil-bg", "#0f0f10"),
    ("--anvil-surface", "#18181a"),
    ("--anvil-text", "#f4f3f1"),
    ("--anvil-muted", "#a3a19c"),
    ("--anvil-border", "#2a2a2d"),
    ("--anvil-input-border", "#6a6a70"),
    ("--anvil-primary", "#ff5a1f"),
    ("--anvil-primary-text", "#0f0f10"),
    ("--anvil-danger", "#f0695e"),
    ("--anvil-focus", "#ff7a45"),
    ("--anvil-link", "#ff7a45"),
    ("--anvil-success", "#3ccf86"),
    ("--anvil-danger-bg", "#2a1614"),
    ("--anvil-warning-bg", "#2a2010"),
    ("--anvil-warning-border", "#f79009"),
    ("--anvil-warning-text", "#fedf89"),
    ("--anvil-code-bg", "#0a0a0b"),
];

/// The button pair of the default theme before the Specianic palette (0.x to 1.0-rc.3), per scheme:
/// `(primary, primary_text)`. A theme that customises only one side of the pair gets the other side
/// from here, both when it is validated and in the generated stylesheet. The Specianic button (ink on
/// orange) is a pair too: pairing a customer's colour with half of it would change existing themes'
/// buttons (white text turning dark) and could newly refuse stored themes.
const LEGACY_BUTTON_LIGHT: (&str, &str) = ("#2f5bd3", "#ffffff");
const LEGACY_BUTTON_DARK: (&str, &str) = ("#6d8ef0", "#0d1020");

fn legacy_button(scheme: ColorScheme) -> (&'static str, &'static str) {
    match scheme {
        ColorScheme::Light => LEGACY_BUTTON_LIGHT,
        ColorScheme::Dark => LEGACY_BUTTON_DARK,
    }
}

/// The partner the stylesheet must add when only one side of the button pair is customised:
/// `(variable, value)`, or `None` when both or neither are set.
fn button_partner(
    scheme: ColorScheme,
    primary_set: bool,
    primary_text_set: bool,
) -> Option<(&'static str, &'static str)> {
    let (primary, primary_text) = legacy_button(scheme);
    match (primary_set, primary_text_set) {
        (true, false) => Some(("--anvil-primary-text", primary_text)),
        (false, true) => Some(("--anvil-primary", primary)),
        _ => None,
    }
}

fn default_of(table: &[(&str, &'static str)], var: &str) -> &'static str {
    table
        .iter()
        .find(|(v, _)| *v == var)
        .map(|(_, value)| *value)
        .unwrap_or_default()
}

/// The colour fields of [`ThemeColors`] with their field name and CSS variable, in output order.
fn color_fields(c: &ThemeColors) -> [(&'static str, &'static str, Option<&str>); 9] {
    [
        ("primary", "--anvil-primary", c.primary.as_deref()),
        (
            "primary_text",
            "--anvil-primary-text",
            c.primary_text.as_deref(),
        ),
        ("bg", "--anvil-bg", c.bg.as_deref()),
        ("surface", "--anvil-surface", c.surface.as_deref()),
        ("text", "--anvil-text", c.text.as_deref()),
        ("muted", "--anvil-muted", c.muted.as_deref()),
        ("border", "--anvil-border", c.border.as_deref()),
        ("focus", "--anvil-focus", c.focus.as_deref()),
        ("danger", "--anvil-danger", c.danger.as_deref()),
    ]
}

fn has_any_color(c: &ThemeColors) -> bool {
    color_fields(c).iter().any(|(_, _, v)| v.is_some())
}

/// `colors_dark` only counts when it customises at least one colour.
fn dark_set(t: &ThemeTokens) -> Option<&ThemeColors> {
    t.colors_dark.as_ref().filter(|c| has_any_color(c))
}

// ---------------------------------------------------------------------------------------------
// Tokens

fn check_colors(prefix: &str, c: &ThemeColors) -> Result<(), ThemeError> {
    for (name, _, value) in color_fields(c) {
        if let Some(v) = value
            && !is_hex_color(v)
        {
            return Err(ThemeError::Color {
                field: format!("{prefix}.{name}"),
            });
        }
    }
    Ok(())
}

/// System font stacks only: `[A-Za-z0-9 ,'"-]`, 1 to 200 characters, not blank, quotes balanced
/// (a quote is closed by the same kind of quote).
fn is_valid_font_family(f: &str) -> bool {
    if f.is_empty() || f.len() > MAX_FONT_FAMILY_LEN || f.trim().is_empty() {
        return false;
    }
    let mut open: Option<u8> = None;
    for b in f.bytes() {
        if !(b.is_ascii_alphanumeric() || matches!(b, b' ' | b',' | b'\'' | b'"' | b'-')) {
            return false;
        }
        if matches!(b, b'\'' | b'"') {
            match open {
                None => open = Some(b),
                Some(q) if q == b => open = None,
                Some(_) => return false,
            }
        }
    }
    open.is_none()
}

/// Syntax checks only (colours, radius, font); no contrast.
fn check_syntax(t: &ThemeTokens) -> Result<(), ThemeError> {
    check_colors("colors", &t.colors)?;
    if let Some(dark) = &t.colors_dark {
        check_colors("colors_dark", dark)?;
    }
    if let Some(value) = t.radius_px
        && value > MAX_RADIUS_PX
    {
        return Err(ThemeError::Radius { value });
    }
    if let Some(f) = &t.font_family
        && !is_valid_font_family(f)
    {
        return Err(ThemeError::FontFamily);
    }
    Ok(())
}

fn check_contrast(
    scheme: ColorScheme,
    c: &ThemeColors,
    warnings: &mut Vec<ThemeWarning>,
) -> Result<(), ThemeError> {
    let defaults = match scheme {
        ColorScheme::Light => LIGHT_DEFAULTS,
        ColorScheme::Dark => DARK_DEFAULTS,
    };
    // A lone customised button colour is paired with the legacy partner (see LEGACY_BUTTON_LIGHT).
    let partner = button_partner(scheme, c.primary.is_some(), c.primary_text.is_some());
    // (custom value, CSS variable) -> effective colour.
    let eff = |v: Option<&String>, var: &str| -> Rgb {
        v.and_then(|s| Rgb::parse(s))
            .or_else(|| {
                partner
                    .filter(|(pv, _)| *pv == var)
                    .and_then(|(_, value)| Rgb::parse(value))
            })
            .or_else(|| Rgb::parse(default_of(defaults, var)))
            .unwrap_or(Rgb { r: 0, g: 0, b: 0 })
    };
    let pairs = [
        (
            ContrastPair::TextOnBackground,
            (c.text.as_ref(), "--anvil-text"),
            (c.bg.as_ref(), "--anvil-bg"),
        ),
        (
            ContrastPair::TextOnSurface,
            (c.text.as_ref(), "--anvil-text"),
            (c.surface.as_ref(), "--anvil-surface"),
        ),
        (
            ContrastPair::PrimaryText,
            (c.primary_text.as_ref(), "--anvil-primary-text"),
            (c.primary.as_ref(), "--anvil-primary"),
        ),
    ];
    for (pair, (fg, fg_var), (bg, bg_var)) in pairs {
        if fg.is_none() && bg.is_none() {
            continue;
        }
        let ratio = contrast_ratio(eff(fg, fg_var), eff(bg, bg_var));
        if ratio < MIN_CONTRAST {
            return Err(ThemeError::Contrast {
                scheme,
                pair,
                ratio,
            });
        }
        if ratio < AA_CONTRAST {
            warnings.push(ThemeWarning {
                scheme,
                pair,
                ratio,
            });
        }
    }
    Ok(())
}

/// Validates theme tokens: colour syntax, radius 0 to 32 px, font family charset, and WCAG contrast
/// for text/bg, text/surface and primary_text/primary in the light set and (when present) the dark
/// set. A pair is checked when either of its colours is customised; the other comes from the default
/// palette of that scheme, except that a lone `primary` or `primary_text` is paired with the legacy
/// button colour the stylesheet emits for it (`LEGACY_BUTTON_LIGHT`). Below 3:1 is an error, below
/// 4.5:1 a warning.
pub fn validate_tokens(t: &ThemeTokens) -> Result<Vec<ThemeWarning>, ThemeError> {
    check_syntax(t)?;
    let mut warnings = Vec::new();
    check_contrast(ColorScheme::Light, &t.colors, &mut warnings)?;
    if let Some(dark) = &t.colors_dark {
        check_contrast(ColorScheme::Dark, dark, &mut warnings)?;
    }
    Ok(warnings)
}

// ---------------------------------------------------------------------------------------------
// Custom CSS

/// Refused anywhere (raw text, including comments and strings, and the comment/whitespace-free view),
/// matched case-insensitively.
const FORBIDDEN: &[(&str, &str)] = &[
    ("@import", "@import is not allowed"),
    ("@font-face", "@font-face is not allowed"),
    ("@namespace", "@namespace is not allowed"),
    (
        "url(",
        "url() is not allowed: themes cannot load external or data resources",
    ),
    ("image-set(", "image-set() is not allowed"),
    ("expression(", "expression() is not allowed"),
    ("-moz-binding", "-moz-binding is not allowed"),
    ("behavior:", "behavior is not allowed"),
    ("javascript:", "javascript: is not allowed"),
    ("\\", "backslash escapes are not allowed"),
    ("<", "'<' is not allowed"),
];

/// At-rules custom CSS may use.
const ALLOWED_AT_RULES: &[&str] = &["media", "supports", "keyframes", "layer", "container"];

/// Functions (and functional pseudo-classes) custom CSS may use. Everything that can reference a
/// resource (`url`, `src`, `image`, `image-set`, `cross-fade`, `element`, `paint`) or read document
/// data (`attr`) is absent.
#[rustfmt::skip]
const ALLOWED_FUNCTIONS: &[&str] = &[
    // colours and values
    "rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch", "color", "color-mix", "var",
    "calc", "min", "max", "clamp", "round", "abs", "sign", "mod", "rem",
    // gradients
    "linear-gradient", "radial-gradient", "conic-gradient", "repeating-linear-gradient",
    "repeating-radial-gradient", "repeating-conic-gradient",
    // transforms and timing
    "translate", "translatex", "translatey", "translatez", "translate3d", "rotate", "rotatex",
    "rotatey", "rotatez", "rotate3d", "scale", "scalex", "scaley", "scalez", "scale3d", "skew",
    "skewx", "skewy", "matrix", "matrix3d", "perspective", "cubic-bezier", "steps",
    // grid
    "minmax", "repeat", "fit-content",
    // filters
    "blur", "brightness", "contrast", "drop-shadow", "grayscale", "hue-rotate", "invert", "opacity",
    "saturate", "sepia",
    // selectors
    "not", "is", "where", "has", "nth-child", "nth-last-child", "nth-of-type", "nth-last-of-type",
    "lang", "dir", "selector",
];

/// Ident bytes for function/at-rule names (non-ASCII bytes count, as in CSS).
fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b >= 0x80
}

fn css_err(line: u32, message: impl Into<String>) -> CssError {
    CssError {
        line,
        message: message.into(),
    }
}

/// Earliest forbidden needle in `hay` (already lowercase), as (offset, message).
fn find_forbidden(hay: &[u8]) -> Option<(usize, &'static str)> {
    FORBIDDEN
        .iter()
        .filter_map(|(needle, msg)| {
            hay.windows(needle.len())
                .position(|w| w == needle.as_bytes())
                .map(|pos| (pos, *msg))
        })
        .min_by_key(|(pos, _)| *pos)
}

fn line_at(bytes: &[u8], offset: usize) -> u32 {
    let n = bytes[..offset.min(bytes.len())]
        .iter()
        .filter(|b| **b == b'\n')
        .count();
    u32::try_from(n + 1).unwrap_or(u32::MAX)
}

/// Validates tenant custom CSS (conservative allow-list; see the module docs):
///
/// - at most 32 KiB; no control characters (tab, LF and CRLF are fine);
/// - none of `@import`, `@font-face`, `@namespace`, `url(`, `image-set(`, `expression(`,
///   `-moz-binding`, `behavior:`, `javascript:`, a backslash or `<`, in any case, also inside comments
///   and strings and with comments or whitespace in between;
/// - only allow-listed at-rules and functions;
/// - balanced and properly nested `{}`, `()`, `[]`; terminated comments and single-line strings.
///
/// Errors carry the 1-based line of the offending construct.
pub fn validate_custom_css(css: &str) -> Result<(), CssError> {
    let bytes = css.as_bytes();
    if bytes.len() > MAX_CUSTOM_CSS_BYTES {
        return Err(css_err(
            line_at(bytes, MAX_CUSTOM_CSS_BYTES),
            "custom CSS is larger than 32 KiB",
        ));
    }

    // Control characters.
    let mut line = 1u32;
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => line += 1,
            '\t' => {}
            '\r' if chars.peek() == Some(&'\n') => {}
            c if c.is_control() => {
                return Err(css_err(line, "control characters are not allowed"));
            }
            _ => {}
        }
    }

    // Forbidden substrings in the raw text (comments and strings included).
    let lower = css.to_ascii_lowercase();
    if let Some((pos, msg)) = find_forbidden(lower.as_bytes()) {
        return Err(css_err(line_at(bytes, pos), msg));
    }

    // Structure pass; also builds the view without comments and whitespace.
    let lb = lower.as_bytes();
    let mut compact: Vec<u8> = Vec::with_capacity(lb.len());
    let mut compact_lines: Vec<u32> = Vec::with_capacity(lb.len());
    let mut stack: Vec<(u8, u32)> = Vec::new();
    let mut structural: Option<CssError> = None;
    let mut line = 1u32;
    let mut i = 0usize;
    while i < lb.len() && structural.is_none() {
        let b = lb[i];
        match b {
            b'/' if lb.get(i + 1) == Some(&b'*') => {
                let start = line;
                i += 2;
                loop {
                    match lb.get(i) {
                        None => {
                            structural = Some(css_err(start, "unterminated comment"));
                            break;
                        }
                        Some(b'*') if lb.get(i + 1) == Some(&b'/') => {
                            i += 2;
                            break;
                        }
                        Some(c) => {
                            if *c == b'\n' {
                                line += 1;
                            }
                            i += 1;
                        }
                    }
                }
                continue;
            }
            b'"' | b'\'' => {
                let start = line;
                compact.push(b);
                compact_lines.push(line);
                i += 1;
                loop {
                    match lb.get(i) {
                        None | Some(b'\n' | b'\r') => {
                            structural = Some(css_err(start, "unterminated string"));
                            break;
                        }
                        Some(c) => {
                            compact.push(*c);
                            compact_lines.push(line);
                            i += 1;
                            if *c == b {
                                break;
                            }
                        }
                    }
                }
                continue;
            }
            b'{' | b'(' | b'[' => {
                if b == b'(' {
                    let start = lb[..i]
                        .iter()
                        .rposition(|c| !is_ident_byte(*c))
                        .map_or(0, |p| p + 1);
                    let name = &css[start..i];
                    if !name.is_empty()
                        && !ALLOWED_FUNCTIONS.contains(&name.to_ascii_lowercase().as_str())
                    {
                        structural =
                            Some(css_err(line, format!("function {name}() is not allowed")));
                    }
                }
                stack.push((b, line));
            }
            b'}' | b')' | b']' => {
                let open = match b {
                    b'}' => b'{',
                    b')' => b'(',
                    _ => b'[',
                };
                match stack.pop() {
                    Some((o, _)) if o == open => {}
                    _ => {
                        structural = Some(css_err(line, format!("unbalanced '{}'", b as char)));
                    }
                }
            }
            b'@' => {
                let end = lb[i + 1..]
                    .iter()
                    .position(|c| !is_ident_byte(*c))
                    .map_or(lb.len(), |p| i + 1 + p);
                let name = &css[i + 1..end];
                if !ALLOWED_AT_RULES.contains(&name.to_ascii_lowercase().as_str()) {
                    structural = Some(css_err(line, format!("at-rule @{name} is not allowed")));
                }
            }
            _ => {}
        }
        if b == b'\n' {
            line += 1;
        }
        if !b.is_ascii_whitespace() {
            compact.push(b);
            compact_lines.push(line);
        }
        i += 1;
    }

    // Forbidden substrings hidden by comments or whitespace (`u/**/rl(`, `behavior : x`).
    if let Some((pos, msg)) = find_forbidden(&compact) {
        let at = compact_lines.get(pos).copied().unwrap_or(line);
        if structural.as_ref().is_none_or(|e| at <= e.line) {
            return Err(css_err(at, msg));
        }
    }
    if let Some(e) = structural {
        return Err(e);
    }
    if let Some((open, at)) = stack.last() {
        return Err(css_err(*at, format!("unclosed '{}'", *open as char)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Merge and stylesheet

fn merge_colors(layers: &[&ThemeColors]) -> ThemeColors {
    let pick =
        |f: fn(&ThemeColors) -> &Option<String>| layers.iter().rev().find_map(|c| f(c).clone());
    ThemeColors {
        primary: pick(|c| &c.primary),
        primary_text: pick(|c| &c.primary_text),
        bg: pick(|c| &c.bg),
        surface: pick(|c| &c.surface),
        text: pick(|c| &c.text),
        muted: pick(|c| &c.muted),
        border: pick(|c| &c.border),
        focus: pick(|c| &c.focus),
        danger: pick(|c| &c.danger),
    }
}

/// Merges tokens per field with precedence client > tenant > `default`. `colors_dark` is merged per
/// colour across the layers that define it and stays `None` when none does.
pub fn merge_tokens(
    default: &ThemeTokens,
    tenant: Option<&ThemeTokens>,
    client: Option<&ThemeTokens>,
) -> ThemeTokens {
    // Lowest precedence first.
    let layers: Vec<&ThemeTokens> = [Some(default), tenant, client]
        .into_iter()
        .flatten()
        .collect();
    let light: Vec<&ThemeColors> = layers.iter().map(|t| &t.colors).collect();
    let dark: Vec<&ThemeColors> = layers
        .iter()
        .filter_map(|t| t.colors_dark.as_ref())
        .collect();
    ThemeTokens {
        colors: merge_colors(&light),
        colors_dark: (!dark.is_empty()).then(|| merge_colors(&dark)),
        font_family: layers.iter().rev().find_map(|t| t.font_family.clone()),
        radius_px: layers.iter().rev().find_map(|t| t.radius_px),
    }
}

fn push_block(out: &mut String, decls: &[(String, String)]) {
    out.push_str(":root{");
    for (n, (var, value)) in decls.iter().enumerate() {
        if n > 0 {
            out.push(';');
        }
        out.push_str(var);
        out.push(':');
        out.push_str(value);
    }
    out.push('}');
}

fn color_decls(c: &ThemeColors) -> Vec<(String, String)> {
    color_fields(c)
        .into_iter()
        .filter_map(|(_, var, v)| v.map(|v| (var.to_owned(), v.to_ascii_lowercase())))
        .collect()
}

/// The colour declarations of one scheme block: the customised colours, the legacy partner of a lone
/// button colour, and `--anvil-link` / `--anvil-focus` derived from a customised `primary`. The `*_set`
/// flags say whether the effective value in this scheme is customer-provided (in the dark scheme that
/// includes light values, which apply there too).
fn scheme_color_decls(
    c: &ThemeColors,
    scheme: ColorScheme,
    primary_set: bool,
    primary_text_set: bool,
    focus_set: bool,
) -> Vec<(String, String)> {
    let mut decls = color_decls(c);
    if let Some((var, value)) = button_partner(scheme, primary_set, primary_text_set) {
        decls.push((var.to_owned(), value.to_owned()));
    }
    if let Some(primary) = &c.primary {
        let primary = primary.to_ascii_lowercase();
        decls.push(("--anvil-link".to_owned(), primary.clone()));
        if !focus_set {
            decls.push(("--anvil-focus".to_owned(), primary));
        }
    }
    decls
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 0xf)] as char);
    }
    s
}

/// Generates the theme stylesheet served after `anvil.css`:
///
/// 1. `:root{…}` with the customised light colours, `--anvil-font` and `--anvil-radius` (fixed order,
///    colours lowercased), omitted when nothing is customised;
/// 2. with a dark set, `@media (prefers-color-scheme: dark){:root{…}}` with its colours; without one
///    but with custom light colours, `:root{color-scheme: light}` plus a dark-media block that pins the
///    whole light palette, so the default theme's dark block cannot override the brand;
/// 3. the custom CSS verbatim.
///
/// Derived variables keep a customer's look on the default theme, whose links, focus ring and cards
/// use their own variables: a customised `primary` also sets `--anvil-link` and (unless `focus` is
/// customised) `--anvil-focus`; `radius_px` also sets `--anvil-card-radius`; a lone `primary` or
/// `primary_text` gets the legacy partner colour (`LEGACY_BUTTON_LIGHT`, dark
/// `LEGACY_BUTTON_DARK`) so the button pair stays the one that was validated.
///
/// The input is re-checked (syntax and custom CSS, not contrast) so stored data can never break out of
/// its declaration. Same input, same bytes, same hash.
pub fn theme_stylesheet(
    tokens: &ThemeTokens,
    custom_css: Option<&str>,
) -> Result<ThemeCss, ThemeError> {
    check_syntax(tokens)?;
    if let Some(css) = custom_css {
        validate_custom_css(css).map_err(ThemeError::Css)?;
    }

    let light = &tokens.colors;
    let mut out = String::new();
    let light_colors = scheme_color_decls(
        light,
        ColorScheme::Light,
        light.primary.is_some(),
        light.primary_text.is_some(),
        light.focus.is_some(),
    );
    let mut decls = light_colors.clone();
    if let Some(font) = &tokens.font_family {
        decls.push(("--anvil-font".to_owned(), font.clone()));
    }
    if let Some(radius) = tokens.radius_px {
        decls.push(("--anvil-radius".to_owned(), format!("{radius}px")));
        decls.push(("--anvil-card-radius".to_owned(), format!("{radius}px")));
    }
    if !decls.is_empty() {
        push_block(&mut out, &decls);
        out.push('\n');
    }

    if let Some(dark) = dark_set(tokens) {
        // Light values without a dark counterpart apply in the dark scheme too (the :root block above
        // is not scheme-scoped), so the button pair and the focus fallback look at both sets.
        let dark_decls = scheme_color_decls(
            dark,
            ColorScheme::Dark,
            dark.primary.is_some() || light.primary.is_some(),
            dark.primary_text.is_some() || light.primary_text.is_some(),
            dark.focus.is_some() || light.focus.is_some(),
        );
        out.push_str("@media (prefers-color-scheme: dark){");
        push_block(&mut out, &dark_decls);
        out.push_str("}\n");
    } else if has_any_color(light) {
        out.push_str(":root{color-scheme: light}\n");
        let custom = light_colors;
        let pinned: Vec<(String, String)> = LIGHT_DEFAULTS
            .iter()
            .map(|(var, default)| {
                custom
                    .iter()
                    .find(|(v, _)| v == var)
                    .cloned()
                    .unwrap_or_else(|| ((*var).to_owned(), (*default).to_owned()))
            })
            .collect();
        out.push_str("@media (prefers-color-scheme: dark){");
        push_block(&mut out, &pinned);
        out.push_str("}\n");
    }

    if let Some(css) = custom_css {
        out.push_str(css);
    }

    let hash = hex(&anvil_jose::encoding::sha256(out.as_bytes()));
    Ok(ThemeCss { css: out, hash })
}

// ---------------------------------------------------------------------------------------------
// Logo

/// Identifies a logo by its magic bytes: PNG, JPEG or WebP, at most 256 KiB. SVG, GIF and anything
/// else are refused. Returns the content type to store and serve.
pub fn sniff_logo(bytes: &[u8]) -> Result<&'static str, LogoError> {
    if bytes.is_empty() {
        return Err(LogoError::Empty);
    }
    if bytes.len() > MAX_LOGO_BYTES {
        return Err(LogoError::TooLarge);
    }
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]) {
        Ok("image/png")
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Ok("image/jpeg")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Ok("image/webp")
    } else {
        Err(LogoError::Unsupported)
    }
}

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
        assert!(
            warnings
                .iter()
                .any(|w| w.pair == ContrastPair::TextOnBackground
                    && w.scheme == ColorScheme::Light
                    && (w.ratio - mid).abs() < 1e-9)
        );

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
             --anvil-link:#2f5bd3;--anvil-focus:#2f5bd3;\
             --anvil-font:Inter, sans-serif;--anvil-radius:8px;--anvil-card-radius:8px}\n\
             @media (prefers-color-scheme: dark){:root{--anvil-primary:#6d8ef0;\
             --anvil-link:#6d8ef0;--anvil-focus:#6d8ef0}}\n\
             a{color:red}"
        );
        assert_eq!(c.hash.len(), 64);
        assert!(
            c.hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
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
        // The brand colour, its derived variables and every default light colour override the
        // theme's dark block.
        let derived = [
            ("--anvil-primary", "#123456"),
            ("--anvil-primary-text", LEGACY_BUTTON_LIGHT.1),
            ("--anvil-link", "#123456"),
            ("--anvil-focus", "#123456"),
        ];
        for (var, value) in derived {
            assert!(dark.contains(&format!("{var}:{value}")), "{var}");
        }
        for (var, value) in LIGHT_DEFAULTS {
            if !derived.iter().any(|(v, _)| v == var) {
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
        assert!(!c.css.contains("color-scheme: light"));
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
        let (light_part, rest) = css
            .split_once("@media (prefers-color-scheme: dark)")
            .unwrap();
        let dark_part = &rest[..rest.find("\n}\n").unwrap()];
        for (table, part) in [(LIGHT_DEFAULTS, light_part), (DARK_DEFAULTS, dark_part)] {
            assert!(table.len() >= 15);
            for (var, value) in table {
                assert!(part.contains(&format!("{var}: {value};")), "{var}: {value}");
            }
        }
    }

    #[test]
    fn stylesheet_derives_link_focus_and_card_radius() {
        let c = theme_stylesheet(&light(|c| c.primary = s("#123456")), None).unwrap();
        let root = c.css.lines().next().unwrap();
        assert!(root.contains("--anvil-link:#123456"), "{root}");
        assert!(root.contains("--anvil-focus:#123456"), "{root}");

        // A customised focus colour is kept.
        let t = light(|c| {
            c.primary = s("#123456");
            c.focus = s("#00AA00");
        });
        let css = theme_stylesheet(&t, None).unwrap().css;
        assert!(css.contains("--anvil-focus:#00aa00"), "{css}");
        assert!(!css.contains("--anvil-focus:#123456"), "{css}");

        let t = ThemeTokens {
            radius_px: Some(8),
            ..ThemeTokens::default()
        };
        assert_eq!(
            theme_stylesheet(&t, None).unwrap().css,
            ":root{--anvil-radius:8px;--anvil-card-radius:8px}\n"
        );

        // Nothing customised: nothing derived.
        assert_eq!(
            theme_stylesheet(&ThemeTokens::default(), None).unwrap().css,
            ""
        );
        // Colours other than primary derive nothing.
        let css = theme_stylesheet(&light(|c| c.danger = s("#aa0000")), None)
            .unwrap()
            .css;
        let root = css.lines().next().unwrap();
        assert_eq!(root, ":root{--anvil-danger:#aa0000}");
    }

    #[test]
    fn lone_button_colour_keeps_its_legacy_partner() {
        // A dark blue primary: fine with the legacy white text, refused next to ink.
        assert!(contrast_ratio(rgb("#1d4ed8"), rgb(LEGACY_BUTTON_LIGHT.1)) >= AA_CONTRAST);
        assert!(
            contrast_ratio(
                rgb("#1d4ed8"),
                rgb(default_of(LIGHT_DEFAULTS, "--anvil-primary-text"))
            ) < MIN_CONTRAST
        );
        let t = light(|c| c.primary = s("#1d4ed8"));
        assert_eq!(validate_tokens(&t), Ok(vec![]));
        let css = theme_stylesheet(&t, None).unwrap().css;
        assert!(
            css.starts_with(":root{--anvil-primary:#1d4ed8;--anvil-primary-text:#ffffff;"),
            "{css}"
        );

        // A light primary_text alone is checked (and rendered) against the legacy primary.
        let t = light(|c| c.primary_text = s("#eeeeee"));
        assert!(
            contrast_ratio(
                rgb("#eeeeee"),
                rgb(default_of(LIGHT_DEFAULTS, "--anvil-primary"))
            ) < MIN_CONTRAST
        );
        assert_eq!(validate_tokens(&t), Ok(vec![]));
        let css = theme_stylesheet(&t, None).unwrap().css;
        assert!(css.contains("--anvil-primary:#2f5bd3"), "{css}");

        // The check still refuses a bad pair built from the legacy partner.
        assert!(matches!(
            validate_tokens(&light(|c| c.primary = s("#eeeeee"))),
            Err(ThemeError::Contrast {
                pair: ContrastPair::PrimaryText,
                ..
            })
        ));

        // Light primary without a dark counterpart: the dark block restores the legacy dark text so
        // the light partner (white) does not leak into the dark scheme.
        let t = ThemeTokens {
            colors: colors(|c| c.primary = s("#1d4ed8")),
            colors_dark: Some(colors(|c| c.bg = s("#000000"))),
            ..ThemeTokens::default()
        };
        let css = theme_stylesheet(&t, None).unwrap().css;
        let dark = css
            .split("@media (prefers-color-scheme: dark)")
            .nth(1)
            .unwrap();
        assert!(dark.contains("--anvil-primary-text:#0d1020"), "{css}");
        assert!(!dark.contains("--anvil-focus"), "{css}");

        // Both sides customised: no partner.
        let t = light(|c| {
            c.primary = s("#1d4ed8");
            c.primary_text = s("#fafafa");
        });
        let css = theme_stylesheet(&t, None).unwrap().css;
        assert_eq!(css.matches("--anvil-primary-text:").count(), 2, "{css}");
        assert!(!css.contains("#ffffff;--anvil-link"), "{css}");
    }

    #[test]
    fn default_palette_meets_contrast() {
        for (scheme, table) in [
            (ColorScheme::Light, LIGHT_DEFAULTS),
            (ColorScheme::Dark, DARK_DEFAULTS),
        ] {
            let c = |var: &str| rgb(default_of(table, var));
            let ratio = |fg: &str, bg: &str| contrast_ratio(c(fg), c(bg));
            // Ink on orange buttons (6.1:1) in both schemes.
            assert!(
                ratio("--anvil-primary-text", "--anvil-primary") > 6.0,
                "{scheme}"
            );
            for bg in ["--anvil-bg", "--anvil-surface", "--anvil-code-bg"] {
                for fg in ["--anvil-text", "--anvil-link", "--anvil-danger"] {
                    assert!(ratio(fg, bg) >= AA_CONTRAST, "{scheme} {fg} on {bg}");
                }
            }
            for bg in ["--anvil-bg", "--anvil-surface"] {
                for fg in ["--anvil-muted", "--anvil-success"] {
                    assert!(ratio(fg, bg) >= AA_CONTRAST, "{scheme} {fg} on {bg}");
                }
                for fg in ["--anvil-focus", "--anvil-input-border"] {
                    assert!(ratio(fg, bg) >= MIN_CONTRAST, "{scheme} {fg} on {bg}");
                }
            }
            assert!(ratio("--anvil-danger", "--anvil-danger-bg") >= AA_CONTRAST);
            assert!(ratio("--anvil-warning-text", "--anvil-warning-bg") >= AA_CONTRAST);
        }
        // Orange is never a text colour: on the light background it is only 3:1.
        assert!(
            contrast_ratio(
                rgb("#ff5a1f"),
                rgb(default_of(LIGHT_DEFAULTS, "--anvil-bg"))
            ) < AA_CONTRAST
        );
    }

    #[test]
    fn anvil_css_keeps_orange_a_fill_and_has_no_shadows() {
        let css = include_str!("../../../../themes/default/static/anvil.css");
        let squashed: String = css.split_whitespace().collect();
        assert!(!squashed.contains("color:var(--anvil-primary)"));
        assert!(!squashed.contains("border-color:var(--anvil-primary)"));
        assert!(!squashed.contains("outline:3pxsolidvar(--anvil-primary)"));
        assert!(!css.contains("box-shadow"));
        for font in [
            "fonts/HankenGrotesk-wght.ttf",
            "fonts/IBMPlexMono-Regular.woff2",
            "fonts/IBMPlexMono-Medium.woff2",
        ] {
            assert!(css.contains(&format!("url(\"{font}\")")), "{font}");
        }
        // Only relative, same-origin font URLs.
        assert!(!css.contains("http:") && !css.contains("https:") && !css.contains("//fonts"));
        for var in ["--anvil-link", "--anvil-card-radius", "--anvil-font-mono"] {
            assert!(css.contains(&format!("var({var})")), "{var} is used");
        }
    }

    /// Pre-Specianic defaults of the pairs the contrast check covers.
    const OLD_LIGHT: &[(&str, &str)] = &[
        ("--anvil-bg", "#f6f7f9"),
        ("--anvil-surface", "#ffffff"),
        ("--anvil-text", "#1c1f24"),
        ("--anvil-primary", "#2f5bd3"),
        ("--anvil-primary-text", "#ffffff"),
    ];
    const OLD_DARK: &[(&str, &str)] = &[
        ("--anvil-bg", "#14161a"),
        ("--anvil-surface", "#1d2026"),
        ("--anvil-text", "#e7e9ee"),
        ("--anvil-primary", "#6d8ef0"),
        ("--anvil-primary-text", "#0d1020"),
    ];

    /// Whether a theme customising only `field` passed the pre-Specianic contrast check.
    fn old_single_field_ok(old: &[(&str, &'static str)], field: &str, value: Rgb) -> bool {
        let pairs: &[(&str, &str)] = &[
            ("text", "bg"),
            ("text", "surface"),
            ("primary_text", "primary"),
        ];
        let var = |f: &str| format!("--anvil-{}", f.replace('_', "-"));
        pairs
            .iter()
            .filter_map(|(a, b)| {
                let other = if *a == field {
                    b
                } else if *b == field {
                    a
                } else {
                    return None;
                };
                Some(contrast_ratio(value, rgb(default_of(old, &var(other)))))
            })
            .all(|r| r >= MIN_CONTRAST)
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
            "a",
            ".x",
            "{",
            "}",
            "color:red;",
            "/*",
            "*/",
            "\"",
            "'",
            "(",
            ")",
            "[",
            "]",
            "@media",
            "@import",
            " ",
            "\n",
            "rgb(",
            "url(",
            "uRl(",
            "<",
            "</style>",
            "\\",
            ":root",
            "--anvil-x:1",
            "var(",
            "@x",
            "\r",
            "\u{0}",
            ";",
            ":",
            "behavior",
            "expression(",
        ])
    }

    proptest! {
        /// Stored themes are never newly refused by the new default palette: a theme customising
        /// one checked colour that passed against the old defaults still passes.
        #[test]
        fn single_colour_themes_valid_before_stay_valid(
            field in prop::sample::select(vec!["text", "bg", "surface", "primary", "primary_text"]),
            dark in any::<bool>(),
            r in any::<u8>(), g in any::<u8>(), b in any::<u8>(),
        ) {
            let value = format!("#{r:02x}{g:02x}{b:02x}");
            let old = if dark { OLD_DARK } else { OLD_LIGHT };
            prop_assume!(old_single_field_ok(old, field, Rgb { r, g, b }));
            let c = colors(|c| *field_mut(c, field) = Some(value.clone()));
            let t = if dark {
                ThemeTokens { colors_dark: Some(c), ..ThemeTokens::default() }
            } else {
                ThemeTokens { colors: c, ..ThemeTokens::default() }
            };
            prop_assert!(validate_tokens(&t).is_ok(), "{field}={value} dark={dark}");
        }

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
