//! THE PEM helper: PKCS#8 `PRIVATE KEY` armor to DER and back.
//!
//! Strict on input: at most 16 KiB; after trimming surrounding whitespace exactly one
//! `-----BEGIN PRIVATE KEY-----` ... `-----END PRIVATE KEY-----` block with LF or CRLF line
//! endings. Any other label (`EC PRIVATE KEY`, `RSA PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`,
//! `PUBLIC KEY`, ...), RFC 1421 headers (`Proc-Type:`), a second block, text before or after the
//! block, blank or whitespace-carrying body lines and anything that is not canonical standard
//! base64 are rejected with `JoseError::Malformed("pem")`. Body lines are concatenated and decoded
//! with [`crate::encoding::b64std_decode`] (the one base64 implementation).
//!
//! Errors never contain key material. Nothing else in the workspace parses PEM: Apple `.p8`
//! keys are validated and loaded through [`pkcs8_der_from_pem`] /
//! [`SigningKey::from_pkcs8_pem`].

use zeroize::Zeroizing;

use crate::JoseError;
use crate::encoding::{b64std, b64std_decode};
use crate::keys::{Alg, SigningKey};

/// Largest accepted PEM input in bytes.
pub const MAX_PEM_LEN: usize = 16 * 1024;
const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const END: &str = "-----END PRIVATE KEY-----";

fn malformed() -> JoseError {
    JoseError::Malformed("pem")
}

/// Decodes a PKCS#8 `PRIVATE KEY` PEM into DER. See the module docs for what is accepted.
pub fn pkcs8_der_from_pem(pem: &str) -> Result<Zeroizing<Vec<u8>>, JoseError> {
    if pem.len() > MAX_PEM_LEN {
        return Err(malformed());
    }
    let trimmed = pem.trim();
    let mut lines = trimmed
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l));
    if lines.next() != Some(BEGIN) {
        return Err(malformed());
    }
    let mut body = Zeroizing::new(String::with_capacity(trimmed.len()));
    let mut ended = false;
    for line in lines {
        if ended {
            // Anything after the END line (a second block, trailing text).
            return Err(malformed());
        }
        if line == END {
            ended = true;
            continue;
        }
        if line.is_empty()
            || line.starts_with("-----")
            || !line
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Err(malformed());
        }
        body.push_str(line);
    }
    if !ended || body.is_empty() {
        return Err(malformed());
    }
    let der = Zeroizing::new(b64std_decode(&body).map_err(|_| malformed())?);
    if der.is_empty() {
        return Err(malformed());
    }
    Ok(der)
}

/// PKCS#8 DER as a `PRIVATE KEY` PEM with 64-column lines and LF endings.
pub(crate) fn pkcs8_pem(pkcs8: &[u8]) -> Zeroizing<String> {
    let b64 = Zeroizing::new(b64std(pkcs8));
    let mut pem = Zeroizing::new(String::with_capacity(b64.len() + b64.len() / 64 + 64));
    pem.push_str(BEGIN);
    pem.push('\n');
    for chunk in b64.as_bytes().chunks(64) {
        // base64 output is ASCII.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str(END);
    pem.push('\n');
    pem
}

impl SigningKey {
    /// Loads a PKCS#8 `PRIVATE KEY` PEM (e.g. an Apple `.p8` key): [`pkcs8_der_from_pem`] then
    /// [`SigningKey::from_pkcs8`], which also rejects a key of the wrong family for `alg`.
    pub fn from_pkcs8_pem(kid: &str, alg: Alg, pem: &str) -> Result<Self, JoseError> {
        let der = pkcs8_der_from_pem(pem)?;
        Self::from_pkcs8(kid, alg, &der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::Jwks;
    use crate::jws::verify_jwt;
    use crate::keys::{generate_es256, generate_rs256};
    use serde_json::json;

    fn es256_pem() -> (crate::keys::GeneratedKey, String) {
        let g = generate_es256().unwrap();
        let pem = pkcs8_pem(&g.pkcs8).to_string();
        (g, pem)
    }

    fn assert_rejected(input: &str, what: &str) {
        assert_eq!(
            pkcs8_der_from_pem(input).map(|_| ()),
            Err(JoseError::Malformed("pem")),
            "{what}"
        );
    }

    #[test]
    fn pem_round_trip_signs_verifiable_jwt_lf_and_crlf() {
        let (g, pem) = es256_pem();
        assert!(pem.lines().all(|l| l.len() <= 64));
        let crlf = pem.replace('\n', "\r\n");
        let padded = format!("\n  {pem}\n\n");
        for input in [&pem, &crlf, &padded] {
            assert_eq!(pkcs8_der_from_pem(input).unwrap().as_slice(), &g.pkcs8[..]);
            let key = SigningKey::from_pkcs8_pem(&g.kid, Alg::ES256, input).unwrap();
            let token = key.sign_jwt(None, &json!({"sub": "team"})).unwrap();
            let jwks = Jwks {
                keys: vec![g.public_jwk.clone()],
            };
            let verified = verify_jwt(&token, &jwks, &[Alg::ES256]).unwrap();
            assert_eq!(verified.claims["sub"], "team");
        }
    }

    #[test]
    fn pem_rejects_other_labels() {
        let (_, pem) = es256_pem();
        for label in [
            "EC PRIVATE KEY",
            "RSA PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PUBLIC KEY",
            "CERTIFICATE",
            "private key",
        ] {
            let other = pem.replace("PRIVATE KEY", label);
            assert_rejected(&other, label);
        }
    }

    #[test]
    fn pem_rejects_headers_blocks_and_junk() {
        let (_, pem) = es256_pem();
        let body_start = BEGIN.len() + 1;
        let with_header = format!("{BEGIN}\nProc-Type: 4,ENCRYPTED\n\n{}", &pem[body_start..]);
        assert_rejected(&with_header, "headers");
        assert_rejected(&format!("{pem}{pem}"), "two blocks");
        assert_rejected(&format!("junk\n{pem}"), "leading junk");
        assert_rejected(&format!("{pem}trailing"), "trailing junk");
        assert_rejected(&format!("{pem}\n# comment"), "trailing comment");
        let no_end = pem.replace(END, "");
        assert_rejected(&no_end, "missing END");
        let blank_line = pem.replacen('\n', "\n\n", 2);
        assert_rejected(&blank_line, "blank line inside the body");
        assert_rejected(&format!("{BEGIN}\n{END}\n"), "empty body");
        assert_rejected(&format!("{BEGIN}{END}"), "single line");
        assert_rejected("", "empty input");
    }

    #[test]
    fn pem_rejects_invalid_base64() {
        let (_, pem) = es256_pem();
        let mut lines: Vec<String> = pem.lines().map(str::to_owned).collect();
        // URL alphabet.
        let mut url = lines.clone();
        url[1] = url[1].replacen(|c: char| c.is_ascii_alphanumeric(), "-", 1);
        assert_rejected(&url.join("\n"), "url alphabet -");
        url[1] = lines[1].replacen(|c: char| c.is_ascii_alphanumeric(), "_", 1);
        assert_rejected(&url.join("\n"), "url alphabet _");
        // Whitespace inside a line.
        let mut ws = lines.clone();
        ws[1].insert(10, ' ');
        assert_rejected(&ws.join("\n"), "space inside a line");
        ws[1] = lines[1].clone();
        ws[1].insert(10, '\t');
        assert_rejected(&ws.join("\n"), "tab inside a line");
        // Non-canonical: a dropped character breaks the length.
        lines[1].pop();
        assert_rejected(&lines.join("\n"), "truncated base64");
        // A body that decodes to nothing is still Malformed (only padding).
        assert_rejected(&format!("{BEGIN}\n====\n{END}"), "padding only");
    }

    #[test]
    fn pem_rejects_oversized_input() {
        let (_, pem) = es256_pem();
        let huge = format!("{pem}{}", " ".repeat(MAX_PEM_LEN));
        assert_rejected(&huge, "> 16 KiB");
    }

    #[test]
    fn pem_wrong_family_is_rejected_by_from_pkcs8() {
        let g = generate_rs256().unwrap();
        let pem = pkcs8_pem(&g.pkcs8);
        assert!(SigningKey::from_pkcs8_pem("k", Alg::RS256, &pem).is_ok());
        let err = SigningKey::from_pkcs8_pem("k", Alg::ES256, &pem).unwrap_err();
        assert!(matches!(err, JoseError::Crypto(_)));
        // Errors never carry key material.
        let b64_line = pem.lines().nth(1).unwrap();
        assert!(!err.to_string().contains(&b64_line[..16]));
    }
}
