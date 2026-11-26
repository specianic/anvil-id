//! Condition checks on a verified SAML Response (ORG-03).
//!
//! [`check`] decides on the values the web adapter extracted from the signature-verified
//! assertion node and its enclosing Response ([`SamlAssertionData`]). It covers the Response
//! checks (Destination, InResponseTo, Status, Issuer, IssueInstant) and the assertion checks
//! (Issuer, NameID, bearer SubjectConfirmation, Conditions, audiences, AuthnStatement). Each
//! check refuses with its own [`SamlReject`] reason code, which is what the audit event
//! records (never XML, NameIDs or attribute values).
//!
//! Profile requirements beyond the bare SAML core (Profiles §4.1.4): `Conditions` with a
//! `NotOnOrAfter`, a `SubjectConfirmationData/@NotOnOrAfter`, at least one
//! `AudienceRestriction`, and a NameID that is not `transient` (JIT needs a stable subject).
//!
//! Time comes only from the caller's `now`; skew is [`DEFAULT_SKEW`].

use anvil_jose::encoding::sha256;
use time::{Duration, OffsetDateTime};

use crate::model::str_enum;
use crate::model::{
    NameIdFormat, SamlAssertionData, SamlAttributeMapping, SamlIdentity, SecretHash,
};

/// Allowed clock skew between us and the IdP.
pub const DEFAULT_SKEW: Duration = Duration::seconds(90);

/// How old a Response `IssueInstant` may be.
pub const MAX_ISSUE_AGE: Duration = Duration::hours(1);

/// Longest a replay-guard entry for an assertion is kept.
pub const MAX_REPLAY_TTL: Duration = Duration::hours(1);

/// `StatusCode` of a successful Response.
pub const STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// The bearer `SubjectConfirmation` method.
pub const CM_BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

/// What the Response must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlExpected {
    /// Our entity ID: every `AudienceRestriction` must contain it.
    pub sp_entity_id: String,
    /// Our ACS URL: `Destination` and `Recipient`.
    pub acs_url: String,
    /// The ID of the pending `AuthnRequest`: both `InResponseTo`s.
    pub request_id: String,
    /// The connection's IdP entity ID: both `Issuer`s.
    pub idp_entity_id: String,
    /// Which attributes carry the profile values.
    pub attributes: SamlAttributeMapping,
    pub skew: Duration,
}

/// Why a Response was refused. One code per check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SamlReject {
    DestinationMismatch,
    InResponseToMismatch,
    StatusNotSuccess,
    ResponseIssuerMismatch,
    IssueInstantInvalid,
    MissingAssertionId,
    AssertionIssuerMismatch,
    EmptyNameId,
    TransientNameId,
    NoBearerConfirmation,
    RecipientMismatch,
    ConfirmationInResponseToMismatch,
    ConfirmationMissingNotOnOrAfter,
    ConfirmationExpired,
    MissingConditions,
    ConditionsMissingNotOnOrAfter,
    NotYetValid,
    ConditionsExpired,
    MissingAudienceRestriction,
    AudienceMismatch,
    MissingAuthnStatement,
}

str_enum!(SamlReject {
    DestinationMismatch => "destination_mismatch",
    InResponseToMismatch => "in_response_to_mismatch",
    StatusNotSuccess => "status_not_success",
    ResponseIssuerMismatch => "response_issuer_mismatch",
    IssueInstantInvalid => "issue_instant_invalid",
    MissingAssertionId => "missing_assertion_id",
    AssertionIssuerMismatch => "assertion_issuer_mismatch",
    EmptyNameId => "empty_name_id",
    TransientNameId => "transient_name_id",
    NoBearerConfirmation => "no_bearer_confirmation",
    RecipientMismatch => "recipient_mismatch",
    ConfirmationInResponseToMismatch => "confirmation_in_response_to_mismatch",
    ConfirmationMissingNotOnOrAfter => "confirmation_missing_not_on_or_after",
    ConfirmationExpired => "confirmation_expired",
    MissingConditions => "missing_conditions",
    ConditionsMissingNotOnOrAfter => "conditions_missing_not_on_or_after",
    NotYetValid => "not_yet_valid",
    ConditionsExpired => "conditions_expired",
    MissingAudienceRestriction => "missing_audience_restriction",
    AudienceMismatch => "audience_mismatch",
    MissingAuthnStatement => "missing_authn_statement",
});

impl std::fmt::Display for SamlReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for SamlReject {}

fn require(ok: bool, reject: SamlReject) -> Result<(), SamlReject> {
    if ok { Ok(()) } else { Err(reject) }
}

/// Validates the extracted values of a verified Response against `expected` at `now` and
/// returns the identity it asserts.
///
/// Time windows (skew `s`): `IssueInstant` in `[now - 1 h, now + s]`;
/// `SubjectConfirmationData/@NotOnOrAfter` and `Conditions/@NotOnOrAfter` must be after
/// `now - s`; `Conditions/@NotBefore`, when present, must not be after `now + s`.
pub fn check(
    data: &SamlAssertionData,
    expected: &SamlExpected,
    now: OffsetDateTime,
) -> Result<SamlIdentity, SamlReject> {
    use SamlReject as R;
    let skew = expected.skew;

    // Response
    require(
        data.response_destination.as_deref() == Some(expected.acs_url.as_str()),
        R::DestinationMismatch,
    )?;
    require(
        data.response_in_response_to.as_deref() == Some(expected.request_id.as_str()),
        R::InResponseToMismatch,
    )?;
    require(data.status_code == STATUS_SUCCESS, R::StatusNotSuccess)?;
    require(
        data.response_issuer
            .as_deref()
            .is_none_or(|i| i == expected.idp_entity_id),
        R::ResponseIssuerMismatch,
    )?;
    require(
        data.issue_instant
            .is_some_and(|t| t <= now + skew && t >= now - MAX_ISSUE_AGE),
        R::IssueInstantInvalid,
    )?;

    // Assertion
    require(!data.assertion_id.is_empty(), R::MissingAssertionId)?;
    require(
        data.issuer == expected.idp_entity_id,
        R::AssertionIssuerMismatch,
    )?;
    require(!data.name_id.trim().is_empty(), R::EmptyNameId)?;
    require(
        data.name_id_format.as_deref() != Some(NameIdFormat::Transient.urn()),
        R::TransientNameId,
    )?;

    let sc = data
        .subject_confirmation
        .as_ref()
        .filter(|sc| sc.method == CM_BEARER)
        .ok_or(R::NoBearerConfirmation)?;
    require(
        sc.recipient.as_deref() == Some(expected.acs_url.as_str()),
        R::RecipientMismatch,
    )?;
    require(
        sc.in_response_to.as_deref() == Some(expected.request_id.as_str()),
        R::ConfirmationInResponseToMismatch,
    )?;
    let sc_expiry = sc
        .not_on_or_after
        .ok_or(R::ConfirmationMissingNotOnOrAfter)?;
    require(sc_expiry > now - skew, R::ConfirmationExpired)?;

    require(data.has_conditions, R::MissingConditions)?;
    let expiry = data
        .not_on_or_after
        .ok_or(R::ConditionsMissingNotOnOrAfter)?;
    require(
        data.not_before.is_none_or(|nb| nb <= now + skew),
        R::NotYetValid,
    )?;
    require(expiry > now - skew, R::ConditionsExpired)?;
    require(!data.audiences.is_empty(), R::MissingAudienceRestriction)?;
    require(
        data.audiences
            .iter()
            .all(|r| r.contains(&expected.sp_entity_id)),
        R::AudienceMismatch,
    )?;
    require(data.has_authn_statement, R::MissingAuthnStatement)?;

    let attr = |name: &Option<String>| {
        name.as_ref()
            .and_then(|n| data.attributes.get(n))
            .and_then(|values| values.first())
            .filter(|v| !v.is_empty())
            .cloned()
    };
    let m = &expected.attributes;
    Ok(SamlIdentity {
        subject: data.name_id.clone(),
        email: attr(&m.email),
        given_name: attr(&m.given_name),
        family_name: attr(&m.family_name),
        name: attr(&m.name),
    })
}

/// The replay-guard key of an assertion: `SHA-256(idp_entity_id ‖ 0x00 ‖ assertion_id)`. The
/// separator keeps `("a", "bc")` and `("ab", "c")` apart.
pub fn replay_key(idp_entity_id: &str, assertion_id: &str) -> SecretHash {
    let mut input = Vec::with_capacity(idp_entity_id.len() + 1 + assertion_id.len());
    input.extend_from_slice(idp_entity_id.as_bytes());
    input.push(0);
    input.extend_from_slice(assertion_id.as_bytes());
    SecretHash(sha256(&input))
}

/// How long the replay-guard entry lives: until the assertion's `NotOnOrAfter`, at most one
/// hour, and at least the skew window (an assertion still acceptable within the skew must stay
/// guarded).
pub fn replay_expiry(not_on_or_after: OffsetDateTime, now: OffsetDateTime) -> OffsetDateTime {
    not_on_or_after
        .min(now + MAX_REPLAY_TTL)
        .max(now + DEFAULT_SKEW)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use time::macros::datetime;

    use super::*;
    use crate::model::SamlSubjectConfirmation;

    const SP: &str = "https://id.example.test/t/acme/saml/okta";
    const ACS: &str = "https://id.example.test/t/acme/ui/login/saml/okta/acs";
    const REQ: &str = "_00112233445566778899aabbccddeeff";
    const IDP: &str = "https://idp.example.test/entity";
    const NOW: OffsetDateTime = datetime!(2026-11-26 09:30:00 UTC);

    fn expected() -> SamlExpected {
        SamlExpected {
            sp_entity_id: SP.into(),
            acs_url: ACS.into(),
            request_id: REQ.into(),
            idp_entity_id: IDP.into(),
            attributes: SamlAttributeMapping {
                email: Some("mail".into()),
                given_name: Some("givenName".into()),
                family_name: Some("sn".into()),
                name: None,
            },
            skew: DEFAULT_SKEW,
        }
    }

    fn valid() -> SamlAssertionData {
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "mail".to_owned(),
            vec![
                "alice@example.com".to_owned(),
                "second@example.com".to_owned(),
            ],
        );
        attributes.insert("givenName".to_owned(), vec!["Alice".to_owned()]);
        attributes.insert("displayName".to_owned(), vec!["Alice A.".to_owned()]);
        SamlAssertionData {
            response_destination: Some(ACS.into()),
            response_in_response_to: Some(REQ.into()),
            status_code: STATUS_SUCCESS.into(),
            response_issuer: Some(IDP.into()),
            issue_instant: Some(NOW - Duration::seconds(5)),
            assertion_id: "_assertion1".into(),
            issuer: IDP.into(),
            name_id: "00u1abcd".into(),
            name_id_format: Some(NameIdFormat::Persistent.urn().into()),
            subject_confirmation: Some(SamlSubjectConfirmation {
                method: CM_BEARER.into(),
                recipient: Some(ACS.into()),
                not_on_or_after: Some(NOW + Duration::minutes(5)),
                in_response_to: Some(REQ.into()),
            }),
            has_conditions: true,
            not_before: Some(NOW - Duration::seconds(10)),
            not_on_or_after: Some(NOW + Duration::minutes(5)),
            audiences: vec![vec![SP.into()]],
            has_authn_statement: true,
            session_index: Some("_s1".into()),
            attributes,
        }
    }

    fn rejected(mutate: impl FnOnce(&mut SamlAssertionData)) -> SamlReject {
        let mut d = valid();
        mutate(&mut d);
        match check(&d, &expected(), NOW) {
            Err(r) => r,
            Ok(id) => panic!("expected a rejection, got {id:?}"),
        }
    }

    fn sc(d: &mut SamlAssertionData) -> &mut SamlSubjectConfirmation {
        d.subject_confirmation.as_mut().unwrap()
    }

    #[test]
    fn valid_assertion_yields_identity() {
        let id = check(&valid(), &expected(), NOW).unwrap();
        assert_eq!(
            id,
            SamlIdentity {
                subject: "00u1abcd".into(),
                email: Some("alice@example.com".into()),
                given_name: Some("Alice".into()),
                family_name: None,
                name: None,
            }
        );
    }

    #[test]
    fn optional_parts_may_be_absent() {
        let mut d = valid();
        d.response_issuer = None;
        d.not_before = None;
        d.name_id_format = None;
        assert!(check(&d, &expected(), NOW).is_ok());
    }

    #[test]
    fn empty_attribute_values_are_not_mapped() {
        let mut d = valid();
        d.attributes.insert("mail".into(), vec![String::new()]);
        d.attributes.insert("givenName".into(), vec![]);
        let id = check(&d, &expected(), NOW).unwrap();
        assert_eq!(id.email, None);
        assert_eq!(id.given_name, None);
    }

    #[test]
    fn rejects_destination_mismatch() {
        assert_eq!(
            rejected(|d| d.response_destination = Some(format!("{ACS}/x"))),
            SamlReject::DestinationMismatch
        );
    }

    #[test]
    fn rejects_destination_missing() {
        assert_eq!(
            rejected(|d| d.response_destination = None),
            SamlReject::DestinationMismatch
        );
    }

    #[test]
    fn rejects_response_in_response_to_mismatch() {
        assert_eq!(
            rejected(|d| d.response_in_response_to = Some("_other".into())),
            SamlReject::InResponseToMismatch
        );
        assert_eq!(
            rejected(|d| d.response_in_response_to = None),
            SamlReject::InResponseToMismatch
        );
    }

    #[test]
    fn rejects_non_success_status() {
        assert_eq!(
            rejected(|d| d.status_code = "urn:oasis:names:tc:SAML:2.0:status:Requester".into()),
            SamlReject::StatusNotSuccess
        );
    }

    #[test]
    fn rejects_response_issuer_mismatch() {
        assert_eq!(
            rejected(|d| d.response_issuer = Some("https://evil.example.test".into())),
            SamlReject::ResponseIssuerMismatch
        );
    }

    #[test]
    fn rejects_issue_instant_in_the_future() {
        assert_eq!(
            rejected(|d| d.issue_instant = Some(NOW + Duration::seconds(91))),
            SamlReject::IssueInstantInvalid
        );
        let mut d = valid();
        d.issue_instant = Some(NOW + Duration::seconds(90));
        assert!(check(&d, &expected(), NOW).is_ok(), "within skew");
    }

    #[test]
    fn rejects_issue_instant_too_old() {
        assert_eq!(
            rejected(|d| d.issue_instant = Some(NOW - Duration::hours(1) - Duration::seconds(1))),
            SamlReject::IssueInstantInvalid
        );
        assert_eq!(
            rejected(|d| d.issue_instant = None),
            SamlReject::IssueInstantInvalid
        );
    }

    #[test]
    fn rejects_missing_assertion_id() {
        assert_eq!(
            rejected(|d| d.assertion_id = String::new()),
            SamlReject::MissingAssertionId
        );
    }

    #[test]
    fn rejects_assertion_issuer_mismatch() {
        assert_eq!(
            rejected(|d| d.issuer = "https://evil.example.test".into()),
            SamlReject::AssertionIssuerMismatch
        );
    }

    #[test]
    fn rejects_empty_name_id() {
        assert_eq!(
            rejected(|d| d.name_id = String::new()),
            SamlReject::EmptyNameId
        );
        assert_eq!(
            rejected(|d| d.name_id = " \n".into()),
            SamlReject::EmptyNameId
        );
    }

    #[test]
    fn rejects_transient_name_id() {
        assert_eq!(
            rejected(|d| {
                d.name_id_format =
                    Some("urn:oasis:names:tc:SAML:2.0:nameid-format:transient".into())
            }),
            SamlReject::TransientNameId
        );
    }

    #[test]
    fn rejects_missing_subject_confirmation() {
        assert_eq!(
            rejected(|d| d.subject_confirmation = None),
            SamlReject::NoBearerConfirmation
        );
    }

    #[test]
    fn rejects_non_bearer_subject_confirmation() {
        assert_eq!(
            rejected(|d| sc(d).method = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key".into()),
            SamlReject::NoBearerConfirmation
        );
    }

    #[test]
    fn rejects_recipient_mismatch() {
        assert_eq!(
            rejected(|d| sc(d).recipient = Some("https://evil.example.test/acs".into())),
            SamlReject::RecipientMismatch
        );
        assert_eq!(
            rejected(|d| sc(d).recipient = None),
            SamlReject::RecipientMismatch
        );
    }

    #[test]
    fn rejects_confirmation_in_response_to_mismatch() {
        assert_eq!(
            rejected(|d| sc(d).in_response_to = Some("_other".into())),
            SamlReject::ConfirmationInResponseToMismatch
        );
        assert_eq!(
            rejected(|d| sc(d).in_response_to = None),
            SamlReject::ConfirmationInResponseToMismatch
        );
    }

    #[test]
    fn rejects_confirmation_without_not_on_or_after() {
        assert_eq!(
            rejected(|d| sc(d).not_on_or_after = None),
            SamlReject::ConfirmationMissingNotOnOrAfter
        );
    }

    #[test]
    fn rejects_expired_confirmation() {
        assert_eq!(
            rejected(|d| sc(d).not_on_or_after = Some(NOW - Duration::seconds(90))),
            SamlReject::ConfirmationExpired
        );
        let mut d = valid();
        sc(&mut d).not_on_or_after = Some(NOW - Duration::seconds(89));
        assert!(check(&d, &expected(), NOW).is_ok(), "within skew");
    }

    #[test]
    fn rejects_missing_conditions() {
        assert_eq!(
            rejected(|d| {
                d.has_conditions = false;
                d.not_before = None;
                d.not_on_or_after = None;
                d.audiences.clear();
            }),
            SamlReject::MissingConditions
        );
    }

    #[test]
    fn rejects_conditions_without_not_on_or_after() {
        assert_eq!(
            rejected(|d| d.not_on_or_after = None),
            SamlReject::ConditionsMissingNotOnOrAfter
        );
    }

    #[test]
    fn rejects_not_yet_valid() {
        assert_eq!(
            rejected(|d| d.not_before = Some(NOW + Duration::seconds(91))),
            SamlReject::NotYetValid
        );
        let mut d = valid();
        d.not_before = Some(NOW + Duration::seconds(90));
        assert!(check(&d, &expected(), NOW).is_ok(), "within skew");
    }

    #[test]
    fn rejects_expired_conditions() {
        assert_eq!(
            rejected(|d| d.not_on_or_after = Some(NOW - Duration::seconds(90))),
            SamlReject::ConditionsExpired
        );
        let mut d = valid();
        d.not_on_or_after = Some(NOW - Duration::seconds(89));
        assert!(check(&d, &expected(), NOW).is_ok(), "within skew");
    }

    #[test]
    fn rejects_one_audience_restriction_without_the_sp() {
        assert_eq!(
            rejected(|d| {
                d.audiences = vec![vec![SP.into()], vec!["https://other.example.test".into()]]
            }),
            SamlReject::AudienceMismatch
        );
        let mut d = valid();
        d.audiences = vec![
            vec!["https://other.example.test".into(), SP.into()],
            vec![SP.into()],
        ];
        assert!(
            check(&d, &expected(), NOW).is_ok(),
            "every restriction names us"
        );
    }

    #[test]
    fn rejects_empty_audience_restriction() {
        assert_eq!(
            rejected(|d| d.audiences = vec![vec![]]),
            SamlReject::AudienceMismatch
        );
    }

    #[test]
    fn rejects_no_audience_restriction() {
        assert_eq!(
            rejected(|d| d.audiences.clear()),
            SamlReject::MissingAudienceRestriction
        );
    }

    #[test]
    fn rejects_missing_authn_statement() {
        assert_eq!(
            rejected(|d| d.has_authn_statement = false),
            SamlReject::MissingAuthnStatement
        );
    }

    #[test]
    fn reason_codes_are_distinct_and_round_trip() {
        let mut seen = std::collections::BTreeSet::new();
        for r in SamlReject::ALL {
            assert!(seen.insert(r.as_str()), "{r:?}");
            assert_eq!(SamlReject::parse(r.as_str()), Some(*r));
            assert_eq!(r.to_string(), r.as_str());
        }
        assert_eq!(SamlReject::ALL.len(), 21);
    }

    #[test]
    fn replay_key_vector() {
        let k = replay_key("https://idp.example.test/entity", "_abc");
        let expected = sha256(b"https://idp.example.test/entity\x00_abc");
        assert_eq!(k, SecretHash(expected));
        // Stable vector: SHA-256("a\0b").
        assert_eq!(
            anvil_jose::encoding::b64url(&replay_key("a", "b").0),
            anvil_jose::encoding::b64url(&sha256(b"a\x00b"))
        );
        assert_ne!(replay_key("a", "bc"), replay_key("ab", "c"));
    }

    #[test]
    fn replay_key_known_answer() {
        // SHA-256 of the three bytes 61 00 62 (computed with Python hashlib).
        let hex: String = replay_key("a", "b")
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hex,
            "59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138"
        );
    }

    #[test]
    fn replay_expiry_bounds() {
        assert_eq!(
            replay_expiry(NOW + Duration::minutes(5), NOW),
            NOW + Duration::minutes(5)
        );
        assert_eq!(
            replay_expiry(NOW + Duration::hours(5), NOW),
            NOW + Duration::hours(1)
        );
        assert_eq!(replay_expiry(NOW, NOW), NOW + DEFAULT_SKEW);
        assert_eq!(
            replay_expiry(NOW - Duration::minutes(1), NOW),
            NOW + DEFAULT_SKEW
        );
    }
}
