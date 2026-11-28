//! SAML 2.0 SP sign-in (ORG-03, experimental behind the operator flag `saml_experimental`):
//! SP-initiated only, HTTP-Redirect `AuthnRequest` (unsigned), HTTP-POST `Response` with a signed
//! `Assertion`. Mirrors [`UpstreamService`] and ends in its shared completion
//! (`UpstreamService::complete_identity`).
//!
//! # Start
//!
//! [`SamlService::start`] is a form POST bound to a login flow in its identify step (flow cookie
//! and CSRF token, like the upstream start). It builds the `AuthnRequest` (16 random bytes for the
//! ID, `ForceAuthn` when the authorization request asked for `prompt=login`), a RelayState
//! `{flow_id}.{nonce}` (16 random bytes, 59 bytes long) and a binding-cookie value, stores a
//! [`SamlPending`] with hashes only by compare-and-swap, and answers the IdP's SSO URL with
//! `SAMLRequest` and `RelayState` appended to its own query.
//!
//! # ACS (Pattern 8)
//!
//! [`SamlService::acs`] receives the IdP's cross-site POST, which carries no cookie. It never
//! trusts cookies; it finds the flow through RelayState and refuses, without parsing any XML:
//!
//! - a missing, malformed or unknown RelayState, or one whose hash is not the pending request's
//!   (`relay_state`): an unsolicited (IdP-initiated) response is refused (decision Q4);
//! - a flow without a pending request (`no_pending_request`, also a second POST).
//!
//! The pending request is then taken out of the flow by compare-and-swap (single use: whatever
//! follows, it is consumed), and these refuse:
//!
//! - older than ten minutes (`expired`);
//! - posted to the ACS of another connection than the request's (`connection_mismatch`);
//! - not decodable (`encoding`) or over 256 KiB (`size`);
//! - [`SamlXml::verify_response`] against the connection's certificates (its reason code);
//! - [`check`] with this request's ID, our entity ID and ACS URL (its reason code);
//! - an assertion ID already recorded in the replay guard (`replay`): kind
//!   [`ReplayKind::SamlAssertionId`], key `sha256(idp entity id || 0x00 || id)` ([`replay_key`]),
//!   stored in the database, so a second app instance refuses it too.
//!
//! Only the extracted identity (never the XML) is sealed into the flow, again by
//! compare-and-swap, and the browser is sent to the same-site continue step.
//!
//! # Continue
//!
//! [`SamlService::continue_login`] requires the binding cookie set at the start (SameSite=Lax, so
//! present on this same-site GET): a response posted in another browser signs nobody in, and a
//! missing or foreign cookie leaves the flow intact. It takes the identity out of the flow
//! (single use) and hands it to the shared completion: link decision, JIT user + link + org
//! membership, org email trust (SAML: the verified domain alone, `upstream_verified = None`),
//! `require_verified_email`, MFA policy and the session.
//!
//! # Audit
//!
//! Every refusal is audited `saml_login_failed` with a reason code only (never XML, NameID or
//! attribute values) and answered with one generic error; a response whose binding is proved
//! audits `saml_login_succeeded` before the completion (which audits its own failures as
//! `upstream_login_failed`).
//!
//! With the operator flag off every method returns [`CoreError::FeatureDisabled`].

use std::sync::Arc;

use anvil_jose::Kek;
use anvil_jose::encoding::{b64std_decode, b64url, b64url_decode, ct_eq, random_bytes};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::account::{AccountService, SettingsBinding};
use super::audit::AuditService;
use super::flow::{BindingError, FlowContext, FlowService, check_binding, holds_recovery_codes};
use super::upstream::{StartResult, UpstreamOutcome, UpstreamRedirect, UpstreamService};
use crate::error::CoreError;
use crate::flow::engine::{FlowState, LoginState};
use crate::flow::login::{SamlPending, take_saml, with_saml};
use crate::flow::upstream::{SealedIdentity, upstream_aad, value_hash};
use crate::model::{
    ActorKind, AuditAction, AuditActor, AuditDetails, AuditOutcome, BrowserSession, Connection,
    ConnectionConfig, Flow, FlowId, FlowKind, ReplayKind, SamlConfig, SamlIdentity, TenantId,
};
use crate::ports::{JtiOutcome, SamlXml, SamlXmlReject, Storage, UpstreamClient};
use crate::saml::request::{
    AuthnRequestParams, authn_request, relay_state, request_id, sp_metadata, split_relay_state,
};
use crate::saml::validate::{DEFAULT_SKEW, SamlExpected, check, replay_expiry, replay_key};
use crate::upstream::claims::UpstreamIdentity;

/// The feature name of [`CoreError::FeatureDisabled`] when the operator flag is off.
pub const FEATURE: &str = "saml";

/// KEK purpose of the verified identity sealed into the flow between the ACS and the continue
/// step (AAD: [`upstream_aad`] of the tenant and flow).
pub const SAML_IDENTITY_PURPOSE: &str = "anvilid/saml-identity/v1";

/// Largest decoded `samlp:Response` accepted (the XML adapter's own cap is the same).
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Our SP entity ID for connection `slug`: `{issuer}/saml/{slug}` (also the metadata location's
/// prefix).
pub fn sp_entity_id(issuer: &str, slug: &str) -> String {
    format!("{issuer}/saml/{slug}")
}

/// Our assertion consumer service URL for connection `slug`.
pub fn acs_url(issuer: &str, slug: &str) -> String {
    format!("{issuer}/ui/login/saml/{slug}/acs")
}

/// Where the SP metadata of connection `slug` is served.
pub fn metadata_url(issuer: &str, slug: &str) -> String {
    format!("{issuer}/saml/{slug}/metadata")
}

/// The continue step's URL for a RelayState.
pub fn continue_url(issuer: &str, slug: &str, relay: &str) -> String {
    let encoded: String = url::form_urlencoded::byte_serialize(relay.as_bytes()).collect();
    format!("{issuer}/ui/login/saml/{slug}/continue?state={encoded}")
}

/// Audit reason of an XML-level refusal.
pub fn xml_reason(r: SamlXmlReject) -> &'static str {
    match r {
        SamlXmlReject::Size => "size",
        SamlXmlReject::Parse => "parse",
        SamlXmlReject::Dtd => "dtd",
        SamlXmlReject::Structure => "structure",
        SamlXmlReject::DuplicateId => "duplicate_id",
        SamlXmlReject::Encrypted => "encrypted",
        SamlXmlReject::SignatureProfile => "signature_profile",
        SamlXmlReject::Algorithm => "algorithm",
        SamlXmlReject::Signature => "signature",
        SamlXmlReject::UntrustedKey => "untrusted_key",
        SamlXmlReject::Unavailable => "unavailable",
    }
}

/// Decodes the posted `SAMLResponse`: standard base64 (line breaks some IdPs insert are
/// dropped first), at most [`MAX_RESPONSE_BYTES`] decoded. `Err` is the audit reason.
pub fn decode_response(value: &str) -> Result<Vec<u8>, &'static str> {
    // 4 base64 characters per 3 bytes, plus padding: anything longer cannot fit the cap.
    const MAX_ENCODED: usize = MAX_RESPONSE_BYTES.div_ceil(3) * 4;
    if value.len() > MAX_ENCODED + MAX_ENCODED / 16 {
        return Err("size");
    }
    let compact: String = value
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n' | ' ' | '\t'))
        .collect();
    if compact.len() > MAX_ENCODED {
        return Err("size");
    }
    if compact.is_empty() {
        return Err("encoding");
    }
    let xml = b64std_decode(&compact).map_err(|_| "encoding")?;
    if xml.len() > MAX_RESPONSE_BYTES {
        return Err("size");
    }
    Ok(xml)
}

/// The IdP SSO URL with `SAMLRequest` and `RelayState` appended to its own query.
pub fn redirect_url(sso_url: &str, saml_request: &str, relay: &str) -> Result<String, CoreError> {
    let mut url = url::Url::parse(sso_url)
        .map_err(|_| CoreError::Internal("SAML connection with an unusable SSO URL".into()))?;
    url.query_pairs_mut()
        .append_pair("SAMLRequest", saml_request)
        .append_pair("RelayState", relay);
    Ok(url.into())
}

/// The identity handed to the shared completion: subject = NameID, profile values from the
/// attribute mapping. `email_verified` is the connection's trust setting; for an org connection
/// the completion replaces it with the org's verified-domain rule.
pub fn upstream_identity(identity: SamlIdentity, conn: &Connection) -> UpstreamIdentity {
    UpstreamIdentity {
        subject: identity.subject,
        email_verified: conn.trust_email_verified && identity.email.is_some(),
        email: identity.email,
        given_name: identity.given_name,
        family_name: identity.family_name,
        name: identity.name,
        metadata: serde_json::Map::new(),
    }
}

fn seal(kek: &Kek, tenant: TenantId, flow: FlowId, value: &[u8]) -> Result<String, CoreError> {
    kek.seal(SAML_IDENTITY_PURPOSE, &upstream_aad(tenant, flow), value)
        .map(|s| b64url(&s))
        .map_err(|_| CoreError::Internal("sealing the SAML identity failed".into()))
}

fn open(kek: &Kek, tenant: TenantId, flow: FlowId, sealed: &str) -> Option<UpstreamIdentity> {
    let raw = b64url_decode(sealed).ok()?;
    let plain = kek
        .open(SAML_IDENTITY_PURPOSE, &upstream_aad(tenant, flow), &raw)
        .ok()?;
    serde_json::from_slice::<SealedIdentity>(&plain)
        .ok()
        .map(Into::into)
}

fn login_state(flow: &Flow) -> Result<LoginState, CoreError> {
    match serde_json::from_str(&flow.state) {
        Ok(FlowState::Login(s)) => Ok(s),
        Ok(_) => Err(CoreError::Internal(
            "corrupt flow state: not a login state".into(),
        )),
        Err(e) => Err(CoreError::Internal(format!("corrupt flow state: {e}"))),
    }
}

fn state_json(state: &LoginState) -> Result<String, CoreError> {
    serde_json::to_string(&FlowState::Login(state.clone()))
        .map_err(|e| CoreError::Internal(format!("flow state encoding failed: {e}")))
}

/// The SAML configuration of an enabled SAML connection.
fn saml_config(conn: &Connection) -> Option<&SamlConfig> {
    match &conn.config {
        ConnectionConfig::Saml(c) if conn.enabled => Some(c),
        _ => None,
    }
}

/// Result of [`SamlService::acs`].
#[derive(Debug, PartialEq, Eq)]
pub enum AcsOutcome {
    /// The identity is sealed in the flow: send the browser here (the continue step).
    Continue { location: String },
    /// Refused (audited with its reason): show the generic SAML error.
    Refused,
}

/// What the continue step answers.
#[derive(Debug)]
pub enum ContinueOutcome {
    /// Refused (audited with its reason): show the generic SAML error.
    Refused,
    /// The shared completion's answer (signed in, second factor, link confirmation, ...).
    Completed(Box<UpstreamOutcome>),
}

/// Result of [`SamlService::continue_login`].
#[derive(Debug)]
pub struct ContinueResult {
    pub outcome: ContinueOutcome,
    /// The RelayState and the binding cookie matched the flow: only then may the caller clear
    /// the binding cookie (a forged continue must not cancel a pending sign-in).
    pub binding_proved: bool,
}

/// SAML SP sign-in over the ports (module docs).
pub struct SamlService<'a> {
    /// Sessions, MFA policy and the login flows.
    pub flows: &'a FlowService,
    /// Required by the shared completion's service (never used for SAML: no account linking).
    pub accounts: &'a AccountService,
    /// Required by the shared completion's service (SAML makes no outbound call).
    pub client: &'a dyn UpstreamClient,
    /// XML parsing and signature verification (web adapter).
    pub saml_xml: &'a dyn SamlXml,
    /// The operator flag `saml_experimental`.
    pub enabled: bool,
}

impl SamlService<'_> {
    fn storage(&self) -> &dyn Storage {
        self.flows.storage.as_ref()
    }

    fn now(&self) -> OffsetDateTime {
        self.flows.clock.now()
    }

    fn require_enabled(&self) -> Result<(), CoreError> {
        if self.enabled {
            Ok(())
        } else {
            Err(CoreError::FeatureDisabled(FEATURE))
        }
    }

    fn upstream(&self) -> UpstreamService<'_> {
        UpstreamService {
            flows: self.flows,
            accounts: self.accounts,
            client: self.client,
        }
    }

    /// The enabled SAML connection `slug` and its configuration.
    async fn connection(
        &self,
        tenant: TenantId,
        slug: &str,
    ) -> Result<Option<(Connection, SamlConfig)>, CoreError> {
        let conn = self
            .storage()
            .connections()
            .get_by_slug(tenant, slug)
            .await?;
        Ok(conn.and_then(|c| saml_config(&c).cloned().map(|cfg| (c, cfg))))
    }

    /// Records `saml_login_failed` with a reason code only.
    async fn refuse(
        &self,
        cx: &FlowContext<'_>,
        conn: Option<&Connection>,
        reason: &'static str,
    ) -> Result<(), CoreError> {
        let details = match conn {
            Some(c) => AuditDetails::connection(&c.slug, c.kind().as_str()),
            None => AuditDetails::empty(),
        };
        AuditService {
            storage: Arc::clone(&self.flows.storage),
            clock: Arc::clone(&self.flows.clock),
        }
        .record(
            cx.tenant.id,
            AuditActor::anonymous(ActorKind::User),
            AuditAction::SamlLoginFailed,
            conn.map(|c| c.id.to_string()),
            AuditOutcome::Failure,
            cx.ctx,
            details.with(AuditDetails::reason(reason)),
        )
        .await
    }

    /// Starts a SAML sign-in with connection `slug` from the login flow `binding` names.
    /// Errors: `FeatureDisabled` (flag off), `Forbidden` (binding), `NotFound` (no enabled SAML
    /// connection `slug`), `InvalidRequest` (past the identify step, or changed concurrently).
    pub async fn start(
        &self,
        cx: &FlowContext<'_>,
        binding: &SettingsBinding<'_>,
        slug: &str,
    ) -> Result<StartResult, CoreError> {
        self.require_enabled()?;
        let tenant = cx.tenant.id;
        let now = self.now();
        let expired = || async {
            let started = self
                .flows
                .restart_login_with(cx, None, "flow.expired")
                .await?;
            Ok::<_, CoreError>(StartResult::Done(Box::new(UpstreamOutcome::Continue {
                started,
                request: None,
            })))
        };
        let Some(flow) = self
            .storage()
            .flows()
            .get(tenant, binding.flow_id, now)
            .await?
        else {
            return expired().await;
        };
        // A finished sign-in holding its recovery codes takes no sign-in step.
        if flow.kind != FlowKind::Login || holds_recovery_codes(&flow) {
            return Err(CoreError::Forbidden);
        }
        match check_binding(&flow, binding.cookie_token, binding.csrf_token, now) {
            Ok(()) => {}
            Err(BindingError::Expired) => return expired().await,
            Err(BindingError::Forbidden) => return Err(CoreError::Forbidden),
        }
        let state = login_state(&flow)?;
        let (conn, cfg) = self
            .connection(tenant, slug)
            .await?
            .ok_or(CoreError::NotFound)?;

        let id = request_id(random_bytes::<16>());
        let relay = relay_state(flow.id, random_bytes::<16>());
        let binding_value = b64url(&random_bytes::<32>());
        let force_authn = match flow.auth_request_id {
            Some(request) => self
                .storage()
                .grants()
                .get_authorization_request(tenant, request, now)
                .await?
                .is_some_and(|r| r.params.prompt.iter().any(|p| p == "login")),
            None => false,
        };
        let pending = SamlPending {
            connection_id: conn.id,
            request_id: id.clone(),
            relay_state_hash: value_hash(&relay),
            binding_hash: value_hash(&binding_value),
            created_at: now.unix_timestamp(),
            identity_sealed: None,
        };
        let Some(next) = with_saml(state, pending) else {
            return Err(CoreError::InvalidRequest(
                "SAML sign-in is not available in this step".into(),
            ));
        };
        let xml = authn_request(&AuthnRequestParams {
            sp_entity_id: &sp_entity_id(cx.issuer, &conn.slug),
            acs_url: &acs_url(cx.issuer, &conn.slug),
            destination: &cfg.sso_url,
            request_id: &id,
            issue_instant: now,
            name_id_format: cfg.name_id_format,
            force_authn,
        });
        let encoded = self
            .saml_xml
            .encode_redirect(&xml)
            .map_err(|_| CoreError::Internal("encoding the SAML AuthnRequest failed".into()))?;
        let url = redirect_url(&cfg.sso_url, &encoded, &relay)?;
        if !self
            .storage()
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &state_json(&next)?, now)
            .await?
        {
            return Err(CoreError::InvalidRequest(
                "the sign-in flow changed concurrently".into(),
            ));
        }
        Ok(StartResult::Redirect(UpstreamRedirect {
            url,
            binding_cookie: SecretString::from(binding_value),
        }))
    }

    /// The assertion consumer service (module docs): `saml_response` is the posted
    /// `SAMLResponse` (base64), `relay` the posted `RelayState`.
    pub async fn acs(
        &self,
        cx: &FlowContext<'_>,
        slug: &str,
        saml_response: Option<&str>,
        relay: Option<&str>,
    ) -> Result<AcsOutcome, CoreError> {
        self.require_enabled()?;
        let tenant = cx.tenant.id;
        let now = self.now();
        let posted_to = self
            .storage()
            .connections()
            .get_by_slug(tenant, slug)
            .await?;
        let c = posted_to.as_ref();
        macro_rules! refuse {
            ($conn:expr, $reason:expr) => {{
                self.refuse(cx, $conn, $reason).await?;
                return Ok(AcsOutcome::Refused);
            }};
        }
        // RelayState is the only way to the flow: none (IdP-initiated) or a foreign one is
        // refused before anything else.
        let Some((relay, flow_id)) = relay.and_then(|r| split_relay_state(r).map(|(f, _)| (r, f)))
        else {
            refuse!(c, "relay_state")
        };
        let Some(flow) = self.storage().flows().get(tenant, flow_id, now).await? else {
            refuse!(c, "relay_state")
        };
        if flow.kind != FlowKind::Login || holds_recovery_codes(&flow) {
            refuse!(c, "relay_state")
        }
        let mut state = login_state(&flow)?;
        let Some(pending) = take_saml(&mut state).filter(|p| p.identity_sealed.is_none()) else {
            refuse!(c, "no_pending_request")
        };
        if !ct_eq(
            value_hash(relay).as_bytes(),
            pending.relay_state_hash.as_bytes(),
        ) {
            refuse!(c, "relay_state")
        }
        // Single use: the pending request is consumed before the response is looked at.
        let consumed = state_json(&state)?;
        if !self
            .storage()
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &consumed, now)
            .await?
        {
            refuse!(c, "no_pending_request")
        }
        if !pending.is_fresh(now) {
            refuse!(c, "expired")
        }
        let Some(conn) = posted_to.as_ref().filter(|c| c.id == pending.connection_id) else {
            refuse!(c, "connection_mismatch")
        };
        let Some(cfg) = saml_config(conn) else {
            refuse!(c, "connection_disabled")
        };
        let xml = match saml_response.map(decode_response) {
            Some(Ok(xml)) => xml,
            Some(Err(reason)) => refuse!(c, reason),
            None => refuse!(c, "encoding"),
        };
        let data = match self.saml_xml.verify_response(&xml, &cfg.signing_certs) {
            Ok(d) => d,
            Err(r) => refuse!(c, xml_reason(r)),
        };
        let expected = SamlExpected {
            sp_entity_id: sp_entity_id(cx.issuer, &conn.slug),
            acs_url: acs_url(cx.issuer, &conn.slug),
            request_id: pending.request_id.clone(),
            idp_entity_id: cfg.idp_entity_id.clone(),
            attributes: cfg.attributes.clone(),
            skew: DEFAULT_SKEW,
        };
        let identity = match check(&data, &expected, now) {
            Ok(i) => i,
            Err(r) => refuse!(c, r.as_str()),
        };
        // `check` required Conditions NotOnOrAfter; the fallback only keeps this total.
        let not_on_or_after = data.not_on_or_after.unwrap_or(now);
        let recorded = self
            .storage()
            .grants()
            .record_jti(
                tenant,
                ReplayKind::SamlAssertionId,
                &replay_key(&cfg.idp_entity_id, &data.assertion_id),
                replay_expiry(not_on_or_after, now),
                now,
            )
            .await?;
        if recorded == JtiOutcome::Replayed {
            refuse!(c, "replay")
        }
        let identity = upstream_identity(identity, conn);
        let json = serde_json::to_vec(&SealedIdentity::from(&identity))
            .map_err(|e| CoreError::Internal(format!("encoding the SAML identity failed: {e}")))?;
        let verified = SamlPending {
            identity_sealed: Some(seal(self.flows.kek.as_ref(), tenant, flow.id, &json)?),
            ..pending
        };
        let next = LoginState {
            saml: Some(Box::new(verified)),
            ..state
        };
        if !self
            .storage()
            .flows()
            .swap_state(tenant, flow.id, &consumed, &state_json(&next)?, now)
            .await?
        {
            refuse!(c, "no_pending_request")
        }
        Ok(AcsOutcome::Continue {
            location: continue_url(cx.issuer, &conn.slug, relay),
        })
    }

    /// The continue step (module docs): `relay` is the `state` query parameter (the RelayState),
    /// `binding_cookie` the browser's binding cookie, `current` its session.
    pub async fn continue_login(
        &self,
        cx: &FlowContext<'_>,
        slug: &str,
        relay: Option<&str>,
        binding_cookie: Option<&str>,
        current: Option<&BrowserSession>,
    ) -> Result<ContinueResult, CoreError> {
        self.require_enabled()?;
        let mut binding_proved = false;
        let outcome = self
            .run_continue(
                cx,
                slug,
                relay,
                binding_cookie,
                current,
                &mut binding_proved,
            )
            .await?;
        Ok(ContinueResult {
            outcome,
            binding_proved,
        })
    }

    async fn run_continue(
        &self,
        cx: &FlowContext<'_>,
        slug: &str,
        relay: Option<&str>,
        binding_cookie: Option<&str>,
        current: Option<&BrowserSession>,
        binding_proved: &mut bool,
    ) -> Result<ContinueOutcome, CoreError> {
        let tenant = cx.tenant.id;
        let now = self.now();
        let named = self
            .storage()
            .connections()
            .get_by_slug(tenant, slug)
            .await?;
        let c = named.as_ref();
        macro_rules! refuse {
            ($reason:expr) => {{
                self.refuse(cx, c, $reason).await?;
                return Ok(ContinueOutcome::Refused);
            }};
        }
        let Some((relay, flow_id)) = relay.and_then(|r| split_relay_state(r).map(|(f, _)| (r, f)))
        else {
            refuse!("relay_state")
        };
        let Some(flow) = self.storage().flows().get(tenant, flow_id, now).await? else {
            refuse!("relay_state")
        };
        if flow.kind != FlowKind::Login || holds_recovery_codes(&flow) {
            refuse!("relay_state")
        }
        let mut state = login_state(&flow)?;
        let Some(pending) = take_saml(&mut state) else {
            refuse!("no_pending_request")
        };
        let Some(sealed) = pending.identity_sealed.as_deref() else {
            refuse!("no_pending_request")
        };
        if !ct_eq(
            value_hash(relay).as_bytes(),
            pending.relay_state_hash.as_bytes(),
        ) {
            refuse!("relay_state")
        }
        // Until the binding is proved, nothing changes the flow.
        let binding_ok = binding_cookie
            .is_some_and(|b| ct_eq(value_hash(b).as_bytes(), pending.binding_hash.as_bytes()));
        if !binding_ok {
            refuse!("binding")
        }
        if c.map(|c| c.id) != Some(pending.connection_id) {
            refuse!("connection_mismatch")
        }
        *binding_proved = true;
        // Single use: take the identity out before it is used.
        if !self
            .storage()
            .flows()
            .swap_state(tenant, flow.id, &flow.state, &state_json(&state)?, now)
            .await?
        {
            refuse!("no_pending_request")
        }
        if !pending.is_fresh(now) {
            refuse!("expired")
        }
        let Some(identity) = open(self.flows.kek.as_ref(), tenant, flow.id, sealed) else {
            refuse!("state_invalid")
        };
        let Some(conn) = named.as_ref().filter(|c| saml_config(c).is_some()) else {
            refuse!("connection_disabled")
        };
        AuditService {
            storage: Arc::clone(&self.flows.storage),
            clock: Arc::clone(&self.flows.clock),
        }
        .record(
            tenant,
            AuditActor::anonymous(ActorKind::User),
            AuditAction::SamlLoginSucceeded,
            Some(conn.id.to_string()),
            AuditOutcome::Success,
            cx.ctx,
            AuditDetails::connection(&conn.slug, conn.kind().as_str()),
        )
        .await?;
        let outcome = self
            .upstream()
            .complete_identity(cx, &flow, state, conn, identity, current)
            .await?;
        Ok(ContinueOutcome::Completed(Box::new(outcome)))
    }

    /// Unsigned SP metadata of the enabled SAML connection `slug` (entity ID, ACS, NameID
    /// format, `WantAssertionsSigned`). Errors: `FeatureDisabled`, `NotFound`.
    pub async fn sp_metadata(
        &self,
        tenant: TenantId,
        issuer: &str,
        slug: &str,
    ) -> Result<String, CoreError> {
        self.require_enabled()?;
        let (conn, cfg) = self
            .connection(tenant, slug)
            .await?
            .ok_or(CoreError::NotFound)?;
        Ok(sp_metadata(
            &sp_entity_id(issuer, &conn.slug),
            &acs_url(issuer, &conn.slug),
            cfg.name_id_format,
        ))
    }
}

#[cfg(test)]
mod tests {
    use anvil_jose::encoding::b64std;

    use super::*;
    use crate::model::{ConnectionId, NameIdFormat, SamlAttributeMapping};

    const ISSUER: &str = "https://id.example.test/t/acme";

    fn connection(trust: bool) -> Connection {
        let now = OffsetDateTime::UNIX_EPOCH;
        Connection {
            id: ConnectionId::new_v7(),
            tenant_id: TenantId::new_v7(),
            org_id: None,
            slug: "okta".into(),
            display_name: "Okta".into(),
            enabled: true,
            config: ConnectionConfig::Saml(SamlConfig {
                idp_entity_id: "https://idp.example.test".into(),
                sso_url: "https://idp.example.test/sso".into(),
                signing_certs: vec![],
                name_id_format: NameIdFormat::Persistent,
                attributes: SamlAttributeMapping::default(),
                metadata_url: None,
            }),
            secret_enc: None,
            trust_email_verified: trust,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn sp_identifiers_follow_the_documented_layout() {
        assert_eq!(sp_entity_id(ISSUER, "okta"), format!("{ISSUER}/saml/okta"));
        assert_eq!(
            acs_url(ISSUER, "okta"),
            format!("{ISSUER}/ui/login/saml/okta/acs")
        );
        assert_eq!(
            metadata_url(ISSUER, "okta"),
            format!("{ISSUER}/saml/okta/metadata")
        );
        let relay = relay_state(FlowId(uuid::Uuid::nil()), [0xFB; 16]);
        let url = continue_url(ISSUER, "okta", &relay);
        assert!(url.starts_with(&format!("{ISSUER}/ui/login/saml/okta/continue?state=")));
        let q = url.split_once("?state=").expect("query").1;
        let decoded: String = url::form_urlencoded::parse(format!("s={q}").as_bytes())
            .next()
            .expect("pair")
            .1
            .into_owned();
        assert_eq!(decoded, relay);
    }

    #[test]
    fn redirect_url_keeps_the_idp_query_and_encodes_the_values() {
        let url = redirect_url("https://idp.example.test/sso?tenant=a&x=1", "a+b/c=", "f.n")
            .expect("url");
        let parsed = url::Url::parse(&url).expect("parse");
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("tenant".into(), "a".into()),
                ("x".into(), "1".into()),
                ("SAMLRequest".into(), "a+b/c=".into()),
                ("RelayState".into(), "f.n".into()),
            ]
        );
        assert!(redirect_url("not a url", "a", "b").is_err());
    }

    #[test]
    fn decode_response_is_strict_and_capped() {
        assert_eq!(decode_response(&b64std(b"<x/>")), Ok(b"<x/>".to_vec()));
        // Line breaks inserted by some IdPs are dropped.
        let wrapped = b64std(&[b'a'; 120]);
        let (a, b) = wrapped.split_at(76);
        assert_eq!(decode_response(&format!("{a}\r\n{b}")), Ok(vec![b'a'; 120]));
        assert_eq!(decode_response(""), Err("encoding"));
        assert_eq!(decode_response("@@@@"), Err("encoding"));
        assert_eq!(decode_response("PHgvPg-_"), Err("encoding"));
        assert_eq!(
            decode_response(&b64std(&vec![b'a'; MAX_RESPONSE_BYTES])).map(|v| v.len()),
            Ok(MAX_RESPONSE_BYTES)
        );
        assert_eq!(
            decode_response(&b64std(&vec![b'a'; MAX_RESPONSE_BYTES + 1])),
            Err("size")
        );
        assert_eq!(decode_response(&"A".repeat(1024 * 1024)), Err("size"));
    }

    #[test]
    fn xml_reasons_are_distinct_snake_case_codes() {
        use SamlXmlReject as R;
        let all = [
            R::Size,
            R::Parse,
            R::Dtd,
            R::Structure,
            R::DuplicateId,
            R::Encrypted,
            R::SignatureProfile,
            R::Algorithm,
            R::Signature,
            R::UntrustedKey,
            R::Unavailable,
        ];
        let codes: std::collections::BTreeSet<_> = all.iter().map(|r| xml_reason(*r)).collect();
        assert_eq!(codes.len(), all.len());
        assert!(
            codes
                .iter()
                .all(|c| c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
        );
    }

    #[test]
    fn identity_maps_name_id_and_profile_values() {
        let saml = SamlIdentity {
            subject: "00u1".into(),
            email: Some("a@example.test".into()),
            given_name: Some("Ada".into()),
            family_name: Some("L".into()),
            name: None,
        };
        let i = upstream_identity(saml.clone(), &connection(true));
        assert_eq!(i.subject, "00u1");
        assert_eq!(i.email.as_deref(), Some("a@example.test"));
        assert_eq!(i.given_name.as_deref(), Some("Ada"));
        assert!(i.email_verified);
        assert!(!upstream_identity(saml.clone(), &connection(false)).email_verified);
        let no_email = SamlIdentity {
            email: None,
            ..saml
        };
        assert!(!upstream_identity(no_email, &connection(true)).email_verified);
    }

    #[test]
    fn sealed_identity_opens_only_in_its_flow_and_tenant() {
        let kek = Kek::generate();
        let tenant = TenantId::new_v7();
        let a = FlowId::new_v7();
        let identity = upstream_identity(
            SamlIdentity {
                subject: "s".into(),
                email: None,
                given_name: None,
                family_name: None,
                name: None,
            },
            &connection(false),
        );
        let json = serde_json::to_vec(&SealedIdentity::from(&identity)).expect("json");
        let sealed = seal(&kek, tenant, a, &json).expect("seal");
        assert_eq!(open(&kek, tenant, a, &sealed), Some(identity));
        assert_eq!(open(&kek, tenant, FlowId::new_v7(), &sealed), None);
        assert_eq!(open(&kek, TenantId::new_v7(), a, &sealed), None);
        assert_eq!(open(&kek, tenant, a, "garbage"), None);
    }
}
