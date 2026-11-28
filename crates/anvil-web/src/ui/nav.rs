//! End-user flow navigation: the single place that turns flow context into links (U-H1).
//!
//! Every link an end-user flow page shows onward (Create account, Sign in, Forgot password, Use
//! another way, Start over, Cancel, "Continue to <app>", the signed-in page's account and
//! sign-out links) is built here by [`NavContext`]. Handlers never format `/ui/login`,
//! `/ui/registration`, `/ui/recovery` or `/ui/verification` URLs themselves.
//!
//! The authorization request a flow continues lives on the flow row (`Flow.auth_request_id`);
//! after the flow started, that row is the authority, not the query string:
//!
//! * `GET` entry points build the context with [`NavContext::from_query`]: the raw `request=` is
//!   parsed and looked up through the grants port (this tenant, unexpired). An unknown, expired,
//!   malformed or other tenant's id is [`StaleRequest::Unknown`], with no reason detail (no
//!   oracle beyond "expired"); such an id is never echoed into a link.
//! * `POST` answers and re-renders use [`NavContext::from_flow`]: the flow's own request, looked
//!   up the same way. An expired request is simply absent (requests live 15 minutes, a link
//!   opened later falls back to the plain pages, never an error).
//!
//! URLs take their scheme and host from the tenant's issuer (or the installation's public URL for
//! the console), never from the request. An honoured `ui_locales` is carried on every flow link
//! ([`carry_ui_locales`]).

use anvil_core::flow::login::{IDENTIFY_FORM_ID, SSO_CHOICE_FORM_ID};
use anvil_core::model::{AuthRequestId, FlowId, RegistrationMode, SYSTEM_TENANT_SLUG};
use anvil_core::policy::return_to::ReturnTarget;

use super::flow_driver;
use crate::i18n::{Locale, carry_ui_locales};
use crate::render::{ContinueLink, PageLinks};
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

/// Message key of the "Continue to <app>" link (argument `app`).
pub(crate) const CONTINUE_KEY: &str = "nav.continue_to";
/// Message key of the account link.
pub(crate) const ACCOUNT_KEY: &str = "nav.go_to_account";
/// Message key of the sign-out button.
pub(crate) const SIGN_OUT_KEY: &str = "nav.sign_out";
/// Message key of the admin console link (system tenant only).
pub(crate) const CONSOLE_KEY: &str = "nav.open_console";
/// Message key of the plain sign-in link.
pub(crate) const SIGN_IN_KEY: &str = "message.go_to_sign_in";

/// An end-user page a flow links to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UiPage {
    Login,
    Registration,
    Recovery,
    Verification,
    Account(AccountSection),
    /// The end-session endpoint (`{issuer}/logout`), posted by the sign-out form. Without an
    /// `id_token_hint` it only asks for confirmation (RP-Initiated Logout 1.0); nothing is
    /// signed out by a `GET`.
    SignOut,
}

/// One variant per account page (`/ui/account/*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the complete page map; the account pages switch to it section by section (07.1-12)"
)]
pub(crate) enum AccountSection {
    Profile,
    Email,
    Password,
    Security,
    Sessions,
    Apps,
    Linked,
    Attributes,
}

impl AccountSection {
    fn path(self) -> &'static str {
        match self {
            Self::Profile => "/ui/account/profile",
            Self::Email => "/ui/account/email",
            Self::Password => "/ui/account/password",
            Self::Security => "/ui/account/security",
            Self::Sessions => "/ui/account/sessions",
            Self::Apps => "/ui/account/apps",
            Self::Linked => "/ui/account/linked",
            Self::Attributes => "/ui/account/attributes",
        }
    }
}

/// An authorization request that exists, belongs to this tenant and has not expired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LiveRequest {
    pub id: AuthRequestId,
    pub client_id: String,
    /// The client's display name (its client id when it has none).
    pub client_name: String,
}

/// A `request=` that cannot be continued. Deliberately without a reason (unknown, expired,
/// malformed and other tenant look the same).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StaleRequest {
    Unknown,
}

/// One link of a [`WayForward`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NavLink {
    pub href: String,
    pub label_key: &'static str,
    /// The application named by a "Continue to <app>" link.
    pub app_name: Option<String>,
    /// Render as a form posting to `href` (sign-out), not as a link.
    pub method_post: bool,
}

/// Where a page that ends a step sends the user next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WayForward {
    pub primary: NavLink,
    pub secondary: Vec<NavLink>,
}

impl WayForward {
    /// The links of a message page.
    pub(crate) fn into_links(self) -> PageLinks {
        let mut links = PageLinks::default();
        for link in std::iter::once(self.primary).chain(self.secondary) {
            match link.label_key {
                CONTINUE_KEY => {
                    links.continue_to = Some(ContinueLink {
                        href: link.href,
                        app_name: link.app_name.unwrap_or_default(),
                    });
                }
                ACCOUNT_KEY => links.account = Some(link.href),
                SIGN_OUT_KEY => links.sign_out = Some(link.href),
                CONSOLE_KEY => links.console = Some(link.href),
                _ => links.login = Some(link.href),
            }
        }
        links
    }
}

/// The flow context links are built from (module docs).
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct NavContext {
    request: Option<LiveRequest>,
    /// The allowlisted return target of a login without an authorization request (the request
    /// always wins, like the flow service).
    return_to: Option<ReturnTarget>,
}

/// `Debug` without the return target (its token is never logged).
impl std::fmt::Debug for NavContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NavContext")
            .field("request", &self.request)
            .field("return_to", &self.return_to.as_ref().map(|_| ".."))
            .finish()
    }
}

impl NavContext {
    /// No flow context: plain links.
    pub(crate) fn none() -> Self {
        Self::default()
    }

    /// The context of a `GET` entry point from its raw `request` query value. Absent or empty →
    /// no request; anything that is not a live request of this tenant → [`StaleRequest`].
    pub(crate) async fn from_query(
        state: &AppState,
        tenant: &ResolvedTenant,
        raw: Option<&str>,
    ) -> Result<Self, StaleRequest> {
        let raw = match raw {
            None | Some("") => return Ok(Self::none()),
            Some(raw) => raw,
        };
        let id = uuid::Uuid::parse_str(raw)
            .map(AuthRequestId)
            .map_err(|_| StaleRequest::Unknown)?;
        match resolve(state, tenant, id).await {
            Some(request) => Ok(Self {
                request: Some(request),
                return_to: None,
            }),
            None => Err(StaleRequest::Unknown),
        }
    }

    /// The context of a flow from its stored authorization request (through the flow port). An
    /// unknown or expired flow or request is no context, never an error.
    pub(crate) async fn from_flow(state: &AppState, tenant: &ResolvedTenant, flow: FlowId) -> Self {
        let request = match flow_driver::flow_meta(state, tenant, flow).await {
            Ok(meta) => meta.and_then(|m| m.request),
            Err(e) => {
                tracing::warn!(error = %e, "loading the flow for its links failed");
                None
            }
        };
        Self::from_request(state, tenant, request).await
    }

    /// The context of an already parsed request id (a flow the core started with it). Not live →
    /// no context.
    pub(crate) async fn from_request(
        state: &AppState,
        tenant: &ResolvedTenant,
        request: Option<AuthRequestId>,
    ) -> Self {
        let request = match request {
            Some(id) => resolve(state, tenant, id).await,
            None => None,
        };
        Self {
            request,
            return_to: None,
        }
    }

    /// Adds the login's allowlisted return target (used only without a request).
    pub(crate) fn with_return_to(mut self, target: Option<ReturnTarget>) -> Self {
        self.return_to = target;
        self
    }

    /// The live authorization request, if any.
    pub(crate) fn request(&self) -> Option<&LiveRequest> {
        self.request.as_ref()
    }

    /// The URL of `page`. Flow pages carry the live request (`?request=`), a sign-in link without
    /// one carries the return target; every link carries an honoured `ui_locales`.
    pub(crate) fn url(&self, tenant: &ResolvedTenant, loc: &Locale, page: UiPage) -> String {
        let path = match page {
            UiPage::Login => "/ui/login",
            UiPage::Registration => "/ui/registration",
            UiPage::Recovery => "/ui/recovery",
            UiPage::Verification => "/ui/verification",
            UiPage::Account(section) => section.path(),
            // The end-session endpoint reads its parameters from the posted body only.
            UiPage::SignOut => return tenant.ui_url("/logout"),
        };
        let flow_page = matches!(
            page,
            UiPage::Login | UiPage::Registration | UiPage::Recovery | UiPage::Verification
        );
        let url = match (&self.request, &self.return_to) {
            (Some(r), _) if flow_page => tenant.ui_url(&format!("{path}?request={}", r.id)),
            (None, Some(target)) if page == UiPage::Login => {
                let encoded: String =
                    url::form_urlencoded::byte_serialize(target.as_path().as_bytes()).collect();
                tenant.ui_url(&format!("{path}?return_to={encoded}"))
            }
            _ => tenant.ui_url(path),
        };
        carry_ui_locales(&url, loc)
    }

    /// The links between the self-service pages for a form: the sign-in forms link registration
    /// (only while self-registration is open) and recovery, every other form links sign-in.
    pub(crate) fn links(&self, tenant: &ResolvedTenant, loc: &Locale, form_id: &str) -> PageLinks {
        match form_id {
            "login" | IDENTIFY_FORM_ID | SSO_CHOICE_FORM_ID => PageLinks {
                registration: (tenant.tenant.settings.registration == RegistrationMode::Open)
                    .then(|| self.url(tenant, loc, UiPage::Registration)),
                recovery: Some(self.url(tenant, loc, UiPage::Recovery)),
                ..PageLinks::default()
            },
            _ => PageLinks {
                login: Some(self.url(tenant, loc, UiPage::Login)),
                ..PageLinks::default()
            },
        }
    }

    /// Where to go after a step that ends here: a live request continues its app (through the
    /// authorization continuation when signed in, else through sign-in); a signed-in user gets
    /// the account page and the sign-out form (plus the admin console in the system tenant);
    /// anyone else the tenant's sign-in page.
    pub(crate) fn way_forward(
        &self,
        state: &AppState,
        tenant: &ResolvedTenant,
        loc: &Locale,
        signed_in: bool,
    ) -> WayForward {
        self.way_forward_from(state.config().public_url.as_str(), tenant, loc, signed_in)
    }

    /// [`Self::way_forward`] with the installation's public URL (the console's origin).
    fn way_forward_from(
        &self,
        public_url: &str,
        tenant: &ResolvedTenant,
        loc: &Locale,
        signed_in: bool,
    ) -> WayForward {
        if let Some(request) = &self.request {
            let href = if signed_in {
                format!(
                    "{}/authorize/continue?request={}",
                    tenant.issuer, request.id
                )
            } else {
                self.url(tenant, loc, UiPage::Login)
            };
            return WayForward {
                primary: NavLink {
                    href,
                    label_key: CONTINUE_KEY,
                    app_name: Some(request.client_name.clone()),
                    method_post: false,
                },
                secondary: Vec::new(),
            };
        }
        if signed_in {
            let mut secondary = vec![NavLink {
                href: self.url(tenant, loc, UiPage::SignOut),
                label_key: SIGN_OUT_KEY,
                app_name: None,
                method_post: true,
            }];
            if tenant.tenant.slug == SYSTEM_TENANT_SLUG {
                secondary.push(NavLink {
                    href: format!("{public_url}/console/"),
                    label_key: CONSOLE_KEY,
                    app_name: None,
                    method_post: false,
                });
            }
            return WayForward {
                primary: NavLink {
                    href: self.url(tenant, loc, UiPage::Account(AccountSection::Profile)),
                    label_key: ACCOUNT_KEY,
                    app_name: None,
                    method_post: false,
                },
                secondary,
            };
        }
        WayForward {
            primary: NavLink {
                href: self.url(tenant, loc, UiPage::Login),
                label_key: SIGN_IN_KEY,
                app_name: None,
                method_post: false,
            },
            secondary: Vec::new(),
        }
    }
}

/// The live request `id` of this tenant with its client's name, through the grants and client
/// ports. Anything else (unknown, expired, other tenant, client gone, lookup failure) is `None`.
async fn resolve(
    state: &AppState,
    tenant: &ResolvedTenant,
    id: AuthRequestId,
) -> Option<LiveRequest> {
    let request = state
        .storage()
        .grants()
        .get_authorization_request(tenant.tenant.id, id, state.clock().now())
        .await
        .inspect_err(|e| tracing::warn!(error = %e, "loading the request for its links failed"))
        .ok()??;
    let client = state
        .storage()
        .clients()
        .get(tenant.tenant.id, &request.client_id)
        .await
        .inspect_err(|e| tracing::warn!(error = %e, "loading the client for its links failed"))
        .ok()??;
    let client_name = if client.name.trim().is_empty() {
        client.client_id.clone()
    } else {
        client.name.clone()
    };
    Some(LiveRequest {
        id: request.id,
        client_id: client.client_id,
        client_name,
    })
}

#[cfg(test)]
mod tests {
    use anvil_core::model::{Tenant, TenantBase, TenantId, TenantSettings};
    use time::OffsetDateTime;

    use super::*;

    const REQ: &str = "0190a6d4-0000-7000-8000-0000000000aa";
    const ISSUER: &str = "https://id.example.com/t/acme";

    fn tenant(slug: &str, registration: RegistrationMode) -> ResolvedTenant {
        let settings = TenantSettings {
            registration,
            ..TenantSettings::default()
        };
        ResolvedTenant {
            tenant: Tenant {
                id: TenantId::new_v7(),
                slug: slug.into(),
                display_name: "Acme".into(),
                host: None,
                settings,
                created_at: OffsetDateTime::UNIX_EPOCH,
            },
            base: TenantBase::Path(slug.into()),
            issuer: format!("https://id.example.com/t/{slug}"),
        }
    }

    fn live() -> NavContext {
        NavContext {
            request: Some(LiveRequest {
                id: AuthRequestId(uuid::Uuid::parse_str(REQ).expect("uuid")),
                client_id: "shop".into(),
                client_name: "Shop".into(),
            }),
            return_to: None,
        }
    }

    fn ui_locales(tags: &str) -> Locale {
        Locale {
            ui_locales: Some(tags.into()),
            ..Locale::new("de")
        }
    }

    #[test]
    fn urls_carry_the_live_request_and_ui_locales() {
        let t = tenant("acme", RegistrationMode::Open);
        let en = Locale::fallback();
        let nav = live();
        assert_eq!(
            nav.url(&t, &en, UiPage::Login),
            format!("{ISSUER}/ui/login?request={REQ}")
        );
        assert_eq!(
            nav.url(&t, &en, UiPage::Recovery),
            format!("{ISSUER}/ui/recovery?request={REQ}")
        );
        assert_eq!(
            nav.url(&t, &en, UiPage::Registration),
            format!("{ISSUER}/ui/registration?request={REQ}")
        );
        assert_eq!(
            nav.url(&t, &en, UiPage::Verification),
            format!("{ISSUER}/ui/verification?request={REQ}")
        );
        assert_eq!(
            nav.url(&t, &ui_locales("de en"), UiPage::Login),
            format!("{ISSUER}/ui/login?request={REQ}&ui_locales=de+en")
        );
        // Account pages and sign-out never carry the request.
        assert_eq!(
            nav.url(&t, &en, UiPage::Account(AccountSection::Sessions)),
            format!("{ISSUER}/ui/account/sessions")
        );
        assert_eq!(
            nav.url(&t, &en, UiPage::SignOut),
            format!("{ISSUER}/logout")
        );
    }

    #[test]
    fn no_context_yields_bare_urls() {
        let t = tenant("acme", RegistrationMode::Open);
        let en = Locale::fallback();
        let nav = NavContext::none();
        assert!(nav.request().is_none());
        assert_eq!(
            nav.url(&t, &en, UiPage::Login),
            format!("{ISSUER}/ui/login")
        );
        assert_eq!(
            nav.url(&t, &ui_locales("de"), UiPage::Recovery),
            format!("{ISSUER}/ui/recovery?ui_locales=de")
        );
    }

    #[test]
    fn return_target_only_on_sign_in_and_only_without_a_request() {
        let t = tenant("acme", RegistrationMode::Open);
        let en = Locale::fallback();
        let target =
            anvil_core::policy::return_to::parse_return_target("/ui/invitation?token=abcDEF123_-");
        assert!(target.is_some());
        let nav = NavContext::none().with_return_to(target.clone());
        assert_eq!(
            nav.url(&t, &en, UiPage::Login),
            format!("{ISSUER}/ui/login?return_to=%2Fui%2Finvitation%3Ftoken%3DabcDEF123_-")
        );
        assert_eq!(
            nav.url(&t, &en, UiPage::Recovery),
            format!("{ISSUER}/ui/recovery")
        );
        let nav = live().with_return_to(target);
        assert_eq!(
            nav.url(&t, &en, UiPage::Login),
            format!("{ISSUER}/ui/login?request={REQ}")
        );
    }

    #[test]
    fn links_follow_the_form() {
        let en = Locale::fallback();
        let open = tenant("acme", RegistrationMode::Open);
        let closed = tenant("acme", RegistrationMode::Disabled);
        for form in ["login", IDENTIFY_FORM_ID, SSO_CHOICE_FORM_ID] {
            let l = NavContext::none().links(&open, &en, form);
            assert_eq!(l.login, None, "{form}");
            assert_eq!(
                l.registration.as_deref(),
                Some(&*format!("{ISSUER}/ui/registration"))
            );
            assert_eq!(
                l.recovery.as_deref(),
                Some(&*format!("{ISSUER}/ui/recovery"))
            );
            let l = live().links(&open, &en, form);
            assert_eq!(
                l.registration.as_deref(),
                Some(&*format!("{ISSUER}/ui/registration?request={REQ}"))
            );
            // The recovery link keeps the request too (it did not before 07.1).
            assert_eq!(
                l.recovery.as_deref(),
                Some(&*format!("{ISSUER}/ui/recovery?request={REQ}"))
            );
            assert_eq!(
                live().links(&closed, &en, form).registration,
                None,
                "{form}"
            );
        }
        for form in [
            "registration",
            "recovery",
            "second-factor",
            "email-code",
            "x",
        ] {
            let l = live().links(&open, &en, form);
            assert_eq!(
                l.login.as_deref(),
                Some(&*format!("{ISSUER}/ui/login?request={REQ}")),
                "{form}"
            );
            assert_eq!(l.registration, None);
            assert_eq!(l.recovery, None);
        }
    }

    #[test]
    fn way_forward_continues_the_app_first() {
        let t = tenant("acme", RegistrationMode::Open);
        let en = Locale::fallback();
        let public = "https://id.example.com";
        let signed_out = live().way_forward_from(public, &t, &en, false);
        assert_eq!(signed_out.primary.label_key, CONTINUE_KEY);
        assert_eq!(signed_out.primary.app_name.as_deref(), Some("Shop"));
        assert_eq!(
            signed_out.primary.href,
            format!("{ISSUER}/ui/login?request={REQ}")
        );
        let signed_in = live().way_forward_from(public, &t, &en, true);
        assert_eq!(
            signed_in.primary.href,
            format!("{ISSUER}/authorize/continue?request={REQ}")
        );
        let links = signed_in.into_links();
        let cont = links.continue_to.expect("continue link");
        assert_eq!(cont.app_name, "Shop");
        assert!(links.account.is_none() && links.sign_out.is_none());
    }

    #[test]
    fn way_forward_signed_in_offers_account_and_sign_out() {
        let en = Locale::fallback();
        let public = "https://id.example.com";
        let t = tenant("acme", RegistrationMode::Open);
        let wf = NavContext::none().way_forward_from(public, &t, &en, true);
        assert_eq!(wf.primary.label_key, ACCOUNT_KEY);
        assert_eq!(wf.primary.href, format!("{ISSUER}/ui/account/profile"));
        assert_eq!(wf.secondary.len(), 1);
        assert!(wf.secondary[0].method_post);
        assert_eq!(wf.secondary[0].href, format!("{ISSUER}/logout"));
        let links = wf.into_links();
        assert!(links.console.is_none() && links.login.is_none());
        assert!(links.account.is_some() && links.sign_out.is_some());

        let system = tenant(SYSTEM_TENANT_SLUG, RegistrationMode::Disabled);
        let links = NavContext::none()
            .way_forward_from(public, &system, &en, true)
            .into_links();
        assert_eq!(
            links.console.as_deref(),
            Some("https://id.example.com/console/")
        );

        let wf = NavContext::none().way_forward_from(public, &t, &en, false);
        assert_eq!(wf.primary.label_key, SIGN_IN_KEY);
        assert_eq!(wf.primary.href, format!("{ISSUER}/ui/login"));
        assert!(wf.secondary.is_empty());
    }
}
