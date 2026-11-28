//! Account page for the user's editable custom attributes (ADM-06, AUTH-14).
//!
//! | Route | |
//! |---|---|
//! | `GET  /ui/account/attributes` | the user-editable attributes as a form; starts a settings flow |
//! | `POST /ui/account/attributes?flow=` | saves them through `AttributeService` (audited `user_attributes_updated`) |
//!
//! Without a session both routes answer 303 to the sign-in page. The POST is behind the
//! Fetch-Metadata layer and must carry the flow cookie and the CSRF token of a settings flow of
//! the same user; otherwise the `csrf` error page (403). No recent sign-in is needed (like the
//! profile page).
//!
//! # Form shapes
//!
//! Only `user_editable` attributes are shown. An attribute whose schema is one of these shapes
//! gets a form input (annotations `title`, `description`, `$comment`, `$schema`, `examples` and
//! `default` are allowed besides the listed keywords):
//!
//! | Schema | Input |
//! |---|---|
//! | `type: string` + `enum` (strings) | `<select>` (with an empty "not set" option) |
//! | `type: string` (+ `minLength`, `maxLength`, `pattern`, `format: email / uri / date`) | `<input type=text / email / url / date>` |
//! | `type: boolean` | checkbox (unchecked = `false`) |
//! | `type: integer / number` (+ `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf`) | `<input type=number>` |
//!
//! Any other editable schema is shown read-only (its JSON value). Form fields are named
//! `attr.{name}`; an empty text, select or number field removes the value. A submission naming
//! an attribute that is not editable on this page (not `user_editable`, or a read-only shape) is
//! refused (400, nothing saved); one naming an unknown attribute or a value the schema rejects
//! shows the form again (400) with the failing fields marked. Refusals follow Post/Redirect/Get
//! (07.1-21): `303` to `GET ?flow=` with a sealed one-shot flash (messages, failing fields and
//! the typed values) that the `GET` shows on a fresh flow. Validation itself is the core
//! service's (one implementation for the account page and the admin API).
//!
//! The navigation entry is shown when the tenant defines at least one user-editable attribute
//! (`account_attributes_nav`). The page works without JavaScript and is `Cache-Control:
//! no-store`.

use std::collections::{BTreeMap, BTreeSet};

use anvil_core::error::CoreError;
use anvil_core::model::{AttributeDefinition, BrowserSession, FlowId, TenantId};
use anvil_core::service::account::SettingsBinding;
use anvil_core::service::attribute::{AttributeError, AttributeService};
use axum::Router;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, RawQuery, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::cookie::CookieJar;
use secrecy::ExposeSecret as _;
use serde::Serialize;
use serde_json::{Map, Value};

use super::account_security::{account_header, client_id_param};
use super::consent::{PageMessage, account_locale, current_session, localized, no_store};
use super::flash::{self, Flash, FlashValues};
use super::login::{UiQuery, csrf_page, rejected_form};
use super::nav::{AccountSection, NavContext};
use crate::errors::core_error_page_in;
use crate::i18n::{Locale, RequestLocale};
use crate::render::PageContext;
use crate::request_context::AuditContext;
use crate::state::AppState;
use crate::tenant::ResolvedTenant;

const PAGE: &str = "/ui/account/attributes";

/// The form id (the flash belongs to it).
const FORM_ID: &str = "attributes-form";

/// Prefix of the attribute form fields.
const FIELD_PREFIX: &str = "attr.";

/// Annotation keywords allowed in every form shape.
const ANNOTATIONS: [&str; 6] = [
    "title",
    "description",
    "$comment",
    "$schema",
    "examples",
    "default",
];

impl AppState {
    /// The attribute service (definitions and validated value writes). `Internal` when no schema
    /// check is configured (never in a built application).
    pub(crate) fn attribute_service(&self) -> Result<AttributeService, CoreError> {
        let check = self
            .attribute_check()
            .ok_or_else(|| CoreError::Internal("no attribute schema check".into()))?;
        Ok(AttributeService {
            storage: self.storage_arc(),
            clock: self.clock_arc(),
            check,
        })
    }
}

/// Whether the account page shows an attribute: the one rule behind both this page's field list
/// and the "Attributes" navigation entry on every account page.
fn is_user_field(d: &AttributeDefinition) -> bool {
    d.user_editable
}

/// Whether the account navigation shows the "Attributes" entry: the tenant has at least one
/// attribute the user can see on the attributes page (`is_user_field`). Every account handler
/// computes it once per request; an error is the caller's error page, never a silent `false`.
pub(crate) async fn attributes_nav(state: &AppState, tenant: TenantId) -> Result<bool, CoreError> {
    let defs = state.attribute_service()?.list(tenant).await?;
    Ok(defs.iter().any(is_user_field))
}

/// `attributes_nav` for an account page handler: the flag, or the tenant's error page to return.
pub(crate) async fn attributes_nav_or_page(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
) -> Result<bool, Box<Response>> {
    attributes_nav(state, tenant.tenant.id)
        .await
        .map_err(|e| Box::new(core_error_page_in(state, Some(tenant), loc, &e)))
}

/// The routes of this module (tenant-relative paths), merged by the parent module.
pub(super) fn routes() -> Router<AppState> {
    Router::new().route(PAGE, get(show).post(submit))
}

// ---------------------------------------------------------------------------------------------
// Form shapes
// ---------------------------------------------------------------------------------------------

/// How an attribute is edited on the page.
#[derive(Debug, Clone, PartialEq)]
enum Shape {
    Select(Vec<String>),
    Text {
        input: &'static str,
        min_length: Option<u64>,
        max_length: Option<u64>,
    },
    Checkbox,
    Number {
        integer: bool,
        min: Option<f64>,
        max: Option<f64>,
    },
}

/// The form shape of a schema, or `None` when the page cannot edit it.
fn form_shape(schema: &Value) -> Option<Shape> {
    let obj = schema.as_object()?;
    let only = |allowed: &[&str]| {
        obj.keys().all(|k| {
            k == "type" || ANNOTATIONS.contains(&k.as_str()) || allowed.contains(&k.as_str())
        })
    };
    let num = |k: &str| obj.get(k).and_then(Value::as_f64);
    let len = |k: &str| obj.get(k).and_then(Value::as_u64);
    match obj.get("type")?.as_str()? {
        "string" => {
            if let Some(e) = obj.get("enum") {
                if !only(&["enum"]) {
                    return None;
                }
                let options: Option<Vec<String>> = e
                    .as_array()?
                    .iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect();
                return options.filter(|o| !o.is_empty()).map(Shape::Select);
            }
            if !only(&["minLength", "maxLength", "pattern", "format"]) {
                return None;
            }
            let input = match obj.get("format") {
                None => "text",
                Some(Value::String(f)) => match f.as_str() {
                    "email" => "email",
                    "uri" => "url",
                    "date" => "date",
                    _ => return None,
                },
                Some(_) => return None,
            };
            Some(Shape::Text {
                input,
                min_length: len("minLength"),
                max_length: len("maxLength"),
            })
        }
        "boolean" => only(&[]).then_some(Shape::Checkbox),
        t @ ("integer" | "number") => {
            if !only(&[
                "minimum",
                "maximum",
                "exclusiveMinimum",
                "exclusiveMaximum",
                "multipleOf",
            ]) {
                return None;
            }
            Some(Shape::Number {
                integer: t == "integer",
                min: num("minimum"),
                max: num("maximum"),
            })
        }
        _ => None,
    }
}

/// One option of a select.
#[derive(Debug, Serialize)]
struct OptionView {
    value: String,
    selected: bool,
}

/// One attribute as rendered.
#[derive(Debug, Serialize)]
struct FieldView {
    name: String,
    /// The schema `title`, else the attribute name (administrator-defined, not translated).
    label: String,
    description: Option<String>,
    /// `select`, `input`, `checkbox`, `readonly`.
    kind: &'static str,
    /// For `input`: `text`, `email`, `url`, `date` or `number`.
    input_type: &'static str,
    value: String,
    checked: bool,
    options: Vec<OptionView>,
    min_length: Option<u64>,
    max_length: Option<u64>,
    min: Option<String>,
    max: Option<String>,
    step: Option<&'static str>,
    required: bool,
    error: bool,
}

/// A stored value as form text.
fn value_text(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// The views of the user-editable attributes. `typed` overrides the stored text of a field
/// (what the user submitted), `errors` marks fields.
fn field_views(
    defs: &[AttributeDefinition],
    stored: &Map<String, Value>,
    typed: &BTreeMap<String, String>,
    errors: &BTreeSet<String>,
) -> Vec<FieldView> {
    defs.iter()
        .filter(|d| is_user_field(d))
        .map(|d| {
            let shape = form_shape(&d.schema);
            let value = typed
                .get(&d.name)
                .cloned()
                .unwrap_or_else(|| value_text(stored.get(&d.name)));
            let mut view = FieldView {
                name: d.name.clone(),
                label: d
                    .schema
                    .get("title")
                    .and_then(Value::as_str)
                    .filter(|t| !t.trim().is_empty())
                    .unwrap_or(&d.name)
                    .to_owned(),
                description: d
                    .schema
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                kind: "readonly",
                input_type: "text",
                value,
                checked: false,
                options: Vec::new(),
                min_length: None,
                max_length: None,
                min: None,
                max: None,
                step: None,
                required: d.required,
                error: errors.contains(&d.name),
            };
            match shape {
                Some(Shape::Select(options)) => {
                    view.kind = "select";
                    view.options = options
                        .into_iter()
                        .map(|o| OptionView {
                            selected: o == view.value,
                            value: o,
                        })
                        .collect();
                }
                Some(Shape::Text {
                    input,
                    min_length,
                    max_length,
                }) => {
                    view.kind = "input";
                    view.input_type = input;
                    view.min_length = min_length;
                    view.max_length = max_length;
                }
                Some(Shape::Checkbox) => {
                    view.kind = "checkbox";
                    view.checked = match typed.get(&d.name) {
                        Some(t) => !t.is_empty(),
                        None => stored.get(&d.name) == Some(&Value::Bool(true)),
                    };
                }
                Some(Shape::Number { integer, min, max }) => {
                    view.kind = "input";
                    view.input_type = "number";
                    view.min = min.map(|m| m.to_string());
                    view.max = max.map(|m| m.to_string());
                    view.step = Some(if integer { "1" } else { "any" });
                }
                None => {}
            }
            view
        })
        .collect()
}

/// Why a submission was refused before reaching the service.
#[derive(Debug, PartialEq, Eq)]
struct Locked(Vec<String>);

/// The submitted values as JSON and the raw text per attribute (shown again on a refusal).
type Parsed = (Map<String, Value>, BTreeMap<String, String>);

/// The submitted values as JSON (see the module docs) and the raw text per attribute.
fn parse_submission(
    defs: &[AttributeDefinition],
    pairs: &[(String, String)],
) -> Result<Parsed, Locked> {
    let mut raw: BTreeMap<String, String> = BTreeMap::new();
    for (k, v) in pairs {
        if let Some(name) = k.strip_prefix(FIELD_PREFIX) {
            raw.insert(name.to_owned(), v.clone());
        }
    }
    let shapes: BTreeMap<&str, Option<Shape>> = defs
        .iter()
        .map(|d| (d.name.as_str(), form_shape(&d.schema)))
        .collect();
    // An editable attribute this page shows read-only cannot be submitted from it.
    let locked: Vec<String> = raw
        .keys()
        .filter(|n| {
            defs.iter()
                .any(|d| &d.name == *n && d.user_editable && form_shape(&d.schema).is_none())
        })
        .cloned()
        .collect();
    if !locked.is_empty() {
        return Err(Locked(locked));
    }
    let mut values = Map::new();
    for (name, text) in &raw {
        let value = match shapes.get(name.as_str()) {
            Some(Some(Shape::Checkbox)) => Value::Bool(true),
            Some(Some(Shape::Number { integer, .. })) => {
                let t = text.trim();
                if t.is_empty() {
                    Value::Null
                } else if *integer {
                    t.parse::<i64>()
                        .map(Value::from)
                        .unwrap_or_else(|_| Value::String(text.clone()))
                } else {
                    t.parse::<f64>()
                        .ok()
                        .and_then(serde_json::Number::from_f64)
                        .map(Value::Number)
                        .unwrap_or_else(|| Value::String(text.clone()))
                }
            }
            // Text, select, and anything the service will refuse (unknown, not editable).
            _ => {
                if text.is_empty() && shapes.get(name.as_str()).is_some_and(Option::is_some) {
                    Value::Null
                } else {
                    Value::String(text.clone())
                }
            }
        };
        values.insert(name.clone(), value);
    }
    // An unchecked checkbox is not posted: it means `false`.
    for d in defs.iter().filter(|d| d.user_editable) {
        if shapes.get(d.name.as_str()) == Some(&Some(Shape::Checkbox))
            && !values.contains_key(&d.name)
        {
            values.insert(d.name.clone(), Value::Bool(false));
        }
    }
    Ok((values, raw))
}

/// The attribute names in error pointers (`/department/0` -> `department`).
fn error_fields(pointers: &[String]) -> BTreeSet<String> {
    pointers
        .iter()
        .filter_map(|p| p.strip_prefix('/'))
        .map(|p| p.split('/').next().unwrap_or_default().to_owned())
        .filter(|n| !n.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------------

fn to_login(tenant: &ResolvedTenant) -> Response {
    no_store(
        (
            StatusCode::SEE_OTHER,
            [(
                header::LOCATION,
                NavContext::login_returning_to(tenant, AccountSection::Attributes),
            )],
        )
            .into_response(),
    )
}

/// The session and its page locale (303 to sign-in without a session).
async fn page_session(
    state: &AppState,
    tenant: &ResolvedTenant,
    locale: &RequestLocale,
    jar: &CookieJar,
) -> Result<(BrowserSession, Locale), Box<Response>> {
    match current_session(state, tenant, jar).await {
        Ok(Some(s)) => {
            let loc = account_locale(state, tenant, locale, &s).await;
            Ok((s, loc))
        }
        Ok(None) => Err(Box::new(to_login(tenant))),
        Err(e) => Err(Box::new(core_error_page_in(
            state,
            Some(tenant),
            &locale.0,
            &e,
        ))),
    }
}

/// The settings flow the page is bound to.
struct Bound {
    flow_id: FlowId,
    csrf: String,
    jar: CookieJar,
}

async fn start_flow(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
) -> Result<Bound, Box<Response>> {
    match state
        .ui_account_service()
        .start(tenant.tenant.id, session)
        .await
    {
        Ok(started) => Ok(Bound {
            flow_id: started.flow_id,
            csrf: started.csrf_token.expose_secret().to_owned(),
            jar: CookieJar::new().add(
                state
                    .cookies()
                    .flow_cookie(&tenant.tenant, started.cookie_token.expose_secret()),
            ),
        }),
        Err(e) => Err(Box::new(core_error_page_in(state, Some(tenant), loc, &e))),
    }
}

/// What the page shows besides the stored values.
#[derive(Default)]
struct Overlay {
    typed: BTreeMap<String, String>,
    errors: BTreeSet<String>,
    messages: Vec<PageMessage>,
    /// The `client_id` the page was opened with (account header, GET only).
    client_id: Option<String>,
}

async fn render(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    bound: Bound,
    overlay: Overlay,
    status: StatusCode,
) -> Response {
    let loaded = async {
        let service = state.attribute_service()?;
        let defs = service.list(tenant.tenant.id).await?;
        let stored = service
            .user_values(tenant.tenant.id, session.user_id)
            .await?;
        Ok::<_, CoreError>((defs, stored))
    }
    .await;
    let (defs, stored) = match loaded {
        Ok(l) => l,
        Err(e) => return core_error_page_in(state, Some(tenant), loc, &e),
    };
    let header =
        match account_header(state, tenant, loc, session, overlay.client_id.as_deref()).await {
            Ok(h) => h,
            Err(page) => return *page,
        };
    let fields = field_views(&defs, &stored, &overlay.typed, &overlay.errors);
    let messages = localized(state, loc, overlay.messages);
    let ctx = minijinja::context! {
        page => PageContext::for_tenant(state, tenant, loc, "title.account_attributes").into_value(),
        account_base => tenant.base_path(),
        account_nav => "attributes",
        account_attributes_nav => !fields.is_empty(),
        account_header => header.value(),
        csrf_token => &bound.csrf,
        messages => minijinja::Value::from(minijinja::value::Serde(&messages)),
        action => tenant.ui_url(&format!(
            "{PAGE}?flow={}{}",
            bound.flow_id,
            header.client_query_tail()
        )),
        fields => minijinja::Value::from(minijinja::value::Serde(&fields)),
        editable => fields.iter().any(|f| f.kind != "readonly"),
    };
    match state.renderer().page("account_attributes.html", ctx) {
        Ok(html) => no_store((status, bound.jar, html).into_response()),
        Err(e) => {
            tracing::error!(error = %e, "rendering the account attributes page failed");
            core_error_page_in(
                state,
                Some(tenant),
                loc,
                &CoreError::Internal("render".into()),
            )
        }
    }
}

async fn show(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    RawQuery(query): RawQuery,
) -> Response {
    let (session, loc) = match page_session(&state, &tenant, &locale, &jar).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let mut bound = match start_flow(&state, &tenant, &loc, &session).await {
        Ok(b) => b,
        Err(resp) => return *resp,
    };
    // The flash of a refused POST (`?flow=`): its messages, marked fields and typed values.
    let (flash, out) = flash::take_account(
        &state,
        &tenant.tenant,
        query.as_deref(),
        FORM_ID,
        &jar,
        std::mem::take(&mut bound.jar),
    );
    bound.jar = out;
    let client_id = client_id_param(query.as_deref());
    let (overlay, status) = match flash {
        Some(f) => (
            Overlay {
                typed: f.values().attributes.clone(),
                errors: f.error_fields().map(str::to_owned).collect(),
                messages: f
                    .page_messages()
                    .map(|(e, k)| PageMessage::from_flash(e, k))
                    .collect(),
                client_id,
            },
            f.status()
                .and_then(|s| StatusCode::from_u16(s).ok())
                .unwrap_or(StatusCode::BAD_REQUEST),
        ),
        None => (
            Overlay {
                client_id,
                ..Overlay::default()
            },
            StatusCode::OK,
        ),
    };
    render(&state, &tenant, &loc, &session, bound, overlay, status).await
}

/// A refused submission: `303` to the page's `GET ?flow=` with `key`, the failing `fields` and
/// the `typed` values in the flash, carrying the resolved client.
#[expect(
    clippy::too_many_arguments,
    reason = "the refusal and the request it answers"
)]
async fn refused_redirect(
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
    session: &BrowserSession,
    flow: FlowId,
    client_id: Option<&str>,
    key: &str,
    fields: &BTreeSet<String>,
    typed: BTreeMap<String, String>,
) -> Response {
    let header = match account_header(state, tenant, loc, session, client_id).await {
        Ok(h) => h,
        Err(page) => return *page,
    };
    let fields: Vec<String> = fields.iter().cloned().collect();
    flash::account_redirect(
        state,
        tenant,
        loc,
        PAGE,
        flow,
        header.client_query(),
        Flash::account(
            FORM_ID,
            &[(true, key)],
            &fields,
            FlashValues {
                attributes: typed,
                ..FlashValues::default()
            },
            StatusCode::BAD_REQUEST.as_u16(),
        ),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "axum handler: one argument per extractor"
)]
async fn submit(
    State(state): State<AppState>,
    tenant: ResolvedTenant,
    locale: RequestLocale,
    jar: CookieJar,
    AuditContext(ctx): AuditContext,
    Query(q): Query<UiQuery>,
    RawQuery(raw): RawQuery,
    form: Result<Form<Vec<(String, String)>>, FormRejection>,
) -> Response {
    let pairs = match form {
        Ok(Form(pairs)) => pairs,
        Err(e) => return rejected_form(&state, Some(&tenant), &locale.0, &e),
    };
    let (session, loc) = match page_session(&state, &tenant, &locale, &jar).await {
        Ok(s) => s,
        Err(resp) => return *resp,
    };
    let csrf = pairs
        .iter()
        .rev()
        .find(|(k, _)| k == "csrf_token")
        .map(|(_, v)| v.clone())
        .filter(|v| !v.is_empty());
    let (Some(flow_id), Some(csrf)) = (q.flow_id(), csrf) else {
        return csrf_page(&state, Some(&tenant), &loc);
    };
    let cookie = jar
        .get(&state.cookies().flow_name(&tenant.tenant))
        .map(|c| c.value().to_owned());
    let binding = SettingsBinding {
        flow_id,
        cookie_token: cookie.as_deref(),
        csrf_token: &csrf,
    };
    let client_id = client_id_param(raw.as_deref());
    let same_flow = || Bound {
        flow_id,
        csrf: csrf.clone(),
        jar: CookieJar::new(),
    };
    let redirect = |key: &'static str, fields: BTreeSet<String>, typed| {
        let client_id = client_id.clone();
        let (state, tenant, loc, session) = (&state, &tenant, &loc, &session);
        async move {
            refused_redirect(
                state,
                tenant,
                loc,
                session,
                flow_id,
                client_id.as_deref(),
                key,
                &fields,
                typed,
            )
            .await
        }
    };
    let service = match state.attribute_service() {
        Ok(s) => s,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    let defs = match service.list(tenant.tenant.id).await {
        Ok(d) => d,
        Err(e) => return core_error_page_in(&state, Some(&tenant), &loc, &e),
    };
    let (values, typed) = match parse_submission(&defs, &pairs) {
        Ok(p) => p,
        Err(Locked(_)) => {
            // Same refusal as the service's for a non-editable attribute, but the binding is
            // checked first so an unbound request learns nothing.
            match service
                .check_own_binding(tenant.tenant.id, &session, &binding)
                .await
            {
                Ok(_) => {
                    return redirect("attributes.not_editable", BTreeSet::new(), BTreeMap::new())
                        .await;
                }
                Err(e) => {
                    return refused(e, redirect, &state, &tenant, &loc).await;
                }
            }
        }
    };
    match service
        .update_own(tenant.tenant.id, &session, &binding, &values, &ctx)
        .await
    {
        Ok(_) => {
            render(
                &state,
                &tenant,
                &loc,
                &session,
                same_flow(),
                Overlay {
                    messages: vec![PageMessage::info("attributes.saved")],
                    ..Overlay::default()
                },
                StatusCode::OK,
            )
            .await
        }
        Err(AttributeError::Invalid(pointers)) => {
            redirect("attributes.invalid", error_fields(&pointers), typed).await
        }
        Err(e) => refused(e, redirect, &state, &tenant, &loc).await,
    }
}

/// The response to a refused write other than invalid values: the `csrf` page for a broken
/// binding, an error page for a core error, else the Post/Redirect/Get answer (`redirect`).
async fn refused<F, Fut>(
    err: AttributeError,
    redirect: F,
    state: &AppState,
    tenant: &ResolvedTenant,
    loc: &Locale,
) -> Response
where
    F: FnOnce(&'static str, BTreeSet<String>, BTreeMap<String, String>) -> Fut,
    Fut: std::future::Future<Output = Response>,
{
    match err {
        AttributeError::Core(CoreError::Forbidden) => csrf_page(state, Some(tenant), loc),
        AttributeError::Core(e) => core_error_page_in(state, Some(tenant), loc, &e),
        AttributeError::NotEditable(_) | AttributeError::Invalid(_) => {
            redirect("attributes.not_editable", BTreeSet::new(), BTreeMap::new()).await
        }
        // The GET starts a fresh flow anyway.
        AttributeError::FlowExpired => {
            redirect("account.flow_expired", BTreeSet::new(), BTreeMap::new()).await
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn def(name: &str, schema: Value, editable: bool) -> AttributeDefinition {
        AttributeDefinition {
            name: name.to_owned(),
            schema,
            required: false,
            user_editable: editable,
            claim: None,
            position: 0,
        }
    }

    #[test]
    fn supported_shapes() {
        assert_eq!(
            form_shape(&json!({"type": "string", "enum": ["eng", "ops"], "title": "Dept"})),
            Some(Shape::Select(vec!["eng".into(), "ops".into()]))
        );
        assert_eq!(
            form_shape(&json!({"type": "string", "format": "email", "maxLength": 50})),
            Some(Shape::Text {
                input: "email",
                min_length: None,
                max_length: Some(50)
            })
        );
        for (format, input) in [("uri", "url"), ("date", "date")] {
            assert!(matches!(
                form_shape(&json!({"type": "string", "format": format})),
                Some(Shape::Text { input: i, .. }) if i == input
            ));
        }
        assert_eq!(
            form_shape(&json!({"type": "boolean"})),
            Some(Shape::Checkbox)
        );
        assert_eq!(
            form_shape(&json!({"type": "integer", "minimum": 1})),
            Some(Shape::Number {
                integer: true,
                min: Some(1.0),
                max: None
            })
        );
        assert!(matches!(
            form_shape(&json!({"type": "number"})),
            Some(Shape::Number { integer: false, .. })
        ));
    }

    #[test]
    fn complex_shapes_are_not_editable() {
        for schema in [
            json!({"type": "array", "items": {"type": "string"}}),
            json!({"type": "object"}),
            json!({"type": ["string", "null"]}),
            json!({"enum": ["a", "b"]}),
            json!({"type": "string", "enum": [1, 2]}),
            json!({"type": "string", "enum": []}),
            json!({"type": "string", "format": "ipv4"}),
            json!({"type": "string", "oneOf": [{"maxLength": 1}]}),
            json!({"type": "boolean", "const": true}),
            json!({"$ref": "#/$defs/x"}),
            json!(true),
        ] {
            assert_eq!(form_shape(&schema), None, "{schema}");
        }
    }

    #[test]
    fn submissions_are_typed() {
        let defs = vec![
            def("dept", json!({"type": "string", "enum": ["eng"]}), true),
            def("vip", json!({"type": "boolean"}), true),
            def("newsletter", json!({"type": "boolean"}), true),
            def("age", json!({"type": "integer"}), true),
            def("score", json!({"type": "number"}), true),
            def("nick", json!({"type": "string"}), true),
        ];
        let pairs: Vec<(String, String)> = [
            ("csrf_token", "x"),
            ("attr.dept", "eng"),
            ("attr.vip", "on"),
            ("attr.age", "42"),
            ("attr.score", "abc"),
            ("attr.nick", ""),
            ("attr.unknown", "v"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let (values, raw) = parse_submission(&defs, &pairs).unwrap();
        assert_eq!(
            Value::Object(values),
            json!({
                "dept": "eng", "vip": true, "newsletter": false, "age": 42,
                "score": "abc", "nick": null, "unknown": "v",
            })
        );
        assert_eq!(raw["score"], "abc");
    }

    #[test]
    fn read_only_shapes_cannot_be_submitted() {
        let defs = vec![def("tags", json!({"type": "array"}), true)];
        let pairs = vec![("attr.tags".to_owned(), "[]".to_owned())];
        assert_eq!(
            parse_submission(&defs, &pairs),
            Err(Locked(vec!["tags".into()]))
        );
    }

    #[test]
    fn error_pointers_name_fields() {
        let p = vec!["/dept".into(), "/tags/0".into(), String::new()];
        assert_eq!(
            error_fields(&p),
            BTreeSet::from(["dept".to_owned(), "tags".to_owned()])
        );
    }
}
