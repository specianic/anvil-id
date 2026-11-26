//! User import with legacy password hashes (ADM-08), end to end on the storage backend under test:
//! `UserImportService` outcomes and idempotency, Firebase hash profiles (sealed signer key,
//! delete refused while referenced), first sign-in through the UI login form with the old
//! password for every scheme (known-answer inputs from the primary sources), the transparent
//! rehash to Argon2id with a compare-and-swap, and the no-leak guarantee.

mod support;
mod ui_helpers;

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use anvil_core::error::CoreError;
use anvil_core::model::{
    AuditAction, AuditActor, AuditQuery, HashProfileMaterial, ProfileKind, PublicUrl,
    RequestContext, Tenant, TenantId, UserId,
};
use anvil_core::ports::{PasswordCheck, PasswordHasher, Storage};
use anvil_core::service::bootstrap::BootstrapService;
use anvil_core::service::hash_profile::{HashProfileService, NewHashProfile};
use anvil_core::service::user_import::{
    IMPORT_BATCH_MAX, ImportReport, ImportRequest, Outcome, RawRecord, RejectReason,
    UserImportService,
};
use anvil_jose::encoding::{b64std, b64std_decode};
use anvil_jose::kek::Kek;
use anvil_web::adapters::PasswordDispatcher;
use anvil_web::adapters::argon2::Argon2Pool;
use anvil_web::adapters::attribute_schema::JsonSchemaCheck;
use anvil_web::adapters::hibp::{BreachCheckMode, breach_checker};
use anvil_web::{AppConfig, AppDeps};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, header};
use http_body_util::BodyExt;
use secrecy::SecretBox;
use tower::ServiceExt;
use uuid::Uuid;

use support::{Backend, PROD_URL, TestClock, TestResponse, start_time};
use ui_helpers::{Client, login};

// --- known-answer inputs (research table; primary sources) ---------------------------------------

/// Openwall crypt_blowfish test vector: password `U*U`.
const BCRYPT_PW: &str = "U*U";
const BCRYPT_HASH: &str = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
/// RFC 7914 §12: P="password", S="NaCl", N=1024, r=8, p=16, dkLen=64.
const SCRYPT_HASH_HEX: &str = "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640";
/// firebase/scrypt README: signer key, separator, rounds 8, mem_cost 14, password `user1password`.
const FB_SIGNER_KEY: &str =
    "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
const FB_SEPARATOR: &str = "Bw==";
const FB_SALT: &str = "42xEC+ixf3L2lw==";
const FB_PW: &str = "user1password";
const FB_HASH: &str =
    "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";
/// RFC 6070 (test 5): PBKDF2-HMAC-SHA1, c=4096, dkLen=25.
const PBKDF2_PW: &str = "passwordPASSWORDpassword";
const PBKDF2_SALT: &str = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
const PBKDF2_HASH_HEX: &str = "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038";
/// P-H-C/phc-winner-argon2 README: Argon2i, password `password`, salt `somesalt`.
const ARGON2I_HASH: &str =
    "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";
/// Django and salted SHA-256 values are computed at test time with aws-lc-rs.
const DJANGO_PW: &str = "django password 1";
const DJANGO_SALT: &str = "seasalt0123456789";
const SHA2_PW: &str = "sha2 password 1";
const SHA2_SALT_HEX: &str = "000102030405060708090a0b0c0d0e0f";

fn django_hash() -> String {
    let mut out = [0u8; 32];
    aws_lc_rs::pbkdf2::derive(
        aws_lc_rs::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100_000).unwrap(),
        DJANGO_SALT.as_bytes(),
        DJANGO_PW.as_bytes(),
        &mut out,
    );
    format!("pbkdf2_sha256$100000${DJANGO_SALT}${}", b64std(&out))
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha2_hash_hex() -> String {
    let mut data = SHA2_PW.as_bytes().to_vec();
    data.extend_from_slice(&hex_decode(SHA2_SALT_HEX));
    hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data).as_ref())
}

/// `(email, password, password object)` for every scheme. Firebase needs the profile id.
fn scheme_users(profile: Uuid) -> Vec<(&'static str, &'static str, serde_json::Value)> {
    use serde_json::json;
    vec![
        (
            "bcrypt@example.com",
            BCRYPT_PW,
            json!({"scheme": "bcrypt", "hash": BCRYPT_HASH}),
        ),
        (
            "scrypt@example.com",
            "password",
            json!({"scheme": "scrypt", "log_n": 10, "r": 8, "p": 16,
                   "salt": {"hex": hex(b"NaCl")}, "hash": {"hex": SCRYPT_HASH_HEX}}),
        ),
        (
            "firebase@example.com",
            FB_PW,
            json!({"scheme": "firebase_scrypt", "profile": profile.to_string(),
                   "salt": {"base64": FB_SALT}, "hash": {"base64": FB_HASH}}),
        ),
        (
            "pbkdf2@example.com",
            PBKDF2_PW,
            json!({"scheme": "pbkdf2", "prf": "sha1", "iterations": 4096,
                   "salt": {"hex": hex(PBKDF2_SALT.as_bytes())}, "hash": {"hex": PBKDF2_HASH_HEX}}),
        ),
        (
            "django@example.com",
            DJANGO_PW,
            json!({"scheme": "django_pbkdf2", "hash": django_hash()}),
        ),
        (
            "sha2@example.com",
            SHA2_PW,
            json!({"scheme": "salted_sha2", "alg": "sha256", "position": "suffix",
                   "salt": {"hex": SHA2_SALT_HEX}, "hash": {"hex": sha2_hash_hex()}}),
        ),
        (
            "argon2i@example.com",
            "password",
            json!({"scheme": "argon2", "hash": ARGON2I_HASH}),
        ),
    ]
}

/// Every hash, salt and key substring the inputs carry (for the leak scans).
fn secret_needles() -> Vec<String> {
    let mut v = vec![
        BCRYPT_HASH.to_owned(),
        BCRYPT_HASH[7..29].to_owned(),
        SCRYPT_HASH_HEX[..32].to_owned(),
        FB_SALT.trim_end_matches('=').to_owned(),
        FB_HASH[..24].to_owned(),
        FB_SIGNER_KEY[..24].to_owned(),
        PBKDF2_HASH_HEX[..24].to_owned(),
        hex(PBKDF2_SALT.as_bytes()),
        ARGON2I_HASH[30..].to_owned(),
        django_hash(),
        DJANGO_SALT.to_owned(),
        sha2_hash_hex()[..32].to_owned(),
        SHA2_SALT_HEX.to_owned(),
        "$anvil-".to_owned(),
        "$2a$".to_owned(),
        "$2b$".to_owned(),
        "$argon2".to_owned(),
    ];
    // base64 forms of the hex inputs, as the stored encoding would carry them.
    v.push(b64std(&hex_decode(SCRYPT_HASH_HEX))[..24].to_owned());
    v.push(b64std(&hex_decode(PBKDF2_HASH_HEX))[..24].to_owned());
    v
}

// --- the application with a hookable hasher ----------------------------------------------------

/// The production hasher with a test hook: when armed, `hash` (called by the rehash after a
/// successful legacy verify) first stores a different password for the user, simulating a
/// password change that lands between verify and rehash.
/// The password write the hook performs: storage, tenant, user and the new PHC string.
type ConcurrentChange = (Arc<dyn Storage>, TenantId, UserId, String);

struct HookedHasher {
    inner: PasswordDispatcher,
    hook: Mutex<Option<ConcurrentChange>>,
}

#[async_trait::async_trait]
impl PasswordHasher for HookedHasher {
    async fn hash(&self, password: &str) -> Result<String, CoreError> {
        let armed = self.hook.lock().unwrap().take();
        if let Some((storage, tenant, user, phc)) = armed {
            assert!(
                storage
                    .users()
                    .set_password(tenant, user, &phc, start_time())
                    .await
                    .unwrap()
            );
        }
        self.inner.hash(password).await
    }

    async fn verify(
        &self,
        phc: Option<&str>,
        password: &str,
        profile: Option<&HashProfileMaterial>,
    ) -> Result<PasswordCheck, CoreError> {
        self.inner.verify(phc, password, profile).await
    }
}

struct ImportApp {
    router: Router,
    storage: Arc<dyn Storage>,
    clock: Arc<TestClock>,
    kek: Arc<Kek>,
    hasher: Arc<HookedHasher>,
    config: AppConfig,
    tenant: Tenant,
    jar: Mutex<BTreeMap<String, String>>,
    /// Last octet of the peer address; each UI login uses a fresh one, so the per-address rate
    /// limit does not interfere with tests that sign in many times.
    peer: std::sync::atomic::AtomicU8,
}

impl ImportApp {
    async fn new() -> Self {
        let storage = Backend::from_env().storage().await;
        let clock = Arc::new(TestClock::new(start_time()));
        let kek = Arc::new(Kek::generate());
        let config = AppConfig::new(PublicUrl::parse(PROD_URL).expect("public url"));
        let hasher = Arc::new(HookedHasher {
            inner: PasswordDispatcher::new(
                Argon2Pool::new(argon2::Params::new(256, 1, 1, None).expect("params"), 4)
                    .expect("argon2 pool"),
            ),
            hook: Mutex::new(None),
        });
        BootstrapService {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock) as Arc<dyn anvil_core::ports::Clock>,
            kek: Arc::clone(&kek),
            hasher: Arc::clone(&hasher) as Arc<dyn PasswordHasher>,
            policy: config.password_policy,
            public_url: config.public_url.clone(),
        }
        .ensure_installed()
        .await
        .expect("install");
        let deps = AppDeps {
            storage: Arc::clone(&storage),
            clock: Arc::clone(&clock) as Arc<dyn anvil_core::ports::Clock>,
            hasher: Arc::clone(&hasher) as Arc<dyn PasswordHasher>,
            breach: breach_checker(BreachCheckMode::Off),
            kek: Arc::clone(&kek),
            domain_txt: Arc::new(support::FakeTxt::default()),
        };
        let router = anvil_web::app(config.clone(), deps).expect("app builds");
        let tenant = storage
            .tenants()
            .get_by_slug("default")
            .await
            .unwrap()
            .expect("default tenant");
        Self {
            router,
            storage,
            clock,
            kek,
            hasher,
            config,
            tenant,
            jar: Mutex::new(BTreeMap::new()),
            peer: std::sync::atomic::AtomicU8::new(1),
        }
    }

    fn importer(&self) -> UserImportService {
        UserImportService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock) as Arc<dyn anvil_core::ports::Clock>,
            check: Arc::new(JsonSchemaCheck::new()),
        }
    }

    fn profiles(&self) -> HashProfileService {
        HashProfileService {
            storage: Arc::clone(&self.storage),
            clock: Arc::clone(&self.clock) as Arc<dyn anvil_core::ports::Clock>,
            kek: Arc::clone(&self.kek),
        }
    }

    async fn firebase_profile(&self) -> Uuid {
        self.profiles()
            .create(
                self.tenant.id,
                NewHashProfile {
                    name: "firebase".into(),
                    kind: ProfileKind::FirebaseScrypt,
                    signer_key: SecretBox::from(
                        b64std_decode(FB_SIGNER_KEY).unwrap().into_boxed_slice(),
                    ),
                    salt_separator: b64std_decode(FB_SEPARATOR).unwrap(),
                    rounds: 8,
                    mem_cost: 14,
                },
                AuditActor::system(),
                &RequestContext::system(),
            )
            .await
            .expect("create profile")
            .id
    }

    async fn import(&self, lines: &[String], dry_run: bool, update: bool) -> ImportReport {
        self.try_import(lines, dry_run, update)
            .await
            .expect("import")
    }

    async fn try_import(
        &self,
        lines: &[String],
        dry_run: bool,
        update: bool,
    ) -> Result<ImportReport, CoreError> {
        let records = lines
            .iter()
            .enumerate()
            .map(|(i, t)| RawRecord {
                line: i + 1,
                text: t.clone(),
            })
            .collect();
        self.importer()
            .import(
                self.tenant.id,
                ImportRequest {
                    records,
                    dry_run,
                    update,
                    source: Some("test-source"),
                    actor: AuditActor::system(),
                    ctx: &RequestContext::system(),
                },
            )
            .await
    }

    async fn phc_of(&self, email: &str) -> Option<String> {
        let user = self
            .storage
            .users()
            .get_by_email(self.tenant.id, email)
            .await
            .unwrap()
            .expect("user exists");
        self.storage
            .users()
            .password(self.tenant.id, user.id)
            .await
            .unwrap()
            .map(|c| c.phc)
    }

    async fn user_count(&self) -> usize {
        self.storage
            .users()
            .list(
                self.tenant.id,
                anvil_core::model::PageRequest {
                    after: None,
                    limit: 200,
                },
            )
            .await
            .unwrap()
            .items
            .len()
    }

    fn next_peer(&self) {
        let n = self.peer.load(std::sync::atomic::Ordering::Relaxed);
        self.peer.store(
            n.wrapping_add(1).max(1),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    fn signed_in(&self) -> bool {
        self.jar
            .lock()
            .unwrap()
            .keys()
            .any(|k| k.contains("anvil_session_"))
    }

    async fn send(&self, mut req: Request<Body>) -> TestResponse {
        req.headers_mut().insert(
            header::HOST,
            self.config.public_url.host_port().parse().expect("host"),
        );
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    203,
                    0,
                    113,
                    self.peer.load(std::sync::atomic::Ordering::Relaxed),
                )),
                40000,
            )));
        let cookie_header = self
            .jar
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        if !cookie_header.is_empty() {
            req.headers_mut()
                .insert(header::COOKIE, cookie_header.parse().expect("cookie"));
        }
        let resp = self.router.clone().oneshot(req).await.expect("infallible");
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec();
        self.store_cookies(&headers);
        TestResponse {
            status,
            headers,
            body,
        }
    }

    fn store_cookies(&self, headers: &HeaderMap) {
        let mut jar = self.jar.lock().unwrap();
        for v in headers.get_all(header::SET_COOKIE) {
            let Ok(raw) = v.to_str() else { continue };
            let Ok(c) = axum_extra::extract::cookie::Cookie::parse(raw.to_owned()) else {
                continue;
            };
            if c.value().is_empty() || c.max_age().is_some_and(|m| m.is_zero()) {
                jar.remove(c.name());
            } else {
                jar.insert(c.name().to_owned(), c.value().to_owned());
            }
        }
    }
}

impl Client for ImportApp {
    fn origin(&self) -> String {
        format!(
            "{}://{}",
            self.config.public_url.scheme(),
            self.config.public_url.host_port()
        )
    }

    async fn get(&self, path: &str) -> TestResponse {
        self.send(Request::get(path).body(Body::empty()).expect("request"))
            .await
    }

    async fn post_form(&self, path: &str, pairs: &[(&str, &str)]) -> TestResponse {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        self.send(
            Request::builder()
                .method(Method::POST)
                .uri(path)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("sec-fetch-site", "same-origin")
                .body(Body::from(body))
                .expect("request"),
        )
        .await
    }

    fn clear_cookies(&self) {
        self.jar.lock().unwrap().clear();
    }
}

fn record(email: &str, password: Option<&serde_json::Value>) -> String {
    let mut v = serde_json::json!({"email": email, "email_verified": true});
    if let Some(p) = password {
        v["password"] = p.clone();
    }
    v.to_string()
}

/// Logs in through the UI form and reports whether a session was established.
async fn ui_login(app: &ImportApp, email: &str, password: &str) -> bool {
    app.next_peer();
    app.clear_cookies();
    let resp = login(app, "", email, password).await;
    let ok = app.signed_in();
    assert!(
        (ok && resp.status == 200) || (!ok && resp.status == 400),
        "unexpected login answer {} for {email}",
        resp.status
    );
    app.clear_cookies();
    ok
}

// --- tests -------------------------------------------------------------------------------------

#[tokio::test]
async fn imported_users_log_in_with_old_password_and_are_rehashed() {
    let app = ImportApp::new().await;
    let profile = app.firebase_profile().await;
    let users = scheme_users(profile);
    let lines: Vec<String> = users.iter().map(|(e, _, p)| record(e, Some(p))).collect();
    let report = app.import(&lines, false, false).await;
    assert_eq!(report.counts.created, users.len() as u64, "{report:?}");
    assert_eq!(report.counts.rejected, 0);
    for (email, password, _) in &users {
        assert!(
            !app.phc_of(email).await.unwrap().starts_with("$argon2id$"),
            "{email} is stored in its legacy form before the first sign-in"
        );
        assert!(ui_login(&app, email, password).await, "{email} logs in");
        let phc = app.phc_of(email).await.unwrap();
        assert!(
            phc.starts_with("$argon2id$"),
            "{email} rehashed to argon2id"
        );
        // The new hash works too.
        assert!(ui_login(&app, email, password).await, "{email} again");
    }
}

#[tokio::test]
async fn imported_wrong_password_fails() {
    let app = ImportApp::new().await;
    let profile = app.firebase_profile().await;
    let users = scheme_users(profile);
    let lines: Vec<String> = users.iter().map(|(e, _, p)| record(e, Some(p))).collect();
    app.import(&lines, false, false).await;
    for (email, _, _) in &users {
        let before = app.phc_of(email).await;
        assert!(
            !ui_login(&app, email, "definitely-not-it-42").await,
            "{email}"
        );
        assert_eq!(app.phc_of(email).await, before, "no rehash on failure");
    }
}

#[tokio::test]
async fn imported_rehash_cas_keeps_concurrent_change() {
    let app = ImportApp::new().await;
    let line = record(
        "race@example.com",
        Some(&serde_json::json!({"scheme": "bcrypt", "hash": BCRYPT_HASH})),
    );
    app.import(&[line], false, false).await;
    let user = app
        .storage
        .users()
        .get_by_email(app.tenant.id, "race@example.com")
        .await
        .unwrap()
        .unwrap();
    let newer = app.hasher.inner.hash("the newer password 1").await.unwrap();
    *app.hasher.hook.lock().unwrap() = Some((
        Arc::clone(&app.storage),
        app.tenant.id,
        user.id,
        newer.clone(),
    ));
    assert!(ui_login(&app, "race@example.com", BCRYPT_PW).await);
    assert!(app.hasher.hook.lock().unwrap().is_none(), "the hook fired");
    assert_eq!(
        app.phc_of("race@example.com").await.as_deref(),
        Some(newer.as_str()),
        "the concurrent password change survives the rehash"
    );
    assert!(ui_login(&app, "race@example.com", "the newer password 1").await);
    assert!(!ui_login(&app, "race@example.com", BCRYPT_PW).await);
}

#[tokio::test]
async fn imported_firebase_missing_profile_fails_closed() {
    let app = ImportApp::new().await;
    let profile = app.firebase_profile().await;
    let fb = scheme_users(profile)
        .into_iter()
        .find(|(e, _, _)| e.starts_with("firebase"))
        .unwrap();
    app.import(&[record(fb.0, Some(&fb.2))], false, false).await;
    // The service refuses to delete a referenced profile...
    let err = app
        .profiles()
        .delete(
            app.tenant.id,
            profile,
            AuditActor::system(),
            &RequestContext::system(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::Conflict(_)), "{err:?}");
    // ...so remove it behind its back through the storage port.
    assert!(
        app.storage
            .password_profiles()
            .delete(app.tenant.id, profile)
            .await
            .unwrap()
    );
    let before = app.phc_of(fb.0).await;
    let failed = {
        app.clear_cookies();
        let resp = login(&app, "", fb.0, fb.1).await;
        assert!(!app.signed_in());
        resp
    };
    // Same answer as an ordinary wrong password.
    app.clear_cookies();
    let wrong = login(&app, "", fb.0, "definitely-not-it-42").await;
    assert_eq!(failed.status, 400);
    assert_eq!(failed.status, wrong.status);
    assert_eq!(
        ui_helpers::message_keys(&failed.html()),
        ui_helpers::message_keys(&wrong.html())
    );
    assert_eq!(app.phc_of(fb.0).await, before);
    // Audited as a normal login failure.
    let failures = app
        .storage
        .audit()
        .query(
            app.tenant.id,
            &AuditQuery {
                action: Some(AuditAction::LoginFailed),
                limit: 10,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert!(failures.items.len() >= 2);
}

#[tokio::test]
async fn imported_over_cap_hash_refused_at_import() {
    let app = ImportApp::new().await;
    let over = serde_json::json!({"scheme": "scrypt", "log_n": 20, "r": 8, "p": 1,
        "salt": {"hex": "00112233"}, "hash": {"hex": SCRYPT_HASH_HEX}});
    let argon_over = serde_json::json!({"scheme": "argon2",
        "hash": "$argon2id$v=19$m=4194304,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"});
    let lines = vec![
        record("over1@example.com", Some(&over)),
        record("over2@example.com", Some(&argon_over)),
    ];
    let report = app.import(&lines, false, false).await;
    assert_eq!(report.counts.rejected, 2);
    for r in &report.records {
        assert_eq!(r.outcome, Outcome::Rejected);
        assert_eq!(r.reason, Some(RejectReason::OverCap));
    }
    for email in ["over1@example.com", "over2@example.com"] {
        assert!(
            app.storage
                .users()
                .get_by_email(app.tenant.id, email)
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn import_outcomes_idempotency_and_dry_run() {
    let app = ImportApp::new().await;
    let bcrypt = serde_json::json!({"scheme": "bcrypt", "hash": BCRYPT_HASH});
    let lines = vec![
        record("a@example.com", Some(&bcrypt)),
        record("b@example.com", None),
        "not json".to_owned(),
        record("bad-email", None),
        record(
            "c@example.com",
            Some(&serde_json::json!({"scheme": "md5", "hash": "x"})),
        ),
        record(
            "d@example.com",
            Some(&serde_json::json!({"scheme": "firebase_scrypt",
                "profile": Uuid::now_v7().to_string(),
                "salt": {"base64": FB_SALT}, "hash": {"base64": FB_HASH}})),
        ),
    ];
    let users_before = app.user_count().await;

    // Dry run: the same report, nothing written.
    let dry = app.import(&lines, true, false).await;
    assert!(dry.dry_run);
    assert_eq!(
        app.user_count().await,
        users_before,
        "dry run writes no user"
    );
    let real = app.import(&lines, false, false).await;
    assert_eq!(dry.counts, real.counts);
    let outcome = |r: &ImportReport| {
        r.records
            .iter()
            .map(|o| (o.line, o.outcome, o.reason))
            .collect::<Vec<_>>()
    };
    assert_eq!(outcome(&dry), outcome(&real));
    assert_eq!(
        outcome(&real),
        vec![
            (1, Outcome::Created, None),
            (2, Outcome::Created, None),
            (3, Outcome::Rejected, Some(RejectReason::InvalidRecord)),
            (4, Outcome::Rejected, Some(RejectReason::InvalidEmail)),
            (5, Outcome::Rejected, Some(RejectReason::UnknownScheme)),
            (6, Outcome::Rejected, Some(RejectReason::UnknownProfile)),
        ]
    );
    assert!(real.records[0].weak, "bcrypt cost 5 is weak");
    assert_eq!(real.counts.weak, 1);
    assert_eq!(app.user_count().await, users_before + 2);

    // Re-run: only unchanged (and the same rejections).
    let again = app.import(&lines[..2], false, false).await;
    assert_eq!(again.counts.unchanged, 2, "{again:?}");
    assert_eq!(again.counts.created + again.counts.conflict, 0);

    // Different data: conflict, not overwritten; with update: updated.
    let changed = vec![
        serde_json::json!({"email": "b@example.com", "email_verified": true,
            "claims": {"name": "Bee"}})
        .to_string(),
    ];
    let conflict = app.import(&changed, false, false).await;
    assert_eq!(conflict.records[0].outcome, Outcome::Conflict);
    let b = app
        .storage
        .users()
        .get_by_email(app.tenant.id, "b@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.claims.name, None, "conflict never overwrites");
    let dry_update = app.import(&changed, true, true).await;
    assert_eq!(dry_update.records[0].outcome, Outcome::Updated);
    let updated = app.import(&changed, false, true).await;
    assert_eq!(updated.records[0].outcome, Outcome::Updated);
    assert_eq!(updated.records[0].user_id, Some(b.id.0));
    let b = app
        .storage
        .users()
        .get(app.tenant.id, b.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b.claims.name.as_deref(), Some("Bee"));
    assert_eq!(
        app.import(&changed, false, true).await.records[0].outcome,
        Outcome::Unchanged
    );

    // Audit: one users_imported per call, counts and flags, user_created per written user.
    let imported = app
        .storage
        .audit()
        .query(
            app.tenant.id,
            &AuditQuery {
                action: Some(AuditAction::UsersImported),
                limit: 50,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(imported.items.len(), 7);
    let first = imported.items.last().unwrap();
    let d = first.details.as_map();
    assert_eq!(d["dry_run"], true);
    assert_eq!(d["created"], 2);
    assert_eq!(d["rejected"], 4);
    assert_eq!(d["source"], "test-source");
    let created = app
        .storage
        .audit()
        .query(
            app.tenant.id,
            &AuditQuery {
                action: Some(AuditAction::UserCreated),
                limit: 50,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(created.items.len(), 2);
}

#[tokio::test]
async fn import_preserves_ids_and_detects_id_conflicts() {
    let app = ImportApp::new().await;
    let id = Uuid::now_v7();
    let with_id = |email: &str, id: &str| serde_json::json!({"email": email, "id": id}).to_string();
    let report = app
        .import(
            &[with_id("keep@example.com", &id.to_string())],
            false,
            false,
        )
        .await;
    assert_eq!(report.records[0].outcome, Outcome::Created);
    assert_eq!(report.records[0].user_id, Some(id));
    let user = app
        .storage
        .users()
        .get_by_email(app.tenant.id, "keep@example.com")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.id.0, id, "the source id becomes the user id (sub)");
    // Rerun with the same id: unchanged.
    let again = app
        .import(
            &[with_id("keep@example.com", &id.to_string())],
            false,
            false,
        )
        .await;
    assert_eq!(again.records[0].outcome, Outcome::Unchanged);
    // The id used by another user.
    let clash = app
        .import(
            &[with_id("other@example.com", &id.to_string())],
            false,
            false,
        )
        .await;
    assert_eq!(clash.records[0].reason, Some(RejectReason::IdConflict));
    // The same email with another id.
    let other_id = app
        .import(
            &[with_id("keep@example.com", &Uuid::now_v7().to_string())],
            false,
            true,
        )
        .await;
    assert_eq!(other_id.records[0].reason, Some(RejectReason::IdConflict));
    // A non-UUID source id.
    let legacy = app
        .import(&[with_id("legacy@example.com", "user-42")], false, false)
        .await;
    assert_eq!(legacy.records[0].reason, Some(RejectReason::InvalidRecord));
}

#[tokio::test]
async fn import_batch_cap_enforced() {
    let app = ImportApp::new().await;
    let lines: Vec<String> = (0..=IMPORT_BATCH_MAX)
        .map(|i| record(&format!("u{i}@example.com"), None))
        .collect();
    let before = app.user_count().await;
    let err = app.try_import(&lines, false, false).await.unwrap_err();
    assert!(
        matches!(
            err,
            CoreError::Validation {
                field: "records",
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(app.user_count().await, before, "nothing imported");
}

#[tokio::test]
async fn profile_signer_key_sealed_and_never_returned() {
    let app = ImportApp::new().await;
    let id = app.firebase_profile().await;
    let key = b64std_decode(FB_SIGNER_KEY).unwrap();
    let stored = app
        .storage
        .password_profiles()
        .get(app.tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(stored.signer_key_sealed, key);
    assert!(
        !stored
            .signer_key_sealed
            .windows(16)
            .any(|w| w == &key[..16])
    );
    let summary = app.profiles().get(app.tenant.id, id).await.unwrap();
    assert!(!format!("{summary:?}").contains(&format!("{:?}", &key[..8])));
    let material = app
        .profiles()
        .material_for(app.tenant.id, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(material.signer_key(), key.as_slice());
    assert!(
        app.profiles()
            .material_for(app.tenant.id, Uuid::now_v7())
            .await
            .unwrap()
            .is_none()
    );
    // Duplicate name: conflict.
    let dup = app
        .profiles()
        .create(
            app.tenant.id,
            NewHashProfile {
                name: "firebase".into(),
                kind: ProfileKind::FirebaseScrypt,
                signer_key: SecretBox::from(vec![1u8; 8].into_boxed_slice()),
                salt_separator: vec![],
                rounds: 8,
                mem_cost: 14,
            },
            AuditActor::system(),
            &RequestContext::system(),
        )
        .await
        .unwrap_err();
    assert!(matches!(dup, CoreError::Conflict(_)));
    // Unreferenced: deletable, audited.
    app.profiles()
        .delete(
            app.tenant.id,
            id,
            AuditActor::system(),
            &RequestContext::system(),
        )
        .await
        .unwrap();
    for action in [
        AuditAction::PasswordProfileCreated,
        AuditAction::PasswordProfileDeleted,
    ] {
        let events = app
            .storage
            .audit()
            .query(
                app.tenant.id,
                &AuditQuery {
                    action: Some(action),
                    limit: 10,
                    ..AuditQuery::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(events.items.len(), 1, "{action:?}");
        assert!(
            !serde_json::to_string(events.items[0].details.as_map())
                .unwrap()
                .contains(&FB_SIGNER_KEY[..16])
        );
    }
}

#[tokio::test]
async fn profile_delete_refused_while_referenced() {
    let app = ImportApp::new().await;
    let profile = app.firebase_profile().await;
    let fb = scheme_users(profile)
        .into_iter()
        .find(|(e, _, _)| e.starts_with("firebase"))
        .unwrap();
    app.import(&[record(fb.0, Some(&fb.2))], false, false).await;
    let err = app
        .profiles()
        .delete(
            app.tenant.id,
            profile,
            AuditActor::system(),
            &RequestContext::system(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, CoreError::Conflict(_)), "{err:?}");
    assert!(app.profiles().get(app.tenant.id, profile).await.is_ok());
}

// --- no-leak scan ------------------------------------------------------------------------------

/// A minimal tracing subscriber that appends every event and span field to a buffer.
struct Capture(Arc<Mutex<String>>);

struct Fields<'a>(&'a Mutex<String>);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let mut s = self.0.lock().unwrap();
        s.push_str(&format!("{}={value:?} ", field.name()));
    }
}

impl tracing::Subscriber for Capture {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        attrs.record(&mut Fields(&self.0));
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        values.record(&mut Fields(&self.0));
    }
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        event.record(&mut Fields(&self.0));
        self.0.lock().unwrap().push('\n');
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::test]
async fn import_never_leaks_hash() {
    let logs = Arc::new(Mutex::new(String::new()));
    // Global, so logs from blocking hasher threads are captured too (no other test here installs
    // a subscriber).
    tracing::subscriber::set_global_default(Capture(Arc::clone(&logs)))
        .expect("install the capturing subscriber");
    tracing::info!(probe = "capture-probe", "the subscriber captures");

    let app = ImportApp::new().await;
    let profile = app.firebase_profile().await;
    let users = scheme_users(profile);
    let mut lines: Vec<String> = users.iter().map(|(e, _, p)| record(e, Some(p))).collect();
    // Rejected records carry hash material too.
    lines.push(record(
        "x2@example.com",
        Some(&serde_json::json!({"scheme": "bcrypt",
            "hash": "$2x$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"})),
    ));
    lines.push(record(
        "over@example.com",
        Some(
            &serde_json::json!({"scheme": "scrypt", "log_n": 24, "r": 8, "p": 1,
            "salt": {"hex": SHA2_SALT_HEX}, "hash": {"hex": SCRYPT_HASH_HEX}}),
        ),
    ));
    let dry = app.import(&lines, true, false).await;
    let report = app.import(&lines, false, false).await;
    let updated = app.import(&lines, false, true).await;
    // Wrong and right passwords exercise the verifiers' logging.
    for (email, password, _) in &users {
        ui_login(&app, email, "definitely-not-it-42").await;
        ui_login(&app, email, password).await;
    }

    let mut haystacks = vec![
        serde_json::to_string(&dry).unwrap(),
        serde_json::to_string(&report).unwrap(),
        serde_json::to_string(&updated).unwrap(),
        format!("{report:?}"),
    ];
    let events = app
        .storage
        .audit()
        .query(
            app.tenant.id,
            &AuditQuery {
                limit: 500,
                ..AuditQuery::default()
            },
        )
        .await
        .unwrap();
    assert!(events.items.len() > users.len());
    for e in &events.items {
        haystacks.push(serde_json::to_string(e.details.as_map()).unwrap());
        haystacks.push(format!("{e:?}"));
    }
    // Errors: a refused batch.
    let too_many: Vec<String> = (0..=IMPORT_BATCH_MAX).map(|_| lines[0].clone()).collect();
    let err = app.try_import(&too_many, false, false).await.unwrap_err();
    haystacks.push(format!("{err} {err:?}"));
    let captured = logs.lock().unwrap().clone();
    assert!(captured.contains("capture-probe"), "capture works");
    haystacks.push(captured);

    for needle in secret_needles() {
        for h in &haystacks {
            assert!(!h.contains(&needle), "found {needle:?} in output");
        }
    }
}
