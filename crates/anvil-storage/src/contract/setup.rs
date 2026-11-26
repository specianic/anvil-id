//! SetupRepo contract.

use std::sync::Arc;

use anvil_core::model::{
    DEFAULT_TENANT_SLUG, InstallPlan, KeyState, PageRequest, SYSTEM_TENANT_SLUG, TenantId,
};
use anvil_core::ports::{InstallOutcome, SetupOutcome};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

/// An install plan with the system and default tenants, one active key each and a setup token.
pub fn new_install_plan() -> InstallPlan {
    let mut system = new_tenant();
    system.slug = SYSTEM_TENANT_SLUG.to_owned();
    system.host = None;
    let mut default = new_tenant();
    default.slug = DEFAULT_TENANT_SLUG.to_owned();
    default.host = None;
    InstallPlan {
        keys: vec![
            (system.id, new_signing_key("RS256", KeyState::Active, None)),
            (default.id, new_signing_key("RS256", KeyState::Active, None)),
        ],
        tenants: vec![system, default],
        setup_token: new_setup_token(Duration::hours(1)),
    }
}

/// Installs and returns (system tenant, default tenant, plan).
pub async fn seed_install(s: &TestStorage) -> (TenantId, TenantId, InstallPlan) {
    let plan = new_install_plan();
    assert_eq!(
        s.storage.setup().install(&plan).await.expect("install"),
        InstallOutcome::Installed
    );
    (plan.tenants[0].id, plan.tenants[1].id, plan)
}

pub async fn install_creates_tenants_keys_token_once(s: &TestStorage) {
    let setup = s.storage.setup();
    assert!(!setup.is_installed().await.expect("is_installed"));
    let (system, default, plan) = seed_install(s).await;
    assert!(setup.is_installed().await.expect("is_installed"));

    let tenants = s.storage.tenants();
    assert_eq!(
        tenants
            .get_by_slug(SYSTEM_TENANT_SLUG)
            .await
            .expect("get_by_slug")
            .map(|t| t.id),
        Some(system)
    );
    assert_eq!(
        tenants
            .get_by_slug(DEFAULT_TENANT_SLUG)
            .await
            .expect("get_by_slug")
            .map(|t| t.id),
        Some(default)
    );
    for (tenant, key) in &plan.keys {
        assert_eq!(
            s.storage
                .keys()
                .active(*tenant, "RS256")
                .await
                .expect("active")
                .map(|k| k.id),
            Some(key.id),
            "install must store each tenant's key"
        );
    }
    assert!(
        setup
            .peek_setup_token(&plan.setup_token.token_hash, now_ms())
            .await
            .expect("peek")
    );

    let second = new_install_plan();
    assert_eq!(
        setup.install(&second).await.expect("install"),
        InstallOutcome::AlreadyInstalled,
        "a second install must not write anything"
    );
    let all = tenants
        .list(PageRequest {
            after: None,
            limit: 10,
        })
        .await
        .expect("list");
    assert_eq!(all.items.len(), 2, "no tenants may be duplicated");
    assert!(
        !setup
            .peek_setup_token(&second.setup_token.token_hash, now_ms())
            .await
            .expect("peek"),
        "the second plan's token must not be stored"
    );
}

pub async fn peek_setup_token(s: &TestStorage) {
    let setup = s.storage.setup();
    let token = new_setup_token(Duration::hours(1));
    setup
        .create_setup_token(&token)
        .await
        .expect("create_setup_token");
    assert!(
        setup
            .peek_setup_token(&token.token_hash, now_ms())
            .await
            .expect("peek")
    );
    assert!(
        setup
            .peek_setup_token(&token.token_hash, now_ms())
            .await
            .expect("peek"),
        "peek must not consume the token"
    );
    assert!(
        !setup
            .peek_setup_token(&unique_hash(), now_ms())
            .await
            .expect("peek")
    );
    assert!(
        !setup
            .peek_setup_token(&token.token_hash, token.expires_at)
            .await
            .expect("peek"),
        "a token must not be valid at exactly expires_at"
    );
}

pub async fn complete_setup_once(s: &TestStorage) {
    let (system, default, plan) = seed_install(s).await;
    let setup = s.storage.setup();
    let admin = new_user();
    let password = new_password();
    let client = new_client();
    let hash = plan.setup_token.token_hash;

    match setup
        .complete_setup(&hash, now_ms(), system, &admin, &password, default, &client)
        .await
        .expect("complete_setup")
    {
        SetupOutcome::Completed { user, client: c } => {
            assert_eq!(user, expected_user(system, &admin));
            assert_eq!(c, expected_client(default, &client));
        }
        SetupOutcome::InvalidToken => panic!("a valid setup token must complete"),
    }
    assert!(
        s.storage
            .users()
            .get(system, admin.id)
            .await
            .expect("get")
            .is_some()
    );
    assert_eq!(
        s.storage
            .users()
            .password(system, admin.id)
            .await
            .expect("password")
            .map(|p| p.phc),
        Some(password.phc.clone())
    );
    assert!(
        s.storage
            .clients()
            .get(default, &client.client_id)
            .await
            .expect("get")
            .is_some()
    );
    assert!(!setup.peek_setup_token(&hash, now_ms()).await.expect("peek"));
    assert_eq!(
        setup
            .complete_setup(
                &hash,
                now_ms(),
                system,
                &new_user(),
                &password,
                default,
                &new_client()
            )
            .await
            .expect("complete_setup"),
        SetupOutcome::InvalidToken,
        "a setup token is single-use"
    );

    // Concurrent completions of a fresh token: exactly one wins.
    const N: usize = 8;
    let token = new_setup_token(Duration::hours(1));
    setup
        .create_setup_token(&token)
        .await
        .expect("create_setup_token");
    let barrier = Arc::new(tokio::sync::Barrier::new(N));
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..N {
        let storage = Arc::clone(&s.storage);
        let barrier = Arc::clone(&barrier);
        let (user, pw, cl) = (new_user(), new_password(), new_client());
        let hash = token.token_hash;
        set.spawn(async move {
            barrier.wait().await;
            storage
                .setup()
                .complete_setup(&hash, now_ms(), system, &user, &pw, default, &cl)
                .await
        });
    }
    let (mut won, mut lost) = (0usize, 0usize);
    while let Some(joined) = set.join_next().await {
        match joined.expect("setup task panicked") {
            Ok(SetupOutcome::Completed { .. }) => won += 1,
            Ok(SetupOutcome::InvalidToken) => lost += 1,
            Err(e) => panic!("no storage errors allowed, got {e:?}"),
        }
    }
    assert_eq!(
        (won, lost),
        (1, N - 1),
        "exactly one concurrent setup must win"
    );
}

pub async fn complete_setup_expired_invalid(s: &TestStorage) {
    let (system, default, _) = seed_install(s).await;
    let setup = s.storage.setup();
    let token = new_setup_token(Duration::seconds(-1));
    setup
        .create_setup_token(&token)
        .await
        .expect("create_setup_token");
    let admin = new_user();
    assert_eq!(
        setup
            .complete_setup(
                &token.token_hash,
                now_ms(),
                system,
                &admin,
                &new_password(),
                default,
                &new_client()
            )
            .await
            .expect("complete_setup"),
        SetupOutcome::InvalidToken
    );
    assert_eq!(
        s.storage.users().get(system, admin.id).await.expect("get"),
        None,
        "nothing may be written for an invalid token"
    );
    assert_eq!(
        setup
            .complete_setup(
                &unique_hash(),
                now_ms(),
                system,
                &admin,
                &new_password(),
                default,
                &new_client()
            )
            .await
            .expect("complete_setup"),
        SetupOutcome::InvalidToken,
        "an unknown token is invalid"
    );
}

pub async fn install_creates_system_administrator_role(s: &TestStorage) {
    use anvil_core::model::SYSTEM_ADMIN_ROLE;

    let (system, default, _plan) = seed_install(s).await;
    let role = s
        .storage
        .roles()
        .get_by_name(system, SYSTEM_ADMIN_ROLE)
        .await
        .expect("get_by_name")
        .expect("install creates the administrator role");
    assert_eq!(role.tenant_id, system);
    assert_eq!(role.org_id, None);
    assert_eq!(role.permissions, vec!["admin:write".to_owned()]);
    assert_eq!(
        s.storage
            .roles()
            .get_by_name(default, SYSTEM_ADMIN_ROLE)
            .await
            .expect("get_by_name"),
        None,
        "only the system tenant gets it"
    );
    assert_eq!(
        s.storage
            .roles()
            .holders_of_permission(system, "admin:write")
            .await
            .expect("holders"),
        0,
        "nobody holds it before setup completes"
    );
}

pub async fn complete_setup_assigns_administrator_role(s: &TestStorage) {
    use anvil_core::model::SYSTEM_ADMIN_ROLE;

    let (system, default, plan) = seed_install(s).await;
    let setup = s.storage.setup();
    let roles = s.storage.roles();

    // The first administrator (install-time setup URL).
    let first = new_user();
    let outcome = setup
        .complete_setup(
            &plan.setup_token.token_hash,
            now_ms(),
            system,
            &first,
            &new_password(),
            default,
            &new_client(),
        )
        .await
        .expect("complete_setup");
    assert!(matches!(outcome, SetupOutcome::Completed { .. }));
    let held: Vec<String> = roles
        .roles_for_user(system, first.id)
        .await
        .expect("roles")
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(held, vec![SYSTEM_ADMIN_ROLE.to_owned()]);

    // A later `admin setup-url` token creates another administrator with the role.
    let token = new_setup_token(Duration::hours(1));
    setup
        .create_setup_token(&token)
        .await
        .expect("create_setup_token");
    let second = new_user();
    let outcome = setup
        .complete_setup(
            &token.token_hash,
            now_ms(),
            system,
            &second,
            &new_password(),
            default,
            &new_client(),
        )
        .await
        .expect("complete_setup");
    assert!(matches!(outcome, SetupOutcome::Completed { .. }));
    assert_eq!(
        roles
            .roles_for_user(system, second.id)
            .await
            .expect("roles")
            .len(),
        1
    );
    assert_eq!(
        roles
            .holders_of_permission(system, "admin:write")
            .await
            .expect("holders"),
        2
    );

    // An invalid token assigns nothing to anybody.
    let nobody = new_user();
    assert_eq!(
        setup
            .complete_setup(
                &token.token_hash,
                now_ms(),
                system,
                &nobody,
                &new_password(),
                default,
                &new_client(),
            )
            .await
            .expect("complete_setup"),
        SetupOutcome::InvalidToken
    );
    assert!(
        roles
            .roles_for_user(system, nobody.id)
            .await
            .expect("roles")
            .is_empty()
    );
}
