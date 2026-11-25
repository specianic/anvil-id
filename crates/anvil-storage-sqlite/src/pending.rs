//! TRANSITIONAL — deleted by plan 02-05. Never returns success.
//!
//! The 0.1 storage ports (plan 02-02) replaced the Phase 1 traits. Until plan 02-05 rewrites
//! this backend against them, every repository method returns
//! [`StorageError::Unsupported`]. `connect` and `migrate` keep working.

use std::time::Duration;

use anvil_core::model::*;
use anvil_core::ports::*;
use time::OffsetDateTime;

/// Placeholder repository: every method fails with `StorageError::Unsupported`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Pending;

fn pending(what: &'static str) -> StorageError {
    StorageError::Unsupported(what)
}

#[async_trait::async_trait]
impl TenantRepo for Pending {
    async fn create(&self, _tenant: &NewTenant) -> Result<Tenant, StorageError> {
        Err(pending("sqlite: TenantRepo::create lands in plan 02-05"))
    }

    async fn get(&self, _id: TenantId) -> Result<Option<Tenant>, StorageError> {
        Err(pending("sqlite: TenantRepo::get lands in plan 02-05"))
    }

    async fn get_by_slug(&self, _slug: &str) -> Result<Option<Tenant>, StorageError> {
        Err(pending(
            "sqlite: TenantRepo::get_by_slug lands in plan 02-05",
        ))
    }

    async fn get_by_host(&self, _host: &str) -> Result<Option<Tenant>, StorageError> {
        Err(pending(
            "sqlite: TenantRepo::get_by_host lands in plan 02-05",
        ))
    }

    async fn list(&self, _page: PageRequest) -> Result<Page<Tenant>, StorageError> {
        Err(pending("sqlite: TenantRepo::list lands in plan 02-05"))
    }

    async fn update(
        &self,
        _id: TenantId,
        _update: &TenantUpdate,
    ) -> Result<Option<Tenant>, StorageError> {
        Err(pending("sqlite: TenantRepo::update lands in plan 02-05"))
    }

    async fn delete(&self, _id: TenantId) -> Result<bool, StorageError> {
        Err(pending("sqlite: TenantRepo::delete lands in plan 02-05"))
    }
}

#[async_trait::async_trait]
impl UserRepo for Pending {
    async fn create(
        &self,
        _tenant: TenantId,
        _user: &NewUser,
        _password: Option<&NewPasswordCredential>,
        _token: Option<&NewSelfServiceToken>,
        _email: Option<&NewEmail>,
    ) -> Result<User, StorageError> {
        Err(pending("sqlite: UserRepo::create lands in plan 02-05"))
    }

    async fn get(&self, _tenant: TenantId, _id: UserId) -> Result<Option<User>, StorageError> {
        Err(pending("sqlite: UserRepo::get lands in plan 02-05"))
    }

    async fn get_by_email(
        &self,
        _tenant: TenantId,
        _email: &str,
    ) -> Result<Option<User>, StorageError> {
        Err(pending(
            "sqlite: UserRepo::get_by_email lands in plan 02-05",
        ))
    }

    async fn list(
        &self,
        _tenant: TenantId,
        _page: PageRequest,
    ) -> Result<Page<User>, StorageError> {
        Err(pending("sqlite: UserRepo::list lands in plan 02-05"))
    }

    async fn update(
        &self,
        _tenant: TenantId,
        _id: UserId,
        _update: &UserUpdate,
        _now: OffsetDateTime,
    ) -> Result<Option<User>, StorageError> {
        Err(pending("sqlite: UserRepo::update lands in plan 02-05"))
    }

    async fn delete(&self, _tenant: TenantId, _id: UserId) -> Result<bool, StorageError> {
        Err(pending("sqlite: UserRepo::delete lands in plan 02-05"))
    }

    async fn password(
        &self,
        _tenant: TenantId,
        _user: UserId,
    ) -> Result<Option<PasswordCredential>, StorageError> {
        Err(pending("sqlite: UserRepo::password lands in plan 02-05"))
    }

    async fn set_password(
        &self,
        _tenant: TenantId,
        _user: UserId,
        _phc: &str,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(pending(
            "sqlite: UserRepo::set_password lands in plan 02-05",
        ))
    }

    async fn record_login(
        &self,
        _tenant: TenantId,
        _user: UserId,
        _now: OffsetDateTime,
    ) -> Result<(), StorageError> {
        Err(pending(
            "sqlite: UserRepo::record_login lands in plan 02-05",
        ))
    }

    async fn issue_self_service_token(
        &self,
        _tenant: TenantId,
        _token: &NewSelfServiceToken,
        _email: Option<&NewEmail>,
    ) -> Result<(), StorageError> {
        Err(pending(
            "sqlite: UserRepo::issue_self_service_token lands in plan 02-05",
        ))
    }

    async fn complete_verification(
        &self,
        _tenant: TenantId,
        _token_hash: &SecretHash,
        _now: OffsetDateTime,
    ) -> Result<Option<User>, StorageError> {
        Err(pending(
            "sqlite: UserRepo::complete_verification lands in plan 02-05",
        ))
    }

    async fn complete_recovery(
        &self,
        _tenant: TenantId,
        _token_hash: &SecretHash,
        _new_phc: &str,
        _now: OffsetDateTime,
        _notice: Option<&NewEmail>,
    ) -> Result<Option<User>, StorageError> {
        Err(pending(
            "sqlite: UserRepo::complete_recovery lands in plan 02-05",
        ))
    }
}

#[async_trait::async_trait]
impl ClientRepo for Pending {
    async fn create(&self, _tenant: TenantId, _client: &NewClient) -> Result<Client, StorageError> {
        Err(pending("sqlite: ClientRepo::create lands in plan 02-05"))
    }

    async fn get(
        &self,
        _tenant: TenantId,
        _client_id: &str,
    ) -> Result<Option<Client>, StorageError> {
        Err(pending("sqlite: ClientRepo::get lands in plan 02-05"))
    }

    async fn list(
        &self,
        _tenant: TenantId,
        _page: PageRequest,
    ) -> Result<Page<Client>, StorageError> {
        Err(pending("sqlite: ClientRepo::list lands in plan 02-05"))
    }

    async fn update(
        &self,
        _tenant: TenantId,
        _client_id: &str,
        _update: &ClientUpdate,
        _now: OffsetDateTime,
    ) -> Result<Option<Client>, StorageError> {
        Err(pending("sqlite: ClientRepo::update lands in plan 02-05"))
    }

    async fn set_secret_hash(
        &self,
        _tenant: TenantId,
        _client_id: &str,
        _secret_hash: Option<SecretHash>,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(pending(
            "sqlite: ClientRepo::set_secret_hash lands in plan 02-05",
        ))
    }

    async fn delete(&self, _tenant: TenantId, _client_id: &str) -> Result<bool, StorageError> {
        Err(pending("sqlite: ClientRepo::delete lands in plan 02-05"))
    }
}

#[async_trait::async_trait]
impl KeyRepo for Pending {
    async fn insert(&self, _tenant: TenantId, _key: &NewSigningKey) -> Result<(), StorageError> {
        Err(pending("sqlite: KeyRepo::insert lands in plan 02-05"))
    }

    async fn active(
        &self,
        _tenant: TenantId,
        _alg: &str,
    ) -> Result<Option<SigningKey>, StorageError> {
        Err(pending("sqlite: KeyRepo::active lands in plan 02-05"))
    }

    async fn published(
        &self,
        _tenant: TenantId,
        _now: OffsetDateTime,
    ) -> Result<Vec<SigningKey>, StorageError> {
        Err(pending("sqlite: KeyRepo::published lands in plan 02-05"))
    }
}

#[async_trait::async_trait]
impl SessionRepo for Pending {
    async fn create(
        &self,
        _tenant: TenantId,
        _session: &NewBrowserSession,
    ) -> Result<(), StorageError> {
        Err(pending("sqlite: SessionRepo::create lands in plan 02-05"))
    }

    async fn get_active(
        &self,
        _tenant: TenantId,
        _token_hash: &SecretHash,
        _now: OffsetDateTime,
    ) -> Result<Option<BrowserSession>, StorageError> {
        Err(pending(
            "sqlite: SessionRepo::get_active lands in plan 02-05",
        ))
    }

    async fn touch(
        &self,
        _tenant: TenantId,
        _id: SessionId,
        _now: OffsetDateTime,
        _idle_expires_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(pending("sqlite: SessionRepo::touch lands in plan 02-05"))
    }

    async fn revoke(
        &self,
        _tenant: TenantId,
        _id: SessionId,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(pending("sqlite: SessionRepo::revoke lands in plan 02-05"))
    }
}

#[async_trait::async_trait]
impl FlowRepo for Pending {
    async fn create(&self, _tenant: TenantId, _flow: &NewFlow) -> Result<(), StorageError> {
        Err(pending("sqlite: FlowRepo::create lands in plan 02-05"))
    }

    async fn get(
        &self,
        _tenant: TenantId,
        _id: FlowId,
        _now: OffsetDateTime,
    ) -> Result<Option<Flow>, StorageError> {
        Err(pending("sqlite: FlowRepo::get lands in plan 02-05"))
    }

    async fn update_state(
        &self,
        _tenant: TenantId,
        _id: FlowId,
        _state: &str,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(pending(
            "sqlite: FlowRepo::update_state lands in plan 02-05",
        ))
    }

    async fn delete(&self, _tenant: TenantId, _id: FlowId) -> Result<bool, StorageError> {
        Err(pending("sqlite: FlowRepo::delete lands in plan 02-05"))
    }
}

#[async_trait::async_trait]
impl GrantRepo for Pending {
    async fn create_authorization_request(
        &self,
        _tenant: TenantId,
        _request: &NewAuthorizationRequest,
    ) -> Result<(), StorageError> {
        Err(pending(
            "sqlite: GrantRepo::create_authorization_request lands in plan 02-05",
        ))
    }

    async fn get_authorization_request(
        &self,
        _tenant: TenantId,
        _id: AuthRequestId,
        _now: OffsetDateTime,
    ) -> Result<Option<AuthorizationRequest>, StorageError> {
        Err(pending(
            "sqlite: GrantRepo::get_authorization_request lands in plan 02-05",
        ))
    }

    async fn delete_authorization_request(
        &self,
        _tenant: TenantId,
        _id: AuthRequestId,
    ) -> Result<bool, StorageError> {
        Err(pending(
            "sqlite: GrantRepo::delete_authorization_request lands in plan 02-05",
        ))
    }

    async fn create_code(
        &self,
        _tenant: TenantId,
        _code: &NewAuthorizationCode,
        _family: &NewTokenFamily,
    ) -> Result<(), StorageError> {
        Err(pending(
            "sqlite: GrantRepo::create_code lands in plan 02-05",
        ))
    }

    async fn consume_code(
        &self,
        _tenant: TenantId,
        _code_hash: &CodeHash,
        _now: OffsetDateTime,
    ) -> Result<ConsumeOutcome, StorageError> {
        Err(pending(
            "sqlite: GrantRepo::consume_code lands in plan 02-05",
        ))
    }

    async fn get_family(
        &self,
        _tenant: TenantId,
        _id: TokenFamilyId,
    ) -> Result<Option<TokenFamily>, StorageError> {
        Err(pending("sqlite: GrantRepo::get_family lands in plan 02-05"))
    }

    async fn revoke_family(
        &self,
        _tenant: TenantId,
        _id: TokenFamilyId,
        _reason: RevokeReason,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(pending(
            "sqlite: GrantRepo::revoke_family lands in plan 02-05",
        ))
    }

    async fn create_refresh_token(
        &self,
        _tenant: TenantId,
        _token: &NewRefreshToken,
    ) -> Result<(), StorageError> {
        Err(pending(
            "sqlite: GrantRepo::create_refresh_token lands in plan 02-05",
        ))
    }

    async fn find_refresh_token(
        &self,
        _tenant: TenantId,
        _token_hash: &SecretHash,
    ) -> Result<Option<(RefreshToken, TokenFamily)>, StorageError> {
        Err(pending(
            "sqlite: GrantRepo::find_refresh_token lands in plan 02-05",
        ))
    }

    async fn rotate_refresh(
        &self,
        _tenant: TenantId,
        _presented: &SecretHash,
        _child: &NewRefreshToken,
        _now: OffsetDateTime,
    ) -> Result<RotateOutcome, StorageError> {
        Err(pending(
            "sqlite: GrantRepo::rotate_refresh lands in plan 02-05",
        ))
    }

    async fn record_jti(
        &self,
        _tenant: TenantId,
        _kind: ReplayKind,
        _hash: &SecretHash,
        _expires_at: OffsetDateTime,
        _now: OffsetDateTime,
    ) -> Result<JtiOutcome, StorageError> {
        Err(pending("sqlite: GrantRepo::record_jti lands in plan 02-05"))
    }
}

#[async_trait::async_trait]
impl SetupRepo for Pending {
    async fn is_installed(&self) -> Result<bool, StorageError> {
        Err(pending(
            "sqlite: SetupRepo::is_installed lands in plan 02-05",
        ))
    }

    async fn install(&self, _plan: &InstallPlan) -> Result<InstallOutcome, StorageError> {
        Err(pending("sqlite: SetupRepo::install lands in plan 02-05"))
    }

    async fn create_setup_token(&self, _token: &NewSetupToken) -> Result<(), StorageError> {
        Err(pending(
            "sqlite: SetupRepo::create_setup_token lands in plan 02-05",
        ))
    }

    async fn peek_setup_token(
        &self,
        _hash: &SecretHash,
        _now: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(pending(
            "sqlite: SetupRepo::peek_setup_token lands in plan 02-05",
        ))
    }

    async fn complete_setup(
        &self,
        _hash: &SecretHash,
        _now: OffsetDateTime,
        _admin_tenant: TenantId,
        _admin: &NewUser,
        _password: &NewPasswordCredential,
        _client_tenant: TenantId,
        _client: &NewClient,
    ) -> Result<SetupOutcome, StorageError> {
        Err(pending(
            "sqlite: SetupRepo::complete_setup lands in plan 02-05",
        ))
    }
}

#[async_trait::async_trait]
impl OutboxRepo for Pending {
    async fn enqueue(&self, _tenant: TenantId, _email: &NewEmail) -> Result<(), StorageError> {
        Err(pending("sqlite: OutboxRepo::enqueue lands in plan 02-05"))
    }

    async fn claim_due(
        &self,
        _now: OffsetDateTime,
        _limit: u32,
        _lease: Duration,
    ) -> Result<Vec<OutboxEmail>, StorageError> {
        Err(pending("sqlite: OutboxRepo::claim_due lands in plan 02-05"))
    }

    async fn mark_sent(&self, _id: OutboxId, _now: OffsetDateTime) -> Result<bool, StorageError> {
        Err(pending("sqlite: OutboxRepo::mark_sent lands in plan 02-05"))
    }

    async fn mark_failed(
        &self,
        _id: OutboxId,
        _error: &str,
        _next_attempt_at: OffsetDateTime,
    ) -> Result<bool, StorageError> {
        Err(pending(
            "sqlite: OutboxRepo::mark_failed lands in plan 02-05",
        ))
    }
}
