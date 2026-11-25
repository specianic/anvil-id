//! FlowRepo contract.

use anvil_core::model::{Flow, FlowId, NewFlow, TenantId};
use time::Duration;

use super::TestStorage;
use super::fixtures::*;

fn expected_flow(tenant: TenantId, n: &NewFlow) -> Flow {
    Flow {
        id: n.id,
        tenant_id: tenant,
        kind: n.kind,
        state: n.state.clone(),
        csrf_hash: n.csrf_hash,
        cookie_hash: n.cookie_hash,
        auth_request_id: n.auth_request_id,
        created_at: n.created_at,
        expires_at: n.expires_at,
    }
}

async fn seed_flow(s: &TestStorage, tenant: TenantId, expires_in: Duration) -> NewFlow {
    let client = seed_client(s, tenant).await;
    let req = new_auth_request(&client.client_id, Duration::minutes(10));
    s.storage
        .grants()
        .create_authorization_request(tenant, &req)
        .await
        .expect("create_authorization_request");
    let flow = new_flow(Some(req.id), expires_in);
    s.storage
        .flows()
        .create(tenant, &flow)
        .await
        .expect("create flow");
    flow
}

pub async fn flow_create_get_update_delete(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let flow = seed_flow(s, tenant, Duration::minutes(15)).await;
    let flows = s.storage.flows();
    assert_eq!(
        flows.get(tenant, flow.id, now_ms()).await.expect("get"),
        Some(expected_flow(tenant, &flow))
    );

    let state = r#"{"step":"password","attempts":1}"#;
    assert!(
        flows
            .update_state(tenant, flow.id, state, now_ms())
            .await
            .expect("update_state")
    );
    assert_eq!(
        flows
            .get(tenant, flow.id, now_ms())
            .await
            .expect("get")
            .expect("flow")
            .state,
        state
    );

    assert!(flows.delete(tenant, flow.id).await.expect("delete"));
    assert_eq!(
        flows.get(tenant, flow.id, now_ms()).await.expect("get"),
        None
    );
    assert!(!flows.delete(tenant, flow.id).await.expect("delete"));
    assert!(
        !flows
            .update_state(tenant, FlowId::new_v7(), state, now_ms())
            .await
            .expect("update_state"),
        "updating a missing flow must return false"
    );

    // A flow without an authorization request.
    let bare = new_flow(None, Duration::minutes(15));
    flows.create(tenant, &bare).await.expect("create");
    assert_eq!(
        flows.get(tenant, bare.id, now_ms()).await.expect("get"),
        Some(expected_flow(tenant, &bare))
    );
}

pub async fn flow_expired_not_returned(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let flows = s.storage.flows();
    let expired = new_flow(None, Duration::seconds(-1));
    flows.create(tenant, &expired).await.expect("create");
    assert_eq!(
        flows.get(tenant, expired.id, now_ms()).await.expect("get"),
        None
    );
    assert!(
        !flows
            .update_state(tenant, expired.id, "{}", now_ms())
            .await
            .expect("update_state"),
        "an expired flow must not be updated"
    );
    let live = new_flow(None, Duration::minutes(5));
    flows.create(tenant, &live).await.expect("create");
    assert_eq!(
        flows
            .get(tenant, live.id, live.expires_at)
            .await
            .expect("get"),
        None,
        "a flow must not be returned at exactly expires_at"
    );
}

pub async fn flow_isolated_by_tenant(s: &TestStorage) {
    let tenant = seed_tenant(s).await;
    let other = seed_tenant(s).await;
    let flow = seed_flow(s, tenant, Duration::minutes(15)).await;
    let flows = s.storage.flows();
    assert_eq!(
        flows.get(other, flow.id, now_ms()).await.expect("get"),
        None
    );
    assert!(
        !flows
            .update_state(other, flow.id, "{}", now_ms())
            .await
            .expect("update_state")
    );
    assert!(!flows.delete(other, flow.id).await.expect("delete"));
    assert!(
        flows
            .get(tenant, flow.id, now_ms())
            .await
            .expect("get")
            .is_some()
    );
}
