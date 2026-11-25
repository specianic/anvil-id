# Phase 4 deferred items

- (found by 04-02, 2026-11-25) `GET /api/admin/v1/tenants/{t}/email-templates` returns 500 at 04-01 commit 755d7c0 and later: admin_api_v02 `email_templates_default_override_validation_and_reset`, security_admin_v02 `every_new_route_requires_its_scope` / `every_new_route_accepts_its_resource_scope_and_admin_write`. Not caused by 04-02 (it fails before 04-02's Task 2/3 too); likely 04-01's in-progress anvil-mail render/check change.
