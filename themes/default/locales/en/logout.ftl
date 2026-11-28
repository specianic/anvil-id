## AnvilID page catalog: English (en), RP-initiated logout (plan 04-13).
##
## The sentences of logout-signed_out, logout-invalid_id_token_hint,
## logout-redirect_uri_not_registered and logout-id_token_hint_required are a stable contract
## (themes/default/README.md, tests/conformance/config.template.json, tests/e2e). Do not reword them.

title-logout_confirm = Sign out
title-logged_out = Signed out
title-logout_error = Sign-out failed

logout-confirm_heading = Sign out?
logout-confirm_text = Do you want to sign out of your account?
logout-confirm_text_client = asked to sign you out of your account. Do you want to sign out?
logout-confirm_submit = Sign out
logout-cancel = Stay signed in
logout-expired = This sign-out page expired. Please try again.

logout-signed_out_heading = Signed out
logout-signed_out = You have been signed out.
logout-sign_in_again = Sign in again
logout-error_heading = Sign-out failed

logout-invalid_id_token_hint = The sign-out request is invalid: the id_token_hint could not be verified.
logout-redirect_uri_not_registered = The sign-out request is invalid: the post_logout_redirect_uri is not registered for this client.
logout-id_token_hint_required = The sign-out request is invalid: post_logout_redirect_uri requires id_token_hint or client_id.
logout-client_mismatch = The sign-out request is invalid: client_id does not match the id_token_hint.
logout-unknown_client = The sign-out request is invalid: this application is not registered.
