## AnvilID page catalog: English (en), friendly error pages (plan 07.1-08).
##
## A heading and an explanation per error key go around the stable contract sentences of
## main.ftl (error-*), which stay unchanged. The way forward links ("Back to <app>", start page)
## and the label next to the danger icon live here too.

errors_friendly-heading-redirect_uri_mismatch = This app's sign-in link is set up wrongly
errors_friendly-heading-unknown_client = This app is not known here
errors_friendly-heading-invalid_request = This sign-in request can't be used
errors_friendly-heading-flow_expired = This sign-in link has expired
errors_friendly-heading-csrf = This form has expired
errors_friendly-heading-not_found = This page doesn't exist
errors_friendly-heading-too_many_requests = Too many requests
errors_friendly-heading-saml_login_failed = Your organization's sign-in did not work
errors_friendly-heading-generic = Something went wrong
errors_friendly-explain-redirect_uri_mismatch = The app sent you here with an address it has not registered, so you can't sign in from this link. Go back to the app and try again, or tell its operator.
errors_friendly-explain-unknown_client = The link you followed names an app that is not registered with this sign-in service. Go back to the app and try again.
errors_friendly-explain-invalid_request = The link you followed is incomplete or was changed on the way. Start again from the app or the sign-in page.
errors_friendly-explain-flow_expired = Sign-in links only work for a few minutes. Nothing was changed; just start again.
errors_friendly-explain-csrf = The page was open for too long or was opened in another tab. Nothing was saved; start again.
errors_friendly-explain-not_found = The address may be mistyped, or the page has moved.
errors_friendly-explain-too_many_requests = To protect your account, we paused further attempts for a short while.
errors_friendly-explain-saml_login_failed = Signing in with your organization's identity provider did not work. Go back to the application and start the sign-in again.
errors_friendly-explain-generic = Please try again in a moment. If it keeps happening, contact the operator of this service.
errors_friendly-danger_label = Error
errors_friendly-detail_label = Technical detail (development mode):
errors_friendly-back_to_app = Back to { $app }
errors_friendly-go_home = Go to the start page

## Tenant root page and setup guidance (`/`, `/ui`, `/console/` before setup, setup pages)

errors_friendly-root_title = Welcome
errors_friendly-root_heading = Welcome
errors_friendly-root_signed_out = Sign in to use the apps of this service and manage your account.
errors_friendly-root_signed_in = You are signed in.
errors_friendly-root_sign_in = Sign in
errors_friendly-root_administration = Administration
errors_friendly-setup_pending_title = Setup is not complete
errors_friendly-setup_pending_lead = This AnvilID installation has no administrator yet.
errors_friendly-setup_pending_how = Open the setup link the server printed when it first started, or create a new one by running this command where the server runs:
errors_friendly-setup_pending_after = The setup link creates the first administrator. Afterwards, the admin console is available here.
errors_friendly-setup_used_title = Setup is already complete
errors_friendly-setup_used = The first administrator has already been created, so this setup link can no longer be used. Sign in to the admin console instead.
errors_friendly-setup_done_next = Next, sign in to the admin console with the administrator account to create your first app.
errors_friendly-setup_done_automation = For automation
errors_friendly-setup_done_automation_lead = Scripts and CI pipelines can call the admin API with these management credentials.
