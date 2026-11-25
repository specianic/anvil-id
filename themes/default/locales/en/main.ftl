## AnvilID page catalog: English (en), release 0.2 pages and messages.
##
## Contribution rules
## - One file per feature: every `*.ftl` file of a locale directory is loaded (in file name
##   order), so a new feature adds `locales/{lang}/<feature>.ftl` instead of editing this file.
##   Two files of one locale must not define the same message id (startup error).
## - Message ids are the dotted keys used in code and templates with every `.` replaced by `-`
##   (`login.invalid_credentials` -> `login-invalid_credentials`). Fluent ids cannot contain `.`.
## - English is the fallback for every other locale: a message missing in `de` renders in English.
## - Leading and trailing spaces of a value are dropped by Fluent; templates keep the spaces
##   around a message, never the message itself.
## - The English sentences of `error-*` and of the form messages are a stable contract
##   (themes/default/README.md, tests/e2e, tests/conformance). Do not reword them.
## - Operators override single messages with `{theme_dir}/locales/{lang}/*.ftl`.

## Page titles

title-login = Sign in
title-second_factor = Two-step verification
title-registration = Create an account
title-verification = Confirm your email address
title-recovery = Reset your password
title-recovery_reset = Choose a new password
title-setup = Set up AnvilID
title-setup_done = Setup complete
title-error = Error
title-consent = Allow access
title-form_post = Continuing
title-account_security = Security
title-account_sessions = Sessions
title-account_apps = Connected apps
title-totp_enroll = Set up an authenticator app
title-recovery_codes = Recovery codes

## Message page headings

heading-check_email = Check your email
heading-password_changed = Password changed
heading-email_confirmed = Email address confirmed
heading-registration_unavailable = Registration unavailable
heading-signed_in = Signed in
heading-done = Done

## Shared page elements

dev-banner = Development mode: not for production use
form-optional = (optional)
form-continue = Continue
nav-account_help = Account help
nav-next_steps = Next steps
nav-other_options = Other options
punct-period = .
scope-use = Use

## Form field labels (FormField.label_key)

field-email = Email
field-admin_email = Admin email
field-password = Password
field-name = Name
field-token = Token
field-code = Authentication code
field-recovery_code = Recovery code

## Flow messages (anvil-core flow engine)

login-invalid_credentials = The email address or password is incorrect.
login-email_not_verified = Please confirm your email address before signing in.
login-second_factor_invalid = That code is not valid. Please try again.
login-passkey_failed = Signing in with a passkey did not work. Please try again or use your password.
login-recovery_code_used = You signed in with a recovery code. Each code works only once; consider generating new codes.
login-signed_in = You are signed in.
login-captcha_required = Please complete the security check, then sign in.
login-captcha_failed = The security check did not succeed. Please complete it again, then sign in.
# $seconds: whole seconds until the next attempt is allowed.
login-too_many_attempts = Too many attempts. Try again in { $seconds ->
        [one] { $seconds } second
       *[other] { $seconds } seconds
    }.
registration-disabled = Self-registration is not available.
registration-email_taken = An account with this email address already exists.
registration-check_email = Your account was created. Check your email to confirm your address, then sign in.
email-invalid = Enter a valid email address.
password-too_short = The password is too short.
password-too_long = The password is too long.
password-breached = This password has appeared in a data breach. Please choose a different one.
recovery-sent = If an account exists for that address, we have sent instructions to reset the password.
recovery-invalid_token = This password reset link is invalid or has expired. Please request a new one.
recovery-done = Your password has been changed. You can now sign in.
verification-invalid_token = This confirmation link is invalid or has expired.
verification-done = Your email address is confirmed.
flow-expired = This sign-in attempt expired. Please start again.
flow-invalid_input = This form submission could not be processed. Please try again.
service-overloaded = The service is busy. Please try again in a moment.

## Account security messages (anvil-core account service)

account-reauth_required = For your security, sign in again before changing how you sign in.
account-flow_expired = This page expired. Please try again.
account-invalid_label = Use a name of at most 64 characters.
account-passkey_failed = The passkey could not be registered. Please try again.
account-passkey_exists = This passkey is already registered.
account-totp_exists = An authenticator app is already set up.
account-totp_not_pending = Start the authenticator app setup again.
account-totp_invalid_code = That code is not valid. Check the time on your device and try again.
account-totp_required = Set up an authenticator app first.
account-credential_not_found = That sign-in method no longer exists.
account-try_again = Another change happened at the same time. Please try again.
account-passkey_registered = Passkey added.
account-passkey_removed = Passkey removed.
account-totp_removed = Authenticator app removed. Your recovery codes were deleted.
account-totp_enrolled = Authenticator app set up.
account-recovery_codes_regenerated = New recovery codes created. The old codes no longer work.

## Sessions page messages (anvil-core session service)

sessions-revoked = The session was signed out.
sessions-revoked_others = All other sessions were signed out.
sessions-not_found = That session is no longer active.

## Consent and connected apps messages

consent-expired = This page expired. Please review the request again.
apps-revoked = Access removed. The app can no longer use your account.
apps-not_found = That app no longer has access to your account.
apps-expired = This page expired. Please try again.

## Scope descriptions (consent screen, connected apps)

scope-openid = Sign you in
scope-profile = See your name and basic profile details
scope-email = See your email address
scope-phone = See your phone number
scope-address = See your postal address
scope-offline_access = Stay signed in

## Error page (stable sentences: see the contract notes above)

error-heading = Something went wrong
error-redirect_uri_mismatch = The redirect URI in this request is not registered for this client.
error-unknown_client = This application is not registered.
error-invalid_request = The sign-in request is invalid.
error-flow_expired = This sign-in attempt expired. Please start again.
error-csrf = This form submission could not be verified. Please try again.
error-not_found = Page not found.
error-too_many_requests = Too many attempts. Please wait a moment and try again.
error-generic = Something went wrong.
error-status = Error { $status }
error-start_again = Start again

## Sign-in page

login-submit = Sign in
login-webauthn-cancelled = The passkey request was cancelled or timed out. Try again, or sign in with your password.
login-webauthn-failed = Your passkey could not be used. Try again, or sign in with your password.
login-passkey_button = Sign in with a passkey
login-forgot_password = Forgot your password?
login-create_account = Create an account
captcha-noscript = This sign-in needs a security check that requires JavaScript. Enable JavaScript and reload the page to continue.

## Second factor

second_factor-code_hint = Open your authenticator app and enter the 6-digit code it shows for this account.
second_factor-use_recovery_code = Use a recovery code instead
second_factor-recovery_code_hint = Enter one of the recovery codes you saved when you set up the authenticator app. Each code works only once.
second_factor-submit = Verify
second_factor-start_over = Start over

## Registration, verification, recovery

registration-submit = Create account
registration-have_account = Already have an account? Sign in
verification-lead = Select the button below to confirm your email address.
verification-submit = Confirm email
recovery-lead = Enter the email address for your account. If it is registered, we will send you a link to reset your password.
recovery-submit = Send reset link
recovery-back_to_sign_in = Back to sign in
recovery_reset-submit = Set new password
message-go_to_sign_in = Go to sign in

## Setup

setup-lead = Create the first administrator account. You will use it to sign in to the admin console.
setup-submit = Create administrator
setup_done-lead_before = The administrator account
setup_done-lead_after = has been created.
setup_done-copy_now = Copy these credentials now.
setup_done-copy_note = The client secret is shown only once and cannot be displayed again.
setup_done-client_id = Management client ID
setup_done-client_secret = Management client secret
setup_done-token_endpoint = Token endpoint
setup_done-admin_api_base = Admin API base
setup_done-usage = Use the client ID and secret with the client credentials grant at the token endpoint to call the admin API.

## Consent screen and form_post

consent-heading = Allow access to your account?
consent-would_like_to = would like to:
consent-note = You can remove this access at any time under Connected apps in your account.
consent-allow = Allow
consent-deny = Deny
form_post-heading = Continuing…
form_post-status = Returning you to the application.

## Account pages

account_nav-label = Account
account_nav-security = Security
account_nav-sessions = Sessions
account_nav-apps = Connected apps

security-reauth_before = To change how you sign in,
security-reauth_link = sign in again
security-reauth_after = first.
security-passkeys = Passkeys
security-col_name = Name
security-col_added = Added
security-col_last_used = Last used
security-col_action = Action
security-never = Never
security-never_lower = never
security-remove = Remove
# $label: the passkey name chosen by the user.
security-remove_passkey = Remove passkey { $label }
security-no_passkeys = You have no passkeys yet.
security-webauthn-cancelled = Adding the passkey was cancelled.
security-webauthn-failed = The passkey could not be added. Please try again.
security-passkey_name = Passkey name
security-add_passkey = Add a passkey
security-passkey_nojs = Adding a passkey needs JavaScript and a browser that supports passkeys.
security-totp_heading = Authenticator app
security-totp_set_up_on = Set up on
security-totp_last_used = . Last used:
security-recovery_codes_left = Recovery codes left:
security-new_recovery_codes = Create new recovery codes
security-remove_totp = Remove authenticator app
security-totp_not_set_up = Not set up. Use an authenticator app for a one-time code at sign-in.
security-set_up_totp = Set up an authenticator app

totp_enroll-heading = Scan the QR code
totp_enroll-instructions = Scan this code with your authenticator app, then enter the 6-digit code the app shows.
totp_enroll-manual = Cannot scan the code? Enter this key in the app instead:
totp_enroll-code_label = Code from the app
totp_enroll-submit = Confirm
totp_enroll-cancel = Cancel

recovery_codes-heading = Save your recovery codes
recovery_codes-help = If you lose your authenticator app, each code lets you sign in once. Store them somewhere safe: they are shown only now.
recovery_codes-copy_label = All codes, for copying
recovery_codes-saved = I have saved my codes

sessions-heading = Where you are signed in
sessions-caption = Your active sessions. Signing out a session also ends the app access granted from it.
sessions-col_device = Device
sessions-col_ip = IP address
sessions-col_signed_in = Signed in
sessions-col_last_active = Last active
sessions-col_action = Action
sessions-this_device = (this device)
sessions-unknown_ip = Unknown
sessions-unknown_device = Unknown device
sessions-sign_out = Sign out
# $device: the browser's user agent (or "Unknown device").
sessions-sign_out_device = Sign out { $device }
sessions-sign_out_this_device = Sign out { $device } (this device)
sessions-sign_out_others = Sign out all other sessions

apps-allowed_on = Allowed on
apps-it_can = . It can:
# $client: the application's display name.
apps-remove_access_for = Remove access for { $client }
apps-remove_access = Remove access
apps-none = No apps have access to your account.
