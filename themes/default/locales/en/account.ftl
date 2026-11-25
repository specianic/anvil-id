# Account profile, email and password pages (plan 04-15).

## Page titles
title-account_profile = Profile
title-account_email = Email address
title-account_email_confirm = Confirm new email address
title-account_password = Password

## Account navigation (account_base.html)
account_nav-profile = Profile
account_nav-email = Email
account_nav-password = Password

## Profile page
profile-heading = Your details
profile-name = Full name
profile-given_name = Given name
profile-family_name = Family name
profile-locale = Language
profile-locale_help = A language tag such as en, de or pt-BR. Account pages use this language when it is available.
profile-save = Save
account-profile_saved = Your details were saved.

## Email page
email_change-heading = Change your email address
email_change-current = Current address:
email_change-verified = (verified)
email_change-unverified = (not verified)
email_change-new_email = New email address
email_change-help = We send a confirmation link to the new address. Your address changes only after you open that link and confirm.
email_change-submit = Send confirmation link
email_change-reauth_before = For your security,
email_change-reauth_link = sign in again
email_change-reauth_after = before changing your email address.
account-email_change_sent = If the address can be used, a confirmation link is on its way to it. Your address changes once you confirm.
email_confirm-heading = Confirm your new email address
email_confirm-explain = Select the button to make this the email address of your account.
email_confirm-submit = Confirm new email
account-email_changed = Your email address was changed.

## Password page
password_change-heading_change = Change your password
password_change-heading_set = Set a password
password_change-none_yet = Your account has no password yet. Set one to sign in with your email address and a password.
password_change-new_password = New password
password_change-help = Choose a long passphrase that you do not use anywhere else.
password_change-revoke_others = Sign out on all other devices
password_change-submit_change = Change password
password_change-submit_set = Set password
password_change-reauth_before = For your security,
password_change-reauth_link = sign in again
password_change-reauth_after = before changing your password.
account-password_changed = Your password was changed.

## Refusals (anvil-core AccountFailure)
account-invalid_name = Use at most 200 characters, without line breaks.
account-invalid_locale = Enter a language tag such as en, de or pt-BR.
account-invalid_email = Enter a valid email address.
account-email_unchanged = That is already your email address.
account-email_taken = This email address is already used by another account. The link stays valid for now; try again later or contact your administrator.
account-email_token_invalid = This link is invalid, expired or already used. Request a new confirmation link from your account page.
account-password_too_short = The password is too short.
account-password_too_long = The password is too long.
account-password_breached = This password has appeared in a data breach. Please choose a different one.
account-overloaded = The service is busy. Please try again in a moment.
