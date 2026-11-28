# Account profile, email and password pages (plan 04-15), German.

## Page titles
title-account_profile = Profil
title-account_email = E-Mail-Adresse
title-account_email_confirm = Neue E-Mail-Adresse bestätigen
title-account_password = Passwort

## Account navigation (account_base.html)
account_nav-profile = Profil
account_nav-email = E-Mail
account_nav-password = Passwort

## Profile page
profile-heading = Ihre Angaben
profile-name = Vollständiger Name
profile-given_name = Vorname
profile-family_name = Nachname
profile-locale = Sprache
profile-locale_help = Die Kontoseiten verwenden diese Sprache.
profile-locale_default = Nicht festgelegt (Sprache Ihres Browsers verwenden)
# The name of this catalog's language, in that language (the language select).
profile-language_name = Deutsch
profile-save = Speichern
account-profile_saved = Ihre Angaben wurden gespeichert.

## Email page
email_change-heading = E-Mail-Adresse ändern
email_change-current = Aktuelle Adresse:
email_change-verified = (bestätigt)
email_change-unverified = (nicht bestätigt)
email_change-new_email = Neue E-Mail-Adresse
email_change-help = Wir senden einen Bestätigungslink an die neue Adresse. Ihre Adresse ändert sich erst, wenn Sie diesen Link öffnen und bestätigen.
email_change-submit = Bestätigungslink senden
email_change-reauth_before = Aus Sicherheitsgründen
email_change-reauth_link = melden Sie sich bitte erneut an
email_change-reauth_after = und ändern Sie danach Ihre E-Mail-Adresse.
account-email_change_sent = Wenn die Adresse verwendet werden kann, ist ein Bestätigungslink dorthin unterwegs. Ihre Adresse ändert sich, sobald Sie bestätigen.
email_confirm-heading = Neue E-Mail-Adresse bestätigen
email_confirm-explain = Klicken Sie auf die Schaltfläche, um diese Adresse zur E-Mail-Adresse Ihres Kontos zu machen.
email_confirm-submit = Neue E-Mail-Adresse bestätigen
account-email_changed = Ihre E-Mail-Adresse wurde geändert.

## Password page
password_change-heading_change = Passwort ändern
password_change-heading_set = Passwort festlegen
password_change-none_yet = Ihr Konto hat noch kein Passwort. Legen Sie eines fest, um sich mit Ihrer E-Mail-Adresse und einem Passwort anzumelden.
password_change-new_password = Neues Passwort
password_change-help = Wählen Sie eine lange Passphrase, die Sie nirgendwo sonst verwenden.
password_change-revoke_others = Auf allen anderen Geräten abmelden
password_change-submit_change = Passwort ändern
password_change-submit_set = Passwort festlegen
password_change-reauth_before = Aus Sicherheitsgründen
password_change-reauth_link = melden Sie sich bitte erneut an
password_change-reauth_after = und ändern Sie danach Ihr Passwort.
account-password_changed = Ihr Passwort wurde geändert.

## Refusals (anvil-core AccountFailure)
account-invalid_name = Verwenden Sie höchstens 200 Zeichen und keine Zeilenumbrüche.
account-invalid_locale = Geben Sie einen Sprachcode wie en, de oder pt-BR ein.
account-invalid_email = Geben Sie eine gültige E-Mail-Adresse ein.
account-email_unchanged = Das ist bereits Ihre E-Mail-Adresse.
account-email_taken = Diese E-Mail-Adresse wird bereits von einem anderen Konto verwendet. Der Link bleibt vorerst gültig; versuchen Sie es später erneut oder wenden Sie sich an Ihre Administration.
account-email_token_invalid = Dieser Link ist ungültig, abgelaufen oder wurde bereits verwendet. Fordern Sie auf Ihrer Kontoseite einen neuen Bestätigungslink an.
account-password_too_short = Das Passwort ist zu kurz.
account-password_too_long = Das Passwort ist zu lang.
account-password_breached = Dieses Passwort ist bereits bei einem Datenleck aufgetaucht. Bitte wählen Sie ein anderes.
account-overloaded = Der Dienst ist gerade ausgelastet. Bitte versuchen Sie es gleich noch einmal.

## Confirmation of destructive actions (account_confirm.html, plan 07.1-21)
account_confirm-cancel = Abbrechen und nichts ändern
account_confirm-remove_passkey_question = Passkey { $subject } entfernen?
account_confirm-remove_passkey_explain = Mit diesem Passkey können Sie sich danach nicht mehr anmelden.
account_confirm-remove_passkey_submit = Passkey entfernen
account_confirm-remove_totp_question = Authenticator-App entfernen?
account_confirm-remove_totp_explain = Die Anmeldung fragt nicht mehr nach einem Code aus Ihrer Authenticator-App, und Ihre Wiederherstellungscodes werden ungültig.
account_confirm-remove_totp_submit = Authenticator-App entfernen
account_confirm-regenerate_codes_question = Neue Wiederherstellungscodes erstellen?
account_confirm-regenerate_codes_explain = Ihre bisherigen Wiederherstellungscodes werden sofort ungültig. Bewahren Sie die neuen an einem sicheren Ort auf.
account_confirm-regenerate_codes_submit = Neue Wiederherstellungscodes erstellen
account_confirm-revoke_app_question = Zugriff für { $subject } entfernen?
account_confirm-revoke_app_explain = { $subject } kann Ihr Konto erst wieder nutzen, wenn Sie es erneut erlauben, und Sie werden dort abgemeldet.
account_confirm-revoke_app_submit = Zugriff entfernen
account_confirm-unlink_question = Verbindung mit { $subject } trennen?
account_confirm-unlink_explain = Sie können sich danach nicht mehr mit { $subject } anmelden. Sie können die Verbindung später wieder herstellen.
account_confirm-unlink_submit = Verbindung trennen
account_confirm-sign_out_others_question = Auf allen anderen Geräten abmelden?
account_confirm-sign_out_others_explain = Alle anderen Geräte, auf denen Sie angemeldet sind, werden abgemeldet. Dieses Gerät bleibt angemeldet.
account_confirm-sign_out_others_submit = Andere Geräte abmelden
