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
profile-locale_help = Ein Sprachcode wie en, de oder pt-BR. Die Kontoseiten verwenden diese Sprache, sofern sie verfügbar ist.
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
