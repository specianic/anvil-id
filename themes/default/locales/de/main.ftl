## AnvilID page catalog: German (de), release 0.2 pages and messages.
##
## German mirrors every message id of locales/en/*.ftl, file by file, with the same variables
## (crates/anvil-web/tests/i18n_catalogs.rs fails otherwise). Formal address ("Sie").
## The English sentences are the stable contract for tests; German texts may be improved freely.

## Page titles

title-login = Anmelden
title-second_factor = Bestätigung in zwei Schritten
title-registration = Konto erstellen
title-verification = E-Mail-Adresse bestätigen
title-recovery = Passwort zurücksetzen
title-recovery_reset = Neues Passwort festlegen
title-setup = AnvilID einrichten
title-setup_done = Einrichtung abgeschlossen
title-error = Fehler
title-consent = Zugriff erlauben
title-form_post = Weiterleitung
title-account_security = Sicherheit
title-account_sessions = Sitzungen
title-account_apps = Verbundene Apps
title-totp_enroll = Authenticator-App einrichten
title-recovery_codes = Wiederherstellungscodes

## Message page headings

heading-check_email = Prüfen Sie Ihre E-Mails
heading-password_changed = Passwort geändert
heading-email_confirmed = E-Mail-Adresse bestätigt
heading-registration_unavailable = Registrierung nicht verfügbar
heading-signed_in = Angemeldet
heading-done = Fertig

## Shared page elements

dev-banner = Entwicklungsmodus: nicht für den Produktivbetrieb geeignet
form-optional = (optional)
form-continue = Weiter
nav-account_help = Hilfe zum Konto
nav-next_steps = Nächste Schritte
nav-other_options = Weitere Möglichkeiten
punct-period = .
scope-use = Nutzung von

## Form field labels (FormField.label_key)

field-email = E-Mail-Adresse
field-admin_email = E-Mail-Adresse des Administrators
field-password = Passwort
field-name = Name
field-token = Token
field-code = Bestätigungscode
field-recovery_code = Wiederherstellungscode

## Flow messages (anvil-core flow engine)

login-invalid_credentials = E-Mail-Adresse oder Passwort ist falsch.
login-email_not_verified = Bitte bestätigen Sie Ihre E-Mail-Adresse, bevor Sie sich anmelden.
login-second_factor_invalid = Dieser Code ist ungültig. Bitte versuchen Sie es erneut.
login-passkey_failed = Die Anmeldung mit einem Passkey hat nicht funktioniert. Bitte versuchen Sie es erneut oder verwenden Sie Ihr Passwort.
login-recovery_code_used = Sie haben sich mit einem Wiederherstellungscode angemeldet. Jeder Code funktioniert nur einmal; erstellen Sie bei Bedarf neue Codes.
login-signed_in = Sie sind angemeldet.
login-captcha_required = Bitte schließen Sie die Sicherheitsprüfung ab und melden Sie sich dann an.
login-captcha_failed = Die Sicherheitsprüfung war nicht erfolgreich. Bitte wiederholen Sie sie und melden Sie sich dann an.
# $seconds: whole seconds until the next attempt is allowed.
login-too_many_attempts = Zu viele Versuche. Versuchen Sie es in { $seconds ->
        [one] { $seconds } Sekunde
       *[other] { $seconds } Sekunden
    } erneut.
registration-disabled = Eine Selbstregistrierung ist nicht möglich.
registration-email_taken = Es gibt bereits ein Konto mit dieser E-Mail-Adresse.
registration-check_email = Ihr Konto wurde erstellt. Bestätigen Sie Ihre Adresse über den Link in der E-Mail und melden Sie sich dann an.
email-invalid = Geben Sie eine gültige E-Mail-Adresse ein.
password-too_short = Das Passwort ist zu kurz.
password-too_long = Das Passwort ist zu lang.
password-breached = Dieses Passwort ist bereits bei einem Datenleck aufgetaucht. Bitte wählen Sie ein anderes.
recovery-sent = Falls zu dieser Adresse ein Konto existiert, haben wir eine Anleitung zum Zurücksetzen des Passworts gesendet.
recovery-invalid_token = Dieser Link zum Zurücksetzen des Passworts ist ungültig oder abgelaufen. Bitte fordern Sie einen neuen an.
recovery-done = Ihr Passwort wurde geändert. Sie können sich jetzt anmelden.
verification-invalid_token = Dieser Bestätigungslink ist ungültig oder abgelaufen.
verification-done = Ihre E-Mail-Adresse ist bestätigt.
flow-expired = Dieser Anmeldeversuch ist abgelaufen. Bitte beginnen Sie von vorn.
flow-invalid_input = Dieses Formular konnte nicht verarbeitet werden. Bitte versuchen Sie es erneut.
service-overloaded = Der Dienst ist gerade ausgelastet. Bitte versuchen Sie es gleich noch einmal.

## Account security messages (anvil-core account service)

account-reauth_required = Aus Sicherheitsgründen müssen Sie sich erneut anmelden, bevor Sie Ihre Anmeldemethoden ändern.
account-flow_expired = Diese Seite ist abgelaufen. Bitte versuchen Sie es erneut.
account-invalid_label = Verwenden Sie einen Namen mit höchstens 64 Zeichen.
account-passkey_failed = Der Passkey konnte nicht registriert werden. Bitte versuchen Sie es erneut.
account-passkey_exists = Dieser Passkey ist bereits registriert.
account-totp_exists = Es ist bereits eine Authenticator-App eingerichtet.
account-totp_not_pending = Starten Sie die Einrichtung der Authenticator-App erneut.
account-totp_invalid_code = Dieser Code ist ungültig. Prüfen Sie die Uhrzeit auf Ihrem Gerät und versuchen Sie es erneut.
account-totp_required = Richten Sie zuerst eine Authenticator-App ein.
account-credential_not_found = Diese Anmeldemethode existiert nicht mehr.
account-try_again = Gleichzeitig wurde eine andere Änderung vorgenommen. Bitte versuchen Sie es erneut.
account-passkey_registered = Passkey hinzugefügt.
account-passkey_removed = Passkey entfernt.
account-totp_removed = Authenticator-App entfernt. Ihre Wiederherstellungscodes wurden gelöscht.
account-totp_enrolled = Authenticator-App eingerichtet.
account-recovery_codes_regenerated = Neue Wiederherstellungscodes wurden erstellt. Die alten Codes funktionieren nicht mehr.

## Sessions page messages (anvil-core session service)

sessions-revoked = Die Sitzung wurde abgemeldet.
sessions-revoked_others = Alle anderen Sitzungen wurden abgemeldet.
sessions-not_found = Diese Sitzung ist nicht mehr aktiv.

## Consent and connected apps messages

consent-expired = Diese Seite ist abgelaufen. Bitte prüfen Sie die Anfrage erneut.
apps-revoked = Zugriff entfernt. Die App kann Ihr Konto nicht mehr verwenden.
apps-not_found = Diese App hat keinen Zugriff mehr auf Ihr Konto.
apps-expired = Diese Seite ist abgelaufen. Bitte versuchen Sie es erneut.

## Scope descriptions (consent screen, connected apps)

scope-openid = Sie anmelden
scope-profile = Ihren Namen und grundlegende Profilangaben sehen
scope-email = Ihre E-Mail-Adresse sehen
scope-phone = Ihre Telefonnummer sehen
scope-address = Ihre Postanschrift sehen
scope-offline_access = Sie angemeldet halten

## Error page

error-heading = Etwas ist schiefgelaufen
error-redirect_uri_mismatch = Die Weiterleitungs-URI dieser Anfrage ist für diesen Client nicht registriert.
error-unknown_client = Diese Anwendung ist nicht registriert.
error-invalid_request = Die Anmeldeanfrage ist ungültig.
error-flow_expired = Dieser Anmeldeversuch ist abgelaufen. Bitte beginnen Sie von vorn.
error-csrf = Dieses Formular konnte nicht überprüft werden. Bitte versuchen Sie es erneut.
error-not_found = Seite nicht gefunden.
error-too_many_requests = Zu viele Versuche. Bitte warten Sie einen Moment und versuchen Sie es dann erneut.
error-generic = Etwas ist schiefgelaufen.
error-status = Fehler { $status }
error-start_again = Von vorn beginnen

## Sign-in page

login-submit = Anmelden
login-webauthn-cancelled = Die Passkey-Anfrage wurde abgebrochen oder ist abgelaufen. Versuchen Sie es erneut oder melden Sie sich mit Ihrem Passwort an.
login-webauthn-failed = Ihr Passkey konnte nicht verwendet werden. Versuchen Sie es erneut oder melden Sie sich mit Ihrem Passwort an.
login-passkey_button = Mit einem Passkey anmelden
login-forgot_password = Passwort vergessen?
login-create_account = Konto erstellen
captcha-noscript = Diese Anmeldung erfordert eine Sicherheitsprüfung, die JavaScript benötigt. Aktivieren Sie JavaScript und laden Sie die Seite neu, um fortzufahren.

## Second factor

second_factor-code_hint = Öffnen Sie Ihre Authenticator-App und geben Sie den 6-stelligen Code ein, den sie für dieses Konto anzeigt.
second_factor-use_recovery_code = Stattdessen einen Wiederherstellungscode verwenden
second_factor-recovery_code_hint = Geben Sie einen der Wiederherstellungscodes ein, die Sie beim Einrichten der Authenticator-App gespeichert haben. Jeder Code funktioniert nur einmal.
second_factor-submit = Bestätigen
second_factor-start_over = Von vorn beginnen
second_factor-passkey_heading = Mit Passkey bestätigen
second_factor-passkey_help = Bestätigen Sie mit dem Passkey auf diesem Gerät oder Ihrem Sicherheitsschlüssel, dass Sie es sind.
second_factor-passkey_button = Mit Passkey bestätigen
second_factor-passkey_nojs = Für Passkeys werden JavaScript und ein Browser mit Passkey-Unterstützung benötigt.
second_factor-passkey_failed = Dieser Passkey kann für dieses Konto nicht verwendet werden. Bitte versuchen Sie es mit Ihrem eigenen Passkey erneut.
second_factor-webauthn-cancelled = Die Passkey-Anfrage wurde abgebrochen oder ist abgelaufen. Bitte versuchen Sie es erneut.
second_factor-webauthn-failed = Ihr Passkey konnte nicht verwendet werden. Bitte versuchen Sie es erneut.

## Registration, verification, recovery

registration-submit = Konto erstellen
registration-have_account = Sie haben bereits ein Konto? Anmelden
verification-lead = Klicken Sie auf die Schaltfläche, um Ihre E-Mail-Adresse zu bestätigen.
verification-submit = E-Mail-Adresse bestätigen
recovery-lead = Geben Sie die E-Mail-Adresse Ihres Kontos ein. Wenn sie registriert ist, senden wir Ihnen einen Link zum Zurücksetzen Ihres Passworts.
recovery-submit = Link zum Zurücksetzen senden
recovery-back_to_sign_in = Zurück zur Anmeldung
recovery_reset-submit = Neues Passwort speichern
message-go_to_sign_in = Zur Anmeldung

## Setup

setup-lead = Erstellen Sie das erste Administratorkonto. Damit melden Sie sich an der Verwaltungskonsole an.
setup-submit = Administrator erstellen
setup_done-lead_before = Das Administratorkonto
setup_done-lead_after = wurde erstellt.
setup_done-copy_now = Kopieren Sie diese Zugangsdaten jetzt.
setup_done-copy_note = Das Client-Secret wird nur einmal angezeigt und kann später nicht erneut angezeigt werden.
setup_done-client_id = Client-ID für die Verwaltung
setup_done-client_secret = Client-Secret für die Verwaltung
setup_done-token_endpoint = Token-Endpunkt
setup_done-admin_api_base = Basis-URL der Admin-API
setup_done-usage = Verwenden Sie Client-ID und Secret mit dem Client-Credentials-Grant am Token-Endpunkt, um die Admin-API aufzurufen.

## Consent screen and form_post

consent-heading = Zugriff auf Ihr Konto erlauben?
consent-would_like_to = möchte:
consent-note = Sie können diesen Zugriff jederzeit in Ihrem Konto unter „Verbundene Apps“ entfernen.
consent-allow = Erlauben
consent-deny = Ablehnen
form_post-heading = Weiterleitung…
form_post-status = Sie werden zur Anwendung zurückgeleitet.

## Account pages

account_nav-label = Konto
account_nav-security = Sicherheit
account_nav-sessions = Sitzungen
account_nav-apps = Verbundene Apps

security-reauth_before = Aus Sicherheitsgründen
security-reauth_link = melden Sie sich bitte erneut an
security-reauth_after = und ändern Sie danach Ihre Anmeldemethoden.
security-passkeys = Passkeys
security-col_name = Name
security-col_added = Hinzugefügt
security-col_last_used = Zuletzt verwendet
security-col_action = Aktion
security-never = Nie
security-never_lower = nie
security-remove = Entfernen
# $label: the passkey name chosen by the user.
security-remove_passkey = Passkey { $label } entfernen
security-no_passkeys = Sie haben noch keine Passkeys.
security-webauthn-cancelled = Das Hinzufügen des Passkeys wurde abgebrochen.
security-webauthn-failed = Der Passkey konnte nicht hinzugefügt werden. Bitte versuchen Sie es erneut.
security-passkey_name = Name des Passkeys
security-add_passkey = Passkey hinzufügen
security-passkey_nojs = Zum Hinzufügen eines Passkeys sind JavaScript und ein Browser mit Passkey-Unterstützung erforderlich.
security-totp_heading = Authenticator-App
security-totp_set_up_on = Eingerichtet am
security-totp_last_used = . Zuletzt verwendet:
security-recovery_codes_left = Verbleibende Wiederherstellungscodes:
security-new_recovery_codes = Neue Wiederherstellungscodes erstellen
security-remove_totp = Authenticator-App entfernen
security-totp_not_set_up = Nicht eingerichtet. Verwenden Sie eine Authenticator-App für einen Einmalcode bei der Anmeldung.
security-set_up_totp = Authenticator-App einrichten

totp_enroll-heading = QR-Code scannen
totp_enroll-instructions = Scannen Sie diesen Code mit Ihrer Authenticator-App und geben Sie dann den 6-stelligen Code ein, den die App anzeigt.
totp_enroll-manual = Sie können den Code nicht scannen? Geben Sie stattdessen diesen Schlüssel in der App ein:
totp_enroll-code_label = Code aus der App
totp_enroll-submit = Bestätigen
totp_enroll-cancel = Abbrechen

recovery_codes-heading = Speichern Sie Ihre Wiederherstellungscodes
recovery_codes-help = Falls Sie Ihre Authenticator-App verlieren, können Sie sich mit jedem Code einmal anmelden. Bewahren Sie die Codes sicher auf: Sie werden nur jetzt angezeigt.
recovery_codes-copy_label = Alle Codes zum Kopieren
recovery_codes-saved = Ich habe meine Codes gespeichert

sessions-heading = Wo Sie angemeldet sind
sessions-caption = Ihre aktiven Sitzungen. Wenn Sie eine Sitzung abmelden, endet auch der App-Zugriff, der darüber erteilt wurde.
sessions-col_device = Gerät
sessions-col_ip = IP-Adresse
sessions-col_signed_in = Angemeldet
sessions-col_last_active = Zuletzt aktiv
sessions-col_action = Aktion
sessions-this_device = (dieses Gerät)
sessions-unknown_ip = Unbekannt
sessions-unknown_device = Unbekanntes Gerät
sessions-sign_out = Abmelden
# $device: the browser's user agent (or "Unknown device").
sessions-sign_out_device = { $device } abmelden
sessions-sign_out_this_device = { $device } abmelden (dieses Gerät)
sessions-sign_out_others = Alle anderen Sitzungen abmelden

apps-allowed_on = Zugriff erteilt am
apps-it_can = . Die App darf:
# $client: the application's display name.
apps-remove_access_for = Zugriff für { $client } entfernen
apps-remove_access = Zugriff entfernen
apps-none = Keine App hat Zugriff auf Ihr Konto.
