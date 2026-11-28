## AnvilID page catalog: German (de), friendly error pages (plan 07.1-08).
##
## A heading and an explanation per error key go around the stable contract sentences of
## main.ftl (error-*), which stay unchanged. The way forward links ("Back to <app>", start page)
## and the label next to the danger icon live here too.

errors_friendly-heading-redirect_uri_mismatch = Der Anmeldelink dieser Anwendung ist falsch eingerichtet
errors_friendly-heading-unknown_client = Diese Anwendung ist hier nicht bekannt
errors_friendly-heading-invalid_request = Diese Anmeldeanfrage kann nicht verwendet werden
errors_friendly-heading-flow_expired = Dieser Anmeldelink ist abgelaufen
errors_friendly-heading-csrf = Dieses Formular ist abgelaufen
errors_friendly-heading-not_found = Diese Seite gibt es nicht
errors_friendly-heading-too_many_requests = Zu viele Anfragen
errors_friendly-heading-saml_login_failed = Die Anmeldung Ihrer Organisation hat nicht funktioniert
errors_friendly-heading-generic = Etwas ist schiefgelaufen
errors_friendly-explain-redirect_uri_mismatch = Die Anwendung hat Sie mit einer Adresse hierher geschickt, die sie nicht registriert hat. Deshalb können Sie sich über diesen Link nicht anmelden. Gehen Sie zurück zur Anwendung und versuchen Sie es erneut, oder informieren Sie deren Betreiber.
errors_friendly-explain-unknown_client = Der Link, dem Sie gefolgt sind, nennt eine Anwendung, die bei diesem Anmeldedienst nicht registriert ist. Gehen Sie zurück zur Anwendung und versuchen Sie es erneut.
errors_friendly-explain-invalid_request = Der Link, dem Sie gefolgt sind, ist unvollständig oder wurde unterwegs verändert. Beginnen Sie erneut in der Anwendung oder auf der Anmeldeseite.
errors_friendly-explain-flow_expired = Anmeldelinks gelten nur wenige Minuten. Es wurde nichts geändert; beginnen Sie einfach von vorn.
errors_friendly-explain-csrf = Die Seite war zu lange geöffnet oder wurde in einem anderen Tab geöffnet. Es wurde nichts gespeichert; beginnen Sie von vorn.
errors_friendly-explain-not_found = Die Adresse ist vielleicht falsch geschrieben, oder die Seite wurde verschoben.
errors_friendly-explain-too_many_requests = Zum Schutz Ihres Kontos haben wir weitere Versuche für kurze Zeit angehalten.
errors_friendly-explain-saml_login_failed = Die Anmeldung über den Identitätsanbieter Ihrer Organisation hat nicht funktioniert. Kehren Sie zur Anwendung zurück und starten Sie die Anmeldung erneut.
errors_friendly-explain-generic = Bitte versuchen Sie es gleich noch einmal. Wenn das Problem bleibt, wenden Sie sich an den Betreiber dieses Dienstes.
errors_friendly-danger_label = Fehler
errors_friendly-detail_label = Technische Details (Entwicklungsmodus):
errors_friendly-back_to_app = Zurück zu { $app }
errors_friendly-go_home = Zur Startseite

## Tenant root page and setup guidance (`/`, `/ui`, `/console/` before setup, setup pages)

errors_friendly-root_title = Willkommen
errors_friendly-root_heading = Willkommen
errors_friendly-root_signed_out = Melden Sie sich an, um die Anwendungen dieses Dienstes zu nutzen und Ihr Konto zu verwalten.
errors_friendly-root_signed_in = Sie sind angemeldet.
errors_friendly-root_sign_in = Anmelden
errors_friendly-root_administration = Verwaltung
errors_friendly-setup_pending_title = Die Einrichtung ist nicht abgeschlossen
errors_friendly-setup_pending_lead = Diese AnvilID-Installation hat noch keinen Administrator.
errors_friendly-setup_pending_how = Öffnen Sie den Einrichtungslink, den der Server beim ersten Start ausgegeben hat, oder erstellen Sie einen neuen, indem Sie diesen Befehl dort ausführen, wo der Server läuft:
errors_friendly-setup_pending_after = Über den Einrichtungslink legen Sie den ersten Administrator an. Danach ist hier die Admin-Konsole verfügbar.
errors_friendly-setup_used_title = Die Einrichtung ist bereits abgeschlossen
errors_friendly-setup_used = Der erste Administrator wurde bereits angelegt, daher kann dieser Einrichtungslink nicht mehr verwendet werden. Melden Sie sich stattdessen an der Admin-Konsole an.
errors_friendly-setup_done_next = Melden Sie sich als Nächstes mit dem Administratorkonto an der Admin-Konsole an, um Ihre erste Anwendung anzulegen.
errors_friendly-setup_done_automation = Für die Automatisierung
errors_friendly-setup_done_automation_lead = Skripte und CI-Pipelines können die Admin-API mit diesen Verwaltungs-Zugangsdaten aufrufen.
