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
errors_friendly-heading-generic = Etwas ist schiefgelaufen
errors_friendly-explain-redirect_uri_mismatch = Die Anwendung hat Sie mit einer Adresse hierher geschickt, die sie nicht registriert hat. Deshalb können Sie sich über diesen Link nicht anmelden. Gehen Sie zurück zur Anwendung und versuchen Sie es erneut, oder informieren Sie deren Betreiber.
errors_friendly-explain-unknown_client = Der Link, dem Sie gefolgt sind, nennt eine Anwendung, die bei diesem Anmeldedienst nicht registriert ist. Gehen Sie zurück zur Anwendung und versuchen Sie es erneut.
errors_friendly-explain-invalid_request = Der Link, dem Sie gefolgt sind, ist unvollständig oder wurde unterwegs verändert. Beginnen Sie erneut in der Anwendung oder auf der Anmeldeseite.
errors_friendly-explain-flow_expired = Anmeldelinks gelten nur wenige Minuten. Es wurde nichts geändert; beginnen Sie einfach von vorn.
errors_friendly-explain-csrf = Die Seite war zu lange geöffnet oder wurde in einem anderen Tab geöffnet. Es wurde nichts gespeichert; beginnen Sie von vorn.
errors_friendly-explain-not_found = Die Adresse ist vielleicht falsch geschrieben, oder die Seite wurde verschoben.
errors_friendly-explain-too_many_requests = Zum Schutz Ihres Kontos haben wir weitere Versuche für kurze Zeit angehalten.
errors_friendly-explain-generic = Bitte versuchen Sie es gleich noch einmal. Wenn das Problem bleibt, wenden Sie sich an den Betreiber dieses Dienstes.
errors_friendly-danger_label = Fehler
errors_friendly-detail_label = Technische Details (Entwicklungsmodus):
errors_friendly-back_to_app = Zurück zu { $app }
errors_friendly-go_home = Zur Startseite
