/*
 * AnvilID form_post helper (OAuth 2.0 Form Post Response Mode).
 *
 * Served as a self-hosted static asset so it runs under the strict CSP (script-src 'self'):
 * no inline script, no eval. Submits the authorization response form (#form-post) once the
 * document is ready. Without JavaScript the page shows a <noscript> Continue button instead.
 */
(function () {
  "use strict";
  var submitted = false;
  function submit() {
    var form = document.getElementById("form-post");
    if (form && !submitted) {
      submitted = true;
      form.submit();
    }
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", submit);
  } else {
    submit();
  }
})();
