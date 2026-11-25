/*
 * AnvilID WebAuthn helper (passkey registration and sign-in).
 *
 * Served as a self-hosted static asset (/assets/webauthn.js) so it runs under the strict CSP
 * (script-src 'self'): no inline script, no inline event handlers, no eval. Classic script, no
 * modules. Load it with <script src="/assets/webauthn.js" defer></script>.
 *
 * DOM contract (one or more forms per page):
 *
 *   <form method="post" action="..." data-webauthn="register|authenticate"
 *         data-options-url="..."                      (optional, see below)
 *         data-webauthn-msg-cancelled="..."           (optional localized messages)
 *         data-webauthn-msg-failed="...">
 *     <input type="hidden" name="csrf_token" value="...">
 *     <input type="hidden" name="response" value="">
 *     <script type="application/json" data-webauthn-options>{"publicKey":{...}}</script>
 *     <button type="button" data-webauthn-trigger hidden>Use a passkey</button>
 *     <p data-webauthn-status aria-live="polite"></p>
 *   </form>
 *
 * Options come from, in order: a <script type="application/json" data-webauthn-options> inside
 * the form, the page-level <script type="application/json" id="webauthn-options">, or a POST to
 * the form's data-options-url carrying the form's csrf_token (the answer is the options JSON).
 * JSON in a type="application/json" script element is data, not script, so CSP allows it.
 *
 * The options JSON is the webauthn-rs shape: {"publicKey": {...}} (creation options for
 * "register", request options for "authenticate"). The credential is serialised with
 * credential.toJSON() (or an equivalent fallback) into the hidden "response" input and the form
 * is submitted.
 *
 * Without WebAuthn support the script does nothing: triggers stay hidden and the page keeps its
 * password path. Errors are written into the [data-webauthn-status] aria-live region.
 */
(function () {
  "use strict";

  var DEFAULT_MESSAGES = {
    cancelled: "The passkey request was cancelled or timed out. Try again.",
    failed: "The passkey could not be used. Try again or use another sign-in method.",
  };

  function supported() {
    return (
      typeof window.PublicKeyCredential === "function" &&
      !!navigator.credentials &&
      typeof navigator.credentials.create === "function" &&
      typeof navigator.credentials.get === "function"
    );
  }

  // ---- base64url <-> ArrayBuffer -------------------------------------------------------------

  function b64urlToBuffer(value) {
    var b64 = String(value).replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) {
      b64 += "=";
    }
    var bin = atob(b64);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) {
      bin += String.fromCharCode(bytes[i]);
    }
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeDescriptors(list) {
    if (!Array.isArray(list)) {
      return list;
    }
    return list.map(function (d) {
      var copy = Object.assign({}, d);
      copy.id = b64urlToBuffer(d.id);
      return copy;
    });
  }

  // ---- options JSON -> WebAuthn options ------------------------------------------------------

  function creationOptions(publicKey) {
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
      return PublicKeyCredential.parseCreationOptionsFromJSON(publicKey);
    }
    var o = Object.assign({}, publicKey);
    o.challenge = b64urlToBuffer(publicKey.challenge);
    o.user = Object.assign({}, publicKey.user, { id: b64urlToBuffer(publicKey.user.id) });
    if (publicKey.excludeCredentials) {
      o.excludeCredentials = decodeDescriptors(publicKey.excludeCredentials);
    }
    return o;
  }

  function requestOptions(publicKey) {
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
      return PublicKeyCredential.parseRequestOptionsFromJSON(publicKey);
    }
    var o = Object.assign({}, publicKey);
    o.challenge = b64urlToBuffer(publicKey.challenge);
    if (publicKey.allowCredentials) {
      o.allowCredentials = decodeDescriptors(publicKey.allowCredentials);
    }
    return o;
  }

  // ---- credential -> JSON --------------------------------------------------------------------

  function credentialJSON(cred) {
    if (typeof cred.toJSON === "function") {
      return cred.toJSON();
    }
    var r = cred.response;
    var response;
    if (typeof r.attestationObject !== "undefined") {
      response = {
        clientDataJSON: bufferToB64url(r.clientDataJSON),
        attestationObject: bufferToB64url(r.attestationObject),
        transports: typeof r.getTransports === "function" ? r.getTransports() : [],
      };
    } else {
      response = {
        clientDataJSON: bufferToB64url(r.clientDataJSON),
        authenticatorData: bufferToB64url(r.authenticatorData),
        signature: bufferToB64url(r.signature),
        userHandle: r.userHandle ? bufferToB64url(r.userHandle) : null,
      };
    }
    return {
      id: cred.id,
      rawId: bufferToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || null,
      response: response,
      clientExtensionResults:
        typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {},
    };
  }

  // ---- form plumbing -------------------------------------------------------------------------

  function message(form, key) {
    return form.getAttribute("data-webauthn-msg-" + key) || DEFAULT_MESSAGES[key];
  }

  function setStatus(form, text) {
    var status = form.querySelector("[data-webauthn-status]");
    if (status) {
      status.textContent = text;
    }
  }

  function inlineOptions(form) {
    var el =
      form.querySelector('script[type="application/json"][data-webauthn-options]') ||
      document.getElementById("webauthn-options");
    if (!el || el.getAttribute("type") !== "application/json") {
      return null;
    }
    return JSON.parse(el.textContent);
  }

  function fetchOptions(form) {
    var url = form.getAttribute("data-options-url");
    var csrf = form.querySelector('input[name="csrf_token"]');
    var body = new URLSearchParams();
    if (csrf) {
      body.set("csrf_token", csrf.value);
    }
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
      body: body,
    }).then(function (res) {
      if (!res.ok) {
        throw new Error("options request failed");
      }
      return res.json();
    });
  }

  function loadOptions(form) {
    if (form.hasAttribute("data-options-url")) {
      return fetchOptions(form);
    }
    var inline = inlineOptions(form);
    if (!inline) {
      return Promise.reject(new Error("no WebAuthn options on the page"));
    }
    return Promise.resolve(inline);
  }

  function ceremony(form, options) {
    var mode = form.getAttribute("data-webauthn");
    var publicKey = options && options.publicKey;
    if (!publicKey) {
      throw new Error("malformed WebAuthn options");
    }
    if (mode === "register") {
      return navigator.credentials.create({ publicKey: creationOptions(publicKey) });
    }
    if (mode === "authenticate") {
      return navigator.credentials.get({ publicKey: requestOptions(publicKey) });
    }
    throw new Error("unknown data-webauthn mode");
  }

  function run(form, trigger) {
    var input = form.querySelector('input[name="response"]');
    if (!input) {
      setStatus(form, message(form, "failed"));
      return;
    }
    if (trigger) {
      trigger.disabled = true;
    }
    setStatus(form, "");
    loadOptions(form)
      .then(function (options) {
        return ceremony(form, options);
      })
      .then(function (cred) {
        if (!cred) {
          throw new Error("no credential returned");
        }
        input.value = JSON.stringify(credentialJSON(cred));
        // Prototype call: a control named "submit" would shadow form.submit.
        HTMLFormElement.prototype.submit.call(form);
      })
      .catch(function (err) {
        var cancelled = err && (err.name === "NotAllowedError" || err.name === "AbortError");
        setStatus(form, message(form, cancelled ? "cancelled" : "failed"));
        if (trigger) {
          trigger.disabled = false;
          trigger.focus();
        }
      });
  }

  function init() {
    var forms = document.querySelectorAll("form[data-webauthn]");
    if (!forms.length) {
      return;
    }
    if (!supported()) {
      return;
    }
    Array.prototype.forEach.call(forms, function (form) {
      var triggers = form.querySelectorAll("[data-webauthn-trigger]");
      Array.prototype.forEach.call(triggers, function (trigger) {
        trigger.hidden = false;
        trigger.addEventListener("click", function (event) {
          event.preventDefault();
          run(form, trigger);
        });
      });
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
