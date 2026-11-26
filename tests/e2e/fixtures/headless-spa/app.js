// Headless SPA fixture (test code only): starts a login flow through the AnvilID headless flow
// API in browser mode, renders the form from the versioned DTO, submits it with the CSRF header
// and `credentials: "include"`, then navigates the top-level window to `result.continue_to`.
//
// Query parameters: `issuer` (the tenant's issuer URL), `request` (the authorization request id
// from the sign-in redirect, optional).
'use strict';

const params = new URLSearchParams(window.location.search);
const issuer = params.get('issuer') || '';
const request = params.get('request');
const api = `${issuer}/api/flows/v1`;

const statusEl = document.getElementById('spa-status');
const errorEl = document.getElementById('spa-error');
const methodsEl = document.getElementById('spa-methods');
const formEl = document.getElementById('spa-form');

let flow = null;
let csrf = null;

function setStatus(text) {
  statusEl.textContent = text;
}

function fail(code) {
  errorEl.textContent = code;
  setStatus('error');
}

async function call(path, body) {
  const headers = { 'content-type': 'application/json' };
  if (csrf) headers['x-csrf-token'] = csrf;
  let res;
  try {
    res = await fetch(`${api}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers,
      body: JSON.stringify(body),
    });
  } catch (e) {
    // A CORS refusal (origin not allow-listed) surfaces as a network error.
    fail('network-error');
    return null;
  }
  const json = await res.json().catch(() => null);
  if (!json) {
    fail(`http-${res.status}`);
    return null;
  }
  return json;
}

function inputType(kind) {
  switch (kind) {
    case 'text':
    case 'email':
    case 'password':
    case 'hidden':
      return kind;
    default:
      return null; // unknown kinds are not rendered (versioning rule)
  }
}

function render(answer) {
  if (answer.code) {
    // A problem (RFC 9457).
    fail(answer.code);
    return;
  }
  if (answer.csrf_token) csrf = answer.csrf_token;
  if (answer.flow) flow = answer.flow;
  switch (answer.step) {
    case 'form':
      renderForm(answer.form);
      return;
    case 'completed':
      setStatus('completed');
      if (answer.result && answer.result.continue_to) {
        window.location.assign(answer.result.continue_to);
      }
      return;
    case 'browser_required':
      setStatus('browser_required');
      window.location.assign(answer.url);
      return;
    case 'message':
      setStatus(`message:${answer.message.key}`);
      formEl.hidden = true;
      return;
    default:
      // Unknown steps are ignored (versioning rule).
      setStatus(`unknown-step:${answer.step}`);
  }
}

function renderForm(form) {
  formEl.replaceChildren();
  methodsEl.replaceChildren();
  formEl.dataset.formId = form.id;
  for (const m of form.methods || []) {
    const li = document.createElement('li');
    li.textContent = m.kind;
    li.dataset.method = m.kind;
    methodsEl.append(li);
  }
  for (const msg of form.messages || []) {
    const p = document.createElement('p');
    p.className = 'spa-message';
    p.dataset.key = msg.key;
    p.textContent = msg.text || msg.key;
    formEl.append(p);
  }
  for (const field of form.fields) {
    const type = inputType(field.kind);
    if (!type) continue;
    const input = document.createElement('input');
    input.type = type;
    input.name = field.name;
    input.id = `spa-field-${field.name}`;
    input.required = field.required && type !== 'hidden';
    if (field.autocomplete) input.autocomplete = field.autocomplete;
    if (field.value !== undefined) input.value = field.value;
    if (type !== 'hidden') {
      const label = document.createElement('label');
      label.htmlFor = input.id;
      label.textContent = field.label || field.label_key;
      formEl.append(label);
    }
    formEl.append(input);
  }
  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.id = 'spa-submit';
  submit.textContent = 'Continue';
  formEl.append(submit);
  formEl.hidden = false;
  setStatus(`form:${form.id}`);
}

formEl.addEventListener('submit', async (event) => {
  event.preventDefault();
  const values = {};
  for (const input of formEl.querySelectorAll('input')) values[input.name] = input.value;
  const body = { values };
  if (formEl.dataset.formId === 'login') body.method = 'password';
  setStatus('submitting');
  const answer = await call(`/${flow.kind}/${flow.id}`, body);
  if (answer) render(answer);
});

(async () => {
  const answer = await call('/login', request ? { request } : {});
  if (answer) render(answer);
})();
