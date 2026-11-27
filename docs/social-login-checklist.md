# Social login: manual real-provider checklist

CI tests every upstream provider adapter (Google, Apple, Microsoft, GitHub, generic OIDC and
generic OAuth 2) against local mock identity providers that copy each provider's endpoints and
claim quirks (`crates/anvil-web/tests/upstream_*.rs`, `tests/e2e`). CI never talks to the real
providers and holds no provider credentials.

This checklist covers what the mocks cannot prove: that the real providers accept AnvilID's
requests and that their answers match what the mocks assume. The project owner runs it before each
release that changes upstream sign-in, using their own app registrations. Any item may be waived
for a release, but the waiver must name the item.

Rules for the run:

- Never paste client secrets, private keys, tokens or real account details into this file, an
  issue or the release notes. Record only pass, fail or waived, and a short reason.
- Use test accounts at each provider, not personal ones.
- `https://id.example.com` below stands for your AnvilID public URL. For a path tenant the issuer is
  `https://id.example.com/t/{slug}`; replace the prefix accordingly.

## 0. Preparation

- [ ] AnvilID runs the release candidate at a public `https://` URL, and `anvilid config show`
      shows that URL as `public_url`.
- [ ] The server can reach the providers over https (no `outbound_allow_cidrs` entry is needed for
      public providers; a corporate egress proxy is not supported, proxy variables are ignored).
- [ ] SMTP is configured, so new accounts and email changes can be checked.
- [ ] A test tenant exists with open registration, `require_verified_email` off, MFA policy
      `optional` and auto-link on (console: **Login settings**).
- [ ] A downstream test client signs in through the tenant, for example `examples/node-rp`, so the
      ID token can be inspected (expected `amr` for an upstream sign-in: `["fed"]`).
- [ ] A local account `alice@…` exists with a password and a verified email that is also the email
      of one provider test account (used for the linking checks).
- [ ] The console audit page (**Audit**) is open in a second tab.

For every connection, the redirect URI to register at the provider is shown on the connection page
in the console. Its form is:

```
https://id.example.com/ui/login/upstream/{connection-slug}/callback
```

Create each connection in the console (**Connections → New**), copy the redirect URI from its page,
register it at the provider exactly (scheme, host, path, no trailing slash), then set the secret.

## 1. Google

Registration: an OAuth client of type "web application" at Google with the redirect URI above.
AnvilID needs the client ID and the client secret. Scopes requested: `openid email profile`.

- [ ] **Create:** connection kind Google, slug `google`, client ID and secret set. Expected: the
      connection page shows "Secret configured", and the sign-in page shows "Continue with Google".
- [ ] **First sign-in (just in time):** sign in with a Google test account that has no local
      account. Expected: Google's consent screen, then back at the client with a code; a new user
      exists with the Google email marked verified; audit shows `user_registered` (with the
      connection); the ID token has `amr` `["fed"]`.
- [ ] **Second sign-in:** sign out, sign in again with the same Google account. Expected: no new
      user; the linked account shows an updated "last used" time on `/ui/account/linked`.
- [ ] **Auto-link:** sign in with the Google account whose email equals `alice@…`. Expected: signed
      in as Alice without a confirmation page; audit `identity_linked` with mode `auto`.
- [ ] **Hosted domain (if you use Workspace):** set `hosted_domains` to your domain. Expected: an
      account of that domain signs in; a personal account is refused with the generic error and
      audit reason `hosted_domain`.
- [ ] **Secret rotation:** create a second secret at Google, set it with **Rotate secret**, sign in
      (works), delete the old secret at Google, sign in again (works).

## 2. Apple

Registration at Apple: an App ID with Sign in with Apple, a Services ID (this is the client ID),
the return URL (the redirect URI above, registered on the Services ID with its domain), and a
Sign in with Apple private key. AnvilID needs the Services ID, the Team ID, the Key ID and the
`.p8` private key file (uploaded as the secret). Scopes requested: `name email`, with
`response_mode=form_post`.

- [ ] **Create:** connection kind Apple with Services ID, Team ID and Key ID; upload the `.p8` file.
      Expected: accepted (a key that is not an ES256 PKCS#8 key is refused with a field error).
- [ ] **PKCE check:** start a sign-in and look at the authorization URL in the browser's network
      panel. Expected: it contains `state` and `nonce` but no `code_challenge` (AnvilID treats
      Apple as not supporting PKCE), and the sign-in completes. Record whether the real service
      accepts the flow without PKCE; a failure here is a release blocker.
- [ ] **Client secret:** the token exchange succeeds. AnvilID mints a fresh ES256 client secret
      (valid 300 s) for each exchange; a failure shows the generic error and audit reason
      `exchange_failed`.
- [ ] **First sign-in, name:** sign in with an Apple test account that never used this Services ID.
      Expected: Apple asks for name and email sharing; the new user's given and family name are the
      ones entered at Apple; the email is the one from the ID token.
- [ ] **Hide my email:** repeat with "Hide my email" selected (or a second test account). Expected:
      sign-in succeeds with the relay address as the user's email.
- [ ] **Second sign-in, no name:** sign out and sign in again. Expected: Apple sends no name this
      time; the user's stored name is unchanged and no error appears.
- [ ] **Return path:** Apple returns with a cross-site POST. Expected: AnvilID answers it with a
      redirect and finishes on a normal page in the same browser (no "form submission could not be
      verified" error).
- [ ] **Key rotation:** create a new key at Apple, update the Key ID and upload the new `.p8`, sign
      in (works), revoke the old key at Apple, sign in again (works).

## 3. Microsoft

Registration: an app registration in Microsoft Entra ID with a web redirect URI (above) and a
client secret. AnvilID needs the application (client) ID, the secret and the tenant setting:
`common` (personal and work accounts), `organizations`, `consumers`, or one directory's tenant ID.

- [ ] **Personal account (`common` or `consumers`):** sign in with a personal Microsoft test
      account. Expected: success; the link metadata on the user shows the `tid` of the personal
      account directory.
- [ ] **Work account (`common` or `organizations`):** sign in with a work test account. Expected:
      success; `tid` is the work directory.
- [ ] **Email is never trusted:** sign in with a Microsoft account whose email equals `alice@…`.
      Expected: no automatic link; the link confirmation page appears (see section 6), even with
      auto-link on.
- [ ] **Single-directory connection:** set the tenant setting to your directory's tenant ID.
      Expected: a work account of that directory signs in; a personal account or an account from
      another directory is refused with the generic error.
- [ ] **Trusting email requires risk acceptance:** try to turn on email trust for the connection
      in the console. Expected: refused until the "accept the risk" box is ticked; the audit event
      carries the reason `email_trust_risk_accepted`. Turn it off again afterwards.
- [ ] **Secret rotation:** add a second client secret in the app registration, rotate it in
      AnvilID, sign in, delete the old secret, sign in again.

## 4. GitHub

Registration: an OAuth app (or a GitHub App with user authorization) with the authorization
callback URL (above). AnvilID needs the client ID and secret. Scopes requested: `read:user
user:email`.

- [ ] **First sign-in:** sign in with a GitHub test account. Expected: a new user whose email is the
      account's primary verified address; the link subject is the numeric GitHub user id.
- [ ] **Private email:** in the GitHub test account, set the email address to private. Sign in
      again (and with a fresh account if possible). Expected: sign-in still succeeds and uses the
      primary verified address, because AnvilID reads the email list of the API and not the public
      profile.
- [ ] **No verified email:** with an account whose primary email is unverified (if available).
      Expected: a new sign-up is refused with the generic error and audit reason `email_missing`;
      an already linked account still signs in.
- [ ] **Renamed login:** rename the GitHub test account's username, sign in. Expected: the same
      AnvilID user (the link uses the numeric id).
- [ ] **Auto-link:** with a GitHub account whose primary verified email equals `alice@…`. Expected:
      linked automatically (mode `auto`).
- [ ] **Secret rotation:** generate a second client secret at GitHub, rotate it in AnvilID, sign
      in, delete the old secret, sign in again.

## 5. Generic OIDC (optional)

Use any standards-based OpenID provider you control, for example a second AnvilID installation.

- [ ] **Discovery:** create a connection of kind OIDC with the provider's issuer. Expected: the first
      sign-in fetches discovery and signs in; a mistyped issuer gives the generic error and audit
      reason `discovery_failed`.
- [ ] **Untrusted by default:** with email trust off, an email match with `alice@…` leads to the
      confirmation page, not an automatic link.

## 6. Link confirmation and account page

- [ ] **Confirmation path:** turn auto-link off, then sign in with a provider account whose email
      equals `alice@…`. Expected: the "connect your account" page names the provider; signing in
      there with Alice's password links the account (audit `identity_linked`, mode `confirmed`) and
      continues to the client. "Cancel" links nothing.
- [ ] **Confirmation with MFA:** enrol TOTP for Alice and repeat. Expected: the second factor is
      asked after the password, then the link is made.
- [ ] **Confirmation without a password (social-only account):** create Bob by signing in with
      GitHub (no password). With auto-link off, sign in with a Google account whose verified
      email equals Bob's. Expected: the page offers "Continue with GitHub to confirm"
      (only providers Bob is linked to); signing in there with Bob's GitHub account links Google
      (audit `identity_linked`, mode `confirmed`), asks the second factor first if Bob has one,
      and signs in. Signing in there with a GitHub account of another user, or one not linked to
      anybody, links nothing (audit `upstream_login_failed`, reason `link_confirm_mismatch`).
- [ ] **Confirmation by emailed code:** with email sign-in codes on (SMTP configured), repeat the
      previous check. Expected: the page also offers "Email me a sign-in code" for Bob's address
      only; the email carries a code and no link; the code links and signs in.
- [ ] **No way to confirm:** for an account with no password, passkey, linked provider or email
      code, expected: the page says so, points to "Go to linked accounts" (sign in another way,
      then connect the provider there) and "Cancel" returns to the sign-in page.
- [ ] **Microsoft (account not revealed):** with Bob as above (GitHub only, verified email), sign
      in with a Microsoft account whose email equals Bob's. Expected: the page shows no address
      and offers every other enabled provider of the tenant ("Continue with GitHub to confirm",
      "Continue with Google to confirm", …, never Microsoft itself), plus "Email me a code" when
      email sign-in codes are on. Signing in there with Bob's GitHub account links Microsoft
      (mode `confirmed`, second factor first if Bob has one). Signing in with a provider account
      linked to another user or to nobody links nothing (reason `link_confirm_mismatch`, generic
      error). "Email me a code" sends a code (no link) to Bob's address only if it is verified;
      the page after it is the same either way, and the code links and signs in. Repeat with an
      account that has a password and no links: the page looks exactly the same.
- [ ] **Back after signing in:** after a completed upstream sign-in, press the browser's back
      button to the provider's return URL. Expected: "This sign-in was already completed or has
      expired. Please start again." (audit reason `flow_expired`), not the generic error.
- [ ] **Connect from the account page:** signed in as a user without links, open
      `/ui/account/linked` and use **Connect** for a provider. Expected: back on the page with the
      provider listed (audit mode `account`).
- [ ] **Already linked elsewhere:** connect a provider account that is linked to another user.
      Expected: refused ("That account is already connected to another user."); nothing changes.
- [ ] **Disconnect:** disconnect a provider from a user who also has a password. Expected: removed.
      For a user whose only sign-in method is that link, expected: refused ("This is your only way
      to sign in. …"). With email sign-in turned on for the tenant, the refusal does not apply.
- [ ] **Disable a connection:** disable it in the console. Expected: its button disappears from the
      sign-in page and an old start or callback URL is refused.

## 7. Recording the run

Record the result outside this repository or in the release notes, with no secrets, account names
or hostnames:

```
Release:        v0.X.Y (commit …)
Date:           YYYY-MM-DD
Google:         pass | fail | waived (reason)
Apple:          pass | fail | waived (reason)   PKCE check: …
Microsoft:      personal … / work … / single directory …
GitHub:         pass | fail | waived (reason)   private email: …
Generic OIDC:   pass | fail | waived | not run
Linking/account page: pass | fail | waived (reason)
```

After a successful run, update the line below with the date and the release.

Last verified: not yet
