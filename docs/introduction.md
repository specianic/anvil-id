# Introduction

AnvilID is an open-source identity and access platform built to be easy to self-host. It ships as a
single binary that starts with no configuration (SQLite by default, Postgres for several nodes) and
provides an OpenID Connect provider, sign-in with passwords, passkeys and TOTP, self-service account
pages, a management API and an admin console.

The source code, releases and issue tracker live at
[github.com/specianic/anvil-id](https://github.com/specianic/anvil-id).

## Where to start

- **Running AnvilID:** [Operating AnvilID](OPERATIONS.md) covers deployment, configuration keys,
  backups, high availability and metrics. [Upgrading](UPGRADING.md) lists what changes between
  releases.
- **Managing tenants as code:** [Declarative tenant configuration](CONFIG-YAML.md).
- **Connecting applications and services:** [MCP servers](MCP.md), [Webhooks](WEBHOOKS.md),
  [Organizations and enterprise SSO](ORGANIZATIONS.md) and [SAML 2.0 connections](SAML.md).
- **How it is designed:** the [product requirements](PRD.md) and the [architecture](ARCHITECTURE.md).
- **Release artifacts and how to verify them:** [Releasing](RELEASING.md).
