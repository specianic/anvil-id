# Security policy

AnvilID is an identity provider: a vulnerability in it can expose every application that trusts it.
We take reports seriously and fix them in the open-source release.

## Supported versions

Security fixes are released for the versions below. Upgrade to a supported version before reporting
a problem that only affects an unsupported one.

Until 1.0.0 is released:

| Version | Supported |
| --- | --- |
| Latest 1.0 prerelease (beta, release candidate) | Yes |
| 0.4.x | Yes |
| 0.3.x and earlier | No |

Once 1.0.0 is released (this table replaces the one above at release):

| Version | Supported |
| --- | --- |
| 1.0.x | Yes |
| 1.0 prereleases (beta, release candidate) | No |
| 0.x | No |

Later minor and major lines will be added to this table with their support window. The compatibility
and upgrade policy is described in [docs/UPGRADING.md](docs/UPGRADING.md).

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through **GitHub private vulnerability reporting**:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Fill in the form. The report is visible only to you and the maintainers.

A useful report contains:

- the affected version (`anvilid --version`) or commit, and the storage backend (SQLite or PostgreSQL);
- the relevant configuration, with every secret removed;
- the steps to reproduce, the expected and the actual behaviour;
- the impact as you understand it (for example: token forgery, account takeover, cross-tenant access,
  information disclosure, denial of service).

Please test only against your own installation. Do not access other people's data, do not degrade a
service you do not operate, and do not run automated scanners against deployments you do not own.

## What happens next

These are targets, not contractual guarantees:

| Step | Target |
| --- | --- |
| Acknowledgement of the report | within 5 working days |
| Initial assessment (confirmed or not, severity) | within 14 days |
| Fix released for critical and high severity issues | as soon as possible, aiming for 30 days |
| Fix released for medium and low severity issues | aiming for 90 days |

We keep you informed while we work on the fix and agree a disclosure date with you. If a fix takes
longer than the target, we tell you why and what the new date is.

## Coordinated disclosure

- Each confirmed vulnerability is handled in a **GitHub Security Advisory** for this repository. The
  fix is developed privately (in the advisory's temporary private fork) until it is released.
- We request a **CVE** identifier for every confirmed vulnerability through the advisory.
- **Fixes ship in the open-source release.** There is no private or paid fixed edition. A security fix
  is released as a patch version of every supported line, together with the published advisory, the
  CVE, the affected and fixed versions and any workaround.
- The release notes and [docs/UPGRADING.md](docs/UPGRADING.md) point to the advisory when an upgrade
  needs operator action.
- With your permission, we credit you in the advisory.

We ask reporters to keep the details private until the advisory is published, or until the agreed
disclosure date if a fix is not ready by then.

## Scope

In scope: the `anvilid` binary and container image published from this repository, its protocol
endpoints, the hosted login and account pages, the admin API and console, the CLI, the storage
backends and the release artefacts (archives, image, provenance attestations).

Out of scope:

- deployments that switch off documented protections (for example development mode on a public
  network, or rate limiting disabled), unless the documentation fails to warn about it;
- vulnerabilities in third-party dependencies that do not affect AnvilID (please report those to the
  dependency's maintainers; tell us if AnvilID is affected);
- reports produced only by automated tools without a demonstrated impact;
- social engineering and physical attacks.

The threat model and the controls each security test covers are described in
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). The scope of the external security review is in
[docs/SECURITY-REVIEW-SCOPE.md](docs/SECURITY-REVIEW-SCOPE.md).
