# API reference

AnvilID's public HTTP APIs are described by OpenAPI 3.1 documents. The committed copies below are
generated from the handlers and checked against the code by drift tests in CI; the
[compatibility policy](COMPATIBILITY.md) says which changes each version may contain.

| API | Document | Guide |
| --- | --- | --- |
| Management API (`/api/admin/v1`) | [`openapi/admin-v1.json`](openapi/admin-v1.json) | [Installing: next steps](INSTALL.md#next-steps) |
| Headless flow API (`/api/flows/v1`) | [`openapi/flows-v1.json`](openapi/flows-v1.json) | [Headless flow API](HEADLESS.md) |

A running server also serves the management API document at `/api/admin/v1/openapi.json`.

The declarative tenant configuration has a JSON Schema,
[`schemas/tenant-config-v1.json`](schemas/tenant-config-v1.json); see
[Declarative tenant configuration](CONFIG-YAML.md).
