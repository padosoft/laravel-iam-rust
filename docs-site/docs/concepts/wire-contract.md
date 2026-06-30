# The wire contract

Every Laravel IAM SDK — Rust, Node, React Native — and the canonical PHP client speak the **same** HTTP
contract to the server. This SDK mirrors the PHP `Padosoft\Iam\Client\Deciders\HttpDecider` byte-for-byte,
so a request from Rust is indistinguishable from one sent by PHP. This page is the exact specification.

## Motivation

A shared, frozen wire format means the server has a single contract to honour and any client can be
swapped for another without server changes. It also means the request body shape is **not** a place for
creative interpretation: the SDK serializes the documented shape exactly, including fields that are
`null`.

## Endpoints

| Operation | Method + path | SDK method |
|---|---|---|
| Decision check | `POST {base_url}/decisions/check` | `check()` |
| Resource listing | `POST {base_url}/decisions/list-resources` | `list_resources()` |
| JWKS | `GET {base_url}/.well-known/jwks.json` | (internal, for `verify_token()`) |

`base_url` is the versioned API root, e.g. `https://iam.example.com/api/iam/v1`. A trailing slash is
trimmed.

::: callout warning
**Slash, not colon.** The real server route is `decisions/check` (slash form), defined in the server's
`routes/admin.php` / `resources/openapi.yaml`. SDK v1.0.0 shipped the colon form `decisions:check`, which
never matched the route and always `404`'d → denied. **v1.0.1 fixed this** to the slash form. If you are
on `1.0.0`, upgrade.
:::

## Request headers

| Header | Value |
|---|---|
| `Accept` | `application/json` |
| `Authorization` | `Bearer <service token>` — only when a token is configured |

## Request body — `decisions/check`

Serialized verbatim from [`DecisionQuery`](/reference/types), matching PHP `DecisionRequest::toArray()`:

```json
{
  "subject":      { "type": "user", "id": "usr_123" },
  "permission":   "stock.adjust",
  "organization": null,
  "application":  "warehouse",
  "resource":     "wh_milan",
  "context":      { "amount": 300 },
  "current_aal":  "aal1",
  "explain":      false
}
```

Notes that the SDK enforces and that its tests assert exactly:

- `subject` is `{ "type", "id" }` — the field is `type` on the wire (the Rust field is `kind`, renamed via
  serde).
- `resource` is a **plain string**, not an object.
- `organization` is present even when `null` (serde does not skip it).
- `current_aal` defaults to `"aal1"`; `explain` defaults to `false`.

## Response body — `decisions/check`

```json
{
  "allowed":          true,
  "decision_id":      "dec_1",
  "policy_version":   7,
  "requires_step_up": false,
  "required_aal":     null,
  "explanation":      ["role grants stock.adjust"]
}
```

Parsed into [`Decision`](/reference/types) with the same defensive rules as PHP `IamDecision::fromArray`:

| Rule | Effect |
|---|---|
| body is not a JSON object | [`IamError::Malformed`](/reference/errors) → deny |
| `allowed` missing or not boolean `true` | `allowed = false` (deny) |
| `policy_version` missing/wrong type | `0` |
| `decision_id` missing | `""` |
| `explanation` missing/not an array of strings | `[]` |
| any other field wrong-typed | its safe default |

## Request / response — `decisions/list-resources`

Request:

```json
{ "subject": { "type": "user", "id": "usr_123" }, "relation": "viewer" }
```

Response — **either** envelope is accepted:

```json
{ "resources": [ { "type": "warehouse", "id": "wh_milan" } ] }
```

```json
[ { "type": "warehouse", "id": "wh_milan" } ]
```

Each item parses into a [`Resource`](/reference/types) (`{ kind, id }`, `kind` ↔ `type`).

## HTTP status mapping

Applied before any body parsing, identical for both POST endpoints:

| Status | Result |
|---|---|
| `200`–`299` | parse the body |
| `401`, `403` | [`IamError::Unauthorized(status)`](/reference/errors) |
| any other non-2xx | [`IamError::Http(status)`](/reference/errors) |

This mirrors the PHP client, which denies on every non-2xx.

## The `{ "data": ... }` envelope

The server wraps some responses in `{ "data": {...} }`. The decision parser reads the decision fields
defensively from the object it is given; align your server/proxy so the decision object is what reaches
the client (as the PHP client and the other SDKs expect). All SDKs are kept consistent on this point.

## Why mirror PHP exactly

::: collapsible "ADR-0003 — Byte-compatible with the PHP client"
**Problem.** Multiple SDKs must interoperate with one server.

**Decision.** Treat the PHP `HttpDecider` request/response shapes as the canonical contract and mirror
them exactly in Rust — same field names, same `null`s, same defensive parsing, same status mapping.

**Consequences.**
- ✅ Any SDK is a drop-in for any other; the server has one contract.
- ✅ Cross-SDK tests can share fixtures.
- ⚠️ The Rust types carry some PHP-isms (e.g. `resource` as a string, `kind` serialized as `type`) — a
  small price for interoperability, documented here and in [Types](/reference/types).
:::

See also: [Types](/reference/types), [Checking decisions](/guides/checking-decisions),
[Error taxonomy](/reference/errors).
