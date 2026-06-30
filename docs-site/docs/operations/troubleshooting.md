# Troubleshooting

A symptom-driven guide. Because the SDK is fail-closed, most problems present as "everything is denied" —
the table below maps that back to a cause.

## Everything is denied

| Likely cause | How to confirm | Fix |
|---|---|---|
| **On crate v1.0.0** (colon endpoint bug) | Server logs show `404` on `decisions:check` | Upgrade to **≥ 1.0.1** (slash endpoint). See [ADR-0004](/architecture/decisions). |
| Wrong `base_url` (missing `/api/iam/v1`) | `IamError::Http(404)` | Point `base_url` at the versioned API root. |
| Bad/expired service token | `IamError::Unauthorized(401\|403)` | Refresh the Client-Credentials token; check scopes. |
| IAM unreachable | `IamError::Network(..)` / `Timeout` | Check connectivity, DNS, TLS, the server's health. |
| Genuinely no permission | `Ok(Decision { allowed: false })` | The server denied — inspect with `explain: true`. |

::: callout tip
Turn on `explain: true` in the `DecisionQuery` and read `decision.explanation` to see *why* the server
decided as it did.
:::

## `IamError::Config`

| Trigger | Meaning |
|---|---|
| `build()` fails with `Config` | `base_url` was missing or empty. |
| `verify_token()` returns `Config` | `issuer` and/or `audience` not configured. |

`verify_token` requires **both** issuer and audience — set them on the builder. See
[Configuration](/operations/configuration).

## Token verification fails (`IamError::TokenInvalid`)

Work down the pipeline (see [JWT / JWKS verification](/concepts/jwt-verification)):

::: steps
1. **Wrong algorithm** — the token isn't `ES256`. Only ES256 is accepted; check how the token was signed.

2. **Unknown `kid`** — the token's key id isn't in the JWKS. Confirm the server published the key; the SDK
   re-fetches on miss, so a persistent failure means the key truly isn't served.

3. **Bad signature** — payload tampered, or the key doesn't match. `TokenInvalid("signature verification
   failed")`.

4. **Expired / not yet valid** — `exp` in the past or `nbf` in the future. There is **no leeway**: check
   clock sync (NTP) on both ends.

5. **Wrong `iss` / `aud`** — the configured issuer/audience don't match the token's claims. Confirm the
   exact strings.

6. **Malformed** — not three base64url segments, or undecodable JSON header/payload.
:::

## Timeouts under load

`IamError::Timeout` means the request didn't complete within the configured window (default 2s).

- A spike in timeouts usually points at IAM-side latency or saturation, not the client.
- Don't widen the timeout blindly — a long auth timeout stalls every request. Prefer a tight timeout +
  alerting on the timeout rate.
- The SDK does **no** automatic retry; add deliberate, bounded retry/backoff around `check()` if
  appropriate, keeping failures as deny.

## `Malformed` responses

`IamError::Malformed` means a 2xx body the SDK couldn't parse into the expected shape (not a JSON object,
or wrong-shaped). Causes:

- A proxy/load balancer returned an HTML error page with a 200.
- The server response isn't the expected decision object (check the `{ "data": ... }` envelope alignment —
  see [The wire contract](/concepts/wire-contract)).

## Build issues

| Symptom | Cause | Fix |
|---|---|---|
| `build_blocking()` not found | `blocking` feature not enabled | Add `features = ["blocking"]`. |
| `.await` won't compile on a method | You're on the blocking client | Drop `.await` (blocking) or use the async client. |
| Deadlock/panic from the blocking client | Called inside an async runtime | Use the async client, or `spawn_blocking`. |

There should be **no** OpenSSL/C-toolchain errors from token verification — that path is pure-Rust
`p256` ([ADR-0001](/architecture/decisions)). If you see linker errors they come from `reqwest`'s
`native-tls`, not the crypto.

## Diagnostic checklist

::: steps
1. **Version ≥ 1.0.1?** (`cargo tree -i laravel-iam`)
2. **`base_url` includes the API version?**
3. **Service token valid and unexpired?**
4. **For `verify_token`: issuer + audience set, clocks synced?**
5. **Reproduce with `explain: true`** and read the explanation.
6. **Check IAM server health/logs** for the matching request.
:::

See also: [Configuration](/operations/configuration), [Error taxonomy](/reference/errors),
[The check flow](/architecture/check-flow).
