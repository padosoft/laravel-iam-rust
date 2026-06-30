# Architecture decision records

The significant, hard-to-reverse choices behind the crate, each as *Problem → Decision → Consequences*.
Several are referenced from elsewhere in these docs.

## ADR-0001 — Pure-Rust crypto (p256) for token verification

::: collapsible open "ADR-0001"
**Problem.** ES256 verification can be done with the popular `jsonwebtoken` crate, which pulls in a
C-backed crypto stack (OpenSSL / ring). That makes cross-compilation, musl/Alpine containers, and
Windows builds fiddly — you must have a working C toolchain and the right OpenSSL to link.

**Decision.** Verify signatures with [`p256`](https://crates.io/crates/p256) from the **RustCrypto**
project (`ecdsa` + `std` features), reconstructing the public key from the JWK's `x`/`y` coordinates as a
SEC1 point and calling `VerifyingKey::verify`. No C, no OpenSSL.

**Consequences.**
- ✅ Portable builds: trivial cross-compilation, small static binaries, simple containers — nothing to
  link.
- ✅ `#![forbid(unsafe_code)]` stays credible; the whole verification path is safe Rust.
- ✅ One fewer class of "works on my machine" toolchain failures.
- ⚠️ We depend on a pure-Rust ECDSA implementation rather than a FIPS-validated C library; for the IAM
  server's EC P-256 / ES256 tokens this is the right trade. Algorithm support is intentionally limited to
  ES256.

**Lesson (toolchain).** Choosing pure-Rust crypto removed an entire category of build pain. For a thin
client SDK that will be vendored into many environments, "no native dependencies" is a feature, not an
afterthought.
:::

## ADR-0002 — Async-first, with an optional blocking twin

::: collapsible "ADR-0002"
**Problem.** Most consumers are async (web servers under `tokio`), but CLIs, build scripts, and sync
services also need to authorize, and forcing them to spin up a runtime is hostile.

**Decision.** Ship the async `IamClient` by default and a synchronous `blocking::IamClient` behind the
`blocking` Cargo feature. Keep all decision logic in a transport-agnostic `wire` module so the two clients
share it byte-for-byte; they differ only in `reqwest::Client` vs `reqwest::blocking::Client` and the
`RwLock` flavour for the JWKS cache.

**Consequences.**
- ✅ Async users pay nothing for blocking; blocking is opt-in.
- ✅ The two clients cannot drift in semantics — the shared `wire` module is the single source of truth.
- ⚠️ The blocking client must not be called from an async runtime thread (it drives its own runtime). This
  is documented loudly; see [The blocking client](/guides/blocking-client).
:::

## ADR-0003 — Byte-compatible with the canonical PHP client

::: collapsible "ADR-0003"
**Problem.** The IAM server has one wire contract, exercised first by the PHP client
(`Padosoft\Iam\Client\Deciders\HttpDecider`). Multiple SDKs must interoperate with that one server.

**Decision.** Mirror the PHP request/response shapes exactly: same field names (e.g. `subject.type`,
`resource` as a plain string), emit `null` fields rather than skipping them, and parse responses with the
same defensive `fromArray` rules and status mapping. The crate's tests assert the exact body shape with
`wiremock` `body_json`.

**Consequences.**
- ✅ Any SDK is a drop-in for any other; the server honours a single contract.
- ✅ Cross-SDK fixtures and conformance tests are shareable.
- ⚠️ A few PHP-isms surface in the Rust types (`kind` serialized as `type`, `resource: Option<String>`);
  documented in [Types](/reference/types) and [The wire contract](/concepts/wire-contract).
:::

## ADR-0004 — Endpoint uses the slash form `decisions/check`

::: collapsible "ADR-0004"
**Problem.** v1.0.0 of this crate posted to `decisions:check` (colon form). The server's real route —
`routes/admin.php`, `resources/openapi.yaml` — is `decisions/check` (slash form). The colon URL never
matched, so the server `404`'d and the client, being fail-closed, denied **every** request.

**Decision.** Use the slash form `{base}/decisions/check` and `{base}/decisions/list-resources`, matching
the real server routes. Fixed in **v1.0.1**.

**Consequences.**
- ✅ `check()` reaches the PDP and returns real decisions.
- ✅ Aligned with the PHP client and the other SDKs.
- ⚠️ Anyone pinned to `1.0.0` silently denied everything; **upgrade to ≥ 1.0.1**. This is the textbook
  argument *for* fail-closed: the bug degraded safely (deny-all) instead of dangerously (allow-all).
:::

## ADR-0005 — No fail-open switch in the transport

::: collapsible "ADR-0005"
**Problem.** Operators ask for a global "degrade open on outage" toggle.

**Decision.** The transport is always fail-closed; there is no such flag. Outage tolerance, where truly
required, is written explicitly at the application layer for specific low-risk actions and only for
outage-class errors (`Timeout`/`Network`).

**Consequences.**
- ✅ A misconfiguration can never silently open every gate.
- ✅ The safe state needs zero configuration.
- ⚠️ Degradation must be hand-written and reviewed — by design. See
  [Fail-closed patterns](/guides/fail-closed-patterns) and [Fail-closed authorization](/concepts/fail-closed).
:::

## ADR-0006 — `requires_step_up` is treated as *not allowed*

::: collapsible "ADR-0006"
**Problem.** The server can return `allowed: true` together with `requires_step_up: true`, meaning "in
principle yes, but re-authenticate at a higher assurance level first". A naive client that reads only
`allowed` would let the action through prematurely.

**Decision.** Define `Decision::granted()` as `allowed && !requires_step_up`, and make both
`Decision::is_allowed()` and `ResultExt::is_allowed()` use `granted()`. A pending step-up is **not**
allowed.

**Consequences.**
- ✅ The fail-safe gate value already accounts for step-up; callers cannot forget it.
- ✅ Step-up-aware UX is still possible by inspecting `requires_step_up` / `required_aal` on the `Ok`.
- ⚠️ Callers who genuinely want the raw boolean must read `Decision::allowed` explicitly — and should
  rarely need to.
:::

See also: [Fail-closed authorization](/concepts/fail-closed), [The wire contract](/concepts/wire-contract),
[The blocking client](/guides/blocking-client).
