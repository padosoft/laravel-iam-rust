# Rule: keep the docmd docs in sync with the crate (binding)

This rule is **binding and blocking**. It governs every change to `laravel-iam-rust`.

## The rule

**Whenever you add or change a user-facing feature of the crate, or update the README in a substantial
way, you MUST update the corresponding docmd page under `docs-site/docs/**` in the same unit of work** —
and register any new page in `navigation[]` of `docs-site/docmd.config.json`. Follow the `docmd-docs`
skill for syntax and structure.

"User-facing" includes, non-exhaustively:

- A new or changed public method on `IamClient` / `blocking::IamClient` (`check`, `list_resources`,
  `verify_token`) or builder option (`base_url`, `token`, `timeout`, `issuer`, `audience`).
- A change to a wire type (`Subject`, `Resource`, `DecisionQuery`, `Decision`, `Claims`) or an
  `IamError` variant.
- A change to the wire contract / endpoints (e.g. `/decisions/check`), status mapping, or fail-closed
  behaviour.
- A new Cargo feature (e.g. another transport) or a change to `blocking`.
- A change to token-verification semantics (algorithm, claim validation, JWKS handling).

When such a change lands, update the matching page(s): the relevant guide, the reference
(`reference/api.md`, `reference/types.md`, `reference/errors.md`), the concept page, and an ADR entry in
`architecture/decisions.md` for a significant or hard-to-reverse decision.

## When the docs do NOT need updating

Declare this explicitly in the changelog / PR description:

- Internal refactors with no public-API or behaviour change.
- Tooling/CI/build-only changes.
- Cosmetic edits (formatting, typos) with no semantic effect.

## Definition of done (blocking)

Before considering the work complete, from `docs-site/`:

```bash
npm run check   # must pass (no raw HTML/MDX, no ::: button)
npm run build   # must succeed (22+ pages, semantic index, sitemap, llms.txt)
```

Both must be green. The docs build is pure Node — it does not require the Rust toolchain.

## Anti-patterns (reject these)

- A user-facing feature shipped without its doc page.
- A new page that is not registered in `navigation[]` (it will be invisible).
- MDX/JSX or raw HTML tags in Markdown, or `::: button` (the guard rejects them).
- Documenting behaviour the crate does not actually have — accuracy over volume; cite real symbols.
- Regenerating the lockfile on Windows instead of verifying the committed cross-platform one with
  `npm ci`.
