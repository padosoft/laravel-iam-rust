---
name: docmd-docs
description: >-
  Author and maintain the public documentation site for laravel-iam-rust, built with docmd and living
  in docs-site/. Use this skill whenever working inside docs-site/ — adding or editing pages under
  docs-site/docs/**, touching navigation[] or plugins in docmd.config.json, changing the brand/footer,
  or keeping the docs in sync with a crate feature or README change. Covers the docmd container syntax,
  Lucide icons, semantic search setup, the page-structure standard, build/check commands, and the
  known gotchas.
---

# docmd docs for laravel-iam-rust

The documentation site lives in `docs-site/` and is built with [docmd](https://docs.docmd.io) — a
static-site generator over plain Markdown + `:::` containers (no MDX/JSX). The build is **pure Node**
(`npm ci` + `npm run build`); it does **not** require the Rust toolchain. Deploy is Cloudflare Pages
(Git integration), done by the maintainer — do not add deploy CI.

## Layout

```
docs-site/
  docmd.config.json          # metadata, url, navigation[], theme, plugins
  package.json               # scripts: dev / build / check
  package-lock.json          # lockfileVersion 3, cross-platform (Linux natives) — verify with `npm ci`, don't regenerate
  .node-version              # "20"
  .gitignore                 # ignores _site/, node_modules/, search cache (keeps .docmd-search/config.json)
  .docmd-search/config.json  # pinned embedding model (committed)
  assets/favicon.svg, custom.css   # brand teal #0d9488
  scripts/check-no-raw-html.mjs    # CI guard against raw HTML / ::: button
  docs/                      # all .md pages — route mirrors the tree (docs/guides/x.md -> /guides/x)
  _site/                     # build output (git-ignored)
```

Route rule: `docs/index.md` → `/`; `docs/foo/bar.md` → `/foo/bar`.

## Commands

```bash
cd docs-site
npm ci          # install from the committed lockfile (preferred over npm install)
npm run check   # guard: no raw HTML/MDX tags, no ::: button
npm run build   # generates _site/ (+ semantic index, llms.txt, sitemap.xml)
npm run dev     # local preview
```

The first build downloads the embedding model; subsequent builds reuse the cache.

## Navigation

`navigation[]` in `docmd.config.json` is the **only** source of the sidebar — it does not auto-generate.
**Every new page must be added there** or it will not appear. Group with `children`; icons are
[Lucide](https://lucide.dev) names in kebab-case (`rocket`, `book-open`, `shield-check`, `workflow`,
`settings`, `book-marked`, `square-function`, `lightbulb`).

## Container syntax (no MDX/JSX — the guard rejects raw tags)

| Need | Syntax |
|---|---|
| Callout | `::: callout info` … `:::` (types: `info`, `tip`, `warning`, `danger`, `success`) |
| Tabs | `::: tabs` then `== tab "Label"` blocks, close `:::` |
| Steps | `::: steps` then a numbered list `1. **Title**` with body indented **3 spaces**, close `:::` |
| Collapsible | `::: collapsible "Title"` … `:::` (prefix `open` to expand by default) |
| Cards | `::: grids` › `::: grid` › `::: card "Title" icon:lucide-name` › body › `[Open →](/path)` › `:::` |
| Diagrams | ` ```mermaid ` fence (flowchart, sequenceDiagram, …) |
| Math | KaTeX `$…$` inline, `$$…$$` block |

Inside a card use a Markdown link `[Open →](/path)` — **`::: button` is not supported** (the guard fails on it).

## Plugins (all enabled)

search (semantic), git (edit links / last-updated), seo, sitemap, mermaid, math, llms, analytics(off).
`sitemap`/`seo`/`llms` need the root `url`. `git` needs `repo`.

## Semantic search

`plugins.search.semantic: true` uses `docmd-search`: embeddings are computed at **build time** via ONNX,
the browser gets quantized Int8 vectors (100% client-side). The model is pinned in
`.docmd-search/config.json` (`Xenova/all-MiniLM-L6-v2`) — this **skips the interactive wizard** that
would otherwise hang CI. Keep that file committed; ignore the rest of `.docmd-search/`.

## Page-structure standard

Deep pages follow: **Motivation → Theory (KaTeX where apt) → Design + Mermaid → Data/contract →
ADR (`::: collapsible`, Problem→Decision→Consequences) → Worked example → Gotchas (`::: callout warning`)**.
Write to what the crate actually does — cite real symbols (`IamClient`, `DecisionQuery`, `ResultExt`,
`IamError`, `wire.rs`) and real endpoints (`/decisions/check` slash form). Accuracy over volume.

## Brand & footer

Teal `#0d9488` in `assets/custom.css`. Footer credits Lorenzo Padovani / Padosoft, MIT, links to GitHub +
crates.io + docs.rs.

## Gotchas

1. `docs/index.md` is mandatory (route `/`).
2. `::: button` is not a block — use a Markdown link inside cards.
3. Steps body must be indented **3 spaces** so nested fences/callouts stay in the item.
4. KaTeX only processes `$…$` outside code blocks.
5. Use the committed cross-platform lockfile; verify with `npm ci`, don't regenerate on Windows.
6. The docs build needs **no Rust toolchain** — pure Node.
