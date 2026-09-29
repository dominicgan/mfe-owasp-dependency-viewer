# MFE Dependency Report Viewer

A browser-based viewer for **OWASP dependency-check** reports across a fleet of
micro-frontends. Drop in every MFE's `dependency-check-report.json` at once and
get one pooled dashboard: which version bumps clear the most, which packages are
shared, where the versions have drifted apart, and which scan is too old to
trust.

The files never leave the machine — parsing happens in the browser.

```bash
npm install
npm run dev
```

Then drop your reports on the page, or click **Load sample estate** to use the
bundled four-MFE fixture.

## Why pool the reports

A dozen micro-frontends on one stack share most of their dependency tree, so the
same four advisories turn up a dozen times. Read one report at a time and you
get a per-team to-do list that is mostly the same to-do list. Read them together
and the question changes from *"how many findings do we have"* to **"which
handful of bumps clears most of them, and who has to be involved."**

On the bundled sample — 4 MFEs, 26 findings, 10 distinct advisories — the answer
is five package upgrades:

```
package              bump to      closes  MFEs  cumulative
fast-uri             3.1.6            12     3   46%
adm-zip              0.6.1             6     3   69%
js-yaml              4.3.2             3     3   81%
tar-fs               3.0.10            2     2   88%
@faker-js/faker      > 10.4.0          2     2   96%
```

That shape — a steep curve over a handful of shared packages — is the argument
for fixing centrally rather than filing four tickets per team.

## Where "fixed in" comes from

This is the load-bearing claim in the whole tool, so it is worth being precise
about.

Every advisory in a dependency-check report carries a CPE with a machine-readable
version range:

```
cpe:2.3:a:*:adm-zip:\<0.6.1:*:*:*:*:*:*:*          ->  < 0.6.1
cpe:2.3:a:*:fast-uri:\>\=3.1.3\<3.1.6:*:*:*:*:*:*  ->  >= 3.1.3, < 3.1.6
cpe:2.3:a:*:\@faker-js\/faker:\<\=10.4.0:*:*:*:*:* ->  <= 10.4.0
```

An **exclusive** upper bound is a statement that the named version is clean, so
`<3.1.6` yields an exact target of `3.1.6`. An **inclusive** upper bound is not:
`<=10.4.0` only says everything up to 10.4.0 is affected, so the constraint is
`> 10.4.0` and the report names no release to move to. Those are different
situations and the UI keeps them apart:

| Fix state | Meaning |
|---|---|
| **Fix available** | The advisory excludes a version, so there is an exact release to bump to |
| **Later release** | Upper bound is inclusive — a fix exists somewhere after it, but the report does not say where |
| **No fix info** | The advisory carries no machine-readable range at all |

Three rules follow from this:

1. **Fix versions are never parsed out of the advisory's prose.** A description
   saying *"upgrade to 2.4.5, 3.1.6, or 4.1.3"* is not read. It is usually
   right, it is occasionally stale, and it is not structured — so it is shown to
   you and not acted on.
2. **Every derived fix records the range it came from.** Hover any fix badge and
   it tells you which CPE range produced it and why that range was the one
   picked (an advisory can list several).
3. **A package's target version is the strongest constraint across all of its
   advisories**, so the Remediation view gives one number that satisfies every
   advisory against that package at once, rather than a per-advisory list to
   reconcile by hand. `adm-zip` is hit by `<0.6.1` and `>=0.5.9<=0.6.0`; the
   combined answer is **0.6.1**.

CPE parsing honours escaping — package names like `\@faker-js\/faker` contain
escaped separators, and a naive `split(':')` gets them wrong.

## The determinism contract

The same files always produce the same dashboard:

1. **One finding is one (MFE × dependency × advisory) tuple.** A package hit by
   four advisories is four rows, because four rows is what you work through —
   but they roll up to one upgrade in Remediation.
2. **Nothing is inferred from field order.** The report is read by key, so a
   dependency-check upgrade that reorders its output lands identically.
3. **Row identity is content-derived** — a hash of report, dependency, advisory
   and path. Each report also carries a `fingerprint` (visible under the ⓘ
   button); two parses of the same bytes always produce the same one.
4. **Findings are sorted worst-first at parse time**, so neither the fingerprint
   nor the default grid order depends on the order dependency-check emitted.

Verify any set of reports against these rules without opening the UI:

```bash
npm run verify                          # the bundled sample estate
npm run verify -- path/to/*.json        # your own reports
```

It prints each report's breakdown and the pooled remediation plan, then asserts
that re-parsing is stable, that row ids are unique, that **every derived fix
version really does fall outside the range it came from**, that it is actually
higher than the installed version, and that the rollup arithmetic adds up.

## The workspace

Reports accumulate. Each is named from its own `projectInfo.name`, and you can
rename it in the **MFEs** panel — a rename survives that MFE's next scan.

Two kinds of collision, handled differently because they mean different things:

| Situation | Behaviour |
|---|---|
| Same file twice (identical bytes) | Ignored, and said so — re-dropping a folder is not a mistake worth punishing |
| Same MFE, newer scan | **Replaces** the old report. Keeping both would double-count every finding in it |
| Same MFE, *older* scan | Replaces, but warns — you probably grabbed the wrong file |

The whole set is kept in **IndexedDB**, so a reload does not mean re-dropping a
dozen files. Nothing is uploaded; this is the same machine's disk. There is a
**Clear all** in the MFEs panel.

Only `.json` is accepted. The HTML and XML reports are renderings of the same
scan and drop the CPE ranges everything above depends on, so dropping one gives
you a specific error rather than a silent empty dashboard.

### Scan age is part of the reading

Two reports scanned three weeks apart are not directly comparable — the older
one was measured against an older advisory database, so a lower count there is
not necessarily better news. Reports older than 30 days are flagged in the MFEs
panel and in the **By MFE** grid, the stalest scan is a KPI tile, and the ⓘ popover
surfaces the NVD "last modified" timestamps that bound what any of the scans
could possibly have known.

## Views

- **Overview** — KPI tiles and charts, led by the remediation curve. Every tile,
  bar and slice is a filter: click it.
- **Remediation** — one row per package: *"if I bump this one dependency, how
  many findings close and which MFEs do I have to touch?"* Sorted by findings
  closed, because that is the order the work should be done in. Shows the target
  version, the versions currently in play, a **drift** flag when MFEs disagree,
  and a **left over** count for findings the bump provably does not clear.
- **By MFE** — the scorecard. Per-MFE severity counts, bumps to do, and the
  split between **shared** debt (in a package someone else also has) and
  **only here** (this team fixes it alone).
- **By advisory** — one row per advisory with its blast radius across the estate.
- **Findings** — the full grid, every field available via the column chooser,
  per-column filters, and a detail sheet on any row.

Each view exports the current selection to CSV.

## Filtering

The left sidebar facets every dimension in the reports. Counts are computed
against the rows surviving all *other* filters, so selecting one value does not
zero out its siblings — in a single pass over the rows rather than one scan per
open facet.

Two filters sit permanently in the toolbar because they are the reason the
reports are pooled at all:

- **Shared only** — packages more than one MFE carries.
- **Fixable** — findings whose advisory names an exact clean version.

**Filter state lives in the URL.** A filtered view is a shareable link and
survives a reload. The reports stay local, so a link only opens meaningfully for
someone whose workspace holds the same MFEs — which is the team this is for.

## Advisory enrichment

These reports are dominated by **GHSA** ids, not CVEs, because npm audit is what
finds most of it. That drives the linking behaviour: NVD and MITRE cannot resolve
a GHSA at all, so those links are simply not offered on a GHSA row, and the
default lookup target is **OSV**, which takes both. An identifier no database
accepts renders as plain text rather than a dead link.

Hovering an advisory opens a preview in two layers:

1. **Instantly**, from the report — severity, CVSS, derived fix, the affected
   range, and which MFEs it hits.
2. **Then live**, from [OSV](https://osv.dev) and
   [FIRST EPSS](https://www.first.org/epss/): the OSV summary, fixed versions per
   ecosystem, aliases, and an exploit-probability bar. EPSS is keyed by CVE, so
   it is queried with the CVE recovered from the advisory's own NVD reference,
   and the card says so when there is no CVE to ask about.

> **Why this is not an iframe of the advisory page.** NVD, MITRE and CISA all
> serve `X-Frame-Options: DENY` and a `frame-ancestors` CSP, so a browser refuses
> to render them in a frame — an embedded preview of those pages is blank by
> design, not by misconfiguration. These two APIs are the CORS-enabled sources
> that let the same information be shown natively.

Lookups fire only on hover, are cached for the session, and send **only the
identifier** — no report content leaves the machine. If your environment does not
permit calls to third-party APIs from an analyst's browser, turn them off under
the 🔗 menu; the card then shows the report's own data only. That preference is
remembered.

## Derived fields

Computed, never read from the report:

| Field | How |
|---|---|
| **Fix state / Fixed in** | From the advisory's CPE range, as described above. Records its own reasoning. |
| **Exposure** | From the CVSS vector: `AV:N` + `PR:N` + `UI:N` is *Remote, unauthenticated*. Answers "can someone on the internet do this without an account", which severity alone does not. |
| **Scope** | Direct vs transitive, from the report's project references. A package reached both ways counts as Direct — that is the reference you can actually edit. |
| **CVSS vector** | Recomposed from the fields the report decomposes it into. |
| **CVE** | The advisory id when it is one, otherwise recovered from its NVD reference. |
| **Spread** | How many MFEs carry a package. A property of the workspace, computed over *unfiltered* rows so narrowing the view does not make the shared-dependency filter fight itself. |
| **Scan age** | Days since the report was generated. |

## Severity

npm audit scores on five levels, so the scale has five real steps —
`critical / high / moderate / low / info` — plus `Unknown` for an advisory with
no severity at all. `moderate` is npm's name for Medium. `Info` is a real
severity and is kept distinct from "we have no severity for this".

Severity is treated as a **status** scale, not a series palette: its steps are
fixed in both light and dark, and every severity renders with its text label, so
hue never carries the meaning alone.

## Stack

- **Vite + React 19 + TypeScript**
- **Tailwind v4** + **shadcn/ui** components (vendored into `src/components/ui`)
- **ag-grid-community** 36 — row virtualisation
- **Recharts** 3 via shadcn-style chart wrappers

ag-grid and Recharts are ~440kB gzipped between them and none of it is needed to
paint the upload screen, so the whole dashboard sits behind a `lazy()` boundary
and is not fetched until there is a report to show. The eager entry chunk is
~104kB gzipped.

## Project layout

```
src/
  lib/
    schema.ts        canonical fields, severity scale, CPE range + version logic
    parse.ts         dependency-check JSON -> findings, report meta, fingerprint
    workspace-store.ts  the loaded set of reports, persisted in IndexedDB
    filters.ts       filter model, faceting, URL serialisation, package spread
    stats.ts         KPIs, breakdowns, package/advisory/MFE rollups, fix plan
    advisory.ts      advisory database links (GHSA- and CVE-aware)
    advisory-data.ts live OSV + EPSS lookup for the hover card
    grid-theme.ts    shared ag-grid theming and column defaults
    format.ts        number/date formatting (UTC)
  hooks/
    use-workspace.ts multi-report ingestion, renaming, filters
  components/
    ui/              shadcn primitives
    charts/          dashboard charts
    ...              facet panel, grids, detail sheet, report manager, toolbar
  App.tsx            upload / hydrate states + the lazy boundary
  dashboard.tsx      everything behind it
scripts/
  verify-parse.ts    parser smoke test / determinism check
  make-samples.mjs   regenerates the bundled sample estate
```

## The sample estate

`public/samples/` holds four synthetic micro-frontends, regenerated with
`npm run samples`. The vulnerability payloads are verbatim from a real report;
the estate around them is not. It is built to exercise everything above: a
package shared by three MFEs at two different versions, all three fix states, a
Critical in two MFEs, and one deliberately stale scan.
