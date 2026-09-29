import type { Finding } from './parse'

/**
 * Filter state is a plain, serialisable object: every filtered view is fully
 * described by this value, which is what makes a URL shareable and a reload
 * land on exactly the same view.
 */
export interface FilterState {
  /** Free-text search across searchable fields. */
  q: string
  /** key -> selected values. Empty/absent means "no constraint on this key". */
  facets: Record<string, string[]>
  /** Inclusive CVSS range; undefined ends are open. */
  cvssMin?: number
  cvssMax?: number
  /** Only rows where a fixed version could be derived. */
  fixableOnly: boolean
  /**
   * Only packages that appear in at least this many MFEs. The whole point of
   * pooling the reports is to find the shared ones, so this is a first-class
   * filter rather than something to reconstruct by hand.
   */
  minMfes?: number
}

export const EMPTY_FILTERS: FilterState = { q: '', facets: {}, fixableOnly: false }

/** Fields free-text search looks at. */
const SEARCH_KEYS = [
  'mfe', 'advisory', 'cve', 'packageName', 'packageVersion', 'purl', 'ecosystem',
  'description', 'cwe', 'fixedIn', 'source', 'projectRef', 'filePath',
]

function buildHaystack(r: Finding): string {
  let s = ''
  for (const k of SEARCH_KEYS) {
    const v = r[k]
    if (v) s += String(v).toLowerCase() + ' '
  }
  return s
}

const haystacks = new WeakMap<Finding, string>()

function haystackOf(r: Finding): string {
  let h = haystacks.get(r)
  if (h === undefined) {
    h = buildHaystack(r)
    haystacks.set(r, h)
  }
  return h
}

export function hasActiveFilters(f: FilterState): boolean {
  return (
    f.q.trim() !== '' ||
    f.fixableOnly ||
    f.cvssMin != null ||
    f.cvssMax != null ||
    (f.minMfes != null && f.minMfes > 1) ||
    Object.values(f.facets).some((v) => v.length > 0)
  )
}

export function countActiveFilters(f: FilterState): number {
  let n = 0
  if (f.q.trim()) n++
  if (f.fixableOnly) n++
  if (f.cvssMin != null || f.cvssMax != null) n++
  if (f.minMfes != null && f.minMfes > 1) n++
  for (const v of Object.values(f.facets)) if (v.length) n++
  return n
}

/** Tokenised AND search: every whitespace-separated term must appear. */
function matchesQuery(r: Finding, terms: string[]): boolean {
  if (!terms.length) return true
  const hay = haystackOf(r)
  for (const t of terms) if (!hay.includes(t)) return false
  return true
}

/**
 * How many distinct MFEs each package appears in.
 *
 * Computed over the *unfiltered* rows on purpose: "this package is in 6 MFEs"
 * is a fact about the estate, not about the current selection, and recomputing
 * it against the filtered set would make the shared-dependency filter fight
 * itself as you narrow down.
 */
export function packageSpread(rows: Finding[]): Map<string, number> {
  const seen = new Map<string, Set<string>>()
  for (const r of rows) {
    const pkg = r.packageName
    if (!pkg) continue
    let set = seen.get(pkg)
    if (!set) {
      set = new Set()
      seen.set(pkg, set)
    }
    set.add(r.mfe)
  }
  const out = new Map<string, number>()
  for (const [pkg, set] of seen) out.set(pkg, set.size)
  return out
}

export interface FilterContext {
  /** packageName -> number of MFEs it appears in, over the whole workspace. */
  spread: Map<string, number>
}

export const EMPTY_CONTEXT: FilterContext = { spread: new Map() }

export function applyFilters(rows: Finding[], f: FilterState, ctx: FilterContext = EMPTY_CONTEXT): Finding[] {
  const terms = f.q.trim().toLowerCase().split(/\s+/).filter(Boolean)
  const facetSets = Object.entries(f.facets)
    .filter(([, v]) => v.length > 0)
    .map(([k, v]) => [k, new Set(v)] as const)

  return rows.filter((r) => {
    for (const [k, set] of facetSets) {
      const v = r[k]
      if (!set.has(v == null || v === '' ? '(blank)' : String(v))) return false
    }
    return passesNonFacet(r, f, terms, ctx)
  })
}

export interface FacetValue {
  value: string
  /** Rows matching this value under every *other* active filter. */
  count: number
  selected: boolean
}

function facetValueOf(r: Finding, key: string): string {
  const raw = r[key]
  return raw == null || raw === '' ? '(blank)' : String(raw)
}

/**
 * Facet counts for several facets in a single pass.
 *
 * Each facet must be counted against the rows surviving every *other* filter,
 * so selecting a value doesn't zero out its siblings. Done naively that is one
 * full scan per open facet. Instead, walk the rows once and count how many
 * facet constraints each row fails:
 *
 *   fails 0  -> the row survives everything, so it counts toward every facet
 *   fails 1  -> it counts toward exactly that one facet (which ignores itself)
 *   fails 2+ -> it counts toward nothing
 *
 * Non-facet constraints (search, CVSS, fixability, spread) are not per-facet,
 * so a row failing any of them is dropped up front.
 */
export function facetValuesMany(
  rows: Finding[],
  f: FilterState,
  keys: string[],
  ctx: FilterContext = EMPTY_CONTEXT,
  limit = 500,
): Map<string, FacetValue[]> {
  const constraints = Object.entries(f.facets)
    .filter(([, v]) => v.length > 0)
    .map(([k, v]) => [k, new Set(v)] as const)

  const terms = f.q.trim().toLowerCase().split(/\s+/).filter(Boolean)

  const counts = new Map<string, Map<string, number>>()
  for (const k of keys) counts.set(k, new Map())

  for (const r of rows) {
    if (!passesNonFacet(r, f, terms, ctx)) continue

    let failed: string | null = null
    let failCount = 0
    for (const [k, set] of constraints) {
      if (!set.has(facetValueOf(r, k))) {
        failCount++
        if (failCount > 1) break
        failed = k
      }
    }
    if (failCount > 1) continue

    if (failCount === 0) {
      for (const k of keys) {
        const m = counts.get(k)!
        const v = facetValueOf(r, k)
        m.set(v, (m.get(v) ?? 0) + 1)
      }
    } else if (failed !== null) {
      const m = counts.get(failed)
      if (m) {
        const v = facetValueOf(r, failed)
        m.set(v, (m.get(v) ?? 0) + 1)
      }
    }
  }

  const out = new Map<string, FacetValue[]>()
  for (const k of keys) {
    const m = counts.get(k)!
    const selected = new Set(f.facets[k] ?? [])
    // Selected values always appear, even at count 0, so they stay clearable.
    for (const v of selected) if (!m.has(v)) m.set(v, 0)
    out.set(
      k,
      [...m.entries()]
        .map(([value, count]) => ({ value, count, selected: selected.has(value) }))
        .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
        .slice(0, limit),
    )
  }
  return out
}

/** Everything except the per-facet value constraints. */
function passesNonFacet(r: Finding, f: FilterState, terms: string[], ctx: FilterContext): boolean {
  if (f.fixableOnly && r.fixStatus !== 'Exact fix') return false

  if (f.minMfes != null && f.minMfes > 1) {
    if ((ctx.spread.get(r.packageName) ?? 0) < f.minMfes) return false
  }

  if (f.cvssMin != null || f.cvssMax != null) {
    const c = r.cvss as number | undefined
    if (c == null) return false
    if (f.cvssMin != null && c < f.cvssMin) return false
    if (f.cvssMax != null && c > f.cvssMax) return false
  }

  return matchesQuery(r, terms)
}

export function facetValues(
  rows: Finding[],
  f: FilterState,
  key: string,
  ctx?: FilterContext,
  limit = 500,
): FacetValue[] {
  return facetValuesMany(rows, f, [key], ctx, limit).get(key) ?? []
}

export function toggleFacet(f: FilterState, key: string, value: string): FilterState {
  const cur = f.facets[key] ?? []
  const next = cur.includes(value) ? cur.filter((v) => v !== value) : [...cur, value]
  const facets = { ...f.facets }
  if (next.length) facets[key] = next
  else delete facets[key]
  return { ...f, facets }
}

export function setFacet(f: FilterState, key: string, values: string[]): FilterState {
  const facets = { ...f.facets }
  if (values.length) facets[key] = values
  else delete facets[key]
  return { ...f, facets }
}

export function clearFacet(f: FilterState, key: string): FilterState {
  return setFacet(f, key, [])
}

// --- URL serialisation ---------------------------------------------------
// The whole view lives in the hash, so a filtered view is a shareable link and
// survives a reload. The reports themselves are local, so a link is only
// meaningful to someone whose workspace holds the same MFEs — which is exactly
// the team this is for.

export function encodeFilters(f: FilterState): string {
  const p = new URLSearchParams()
  if (f.q.trim()) p.set('q', f.q.trim())
  if (f.fixableOnly) p.set('fixable', '1')
  if (f.cvssMin != null) p.set('cvssMin', String(f.cvssMin))
  if (f.cvssMax != null) p.set('cvssMax', String(f.cvssMax))
  if (f.minMfes != null && f.minMfes > 1) p.set('minMfes', String(f.minMfes))
  for (const [k, v] of Object.entries(f.facets)) {
    if (v.length) p.set(`f.${k}`, v.join('~'))
  }
  return p.toString()
}

export function decodeFilters(qs: string): FilterState {
  const p = new URLSearchParams(qs)
  const facets: Record<string, string[]> = {}
  for (const [k, v] of p.entries()) {
    if (k.startsWith('f.') && v) facets[k.slice(2)] = v.split('~').filter(Boolean)
  }
  const num = (k: string) => {
    const v = p.get(k)
    if (v == null || v === '') return undefined
    const n = Number(v)
    return Number.isFinite(n) ? n : undefined
  }
  return {
    q: p.get('q') ?? '',
    facets,
    fixableOnly: p.get('fixable') === '1',
    cvssMin: num('cvssMin'),
    cvssMax: num('cvssMax'),
    minMfes: num('minMfes'),
  }
}
