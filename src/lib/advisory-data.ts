/**
 * Live enrichment for the advisory hover card.
 *
 * Why this is a data fetch and not an iframe of the advisory page: NVD, MITRE
 * and CISA all serve `X-Frame-Options: DENY` (and a `frame-ancestors` CSP), so
 * a browser refuses to render them in a frame — an embedded preview of those
 * pages is blank by design, not by misconfiguration. These two APIs are the
 * CORS-enabled sources that let the same information be shown natively.
 *
 *   - OSV.dev     summary, aliases, per-ecosystem fixed versions, references
 *   - FIRST EPSS  probability the CVE will be exploited in the next 30 days
 *
 * OSV is keyed by the advisory id directly, GHSA included. EPSS only knows
 * CVEs, so it is queried with the CVE the parser recovered from the advisory's
 * own NVD reference — and skipped when there is no CVE to ask about.
 *
 * Lookups fire only on hover, are cached for the session, and send **only the
 * identifier** — no report content leaves the machine.
 */

export interface AdvisoryDetails {
  id: string
  summary?: string
  details?: string
  aliases: string[]
  published?: string
  modified?: string
  severity?: string
  /** Ecosystem -> the versions OSV considers fixed. */
  fixedVersions: { ecosystem: string; name: string; fixed: string[] }[]
  references: { type: string; url: string }[]
  /** 0..1 probability of exploitation in the next 30 days. */
  epss?: number
  /** 0..1 percentile among all scored CVEs. */
  epssPercentile?: number
  /** True when OSV has no record; not an error, just no public data. */
  notFound?: boolean
}

export type AdvisoryFetchState =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'ready'; data: AdvisoryDetails }
  | { status: 'error'; message: string }

const cache = new Map<string, AdvisoryFetchState>()
const inflight = new Map<string, Promise<AdvisoryFetchState>>()

export function cachedAdvisory(id: string): AdvisoryFetchState {
  return cache.get(id.toUpperCase()) ?? { status: 'idle' }
}

const TIMEOUT_MS = 8000

async function getJson(url: string, signal: AbortSignal): Promise<unknown | null> {
  const res = await fetch(url, { signal, headers: { accept: 'application/json' } })
  if (res.status === 404) return null
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}

interface OsvAffected {
  package?: { ecosystem?: string; name?: string }
  ranges?: { events?: { fixed?: string }[] }[]
}
interface OsvVuln {
  summary?: string
  details?: string
  aliases?: string[]
  published?: string
  modified?: string
  severity?: { type?: string; score?: string }[]
  database_specific?: { severity?: string }
  affected?: OsvAffected[]
  references?: { type?: string; url?: string }[]
}
interface EpssResponse {
  data?: { cve?: string; epss?: string; percentile?: string }[]
}

/**
 * Fetch once per advisory per session. Concurrent hovers over the same id share
 * a single request rather than racing.
 */
export function fetchAdvisory(rawId: string, cve?: string): Promise<AdvisoryFetchState> {
  const id = rawId.trim().toUpperCase()
  const done = cache.get(id)
  if (done && done.status !== 'idle' && done.status !== 'loading') return Promise.resolve(done)

  const running = inflight.get(id)
  if (running) return running

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS)
  const epssId = cve?.trim().toUpperCase()

  const task = (async (): Promise<AdvisoryFetchState> => {
    try {
      // Failures are independent: EPSS being down should not hide the OSV record.
      const [osvRes, epssRes] = await Promise.allSettled([
        getJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, controller.signal),
        epssId
          ? getJson(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(epssId)}`, controller.signal)
          : Promise.resolve(null),
      ])

      const osv = osvRes.status === 'fulfilled' ? (osvRes.value as OsvVuln | null) : null
      const epssRow = epssRes.status === 'fulfilled' ? (epssRes.value as EpssResponse | null)?.data?.[0] : undefined

      if (osvRes.status === 'rejected' && (epssRes.status === 'rejected' || !epssId)) {
        const reason = osvRes.reason
        throw reason instanceof Error ? reason : new Error(String(reason))
      }

      const fixedVersions = (osv?.affected ?? [])
        .map((a) => ({
          ecosystem: a.package?.ecosystem ?? '',
          name: a.package?.name ?? '',
          fixed: (a.ranges ?? []).flatMap((r) => (r.events ?? []).map((e) => e.fixed).filter(Boolean) as string[]),
        }))
        .filter((a) => a.name && a.fixed.length > 0)
        // One entry per package; OSV repeats a package per range.
        .reduce<AdvisoryDetails['fixedVersions']>((acc, cur) => {
          const hit = acc.find((x) => x.ecosystem === cur.ecosystem && x.name === cur.name)
          if (hit) hit.fixed = [...new Set([...hit.fixed, ...cur.fixed])]
          else acc.push({ ...cur, fixed: [...new Set(cur.fixed)] })
          return acc
        }, [])
        .slice(0, 6)

      const data: AdvisoryDetails = {
        id,
        summary: osv?.summary,
        details: osv?.details,
        severity: osv?.database_specific?.severity,
        aliases: (osv?.aliases ?? []).filter((a) => a.toUpperCase() !== id).slice(0, 6),
        published: osv?.published,
        modified: osv?.modified,
        fixedVersions,
        references: (osv?.references ?? [])
          .filter((r): r is { type: string; url: string } => Boolean(r.url))
          .map((r) => ({ type: r.type ?? 'WEB', url: r.url }))
          .slice(0, 5),
        epss: epssRow?.epss != null ? Number(epssRow.epss) : undefined,
        epssPercentile: epssRow?.percentile != null ? Number(epssRow.percentile) : undefined,
        notFound: osv == null,
      }

      const state: AdvisoryFetchState = { status: 'ready', data }
      cache.set(id, state)
      return state
    } catch (e) {
      const message =
        e instanceof DOMException && e.name === 'AbortError'
          ? 'Lookup timed out'
          : e instanceof TypeError
            ? 'Could not reach the vulnerability APIs — offline, or blocked by network policy'
            : e instanceof Error
              ? e.message
              : String(e)
      const state: AdvisoryFetchState = { status: 'error', message }
      cache.set(id, state)
      return state
    } finally {
      clearTimeout(timer)
      inflight.delete(id)
    }
  })()

  inflight.set(id, task)
  cache.set(id, { status: 'loading' })
  return task
}

/** Plain-language band for an EPSS probability. */
export function epssBand(p: number): { label: string; tone: 'critical' | 'high' | 'medium' | 'low' } {
  if (p >= 0.1) return { label: 'High likelihood of exploitation', tone: 'critical' }
  if (p >= 0.01) return { label: 'Elevated likelihood', tone: 'high' }
  if (p >= 0.001) return { label: 'Low likelihood', tone: 'medium' }
  return { label: 'Very low likelihood', tone: 'low' }
}

// --- opt-out -------------------------------------------------------------
// Live lookups are on by default, but some environments will not allow calls to
// third-party APIs from an analyst's browser, so the choice is persisted.

const LOOKUP_KEY = 'owasp-viewer.live-lookup'

export function liveLookupEnabled(): boolean {
  if (typeof localStorage === 'undefined') return true
  return localStorage.getItem(LOOKUP_KEY) !== 'off'
}

export function setLiveLookup(on: boolean) {
  if (typeof localStorage === 'undefined') return
  localStorage.setItem(LOOKUP_KEY, on ? 'on' : 'off')
}
