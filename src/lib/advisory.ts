/**
 * Where an advisory identifier can be looked up.
 *
 * These reports are dominated by **GHSA** ids, not CVEs, because the npm audit
 * analyser is what finds most of it. That matters: NVD and MITRE cannot resolve
 * a GHSA at all, so a link is only offered where the database can actually
 * answer, and the default target is OSV — the one source that takes both.
 */

export type AdvisoryKind = 'cve' | 'ghsa' | 'retirejs' | 'other'

export const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i
export const GHSA_PATTERN = /^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$/i

export function advisoryKind(id: unknown): AdvisoryKind {
  const v = String(id ?? '').trim()
  if (CVE_PATTERN.test(v)) return 'cve'
  if (GHSA_PATTERN.test(v)) return 'ghsa'
  if (/^RETIREJS/i.test(v)) return 'retirejs'
  return 'other'
}

export function isCve(v: unknown): boolean {
  return advisoryKind(v) === 'cve'
}

export interface AdvisorySource {
  id: string
  label: string
  /** Short blurb shown in the picker. */
  hint: string
  /** Which identifier kinds this database can resolve. */
  accepts: AdvisoryKind[]
  url: (id: string) => string
}

export const ADVISORY_SOURCES: AdvisorySource[] = [
  {
    id: 'osv',
    label: 'OSV',
    hint: 'Open Source Vulnerabilities — resolves both GHSA and CVE ids, with per-ecosystem fixed versions',
    accepts: ['cve', 'ghsa'],
    url: (v) => `https://osv.dev/vulnerability/${encodeURIComponent(v)}`,
  },
  {
    id: 'ghsa',
    label: 'GitHub Advisory',
    hint: 'GitHub Advisory Database — package-level fix guidance and the advisory write-up',
    accepts: ['cve', 'ghsa'],
    url: (v) =>
      advisoryKind(v) === 'ghsa'
        ? `https://github.com/advisories/${encodeURIComponent(v)}`
        : `https://github.com/advisories?query=${encodeURIComponent(v)}`,
  },
  {
    id: 'nvd',
    label: 'NVD',
    hint: 'NIST National Vulnerability Database — CVSS vectors, CWE, references. CVE ids only',
    accepts: ['cve'],
    url: (v) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v)}`,
  },
  {
    id: 'mitre',
    label: 'MITRE',
    hint: 'The CVE Program record itself — canonical description. CVE ids only',
    accepts: ['cve'],
    url: (v) => `https://www.cve.org/CVERecord?id=${encodeURIComponent(v)}`,
  },
  {
    id: 'cisa-kev',
    label: 'CISA KEV',
    hint: 'Known Exploited Vulnerabilities catalogue — is this being exploited in the wild? CVE ids only',
    accepts: ['cve'],
    url: (v) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v)}`,
  },
  {
    id: 'epss',
    label: 'FIRST EPSS',
    hint: 'Exploit Prediction Scoring System — probability of exploitation. CVE ids only',
    accepts: ['cve'],
    url: (v) => `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(v)}`,
  },
]

/** OSV first: it is the only source that resolves the GHSA ids these reports mostly carry. */
export const DEFAULT_ADVISORY_SOURCE = 'osv'

export function sourcesFor(id: unknown): AdvisorySource[] {
  const kind = advisoryKind(id)
  return ADVISORY_SOURCES.filter((s) => s.accepts.includes(kind))
}

/** An identifier no database here can resolve renders as plain text, not a dead link. */
export function isLinkable(id: unknown): boolean {
  return sourcesFor(id).length > 0
}

/**
 * The preferred source's URL, falling back to the first source that accepts
 * this kind of id — picking NVD in the toolbar should not turn every GHSA row
 * into a 404.
 */
export function advisoryUrl(id: string, sourceId: string = DEFAULT_ADVISORY_SOURCE): string | null {
  const v = id.trim()
  const usable = sourcesFor(v)
  if (!usable.length) return null
  const chosen = usable.find((s) => s.id === sourceId) ?? usable[0]
  return chosen.url(advisoryKind(v) === 'cve' ? v.toUpperCase() : v)
}
