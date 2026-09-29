/**
 * The canonical shape of a finding, plus the two pieces of domain logic that
 * everything else leans on: the severity scale, and how a "fixed in" version is
 * recovered from an OWASP dependency-check report.
 */

export type FieldKind = 'string' | 'number' | 'enum' | 'date' | 'list'

export interface Field {
  key: string
  label: string
  kind: FieldKind
  /** Short explanation, surfaced in the column chooser and the detail sheet. */
  hint?: string
}

/**
 * Every column the grid can show. Order here is the order they appear in the
 * column chooser.
 */
export const FIELDS: Field[] = [
  { key: 'mfe', label: 'MFE', kind: 'enum', hint: "The micro-frontend this finding came from (the report's projectInfo.name)" },
  { key: 'severity', label: 'Severity', kind: 'enum', hint: 'Severity as reported by the advisory source' },
  { key: 'cvss', label: 'CVSS', kind: 'number', hint: 'CVSS base score, v3 preferred over v2' },
  { key: 'cvssVersion', label: 'CVSS version', kind: 'enum' },
  { key: 'baseSeverity', label: 'CVSS severity', kind: 'enum', hint: 'Severity implied by the CVSS base score' },
  { key: 'advisory', label: 'Advisory', kind: 'string', hint: 'Advisory identifier: GHSA-…, CVE-…, RETIREJS-…' },
  { key: 'cve', label: 'CVE', kind: 'string', hint: 'CVE id, taken from the advisory id or recovered from its NVD reference' },
  { key: 'source', label: 'Source', kind: 'enum', hint: 'Which analyser produced this: NPM audit, NVD, RetireJS, OSS Index' },
  { key: 'packageName', label: 'Package', kind: 'string' },
  { key: 'packageVersion', label: 'Version', kind: 'string', hint: 'The version resolved in this MFE' },
  { key: 'ecosystem', label: 'Ecosystem', kind: 'enum', hint: 'From the Package URL, e.g. npm' },
  { key: 'purl', label: 'Package URL', kind: 'string' },
  { key: 'dependencyScope', label: 'Scope', kind: 'enum', hint: 'Direct or transitive, from the report’s project references' },
  { key: 'projectRef', label: 'Manifest', kind: 'enum', hint: 'Which manifest pulled it in, e.g. package-lock.json' },
  { key: 'fixStatus', label: 'Fix', kind: 'enum', hint: 'Whether a fixed version could be derived for this advisory' },
  { key: 'fixedIn', label: 'Fixed in', kind: 'string', hint: 'Lowest version that is not affected, derived from the advisory’s CPE range' },
  { key: 'fixReason', label: 'Why this fix', kind: 'string' },
  { key: 'upgrade', label: 'Upgrade', kind: 'string', hint: 'Installed version → fixed version' },
  { key: 'cwe', label: 'CWE', kind: 'enum', hint: 'Primary weakness class' },
  { key: 'cwes', label: 'All CWEs', kind: 'list' },
  { key: 'attackVector', label: 'Attack vector', kind: 'enum' },
  { key: 'attackComplexity', label: 'Attack complexity', kind: 'enum' },
  { key: 'privilegesRequired', label: 'Privileges required', kind: 'enum' },
  { key: 'userInteraction', label: 'User interaction', kind: 'enum' },
  { key: 'cvssScope', label: 'CVSS scope', kind: 'enum' },
  { key: 'confidentialityImpact', label: 'Confidentiality', kind: 'enum' },
  { key: 'integrityImpact', label: 'Integrity', kind: 'enum' },
  { key: 'availabilityImpact', label: 'Availability', kind: 'enum' },
  { key: 'cvssVector', label: 'CVSS vector', kind: 'string' },
  { key: 'exposure', label: 'Exposure', kind: 'enum', hint: 'Remotely reachable with no privileges and no user interaction' },
  { key: 'unscored', label: 'Unscored', kind: 'enum', hint: 'The source flagged the CVSS score as not officially assigned' },
  { key: 'description', label: 'Description', kind: 'string' },
  { key: 'affectedRange', label: 'Affected range', kind: 'string', hint: 'The advisory’s own version range for this package' },
  { key: 'reportDate', label: 'Scanned', kind: 'date', hint: 'When this MFE’s report was generated' },
  { key: 'scanAgeDays', label: 'Scan age (d)', kind: 'number' },
  { key: 'engineVersion', label: 'Engine', kind: 'enum', hint: 'dependency-check version that produced the report' },
  { key: 'filePath', label: 'File path', kind: 'string' },
  { key: 'refCount', label: 'References', kind: 'number' },
]

export const FIELD_BY_KEY = new Map(FIELDS.map((f) => [f.key, f]))

// --- Severity ------------------------------------------------------------

/**
 * npm audit — which is what feeds most of these reports — scores on five
 * levels, so the scale has five real steps plus Unknown for an advisory that
 * carries no severity at all. `moderate` is npm's name for Medium.
 */
export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'] as const
export type Severity = (typeof SEVERITY_ORDER)[number]

const SEVERITY_ALIASES: Record<string, Severity> = {
  critical: 'Critical',
  high: 'High',
  moderate: 'Medium',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  informational: 'Info',
  none: 'Info',
}

export function normaliseSeverity(raw: unknown): Severity {
  const v = String(raw ?? '').trim().toLowerCase()
  return SEVERITY_ALIASES[v] ?? 'Unknown'
}

const SEVERITY_INDEX = new Map(SEVERITY_ORDER.map((s, i) => [s, i]))

/** Lower rank = more severe, so a plain ascending sort puts Critical first. */
export function severityRank(s: unknown): number {
  return SEVERITY_INDEX.get(String(s) as Severity) ?? SEVERITY_ORDER.length
}

/** Severity implied by a CVSS base score, for the CVSS-derived column. */
export function severityFromScore(score: number | undefined): Severity {
  if (score == null || !Number.isFinite(score)) return 'Unknown'
  if (score >= 9) return 'Critical'
  if (score >= 7) return 'High'
  if (score >= 4) return 'Medium'
  if (score > 0) return 'Low'
  return 'Info'
}

// --- Versions ------------------------------------------------------------

/**
 * Semver-ish comparison, enough for the npm versions these reports carry.
 * Numeric segments compare numerically, a release outranks its own
 * pre-releases, and anything unparseable falls back to a string compare so the
 * ordering stays total (and therefore stable).
 */
export function compareVersions(a: string, b: string): number {
  if (a === b) return 0
  const [mainA = '', preA = ''] = splitPrerelease(a)
  const [mainB = '', preB = ''] = splitPrerelease(b)

  const segA = mainA.split('.')
  const segB = mainB.split('.')
  const len = Math.max(segA.length, segB.length)
  for (let i = 0; i < len; i++) {
    const na = Number(segA[i] ?? 0)
    const nb = Number(segB[i] ?? 0)
    if (Number.isFinite(na) && Number.isFinite(nb)) {
      if (na !== nb) return na - nb
    } else {
      const c = (segA[i] ?? '').localeCompare(segB[i] ?? '')
      if (c !== 0) return c
    }
  }

  // 1.0.0 > 1.0.0-rc.1: a release outranks its own pre-releases.
  if (preA === preB) return 0
  if (!preA) return 1
  if (!preB) return -1
  return preA.localeCompare(preB)
}

function splitPrerelease(v: string): [string, string] {
  const clean = v.trim().replace(/^[v=]+/, '')
  const i = clean.search(/[-+]/)
  return i === -1 ? [clean, ''] : [clean.slice(0, i), clean.slice(i + 1)]
}

export function maxVersion(versions: string[]): string | undefined {
  if (!versions.length) return undefined
  return versions.reduce((a, b) => (compareVersions(a, b) >= 0 ? a : b))
}

// --- CPE version ranges --------------------------------------------------

/**
 * A fix expressed as the weakest version that is *not* affected.
 *
 * `<0.6.1` in the advisory means 0.6.1 is clean, so the constraint is `>=0.6.1`
 * and there is an exact version to bump to. `<=10.4.0` only says "10.4.0 and
 * below are affected" — the fix is some later release the report does not name,
 * so the constraint is `>10.4.0` and the target stays inexact.
 */
export interface FixConstraint {
  op: '>=' | '>'
  version: string
}

export interface CpeRange {
  /** The raw, unescaped version expression, e.g. `>=3.1.3<3.1.6`. */
  raw: string
  lower?: { op: '>' | '>='; version: string }
  upper?: { op: '<' | '<='; version: string }
  /** Absent when the advisory pins an exact version rather than a range. */
  exact?: string
}

/**
 * Split a CPE 2.3 formatted string on its *unescaped* colons.
 *
 * Package names routinely carry escapes — `\@faker-js\/faker` — and a naive
 * `split(':')` would also break on any escaped colon, so the separator has to
 * be matched with the escaping honoured.
 */
export function splitCpe(id: string): string[] {
  const parts: string[] = []
  let cur = ''
  for (let i = 0; i < id.length; i++) {
    const ch = id[i]
    if (ch === '\\') {
      cur += ch + (id[i + 1] ?? '')
      i++
    } else if (ch === ':') {
      parts.push(cur)
      cur = ''
    } else {
      cur += ch
    }
  }
  parts.push(cur)
  return parts
}

/** `\@faker-js\/faker` -> `@faker-js/faker`. */
export function unescapeCpe(v: string): string {
  return v.replace(/\\(.)/g, '$1')
}

export interface ParsedCpe {
  product: string
  range: CpeRange | null
}

export function parseCpe(id: string): ParsedCpe | null {
  const parts = splitCpe(id)
  // cpe:2.3:<part>:<vendor>:<product>:<version>:…
  if (parts.length < 6 || parts[0] !== 'cpe') return null
  return {
    product: unescapeCpe(parts[4] ?? ''),
    range: parseVersionExpression(unescapeCpe(parts[5] ?? '')),
  }
}

/**
 * Decode `>=3.1.3<3.1.6`, `<0.6.1`, `<=10.4.0` or a bare `1.2.3` into bounds.
 * Returns null for the wildcard (`*`) and anything else we cannot read, so a
 * range we do not understand never silently becomes a fix recommendation.
 */
export function parseVersionExpression(expr: string): CpeRange | null {
  const raw = expr.trim()
  if (!raw || raw === '*' || raw === '-') return null

  const tokens = [...raw.matchAll(/(<=|>=|<|>|=)?\s*([^<>=\s]+)/g)]
  if (!tokens.length) return null

  const out: CpeRange = { raw }
  for (const [, op, version] of tokens) {
    if (!version) continue
    if (op === '<' || op === '<=') out.upper = { op, version }
    else if (op === '>' || op === '>=') out.lower = { op, version }
    else out.exact = version
  }
  return out.lower || out.upper || out.exact ? out : null
}

/** Does `version` fall inside this range? Used to pick the applicable range. */
export function rangeContains(range: CpeRange, version: string): boolean {
  if (range.exact != null) return compareVersions(range.exact, version) === 0
  if (range.lower) {
    const c = compareVersions(version, range.lower.version)
    if (range.lower.op === '>=' ? c < 0 : c <= 0) return false
  }
  if (range.upper) {
    const c = compareVersions(version, range.upper.version)
    if (range.upper.op === '<=' ? c > 0 : c >= 0) return false
  }
  return true
}

/** The constraint a fix must satisfy, or undefined when the range names no upper bound. */
export function fixConstraintFor(range: CpeRange): FixConstraint | undefined {
  if (!range.upper) return undefined
  return range.upper.op === '<'
    ? { op: '>=', version: range.upper.version }
    : { op: '>', version: range.upper.version }
}

/**
 * Combine several constraints into the single strongest one — the version to
 * actually bump to so that every advisory in the set is cleared.
 *
 * On a tie, `>` wins over `>=`: `>1.2.3` is the stricter of the two.
 */
export function strongestConstraint(constraints: FixConstraint[]): FixConstraint | undefined {
  if (!constraints.length) return undefined
  return constraints.reduce((a, b) => {
    const c = compareVersions(a.version, b.version)
    if (c !== 0) return c > 0 ? a : b
    return a.op === '>' ? a : b
  })
}

/** Does `version` already satisfy the constraint? */
export function satisfies(version: string, c: FixConstraint): boolean {
  const cmp = compareVersions(version, c.version)
  return c.op === '>=' ? cmp >= 0 : cmp > 0
}

/** `{ op: '>=', version: '3.1.6' }` -> `3.1.6`; `>` -> `> 0.6.0` (no exact release named). */
export function formatConstraint(c: FixConstraint | undefined): string {
  if (!c) return ''
  return c.op === '>=' ? c.version : `> ${c.version}`
}
