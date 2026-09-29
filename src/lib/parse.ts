/**
 * OWASP dependency-check JSON -> findings.
 *
 * The determinism contract, which the whole tool rests on:
 *
 *  1. **One finding is one (MFE x dependency x advisory) tuple.** A package hit
 *     by four advisories is four rows, because four rows is what you have to
 *     work through — but they roll up to one upgrade in the Remediation view.
 *  2. **Nothing is inferred from field order.** The report is read by key, so a
 *     dependency-check upgrade that reorders its output lands identically.
 *  3. **Fix versions come from the advisory's CPE range, not from its prose.**
 *     `<0.6.1` is a machine-readable statement that 0.6.1 is clean. The
 *     description's "upgrade to 2.4.5, 3.1.6, or 4.1.3" is not, and is never
 *     parsed. Every derived fix records the range it came from.
 *  4. **Row identity is content-derived**, so re-uploading the same report
 *     produces the same ids and the same fingerprint.
 */

import {
  compareVersions,
  fixConstraintFor,
  formatConstraint,
  normaliseSeverity,
  parseCpe,
  rangeContains,
  severityFromScore,
  type CpeRange,
  type FixConstraint,
  type Severity,
} from './schema'

export interface Finding extends Record<string, unknown> {
  id: string
  /** Which report this came from; stable across renames of the MFE. */
  reportId: string
  mfe: string
  severity: Severity
  advisory: string
  packageName: string
  packageVersion: string
}

export interface DataSource {
  name: string
  timestamp?: string
}

export interface ReportMeta {
  reportId: string
  /** Display name. Starts as `reportedName` and can be renamed by the user. */
  mfe: string
  /** `projectInfo.name` exactly as the report carries it. */
  reportedName: string
  fileName: string
  reportDate?: string
  engineVersion?: string
  schemaVersion?: string
  /** Every dependency the scan looked at, vulnerable or not. */
  dependencyCount: number
  vulnerableDependencies: number
  findingCount: number
  /** Advisories the project has explicitly suppressed; excluded from findings. */
  suppressedCount: number
  fingerprint: string
  dataSources: DataSource[]
  addedAt: number
}

export interface ParsedReport {
  rows: Finding[]
  meta: ReportMeta
}

// --- hashing -------------------------------------------------------------

/**
 * 64-bit FNV-1a as two 32-bit lanes, rendered hex. A 32-bit hash over a few
 * thousand rows has a real collision probability; this does not, and row ids
 * are used as grid keys where a collision would drop a row.
 */
function hashString(s: string): string {
  let h1 = 0x811c9dc5
  let h2 = 0x01000193
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    h1 = Math.imul(h1 ^ c, 0x01000193)
    h2 = Math.imul(h2 ^ c, 0x85ebca6b) ^ (h1 >>> 13)
  }
  return ((h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0'))
}

/** SHA-256 of the file's bytes — the report's identity, independent of its name. */
export async function contentKey(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text)
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const digest = await crypto.subtle.digest('SHA-256', bytes)
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
  }
  // Non-secure contexts have no SubtleCrypto; the key only needs to be stable.
  return hashString(text)
}

// --- raw report shapes ---------------------------------------------------

interface RawCvss {
  baseScore?: number
  score?: number
  version?: string
  baseSeverity?: string
  severity?: string
  attackVector?: string
  accessVector?: string
  attackComplexity?: string
  accessComplexity?: string
  privilegesRequired?: string
  authenticationr?: string
  authentication?: string
  userInteraction?: string
  scope?: string
  confidentialityImpact?: string
  confidentialImpact?: string
  integrityImpact?: string
  availabilityImpact?: string
}

interface RawVulnerability {
  source?: string
  name?: string
  unscored?: string | boolean
  severity?: string
  cvssv2?: RawCvss
  cvssv3?: RawCvss
  cwes?: string[]
  description?: string
  notes?: string
  references?: { source?: string; url?: string; name?: string }[]
  vulnerableSoftware?: { software?: { id?: string; versionEndExcluding?: string; versionEndIncluding?: string } }[]
}

interface RawDependency {
  isVirtual?: boolean
  fileName?: string
  filePath?: string
  projectReferences?: string[]
  packages?: { id?: string; confidence?: string }[]
  vulnerabilityIds?: { id?: string }[]
  vulnerabilities?: RawVulnerability[]
  suppressedVulnerabilities?: RawVulnerability[]
}

interface RawReport {
  reportSchema?: string
  scanInfo?: { engineVersion?: string; dataSource?: DataSource[] }
  projectInfo?: { name?: string; reportDate?: string }
  dependencies?: RawDependency[]
}

// --- parsing -------------------------------------------------------------

export class ReportFormatError extends Error {}

/**
 * Validate and decode the report envelope. Rejects loudly rather than producing
 * an empty dashboard, because "0 findings" and "wrong file" look identical
 * otherwise.
 */
function decodeEnvelope(text: string, fileName: string): RawReport {
  const trimmed = text.trimStart()
  if (trimmed.startsWith('<')) {
    throw new ReportFormatError(
      trimmed.toLowerCase().includes('<html')
        ? `${fileName} is the HTML report. Upload dependency-check-report.json instead — the HTML is a rendering of it and drops the machine-readable version ranges this tool needs.`
        : `${fileName} looks like XML. Upload dependency-check-report.json instead.`,
    )
  }

  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch (e) {
    throw new ReportFormatError(`${fileName} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`)
  }

  if (!raw || typeof raw !== 'object') {
    throw new ReportFormatError(`${fileName} does not contain a JSON object.`)
  }
  const report = raw as RawReport
  if (!Array.isArray(report.dependencies)) {
    throw new ReportFormatError(
      `${fileName} has no "dependencies" array, so it is not an OWASP dependency-check report.`,
    )
  }
  return report
}

/** `pkg:npm/%40faker-js%2Ffaker@9.9.0` -> ecosystem, name, version. */
export function parsePurl(purl: string): { ecosystem: string; name: string; version: string } | null {
  if (!purl.startsWith('pkg:')) return null
  const body = purl.slice(4)
  const at = body.lastIndexOf('@')
  const withoutVersion = at > 0 ? body.slice(0, at) : body
  const version = at > 0 ? body.slice(at + 1) : ''
  const slash = withoutVersion.indexOf('/')
  if (slash === -1) return null
  const decode = (s: string) => {
    try {
      return decodeURIComponent(s)
    } catch {
      return s
    }
  }
  return {
    ecosystem: decode(withoutVersion.slice(0, slash)),
    name: decode(withoutVersion.slice(slash + 1)),
    // A qualifier or subpath would follow the version; neither appears in these
    // reports, but trimming keeps a stray one out of the version string.
    version: decode(version.split(/[?#]/)[0] ?? ''),
  }
}

/** `@faker-js/faker:9.9.0` -> name and version, splitting on the *last* colon. */
function parseFileName(fileName: string): { name: string; version: string } {
  const i = fileName.lastIndexOf(':')
  return i === -1
    ? { name: fileName, version: '' }
    : { name: fileName.slice(0, i), version: fileName.slice(i + 1) }
}

/**
 * `["package-lock.json: transitive"]` -> manifest and scope. A package reached
 * both ways is Direct: that is the reference you can actually edit.
 */
function parseProjectReferences(refs: string[] | undefined): { manifest: string; scope: string } {
  if (!refs?.length) return { manifest: '', scope: 'Unknown' }
  const manifests: string[] = []
  let direct = false
  let transitive = false
  for (const ref of refs) {
    const i = ref.indexOf(':')
    const manifest = (i === -1 ? ref : ref.slice(0, i)).trim()
    const scope = (i === -1 ? '' : ref.slice(i + 1)).trim().toLowerCase()
    if (manifest) manifests.push(manifest)
    if (scope.includes('transitive')) transitive = true
    else if (scope) direct = true
  }
  return {
    manifest: [...new Set(manifests)].join(', '),
    scope: direct ? 'Direct' : transitive ? 'Transitive' : 'Unknown',
  }
}

const CVE_IN_TEXT = /CVE-\d{4}-\d{4,}/i

/** The advisory's own CVE id, or the one its NVD reference points at. */
function findCve(vuln: RawVulnerability): string {
  const name = String(vuln.name ?? '')
  if (CVE_IN_TEXT.test(name)) return name.toUpperCase()
  for (const ref of vuln.references ?? []) {
    const url = String(ref.url ?? '')
    if (!url.includes('nvd.nist.gov') && !url.includes('cve.org') && !url.includes('/cve/')) continue
    const hit = url.match(CVE_IN_TEXT)
    if (hit) return hit[0].toUpperCase()
  }
  return ''
}

const VECTOR_ABBREV: Record<string, string> = {
  NETWORK: 'N',
  ADJACENT: 'A',
  ADJACENT_NETWORK: 'A',
  LOCAL: 'L',
  PHYSICAL: 'P',
  LOW: 'L',
  HIGH: 'H',
  MEDIUM: 'M',
  NONE: 'N',
  REQUIRED: 'R',
  UNCHANGED: 'U',
  CHANGED: 'C',
  PARTIAL: 'P',
  COMPLETE: 'C',
  SINGLE: 'S',
  MULTIPLE: 'M',
}

function abbrev(v: string | undefined): string {
  return VECTOR_ABBREV[String(v ?? '').toUpperCase()] ?? ''
}

/** Rebuild the CVSS vector string the report decomposed into fields. */
function buildVector(c: RawCvss | undefined): string {
  if (!c) return ''
  const parts: [string, string][] = [
    ['AV', abbrev(c.attackVector ?? c.accessVector)],
    ['AC', abbrev(c.attackComplexity ?? c.accessComplexity)],
    ['PR', abbrev(c.privilegesRequired)],
    ['UI', abbrev(c.userInteraction)],
    ['S', abbrev(c.scope)],
    ['C', abbrev(c.confidentialityImpact ?? c.confidentialImpact)],
    ['I', abbrev(c.integrityImpact)],
    ['A', abbrev(c.availabilityImpact)],
  ]
  const present = parts.filter(([, v]) => v)
  if (!present.length) return ''
  const prefix = c.version ? `CVSS:${c.version}` : 'CVSS'
  return [prefix, ...present.map(([k, v]) => `${k}:${v}`)].join('/')
}

/**
 * How reachable this is, in one word. Derived from the CVSS vector so it is not
 * a second opinion on severity — it answers "can someone on the internet do
 * this to us without an account and without tricking a user?".
 */
function deriveExposure(c: RawCvss | undefined): string {
  if (!c) return 'Unknown'
  const av = String(c.attackVector ?? c.accessVector ?? '').toUpperCase()
  if (!av) return 'Unknown'
  if (av !== 'NETWORK') {
    return av === 'PHYSICAL' ? 'Physical access' : av === 'LOCAL' ? 'Local only' : 'Adjacent network'
  }
  const pr = String(c.privilegesRequired ?? '').toUpperCase()
  const ui = String(c.userInteraction ?? '').toUpperCase()
  if (ui === 'REQUIRED') return 'Remote, needs user action'
  if (pr && pr !== 'NONE') return 'Remote, authenticated'
  return 'Remote, unauthenticated'
}

/**
 * The advisory's version range for *this* package, and the fix it implies.
 *
 * An advisory can list several CPEs. Prefer the one whose product matches the
 * package and whose range actually contains the installed version — that is the
 * statement about the version in front of us. Fall back to a product match, then
 * to any parseable range, so a report with looser CPEs still yields something.
 */
function resolveFix(
  vuln: RawVulnerability,
  packageName: string,
  installed: string,
): { range?: CpeRange; constraint?: FixConstraint; reason: string } {
  const candidates: { range: CpeRange; productMatches: boolean }[] = []
  const wanted = packageName.toLowerCase()

  for (const entry of vuln.vulnerableSoftware ?? []) {
    const id = entry.software?.id
    if (!id) continue
    const parsed = parseCpe(id)
    if (!parsed?.range) continue
    candidates.push({ range: parsed.range, productMatches: parsed.product.toLowerCase() === wanted })
  }

  if (!candidates.length) {
    return { reason: 'The advisory lists no machine-readable version range.' }
  }

  const containing = installed
    ? candidates.find((c) => c.productMatches && rangeContains(c.range, installed)) ??
      candidates.find((c) => rangeContains(c.range, installed))
    : undefined
  const chosen = containing ?? candidates.find((c) => c.productMatches) ?? candidates[0]

  const constraint = fixConstraintFor(chosen.range)
  const how = containing
    ? `covers the installed ${installed}`
    : chosen.productMatches
      ? 'matches this package'
      : 'the only range the advisory lists'

  if (!constraint) {
    return {
      range: chosen.range,
      reason: `Range "${chosen.range.raw}" (${how}) names no upper bound, so no fixed version can be derived.`,
    }
  }
  return {
    range: chosen.range,
    constraint,
    reason:
      constraint.op === '>='
        ? `Range "${chosen.range.raw}" (${how}) excludes ${constraint.version}, so that release is clean.`
        : `Range "${chosen.range.raw}" (${how}) includes ${constraint.version}, so the fix is a later release the advisory does not name.`,
  }
}

const DAY_MS = 86_400_000

export function parseReport(text: string, fileName: string, reportId: string): ParsedReport {
  const report = decodeEnvelope(text, fileName)

  const reportedName = String(report.projectInfo?.name ?? '').trim()
  const reportDate = report.projectInfo?.reportDate
  const engineVersion = report.scanInfo?.engineVersion
  const parsedDate = reportDate ? Date.parse(reportDate) : Number.NaN
  const scanAgeDays = Number.isNaN(parsedDate) ? undefined : Math.max(0, Math.floor((Date.now() - parsedDate) / DAY_MS))

  // Falling back to the file name keeps an unnamed report distinguishable
  // rather than collapsing every such upload into one blank MFE.
  const mfe = reportedName || fileName.replace(/\.json$/i, '')

  const rows: Finding[] = []
  let vulnerableDependencies = 0
  let suppressedCount = 0

  for (const dep of report.dependencies ?? []) {
    suppressedCount += dep.suppressedVulnerabilities?.length ?? 0
    const vulns = dep.vulnerabilities ?? []
    if (!vulns.length) continue
    vulnerableDependencies++

    const depFileName = String(dep.fileName ?? '')
    const purl = dep.packages?.find((p) => p.id)?.id ?? ''
    const fromPurl = purl ? parsePurl(purl) : null
    const fromFileName = parseFileName(depFileName)
    const packageName = fromPurl?.name || fromFileName.name
    const packageVersion = fromPurl?.version || fromFileName.version
    const { manifest, scope } = parseProjectReferences(dep.projectReferences)

    for (const vuln of vulns) {
      const advisory = String(vuln.name ?? '').trim() || '(unnamed advisory)'
      const cvss3 = vuln.cvssv3
      const cvss2 = vuln.cvssv2
      const active = cvss3 ?? cvss2
      const score = cvss3?.baseScore ?? cvss2?.score ?? cvss2?.baseScore
      const cvss = typeof score === 'number' && Number.isFinite(score) ? Math.round(score * 10) / 10 : undefined

      const fix = resolveFix(vuln, packageName, packageVersion)
      const fixedIn = formatConstraint(fix.constraint)
      const fixStatus = !fix.constraint ? 'Unknown' : fix.constraint.op === '>=' ? 'Exact fix' : 'Later release'

      const cwes = (vuln.cwes ?? []).map(String)

      rows.push({
        id: hashString(`${reportId}|${depFileName}|${advisory}|${dep.filePath ?? ''}`),
        reportId,
        mfe,
        severity: normaliseSeverity(vuln.severity),
        cvss,
        cvssVersion: active?.version ? `v${active.version}` : cvss3 ? 'v3' : cvss2 ? 'v2' : '',
        baseSeverity: cvss3?.baseSeverity
          ? normaliseSeverity(cvss3.baseSeverity)
          : severityFromScore(cvss),
        advisory,
        cve: findCve(vuln),
        source: String(vuln.source ?? '').trim() || 'Unknown',
        packageName,
        packageVersion,
        ecosystem: fromPurl?.ecosystem ?? '',
        purl,
        dependencyScope: scope,
        projectRef: manifest,
        fixStatus,
        fixedIn,
        fixReason: fix.reason,
        upgrade: fixedIn && packageVersion ? `${packageVersion} → ${fixedIn}` : '',
        cwe: cwes[0] ?? '',
        cwes,
        attackVector: active?.attackVector ?? active?.accessVector ?? '',
        attackComplexity: active?.attackComplexity ?? active?.accessComplexity ?? '',
        privilegesRequired: active?.privilegesRequired ?? '',
        userInteraction: active?.userInteraction ?? '',
        cvssScope: active?.scope ?? '',
        confidentialityImpact: active?.confidentialityImpact ?? active?.confidentialImpact ?? '',
        integrityImpact: active?.integrityImpact ?? '',
        availabilityImpact: active?.availabilityImpact ?? '',
        cvssVector: buildVector(active),
        exposure: deriveExposure(active),
        // The flag travels as a string so it faceted alongside every other
        // tri-state rather than as a bare boolean the filter model would have
        // to special-case.
        unscored: vuln.unscored === true || vuln.unscored === 'true' ? 'Yes' : 'No',
        description: String(vuln.description ?? '').trim(),
        affectedRange: fix.range?.raw ?? '',
        references: (vuln.references ?? [])
          .map((r) => ({ url: String(r.url ?? ''), name: String(r.name ?? r.url ?? '') }))
          .filter((r) => r.url),
        refCount: (vuln.references ?? []).filter((r) => r.url).length,
        reportDate: reportDate ?? '',
        scanAgeDays,
        engineVersion: engineVersion ?? '',
        filePath: String(dep.filePath ?? ''),
        isVirtual: dep.isVirtual === true ? 'Yes' : 'No',
      })
    }
  }

  // Sorted worst-first so the fingerprint — and the default grid order — do not
  // depend on the order dependency-check happened to emit.
  rows.sort(
    (a, b) =>
      (b.cvss == null ? -1 : (b.cvss as number)) - (a.cvss == null ? -1 : (a.cvss as number)) ||
      a.packageName.localeCompare(b.packageName) ||
      compareVersions(a.packageVersion, b.packageVersion) ||
      a.advisory.localeCompare(b.advisory),
  )

  const meta: ReportMeta = {
    reportId,
    mfe,
    reportedName,
    fileName,
    reportDate,
    engineVersion,
    schemaVersion: report.reportSchema,
    dependencyCount: report.dependencies?.length ?? 0,
    vulnerableDependencies,
    findingCount: rows.length,
    suppressedCount,
    fingerprint: hashString(rows.map((r) => r.id).join('|')).slice(0, 12),
    dataSources: (report.scanInfo?.dataSource ?? []).map((d) => ({
      name: String(d.name ?? ''),
      timestamp: d.timestamp,
    })),
    addedAt: Date.now(),
  }

  return { rows, meta }
}

/** Read, hash and parse one uploaded file. */
export async function parseReportFile(file: File | Blob, fileName: string): Promise<ParsedReport> {
  const text = await file.text()
  const reportId = await contentKey(text)
  return parseReport(text, fileName, reportId)
}
