/**
 * Breakdowns and rollups.
 *
 * The reason this tool exists is the *package* rollup: a dozen MFEs built on
 * one stack share most of their dependency tree, so the same four advisories
 * turn up a dozen times and the estate-wide question is not "how many findings
 * do we have" but "which handful of version bumps clears most of them".
 */

import type { Finding, ReportMeta } from './parse'
import {
  compareVersions,
  fixConstraintFor,
  formatConstraint,
  maxVersion,
  parseVersionExpression,
  severityRank,
  SEVERITY_ORDER,
  strongestConstraint,
  type FixConstraint,
  type Severity,
} from './schema'

export interface Bucket {
  key: string
  count: number
}

/** Count rows by a field, in a caller-supplied order where one exists. */
export function countBy(rows: Finding[], key: string, order?: readonly string[]): Bucket[] {
  const m = new Map<string, number>()
  for (const r of rows) {
    const raw = r[key]
    const k = raw == null || raw === '' ? 'Unknown' : String(raw)
    m.set(k, (m.get(k) ?? 0) + 1)
  }
  const entries = [...m.entries()].map(([key, count]) => ({ key, count }))
  if (order) {
    const idx = new Map(order.map((o, i) => [o, i]))
    return entries.sort((a, b) => (idx.get(a.key) ?? 999) - (idx.get(b.key) ?? 999) || a.key.localeCompare(b.key))
  }
  return entries.sort((a, b) => b.count - a.count || a.key.localeCompare(b.key))
}

export function severityBreakdown(rows: Finding[]): Bucket[] {
  return countBy(rows, 'severity', SEVERITY_ORDER)
}

/** Rows grouped by `key`, each with a severity split - for stacked bars. */
export interface StackedRow extends Record<string, string | number> {
  key: string
  total: number
}

export function stackedBySeverity(rows: Finding[], key: string, topN = 12): StackedRow[] {
  const m = new Map<string, StackedRow>()
  for (const r of rows) {
    const raw = r[key]
    const k = raw == null || raw === '' ? 'Unknown' : String(raw)
    let e = m.get(k)
    if (!e) {
      e = { key: k, total: 0 }
      for (const s of SEVERITY_ORDER) e[s] = 0
      m.set(k, e)
    }
    const sev = String(r.severity ?? 'Unknown')
    if (sev in e) (e[sev] as number)++
    e.total++
  }
  return [...m.values()].sort((a, b) => b.total - a.total || a.key.localeCompare(b.key)).slice(0, topN)
}

function worstSeverity(rows: Finding[]): Severity {
  return rows.reduce<Severity>(
    (worst, r) => (severityRank(r.severity) < severityRank(worst) ? (r.severity as Severity) : worst),
    'Unknown',
  )
}

function maxCvss(rows: Finding[]): number | undefined {
  return rows.reduce<number | undefined>((mx, r) => {
    const c = r.cvss as number | undefined
    return c == null ? mx : mx == null ? c : Math.max(mx, c)
  }, undefined)
}

function uniq(rows: Finding[], key: string): string[] {
  return [...new Set(rows.map((r) => String(r[key] ?? '')).filter(Boolean))].sort()
}

function groupBy(rows: Finding[], key: string): Map<string, Finding[]> {
  const m = new Map<string, Finding[]>()
  for (const r of rows) {
    const k = String(r[key] ?? '')
    if (!k) continue
    const list = m.get(k)
    if (list) list.push(r)
    else m.set(k, [r])
  }
  return m
}

/** The fix constraint this finding carries, re-derived from its stored range. */
function constraintOf(r: Finding): FixConstraint | undefined {
  const raw = String(r.affectedRange ?? '')
  if (!raw) return undefined
  const range = parseVersionExpression(raw)
  return range ? fixConstraintFor(range) : undefined
}

// --- Package rollup: the remediation plan --------------------------------

export interface PackageRollup {
  packageName: string
  ecosystem: string
  /** Distinct installed versions across the estate, ascending. */
  versions: string[]
  /** More than one version in play — the bump is not uniform across MFEs. */
  versionDrift: boolean
  /** The oldest version anyone is on; the one that decides the work. */
  lowestVersion?: string
  mfes: string[]
  mfeCount: number
  findings: number
  advisories: string[]
  advisoryCount: number
  worstSeverity: Severity
  maxCvss?: number
  /** The single version to move to so every derivable advisory here is cleared. */
  target?: FixConstraint
  targetVersion: string
  /** Findings this one bump provably closes. */
  closes: number
  /** Findings left behind because their advisory names no fixed version. */
  residual: number
  /** MFEs already on a version at or past the target — nothing to do there. */
  alreadyClear: string[]
  remoteUnauth: number
  scope: string
}

/**
 * One row per package: *"if I bump this one dependency, how many findings close
 * and which MFEs do I have to touch?"*
 *
 * The target version is the strongest constraint across every advisory against
 * the package, so it is a single number that satisfies all of them at once
 * rather than a per-advisory list somebody has to reconcile by hand.
 */
export function rollupByPackage(rows: Finding[]): PackageRollup[] {
  return [...groupBy(rows, 'packageName').entries()]
    .map(([packageName, list]) => {
      const constraints = list.map(constraintOf).filter((c): c is FixConstraint => c != null)
      const target = strongestConstraint(constraints)
      const versions = uniq(list, 'packageVersion').sort(compareVersions)
      const scopes = new Set(list.map((r) => String(r.dependencyScope ?? 'Unknown')))
      const mfes = uniq(list, 'mfe')

      // An MFE already on a satisfying version has nothing to do here; without
      // this the plan would send people to repos that are already fine.
      const alreadyClear = target
        ? [
            ...new Set(
              list
                .filter((r) => {
                  const v = String(r.packageVersion ?? '')
                  if (!v) return false
                  const cmp = compareVersions(v, target.version)
                  return target.op === '>=' ? cmp >= 0 : cmp > 0
                })
                .map((r) => r.mfe),
            ),
          ].sort()
        : []

      return {
        packageName,
        ecosystem: String(list[0].ecosystem ?? ''),
        versions,
        versionDrift: versions.length > 1,
        lowestVersion: versions[0],
        mfes,
        mfeCount: mfes.length,
        findings: list.length,
        advisories: uniq(list, 'advisory'),
        advisoryCount: new Set(list.map((r) => r.advisory)).size,
        worstSeverity: worstSeverity(list),
        maxCvss: maxCvss(list),
        target,
        targetVersion: formatConstraint(target),
        closes: constraints.length,
        residual: list.length - constraints.length,
        alreadyClear,
        remoteUnauth: list.filter((r) => r.exposure === 'Remote, unauthenticated').length,
        scope: scopes.size > 1 ? 'Mixed' : (scopes.values().next().value ?? 'Unknown'),
      }
    })
    .sort(
      (a, b) =>
        b.findings - a.findings ||
        b.mfeCount - a.mfeCount ||
        severityRank(a.worstSeverity) - severityRank(b.worstSeverity) ||
        a.packageName.localeCompare(b.packageName),
    )
}

// --- Advisory rollup -----------------------------------------------------

export interface AdvisoryRollup {
  advisory: string
  cve: string
  severity: Severity
  cvss?: number
  cwe: string
  source: string
  exposure: string
  mfes: string[]
  mfeCount: number
  packages: string[]
  versions: string[]
  findings: number
  fixedIn: string
  fixStatus: string
  description: string
}

/** One row per advisory, with its blast radius across the estate. */
export function rollupByAdvisory(rows: Finding[]): AdvisoryRollup[] {
  return [...groupBy(rows, 'advisory').entries()]
    .map(([advisory, list]) => {
      const mfes = uniq(list, 'mfe')
      const first = list[0]
      // The same advisory can hit several packages at different versions, so
      // take the strongest fix across them rather than whichever came first.
      const target = strongestConstraint(list.map(constraintOf).filter((c): c is FixConstraint => c != null))
      return {
        advisory,
        cve: String(list.find((r) => r.cve)?.cve ?? ''),
        severity: worstSeverity(list),
        cvss: maxCvss(list),
        cwe: String(list.find((r) => r.cwe)?.cwe ?? ''),
        source: String(first.source ?? ''),
        exposure: String(first.exposure ?? 'Unknown'),
        mfes,
        mfeCount: mfes.length,
        packages: uniq(list, 'packageName'),
        versions: uniq(list, 'packageVersion').sort(compareVersions),
        findings: list.length,
        fixedIn: formatConstraint(target),
        fixStatus: target ? (target.op === '>=' ? 'Exact fix' : 'Later release') : 'Unknown',
        description: String(list.find((r) => r.description)?.description ?? ''),
      }
    })
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        b.mfeCount - a.mfeCount ||
        b.findings - a.findings ||
        a.advisory.localeCompare(b.advisory),
    )
}

// --- MFE scorecard -------------------------------------------------------

export interface MfeRollup {
  mfe: string
  reportId: string
  reportDate: string
  scanAgeDays?: number
  engineVersion: string
  findings: number
  critical: number
  high: number
  medium: number
  low: number
  maxCvss?: number
  packages: number
  advisories: number
  /** Packages here with a derivable target version — the size of the to-do list. */
  bumps: number
  fixableFindings: number
  remoteUnauth: number
  /** Findings in packages that at least one other MFE also carries. */
  sharedFindings: number
  /** Findings in packages nobody else has — this team's own problem. */
  uniqueFindings: number
  dependencyCount?: number
}

/**
 * One row per MFE. `spread` must be computed over the whole workspace, so the
 * shared/unique split stays a fact about the estate.
 */
export function rollupByMfe(rows: Finding[], spread: Map<string, number>, metas: ReportMeta[]): MfeRollup[] {
  const metaByName = new Map(metas.map((m) => [m.mfe, m]))
  return [...groupBy(rows, 'mfe').entries()]
    .map(([mfe, list]) => {
      const meta = metaByName.get(mfe)
      const packages = rollupByPackage(list)
      const sev = (s: Severity) => list.filter((r) => r.severity === s).length
      const shared = list.filter((r) => (spread.get(r.packageName) ?? 0) > 1).length
      return {
        mfe,
        reportId: String(list[0].reportId ?? ''),
        reportDate: String(list[0].reportDate ?? ''),
        scanAgeDays: list[0].scanAgeDays as number | undefined,
        engineVersion: String(list[0].engineVersion ?? ''),
        findings: list.length,
        critical: sev('Critical'),
        high: sev('High'),
        medium: sev('Medium'),
        low: sev('Low'),
        maxCvss: maxCvss(list),
        packages: packages.length,
        advisories: new Set(list.map((r) => r.advisory)).size,
        bumps: packages.filter((p) => p.target).length,
        fixableFindings: list.filter((r) => r.fixStatus === 'Exact fix').length,
        remoteUnauth: list.filter((r) => r.exposure === 'Remote, unauthenticated').length,
        sharedFindings: shared,
        uniqueFindings: list.length - shared,
        dependencyCount: meta?.dependencyCount,
      }
    })
    .sort(
      (a, b) =>
        b.critical - a.critical || b.high - a.high || b.findings - a.findings || a.mfe.localeCompare(b.mfe),
    )
}

// --- The fix plan --------------------------------------------------------

export interface FixPlanStep extends PackageRollup {
  /** Findings closed by this step and every step above it. */
  cumulative: number
  /** Share of all findings in view closed by this point. */
  cumulativePct: number
}

/**
 * Package bumps ordered by how much each one closes, with the running total.
 *
 * This is the chart that answers "how much of the backlog is a morning's
 * work?" — on a shared stack the curve is usually brutally steep.
 */
export function fixPlan(rows: Finding[], packages?: PackageRollup[]): FixPlanStep[] {
  const list = (packages ?? rollupByPackage(rows)).filter((p) => p.target && p.closes > 0)
  const ranked = [...list].sort(
    (a, b) =>
      b.closes - a.closes ||
      b.mfeCount - a.mfeCount ||
      severityRank(a.worstSeverity) - severityRank(b.worstSeverity) ||
      a.packageName.localeCompare(b.packageName),
  )
  const total = rows.length || 1
  let cumulative = 0
  return ranked.map((p) => {
    cumulative += p.closes
    return { ...p, cumulative, cumulativePct: cumulative / total }
  })
}

/** How many packages are shared by exactly k MFEs — the pooling payoff, plotted. */
export function spreadHistogram(spread: Map<string, number>, packagesInView: Set<string>): Bucket[] {
  const m = new Map<number, number>()
  for (const [pkg, n] of spread) {
    if (!packagesInView.has(pkg)) continue
    m.set(n, (m.get(n) ?? 0) + 1)
  }
  return [...m.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([n, count]) => ({ key: n === 1 ? '1 MFE' : `${n} MFEs`, count }))
}

// --- Headline numbers ----------------------------------------------------

export interface Kpis {
  mfes: number
  findings: number
  advisories: number
  packages: number
  critical: number
  high: number
  remoteUnauth: number
  /** Findings whose advisory names an exact clean version. */
  fixable: number
  /** Distinct package bumps that would close those findings. */
  bumps: number
  /** Findings closed by the five highest-leverage bumps. */
  quickWin: number
  quickWinBumps: number
  /** Packages carried by two or more MFEs. */
  sharedPackages: number
  sharedFindings: number
  /** Age of the stalest report in view, in days. */
  stalestScanDays?: number
  stalestMfe?: string
  versionDriftPackages: number
}

export function computeKpis(rows: Finding[], spread: Map<string, number>): Kpis {
  const packages = rollupByPackage(rows)
  const plan = fixPlan(rows, packages)
  const quickWinSteps = plan.slice(0, 5)

  let critical = 0
  let high = 0
  let remoteUnauth = 0
  let fixable = 0
  let sharedFindings = 0
  let stalestScanDays: number | undefined
  let stalestMfe: string | undefined
  const mfes = new Set<string>()
  const advisories = new Set<string>()

  for (const r of rows) {
    if (r.severity === 'Critical') critical++
    else if (r.severity === 'High') high++
    if (r.exposure === 'Remote, unauthenticated') remoteUnauth++
    if (r.fixStatus === 'Exact fix') fixable++
    if ((spread.get(r.packageName) ?? 0) > 1) sharedFindings++
    mfes.add(r.mfe)
    advisories.add(r.advisory)

    const age = r.scanAgeDays as number | undefined
    if (age != null && (stalestScanDays == null || age > stalestScanDays)) {
      stalestScanDays = age
      stalestMfe = r.mfe
    }
  }

  const inView = new Set(packages.map((p) => p.packageName))

  return {
    mfes: mfes.size,
    findings: rows.length,
    advisories: advisories.size,
    packages: packages.length,
    critical,
    high,
    remoteUnauth,
    fixable,
    bumps: packages.filter((p) => p.target).length,
    quickWin: quickWinSteps.at(-1)?.cumulative ?? 0,
    quickWinBumps: quickWinSteps.length,
    sharedPackages: [...inView].filter((p) => (spread.get(p) ?? 0) > 1).length,
    sharedFindings,
    stalestScanDays,
    stalestMfe,
    versionDriftPackages: packages.filter((p) => p.versionDrift).length,
  }
}

/** Highest installed version of a package anywhere in the estate. */
export function highestInstalled(rows: Finding[], packageName: string): string | undefined {
  return maxVersion(rows.filter((r) => r.packageName === packageName).map((r) => String(r.packageVersion ?? '')).filter(Boolean))
}
