/**
 * Parser smoke test and determinism check.
 *
 *     npm run verify                        # the bundled sample estate
 *     npm run verify -- a.json b.json …     # your own reports
 *
 * Prints what each report yielded, the pooled remediation plan, and then
 * asserts the properties the UI takes for granted: parsing the same bytes twice
 * produces identical ids and fingerprints, every derived fix version really is
 * outside the range it was derived from, and no two findings share an id.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { basename, resolve } from 'node:path'
import { contentKey, parseReport, type Finding } from '../src/lib/parse'
import { packageSpread } from '../src/lib/filters'
import { compareVersions, parseVersionExpression, rangeContains } from '../src/lib/schema'
import { computeKpis, fixPlan, rollupByPackage } from '../src/lib/stats'

const SAMPLES = resolve(import.meta.dirname, '../public/samples')

function sampleFiles(): string[] {
  return readdirSync(SAMPLES)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => resolve(SAMPLES, f))
}

const args = process.argv.slice(2)
const files = args.length ? args.map((a) => resolve(a)) : sampleFiles()

if (!files.length) {
  console.error('No reports to verify. Pass paths, or run `node scripts/make-samples.mjs` first.')
  process.exit(1)
}

let failures = 0
function check(ok: boolean, label: string, detail?: string) {
  if (ok) {
    console.log(`  ok   ${label}`)
  } else {
    failures++
    console.log(`  FAIL ${label}${detail ? `\n       ${detail}` : ''}`)
  }
}

const allRows: Finding[] = []

console.log(`\nParsing ${files.length} report${files.length === 1 ? '' : 's'}\n${'='.repeat(60)}`)

for (const file of files) {
  const name = basename(file)
  let text: string
  try {
    text = readFileSync(file, 'utf8')
  } catch (e) {
    console.log(`\n${name}\n  FAIL could not read: ${e instanceof Error ? e.message : String(e)}`)
    failures++
    continue
  }

  const key = await contentKey(text)
  let parsed
  try {
    parsed = parseReport(text, name, key)
  } catch (e) {
    console.log(`\n${name}\n  FAIL ${e instanceof Error ? e.message : String(e)}`)
    failures++
    continue
  }

  const { rows, meta } = parsed
  allRows.push(...rows)

  console.log(`\n${name}`)
  console.log(`  MFE              ${meta.mfe}`)
  console.log(`  scanned          ${meta.reportDate ?? 'unknown'} · engine ${meta.engineVersion ?? '?'}`)
  console.log(`  dependencies     ${meta.dependencyCount} (${meta.vulnerableDependencies} vulnerable)`)
  console.log(`  findings         ${meta.findingCount}`)
  console.log(`  suppressed       ${meta.suppressedCount}`)
  console.log(`  fingerprint      ${meta.fingerprint}`)

  const bySeverity = new Map<string, number>()
  const byFix = new Map<string, number>()
  for (const r of rows) {
    bySeverity.set(r.severity, (bySeverity.get(r.severity) ?? 0) + 1)
    const fs = String(r.fixStatus)
    byFix.set(fs, (byFix.get(fs) ?? 0) + 1)
  }
  console.log(`  severity         ${[...bySeverity].map(([k, v]) => `${k}=${v}`).join(' ') || '-'}`)
  console.log(`  fix state        ${[...byFix].map(([k, v]) => `${k}=${v}`).join(' ') || '-'}`)

  // Determinism: the same bytes, parsed again, must produce the same output.
  const again = parseReport(text, name, key)
  check(again.meta.fingerprint === meta.fingerprint, 'reparse produces the same fingerprint')
  check(
    again.rows.length === rows.length && again.rows.every((r, i) => r.id === rows[i].id),
    'reparse produces the same row ids in the same order',
  )

  check(new Set(rows.map((r) => r.id)).size === rows.length, 'row ids are unique')

  // Every derived fix must actually sit outside the range it came from, or the
  // upgrade advice is wrong.
  const badFix = rows.find((r) => {
    const raw = String(r.affectedRange ?? '')
    const fixed = String(r.fixedIn ?? '')
    if (!raw || !fixed || r.fixStatus !== 'Exact fix') return false
    const range = parseVersionExpression(raw)
    return range ? rangeContains(range, fixed) : false
  })
  check(
    !badFix,
    'every exact fix version falls outside its advisory range',
    badFix && `${badFix.packageName} ${badFix.fixedIn} is still inside ${badFix.affectedRange}`,
  )

  // And it must be an actual upgrade from what is installed.
  const notAnUpgrade = rows.find((r) => {
    const fixed = String(r.fixedIn ?? '')
    const installed = String(r.packageVersion ?? '')
    if (!fixed || !installed || r.fixStatus !== 'Exact fix') return false
    return compareVersions(fixed, installed) <= 0
  })
  check(
    !notAnUpgrade,
    'every exact fix version is higher than the installed version',
    notAnUpgrade &&
      `${notAnUpgrade.packageName}: installed ${notAnUpgrade.packageVersion}, "fix" ${notAnUpgrade.fixedIn}`,
  )
}

// --- the pooled view ------------------------------------------------------

if (allRows.length) {
  const spread = packageSpread(allRows)
  const packages = rollupByPackage(allRows)
  const plan = fixPlan(allRows, packages)
  const kpis = computeKpis(allRows, spread)

  console.log(`\n${'='.repeat(60)}\nPooled across ${kpis.mfes} MFEs`)
  console.log(`  findings         ${kpis.findings}`)
  console.log(`  advisories       ${kpis.advisories}`)
  console.log(`  bad packages     ${kpis.packages} (${kpis.sharedPackages} shared by 2+ MFEs)`)
  console.log(`  bumps to do      ${kpis.bumps}`)
  console.log(`  version drift    ${kpis.versionDriftPackages} packages`)
  console.log(`  remote unauth    ${kpis.remoteUnauth}`)
  console.log(`  stalest scan     ${kpis.stalestScanDays ?? '?'}d (${kpis.stalestMfe ?? '-'})`)

  console.log('\n  Remediation plan')
  console.log(`  ${'package'.padEnd(20)} ${'bump to'.padEnd(12)} closes  MFEs  cumulative`)
  for (const step of plan.slice(0, 10)) {
    console.log(
      `  ${step.packageName.slice(0, 19).padEnd(20)} ${step.targetVersion.padEnd(12)} ` +
        `${String(step.closes).padStart(6)}  ${String(step.mfeCount).padStart(4)}  ` +
        `${String(Math.round(step.cumulativePct * 100)).padStart(3)}%`,
    )
  }

  const drift = packages.filter((p) => p.versionDrift)
  if (drift.length) {
    console.log('\n  Version drift')
    for (const p of drift) {
      console.log(`  ${p.packageName.padEnd(20)} ${p.versions.join(', ')}  ->  ${p.targetVersion || '?'}`)
    }
  }

  console.log('\n  Assertions')
  check(
    plan.every((s, i) => i === 0 || s.cumulative >= plan[i - 1].cumulative),
    'the fix plan’s cumulative total never decreases',
  )
  check(
    plan.every((s) => s.closes <= s.findings),
    'a bump never claims to close more findings than the package has',
  )
  check(
    packages.every((p) => p.closes + p.residual === p.findings),
    'closed + left over accounts for every finding on each package',
  )
  check(
    packages.every((p) => p.mfeCount === (spread.get(p.packageName) ?? 0)),
    'per-package MFE counts agree with the workspace-wide spread',
  )
  const overCounted = packages.find((p) => p.mfeCount > kpis.mfes)
  check(!overCounted, 'no package claims more MFEs than are loaded', overCounted?.packageName)
}

console.log(`\n${'='.repeat(60)}`)
if (failures) {
  console.log(`${failures} check${failures === 1 ? '' : 's'} failed.\n`)
  process.exit(1)
}
console.log('All checks passed.\n')
