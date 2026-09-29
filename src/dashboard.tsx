import type { GridApi } from 'ag-grid-community'
import { PanelLeftIcon } from 'lucide-react'
import { useCallback, useMemo, useState } from 'react'
import {
  DimensionChart,
  FixPlanChart,
  MfeChart,
  PackageChart,
  SeverityChart,
  SpreadChart,
} from '@/components/charts/dashboard-charts'
import { FacetPanel } from '@/components/facet-panel'
import { FindingDetail } from '@/components/finding-detail'
import { exportGridCsv, FindingsGrid, type GridContext } from '@/components/findings-grid'
import { KpiCards } from '@/components/kpi-cards'
import { ReportManager } from '@/components/report-manager'
import { ResizableSidebar } from '@/components/resizable-sidebar'
import { AdvisoryGrid, MfeGrid, PackageGrid } from '@/components/rollup-grids'
import { Toolbar } from '@/components/toolbar'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  useEffectiveFilters,
  useFilteredRows,
  useFilters,
  type IngestOutcome,
  type useWorkspace,
} from '@/hooks/use-workspace'
import { DEFAULT_ADVISORY_SOURCE } from '@/lib/advisory'
import { setFacet, toggleFacet } from '@/lib/filters'
import type { Finding } from '@/lib/parse'
import { computeKpis } from '@/lib/stats'

type Workspace = ReturnType<typeof useWorkspace>

/** Columns worth offering as a facet — anything with more than one value. */
const FACET_CANDIDATES = [
  'mfe', 'dependencyScope', 'projectRef', 'severity', 'exposure', 'baseSeverity', 'cwe',
  'fixStatus', 'packageName', 'fixedIn', 'ecosystem', 'packageVersion', 'attackVector',
  'attackComplexity', 'privilegesRequired', 'userInteraction', 'cvssScope',
  'confidentialityImpact', 'integrityImpact', 'availabilityImpact', 'cvssVersion',
  'source', 'advisory', 'unscored', 'engineVersion',
]

/**
 * A facet whose every row holds the same value cannot narrow anything, so it is
 * dropped rather than shown as a single un-unselectable checkbox.
 */
function usefulFacetKeys(rows: Finding[], candidates: string[]): Set<string> {
  const keys = new Set<string>()
  for (const key of candidates) {
    const seen = new Set<string>()
    for (const r of rows) {
      const v = r[key]
      if (v != null && v !== '') seen.add(String(v))
      // Two distinct values is enough to make a facet worth offering; stop
      // scanning rather than building the full value set for every column.
      if (seen.size > 1) break
    }
    if (seen.size > 1) keys.add(key)
  }
  return keys
}

export default function Dashboard({
  ws,
  outcomes,
  onAddFiles,
  onDismissOutcomes,
}: {
  ws: Workspace
  outcomes: IngestOutcome[]
  onAddFiles: (files: File[]) => void
  onDismissOutcomes: () => void
}) {
  const { filters, setFilters, clearAll } = useFilters()
  const [advisorySource, setAdvisorySource] = useState(DEFAULT_ADVISORY_SOURCE)
  const [selected, setSelected] = useState<Finding | null>(null)
  const [gridApis, setGridApis] = useState<Record<string, GridApi | null>>({})
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [managerOpen, setManagerOpen] = useState(false)
  const [tab, setTab] = useState('overview')

  // Leaving the Findings tab closes the detail sheet: it belongs to a row in
  // that grid, and leaving it open over a different view reads as a bug.
  const changeTab = useCallback((next: string) => {
    setTab(next)
    if (next !== 'findings') setSelected(null)
  }, [])

  const rows = ws.rows
  const effective = useEffectiveFilters(filters)
  const filtered = useFilteredRows(rows, effective, ws.context)
  const kpis = useMemo(() => computeKpis(filtered, ws.context.spread), [filtered, ws.context.spread])

  const availableKeys = useMemo(() => usefulFacetKeys(rows, FACET_CANDIDATES), [rows])

  /** Which MFEs each advisory shows up in — for the hover card and detail sheet. */
  const advisoryMfes = useMemo(() => {
    const m = new Map<string, Set<string>>()
    for (const r of rows) {
      let set = m.get(r.advisory)
      if (!set) {
        set = new Set()
        m.set(r.advisory, set)
      }
      set.add(r.mfe)
    }
    return new Map([...m].map(([k, v]) => [k, [...v].sort()]))
  }, [rows])

  const gridContext = useMemo<GridContext>(
    () => ({ advisorySource, spread: ws.context.spread, mfeCount: ws.reports.length, advisoryMfes }),
    [advisorySource, ws.context.spread, ws.reports.length, advisoryMfes],
  )

  const only = useCallback(
    (key: string, value: string) => setFilters(setFacet(filters, key, [value])),
    [filters, setFilters],
  )
  const toggle = useCallback(
    (key: string, value: string) => setFilters(toggleFacet(filters, key, value)),
    [filters, setFilters],
  )

  const kpiActions = useMemo(
    () => ({
      onSeverity: (sev: string) => only('severity', sev),
      onRemote: () => only('exposure', 'Remote, unauthenticated'),
      onFixable: () => setFilters({ ...filters, fixableOnly: true }),
      onShared: () => setFilters({ ...filters, minMfes: 2 }),
      onDrift: () => {
        // Version drift is a property of a package, not of a row, so the filter
        // is expressed as the set of packages that have it.
        const byPkg = new Map<string, Set<string>>()
        for (const r of rows) {
          let set = byPkg.get(r.packageName)
          if (!set) {
            set = new Set()
            byPkg.set(r.packageName, set)
          }
          set.add(r.packageVersion)
        }
        setFilters(
          setFacet(
            filters,
            'packageName',
            [...byPkg].filter(([, v]) => v.size > 1).map(([k]) => k),
          ),
        )
      },
    }),
    [filters, setFilters, only, rows],
  )

  const exportCurrent = useCallback(() => {
    const api = gridApis[tab] ?? gridApis.findings
    const name =
      tab === 'packages'
        ? 'remediation-plan'
        : tab === 'advisories'
          ? 'advisories'
          : tab === 'mfes'
            ? 'mfe-scorecard'
            : 'findings'
    exportGridCsv(api ?? null, `mfe-${name}.csv`)
  }, [gridApis, tab])

  const registerApi = useCallback(
    (key: string) => (api: GridApi) => setGridApis((s) => (s[key] === api ? s : { ...s, [key]: api })),
    [],
  )

  const packagesInView = useMemo(() => new Set(filtered.map((r) => r.packageName)), [filtered])

  return (
    <div className="flex h-full flex-col">
      <Toolbar
        filters={filters}
        setFilters={setFilters}
        clearAll={clearAll}
        total={rows.length}
        shown={filtered.length}
        metas={ws.metas}
        advisorySource={advisorySource}
        setAdvisorySource={setAdvisorySource}
        onExport={exportCurrent}
        onManageReports={() => setManagerOpen(true)}
      />

      <IngestBanner outcomes={outcomes} onDismiss={onDismissOutcomes} />

      <div className="flex min-h-0 flex-1">
        <ResizableSidebar open={sidebarOpen} className="bg-card/40 border-r">
          <FacetPanel
            rows={rows}
            filters={filters}
            countBasis={effective}
            context={ws.context}
            setFilters={setFilters}
            availableKeys={availableKeys}
          />
        </ResizableSidebar>

        <main className="flex min-w-0 flex-1 flex-col">
          <Tabs value={tab} onValueChange={changeTab} className="flex min-h-0 flex-1 flex-col gap-0">
            <div className="flex items-center gap-2 border-b px-3 py-1.5">
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={() => setSidebarOpen((s) => !s)}
                aria-label={sidebarOpen ? 'Hide filters' : 'Show filters'}
              >
                <PanelLeftIcon />
              </Button>
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="packages">Remediation</TabsTrigger>
                <TabsTrigger value="mfes">By MFE</TabsTrigger>
                <TabsTrigger value="advisories">By advisory</TabsTrigger>
                <TabsTrigger value="findings">Findings</TabsTrigger>
              </TabsList>
            </div>

            <TabsContent value="overview" className="min-h-0 data-[state=inactive]:hidden">
              <ScrollArea className="h-full">
                <div className="space-y-3 p-3">
                  <KpiCards kpis={kpis} actions={kpiActions} />
                  <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-3">
                    <FixPlanChart rows={filtered} onSelect={(p) => only('packageName', p)} />
                    <SeverityChart rows={filtered} onSelect={(s) => only('severity', s)} />
                    <MfeChart rows={filtered} onSelect={(m) => toggle('mfe', m)} />
                    <PackageChart rows={filtered} onSelect={(p) => toggle('packageName', p)} />
                    <div className="grid gap-3">
                      <SpreadChart
                        spread={ws.context.spread}
                        packagesInView={packagesInView}
                        mfeCount={ws.reports.length}
                      />
                      <DimensionChart
                        rows={filtered}
                        dimension="fixStatus"
                        title="Fix availability"
                        description="Can a target version be derived from the advisory?"
                        onSelect={(v) => toggle('fixStatus', v)}
                        height={150}
                        topN={4}
                      />
                    </div>
                    <DimensionChart
                      rows={filtered}
                      dimension="exposure"
                      title="Exposure"
                      description="How reachable, read off the CVSS vector"
                      onSelect={(v) => toggle('exposure', v)}
                      height={200}
                      topN={6}
                    />
                    <DimensionChart
                      rows={filtered}
                      dimension="cwe"
                      title="Weakness class"
                      description="The kind of bug, by CWE"
                      onSelect={(v) => toggle('cwe', v)}
                      height={220}
                    />
                    <DimensionChart
                      rows={filtered}
                      dimension="dependencyScope"
                      title="Direct vs transitive"
                      description="Whether it is in your package.json or pulled in beneath it"
                      onSelect={(v) => toggle('dependencyScope', v)}
                      height={150}
                      topN={4}
                    />
                  </div>
                </div>
              </ScrollArea>
            </TabsContent>

            <TabsContent value="packages" className="min-h-0 data-[state=inactive]:hidden">
              <PackageGrid
                rows={filtered}
                mfeCount={ws.reports.length}
                onSelect={(p) => only('packageName', p)}
                onApiReady={registerApi('packages')}
              />
            </TabsContent>

            <TabsContent value="mfes" className="min-h-0 data-[state=inactive]:hidden">
              <MfeGrid
                rows={filtered}
                spread={ws.context.spread}
                metas={ws.metas}
                onSelect={(m) => only('mfe', m)}
                onApiReady={registerApi('mfes')}
              />
            </TabsContent>

            <TabsContent value="advisories" className="min-h-0 data-[state=inactive]:hidden">
              <AdvisoryGrid
                rows={filtered}
                advisorySource={advisorySource}
                mfeCount={ws.reports.length}
                onSelect={(a) => only('advisory', a)}
                onApiReady={registerApi('advisories')}
              />
            </TabsContent>

            <TabsContent value="findings" className="min-h-0 data-[state=inactive]:hidden">
              <FindingsGrid
                rows={filtered}
                context={gridContext}
                onRowClick={setSelected}
                onApiReady={registerApi('findings')}
              />
            </TabsContent>
          </Tabs>
        </main>
      </div>

      <FindingDetail
        finding={selected}
        advisorySource={advisorySource}
        mfesForAdvisory={selected ? (advisoryMfes.get(selected.advisory) ?? []) : []}
        onClose={() => setSelected(null)}
        onFilterBy={(k, v) => {
          only(k, v)
          setSelected(null)
        }}
      />

      <ReportManager
        open={managerOpen}
        onOpenChange={setManagerOpen}
        reports={ws.reports}
        onAddFiles={onAddFiles}
        onRename={ws.renameMfe}
        onRemove={ws.removeReport}
        onClearAll={ws.clearAll}
        busy={ws.busy}
      />
    </div>
  )
}

/**
 * What just happened to the dropped files. A replaced report and a rejected
 * duplicate look identical from the outside — the count simply does not go up —
 * so both are stated rather than left to be inferred.
 */
function IngestBanner({ outcomes, onDismiss }: { outcomes: IngestOutcome[]; onDismiss: () => void }) {
  if (!outcomes.length) return null

  const added = outcomes.filter((o) => o.kind === 'added')
  const replaced = outcomes.filter((o) => o.kind === 'replaced')
  const duplicates = outcomes.filter((o) => o.kind === 'duplicate')
  const failed = outcomes.filter((o) => o.kind === 'failed')
  const older = replaced.filter((o) => o.older)

  const parts: string[] = []
  if (added.length) parts.push(`${added.length} report${added.length === 1 ? '' : 's'} added`)
  if (replaced.length) parts.push(`${replaced.length} replaced with a newer scan`)
  if (duplicates.length) parts.push(`${duplicates.length} already loaded`)

  return (
    <div
      className={`flex items-start gap-3 border-b px-3 py-2 text-xs ${
        failed.length ? 'border-destructive/40 bg-destructive/10' : 'bg-muted/40'
      }`}
    >
      <div className="min-w-0 flex-1 space-y-1">
        {parts.length > 0 && <p>{parts.join(' · ')}.</p>}
        {older.map((o) => (
          <p key={o.fileName} className="text-sev-medium">
            {o.mfe}: the report you just dropped is <strong>older</strong> than the one it replaced. Check you
            uploaded the right file.
          </p>
        ))}
        {duplicates.map((o) => (
          <p key={o.fileName} className="text-muted-foreground">
            {o.fileName} is byte-for-byte identical to the report already loaded for {o.mfe} — nothing changed.
          </p>
        ))}
        {failed.map((o) => (
          <p key={o.fileName} className="text-destructive">
            {o.message}
          </p>
        ))}
      </div>
      <Button variant="ghost" size="xs" onClick={onDismiss}>
        Dismiss
      </Button>
    </div>
  )
}
