import type { ColDef, GridApi, GridReadyEvent, ValueFormatterParams } from 'ag-grid-community'
import { AgGridReact } from 'ag-grid-react'
import { useCallback, useMemo } from 'react'
import { AdvisoryLink, ExposureBadge, FixBadge, SeverityBadge, SpreadBadge, UpgradeCell } from '@/components/badges'
import { useTheme } from '@/components/theme-provider'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { cvss as fmtCvss, date as fmtDate, truncate } from '@/lib/format'
import type { Finding, ReportMeta } from '@/lib/parse'
import { defaultColDef, gridTheme } from '@/lib/grid-theme'
import { severityRank } from '@/lib/schema'
import {
  rollupByAdvisory,
  rollupByMfe,
  rollupByPackage,
  type AdvisoryRollup,
  type MfeRollup,
  type PackageRollup,
} from '@/lib/stats'

function listFormatter(p: ValueFormatterParams) {
  return Array.isArray(p.value) ? p.value.join(', ') : String(p.value ?? '')
}

function ListCell({ values, max = 2 }: { values: string[]; max?: number }) {
  if (!values?.length) return <span className="text-muted-foreground">-</span>
  return (
    <span className="flex min-w-0 items-center gap-1" title={values.join('\n')}>
      <span className="truncate">{values.slice(0, max).join(', ')}</span>
      {values.length > max && (
        <Badge variant="secondary" className="shrink-0 px-1 tabular-nums">
          +{values.length - max}
        </Badge>
      )}
    </span>
  )
}

// --- Remediation: one row per package ------------------------------------

/**
 * The view the whole tool is built around: *"if I bump this one dependency,
 * how many findings close and which MFEs do I have to touch?"*
 *
 * Default sort is findings closed, because that is the order the work should
 * actually be done in — not alphabetical, and not by severity, which would put
 * a single Critical above a bump that clears thirty Highs across six repos.
 */
export function PackageGrid({
  rows,
  mfeCount,
  onSelect,
  onApiReady,
}: {
  rows: Finding[]
  mfeCount: number
  onSelect?: (pkg: string) => void
  onApiReady?: (api: GridApi) => void
}) {
  const { resolved } = useTheme()
  const data = useMemo(() => rollupByPackage(rows), [rows])

  const columnDefs = useMemo<ColDef<PackageRollup>[]>(
    () => [
      {
        field: 'worstSeverity',
        headerName: 'Worst',
        width: 104,
        pinned: 'left',
        comparator: (a, b) => severityRank(a) - severityRank(b),
        cellRenderer: (p: { value: unknown }) => <SeverityBadge severity={p.value} />,
      },
      { field: 'packageName', headerName: 'Package', width: 230, pinned: 'left', tooltipField: 'packageName' },
      {
        field: 'closes',
        headerName: 'Findings closed',
        width: 146,
        type: 'numericColumn',
        sort: 'desc',
        headerTooltip: 'Findings this single bump provably clears, across every MFE in view',
      },
      {
        field: 'mfeCount',
        headerName: 'MFEs',
        width: 96,
        type: 'numericColumn',
        cellRenderer: (p: { value: number; data?: PackageRollup }) => (
          <Tooltip>
            <TooltipTrigger asChild>
              <span>
                <SpreadBadge count={p.value} total={mfeCount} />
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-sm">{p.data?.mfes.join(', ')}</TooltipContent>
          </Tooltip>
        ),
      },
      {
        field: 'targetVersion',
        headerName: 'Bump to',
        width: 136,
        cellRenderer: (p: { value: unknown }) =>
          p.value ? (
            <span className="font-mono text-xs font-medium">{String(p.value)}</span>
          ) : (
            <span className="text-muted-foreground">unknown</span>
          ),
        headerTooltip: 'The single version that satisfies every advisory against this package at once',
      },
      {
        field: 'versions',
        headerName: 'Currently on',
        width: 190,
        valueFormatter: listFormatter,
        cellRenderer: (p: { value: string[]; data?: PackageRollup }) => (
          <span className="flex min-w-0 items-center gap-1.5">
            <ListCell values={p.value ?? []} />
            {p.data?.versionDrift && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant="outline"
                    className="border-sev-high/40 bg-sev-high/15 text-sev-high shrink-0 font-medium"
                  >
                    drift
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  MFEs resolved different versions of this package, so the upgrade is not identical everywhere.
                </TooltipContent>
              </Tooltip>
            )}
          </span>
        ),
      },
      {
        colId: 'upgrade',
        headerName: 'Upgrade',
        width: 176,
        valueGetter: (p) => `${p.data?.lowestVersion ?? ''} → ${p.data?.targetVersion ?? ''}`,
        cellRenderer: (p: { data?: PackageRollup }) => (
          <UpgradeCell from={p.data?.lowestVersion} to={p.data?.targetVersion} />
        ),
      },
      {
        field: 'residual',
        headerName: 'Left over',
        width: 116,
        type: 'numericColumn',
        cellRenderer: (p: { value: number }) =>
          p.value > 0 ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge variant="outline" className="border-sev-medium/40 bg-sev-medium/15 text-sev-medium tabular-nums">
                  {p.value}
                </Badge>
              </TooltipTrigger>
              <TooltipContent className="max-w-sm">
                Findings this bump does not clear, because their advisory names no fixed version. They need a
                manual check against the project.
              </TooltipContent>
            </Tooltip>
          ) : (
            <span className="text-muted-foreground">0</span>
          ),
      },
      { field: 'findings', headerName: 'Findings', width: 106, type: 'numericColumn' },
      { field: 'advisoryCount', headerName: 'Advisories', width: 116, type: 'numericColumn' },
      {
        field: 'remoteUnauth',
        headerName: 'Remote unauth',
        width: 140,
        type: 'numericColumn',
        headerTooltip: 'Of these findings, how many are reachable remotely with no credentials',
      },
      { field: 'maxCvss', headerName: 'Max CVSS', width: 110, type: 'numericColumn', valueFormatter: (p) => fmtCvss(p.value) },
      {
        field: 'scope',
        headerName: 'Scope',
        width: 106,
        cellRenderer: (p: { value: unknown }) => (
          <Badge variant={p.value === 'Direct' ? 'secondary' : 'outline'} className="font-normal">
            {String(p.value ?? 'Unknown')}
          </Badge>
        ),
      },
      { field: 'ecosystem', headerName: 'Ecosystem', width: 110 },
      {
        field: 'mfes',
        headerName: 'Affected MFEs',
        width: 300,
        valueFormatter: listFormatter,
        cellRenderer: (p: { value: string[] }) => <ListCell values={p.value ?? []} max={3} />,
      },
      {
        field: 'alreadyClear',
        headerName: 'Already clear',
        width: 220,
        valueFormatter: listFormatter,
        headerTooltip: 'MFEs already on a version at or past the target — nothing to do in these',
        cellRenderer: (p: { value: string[] }) => <ListCell values={p.value ?? []} max={2} />,
      },
      {
        field: 'advisories',
        headerName: 'Advisories',
        width: 260,
        valueFormatter: listFormatter,
        cellRenderer: (p: { value: string[] }) => <ListCell values={p.value ?? []} />,
      },
    ],
    [mfeCount],
  )

  return (
    <RollupGrid<PackageRollup>
      theme={resolved}
      rowData={data}
      columnDefs={columnDefs}
      getRowId={(d) => d.packageName}
      onRowClicked={(d) => onSelect?.(d.packageName)}
      onApiReady={onApiReady}
      emptyMessage="No packages in the current selection"
    />
  )
}

// --- One row per advisory ------------------------------------------------

export function AdvisoryGrid({
  rows,
  advisorySource,
  mfeCount,
  onSelect,
  onApiReady,
}: {
  rows: Finding[]
  advisorySource: string
  mfeCount: number
  onSelect?: (advisory: string) => void
  onApiReady?: (api: GridApi) => void
}) {
  const { resolved } = useTheme()
  const data = useMemo(() => rollupByAdvisory(rows), [rows])

  const columnDefs = useMemo<ColDef<AdvisoryRollup>[]>(
    () => [
      {
        field: 'severity',
        headerName: 'Severity',
        width: 104,
        pinned: 'left',
        comparator: (a, b) => severityRank(a) - severityRank(b),
        cellRenderer: (p: { value: unknown }) => <SeverityBadge severity={p.value} />,
      },
      {
        field: 'advisory',
        headerName: 'Advisory',
        width: 200,
        pinned: 'left',
        cellRenderer: (p: { value: unknown; data?: AdvisoryRollup }) => (
          <AdvisoryLink
            advisory={p.value}
            source={advisorySource}
            preview={{
              severity: p.data?.severity,
              cvss: p.data?.cvss,
              description: p.data?.description,
              packageName: p.data?.packages?.[0],
              packageVersion: p.data?.versions?.[0],
              fixedIn: p.data?.fixedIn,
              cve: p.data?.cve,
              mfes: p.data?.mfes,
            }}
          />
        ),
      },
      {
        field: 'mfeCount',
        headerName: 'MFEs hit',
        width: 108,
        type: 'numericColumn',
        sort: 'desc',
        cellRenderer: (p: { value: number; data?: AdvisoryRollup }) => (
          <Tooltip>
            <TooltipTrigger asChild>
              <span>
                <SpreadBadge count={p.value} total={mfeCount} />
              </span>
            </TooltipTrigger>
            <TooltipContent className="max-w-sm">{p.data?.mfes.join(', ')}</TooltipContent>
          </Tooltip>
        ),
      },
      { field: 'cvss', headerName: 'CVSS', width: 84, type: 'numericColumn', valueFormatter: (p) => fmtCvss(p.value) },
      {
        field: 'packages',
        headerName: 'Packages',
        width: 210,
        valueFormatter: listFormatter,
        cellRenderer: (p: { value: string[] }) => <ListCell values={p.value ?? []} />,
      },
      {
        field: 'fixStatus',
        headerName: 'Fix',
        width: 148,
        cellRenderer: (p: { value: unknown; data?: AdvisoryRollup }) => (
          <FixBadge status={p.value} fixedIn={p.data?.fixedIn} />
        ),
      },
      {
        field: 'exposure',
        headerName: 'Exposure',
        width: 196,
        cellRenderer: (p: { value: unknown }) => <ExposureBadge exposure={p.value} />,
      },
      { field: 'findings', headerName: 'Findings', width: 106, type: 'numericColumn' },
      { field: 'cve', headerName: 'CVE', width: 150 },
      { field: 'cwe', headerName: 'CWE', width: 110 },
      { field: 'source', headerName: 'Source', width: 104 },
      {
        field: 'versions',
        headerName: 'Versions in use',
        width: 180,
        valueFormatter: listFormatter,
        cellRenderer: (p: { value: string[] }) => <ListCell values={p.value ?? []} />,
      },
      {
        field: 'mfes',
        headerName: 'Affected MFEs',
        width: 300,
        valueFormatter: listFormatter,
        cellRenderer: (p: { value: string[] }) => <ListCell values={p.value ?? []} max={3} />,
      },
      {
        field: 'description',
        headerName: 'Description',
        width: 460,
        tooltipField: 'description',
        valueFormatter: (p) => truncate(p.value, 300),
      },
    ],
    [advisorySource, mfeCount],
  )

  return (
    <RollupGrid<AdvisoryRollup>
      theme={resolved}
      rowData={data}
      columnDefs={columnDefs}
      getRowId={(d) => d.advisory}
      onRowClicked={(d) => onSelect?.(d.advisory)}
      onApiReady={onApiReady}
      emptyMessage="No advisories match the current filters"
    />
  )
}

// --- One row per MFE -----------------------------------------------------

/** The scorecard: how each MFE compares, and how much of its debt is its own. */
export function MfeGrid({
  rows,
  spread,
  metas,
  onSelect,
  onApiReady,
}: {
  rows: Finding[]
  spread: Map<string, number>
  metas: ReportMeta[]
  onSelect?: (mfe: string) => void
  onApiReady?: (api: GridApi) => void
}) {
  const { resolved } = useTheme()
  const data = useMemo(() => rollupByMfe(rows, spread, metas), [rows, spread, metas])

  const columnDefs = useMemo<ColDef<MfeRollup>[]>(
    () => [
      { field: 'mfe', headerName: 'MFE', width: 230, pinned: 'left', tooltipField: 'mfe' },
      { field: 'findings', headerName: 'Findings', width: 106, type: 'numericColumn' },
      {
        field: 'critical',
        headerName: 'Critical',
        width: 102,
        type: 'numericColumn',
        sort: 'desc',
        cellRenderer: (p: { value: number }) =>
          p.value > 0 ? (
            <Badge variant="outline" className="border-sev-critical/40 bg-sev-critical/15 text-sev-critical tabular-nums">
              {p.value}
            </Badge>
          ) : (
            <span className="text-muted-foreground">0</span>
          ),
      },
      {
        field: 'high',
        headerName: 'High',
        width: 92,
        type: 'numericColumn',
        cellRenderer: (p: { value: number }) =>
          p.value > 0 ? (
            <Badge variant="outline" className="border-sev-high/40 bg-sev-high/15 text-sev-high tabular-nums">
              {p.value}
            </Badge>
          ) : (
            <span className="text-muted-foreground">0</span>
          ),
      },
      { field: 'medium', headerName: 'Medium', width: 98, type: 'numericColumn' },
      { field: 'low', headerName: 'Low', width: 84, type: 'numericColumn' },
      {
        field: 'bumps',
        headerName: 'Bumps to do',
        width: 132,
        type: 'numericColumn',
        headerTooltip: 'Distinct package upgrades needed in this MFE — the actual size of the work',
      },
      {
        field: 'uniqueFindings',
        headerName: 'Only here',
        width: 120,
        type: 'numericColumn',
        headerTooltip: 'Findings in packages no other loaded MFE carries — this team fixes these alone',
        cellRenderer: (p: { value: number }) =>
          p.value > 0 ? (
            <Badge variant="outline" className="border-chart-2/40 bg-chart-2/15 text-chart-2 tabular-nums">
              {p.value}
            </Badge>
          ) : (
            <span className="text-muted-foreground">0</span>
          ),
      },
      {
        field: 'sharedFindings',
        headerName: 'Shared',
        width: 104,
        type: 'numericColumn',
        headerTooltip: 'Findings in packages at least one other MFE also carries — fixed centrally, in effect',
      },
      { field: 'remoteUnauth', headerName: 'Remote unauth', width: 140, type: 'numericColumn' },
      { field: 'maxCvss', headerName: 'Max CVSS', width: 110, type: 'numericColumn', valueFormatter: (p) => fmtCvss(p.value) },
      { field: 'packages', headerName: 'Bad packages', width: 132, type: 'numericColumn' },
      { field: 'advisories', headerName: 'Advisories', width: 116, type: 'numericColumn' },
      {
        field: 'dependencyCount',
        headerName: 'Deps scanned',
        width: 132,
        type: 'numericColumn',
        headerTooltip: 'Every dependency the scan looked at, vulnerable or not',
      },
      { field: 'reportDate', headerName: 'Scanned', width: 116, valueFormatter: (p) => fmtDate(p.value) },
      {
        field: 'scanAgeDays',
        headerName: 'Scan age (d)',
        width: 124,
        type: 'numericColumn',
        cellRenderer: (p: { value: number | undefined }) =>
          p.value != null && p.value > 30 ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <Badge variant="outline" className="border-sev-medium/40 bg-sev-medium/15 text-sev-medium tabular-nums">
                  {p.value}
                </Badge>
              </TooltipTrigger>
              <TooltipContent className="max-w-sm">
                Over a month old. A lower finding count here may just mean this MFE was measured against an older
                advisory database.
              </TooltipContent>
            </Tooltip>
          ) : (
            <span className="tabular-nums">{p.value ?? '-'}</span>
          ),
      },
      { field: 'engineVersion', headerName: 'Engine', width: 100 },
    ],
    [],
  )

  return (
    <RollupGrid<MfeRollup>
      theme={resolved}
      rowData={data}
      columnDefs={columnDefs}
      getRowId={(d) => d.mfe}
      onRowClicked={(d) => onSelect?.(d.mfe)}
      onApiReady={onApiReady}
      emptyMessage="No MFEs in the current selection"
    />
  )
}

// --- shared shell --------------------------------------------------------

function RollupGrid<T>({
  theme,
  rowData,
  columnDefs,
  getRowId,
  onRowClicked,
  onApiReady,
  emptyMessage,
}: {
  theme: 'dark' | 'light'
  rowData: T[]
  columnDefs: ColDef<T>[]
  getRowId: (d: T) => string
  onRowClicked?: (d: T) => void
  onApiReady?: (api: GridApi) => void
  emptyMessage: string
}) {
  const onGridReady = useCallback((e: GridReadyEvent) => onApiReady?.(e.api), [onApiReady])

  return (
    <AgGridReact<T>
      theme={gridTheme(theme)}
      rowData={rowData}
      columnDefs={columnDefs}
      defaultColDef={defaultColDef}
      getRowId={(p) => getRowId(p.data)}
      onGridReady={onGridReady}
      onRowClicked={(e) => e.data && onRowClicked?.(e.data)}
      rowSelection={{ mode: 'singleRow', checkboxes: false, enableClickSelection: true }}
      suppressCellFocus
      animateRows={false}
      tooltipShowDelay={300}
      overlayNoRowsTemplate={`<span class="text-xs text-muted-foreground">${emptyMessage}</span>`}
    />
  )
}
