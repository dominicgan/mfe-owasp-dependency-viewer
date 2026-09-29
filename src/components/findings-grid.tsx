import type { ColDef, GridApi, GridReadyEvent, ValueFormatterParams } from 'ag-grid-community'
import { AgGridReact } from 'ag-grid-react'
import { useCallback, useMemo, useRef } from 'react'
import { AdvisoryLink, ExposureBadge, FixBadge, SeverityBadge, SpreadBadge, UpgradeCell } from '@/components/badges'
import { useTheme } from '@/components/theme-provider'
import { Badge } from '@/components/ui/badge'
import { cvss as fmtCvss, date as fmtDate } from '@/lib/format'
import type { Finding } from '@/lib/parse'
import { defaultColDef, gridTheme, numFilter, setish, textFilter } from '@/lib/grid-theme'
import { FIELDS, severityRank } from '@/lib/schema'

function dateFormatter(p: ValueFormatterParams) {
  return fmtDate(p.value)
}

export interface GridContext {
  advisorySource: string
  /** packageName -> how many MFEs carry it, over the whole workspace. */
  spread: Map<string, number>
  mfeCount: number
  /** advisory -> every MFE it shows up in, for the hover card. */
  advisoryMfes: Map<string, string[]>
}

/** Columns shown up front; everything else is available in the column chooser. */
const PRIMARY: ColDef<Finding>[] = [
  { field: 'mfe', headerName: 'MFE', width: 190, pinned: 'left', tooltipField: 'mfe', ...textFilter },
  {
    field: 'severity',
    headerName: 'Severity',
    width: 104,
    pinned: 'left',
    comparator: (a, b) => severityRank(a) - severityRank(b),
    cellRenderer: (p: { value: unknown }) => <SeverityBadge severity={p.value} />,
    ...setish,
  },
  {
    field: 'cvss',
    headerName: 'CVSS',
    width: 78,
    type: 'numericColumn',
    valueFormatter: (p) => fmtCvss(p.value),
    ...numFilter,
  },
  {
    field: 'advisory',
    headerName: 'Advisory',
    width: 198,
    cellRenderer: (p: { value: unknown; data?: Finding; context?: GridContext }) => (
      <AdvisoryLink
        advisory={p.value}
        source={p.context?.advisorySource}
        preview={{
          severity: p.data?.severity,
          cvss: p.data?.cvss,
          description: p.data?.description,
          packageName: p.data?.packageName,
          packageVersion: p.data?.packageVersion,
          fixedIn: p.data?.fixedIn,
          affectedRange: p.data?.affectedRange,
          cve: p.data?.cve,
          mfes: p.context?.advisoryMfes.get(String(p.data?.advisory ?? '')),
        }}
      />
    ),
    ...textFilter,
  },
  { field: 'packageName', headerName: 'Package', width: 210, tooltipField: 'purl', ...textFilter },
  { field: 'packageVersion', headerName: 'Version', width: 104, ...textFilter },
  {
    // Not a field on the row: the spread is a property of the workspace, so it
    // is looked up rather than duplicated onto every finding.
    colId: 'spread',
    headerName: 'MFEs',
    width: 92,
    valueGetter: (p) => (p.data ? (p.context as GridContext).spread.get(p.data.packageName) ?? 1 : 0),
    type: 'numericColumn',
    cellRenderer: (p: { value: number; context?: GridContext }) => (
      <SpreadBadge count={p.value} total={p.context?.mfeCount} />
    ),
    headerTooltip: 'How many of your loaded MFEs carry this package',
    ...numFilter,
  },
  {
    field: 'fixStatus',
    headerName: 'Fix',
    width: 148,
    cellRenderer: (p: { value: unknown; data?: Finding }) => (
      <FixBadge status={p.value} fixedIn={p.data?.fixedIn} reason={p.data?.fixReason} />
    ),
    ...setish,
  },
  {
    field: 'upgrade',
    headerName: 'Upgrade',
    width: 168,
    cellRenderer: (p: { data?: Finding }) => (
      <UpgradeCell from={p.data?.packageVersion} to={p.data?.fixedIn} />
    ),
    ...textFilter,
  },
  {
    field: 'exposure',
    headerName: 'Exposure',
    width: 196,
    cellRenderer: (p: { value: unknown; data?: Finding }) => (
      <ExposureBadge exposure={p.value} vector={p.data?.cvssVector} />
    ),
    ...setish,
  },
  {
    field: 'dependencyScope',
    headerName: 'Scope',
    width: 110,
    cellRenderer: (p: { value: unknown }) => {
      const v = String(p.value ?? 'Unknown')
      return (
        <Badge variant={v === 'Direct' ? 'secondary' : 'outline'} className="font-normal">
          {v}
        </Badge>
      )
    },
    ...setish,
  },
  { field: 'cwe', headerName: 'CWE', width: 108, ...setish },
  { field: 'cve', headerName: 'CVE', width: 148, ...textFilter },
  { field: 'source', headerName: 'Source', width: 104, ...setish },
]

const PRIMARY_KEYS = new Set(PRIMARY.map((c) => c.field as string).filter(Boolean))

/** Everything else from the schema, hidden until the user asks for it. */
const SECONDARY: ColDef<Finding>[] = FIELDS.filter((f) => !PRIMARY_KEYS.has(f.key)).map((f) => ({
  field: f.key,
  headerName: f.label,
  headerTooltip: f.hint,
  width: f.kind === 'date' ? 120 : f.key === 'description' || f.key === 'fixReason' ? 420 : 160,
  hide: true,
  ...(f.key === 'description' || f.key === 'fixReason' ? { tooltipField: f.key } : {}),
  ...(f.kind === 'list' ? { valueFormatter: (p: ValueFormatterParams) => (Array.isArray(p.value) ? p.value.join(', ') : '') } : {}),
  ...(f.kind === 'date' ? { valueFormatter: dateFormatter, ...textFilter } : {}),
  ...(f.kind === 'number' ? { type: 'numericColumn', ...numFilter } : {}),
  ...(f.kind === 'string' || f.kind === 'enum' ? textFilter : {}),
}))

export function FindingsGrid({
  rows,
  context,
  onRowClick,
  onApiReady,
}: {
  rows: Finding[]
  context: GridContext
  onRowClick?: (row: Finding) => void
  onApiReady?: (api: GridApi<Finding>) => void
}) {
  const { resolved } = useTheme()
  const apiRef = useRef<GridApi<Finding> | null>(null)

  const columnDefs = useMemo<ColDef<Finding>[]>(() => [...PRIMARY, ...SECONDARY], [])

  const onGridReady = useCallback(
    (e: GridReadyEvent<Finding>) => {
      apiRef.current = e.api
      onApiReady?.(e.api)
    },
    [onApiReady],
  )

  return (
    <div className="h-full w-full">
      <AgGridReact<Finding>
        theme={gridTheme(resolved)}
        rowData={rows}
        columnDefs={columnDefs}
        defaultColDef={defaultColDef}
        context={context}
        getRowId={(p) => p.data.id}
        onGridReady={onGridReady}
        onRowClicked={(e) => e.data && onRowClick?.(e.data)}
        rowSelection={{ mode: 'singleRow', checkboxes: false, enableClickSelection: true }}
        // Virtualised: only the visible window is in the DOM, so a large estate
        // scrolls without the browser doing thousands of row layouts.
        rowBuffer={12}
        animateRows={false}
        suppressCellFocus
        tooltipShowDelay={300}
        overlayNoRowsTemplate={
          '<span class="text-xs text-muted-foreground">No findings match the current filters</span>'
        }
      />
    </div>
  )
}

/** CSV of exactly what is on screen, column order and all. */
export function exportGridCsv(api: GridApi | null, fileName: string) {
  api?.exportDataAsCsv({
    fileName,
    allColumns: false,
    processCellCallback: (p) => {
      const v = p.value
      if (v == null) return ''
      if (Array.isArray(v)) return v.join(', ')
      if (p.column.getColId() === 'reportDate') return fmtDate(v)
      return v
    },
  })
}
