import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  applyFilters,
  decodeFilters,
  encodeFilters,
  EMPTY_FILTERS,
  packageSpread,
  type FilterContext,
  type FilterState,
} from '@/lib/filters'
import { parseReportFile, ReportFormatError, type Finding, type ReportMeta } from '@/lib/parse'
import {
  clearStoredReports,
  deleteStoredReport,
  loadStoredReports,
  putStoredReport,
} from '@/lib/workspace-store'

export interface LoadedReport {
  meta: ReportMeta
  rows: Finding[]
}

/** What happened to each file in an upload, so the UI can say so precisely. */
export type IngestOutcome =
  | { kind: 'added'; fileName: string; mfe: string; findings: number }
  | { kind: 'replaced'; fileName: string; mfe: string; findings: number; previousDate?: string; older: boolean }
  | { kind: 'duplicate'; fileName: string; mfe: string }
  | { kind: 'failed'; fileName: string; message: string }

export interface WorkspaceState {
  reports: LoadedReport[]
  /** True until the persisted workspace has been read back. */
  hydrating: boolean
  busy: boolean
  progress: { done: number; total: number } | null
}

const INITIAL: WorkspaceState = { reports: [], hydrating: true, busy: false, progress: null }

export function useWorkspace() {
  const [state, setState] = useState<WorkspaceState>(INITIAL)

  // Reads the latest reports without making every callback depend on them,
  // which would rebuild the handlers on each ingest tick.
  const reportsRef = useRef<LoadedReport[]>([])
  useEffect(() => {
    reportsRef.current = state.reports
  }, [state.reports])

  useEffect(() => {
    let alive = true
    loadStoredReports().then((stored) => {
      if (!alive) return
      setState((s) => ({ ...s, reports: stored, hydrating: false }))
    })
    return () => {
      alive = false
    }
  }, [])

  /**
   * Ingest dropped files.
   *
   * Two kinds of collision, handled differently because they mean different
   * things: the *same bytes* twice is a no-op, while the same MFE re-scanned is
   * a newer report that should displace the old one — keeping both would
   * double-count every finding in it.
   */
  const addFiles = useCallback(async (files: File[]): Promise<IngestOutcome[]> => {
    if (!files.length) return []
    setState((s) => ({ ...s, busy: true, progress: { done: 0, total: files.length } }))

    const outcomes: IngestOutcome[] = []
    const next = [...reportsRef.current]

    for (const [i, file] of files.entries()) {
      try {
        const { rows, meta } = await parseReportFile(file, file.name)

        const sameBytes = next.findIndex((r) => r.meta.reportId === meta.reportId)
        if (sameBytes !== -1) {
          outcomes.push({ kind: 'duplicate', fileName: file.name, mfe: next[sameBytes].meta.mfe })
          continue
        }

        // Match on the *reported* name, not the display name: renaming an MFE
        // in the UI should not stop its next scan from recognising it.
        const sameMfe = next.findIndex(
          (r) => r.meta.reportedName === meta.reportedName && r.meta.reportedName !== '',
        )

        if (sameMfe !== -1) {
          const prev = next[sameMfe]
          const prevTime = prev.meta.reportDate ? Date.parse(prev.meta.reportDate) : Number.NaN
          const nextTime = meta.reportDate ? Date.parse(meta.reportDate) : Number.NaN
          const older = Number.isFinite(prevTime) && Number.isFinite(nextTime) && nextTime < prevTime

          // Carry the display name across, so a rename survives a re-scan.
          const kept = { ...meta, mfe: prev.meta.mfe }
          const renamed = kept.mfe === meta.mfe ? rows : rows.map((r) => ({ ...r, mfe: kept.mfe }))

          next[sameMfe] = { meta: kept, rows: renamed }
          await deleteStoredReport(prev.meta.reportId)
          await putStoredReport(kept, renamed)
          outcomes.push({
            kind: 'replaced',
            fileName: file.name,
            mfe: kept.mfe,
            findings: rows.length,
            previousDate: prev.meta.reportDate,
            older,
          })
          continue
        }

        next.push({ meta, rows })
        await putStoredReport(meta, rows)
        outcomes.push({ kind: 'added', fileName: file.name, mfe: meta.mfe, findings: rows.length })
      } catch (e) {
        outcomes.push({
          kind: 'failed',
          fileName: file.name,
          message:
            e instanceof ReportFormatError
              ? e.message
              : `${file.name} could not be read: ${e instanceof Error ? e.message : String(e)}`,
        })
      } finally {
        setState((s) => ({ ...s, progress: { done: i + 1, total: files.length } }))
      }
    }

    setState((s) => ({ ...s, reports: next, busy: false, progress: null }))
    return outcomes
  }, [])

  /** Returns an error message when the name is already taken, else null. */
  const renameMfe = useCallback((reportId: string, rawName: string): string | null => {
    const name = rawName.trim()
    if (!name) return 'An MFE needs a name.'
    const current = reportsRef.current
    if (current.some((r) => r.meta.reportId !== reportId && r.meta.mfe === name)) {
      // Two reports under one name would silently merge in every rollup and
      // double the findings attributed to that MFE.
      return `Another report is already called "${name}".`
    }

    setState((s) => ({
      ...s,
      reports: s.reports.map((r) => {
        if (r.meta.reportId !== reportId || r.meta.mfe === name) return r
        const meta = { ...r.meta, mfe: name }
        const rows = r.rows.map((row) => ({ ...row, mfe: name }))
        void putStoredReport(meta, rows)
        return { meta, rows }
      }),
    }))
    return null
  }, [])

  const removeReport = useCallback((reportId: string) => {
    setState((s) => ({ ...s, reports: s.reports.filter((r) => r.meta.reportId !== reportId) }))
    void deleteStoredReport(reportId)
  }, [])

  const clearAll = useCallback(() => {
    setState((s) => ({ ...s, reports: [] }))
    void clearStoredReports()
  }, [])

  /** Every finding across every loaded MFE, in one flat list. */
  const rows = useMemo(() => state.reports.flatMap((r) => r.rows), [state.reports])
  const metas = useMemo(() => state.reports.map((r) => r.meta), [state.reports])

  /**
   * How widely each package is shared, over the *whole* workspace. Filters read
   * this, so it must not be derived from the filtered rows.
   */
  const context = useMemo<FilterContext>(() => ({ spread: packageSpread(rows) }), [rows])

  return { ...state, rows, metas, context, addFiles, renameMfe, removeReport, clearAll }
}

/**
 * Filter state mirrored into the URL hash, so a filtered view is a link and
 * survives a reload. The hash is the single source of truth on first paint.
 */
export function useFilters() {
  const [filters, setFilters] = useState<FilterState>(() =>
    typeof location === 'undefined' ? EMPTY_FILTERS : decodeFilters(location.hash.slice(1)),
  )

  useEffect(() => {
    const encoded = encodeFilters(filters)
    const next = encoded ? `#${encoded}` : ' '
    if (location.hash.slice(1) !== encoded) history.replaceState(null, '', next)
  }, [filters])

  useEffect(() => {
    const onPop = () => setFilters(decodeFilters(location.hash.slice(1)))
    addEventListener('popstate', onPop)
    return () => removeEventListener('popstate', onPop)
  }, [])

  const clearAll = useCallback(() => setFilters(EMPTY_FILTERS), [])
  return { filters, setFilters, clearAll }
}

/** Debounced so typing in the search box doesn't refilter on every keystroke. */
export function useDebounced<T>(value: T, ms = 200): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

/**
 * The filter state everything *expensive* should read: identical to the live
 * state except the search box lags by one debounce interval.
 *
 * Keep this separate from the live state — anything that mutates filters must
 * start from the live copy, or a keystroke in flight gets clobbered by a stale
 * `q`.
 */
export function useEffectiveFilters(filters: FilterState): FilterState {
  const debouncedQ = useDebounced(filters.q, 200)
  return useMemo(() => ({ ...filters, q: debouncedQ }), [filters, debouncedQ])
}

export function useFilteredRows(rows: Finding[], effective: FilterState, ctx: FilterContext): Finding[] {
  return useMemo(() => applyFilters(rows, effective, ctx), [rows, effective, ctx])
}
