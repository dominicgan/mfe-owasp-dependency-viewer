import {
  CheckIcon,
  ClockAlertIcon,
  LayersIcon,
  PencilIcon,
  PlusIcon,
  Trash2Icon,
  TriangleAlertIcon,
  XIcon,
} from 'lucide-react'
import { useCallback, useRef, useState } from 'react'
import { jsonFilesFrom } from '@/components/upload-zone'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import type { LoadedReport } from '@/hooks/use-workspace'
import { date as fmtDate, num } from '@/lib/format'

/** A scan older than this is called out; dependency advisories move weekly. */
const STALE_DAYS = 30

export function ReportManager({
  open,
  onOpenChange,
  reports,
  onAddFiles,
  onRename,
  onRemove,
  onClearAll,
  busy,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  reports: LoadedReport[]
  onAddFiles: (files: File[]) => void
  onRename: (reportId: string, name: string) => string | null
  onRemove: (reportId: string) => void
  onClearAll: () => void
  busy: boolean
}) {
  const [dragging, setDragging] = useState(false)
  const [confirmClear, setConfirmClear] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  // Reset the destructive confirmation as the panel closes, so a stale "click
  // again to clear" never greets the next visit. Done from the event that
  // causes it rather than an effect watching `open`, which would re-render.
  const changeOpen = useCallback(
    (next: boolean) => {
      if (!next) setConfirmClear(false)
      onOpenChange(next)
    },
    [onOpenChange],
  )

  const handle = useCallback(
    (list: FileList | null) => {
      const files = jsonFilesFrom(list)
      if (files.length) onAddFiles(files)
    },
    [onAddFiles],
  )

  const totalFindings = reports.reduce((a, r) => a + r.rows.length, 0)

  return (
    <Sheet open={open} onOpenChange={changeOpen}>
      <SheetContent className="flex w-full flex-col gap-0 p-0 sm:max-w-lg">
        <SheetHeader className="border-b">
          <SheetTitle>Loaded MFEs</SheetTitle>
          <SheetDescription>
            {reports.length} report{reports.length === 1 ? '' : 's'} · {num(totalFindings)} findings. Kept on this
            machine so a reload does not mean re-dropping them.
          </SheetDescription>
        </SheetHeader>

        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-2 p-4">
            {reports.map((r) => (
              <ReportRow key={r.meta.reportId} report={r} onRename={onRename} onRemove={onRemove} />
            ))}

            <div
              onDragOver={(e) => {
                e.preventDefault()
                setDragging(true)
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault()
                setDragging(false)
                handle(e.dataTransfer.files)
              }}
              className={`flex flex-col items-center rounded-lg border-2 border-dashed p-5 transition-colors ${
                dragging ? 'border-ring bg-accent/50' : ''
              }`}
            >
              <p className="text-muted-foreground text-xs">Drop more reports here</p>
              <input
                ref={inputRef}
                type="file"
                accept=".json,application/json"
                multiple
                className="sr-only"
                onChange={(e) => {
                  handle(e.target.files)
                  e.target.value = ''
                }}
              />
              <Button
                variant="outline"
                size="xs"
                className="mt-2"
                disabled={busy}
                onClick={() => inputRef.current?.click()}
              >
                <PlusIcon />
                Add reports
              </Button>
            </div>
          </div>
        </ScrollArea>

        <div className="flex items-center justify-between gap-2 border-t p-3">
          <p className="text-muted-foreground text-xs">
            {confirmClear ? 'This removes every loaded report.' : 'Reports stay until you remove them.'}
          </p>
          <Button
            variant={confirmClear ? 'destructive' : 'outline'}
            size="xs"
            onClick={() => {
              if (!confirmClear) {
                setConfirmClear(true)
                return
              }
              onClearAll()
              changeOpen(false)
            }}
          >
            <Trash2Icon />
            {confirmClear ? 'Confirm — remove all' : 'Clear all'}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  )
}

function ReportRow({
  report,
  onRename,
  onRemove,
}: {
  report: LoadedReport
  onRename: (reportId: string, name: string) => string | null
  onRemove: (reportId: string) => void
}) {
  const { meta, rows } = report
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(meta.mfe)
  const [error, setError] = useState<string | null>(null)

  const stale = meta.reportDate ? daysSince(meta.reportDate) : undefined
  const isStale = stale != null && stale > STALE_DAYS
  const critical = rows.filter((r) => r.severity === 'Critical').length
  const high = rows.filter((r) => r.severity === 'High').length

  const commit = () => {
    const err = onRename(meta.reportId, draft)
    setError(err)
    if (!err) setEditing(false)
  }

  return (
    <div className="rounded-lg border p-3">
      <div className="flex items-start justify-between gap-2">
        {editing ? (
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-1">
              <Input
                autoFocus
                value={draft}
                onChange={(e) => {
                  setDraft(e.target.value)
                  setError(null)
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') commit()
                  if (e.key === 'Escape') {
                    setDraft(meta.mfe)
                    setError(null)
                    setEditing(false)
                  }
                }}
                className="h-7 text-xs"
              />
              <Button variant="ghost" size="icon-sm" className="size-7" onClick={commit} aria-label="Save name">
                <CheckIcon className="size-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="icon-sm"
                className="size-7"
                onClick={() => {
                  setDraft(meta.mfe)
                  setError(null)
                  setEditing(false)
                }}
                aria-label="Cancel rename"
              >
                <XIcon className="size-3.5" />
              </Button>
            </div>
            {error && <p className="text-destructive mt-1 text-[11px]">{error}</p>}
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setEditing(true)}
            className="group min-w-0 flex-1 text-left"
            title="Rename this MFE"
          >
            <span className="flex items-center gap-1.5">
              <LayersIcon className="text-muted-foreground size-3.5 shrink-0" />
              <span className="truncate text-sm font-medium">{meta.mfe}</span>
              <PencilIcon className="text-muted-foreground size-3 shrink-0 opacity-0 transition-opacity group-hover:opacity-100" />
            </span>
            {meta.reportedName && meta.reportedName !== meta.mfe && (
              <span className="text-muted-foreground mt-0.5 block truncate text-[11px]">
                reported as {meta.reportedName}
              </span>
            )}
          </button>
        )}

        <Button
          variant="ghost"
          size="icon-sm"
          className="size-7 shrink-0"
          onClick={() => onRemove(meta.reportId)}
          aria-label={`Remove ${meta.mfe}`}
        >
          <Trash2Icon className="size-3.5" />
        </Button>
      </div>

      <div className="mt-2 flex flex-wrap items-center gap-1.5">
        <Badge variant="secondary" className="tabular-nums">
          {num(rows.length)} findings
        </Badge>
        {critical > 0 && (
          <Badge variant="outline" className="border-sev-critical/40 bg-sev-critical/15 text-sev-critical tabular-nums">
            {critical} critical
          </Badge>
        )}
        {high > 0 && (
          <Badge variant="outline" className="border-sev-high/40 bg-sev-high/15 text-sev-high tabular-nums">
            {high} high
          </Badge>
        )}
        <Badge variant="secondary" className="tabular-nums">
          {num(meta.dependencyCount)} deps scanned
        </Badge>
        {meta.suppressedCount > 0 && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge variant="secondary" className="tabular-nums">
                {meta.suppressedCount} suppressed
              </Badge>
            </TooltipTrigger>
            <TooltipContent>
              Advisories this project has explicitly suppressed. They are excluded from every number here.
            </TooltipContent>
          </Tooltip>
        )}
      </div>

      <div className="text-muted-foreground mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
        <span className="flex items-center gap-1">
          {isStale && <ClockAlertIcon className="text-sev-medium size-3" />}
          Scanned {meta.reportDate ? fmtDate(meta.reportDate) : 'date unknown'}
          {stale != null && ` · ${stale}d ago`}
        </span>
        {meta.engineVersion && <span>engine {meta.engineVersion}</span>}
        <span className="truncate" title={meta.fileName}>
          {meta.fileName}
        </span>
      </div>

      {isStale && (
        <p className="text-sev-medium mt-1.5 flex items-start gap-1 text-[11px]">
          <TriangleAlertIcon className="mt-px size-3 shrink-0" />
          This scan is over {STALE_DAYS} days old — newer advisories against these same versions will not appear.
        </p>
      )}
    </div>
  )
}

function daysSince(iso: string): number | undefined {
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return undefined
  return Math.max(0, Math.floor((Date.now() - t) / 86_400_000))
}
