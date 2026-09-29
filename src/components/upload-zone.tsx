import { FilesIcon, LoaderCircleIcon, ShieldIcon, TriangleAlertIcon, UploadIcon } from 'lucide-react'
import { useCallback, useRef, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import type { IngestOutcome } from '@/hooks/use-workspace'
import { cn } from '@/lib/utils'

const ACCEPT = '.json,application/json'

/** Only .json files are read; anything else in a dropped folder is ignored. */
export function jsonFilesFrom(list: FileList | null): File[] {
  return [...(list ?? [])].filter((f) => f.name.toLowerCase().endsWith('.json') || f.type === 'application/json')
}

export function UploadZone({
  onFiles,
  busy,
  progress,
  failures,
  onLoadSample,
}: {
  onFiles: (files: File[]) => void
  busy: boolean
  progress: { done: number; total: number } | null
  /** Files from the last attempt that could not be read. */
  failures: Extract<IngestOutcome, { kind: 'failed' }>[]
  onLoadSample?: () => void
}) {
  const [dragging, setDragging] = useState(false)
  const [rejected, setRejected] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const handle = useCallback(
    (list: FileList | null) => {
      const all = [...(list ?? [])]
      const files = jsonFilesFrom(list)
      setRejected(all.length - files.length)
      if (files.length) onFiles(files)
    },
    [onFiles],
  )

  return (
    <div className="mx-auto flex min-h-full w-full max-w-2xl flex-col justify-center p-6">
      <div className="mb-6 text-center">
        <div className="bg-muted mx-auto mb-3 flex size-11 items-center justify-center rounded-xl">
          <ShieldIcon className="size-5" />
        </div>
        <h1 className="text-xl font-semibold">MFE Dependency Report Viewer</h1>
        <p className="text-muted-foreground mx-auto mt-1.5 max-w-md text-sm">
          Drop the OWASP dependency-check JSON from every micro-frontend in at once. They share a stack, so they
          share most of their vulnerabilities — this pools them and works out which version bumps clear the most.
          Parsing happens in your browser; nothing is uploaded.
        </p>
      </div>

      <Card
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
        className={cn(
          'flex flex-col items-center justify-center border-2 border-dashed p-10 transition-colors',
          dragging && 'border-ring bg-accent/50',
          busy && 'opacity-70',
        )}
      >
        {busy ? (
          <LoaderCircleIcon className="text-muted-foreground size-7 animate-spin" />
        ) : (
          <FilesIcon className="text-muted-foreground size-7" />
        )}
        <p className="mt-3 text-sm font-medium">
          {busy
            ? `Reading report ${progress?.done ?? 0} of ${progress?.total ?? 0}…`
            : 'Drop your dependency-check reports here'}
        </p>
        {busy ? (
          <div className="mt-2 w-56">
            <div className="bg-muted h-1 overflow-hidden rounded-full">
              <div
                className="bg-primary h-full rounded-full transition-[width] duration-200"
                style={{ width: `${Math.round(((progress?.done ?? 0) / Math.max(1, progress?.total ?? 1)) * 100)}%` }}
              />
            </div>
          </div>
        ) : (
          <p className="text-muted-foreground mt-1 text-xs">
            <code className="text-foreground">dependency-check-report.json</code> — as many as you like, at once
          </p>
        )}

        <input
          ref={inputRef}
          type="file"
          accept={ACCEPT}
          multiple
          className="sr-only"
          onChange={(e) => {
            handle(e.target.files)
            e.target.value = ''
          }}
        />
        <div className="mt-4 flex gap-2">
          <Button size="sm" disabled={busy} onClick={() => inputRef.current?.click()}>
            <UploadIcon />
            Choose files
          </Button>
          {onLoadSample && (
            <Button size="sm" variant="outline" disabled={busy} onClick={onLoadSample}>
              Load sample estate
            </Button>
          )}
        </div>
      </Card>

      {rejected > 0 && failures.length === 0 && (
        <p className="text-muted-foreground mt-3 text-xs">
          Ignored {rejected} non-JSON file{rejected === 1 ? '' : 's'}. The HTML and XML reports are renderings of
          the same scan and drop the version ranges this tool needs.
        </p>
      )}

      {failures.length > 0 && (
        <div className="border-destructive/40 bg-destructive/10 text-destructive mt-4 space-y-2 rounded-md border p-3 text-xs">
          {failures.map((f) => (
            <p key={f.fileName} className="flex items-start gap-1.5">
              <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
              <span>{f.message}</span>
            </p>
          ))}
        </div>
      )}

      <div className="text-muted-foreground mt-6 space-y-1.5 text-xs">
        <p className="text-foreground font-medium">What it reads</p>
        <p>
          One row per MFE × dependency × advisory. Each MFE is named from the report&rsquo;s own{' '}
          <code className="text-foreground">projectInfo.name</code>, and you can rename it afterwards. Re-uploading a
          newer scan of the same MFE replaces the old one rather than doubling its findings.
        </p>
        <p>
          Fixed versions are derived from the advisory&rsquo;s machine-readable CPE range — a range of{' '}
          <code className="text-foreground">&lt;3.1.6</code> states that 3.1.6 is clean — never from the prose of
          its description. Every derived fix shows the range it came from.
        </p>
      </div>
    </div>
  )
}
