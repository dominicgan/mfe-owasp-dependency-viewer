import { LoaderCircleIcon } from 'lucide-react'
import { lazy, Suspense, useCallback, useState } from 'react'
import { ThemeProvider } from '@/components/theme-provider'
import { TooltipProvider } from '@/components/ui/tooltip'
import { UploadZone } from '@/components/upload-zone'
import { useWorkspace, type IngestOutcome } from '@/hooks/use-workspace'

/**
 * The dashboard pulls in ag-grid and recharts — around 440kB gzipped between
 * them — and none of it is needed to paint the upload screen. Splitting here
 * rather than only chunking in the build config means that weight is not
 * fetched at all until there is actually a report to show.
 */
const Dashboard = lazy(() => import('@/dashboard'))

const SAMPLE_FILES = ['dashboard-ui', 'accounts-ui', 'payments-ui', 'shell-host'].map(
  (n) => `${import.meta.env.BASE_URL}samples/${n}.dependency-check-report.json`,
)

function Busy({ label }: { label: string }) {
  return (
    <div className="text-muted-foreground flex h-full items-center justify-center gap-2 text-sm">
      <LoaderCircleIcon className="size-4 animate-spin" />
      {label}
    </div>
  )
}

function Viewer() {
  const ws = useWorkspace()
  const [outcomes, setOutcomes] = useState<IngestOutcome[]>([])

  const addFiles = useCallback(
    async (files: File[]) => {
      setOutcomes(await ws.addFiles(files))
    },
    [ws],
  )

  const loadSample = useCallback(async () => {
    const files = await Promise.all(
      SAMPLE_FILES.map(async (url) => {
        const res = await fetch(url)
        if (!res.ok) return null
        const blob = await res.blob()
        return new File([blob], url.split('/').pop() ?? 'sample.json', { type: 'application/json' })
      }),
    )
    await addFiles(files.filter((f): f is File => f != null))
  }, [addFiles])

  if (ws.hydrating) return <Busy label="Restoring your reports…" />

  if (ws.reports.length === 0) {
    return (
      <UploadZone
        onFiles={addFiles}
        busy={ws.busy}
        progress={ws.progress}
        failures={outcomes.filter((o) => o.kind === 'failed')}
        onLoadSample={loadSample}
      />
    )
  }

  return (
    <Suspense fallback={<Busy label="Loading the dashboard…" />}>
      <Dashboard
        ws={ws}
        outcomes={outcomes}
        onAddFiles={addFiles}
        onDismissOutcomes={() => setOutcomes([])}
      />
    </Suspense>
  )
}

export default function App() {
  return (
    <ThemeProvider>
      <TooltipProvider>
        <Viewer />
      </TooltipProvider>
    </ThemeProvider>
  )
}
