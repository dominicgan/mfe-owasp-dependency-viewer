import { ExternalLinkIcon, LoaderCircleIcon, TriangleAlertIcon, WifiOffIcon } from 'lucide-react'
import { useEffect, useState } from 'react'
import { SeverityBadge } from '@/components/badges'
import { Badge } from '@/components/ui/badge'
import { HoverCard, HoverCardContent, HoverCardTrigger } from '@/components/ui/hover-card'
import { advisoryUrl, isLinkable, sourcesFor } from '@/lib/advisory'
import {
  cachedAdvisory,
  epssBand,
  fetchAdvisory,
  liveLookupEnabled,
  type AdvisoryDetails,
  type AdvisoryFetchState,
} from '@/lib/advisory-data'
import { cvss as fmtCvss, date as fmtDate, truncate } from '@/lib/format'
import { cn } from '@/lib/utils'

/** What the report already knows — shown instantly, with no network wait. */
export interface LocalAdvisoryContext {
  severity?: unknown
  cvss?: unknown
  description?: unknown
  packageName?: unknown
  packageVersion?: unknown
  fixedIn?: unknown
  affectedRange?: unknown
  cve?: unknown
  mfes?: string[]
}

/**
 * Hover preview for an advisory cell.
 *
 * Renders in two layers: what the report already tells us (instant), then live
 * detail from OSV and EPSS once the pointer settles. An iframe of the advisory
 * page is not an option — NVD, MITRE and CISA all refuse to be framed — so this
 * shows the same facts natively instead.
 */
export function AdvisoryHover({
  advisory,
  source,
  local,
  children,
}: {
  advisory: string
  source?: string
  local?: LocalAdvisoryContext
  children: React.ReactNode
}) {
  const [open, setOpen] = useState(false)

  if (!isLinkable(advisory)) return <>{children}</>

  return (
    <HoverCard open={open} onOpenChange={setOpen} openDelay={280} closeDelay={120}>
      <HoverCardTrigger asChild>{children}</HoverCardTrigger>
      <HoverCardContent>
        {open && <AdvisoryCard key={advisory} advisory={advisory} source={source} local={local} />}
      </HoverCardContent>
    </HoverCard>
  )
}

function AdvisoryCard({
  advisory,
  source,
  local,
}: {
  advisory: string
  source?: string
  local?: LocalAdvisoryContext
}) {
  const live = liveLookupEnabled()
  const cve = local?.cve ? String(local.cve) : undefined

  // Seed from the session cache at render time: an advisory looked up earlier
  // shows instantly, and a cold one opens in the loading state with no extra
  // render.
  const [state, setState] = useState<AdvisoryFetchState>(() => {
    if (!live) return { status: 'idle' }
    const cached = cachedAdvisory(advisory)
    return cached.status === 'idle' ? { status: 'loading' } : cached
  })

  useEffect(() => {
    if (!live) return
    let alive = true
    fetchAdvisory(advisory, cve).then((s) => {
      if (alive) setState(s)
    })
    return () => {
      alive = false
    }
  }, [advisory, cve, live])

  const data = state.status === 'ready' ? state.data : undefined
  const href = advisoryUrl(advisory, source)

  return (
    <div className="flex max-h-[70vh] flex-col">
      <header className="flex items-start justify-between gap-2 border-b p-3">
        <div className="min-w-0">
          {href ? (
            <a
              href={href}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 font-mono text-sm font-medium hover:underline"
            >
              {advisory}
              <ExternalLinkIcon className="size-3 opacity-60" />
            </a>
          ) : (
            <span className="font-mono text-sm font-medium">{advisory}</span>
          )}
          {local?.packageName ? (
            <p className="text-muted-foreground mt-0.5 truncate text-xs">
              {String(local.packageName)} {String(local.packageVersion ?? '')}
            </p>
          ) : null}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          {local?.severity ? <SeverityBadge severity={local.severity} /> : null}
          {local?.cvss != null && local.cvss !== '' && (
            <Badge variant="secondary" className="tabular-nums">
              {fmtCvss(local.cvss)}
            </Badge>
          )}
        </div>
      </header>

      <div className="scrollbar-thin min-h-0 flex-1 space-y-3 overflow-y-auto p-3 text-xs">
        {/* Layer 1: straight from the report, always available. */}
        {Boolean(local?.fixedIn) && (
          <div>
            <h4 className="mb-0.5 font-semibold">Fix (derived from this report)</h4>
            <p className="leading-relaxed">
              Upgrade to <span className="font-mono font-medium">{String(local?.fixedIn)}</span>
            </p>
            {Boolean(local?.affectedRange) && (
              <p className="text-muted-foreground mt-0.5">
                Advisory range <span className="font-mono">{String(local?.affectedRange)}</span>
              </p>
            )}
          </div>
        )}

        {local?.mfes && local.mfes.length > 0 && (
          <div>
            <h4 className="mb-1 font-semibold">
              Affects {local.mfes.length} MFE{local.mfes.length === 1 ? '' : 's'}
            </h4>
            <div className="flex flex-wrap gap-1">
              {local.mfes.slice(0, 8).map((m) => (
                <Badge key={m} variant="secondary" className="font-normal">
                  {m}
                </Badge>
              ))}
              {local.mfes.length > 8 && (
                <Badge variant="secondary" className="font-normal">
                  +{local.mfes.length - 8}
                </Badge>
              )}
            </div>
          </div>
        )}

        {Boolean(local?.description) && (
          <p className="text-muted-foreground leading-relaxed">{truncate(local?.description, 420)}</p>
        )}

        {/* Layer 2: live enrichment. */}
        {!live ? (
          <p className="text-muted-foreground flex items-center gap-1.5">
            <WifiOffIcon className="size-3.5 shrink-0" />
            Live lookups are turned off.
          </p>
        ) : state.status === 'loading' ? (
          <p className="text-muted-foreground flex items-center gap-1.5">
            <LoaderCircleIcon className="size-3.5 shrink-0 animate-spin" />
            Looking up OSV{cve ? ' and EPSS' : ''}&hellip;
          </p>
        ) : state.status === 'error' ? (
          <p className="text-muted-foreground flex items-start gap-1.5">
            <TriangleAlertIcon className="mt-0.5 size-3.5 shrink-0" />
            {state.message}
          </p>
        ) : data ? (
          <LiveDetail data={data} hasCve={Boolean(cve)} />
        ) : null}
      </div>

      <footer className="flex flex-wrap items-center gap-x-2 gap-y-1 border-t p-2.5">
        {sourcesFor(advisory).map((s) => (
          <a
            key={s.id}
            href={s.url(advisory)}
            target="_blank"
            rel="noreferrer noopener"
            title={s.hint}
            className="text-muted-foreground hover:text-foreground text-[11px] underline decoration-dotted underline-offset-2"
          >
            {s.label}
          </a>
        ))}
      </footer>
    </div>
  )
}

function LiveDetail({ data, hasCve }: { data: AdvisoryDetails; hasCve: boolean }) {
  if (data.notFound && data.epss == null) {
    return <p className="text-muted-foreground">No public OSV record for this identifier.</p>
  }

  return (
    <div className="space-y-3 border-t pt-3">
      {data.epss != null ? (
        <Epss value={data.epss} percentile={data.epssPercentile} />
      ) : !hasCve ? (
        <p className="text-muted-foreground">
          No exploit-prediction score: EPSS is keyed by CVE, and this advisory carries no CVE id.
        </p>
      ) : null}

      {Boolean(data.summary) && (
        <div>
          <h4 className="mb-0.5 font-semibold">OSV summary</h4>
          <p className="text-muted-foreground leading-relaxed">{data.summary}</p>
        </div>
      )}

      {data.fixedVersions.length > 0 && (
        <div>
          <h4 className="mb-1 font-semibold">Fixed versions (OSV)</h4>
          <ul className="space-y-0.5">
            {data.fixedVersions.map((f) => (
              <li key={`${f.ecosystem}/${f.name}`} className="flex items-baseline justify-between gap-2">
                <span className="text-muted-foreground min-w-0 truncate font-mono text-[11px]">{f.name}</span>
                <span className="shrink-0 font-mono text-[11px]">{f.fixed.join(', ')}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {data.aliases.length > 0 && (
        <div>
          <h4 className="mb-1 font-semibold">Also known as</h4>
          <div className="flex flex-wrap gap-1">
            {data.aliases.map((a) => (
              <Badge key={a} variant="secondary" className="font-mono font-normal">
                {a}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {(data.published || data.modified) && (
        <p className="text-muted-foreground">
          {data.published && <>Published {fmtDate(data.published)}</>}
          {data.published && data.modified && ' · '}
          {data.modified && <>updated {fmtDate(data.modified)}</>}
        </p>
      )}
    </div>
  )
}

/** EPSS is a probability, so it gets a bar and a sentence, not a bare number. */
function Epss({ value, percentile }: { value: number; percentile?: number }) {
  const band = epssBand(value)
  const pct = value * 100
  return (
    <div>
      <h4 className="mb-1 font-semibold">Exploit prediction (EPSS)</h4>
      <div className="flex items-center gap-2">
        <div className="bg-muted h-1.5 flex-1 overflow-hidden rounded-full">
          <div
            className={cn(
              'h-full rounded-full',
              band.tone === 'critical' && 'bg-sev-critical',
              band.tone === 'high' && 'bg-sev-high',
              band.tone === 'medium' && 'bg-sev-medium',
              band.tone === 'low' && 'bg-sev-low',
            )}
            // Probabilities cluster near zero, so a square-root scale keeps a
            // 0.3% score visible instead of rendering as an empty bar.
            style={{ width: `${Math.max(2, Math.sqrt(value) * 100)}%` }}
          />
        </div>
        <span className="shrink-0 font-medium tabular-nums">{pct < 1 ? pct.toFixed(2) : pct.toFixed(1)}%</span>
      </div>
      <p className="text-muted-foreground mt-1">
        {band.label}
        {percentile != null && <> &middot; higher than {Math.round(percentile * 100)}% of all scored CVEs</>}
      </p>
    </div>
  )
}
