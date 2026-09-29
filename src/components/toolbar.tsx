import {
  CheckIcon,
  DownloadIcon,
  InfoIcon,
  LayersIcon,
  Link2Icon,
  MonitorIcon,
  MoonIcon,
  SearchIcon,
  SunIcon,
  WifiIcon,
  WifiOffIcon,
  XIcon,
} from 'lucide-react'
import { useState } from 'react'
import { useTheme, type Theme } from '@/components/theme-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { ADVISORY_SOURCES } from '@/lib/advisory'
import { liveLookupEnabled, setLiveLookup } from '@/lib/advisory-data'
import { countActiveFilters, type FilterState } from '@/lib/filters'
import { date as fmtDate, num } from '@/lib/format'
import type { ReportMeta } from '@/lib/parse'
import { FIELD_BY_KEY } from '@/lib/schema'
import { cn } from '@/lib/utils'

function labelFor(key: string) {
  return FIELD_BY_KEY.get(key)?.label ?? key
}

export function Toolbar({
  filters,
  setFilters,
  clearAll,
  total,
  shown,
  metas,
  advisorySource,
  setAdvisorySource,
  onExport,
  onManageReports,
}: {
  filters: FilterState
  setFilters: (f: FilterState) => void
  clearAll: () => void
  total: number
  shown: number
  metas: ReportMeta[]
  advisorySource: string
  setAdvisorySource: (s: string) => void
  onExport: () => void
  onManageReports: () => void
}) {
  const active = countActiveFilters(filters)
  const filtered = shown !== total

  return (
    <div className="flex flex-wrap items-center gap-2 border-b px-3 py-2">
      <div className="relative min-w-[200px] flex-1">
        <SearchIcon className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2" />
        <Input
          value={filters.q}
          onChange={(e) => setFilters({ ...filters, q: e.target.value })}
          placeholder="Search advisory, CVE, package, MFE, CWE…"
          className="h-8 pr-8 pl-8 text-xs"
        />
        {filters.q && (
          <Button
            variant="ghost"
            size="icon-sm"
            className="absolute top-1/2 right-0.5 size-7 -translate-y-1/2"
            onClick={() => setFilters({ ...filters, q: '' })}
            aria-label="Clear search"
          >
            <XIcon className="size-3.5" />
          </Button>
        )}
      </div>

      <div className="text-muted-foreground shrink-0 text-xs tabular-nums">
        {filtered ? (
          <>
            <span className="text-foreground font-medium">{num(shown)}</span> of {num(total)}
          </>
        ) : (
          <>
            <span className="text-foreground font-medium">{num(total)}</span> findings
          </>
        )}
      </div>

      {/* Two filters that earn a permanent spot: they are the whole reason the
          reports are pooled, and burying them in the facet list would hide it. */}
      <div className="flex shrink-0 items-center gap-1">
        <FilterToggle
          icon={LayersIcon}
          label="Shared only"
          pressed={(filters.minMfes ?? 1) > 1}
          onPressedChange={(on) => setFilters({ ...filters, minMfes: on ? 2 : undefined })}
          hint="Only packages that more than one MFE carries."
        />
        <FilterToggle
          icon={CheckIcon}
          label="Fixable"
          pressed={filters.fixableOnly}
          onPressedChange={(on) => setFilters({ ...filters, fixableOnly: on })}
          hint="Only findings whose advisory names an exact clean version."
        />
      </div>

      {active > 0 && (
        <Button variant="ghost" size="xs" onClick={clearAll}>
          <XIcon />
          Clear {active} filter{active === 1 ? '' : 's'}
        </Button>
      )}

      <div className="ml-auto flex shrink-0 items-center gap-1">
        <Button variant="outline" size="xs" onClick={onManageReports}>
          <LayersIcon />
          {metas.length} MFE{metas.length === 1 ? '' : 's'}
        </Button>

        <CopyLinkButton />

        <DropdownMenu>
          <Tooltip>
            <TooltipTrigger asChild>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon-sm">
                  <Link2Icon />
                  <span className="sr-only">Advisory lookup database</span>
                </Button>
              </DropdownMenuTrigger>
            </TooltipTrigger>
            <TooltipContent>
              Advisory links prefer {ADVISORY_SOURCES.find((s) => s.id === advisorySource)?.label}
            </TooltipContent>
          </Tooltip>
          <DropdownMenuContent align="end" className="w-80">
            <DropdownMenuLabel>Open advisory links in</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {ADVISORY_SOURCES.map((s) => (
              <DropdownMenuItem key={s.id} onSelect={() => setAdvisorySource(s.id)} className="items-start gap-2">
                <CheckIcon className={advisorySource === s.id ? 'mt-0.5 opacity-100' : 'mt-0.5 opacity-0'} />
                <span className="min-w-0">
                  <span className="block font-medium">{s.label}</span>
                  <span className="text-muted-foreground block text-xs">{s.hint}</span>
                </span>
              </DropdownMenuItem>
            ))}
            <DropdownMenuSeparator />
            <div className="text-muted-foreground px-2 py-1.5 text-xs">
              A database that cannot resolve an id is skipped for that row — most of these advisories are GHSA,
              which NVD and MITRE do not index.
            </div>
            <DropdownMenuSeparator />
            <LiveLookupToggle />
          </DropdownMenuContent>
        </DropdownMenu>

        <WorkspaceInfo metas={metas} />

        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="ghost" size="icon-sm" onClick={onExport}>
              <DownloadIcon />
              <span className="sr-only">Export CSV</span>
            </Button>
          </TooltipTrigger>
          <TooltipContent>Export the current view as CSV</TooltipContent>
        </Tooltip>

        <ThemeToggle />
      </div>

      {active > 0 && (
        <div className="flex w-full flex-wrap items-center gap-1">
          {filters.fixableOnly && (
            <Chip label="Has an exact fix" onClear={() => setFilters({ ...filters, fixableOnly: false })} />
          )}
          {(filters.minMfes ?? 1) > 1 && (
            <Chip
              label={`In ${filters.minMfes}+ MFEs`}
              onClear={() => setFilters({ ...filters, minMfes: undefined })}
            />
          )}
          {(filters.cvssMin != null || filters.cvssMax != null) && (
            <Chip
              label={`CVSS ${filters.cvssMin ?? 0}-${filters.cvssMax ?? 10}`}
              onClear={() => setFilters({ ...filters, cvssMin: undefined, cvssMax: undefined })}
            />
          )}
          {Object.entries(filters.facets).map(([k, vals]) =>
            vals.length ? (
              <Chip
                key={k}
                label={`${labelFor(k)}: ${vals.length > 2 ? `${vals.length} selected` : vals.join(', ')}`}
                title={vals.join('\n')}
                onClear={() => {
                  const facets = { ...filters.facets }
                  delete facets[k]
                  setFilters({ ...filters, facets })
                }}
              />
            ) : null,
          )}
        </div>
      )}
    </div>
  )
}

/**
 * A two-state filter switch. Built on a button with `aria-pressed` rather than
 * a checkbox: it toggles a view, it does not submit a value, and a screen
 * reader should hear "pressed" rather than "checked".
 */
function FilterToggle({
  icon: Icon,
  label,
  pressed,
  onPressedChange,
  hint,
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  pressed: boolean
  onPressedChange: (on: boolean) => void
  hint: string
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant={pressed ? 'secondary' : 'ghost'}
          size="xs"
          aria-pressed={pressed}
          onClick={() => onPressedChange(!pressed)}
          className={cn('gap-1.5', pressed && 'border-ring border')}
        >
          <Icon className="size-3.5" />
          {label}
        </Button>
      </TooltipTrigger>
      <TooltipContent>{hint}</TooltipContent>
    </Tooltip>
  )
}

/**
 * Hovering an advisory calls OSV and EPSS. Some environments will not allow an
 * analyst's browser to reach third-party APIs, so the lookup can be switched
 * off and the choice is remembered.
 */
function LiveLookupToggle() {
  const [on, setOn] = useState(liveLookupEnabled)
  return (
    <DropdownMenuItem
      className="items-start gap-2"
      onSelect={(e) => {
        e.preventDefault()
        const next = !on
        setLiveLookup(next)
        setOn(next)
      }}
    >
      {on ? <WifiIcon className="mt-0.5" /> : <WifiOffIcon className="mt-0.5" />}
      <span className="min-w-0">
        <span className="block font-medium">Live detail on hover: {on ? 'on' : 'off'}</span>
        <span className="text-muted-foreground block text-xs">
          Looks up OSV (and EPSS, where a CVE is known) by identifier. No report content is sent.
        </span>
      </span>
    </DropdownMenuItem>
  )
}

function Chip({ label, title, onClear }: { label: string; title?: string; onClear: () => void }) {
  return (
    <Badge variant="secondary" className="gap-1 py-1 pr-1 pl-2 font-normal" title={title}>
      <span className="max-w-[260px] truncate">{label}</span>
      <button
        type="button"
        onClick={onClear}
        className="hover:bg-background/60 rounded p-0.5"
        aria-label="Remove filter"
      >
        <XIcon className="size-3" />
      </button>
    </Badge>
  )
}

function CopyLinkButton() {
  const [copied, setCopied] = useState(false)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="icon-sm"
          onClick={() => {
            navigator.clipboard.writeText(location.href)
            setCopied(true)
            setTimeout(() => setCopied(false), 1400)
          }}
        >
          {copied ? <CheckIcon /> : <Link2Icon />}
          <span className="sr-only">Copy link to this view</span>
        </Button>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        {copied
          ? 'Copied'
          : 'Copy a link to this exact filtered view. The reports stay local, so it only opens for someone whose workspace holds the same MFEs.'}
      </TooltipContent>
    </Tooltip>
  )
}

/**
 * Provenance for the whole workspace. Two reports scanned weeks apart are not
 * directly comparable, and the NVD data timestamps bound what any of them could
 * possibly have known — both belong on screen rather than in a README.
 */
function WorkspaceInfo({ metas }: { metas: ReportMeta[] }) {
  const dates = metas.map((m) => m.reportDate).filter(Boolean).sort() as string[]
  const oldest = dates[0]
  const newest = dates.at(-1)
  const engines = [...new Set(metas.map((m) => m.engineVersion).filter(Boolean))]
  const nvdStamps = [
    ...new Set(
      metas.flatMap((m) =>
        m.dataSources.filter((d) => /NVD API Last Modified/i.test(d.name)).map((d) => d.timestamp ?? ''),
      ),
    ),
  ].filter(Boolean)

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon-sm">
          <InfoIcon />
          <span className="sr-only">Workspace details</span>
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 p-0">
        <ScrollArea className="max-h-[70vh]">
          <div className="space-y-3 p-3 text-xs">
            <div>
              <div className="mb-1 font-medium">
                {metas.length} report{metas.length === 1 ? '' : 's'} loaded
              </div>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                <dt className="text-muted-foreground">Scanned</dt>
                <dd>
                  {oldest === newest
                    ? fmtDate(oldest)
                    : `${fmtDate(oldest)} → ${fmtDate(newest)}`}
                </dd>
                <dt className="text-muted-foreground">Engine</dt>
                <dd>{engines.length ? engines.join(', ') : 'unknown'}</dd>
                <dt className="text-muted-foreground">Dependencies scanned</dt>
                <dd className="tabular-nums">{num(metas.reduce((a, m) => a + m.dependencyCount, 0))}</dd>
                <dt className="text-muted-foreground">Suppressed</dt>
                <dd className="tabular-nums">{num(metas.reduce((a, m) => a + m.suppressedCount, 0))}</dd>
              </dl>
            </div>

            {oldest !== newest && (
              <p className="text-muted-foreground border-t pt-2">
                These reports were not produced at the same time. A gap between scans means the older MFEs are
                measured against an older advisory database — a lower count there is not necessarily better news.
              </p>
            )}

            {nvdStamps.length > 0 && (
              <div className="border-t pt-2">
                <div className="text-muted-foreground mb-1">NVD data last modified</div>
                <div className="font-mono text-[11px]">{nvdStamps.map((s) => fmtDate(s)).join(', ')}</div>
                <p className="text-muted-foreground mt-1">
                  Nothing published after this date could have been found by these scans.
                </p>
              </div>
            )}

            <div className="border-t pt-2">
              <div className="text-muted-foreground mb-1">Per report</div>
              <ul className="space-y-1">
                {metas.map((m) => (
                  <li key={m.reportId} className="flex items-baseline justify-between gap-2">
                    <span className="min-w-0 truncate">{m.mfe}</span>
                    <span className="text-muted-foreground shrink-0 font-mono text-[11px]">
                      {m.fingerprint} · {fmtDate(m.reportDate)}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="text-muted-foreground mt-1.5">
                The fingerprint is derived from the parsed findings: two parses of the same bytes always produce the
                same one.
              </p>
            </div>
          </div>
        </ScrollArea>
      </PopoverContent>
    </Popover>
  )
}

export function ThemeToggle() {
  const { theme, setTheme } = useTheme()
  const options: { value: Theme; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { value: 'dark', label: 'Dark', icon: MoonIcon },
    { value: 'light', label: 'Light', icon: SunIcon },
    { value: 'system', label: 'System', icon: MonitorIcon },
  ]
  const Current = options.find((o) => o.value === theme)?.icon ?? MoonIcon

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm">
          <Current />
          <span className="sr-only">Colour mode</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {options.map((o) => (
          <DropdownMenuItem key={o.value} onSelect={() => setTheme(o.value)}>
            <o.icon />
            {o.label}
            {theme === o.value && <CheckIcon className="ml-auto" />}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
