import {
  ClockAlertIcon,
  FileWarningIcon,
  GitCompareArrowsIcon,
  GlobeIcon,
  LayersIcon,
  PackageIcon,
  WrenchIcon,
  ZapIcon,
} from 'lucide-react'
import { Card } from '@/components/ui/card'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { num, pct } from '@/lib/format'
import type { Kpis } from '@/lib/stats'
import { cn } from '@/lib/utils'

interface Tile {
  id: string
  label: string
  value: number | undefined
  sub?: string
  hint: string
  icon: React.ComponentType<{ className?: string }>
  tone?: 'critical' | 'high' | 'good' | 'default'
  onClick?: () => void
}

export interface KpiActions {
  onSeverity?: (sev: string) => void
  onRemote?: () => void
  onFixable?: () => void
  onShared?: () => void
  onDrift?: () => void
}

export function KpiCards({ kpis, actions }: { kpis: Kpis; actions?: KpiActions }) {
  const total = kpis.findings

  const tiles: Tile[] = [
    {
      id: 'quickwin',
      label: 'Top 5 bumps clear',
      value: kpis.quickWin,
      sub: `${pct(kpis.quickWin, total)} of everything`,
      hint: `The five highest-leverage package upgrades close ${num(kpis.quickWin)} of ${num(total)} findings between them. On a shared stack this is usually most of the backlog.`,
      icon: ZapIcon,
      tone: 'good',
    },
    {
      id: 'bumps',
      label: 'Bumps to do',
      value: kpis.bumps,
      sub: `across ${num(kpis.packages)} bad packages`,
      hint: 'Distinct packages with a derivable target version. This is the real size of the work — not the finding count.',
      icon: WrenchIcon,
      onClick: actions?.onFixable,
    },
    {
      id: 'critical',
      label: 'Critical',
      value: kpis.critical,
      sub: `${num(kpis.high)} high`,
      hint: 'Findings at Critical severity, pooled across every loaded MFE. The sub-figure counts High.',
      icon: FileWarningIcon,
      tone: 'critical',
      onClick: () => actions?.onSeverity?.('Critical'),
    },
    {
      id: 'remote',
      label: 'Remote, unauth',
      value: kpis.remoteUnauth,
      sub: `${pct(kpis.remoteUnauth, total)} of findings`,
      hint: 'Reachable over the network with no privileges and no user interaction, read off the CVSS vector. The first place an attacker looks.',
      icon: GlobeIcon,
      tone: kpis.remoteUnauth > 0 ? 'high' : 'default',
      onClick: actions?.onRemote,
    },
    {
      id: 'shared',
      label: 'Shared debt',
      value: kpis.sharedFindings,
      sub: `${num(kpis.sharedPackages)} packages in 2+ MFEs`,
      hint: 'Findings sitting in a package more than one MFE carries. These are the ones where a single upgrade pays off repeatedly.',
      icon: LayersIcon,
      onClick: actions?.onShared,
    },
    {
      id: 'drift',
      label: 'Version drift',
      value: kpis.versionDriftPackages,
      sub: 'packages on mixed versions',
      hint: 'Packages where different MFEs resolved different versions. The bump is not uniform, so each repo needs checking rather than a copy-paste.',
      icon: GitCompareArrowsIcon,
      tone: kpis.versionDriftPackages > 0 ? 'high' : 'default',
      onClick: actions?.onDrift,
    },
    {
      id: 'mfes',
      label: 'MFEs in view',
      value: kpis.mfes,
      sub: `${num(kpis.advisories)} distinct advisories`,
      hint: 'How many micro-frontends the current selection spans, and how many unique advisories are behind all these findings.',
      icon: PackageIcon,
    },
    {
      id: 'stale',
      label: 'Stalest scan',
      value: kpis.stalestScanDays,
      sub: kpis.stalestMfe ? `days · ${kpis.stalestMfe}` : 'days old',
      hint: 'Age of the oldest report in view. Advisories are published continuously, so an old scan under-reports — it does not mean that MFE is clean.',
      icon: ClockAlertIcon,
      tone: (kpis.stalestScanDays ?? 0) > 30 ? 'high' : 'default',
    },
  ]

  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 xl:grid-cols-8">
      {tiles.map((t) => (
        <KpiTile key={t.id} tile={t} />
      ))}
    </div>
  )
}

function KpiTile({ tile }: { tile: Tile }) {
  const Icon = tile.icon
  const interactive = Boolean(tile.onClick)

  const body = (
    <Card
      className={cn(
        'relative h-full overflow-hidden p-3 transition-colors',
        interactive && 'hover:border-ring cursor-pointer',
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-muted-foreground text-xs font-medium">{tile.label}</span>
        <Icon
          className={cn(
            'size-3.5 shrink-0',
            tile.tone === 'critical' && 'text-sev-critical',
            tile.tone === 'high' && 'text-sev-high',
            tile.tone === 'good' && 'text-chart-3',
            (!tile.tone || tile.tone === 'default') && 'text-muted-foreground',
          )}
        />
      </div>
      <div className="mt-1.5 text-2xl leading-none font-semibold tabular-nums">{num(tile.value)}</div>
      {tile.sub && <div className="text-muted-foreground mt-1 text-[11px]">{tile.sub}</div>}
    </Card>
  )

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        {interactive ? (
          <button type="button" onClick={tile.onClick} className="text-left">
            {body}
          </button>
        ) : (
          <div>{body}</div>
        )}
      </TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-xs">
        {tile.hint}
        {interactive && <span className="text-muted-foreground mt-1 block">Click to filter.</span>}
      </TooltipContent>
    </Tooltip>
  )
}
