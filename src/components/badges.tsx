import {
  ArrowRightIcon,
  ExternalLinkIcon,
  GlobeIcon,
  HelpCircleIcon,
  LaptopIcon,
  MousePointerClickIcon,
  UserCheckIcon,
  WrenchIcon,
} from 'lucide-react'
import { AdvisoryHover, type LocalAdvisoryContext } from '@/components/advisory-hover'
import { Badge } from '@/components/ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { advisoryKind, advisoryUrl, isLinkable } from '@/lib/advisory'
import { cn } from '@/lib/utils'

const SEV_STYLE: Record<string, string> = {
  Critical: 'border-sev-critical/40 bg-sev-critical/15 text-sev-critical',
  High: 'border-sev-high/40 bg-sev-high/15 text-sev-high',
  Medium: 'border-sev-medium/40 bg-sev-medium/15 text-sev-medium',
  Low: 'border-sev-low/40 bg-sev-low/15 text-sev-low',
  Info: 'border-sev-info/40 bg-sev-info/15 text-sev-info',
  Unknown: 'border-sev-none/40 bg-sev-none/15 text-sev-none',
}

/**
 * Severity always ships as colour + text. Status colours never carry meaning
 * alone, so the label is not optional.
 */
export function SeverityBadge({ severity, className }: { severity: unknown; className?: string }) {
  const s = String(severity ?? 'Unknown')
  return (
    <Badge variant="outline" className={cn('font-medium', SEV_STYLE[s] ?? SEV_STYLE.Unknown, className)}>
      {s}
    </Badge>
  )
}

const FIX_COPY: Record<string, { label: string; hint: string; tone: string }> = {
  'Exact fix': {
    label: 'Fix available',
    hint: 'The advisory names a version that is not affected, so there is an exact release to bump to.',
    tone: 'border-sev-low/40 bg-sev-low/15 text-sev-low',
  },
  'Later release': {
    label: 'Later release',
    hint: 'The advisory says every version up to and including the one listed is affected, but does not name the release that fixed it. You will need to check the project for the next version.',
    tone: 'border-sev-medium/40 bg-sev-medium/15 text-sev-medium',
  },
  Unknown: {
    label: 'No fix info',
    hint: 'This advisory carries no machine-readable version range, so no fixed version can be derived from the report.',
    tone: 'text-muted-foreground',
  },
}

/**
 * Whether a fix version could be derived, with the reason on hover. Three
 * states, not two: "no upper bound in the advisory" is a different problem from
 * "there is no fix", and collapsing them would quietly hide work.
 */
export function FixBadge({
  status,
  fixedIn,
  reason,
  className,
}: {
  status: unknown
  fixedIn?: unknown
  reason?: unknown
  className?: string
}) {
  const key = String(status ?? 'Unknown')
  const copy = FIX_COPY[key] ?? FIX_COPY.Unknown
  const version = String(fixedIn ?? '')

  const badge = (
    <Badge variant="outline" className={cn('gap-1 font-medium', copy.tone, className)}>
      {key === 'Unknown' ? <HelpCircleIcon className="size-3" /> : <WrenchIcon className="size-3" />}
      {version || copy.label}
    </Badge>
  )

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span>{badge}</span>
      </TooltipTrigger>
      <TooltipContent className="max-w-sm">
        <span className="block font-medium">{copy.label}</span>
        <span className="text-muted-foreground mt-0.5 block">{copy.hint}</span>
        {Boolean(reason) && <span className="mt-1 block border-t pt-1">{String(reason)}</span>}
      </TooltipContent>
    </Tooltip>
  )
}

const EXPOSURE_STYLE: Record<string, { icon: React.ComponentType<{ className?: string }>; tone: string }> = {
  'Remote, unauthenticated': { icon: GlobeIcon, tone: 'border-sev-critical/40 bg-sev-critical/15 text-sev-critical' },
  'Remote, needs user action': { icon: MousePointerClickIcon, tone: 'border-sev-high/40 bg-sev-high/15 text-sev-high' },
  'Remote, authenticated': { icon: UserCheckIcon, tone: 'border-sev-medium/40 bg-sev-medium/15 text-sev-medium' },
  'Adjacent network': { icon: LaptopIcon, tone: 'text-muted-foreground' },
  'Local only': { icon: LaptopIcon, tone: 'text-muted-foreground' },
  'Physical access': { icon: LaptopIcon, tone: 'text-muted-foreground' },
}

/** Reachability, read straight off the CVSS vector rather than guessed. */
export function ExposureBadge({ exposure, vector, className }: { exposure: unknown; vector?: unknown; className?: string }) {
  const v = String(exposure ?? 'Unknown')
  const style = EXPOSURE_STYLE[v]
  const Icon = style?.icon ?? HelpCircleIcon

  const badge = (
    <Badge variant="outline" className={cn('gap-1 font-medium', style?.tone ?? 'text-muted-foreground', className)}>
      <Icon className="size-3" />
      {v}
    </Badge>
  )
  if (!vector) return badge
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span>{badge}</span>
      </TooltipTrigger>
      <TooltipContent>
        Derived from <span className="font-mono">{String(vector)}</span>
      </TooltipContent>
    </Tooltip>
  )
}

/** `3.1.5 → 3.1.6`, with the arrow rendered rather than typed into the data. */
export function UpgradeCell({ from, to, className }: { from: unknown; to: unknown; className?: string }) {
  const a = String(from ?? '')
  const b = String(to ?? '')
  if (!b) return <span className="text-muted-foreground">-</span>
  return (
    <span className={cn('inline-flex items-center gap-1 font-mono text-xs', className)}>
      <span className="text-muted-foreground">{a || '?'}</span>
      <ArrowRightIcon className="size-3 shrink-0 opacity-60" />
      <span className="font-medium">{b}</span>
    </span>
  )
}

/** How many MFEs carry this, as a number you can see at a glance. */
export function SpreadBadge({ count, total, className }: { count: number; total?: number; className?: string }) {
  const shared = count > 1
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge
          variant="outline"
          className={cn(
            'tabular-nums',
            shared ? 'border-chart-2/40 bg-chart-2/15 text-chart-2 font-medium' : 'text-muted-foreground font-normal',
            className,
          )}
        >
          {count}
          {total ? ` / ${total}` : ''}
        </Badge>
      </TooltipTrigger>
      <TooltipContent>
        {shared
          ? `Present in ${count} of your loaded MFEs — one bump fixes all of them.`
          : 'Only one MFE carries this.'}
      </TooltipContent>
    </Tooltip>
  )
}

/**
 * An advisory id links out to a database that can actually resolve it. NVD
 * cannot answer a GHSA, so a GHSA never renders as an NVD link; an identifier
 * no source accepts renders as plain text rather than a dead link.
 */
export function AdvisoryLink({
  advisory,
  source,
  className,
  showIcon = true,
  preview,
}: {
  advisory: unknown
  source?: string
  className?: string
  showIcon?: boolean
  /** Row context for the hover card. Omit to render a plain link. */
  preview?: LocalAdvisoryContext | false
}) {
  const v = String(advisory ?? '').trim()
  if (!v) return <span className="text-muted-foreground">-</span>

  const href = isLinkable(v) ? advisoryUrl(v, source) : null
  if (!href) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span className={cn('font-mono text-xs', className)}>{v}</span>
        </TooltipTrigger>
        <TooltipContent>No public vulnerability database resolves this identifier.</TooltipContent>
      </Tooltip>
    )
  }

  const link = (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      onClick={(e) => e.stopPropagation()}
      className={cn(
        'text-foreground inline-flex items-center gap-1 font-mono text-xs underline decoration-dotted underline-offset-2 hover:decoration-solid',
        className,
      )}
      title={advisoryKind(v) === 'ghsa' ? 'GitHub Security Advisory' : undefined}
    >
      {v}
      {showIcon && <ExternalLinkIcon className="size-3 shrink-0 opacity-60" />}
    </a>
  )

  if (preview === false || preview === undefined) return link
  return (
    <AdvisoryHover advisory={v} source={source} local={preview}>
      {link}
    </AdvisoryHover>
  )
}
