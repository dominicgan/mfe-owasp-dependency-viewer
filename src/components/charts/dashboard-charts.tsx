import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ComposedChart,
  Line,
  Pie,
  PieChart,
  XAxis,
  YAxis,
} from 'recharts'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  axisProps,
  ChartContainer,
  ChartLegend,
  ChartTooltip,
  foldToSlots,
  gridProps,
  SEVERITY_CONFIG,
} from '@/components/ui/chart'
import { num, pct } from '@/lib/format'
import type { Finding } from '@/lib/parse'
import { SEVERITY_ORDER } from '@/lib/schema'
import { countBy, fixPlan, severityBreakdown, spreadHistogram, stackedBySeverity } from '@/lib/stats'
import { cn } from '@/lib/utils'

const SEV_KEYS = [...SEVERITY_ORDER]

/**
 * Recharts hands click handlers a shape whose `key` collides with React's own
 * `Key` type, so read the bucket key off the payload defensively instead of
 * destructuring it.
 */
function onBucketClick(fn?: (value: string) => void) {
  if (!fn) return undefined
  return (d: unknown) => {
    const rec = d as { key?: unknown; payload?: { key?: unknown } } | undefined
    const v = rec?.payload?.key ?? rec?.key
    if (typeof v === 'string') fn(v)
  }
}

/** A stacked bar leaves a 2px surface gap between segments, per the mark spec. */
const STACK_GAP = { stroke: 'var(--card)', strokeWidth: 2 }

function ChartCard({
  title,
  description,
  children,
  className,
}: {
  title: string
  description?: string
  children: React.ReactNode
  className?: string
}) {
  return (
    <Card className={cn('flex flex-col', className)}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent className="flex-1">{children}</CardContent>
    </Card>
  )
}

function EmptyPlot({ height = 220 }: { height?: number }) {
  return (
    <div className="text-muted-foreground flex items-center justify-center text-xs" style={{ height }}>
      No rows match the current filters
    </div>
  )
}

/** Severity split. Donut, because this is a part-to-whole with few slices. */
export function SeverityChart({ rows, onSelect }: { rows: Finding[]; onSelect?: (sev: string) => void }) {
  const data = severityBreakdown(rows).filter((d) => d.count > 0)
  const total = data.reduce((a, b) => a + b.count, 0)
  const present = data.map((d) => d.key)

  return (
    <ChartCard title="Severity" description={`${num(total)} findings across every loaded MFE`}>
      {!total ? (
        <EmptyPlot height={200} />
      ) : (
        <>
          {/* The centre figure is an HTML overlay rather than an SVG <Label>:
              it inherits the app's type tokens and is not subject to the
              chart library's label-layout rules. */}
          <div className="relative">
            <ChartContainer height={200}>
              <PieChart>
                <ChartTooltip config={SEVERITY_CONFIG} />
                <Pie
                  data={data}
                  dataKey="count"
                  nameKey="key"
                  innerRadius={52}
                  outerRadius={78}
                  paddingAngle={2}
                  strokeWidth={0}
                  onClick={onBucketClick(onSelect)}
                  className={onSelect ? 'cursor-pointer' : undefined}
                >
                  {data.map((d) => (
                    <Cell key={d.key} fill={SEVERITY_CONFIG[d.key]?.color ?? 'var(--sev-none)'} />
                  ))}
                </Pie>
              </PieChart>
            </ChartContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-2xl leading-none font-semibold tabular-nums">{num(total)}</span>
              <span className="text-muted-foreground mt-1 text-[11px]">findings</span>
            </div>
          </div>
          <ChartLegend config={SEVERITY_CONFIG} keys={present} className="mt-1 justify-center" onSelect={onSelect} />
          {/* Direct labels: identity is never carried by colour alone. */}
          <div className="text-muted-foreground mt-2 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px] tabular-nums">
            {data.map((d) => (
              <div key={d.key} className="flex justify-between gap-2">
                <span>{d.key}</span>
                <span className="text-foreground font-medium">
                  {num(d.count)} <span className="text-muted-foreground font-normal">{pct(d.count, total)}</span>
                </span>
              </div>
            ))}
          </div>
        </>
      )}
    </ChartCard>
  )
}

/**
 * The remediation curve: bumps ordered by leverage, with the running share of
 * the backlog they clear.
 *
 * This is the chart the pooling exists to produce. On a shared stack the line
 * is brutally steep — a handful of upgrades usually covers most of it — and
 * that shape is the argument for doing the work centrally rather than per team.
 */
export function FixPlanChart({ rows, onSelect }: { rows: Finding[]; onSelect?: (pkg: string) => void }) {
  const plan = fixPlan(rows).slice(0, 12)
  const total = rows.length
  const data = plan.map((p) => ({
    key: p.packageName,
    closes: p.closes,
    cumulative: p.cumulative,
    cumulativePct: Math.round(p.cumulativePct * 100),
    mfeCount: p.mfeCount,
    target: p.targetVersion,
  }))

  const covered = plan.at(-1)?.cumulative ?? 0
  const config = {
    closes: { label: 'Findings closed', color: 'var(--chart-1)' },
    cumulativePct: { label: 'Cumulative %', color: 'var(--chart-3)' },
  }

  return (
    <ChartCard
      title="Remediation plan"
      description={
        data.length
          ? `The ${data.length} highest-leverage bumps clear ${num(covered)} of ${num(total)} findings (${pct(covered, total)})`
          : 'Bumps ranked by how much each one clears'
      }
      className="lg:col-span-2 xl:col-span-2"
    >
      {!data.length ? (
        <div className="text-muted-foreground flex h-[260px] items-center justify-center px-4 text-center text-xs">
          No advisory in the current selection names a fixed version, so no upgrade plan can be derived.
        </div>
      ) : (
        <>
          <ChartContainer height={260}>
            <ComposedChart data={data} margin={{ left: 4, right: 12, top: 8, bottom: 40 }}>
              <CartesianGrid {...gridProps} />
              <XAxis
                dataKey="key"
                {...axisProps}
                axisLine={false}
                interval={0}
                angle={-35}
                textAnchor="end"
                height={56}
                tickFormatter={(v: string) => (v.length > 16 ? `${v.slice(0, 15)}…` : v)}
              />
              <YAxis yAxisId="left" {...axisProps} axisLine={false} width={36} />
              <YAxis
                yAxisId="right"
                orientation="right"
                {...axisProps}
                axisLine={false}
                width={40}
                domain={[0, 100]}
                tickFormatter={(v: number) => `${v}%`}
              />
              <ChartTooltip config={config} />
              <Bar
                yAxisId="left"
                dataKey="closes"
                fill="var(--chart-1)"
                radius={[4, 4, 0, 0]}
                maxBarSize={38}
                onClick={onBucketClick(onSelect)}
                className={onSelect ? 'cursor-pointer' : undefined}
              />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="cumulativePct"
                stroke="var(--chart-3)"
                strokeWidth={2}
                dot={{ r: 3, strokeWidth: 0, fill: 'var(--chart-3)' }}
                activeDot={{ r: 5, stroke: 'var(--card)', strokeWidth: 2 }}
              />
            </ComposedChart>
          </ChartContainer>
          <ChartLegend config={config} keys={['closes', 'cumulativePct']} className="mt-1" />
          <p className="text-muted-foreground mt-2 text-[11px] leading-relaxed">
            Bars are findings closed by that one bump; the line is the running share of the whole backlog. Work
            left to right.
          </p>
        </>
      )}
    </ChartCard>
  )
}

/** Per-MFE totals, split by severity. The scorecard, as a picture. */
export function MfeChart({ rows, onSelect }: { rows: Finding[]; onSelect?: (mfe: string) => void }) {
  const data = stackedBySeverity(rows, 'mfe', 16)
  const present = SEV_KEYS.filter((k) => data.some((d) => (d[k] as number) > 0))

  return (
    <ChartCard title="By MFE" description="Which micro-frontends carry the most, stacked by severity">
      {!data.length ? (
        <EmptyPlot height={240} />
      ) : (
        <>
          <ChartContainer height={Math.max(180, data.length * 26 + 30)}>
            <BarChart data={data} layout="vertical" margin={{ left: 4, right: 16, top: 4, bottom: 0 }}>
              <CartesianGrid {...gridProps} horizontal={false} vertical />
              <XAxis type="number" {...axisProps} axisLine={false} />
              <YAxis
                type="category"
                dataKey="key"
                width={172}
                {...axisProps}
                axisLine={false}
                interval={0}
                tickFormatter={(v: string) => (v.length > 24 ? `${v.slice(0, 23)}…` : v)}
              />
              <ChartTooltip config={SEVERITY_CONFIG} total />
              {present.map((k, i) => (
                <Bar
                  key={k}
                  dataKey={k}
                  stackId="s"
                  fill={SEVERITY_CONFIG[k].color}
                  {...STACK_GAP}
                  radius={i === present.length - 1 ? [0, 4, 4, 0] : 0}
                  barSize={18}
                  onClick={onBucketClick(onSelect)}
                  className={onSelect ? 'cursor-pointer' : undefined}
                />
              ))}
            </BarChart>
          </ChartContainer>
          <ChartLegend config={SEVERITY_CONFIG} keys={present} className="mt-1" />
        </>
      )}
    </ChartCard>
  )
}

/** Top packages by finding count, split by severity. */
export function PackageChart({ rows, onSelect }: { rows: Finding[]; onSelect?: (pkg: string) => void }) {
  const data = stackedBySeverity(rows, 'packageName', 14)
  const present = SEV_KEYS.filter((k) => data.some((d) => (d[k] as number) > 0))

  return (
    <ChartCard title="Top packages" description="Which dependency accounts for the most findings">
      {!data.length ? (
        <EmptyPlot height={300} />
      ) : (
        <>
          <ChartContainer height={Math.max(180, data.length * 26 + 30)}>
            <BarChart data={data} layout="vertical" margin={{ left: 4, right: 16, top: 4, bottom: 0 }}>
              <CartesianGrid {...gridProps} horizontal={false} vertical />
              <XAxis type="number" {...axisProps} axisLine={false} />
              <YAxis
                type="category"
                dataKey="key"
                width={172}
                {...axisProps}
                axisLine={false}
                interval={0}
                tickFormatter={(v: string) => (v.length > 24 ? `${v.slice(0, 23)}…` : v)}
              />
              <ChartTooltip config={SEVERITY_CONFIG} total />
              {present.map((k, i) => (
                <Bar
                  key={k}
                  dataKey={k}
                  stackId="s"
                  fill={SEVERITY_CONFIG[k].color}
                  {...STACK_GAP}
                  radius={i === present.length - 1 ? [0, 4, 4, 0] : 0}
                  barSize={18}
                  onClick={onBucketClick(onSelect)}
                  className={onSelect ? 'cursor-pointer' : undefined}
                />
              ))}
            </BarChart>
          </ChartContainer>
          <ChartLegend config={SEVERITY_CONFIG} keys={present} className="mt-1" />
        </>
      )}
    </ChartCard>
  )
}

/**
 * How concentrated the shared debt is: packages grouped by how many MFEs carry
 * them. A tall bar on the right is the case for fixing centrally.
 */
export function SpreadChart({
  spread,
  packagesInView,
  mfeCount,
}: {
  spread: Map<string, number>
  packagesInView: Set<string>
  mfeCount: number
}) {
  const data = spreadHistogram(spread, packagesInView)
  const shared = data.filter((d) => d.key !== '1 MFE').reduce((a, b) => a + b.count, 0)
  const totalPackages = data.reduce((a, b) => a + b.count, 0)

  return (
    <ChartCard
      title="Shared dependencies"
      description={
        totalPackages
          ? `${num(shared)} of ${num(totalPackages)} vulnerable packages sit in more than one of your ${mfeCount} MFEs`
          : 'Vulnerable packages, grouped by how many MFEs carry them'
      }
    >
      {!data.length ? (
        <EmptyPlot height={180} />
      ) : (
        <ChartContainer height={180}>
          <BarChart data={data} margin={{ left: 0, right: 8, top: 8, bottom: 0 }}>
            <CartesianGrid {...gridProps} />
            <XAxis dataKey="key" {...axisProps} axisLine={false} />
            <YAxis {...axisProps} axisLine={false} width={36} />
            <ChartTooltip config={{ count: { label: 'Packages', color: 'var(--chart-1)' } }} />
            <Bar dataKey="count" fill="var(--chart-1)" radius={[4, 4, 0, 0]} maxBarSize={44} />
          </BarChart>
        </ChartContainer>
      )}
    </ChartCard>
  )
}

/** A single-series count bar over an arbitrary dimension. */
export function DimensionChart({
  rows,
  dimension,
  title,
  description,
  onSelect,
  height = 200,
  topN = 10,
}: {
  rows: Finding[]
  dimension: string
  title: string
  description?: string
  onSelect?: (value: string) => void
  height?: number
  topN?: number
}) {
  // The tail folds into "Other" rather than being dropped, so the bars still
  // add up to the filtered total.
  const data = foldToSlots(countBy(rows, dimension), topN)
  // One measure, one colour: the category is already named on the y-axis, so
  // giving each bar its own hue would encode nothing.
  const config = { count: { label: 'Findings', color: 'var(--chart-1)' } }

  return (
    <ChartCard title={title} description={description}>
      {!data.length ? (
        <EmptyPlot height={height} />
      ) : (
        <ChartContainer height={height}>
          <BarChart data={data} layout="vertical" margin={{ left: 4, right: 16, top: 4, bottom: 0 }}>
            <CartesianGrid {...gridProps} horizontal={false} vertical />
            <XAxis type="number" {...axisProps} axisLine={false} />
            <YAxis
              type="category"
              dataKey="key"
              width={168}
              {...axisProps}
              axisLine={false}
              interval={0}
              tickFormatter={(v: string) => (v.length > 23 ? `${v.slice(0, 22)}…` : v)}
            />
            <ChartTooltip config={config} />
            <Bar
              dataKey="count"
              fill="var(--chart-1)"
              radius={[0, 4, 4, 0]}
              barSize={18}
              onClick={onBucketClick(onSelect)}
              className={onSelect ? 'cursor-pointer' : undefined}
            />
          </BarChart>
        </ChartContainer>
      )}
    </ChartCard>
  )
}
