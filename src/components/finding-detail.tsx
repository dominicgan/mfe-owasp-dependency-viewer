import { ExternalLinkIcon, FilterIcon } from 'lucide-react'
import { AdvisoryLink, ExposureBadge, FixBadge, SeverityBadge, UpgradeCell } from '@/components/badges'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'
import { sourcesFor } from '@/lib/advisory'
import { cvss as fmtCvss, date as fmtDate } from '@/lib/format'
import type { Finding } from '@/lib/parse'

interface Reference {
  url: string
  name: string
}

export function FindingDetail({
  finding,
  advisorySource,
  mfesForAdvisory,
  onClose,
  onFilterBy,
}: {
  finding: Finding | null
  advisorySource: string
  /** Every MFE this advisory shows up in, so the sheet answers "who else?". */
  mfesForAdvisory: string[]
  onClose: () => void
  onFilterBy: (key: string, value: string) => void
}) {
  if (!finding) return null
  const f = finding
  const refs = (f.references as Reference[] | undefined) ?? []
  const cwes = (f.cwes as string[] | undefined) ?? []

  return (
    <Sheet open onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="flex w-full flex-col gap-0 p-0 sm:max-w-xl">
        <SheetHeader className="border-b">
          <SheetTitle className="flex flex-wrap items-center gap-2">
            <AdvisoryLink advisory={f.advisory} source={advisorySource} preview={false} className="text-sm" />
            <SeverityBadge severity={f.severity} />
            {f.cvss != null && (
              <Badge variant="secondary" className="tabular-nums">
                CVSS {fmtCvss(f.cvss)} {String(f.cvssVersion ?? '')}
              </Badge>
            )}
            {f.unscored === 'Yes' && (
              <Badge variant="outline" className="font-normal" title="The source flagged this score as not officially assigned">
                unscored
              </Badge>
            )}
          </SheetTitle>
          <SheetDescription>
            {String(f.packageName)} {String(f.packageVersion)} in {String(f.mfe)}
          </SheetDescription>
        </SheetHeader>

        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-4 p-4 text-xs">
            <Section title="Fix">
              <div className="flex flex-wrap items-center gap-2">
                <FixBadge status={f.fixStatus} fixedIn={f.fixedIn} reason={f.fixReason} />
                {Boolean(f.fixedIn) && <UpgradeCell from={f.packageVersion} to={f.fixedIn} className="text-sm" />}
              </div>
              {Boolean(f.fixReason) && (
                <p className="text-muted-foreground mt-2 leading-relaxed">{String(f.fixReason)}</p>
              )}
              {Boolean(f.affectedRange) && (
                <Row label="Advisory range">
                  <span className="font-mono">{String(f.affectedRange)}</span>
                </Row>
              )}
            </Section>

            {mfesForAdvisory.length > 1 && (
              <Section title={`This advisory also hits ${mfesForAdvisory.length - 1} other MFE${mfesForAdvisory.length === 2 ? '' : 's'}`}>
                <div className="flex flex-wrap gap-1">
                  {mfesForAdvisory.map((m) => (
                    <button key={m} type="button" onClick={() => onFilterBy('mfe', m)}>
                      <Badge variant={m === f.mfe ? 'default' : 'secondary'} className="font-normal">
                        {m}
                      </Badge>
                    </button>
                  ))}
                </div>
                <p className="text-muted-foreground mt-1.5">
                  One upgrade in the shared dependency clears it everywhere it appears at the same version.
                </p>
              </Section>
            )}

            <Section title="Where">
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5">
                <Field label="MFE" value={f.mfe} onFilter={() => onFilterBy('mfe', String(f.mfe))} />
                <Field
                  label="Package"
                  value={f.packageName}
                  onFilter={() => onFilterBy('packageName', String(f.packageName))}
                />
                <Field label="Version" value={f.packageVersion} mono />
                <Field
                  label="Scope"
                  value={f.dependencyScope}
                  onFilter={() => onFilterBy('dependencyScope', String(f.dependencyScope))}
                />
                {Boolean(f.projectRef) && <Field label="Manifest" value={f.projectRef} mono />}
                {Boolean(f.purl) && <Field label="Package URL" value={f.purl} mono />}
                {Boolean(f.filePath) && <Field label="File path" value={f.filePath} mono />}
              </dl>
            </Section>

            <Section title="Risk">
              <div className="mb-2 flex flex-wrap gap-2">
                <ExposureBadge exposure={f.exposure} vector={f.cvssVector} />
                {cwes.map((c) => (
                  <button key={c} type="button" onClick={() => onFilterBy('cwe', c)}>
                    <Badge variant="outline" className="font-normal">
                      {c}
                    </Badge>
                  </button>
                ))}
              </div>
              {Boolean(f.cvssVector) && (
                <Row label="Vector">
                  <span className="font-mono break-all">{String(f.cvssVector)}</span>
                </Row>
              )}
              <dl className="mt-1.5 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5">
                <Field label="Attack vector" value={f.attackVector} />
                <Field label="Attack complexity" value={f.attackComplexity} />
                <Field label="Privileges required" value={f.privilegesRequired} />
                <Field label="User interaction" value={f.userInteraction} />
                <Field label="Scope" value={f.cvssScope} />
                <Field label="Confidentiality" value={f.confidentialityImpact} />
                <Field label="Integrity" value={f.integrityImpact} />
                <Field label="Availability" value={f.availabilityImpact} />
              </dl>
            </Section>

            {Boolean(f.description) && (
              <Section title="Description">
                {/* Advisory descriptions are Markdown. Rendering them as a
                    whitespace-preserving block keeps their structure legible
                    without pulling in a Markdown renderer — and without ever
                    putting advisory-supplied HTML into the document. */}
                <p className="text-muted-foreground leading-relaxed whitespace-pre-wrap">
                  {String(f.description)}
                </p>
              </Section>
            )}

            <Section title="Provenance">
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5">
                <Field label="Reported by" value={f.source} onFilter={() => onFilterBy('source', String(f.source))} />
                {Boolean(f.cve) && <Field label="CVE" value={f.cve} mono />}
                <Field label="Scanned" value={fmtDate(f.reportDate)} />
                {f.scanAgeDays != null && <Field label="Scan age" value={`${String(f.scanAgeDays)} days`} />}
                {Boolean(f.engineVersion) && <Field label="Engine" value={f.engineVersion} />}
              </dl>
            </Section>

            {refs.length > 0 && (
              <Section title={`References (${refs.length})`}>
                <ul className="space-y-1">
                  {refs.map((r) => (
                    <li key={r.url}>
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-muted-foreground hover:text-foreground inline-flex min-w-0 items-start gap-1 underline decoration-dotted underline-offset-2"
                      >
                        <span className="break-all">{r.url}</span>
                        <ExternalLinkIcon className="mt-0.5 size-3 shrink-0 opacity-60" />
                      </a>
                    </li>
                  ))}
                </ul>
              </Section>
            )}
          </div>
        </ScrollArea>

        <div className="flex flex-wrap items-center gap-x-2 gap-y-1 border-t p-3">
          <span className="text-muted-foreground text-[11px]">Look up:</span>
          {sourcesFor(f.advisory).map((s) => (
            <a
              key={s.id}
              href={s.url(String(f.advisory))}
              target="_blank"
              rel="noreferrer noopener"
              title={s.hint}
              className="text-muted-foreground hover:text-foreground text-[11px] underline decoration-dotted underline-offset-2"
            >
              {s.label}
            </a>
          ))}
          {Boolean(f.cve) && f.cve !== f.advisory && (
            <span className="text-muted-foreground text-[11px]">· as {String(f.cve)}</span>
          )}
        </div>
      </SheetContent>
    </Sheet>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-1.5 text-xs font-semibold">{title}</h3>
      <Separator className="mb-2" />
      {children}
    </section>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mt-1.5 flex gap-3">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className="min-w-0">{children}</span>
    </div>
  )
}

function Field({
  label,
  value,
  mono,
  onFilter,
}: {
  label: string
  value: unknown
  mono?: boolean
  onFilter?: () => void
}) {
  const v = String(value ?? '')
  if (!v) return null
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={`flex min-w-0 items-start gap-1 ${mono ? 'font-mono break-all' : ''}`}>
        <span className="min-w-0">{v}</span>
        {onFilter && (
          <Button
            variant="ghost"
            size="icon-sm"
            className="size-5 shrink-0"
            onClick={onFilter}
            aria-label={`Filter by ${label} ${v}`}
            title={`Filter to ${v}`}
          >
            <FilterIcon className="size-3" />
          </Button>
        )}
      </dd>
    </>
  )
}
