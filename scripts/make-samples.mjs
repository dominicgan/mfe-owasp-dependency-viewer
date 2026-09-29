/**
 * Builds the bundled sample estate in `public/samples/`.
 *
 * Four synthetic micro-frontends, assembled from real OWASP dependency-check
 * output, chosen to exercise everything the viewer claims to do:
 *
 *   - a package shared by three MFEs at two different versions (version drift)
 *   - the three fix states: an exact version, a "later release" upper bound
 *     that names no clean release, and an advisory with no range at all
 *   - a Critical finding in two MFEs
 *   - one deliberately stale scan, to trigger the scan-age warning
 *
 * The vulnerability payloads are verbatim from a real report; the estate around
 * them is not. Regenerate with:
 *
 *     node scripts/make-samples.mjs
 */
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const OUT = resolve(dirname(fileURLToPath(import.meta.url)), '../public/samples')
mkdirSync(OUT, { recursive: true })

const SCAN_INFO = {
  engineVersion: '12.1.3',
  dataSource: [
    { name: 'NVD API Last Checked', timestamp: '2026-09-25T13:37:47Z' },
    { name: 'NVD API Last Modified', timestamp: '2026-05-17T02:16:45Z' },
    { name: 'NVD Cache Last Checked', timestamp: '2026-09-25T13:37:47Z' },
    { name: 'NVD Cache Last Modified', timestamp: '2026-05-17T02:16:45Z' },
  ],
}

const CREDITS = {
  NVD: 'This product uses the NVD API but is not endorsed or certified by the NVD. This report contains data retrieved from the National Vulnerability Database: https://nvd.nist.gov',
  CISA: 'This report may contain data retrieved from the CISA Known Exploited Vulnerability Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  NPM: 'This report may contain data retrieved from the Github Advisory Database (via NPM Audit API): https://github.com/advisories/',
  RETIREJS: 'This report may contain data retrieved from the RetireJS community: https://retirejs.github.io/retire.js/',
  OSSINDEX: 'This report may contain data retrieved from the Sonatype OSS Index: https://ossindex.sonatype.org',
}

const cvss = (baseScore, attackVector, privilegesRequired, userInteraction, scope, c, i, a, baseSeverity) => ({
  baseScore,
  attackVector,
  attackComplexity: 'LOW',
  privilegesRequired,
  userInteraction,
  scope,
  confidentialityImpact: c,
  integrityImpact: i,
  availabilityImpact: a,
  baseSeverity,
  version: '3.1',
})

const refs = (...urls) =>
  urls.map((url) => ({ source: 'NPM Advisory reference: ', url, name: url }))

const cpe = (product, range) => [{ software: { id: `cpe:2.3:a:*:${product}:${range}:*:*:*:*:*:*:*` } }]

/** Vulnerability payloads, keyed by the package they belong to. */
const VULNS = {
  '@faker-js/faker': [
    {
      source: 'NPM',
      name: 'GHSA-qxc2-j82w-r537',
      unscored: 'true',
      severity: 'high',
      cvssv3: cvss(7.800000190734863, 'LOCAL', 'LOW', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 'HIGH'),
      cwes: ['CWE-95'],
      description:
        '### Summary\n\n`faker.helpers.fake` can be tricked into arbritary code execution.\n\n### Details\n\nfakeEval.resolveProperty resolves properties on functions itself instead of resolving the nested function first.\nThis can be addressed by recursively calling resolveProperty instead of accessing the property after one iteration.\n\n### Impact\n\nThe Fake method claims:\n\n> It is also NOT possible to use any non-faker methods or plain javascript in such patterns.\n\nWhich is objectively false, since any global gets fully accessible in the fake string.',
      notes: '',
      references: refs(
        'https://github.com/faker-js/faker/commit/54586208f904012f57c50b46cc1ad32bcbe4bfb7',
        'https://github.com/faker-js/faker/pull/3852',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-73231',
        'https://github.com/faker-js/faker/security/advisories/GHSA-qxc2-j82w-r537',
        'https://github.com/faker-js/faker/releases/tag/v10.5.0',
        'https://github.com/advisories/GHSA-qxc2-j82w-r537',
      ),
      // Upper bound is inclusive, so the report names no clean release: this is
      // the "later release" fix state.
      vulnerableSoftware: cpe('\\@faker-js\\/faker', '\\<\\=10.4.0'),
    },
  ],
  'adm-zip': [
    {
      source: 'NPM',
      name: 'GHSA-7q85-xj36-vmfc',
      unscored: 'true',
      severity: 'high',
      cvssv3: cvss(7.5, 'NETWORK', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'NONE', 'HIGH', 'HIGH'),
      cwes: ['CWE-789'],
      description:
        "### Summary\nadm-zip allocates an entry's output buffer from the declared uncompressed size (central-directory `size` field) before validating it against the actual data. A tiny crafted ZIP that declares a huge uncompressed size forces a multi-gigabyte allocation from a few bytes.\n\n### Impact\nOn adm-zip 0.5.17 (latest), Node 24, a 105-byte ZIP with one stored entry declaring size = 1,774,399,200 makes `new AdmZip(buf).getEntries()[0].getData()` commit ~1.8 GB of resident memory in ~4.4 s before throwing `Error: ADM-ZIP: CRC32 checksum failed`, roughly 16 million times the input size. Because the buffer is committed before any validation, on a memory-constrained host (containers, serverless, small VMs) the allocation OOM-kills the process before the CRC check (uncatchable), and concurrent requests can exhaust memory even on larger hosts. Any service that reads entries from untrusted ZIPs is exposed to a remote denial of service.\n\n### Root cause\n`zipEntry.js` does `Buffer.alloc(<declared uncompressed size>)` before checking the declared size against the compressed size / available bytes.\n\n### Suggested fix\nValidate the declared uncompressed size against the compressed size and a configurable maximum before allocating.",
      notes: '',
      references: refs(
        'https://github.com/cthackers/adm-zip/security/advisories/GHSA-7q85-xj36-vmfc',
        'https://github.com/cthackers/adm-zip/commit/491600683dacb6cb9fe0718a0eeb9cb5eb49afa6',
        'https://github.com/cthackers/adm-zip/releases/tag/v0.6.1',
        'https://github.com/advisories/GHSA-7q85-xj36-vmfc',
      ),
      vulnerableSoftware: cpe('adm-zip', '\\<0.6.1'),
    },
    {
      source: 'NPM',
      name: 'GHSA-vwc7-r8mq-g2x9',
      unscored: 'true',
      severity: 'moderate',
      cvssv3: cvss(6.5, 'LOCAL', 'LOW', 'NONE', 'CHANGED', 'NONE', 'HIGH', 'NONE', 'MEDIUM'),
      cwes: ['CWE-59'],
      description:
        'adm-zip 0.5.9 through 0.6.0 follows symbolic links at the extraction destination. Utils.sanitize in util/utils.js enforces containment by comparing only the string form of an archive entry name against the resolved extraction root, and Utils.writeFileTo opens the computed destination with fs.openSync(path, "w", 0o666), which resolves symbolic links and carries neither O_NOFOLLOW nor a pre-write fs.lstatSync check. When a path component at the destination already exists as a symbolic link pointing outside the extraction root, extractAllTo, extractAllToAsync and extractEntryTo write the entry contents through that link and then chmod its target, placing attacker-controlled content in a file outside the root without any traversal sequence appearing in the archive. An attacker able to create a symbolic link inside a shared, reused or predictable extraction directory, such as a temporary directory or a continuous integration workspace, can overwrite any file the extracting process is permitted to write.',
      notes: '',
      references: refs(
        'https://github.com/cthackers/adm-zip/pull/575',
        'https://github.com/advisories/GHSA-vwc7-r8mq-g2x9',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-76845',
        'https://github.com/cthackers/adm-zip/issues/574',
      ),
      vulnerableSoftware: cpe('adm-zip', '\\>\\=0.5.9\\<\\=0.6.0'),
    },
  ],
  'fast-uri': [
    {
      source: 'NPM',
      name: 'GHSA-5jgf-p345-68v8',
      unscored: 'true',
      severity: 'high',
      cvssv3: cvss(7.5, 'NETWORK', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'HIGH', 'NONE', 'HIGH'),
      cwes: ['CWE-436'],
      description:
        '### Impact\n\n`fast-uri` canonicalizes a host to its ASCII form only when the input carries an explicit scheme. When `resolve()` resolves a scheme-relative reference (`//host/`) against a scheme-bearing base, it still emits the host verbatim even though the effective scheme is known, so re-parsing the resolved URI yields a different host than the one `resolve()` returned. An application that resolves an untrusted reference with `fast-uri` and then checks or routes on the resulting host can make a policy decision on one host and reach another.\n\n### Patches\n\nUpgrade to `fast-uri` 2.4.5, 3.1.6, or 4.1.3.',
      notes: '',
      references: refs(
        'https://github.com/fastify/fast-uri/security/advisories/GHSA-5jgf-p345-68v8',
        'https://github.com/fastify/fast-uri/releases/tag/v3.1.6',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-75931',
        'https://github.com/advisories/GHSA-5jgf-p345-68v8',
      ),
      vulnerableSoftware: cpe('fast-uri', '\\>\\=3.1.3\\<3.1.6'),
    },
    {
      source: 'NPM',
      name: 'GHSA-f65p-4m7j-42xc',
      unscored: 'true',
      severity: 'high',
      cvssv3: cvss(7.5, 'NETWORK', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'HIGH', 'NONE', 'HIGH'),
      cwes: ['CWE-20', 'CWE-918'],
      description:
        "### Impact\n\n`fast-uri` does not validate the complete RFC 3986 grammar for bracketed IPv6 literals, so a malformed literal with invalid trailing text is silently truncated to a different valid IPv6 address with no error reported. For example, `normalize('http://[::not-valid]/private')` returns `http://[::]/private`. An application that normalizes an untrusted URL before an outbound request, redirect, or host-policy check can be routed to a local or private address such as loopback (`::1`), unique-local, or link-local.\n\n### Patches\n\nUpgrade to `fast-uri` 2.4.5, 3.1.6, or 4.1.3.",
      notes: '',
      references: refs(
        'https://github.com/fastify/fast-uri/security/advisories/GHSA-f65p-4m7j-42xc',
        'https://github.com/fastify/fast-uri/releases/tag/v3.1.6',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-75975',
        'https://github.com/advisories/GHSA-f65p-4m7j-42xc',
      ),
      vulnerableSoftware: cpe('fast-uri', '\\>\\=3.0.0\\<3.1.6'),
    },
    {
      source: 'NPM',
      name: 'GHSA-fph4-wmhf-6fwf',
      unscored: 'true',
      severity: 'high',
      cvssv3: cvss(7.5, 'NETWORK', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'HIGH', 'NONE', 'HIGH'),
      cwes: ['CWE-174', 'CWE-918'],
      description:
        "### Impact\n\n`fast-uri` decodes a hostname's percent escapes twice in a single `normalize()` or `resolve()` call: once during parsing and again during authority recomposition. A nested percent-encoded host therefore survives the first decode and is turned into a live destination by the second, so `normalize('http://%256c%256f%2563%2561%256c%2568%256f%2573%2574/')` returns `http://localhost/`. Applications that normalize or resolve an untrusted URI before an SSRF check, redirect validation, or host allowlist can be steered to a different destination, including internal addresses such as loopback or a cloud metadata endpoint.\n\n### Patches\n\nFixed in `fast-uri` 2.4.5, 3.1.6, and 4.1.3.",
      notes: '',
      references: refs(
        'https://github.com/fastify/fast-uri/security/advisories/GHSA-fph4-wmhf-6fwf',
        'https://github.com/fastify/fast-uri/releases/tag/v3.1.6',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-75899',
        'https://github.com/advisories/GHSA-fph4-wmhf-6fwf',
      ),
      vulnerableSoftware: cpe('fast-uri', '\\>\\=3.1.2\\<3.1.6'),
    },
    {
      source: 'NPM',
      name: 'GHSA-jqff-g426-hqxp',
      unscored: 'true',
      severity: 'high',
      cvssv3: cvss(7.5, 'NETWORK', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'HIGH', 'NONE', 'HIGH'),
      cwes: ['CWE-177'],
      description:
        '### Impact\n\n`fast-uri` decodes percent-encoded characters in the scheme component with the legacy global `unescape()` and serializes the result back as raw characters, without re-escaping it or validating it as a scheme. A scheme that decodes to characters outside the RFC 3986 scheme grammar can therefore introduce structure the original input did not contain.\n\nFor example, `%2f%2fevil.example:/pwn` parses with no authority, but `resolve()` and `normalize()` return `//evil.example:/pwn`, which reparses with host `evil.example`. A scheme containing `%0d%0a` reaches the output as a raw CR LF.\n\n### Patches\n\nUpgrade to `fast-uri` >= 4.1.3, or >= 3.1.6 in the v3.x release line, or >= 2.4.5 in the v2.x release line.',
      notes: '',
      references: refs(
        'https://github.com/fastify/fast-uri/security/advisories/GHSA-jqff-g426-hqxp',
        'https://github.com/fastify/fast-uri/releases/tag/v3.1.6',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-76172',
        'https://github.com/advisories/GHSA-jqff-g426-hqxp',
      ),
      vulnerableSoftware: cpe('fast-uri', '\\>\\=3.0.0\\<3.1.6'),
    },
  ],
  'js-yaml': [
    {
      source: 'NPM',
      name: 'GHSA-2883-xcg3-v3hh',
      unscored: 'true',
      severity: 'high',
      cvssv3: cvss(7.5, 'NETWORK', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'NONE', 'HIGH', 'HIGH'),
      cwes: ['CWE-400', 'CWE-407'],
      description:
        '## Summary\n\n`maxTotalMergeKeys` does not count empty mappings. An attacker can repeatedly merge a large sequence of them and consume significant CPU without reaching the configured limit.\n\n## Impact\n\nAn attacker can submit a relatively small YAML document that causes prolonged CPU consumption despite the default `maxTotalMergeKeys` limit. A 500 KB document measured at ~13 seconds.\n\n## Fix\n\nCount each merge-source mapping as one budget unit, in addition to counting its keys.\n\n## Difference with v5\n\nIn v3 & v4, merge is enabled by default. So, the severity score is higher.',
      notes: '',
      references: refs(
        'https://github.com/nodeca/js-yaml/security/advisories/GHSA-2883-xcg3-v3hh',
        'https://github.com/nodeca/js-yaml/pull/797',
        'https://github.com/nodeca/js-yaml/releases/tag/4.3.2',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-84375',
        'https://github.com/advisories/GHSA-2883-xcg3-v3hh',
      ),
      vulnerableSoftware: cpe('js-yaml', '\\>\\=4.0.0\\<4.3.2'),
    },
  ],
  'tar-fs': [
    {
      source: 'NPM',
      name: 'GHSA-8cj5-5rvv-wf4v',
      unscored: 'true',
      severity: 'critical',
      cvssv3: cvss(9.800000190734863, 'NETWORK', 'NONE', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 'CRITICAL'),
      cwes: ['CWE-22'],
      description:
        '### Summary\n\n`tar-fs` does not resolve a symbolic link in an intermediate path component before writing an entry, so an archive whose entries traverse a link planted earlier in the same archive can write outside the extraction directory.\n\n### Impact\n\nAny service that extracts an untrusted tarball can have arbitrary files written with the permissions of the extracting process. In a build agent this reaches the workspace and the runner configuration.\n\n### Patches\n\nUpgrade to `tar-fs` 3.0.10, 2.1.4 or 1.16.6.',
      notes: '',
      references: refs(
        'https://github.com/mafintosh/tar-fs/security/advisories/GHSA-8cj5-5rvv-wf4v',
        'https://nvd.nist.gov/vuln/detail/CVE-2026-71104',
        'https://github.com/advisories/GHSA-8cj5-5rvv-wf4v',
      ),
      vulnerableSoftware: cpe('tar-fs', '\\>\\=3.0.0\\<3.0.10'),
    },
  ],
  'lodash.template': [
    {
      source: 'NPM',
      name: 'GHSA-35jh-r3h4-6jhm',
      unscored: 'true',
      severity: 'high',
      cvssv3: cvss(7.199999809265137, 'NETWORK', 'HIGH', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 'HIGH'),
      cwes: ['CWE-94'],
      description:
        'The template function is vulnerable to command injection via the options argument. This package is deprecated and no fixed release is planned; migrate to a maintained templating library.',
      notes: '',
      references: refs('https://github.com/advisories/GHSA-35jh-r3h4-6jhm'),
      // Deliberately empty: exercises the "no fix information" state, where the
      // advisory carries no machine-readable range to derive a target from.
      vulnerableSoftware: [],
    },
  ],
}

function encodePurl(name, version) {
  if (!name.startsWith('@')) return `pkg:npm/${name}@${version}`
  const [scope, rest] = name.split('/')
  return `pkg:npm/${encodeURIComponent(scope)}%2F${rest}@${version}`
}

function dep(name, version, project, scope = 'transitive') {
  const vulns = VULNS[name]
  if (!vulns) throw new Error(`no vulnerability payload for ${name}`)
  return {
    isVirtual: true,
    fileName: `${name}:${version}`,
    filePath: `/__w/${project}/${project}/package-lock.json?${name}`,
    projectReferences: [`package-lock.json: ${scope}`],
    evidenceCollected: {
      vendorEvidence: [{ type: 'vendor', confidence: 'HIGH', source: 'package.json', name: 'name', value: name }],
      productEvidence: [{ type: 'product', confidence: 'HIGHEST', source: 'package.json', name: 'name', value: name }],
      versionEvidence: [{ type: 'version', confidence: 'HIGHEST', source: 'package.json', name: 'version', value: version }],
    },
    packages: [{ id: encodePurl(name, version), confidence: 'HIGHEST' }],
    vulnerabilities: structuredClone(vulns),
  }
}

const ESTATE = [
  {
    project: 'myexpress-dashboard-ui',
    file: 'dashboard-ui',
    reportDate: '2026-09-25T13:39:20.313740050Z',
    scanned: 412,
    deps: (p) => [
      dep('@faker-js/faker', '9.9.0', p),
      dep('adm-zip', '0.6.0', p),
      dep('fast-uri', '3.1.5', p),
      dep('js-yaml', '4.3.1', p),
    ],
  },
  {
    project: 'myexpress-accounts-ui',
    file: 'accounts-ui',
    reportDate: '2026-09-24T09:14:02.118200000Z',
    scanned: 388,
    deps: (p) => [
      dep('fast-uri', '3.1.5', p),
      // Drift: a different minor of a dependency three MFEs share.
      dep('js-yaml', '4.2.0', p),
      dep('tar-fs', '3.0.8', p),
    ],
  },
  {
    project: 'myexpress-payments-ui',
    file: 'payments-ui',
    reportDate: '2026-09-25T11:02:47.905110000Z',
    scanned: 401,
    deps: (p) => [
      dep('fast-uri', '3.1.3', p),
      dep('adm-zip', '0.6.0', p),
      dep('tar-fs', '3.0.8', p),
      dep('lodash.template', '4.5.0', p, 'direct'),
    ],
  },
  {
    project: 'myexpress-shell-host',
    file: 'shell-host',
    // Deliberately stale, to exercise the scan-age warning.
    reportDate: '2026-08-12T07:41:16.440900000Z',
    scanned: 356,
    deps: (p) => [dep('js-yaml', '4.3.1', p), dep('@faker-js/faker', '9.9.0', p), dep('adm-zip', '0.5.9', p)],
  },
]

for (const mfe of ESTATE) {
  const dependencies = mfe.deps(mfe.project)
  const vulnerable = dependencies.length
  const findings = dependencies.reduce((a, d) => a + d.vulnerabilities.length, 0)

  // Pad with the clean dependencies a real scan also reports, so "dependencies
  // scanned" is not just the vulnerable ones.
  for (let i = vulnerable; i < mfe.scanned; i++) {
    dependencies.push({
      isVirtual: true,
      fileName: `clean-package-${i}:1.0.0`,
      filePath: `/__w/${mfe.project}/${mfe.project}/package-lock.json?clean-package-${i}`,
      projectReferences: ['package-lock.json: transitive'],
      evidenceCollected: { vendorEvidence: [], productEvidence: [], versionEvidence: [] },
      packages: [{ id: `pkg:npm/clean-package-${i}@1.0.0`, confidence: 'HIGHEST' }],
    })
  }

  const report = {
    reportSchema: '1.1',
    scanInfo: structuredClone(SCAN_INFO),
    projectInfo: { name: mfe.project, reportDate: mfe.reportDate, credits: structuredClone(CREDITS) },
    dependencies,
  }

  writeFileSync(`${OUT}/${mfe.file}.dependency-check-report.json`, JSON.stringify(report))
  console.log(
    `${mfe.file.padEnd(13)} ${String(vulnerable).padStart(2)} vulnerable deps · ` +
      `${String(findings).padStart(2)} findings · ${dependencies.length} scanned`,
  )
}
