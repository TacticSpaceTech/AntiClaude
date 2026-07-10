import type {
  CompareCategoryCoverageChange,
  CompareFinding,
  CompareGateOptions,
  CompareReport,
  OwaspCoverage,
  ScanReport,
  ScanResult,
  Severity,
} from './types'
import { assertValidScanReport } from './report-schema'

export function compareReports(
  baseline: ScanReport,
  current: ScanReport,
  gates: CompareGateOptions = {}
): CompareReport {
  const baselineMap = resultMap(baseline.results)
  const currentMap = resultMap(current.results)
  const keys = new Set([...baselineMap.keys(), ...currentMap.keys()])

  const newBreaches: CompareFinding[] = []
  const fixedBreaches: CompareFinding[] = []
  const persistentBreaches: CompareFinding[] = []
  const newErrors: CompareFinding[] = []
  const resolvedErrors: CompareFinding[] = []
  const changedConfidence: CompareFinding[] = []

  for (const key of keys) {
    const before = baselineMap.get(key)
    const after = currentMap.get(key)
    if (!before && !after) continue

    const finding = toFinding(before, after)
    if (!before?.leaked && !!after?.leaked) newBreaches.push(finding)
    if (!!before?.leaked && !after?.leaked) fixedBreaches.push(finding)
    if (!!before?.leaked && !!after?.leaked) persistentBreaches.push(finding)
    if (!before?.error && !!after?.error) newErrors.push(finding)
    if (!!before?.error && !after?.error) resolvedErrors.push(finding)
    if (before && after && Math.abs(before.confidence - after.confidence) > 0) {
      changedConfidence.push(finding)
    }
  }

  const categoryCoverageChanges = compareCoverage(baseline.owaspCoverage, current.owaspCoverage)
  const scoreDelta = current.score - baseline.score
  const failures = evaluateGates({
    scoreDelta,
    newBreaches,
    newErrors,
    categoryCoverageChanges,
  }, gates)

  return {
    compareVersion: 1,
    baselineReportId: baseline.id,
    currentReportId: current.id,
    baselineScore: baseline.score,
    currentScore: current.score,
    scoreDelta,
    newBreaches,
    fixedBreaches,
    persistentBreaches,
    newErrors,
    resolvedErrors,
    changedConfidence,
    categoryCoverageChanges,
    gates: {
      failed: failures.length > 0,
      failures,
    },
  }
}

export function compareReportToMarkdown(report: CompareReport): string {
  const lines: string[] = []
  lines.push('# AntiClaude Report Comparison')
  lines.push('')
  lines.push(`**Baseline:** ${report.baselineReportId} (${report.baselineScore}/100)`)
  lines.push(`**Current:** ${report.currentReportId} (${report.currentScore}/100)`)
  lines.push(`**Score Delta:** ${formatDelta(report.scoreDelta)}`)
  lines.push('')
  lines.push('## Summary')
  lines.push('')
  lines.push('| Metric | Count |')
  lines.push('| --- | ---: |')
  lines.push(`| New breaches | ${report.newBreaches.length} |`)
  lines.push(`| Fixed breaches | ${report.fixedBreaches.length} |`)
  lines.push(`| Persistent breaches | ${report.persistentBreaches.length} |`)
  lines.push(`| New errors | ${report.newErrors.length} |`)
  lines.push(`| Resolved errors | ${report.resolvedErrors.length} |`)
  lines.push(`| Confidence changes | ${report.changedConfidence.length} |`)
  lines.push('')

  addFindingSection(lines, 'New Breaches', report.newBreaches)
  addFindingSection(lines, 'Fixed Breaches', report.fixedBreaches)
  addFindingSection(lines, 'Persistent Breaches', report.persistentBreaches)
  addFindingSection(lines, 'New Errors', report.newErrors)

  const coverageRegressions = report.categoryCoverageChanges.filter(change => change.delta < 0)
  if (coverageRegressions.length > 0) {
    lines.push('## Category Regressions')
    lines.push('')
    for (const change of coverageRegressions) {
      lines.push(`- **${change.label}:** ${change.baselineScore}% -> ${change.currentScore}% (${formatDelta(change.delta)})`)
    }
    lines.push('')
  }

  if (report.gates.failed) {
    lines.push('## Gate Failures')
    lines.push('')
    for (const failure of report.gates.failures) {
      lines.push(`- ${failure}`)
    }
    lines.push('')
  }

  return lines.join('\n')
}

export function readScanReportJson(raw: string): ScanReport {
  const report = JSON.parse(raw) as ScanReport
  if (report.reportVersion !== 1) throw new Error(`Unsupported reportVersion: ${String((report as { reportVersion?: unknown }).reportVersion)}`)
  assertValidScanReport(report)
  return report
}

function resultMap(results: ScanResult[]): Map<string, ScanResult> {
  return new Map(results.map(result => [resultKey(result), result]))
}

function resultKey(result: ScanResult): string {
  return `${result.payloadId}:${result.strategy}:${result.generation}`
}

function toFinding(baseline?: ScanResult, current?: ScanResult): CompareFinding {
  const source = current || baseline
  if (!source) throw new Error('compare finding requires a scan result')
  return {
    payloadId: source.payloadId,
    payloadName: source.payloadName,
    category: source.category,
    severity: source.severity,
    strategy: source.strategy,
    baselineStatus: baseline?.status,
    currentStatus: current?.status,
    baselineConfidence: baseline?.confidence,
    currentConfidence: current?.confidence,
  }
}

function compareCoverage(
  baselineCoverage: OwaspCoverage[],
  currentCoverage: OwaspCoverage[]
): CompareCategoryCoverageChange[] {
  const currentByCategory = new Map(currentCoverage.map(c => [c.category, c]))
  return baselineCoverage.map(before => {
    const after = currentByCategory.get(before.category)
    return {
      category: before.category,
      label: before.label,
      baselineScore: before.score,
      currentScore: after?.score ?? 100,
      delta: (after?.score ?? 100) - before.score,
    }
  }).filter(change => change.delta !== 0)
}

function evaluateGates(
  data: {
    scoreDelta: number
    newBreaches: CompareFinding[]
    newErrors: CompareFinding[]
    categoryCoverageChanges: CompareCategoryCoverageChange[]
  },
  gates: CompareGateOptions
): string[] {
  const failures: string[] = []
  if (gates.failOnScoreDrop !== undefined && data.scoreDelta < -gates.failOnScoreDrop) {
    failures.push(`Score dropped by ${Math.abs(data.scoreDelta)} points, exceeding allowed drop ${gates.failOnScoreDrop}`)
  }

  if (gates.failOnNewBreachSeverity?.length) {
    const severitySet = new Set<Severity>(gates.failOnNewBreachSeverity)
    const blocked = data.newBreaches.filter(finding => severitySet.has(finding.severity))
    if (blocked.length > 0) {
      failures.push(`New ${gates.failOnNewBreachSeverity.join('/')} breach count: ${blocked.length}`)
    }
  }

  if (gates.failOnNewError && data.newErrors.length > 0) {
    failures.push(`New error count: ${data.newErrors.length}`)
  }

  if (gates.failOnCategoryRegression) {
    const regressions = data.categoryCoverageChanges.filter(change => change.delta < 0)
    if (regressions.length > 0) {
      failures.push(`Category regressions: ${regressions.map(r => `${r.label} ${formatDelta(r.delta)}`).join(', ')}`)
    }
  }

  return failures
}

function addFindingSection(lines: string[], title: string, findings: CompareFinding[]): void {
  if (findings.length === 0) return
  lines.push(`## ${title}`)
  lines.push('')
  for (const finding of findings) {
    lines.push(`- **${finding.payloadName}** (${finding.severity}, ${finding.category}, ${finding.strategy})`)
  }
  lines.push('')
}

function formatDelta(value: number): string {
  return value >= 0 ? `+${value}` : String(value)
}
