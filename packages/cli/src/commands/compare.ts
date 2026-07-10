import { Command } from 'commander'
import chalk from 'chalk'
import * as fs from 'fs'
import { compareReports, compareReportToMarkdown, readScanReportJson } from '@anticlaude/engine'
import type { CompareGateOptions, Severity } from '@anticlaude/engine'

const severities: Severity[] = ['critical', 'high', 'medium', 'low']

export const compareCommand = new Command('compare')
  .description('Compare two AntiClaude JSON reports and detect regressions')
  .argument('<baseline>', 'Baseline JSON report')
  .argument('<current>', 'Current JSON report')
  .option('--output <format>', 'Output format: markdown, json', 'markdown')
  .option('--out <file>', 'Write comparison to file')
  .option('--fail-on-score-drop <points>', 'Exit 1 if score drops by more than this many points')
  .option('--fail-on-new-severity <list>', 'Exit 1 on new breaches at these severities, comma-separated')
  .option('--fail-on-new-error', 'Exit 1 if current report has new errors')
  .option('--fail-on-category-regression', 'Exit 1 if any OWASP category score regresses')
  .action((baselinePath: string, currentPath: string, opts) => {
    const baseline = readScanReportJson(fs.readFileSync(baselinePath, 'utf-8'))
    const current = readScanReportJson(fs.readFileSync(currentPath, 'utf-8'))
    const gates = parseGates(opts)
    const comparison = compareReports(baseline, current, gates)
    const output = opts.output === 'json'
      ? JSON.stringify(comparison, null, 2)
      : compareReportToMarkdown(comparison)

    if (opts.out) {
      fs.writeFileSync(opts.out, output, 'utf-8')
      console.log(chalk.dim(`Comparison written to ${opts.out}`))
    } else {
      console.log(output)
    }

    if (comparison.gates.failed) {
      for (const failure of comparison.gates.failures) {
        console.error(chalk.red(`Gate failed: ${failure}`))
      }
      process.exit(1)
    }
  })

function parseGates(opts: Record<string, unknown>): CompareGateOptions {
  return {
    failOnScoreDrop: opts.failOnScoreDrop !== undefined
      ? parseNonNegativeNumber(String(opts.failOnScoreDrop), 'fail-on-score-drop')
      : undefined,
    failOnNewBreachSeverity: opts.failOnNewSeverity
      ? parseSeverityList(String(opts.failOnNewSeverity))
      : undefined,
    failOnNewError: !!opts.failOnNewError,
    failOnCategoryRegression: !!opts.failOnCategoryRegression,
  }
}

function parseNonNegativeNumber(value: string, name: string): number {
  const parsed = Number(value)
  if (!Number.isFinite(parsed) || parsed < 0) {
    console.error(`Error: --${name} must be a non-negative number, got: "${value}"`)
    process.exit(1)
  }
  return parsed
}

function parseSeverityList(value: string): Severity[] {
  const parsed = value.split(',').map(item => item.trim()).filter(Boolean)
  const invalid = parsed.filter(item => !severities.includes(item as Severity))
  if (invalid.length > 0) {
    console.error(`Error: invalid severities: ${invalid.join(', ')}. Use ${severities.join(', ')}`)
    process.exit(1)
  }
  return parsed as Severity[]
}
