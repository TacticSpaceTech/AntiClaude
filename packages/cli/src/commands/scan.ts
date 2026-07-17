import { Command } from 'commander'
import chalk from 'chalk'
import ora from 'ora'
import * as fs from 'fs'
import { loadEvalSuite, runScan, reportToJson, reportToMarkdown, reportToHtml } from '@anticlaude/engine'
import { generateBadgeUrl } from './badge'
import { resolveSuitePath } from '../paths'
import type { ScanProgress, ScanReport, LlmJudgeConfig, LlmJudgeProvider, TargetAdapter } from '@anticlaude/engine'

function parseIntOption(value: string, name: string): number {
  const n = parseInt(value, 10)
  if (Number.isNaN(n) || n <= 0) {
    console.error(`Error: --${name} must be a positive integer, got: "${value}"`)
    process.exit(1)
  }
  return n
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return chalk.red.bold(severity.toUpperCase())
    case 'high': return chalk.red(severity.toUpperCase())
    case 'medium': return chalk.yellow(severity.toUpperCase())
    case 'low': return chalk.green(severity.toUpperCase())
    default: return severity
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return chalk.green.bold(`${score}/100`)
  if (score >= 50) return chalk.yellow.bold(`${score}/100`)
  return chalk.red.bold(`${score}/100`)
}

function parseAdapter(value: string): TargetAdapter {
  const adapters: TargetAdapter[] = ['generic-json', 'openai-chat', 'anthropic-messages', 'custom-json']
  if (!adapters.includes(value as TargetAdapter)) {
    console.error(`Error: --adapter must be one of ${adapters.join(', ')}, got: "${value}"`)
    process.exit(1)
  }
  return value as TargetAdapter
}

export const scanCommand = new Command('scan')
  .description('Scan an AI agent endpoint for vulnerabilities')
  .requiredOption('--endpoint <url>', 'Target API endpoint URL')
  .option('--auth <header>', 'Authorization header value')
  .option('--adapter <type>', 'Target request adapter: generic-json, openai-chat, anthropic-messages, custom-json', 'generic-json')
  .option('--body-field <name>', 'JSON field used by the generic-json adapter', 'message')
  .option('--body-template <json>', 'Custom JSON request template. Use {{prompt}} inside a JSON string or {{promptJson}} as a JSON value.')
  .option('--target-model <model>', 'Model field for OpenAI-compatible or Anthropic-compatible adapters')
  .option('--max-tokens <number>', 'max_tokens for Anthropic-compatible requests', '1024')
  .option('--suite <file>', 'Eval suite JSON path or built-in name (smoke, builtin:smoke)')
  .option('--count <number>', 'Number of payloads to test', '12')
  .option('--variants <number>', 'Max variants per payload', '2')
  .option('--timeout <ms>', 'Request timeout in ms', '15000')
  .option('--output <format>', 'Output format: json, markdown, html', 'markdown')
  .option('--out <file>', 'Write report to file')
  .option('--fail-threshold <score>', 'Exit 1 if score is below this threshold')
  .option('--llm-judge <provider>', 'Enable LLM judge: openai or anthropic')
  .option('--llm-key <key>', 'API key for LLM judge (or set ANTICLAUDE_LLM_KEY)')
  .option('--llm-model <model>', 'Model override for LLM judge')
  .option('--json-summary', 'Output machine-readable summary line for CI')
  .action(async (opts) => {
    console.log('')
    console.log(chalk.green.bold('  ╔═══════════════════════════════════╗'))
    console.log(chalk.green.bold('  ║') + chalk.white.bold('   AntiClaude Security Scanner   ') + chalk.green.bold('║'))
    console.log(chalk.green.bold('  ╚═══════════════════════════════════╝'))
    console.log('')
    console.log(chalk.dim(`  Target: ${opts.endpoint}`))
    console.log('')

    const spinner = ora({ text: 'Loading payloads...', color: 'green' }).start()
    let currentPayloadName = ''

    const onProgress = (progress: ScanProgress) => {
      switch (progress.type) {
        case 'init':
          spinner.text = `Loaded ${progress.totalPayloads} payloads`
          break

        case 'attack_start':
          currentPayloadName = progress.payload?.info.name || ''
          spinner.text = `Testing: ${currentPayloadName} [${severityColor(progress.payload?.info.severity || '')}]`
          break

        case 'strategy_selected':
          spinner.text = `  → Strategy: ${chalk.yellow(progress.strategy || '')} for ${currentPayloadName}`
          break

        case 'attack_result': {
          const r = progress.result!
          spinner.stop()
          if (r.leaked) {
            console.log(
              chalk.red('  ✗ LEAKED') +
              chalk.dim(` [${r.confidence}%] `) +
              r.payloadName +
              chalk.dim(` (${severityColor(r.severity)})`)
            )
            if (r.indicators.length > 0) {
              console.log(chalk.dim(`    Indicators: ${r.indicators.join(', ')}`))
            }
            if (r.judgeVerdict) {
              console.log(chalk.magenta(`    Judge: ${r.judgeVerdict.reasoning}`))
            }
          } else if (r.error) {
            console.log(
              chalk.yellow('  ⚠ ERROR ') +
              r.payloadName +
              chalk.dim(` — ${r.error}`)
            )
          } else {
            console.log(
              chalk.green('  ✓ BLOCKED') +
              chalk.dim(' ') +
              r.payloadName
            )
          }
          spinner.start()
          break
        }

        case 'error':
          spinner.warn(chalk.yellow(`Error: ${progress.message}`))
          spinner.start()
          break

        case 'complete':
          spinner.stop()
          break
      }
    }

    try {
      let llmJudge: LlmJudgeConfig | undefined
      if (opts.llmJudge) {
        const provider = opts.llmJudge as LlmJudgeProvider
        const apiKey = opts.llmKey
          || process.env.ANTICLAUDE_LLM_KEY
          || (provider === 'openai' ? process.env.OPENAI_API_KEY : process.env.ANTHROPIC_API_KEY)
          || ''
        if (!apiKey) {
          console.error(chalk.red('Error: LLM judge requires an API key. Use --llm-key or set ANTICLAUDE_LLM_KEY.'))
          process.exit(1)
        }
        llmJudge = { provider, apiKey, model: opts.llmModel }
        console.log(chalk.dim(`  LLM Judge: ${provider} (${llmJudge.model || 'default model'})`))
        console.log('')
      }

      const adapter = parseAdapter(opts.adapter)
      const suite = opts.suite ? loadEvalSuite(resolveSuitePath(opts.suite)) : undefined
      const report = await runScan({
        endpoint: opts.endpoint,
        target: {
          adapter,
          authHeader: opts.auth,
          bodyField: opts.bodyField,
          bodyTemplate: opts.bodyTemplate,
          model: opts.targetModel,
          maxTokens: adapter === 'anthropic-messages' ? parseIntOption(opts.maxTokens, 'max-tokens') : undefined,
        },
        payloadCount: parseIntOption(opts.count, 'count'),
        maxVariants: suite?.maxVariants ?? parseIntOption(opts.variants, 'variants'),
        timeout: parseIntOption(opts.timeout, 'timeout'),
        suite,
        onProgress,
        llmJudge,
      })

      printSummary(report)

      if (opts.out) {
        writeReport(report, opts.output, opts.out)
      }

      if (opts.jsonSummary) {
        console.log(`ANTICLAUDE_SUMMARY=${JSON.stringify({
          reportVersion: report.reportVersion,
          score: report.score,
          breaches: report.summary.breaches,
          errors: report.summary.errors,
        })}`)
      }

      if (opts.failThreshold !== undefined) {
        const threshold = parseIntOption(opts.failThreshold, 'fail-threshold')
        if (report.score < threshold) {
          console.error(chalk.red(`AntiClaude score ${report.score} is below threshold ${threshold}`))
          process.exit(1)
        }
      }
    } catch (err) {
      spinner.fail(chalk.red(`Scan failed: ${err instanceof Error ? err.message : err}`))
      process.exit(1)
    }
  })

function printSummary(report: ScanReport) {
  console.log('')
  console.log(chalk.green.bold('  ─── Scan Complete ───'))
  console.log('')
  console.log(`  Score:    ${scoreColor(report.score)}`)
  console.log(`  Duration: ${chalk.dim((report.duration / 1000).toFixed(1) + 's')}`)
  console.log(`  Tested:   ${report.summary.totalAttempts} attempts across ${report.summary.totalPayloads} payloads`)
  console.log(`  Breaches: ${report.summary.breaches > 0 ? chalk.red.bold(String(report.summary.breaches)) : chalk.green('0')}`)
  console.log(`  Blocked:  ${chalk.green(String(report.summary.blocked))}`)
  if (report.summary.errors > 0) {
    console.log(`  Errors:   ${chalk.yellow(String(report.summary.errors))}`)
  }
  console.log('')

  // OWASP coverage
  console.log(chalk.green.bold('  ─── OWASP Agentic Top 10 ───'))
  console.log('')
  for (const c of report.owaspCoverage) {
    if (c.tested === 0) continue
    const bar = c.score >= 80 ? chalk.green('█') : c.score >= 50 ? chalk.yellow('█') : chalk.red('█')
    const barStr = bar.repeat(Math.round(c.score / 5)) + chalk.dim('░').repeat(20 - Math.round(c.score / 5))
    console.log(`  ${barStr} ${c.score}% ${chalk.dim(c.label)}`)
  }
  console.log('')

  const badgeUrl = generateBadgeUrl(report.score)
  console.log(chalk.dim(`  Badge: ![AntiClaude Security](${badgeUrl})`))
  console.log('')
}

function writeReport(report: ScanReport, format: string, filePath: string) {
  let content: string
  switch (format) {
    case 'json':
      content = reportToJson(report)
      break
    case 'html':
      content = reportToHtml(report)
      break
    case 'markdown':
    default:
      content = reportToMarkdown(report)
      break
  }

  fs.writeFileSync(filePath, content, 'utf-8')
  console.log(chalk.dim(`  Report written to ${filePath}`))
}
