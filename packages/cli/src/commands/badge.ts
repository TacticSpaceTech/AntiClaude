import { Command } from 'commander'
import chalk from 'chalk'
import * as fs from 'fs'

function generateBadgeUrl(score: number): string {
  const color = score >= 80 ? 'brightgreen' : score >= 50 ? 'yellow' : 'red'
  const label = 'AntiClaude'
  const message = `${score}%2F100`
  return `https://img.shields.io/badge/${label}-${message}-${color}`
}

export const badgeCommand = new Command('badge')
  .description('Generate a security badge URL for your README')
  .option('--score <number>', 'Security score (0-100)')
  .option('--report <path>', 'Read score from a JSON report file')
  .option('--format <type>', 'Output format: url, markdown, html', 'markdown')
  .action((opts) => {
    let score: number

    if (opts.report) {
      if (!fs.existsSync(opts.report)) {
        console.error(chalk.red(`Error: Report file not found: ${opts.report}`))
        process.exit(1)
      }
      const report = JSON.parse(fs.readFileSync(opts.report, 'utf-8'))
      score = report.score
      if (typeof score !== 'number') {
        console.error(chalk.red('Error: Could not read score from report file'))
        process.exit(1)
      }
    } else if (opts.score) {
      score = parseInt(opts.score, 10)
      if (Number.isNaN(score) || score < 0 || score > 100) {
        console.error(chalk.red('Error: --score must be a number between 0 and 100'))
        process.exit(1)
      }
    } else {
      console.error(chalk.red('Error: Provide --score or --report'))
      process.exit(1)
    }

    const url = generateBadgeUrl(score)

    switch (opts.format) {
      case 'url':
        console.log(url)
        break
      case 'html':
        console.log(`<img src="${url}" alt="AntiClaude Security Score">`)
        break
      case 'markdown':
      default:
        console.log(`![AntiClaude Security](${url})`)
        break
    }
  })

export { generateBadgeUrl }
