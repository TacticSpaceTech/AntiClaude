import { Command } from 'commander'
import chalk from 'chalk'
import * as fs from 'fs'
import * as path from 'path'
import { parseSkillFiles, auditSkills, generateLockFile } from '@anticlaude/engine'
import type { SkillAuditResult, SkillFinding } from '@anticlaude/engine'

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return chalk.red.bold(severity.toUpperCase())
    case 'high': return chalk.red(severity.toUpperCase())
    case 'medium': return chalk.yellow(severity.toUpperCase())
    case 'low': return chalk.green(severity.toUpperCase())
    default: return severity
  }
}

function dimensionLabel(dim: string): string {
  const labels: Record<string, string> = {
    'description-poisoning': 'Description Poisoning',
    'parameter-injection': 'Parameter Injection',
    'permission-scope': 'Permission Scope',
    'return-value-trust': 'Return Value Trust',
    'tool-shadowing': 'Tool Shadowing',
    'integrity': 'Integrity',
  }
  return labels[dim] || dim
}

export const auditCommand = new Command('audit')
  .description('Audit AI tool/skill definitions for security issues')
  .argument('<path>', 'Path to skill file or directory')
  .option('--pin', 'Generate .anticlaude-lock integrity file')
  .option('--lock <file>', 'Path to existing lock file for integrity checks')
  .action(async (targetPath: string, opts: { pin?: boolean; lock?: string }) => {
    console.log('')
    console.log(chalk.green.bold('  ╔═══════════════════════════════════╗'))
    console.log(chalk.green.bold('  ║') + chalk.white.bold('    AntiClaude Skill Auditor     ') + chalk.green.bold('║'))
    console.log(chalk.green.bold('  ╚═══════════════════════════════════╝'))
    console.log('')

    const resolvedPath = path.resolve(targetPath)
    if (!fs.existsSync(resolvedPath)) {
      console.log(chalk.red(`  Error: Path not found: ${resolvedPath}`))
      process.exit(1)
    }

    console.log(chalk.dim(`  Scanning: ${resolvedPath}`))
    console.log('')

    const skills = parseSkillFiles(resolvedPath)
    if (skills.length === 0) {
      console.log(chalk.yellow('  No skill definitions found.'))
      console.log(chalk.dim('  Expected JSON or YAML files with "name" and "description" fields.'))
      process.exit(0)
    }

    console.log(chalk.dim(`  Found ${skills.length} skill definition(s)`))
    console.log('')

    const lockFile = opts.lock || path.join(path.dirname(resolvedPath), '.anticlaude-lock')
    const results = auditSkills(skills, fs.existsSync(lockFile) ? lockFile : undefined)

    for (const result of results) {
      printSkillResult(result)
    }

    // Overall summary
    const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0)
    const avgScore = Math.round(results.reduce((sum, r) => sum + r.score, 0) / results.length)

    console.log(chalk.green.bold('  ─── Summary ───'))
    console.log('')
    console.log(`  Skills audited: ${results.length}`)
    console.log(`  Total findings: ${totalFindings > 0 ? chalk.red.bold(String(totalFindings)) : chalk.green('0')}`)
    console.log(`  Average score:  ${avgScore >= 80 ? chalk.green.bold(`${avgScore}/100`) : avgScore >= 50 ? chalk.yellow.bold(`${avgScore}/100`) : chalk.red.bold(`${avgScore}/100`)}`)
    console.log('')

    // Generate lock file if --pin
    if (opts.pin) {
      const lock = generateLockFile(results)
      const lockPath = path.join(
        fs.statSync(resolvedPath).isDirectory() ? resolvedPath : path.dirname(resolvedPath),
        '.anticlaude-lock'
      )
      fs.writeFileSync(lockPath, JSON.stringify(lock, null, 2), 'utf-8')
      console.log(chalk.green(`  Lock file written to ${lockPath}`))
      console.log(chalk.dim('  Run audit again to verify integrity against this lock.'))
      console.log('')
    }
  })

function printSkillResult(result: SkillAuditResult) {
  const scoreStr = result.score >= 80
    ? chalk.green.bold(`${result.score}/100`)
    : result.score >= 50
    ? chalk.yellow.bold(`${result.score}/100`)
    : chalk.red.bold(`${result.score}/100`)

  console.log(`  ${chalk.white.bold(result.skill.name)} — ${scoreStr}`)

  if (result.findings.length === 0) {
    console.log(chalk.green('    ✓ No issues found'))
  } else {
    for (const f of result.findings) {
      console.log(
        `    ${severityColor(f.severity)} ` +
        chalk.dim(`[${dimensionLabel(f.dimension)}] `) +
        f.message
      )
      if (f.evidence) {
        console.log(chalk.dim(`      Evidence: ${f.evidence}`))
      }
      console.log(chalk.dim(`      Fix: ${f.recommendation}`))
    }
  }
  console.log('')
}
