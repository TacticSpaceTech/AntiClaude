#!/usr/bin/env node

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Command } from 'commander'
import { scanCommand } from './commands/scan'
import { auditCommand } from './commands/audit'
import { mcpScanCommand } from './commands/mcp-scan'
import { badgeCommand } from './commands/badge'
import { fixturesCommand } from './commands/fixtures'
import { compareCommand } from './commands/compare'
import { guardCommand } from './commands/guard'
import { replayCommand } from './commands/replay'
import { reviewCommand } from './commands/review'

function resolveVersion(): string {
  try {
    const pkgPath = join(__dirname, '..', 'package.json')
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version?: string }
    if (pkg.version) return pkg.version
  } catch {
    // fall through
  }
  return '1.1.0'
}

const program = new Command()

program
  .name('anticlaude')
  .description('Local-first eval, runtime control, and audit replay for AI agents')
  .version(resolveVersion())

program.addCommand(scanCommand)
program.addCommand(auditCommand)
program.addCommand(mcpScanCommand)
program.addCommand(badgeCommand)
program.addCommand(fixturesCommand)
program.addCommand(compareCommand)
program.addCommand(guardCommand)
program.addCommand(replayCommand)
program.addCommand(reviewCommand)

program.parse()
