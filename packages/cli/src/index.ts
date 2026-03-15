#!/usr/bin/env node

import { Command } from 'commander'
import { scanCommand } from './commands/scan'
import { auditCommand } from './commands/audit'
import { mcpScanCommand } from './commands/mcp-scan'
import { badgeCommand } from './commands/badge'

const program = new Command()

program
  .name('anticlaude')
  .description('AI Agent Security Scanner — Red team your AI agents')
  .version('1.0.0')

program.addCommand(scanCommand)
program.addCommand(auditCommand)
program.addCommand(mcpScanCommand)
program.addCommand(badgeCommand)

program.parse()
