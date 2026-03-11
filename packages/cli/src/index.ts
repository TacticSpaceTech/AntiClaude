#!/usr/bin/env node

import { Command } from 'commander'
import { scanCommand } from './commands/scan'
import { auditCommand } from './commands/audit'

const program = new Command()

program
  .name('anticlaude')
  .description('AI Agent Security Scanner — Red team your AI agents')
  .version('1.0.0')

program.addCommand(scanCommand)
program.addCommand(auditCommand)

program.parse()
