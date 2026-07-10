import { Command } from 'commander'
import chalk from 'chalk'
import { adapterForKind, startMockAgent } from '@anticlaude/engine'
import type { MockAgentKind } from '@anticlaude/engine'

const kinds: MockAgentKind[] = [
  'vulnerable-generic',
  'safe-generic',
  'openai-chat',
  'anthropic-messages',
  'tool-calling',
  'support-agent',
]

function parseKind(value: string): MockAgentKind {
  if (!kinds.includes(value as MockAgentKind)) {
    console.error(`Error: --kind must be one of ${kinds.join(', ')}, got: "${value}"`)
    process.exit(1)
  }
  return value as MockAgentKind
}

export const fixturesCommand = new Command('fixtures')
  .description('Start a local deterministic mock agent fixture')
  .option('--kind <kind>', `Fixture kind: ${kinds.join(', ')}`, 'vulnerable-generic')
  .option('--port <port>', 'Port to bind. Use 0 for a random local port.', '0')
  .action(async (opts) => {
    const kind = parseKind(opts.kind)
    const port = Number.parseInt(opts.port, 10)
    if (!Number.isInteger(port) || port < 0) {
      console.error(`Error: --port must be a non-negative integer, got: "${opts.port}"`)
      process.exit(1)
    }

    const fixture = await startMockAgent(kind, port)
    const target = adapterForKind(kind)

    console.log(chalk.green(`AntiClaude fixture '${kind}' listening on ${fixture.endpoint}`))
    console.log(chalk.dim(`Adapter: ${target.adapter}`))
    if (target.bodyField) console.log(chalk.dim(`Body field: ${target.bodyField}`))
    if (target.model) console.log(chalk.dim(`Model: ${target.model}`))
    console.log('')
    console.log('Example:')
    console.log(`  node packages/cli/dist/index.js scan --endpoint ${fixture.endpoint} --adapter ${target.adapter} --count 3 --output json`)

    await new Promise<void>((resolve) => {
      const shutdown = async () => {
        await fixture.close()
        resolve()
      }
      process.on('SIGINT', shutdown)
      process.on('SIGTERM', shutdown)
    })
  })
