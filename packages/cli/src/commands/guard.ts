import { Command } from 'commander'
import chalk from 'chalk'
import {
  DEFAULT_GUARD_POLICY,
  DEFAULT_RUNTIME_POLICY_PROFILE,
  loadGuardPolicy,
  loadRuntimePolicyProfile,
  startGuardGateway,
} from '@anticlaude/engine'
import type { TargetAdapter } from '@anticlaude/engine'
import { resolvePolicyPath } from '../paths'

const adapters: TargetAdapter[] = ['generic-json', 'openai-chat', 'anthropic-messages', 'custom-json']

export const guardCommand = new Command('guard')
  .description('Start the local-only AntiClaude Guard alpha gateway')
  .requiredOption('--target <url>', 'Target API endpoint URL to forward allowed requests to')
  .option('--config <file>', 'Guard policy JSON/YAML path or built-in name (default, builtin:default)')
  .option('--port <port>', 'Local port to bind. Use 0 for a random local port.', '0')
  .option('--adapter <type>', 'Target request adapter: generic-json, openai-chat, anthropic-messages, custom-json', 'generic-json')
  .option('--body-field <name>', 'JSON field used by the generic-json adapter', 'message')
  .option('--body-template <json>', 'Custom JSON request template. Use {{prompt}} or {{promptJson}}.')
  .option('--target-model <model>', 'Model field for provider-compatible adapters')
  .option('--max-tokens <number>', 'max_tokens for Anthropic-compatible requests', '1024')
  .option('--auth <header>', 'Authorization header value for the target. Trace output redacts it.')
  .option('--timeout <ms>', 'Target request timeout in ms', '15000')
  .option('--trace <file>', 'Append JSONL policy trace events to this local file', 'traces/anticlaude-guard.jsonl')
  .option('--runtime-profile <file>', 'Runtime tool-governance profile JSON/YAML file. Defaults to support-agent beta profile when runtime review options are used.')
  .option('--agent-id <id>', 'Fallback runtime agent id when the target response does not include agent.id', 'support-agent')
  .option('--review-store <file>', 'Append pending runtime review requests to this local JSONL file')
  .action(async (opts) => {
    const port = parseNonNegativeInt(opts.port, 'port')
    const timeout = parsePositiveInt(opts.timeout, 'timeout')
    const adapter = parseAdapter(opts.adapter)
    const maxTokens = adapter === 'anthropic-messages'
      ? parsePositiveInt(opts.maxTokens, 'max-tokens')
      : undefined
    const policy = opts.config ? loadGuardPolicy(resolvePolicyPath(opts.config)) : DEFAULT_GUARD_POLICY
    const runtimeProfile = opts.runtimeProfile
      ? loadRuntimePolicyProfile(opts.runtimeProfile)
      : opts.reviewStore
        ? DEFAULT_RUNTIME_POLICY_PROFILE
        : undefined

    const gateway = await startGuardGateway({
      policy,
      targetEndpoint: opts.target,
      target: {
        adapter,
        authHeader: opts.auth,
        bodyField: opts.bodyField,
        bodyTemplate: opts.bodyTemplate,
        model: opts.targetModel,
        maxTokens,
      },
      port,
      timeout,
      traceFile: opts.trace,
      runtimeProfile,
      agentId: opts.agentId,
      reviewStoreFile: opts.reviewStore,
    })

    console.log(chalk.green(`AntiClaude Guard alpha listening on ${gateway.endpoint}`))
    console.log(chalk.dim('Local-only prototype. It evaluates prompt, tool-call, and output risk before returning a response.'))
    console.log(chalk.dim(`Target: ${opts.target}`))
    console.log(chalk.dim(`Adapter: ${adapter}`))
    console.log(chalk.dim(`Trace: ${opts.trace}`))
    if (runtimeProfile) console.log(chalk.dim(`Runtime profile: ${runtimeProfile.id}@${runtimeProfile.version}`))
    if (opts.reviewStore) console.log(chalk.dim(`Review store: ${opts.reviewStore}`))
    console.log('')
    console.log('Example:')
    console.log(`  curl -s ${gateway.endpoint} -H 'Content-Type: application/json' -d '{"message":"hello"}'`)

    await new Promise<void>((resolve) => {
      const shutdown = async () => {
        await gateway.close()
        resolve()
      }
      process.on('SIGINT', shutdown)
      process.on('SIGTERM', shutdown)
    })
  })

function parseAdapter(value: string): TargetAdapter {
  if (!adapters.includes(value as TargetAdapter)) {
    console.error(`Error: --adapter must be one of ${adapters.join(', ')}, got: "${value}"`)
    process.exit(1)
  }
  return value as TargetAdapter
}

function parsePositiveInt(value: string, name: string): number {
  const parsed = Number.parseInt(value, 10)
  if (!Number.isInteger(parsed) || parsed <= 0) {
    console.error(`Error: --${name} must be a positive integer, got: "${value}"`)
    process.exit(1)
  }
  return parsed
}

function parseNonNegativeInt(value: string, name: string): number {
  const parsed = Number.parseInt(value, 10)
  if (!Number.isInteger(parsed) || parsed < 0) {
    console.error(`Error: --${name} must be a non-negative integer, got: "${value}"`)
    process.exit(1)
  }
  return parsed
}
