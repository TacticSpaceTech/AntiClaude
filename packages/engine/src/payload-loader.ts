import * as fs from 'fs'
import * as path from 'path'
import * as yaml from 'js-yaml'
import type { PayloadDefinition, OwaspCategory } from './types'

const PAYLOAD_DIR_NAME = 'payloads'

const OWASP_CATEGORIES: OwaspCategory[] = [
  'ASI01-agent-goal-hijack',
  'ASI02-tool-abuse',
  'ASI04-supply-chain',
  'ASI07-system-prompt-leak',
  'ASI08-human-agent-trust',
]

function findPayloadRoot(startDir?: string): string {
  let dir = startDir || process.cwd()
  for (let i = 0; i < 10; i++) {
    const candidate = path.join(dir, PAYLOAD_DIR_NAME)
    if (fs.existsSync(candidate)) return candidate
    const parent = path.dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  throw new Error(`Cannot find '${PAYLOAD_DIR_NAME}/' directory. Run from the AntiClaude project root.`)
}

export function loadPayloads(payloadDir?: string): PayloadDefinition[] {
  const root = payloadDir || findPayloadRoot()
  const payloads: PayloadDefinition[] = []

  for (const category of OWASP_CATEGORIES) {
    const categoryDir = path.join(root, category)
    if (!fs.existsSync(categoryDir)) continue

    const files = fs.readdirSync(categoryDir).filter((f: string) => f.endsWith('.yaml') || f.endsWith('.yml'))
    for (const file of files) {
      const content = fs.readFileSync(path.join(categoryDir, file), 'utf-8')
      const parsed = yaml.load(content) as PayloadDefinition
      if (parsed && parsed.id && parsed.info && parsed.attack) {
        payloads.push(parsed)
      }
    }
  }

  if (payloads.length === 0) {
    throw new Error(`No payloads found in '${root}'. Ensure YAML files exist in category subdirectories.`)
  }

  return payloads
}

export function loadPayloadsByCategory(category: OwaspCategory, payloadDir?: string): PayloadDefinition[] {
  return loadPayloads(payloadDir).filter(p => p.info.category === category)
}

function fisherYatesShuffle<T>(arr: T[]): T[] {
  const result = [...arr]
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[result[i], result[j]] = [result[j], result[i]]
  }
  return result
}

export function getRandomPayloads(payloads: PayloadDefinition[], count: number): PayloadDefinition[] {
  const shuffled = fisherYatesShuffle(payloads)
  return shuffled.slice(0, Math.min(count, shuffled.length))
}

export function loadPayloadsFromJson(manifest: PayloadDefinition[]): PayloadDefinition[] {
  return manifest.filter(p => p.id && p.info && p.attack)
}
