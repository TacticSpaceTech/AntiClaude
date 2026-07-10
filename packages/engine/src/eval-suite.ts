import * as fs from 'fs'
import type { EvalSuiteConfig, EvalSuiteMetadata, PayloadDefinition } from './types'

export function loadEvalSuite(filePath: string): EvalSuiteConfig {
  const raw = fs.readFileSync(filePath, 'utf-8')
  const parsed = JSON.parse(raw) as EvalSuiteConfig
  validateEvalSuite(parsed)
  return parsed
}

export function validateEvalSuite(suite: EvalSuiteConfig): void {
  if (suite.count !== undefined && (!Number.isInteger(suite.count) || suite.count <= 0)) {
    throw new Error('suite.count must be a positive integer')
  }
  if (suite.maxVariants !== undefined && (!Number.isInteger(suite.maxVariants) || suite.maxVariants < 0)) {
    throw new Error('suite.maxVariants must be a non-negative integer')
  }
  for (const [field, value] of Object.entries({
    categories: suite.categories,
    severities: suite.severities,
    tags: suite.tags,
    payloadIds: suite.payloadIds,
  })) {
    if (value !== undefined && !Array.isArray(value)) {
      throw new Error(`suite.${field} must be an array`)
    }
  }
}

export function suiteMetadata(suite?: EvalSuiteConfig): EvalSuiteMetadata | undefined {
  if (!suite) return undefined
  return {
    name: suite.name,
    description: suite.description,
    seed: suite.seed,
    count: suite.count,
    categories: suite.categories,
    severities: suite.severities,
    tags: suite.tags,
    payloadIds: suite.payloadIds,
  }
}

export function selectPayloadsForSuite(
  payloads: PayloadDefinition[],
  suite: EvalSuiteConfig | undefined,
  fallbackCount: number
): PayloadDefinition[] {
  if (!suite) return seededShuffle(payloads).slice(0, Math.min(fallbackCount, payloads.length))

  let selected = payloads
  if (suite.payloadIds?.length) {
    const idSet = new Set(suite.payloadIds)
    selected = selected.filter(payload => idSet.has(payload.id))
  }
  if (suite.categories?.length) {
    const categorySet = new Set(suite.categories)
    selected = selected.filter(payload => categorySet.has(payload.info.category))
  }
  if (suite.severities?.length) {
    const severitySet = new Set(suite.severities)
    selected = selected.filter(payload => severitySet.has(payload.info.severity))
  }
  if (suite.tags?.length) {
    const tagSet = new Set(suite.tags)
    selected = selected.filter(payload => payload.info.tags.some(tag => tagSet.has(tag)))
  }

  if (suite.seed !== undefined) {
    selected = seededShuffle(selected, String(suite.seed))
  }

  const count = suite.count ?? fallbackCount
  return selected.slice(0, Math.min(count, selected.length))
}

export function seededShuffle<T>(items: T[], seed = 'anticlaude-default-seed'): T[] {
  const result = [...items]
  let state = hashSeed(seed)
  for (let i = result.length - 1; i > 0; i--) {
    state = nextState(state)
    const j = state % (i + 1)
    ;[result[i], result[j]] = [result[j], result[i]]
  }
  return result
}

function hashSeed(seed: string): number {
  let hash = 2166136261
  for (let i = 0; i < seed.length; i++) {
    hash ^= seed.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return hash >>> 0
}

function nextState(state: number): number {
  return (Math.imul(state, 1664525) + 1013904223) >>> 0
}
