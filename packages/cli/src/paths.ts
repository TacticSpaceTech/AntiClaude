import { existsSync } from 'node:fs'
import { join } from 'node:path'

/** Package root (packages/cli), whether running from src or dist. */
export function packageRoot(): string {
  // dist/index.js or dist/commands/*.js → packages/cli
  return join(__dirname, '..')
}

/**
 * Resolve a suite path for `scan --suite`.
 * Accepts a filesystem path, or a built-in name (`smoke`, `builtin:smoke`).
 */
export function resolveSuitePath(input: string): string {
  if (existsSync(input)) return input

  const name = input.replace(/^builtin:/, '').replace(/\.json$/i, '')
  const candidates = [
    join(packageRoot(), 'examples', 'suites', `${name}.json`),
    join(packageRoot(), 'examples', 'suites', name),
  ]

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }

  throw new Error(
    `Suite not found: "${input}". Use a file path or a built-in suite name (e.g. smoke).`
  )
}

/**
 * Resolve a guard policy path.
 * Accepts a filesystem path, or a built-in name (`default`, `builtin:default`).
 */
export function resolvePolicyPath(input: string): string {
  if (existsSync(input)) return input

  const name = input.replace(/^builtin:/, '').replace(/\.ya?ml$/i, '')
  const candidates = [
    join(packageRoot(), 'examples', 'policies', `${name}.policy.yaml`),
    join(packageRoot(), 'examples', 'policies', `${name}.yaml`),
    join(packageRoot(), 'examples', 'policies', name),
  ]

  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }

  throw new Error(
    `Policy not found: "${input}". Use a file path or a built-in policy name (e.g. default).`
  )
}
