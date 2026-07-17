#!/usr/bin/env node
/**
 * Release hygiene: pack engine + CLI and assert npm tarball contents.
 * Run after `pnpm run build:packages`.
 */
import { execSync } from 'node:child_process'
import { existsSync, readdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'

const root = join(import.meta.dirname, '..')

function assert(condition, message) {
  if (!condition) {
    console.error(`pack-check failed: ${message}`)
    process.exit(1)
  }
}

function packPackage(dir) {
  // Remove stale packs so we always inspect the fresh tarball
  for (const f of readdirSync(dir)) {
    if (f.endsWith('.tgz')) rmSync(join(dir, f), { force: true })
  }

  const out = execSync('pnpm pack --pack-destination .', {
    cwd: dir,
    encoding: 'utf8',
  })
  const listed = readdirSync(dir).filter((f) => f.endsWith('.tgz'))
  assert(listed.length === 1, `expected one .tgz in ${dir} after pack, got: ${listed.join(', ') || '(none)'}\n${out}`)
  return join(dir, listed[0])
}

function listTarball(tgz) {
  const out = execSync(`tar -tzf ${JSON.stringify(tgz)}`, { encoding: 'utf8' })
  return out.split('\n').filter(Boolean)
}

function readPackedPackageJson(tgz) {
  const out = execSync(`tar -xOf ${JSON.stringify(tgz)} package/package.json`, {
    encoding: 'utf8',
  })
  return JSON.parse(out)
}

const engineDir = join(root, 'packages/engine')
const cliDir = join(root, 'packages/cli')

assert(existsSync(join(engineDir, 'dist/index.js')), 'engine dist missing; run build:packages first')
assert(existsSync(join(cliDir, 'dist/index.js')), 'cli dist missing; run build:packages first')
assert(
  !existsSync(join(engineDir, 'dist/__tests__')),
  'engine dist still contains __tests__; exclude tests from tsconfig and rebuild'
)

console.log('Packing @anticlaude/engine...')
const engineTgz = packPackage(engineDir)
const engineFiles = listTarball(engineTgz)
assert(!engineFiles.some((f) => f.includes('__tests__')), 'engine tarball must not include __tests__')
assert(engineFiles.some((f) => f === 'package/dist/index.js'), 'engine tarball missing dist/index.js')
assert(engineFiles.some((f) => f === 'package/dist/payloads.json'), 'engine tarball missing payloads.json')
assert(engineFiles.some((f) => f === 'package/LICENSE'), 'engine tarball missing LICENSE')

const enginePkg = readPackedPackageJson(engineTgz)
assert(enginePkg.version === '1.1.0', `engine version expected 1.1.0, got ${enginePkg.version}`)
assert(enginePkg.exports?.['.'], 'engine package.json missing exports["."]')

console.log('Packing anticlaude CLI...')
const cliTgz = packPackage(cliDir)
const cliFiles = listTarball(cliTgz)
assert(cliFiles.some((f) => f === 'package/dist/index.js'), 'cli tarball missing dist/index.js')
assert(
  cliFiles.some((f) => f === 'package/examples/suites/smoke.json'),
  'cli tarball missing examples/suites/smoke.json'
)
assert(
  cliFiles.some((f) => f === 'package/examples/policies/default.policy.yaml'),
  'cli tarball missing examples/policies/default.policy.yaml'
)
assert(cliFiles.some((f) => f === 'package/LICENSE'), 'cli tarball missing LICENSE')

const cliPkg = readPackedPackageJson(cliTgz)
assert(cliPkg.version === '1.1.0', `cli version expected 1.1.0, got ${cliPkg.version}`)
assert(
  cliPkg.dependencies?.['@anticlaude/engine'] === '1.1.0',
  `cli must rewrite workspace:* to 1.1.0 on pack, got ${cliPkg.dependencies?.['@anticlaude/engine']}`
)
assert(!String(cliPkg.dependencies?.['@anticlaude/engine'] || '').includes('workspace'), 'cli still has workspace protocol')

// cleanup tarballs from package dirs
rmSync(engineTgz, { force: true })
rmSync(cliTgz, { force: true })

console.log('pack-check passed')
