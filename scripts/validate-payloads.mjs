// Validate all YAML payloads conform to the expected schema
// Usage: node scripts/validate-payloads.mjs

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import yaml from 'js-yaml'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PAYLOAD_DIR = path.resolve(__dirname, '..', 'payloads')

const VALID_CATEGORIES = [
  'ASI01-agent-goal-hijack',
  'ASI02-tool-abuse',
  'ASI03-permission-abuse',
  'ASI04-supply-chain',
  'ASI05-code-execution',
  'ASI07-system-prompt-leak',
  'ASI08-human-agent-trust',
]

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low']
const VALID_RULE_TYPES = ['contains_any', 'not_contains', 'regex', 'length_above']

let errors = 0
let total = 0

for (const category of fs.readdirSync(PAYLOAD_DIR)) {
  const catDir = path.join(PAYLOAD_DIR, category)
  if (!fs.statSync(catDir).isDirectory()) continue

  const files = fs.readdirSync(catDir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'))

  for (const file of files) {
    total++
    const filePath = path.join(catDir, file)
    const prefix = `${category}/${file}`

    try {
      const content = fs.readFileSync(filePath, 'utf-8')
      const p = yaml.load(content)

      const err = (msg) => { console.error(`  ERROR ${prefix}: ${msg}`); errors++ }

      if (!p.id) err('missing id')
      if (!p.info?.name) err('missing info.name')
      if (!p.info?.severity) err('missing info.severity')
      else if (!VALID_SEVERITIES.includes(p.info.severity)) err(`invalid severity: ${p.info.severity}`)
      if (!p.info?.category) err('missing info.category')
      else if (!VALID_CATEGORIES.includes(p.info.category)) err(`invalid category: ${p.info.category}`)
      if (!Array.isArray(p.info?.tags)) err('missing or invalid info.tags (must be array)')
      if (!p.attack?.type) err('missing attack.type')
      if (!p.attack?.payload) err('missing attack.payload')
      if (!Array.isArray(p.detect?.rules)) err('missing or invalid detect.rules (must be array)')
      else {
        for (let i = 0; i < p.detect.rules.length; i++) {
          const rule = p.detect.rules[i]
          if (!rule.type) err(`detect.rules[${i}]: missing type`)
          else if (!VALID_RULE_TYPES.includes(rule.type)) err(`detect.rules[${i}]: invalid type: ${rule.type}`)
          if (typeof rule.weight !== 'number') err(`detect.rules[${i}]: missing or invalid weight`)
        }
      }
      if (typeof p.detect?.threshold !== 'number' || p.detect.threshold <= 0) err('missing or invalid detect.threshold')

      // Filename should start with id
      if (!file.startsWith(p.id)) {
        err(`filename "${file}" does not start with id "${p.id}"`)
      }
    } catch (e) {
      console.error(`  ERROR ${prefix}: failed to parse: ${e.message}`)
      errors++
    }
  }
}

console.log(`\nValidated ${total} payloads, ${errors} error(s)`)

if (errors > 0) {
  process.exit(1)
} else {
  console.log('All payloads valid.')
}
