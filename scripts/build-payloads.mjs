// Build script: converts YAML payloads to a single JSON manifest for browser usage
// Usage: node scripts/build-payloads.mjs

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import yaml from 'js-yaml'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PAYLOAD_DIR = path.resolve(__dirname, '..', 'payloads')
const OUTPUT_FILE = path.resolve(__dirname, '..', 'packages', 'engine', 'src', 'payloads.json')

const CATEGORIES = [
  'ASI01-agent-goal-hijack',
  'ASI02-tool-abuse',
  'ASI03-permission-abuse',
  'ASI04-supply-chain',
  'ASI05-code-execution',
  'ASI07-system-prompt-leak',
  'ASI08-human-agent-trust',
]

const payloads = []

for (const category of CATEGORIES) {
  const dir = path.join(PAYLOAD_DIR, category)
  if (!fs.existsSync(dir)) continue

  const files = fs.readdirSync(dir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'))
  for (const file of files) {
    const content = fs.readFileSync(path.join(dir, file), 'utf-8')
    const parsed = yaml.load(content)
    if (parsed && parsed.id) {
      payloads.push(parsed)
    }
  }
}

fs.writeFileSync(OUTPUT_FILE, JSON.stringify(payloads, null, 2), 'utf-8')
console.log(`Built ${payloads.length} payloads → ${OUTPUT_FILE}`)
