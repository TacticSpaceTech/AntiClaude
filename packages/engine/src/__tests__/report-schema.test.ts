import { describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { readScanReportJson } from '../compare'
import { validateScanReport } from '../report-schema'

const reportsDir = path.resolve(process.cwd(), '../../docs/examples/reports')

function readExampleReport(fileName: string): unknown {
  return JSON.parse(fs.readFileSync(path.join(reportsDir, fileName), 'utf-8'))
}

describe('validateScanReport', () => {
  it.each([
    'baseline-safe.json',
    'current-vulnerable.json',
    'error-report.json',
    'judge-unavailable.json',
  ])('accepts committed example report %s', fileName => {
    const validation = validateScanReport(readExampleReport(fileName))

    expect(validation.errors).toEqual([])
    expect(validation.valid).toBe(true)
  })

  it('rejects reports missing request evidence', () => {
    const report = readExampleReport('baseline-safe.json') as Record<string, unknown>
    const results = report.results as Array<Record<string, unknown>>
    delete results[0].request

    const validation = validateScanReport(report)

    expect(validation.valid).toBe(false)
    expect(validation.errors).toContain('results[0].request must be an object')
  })

  it('rejects invalid enum values', () => {
    const report = readExampleReport('baseline-safe.json') as Record<string, unknown>
    const results = report.results as Array<Record<string, unknown>>
    results[0].severity = 'severe'

    const validation = validateScanReport(report)

    expect(validation.valid).toBe(false)
    expect(validation.errors.some(error => error.includes('results[0].severity must be one of'))).toBe(true)
  })

  it('protects readScanReportJson with v1 validation', () => {
    const report = readExampleReport('baseline-safe.json') as Record<string, unknown>
    delete report.reproduction

    expect(() => readScanReportJson(JSON.stringify(report))).toThrow('Invalid AntiClaude report')
  })
})
