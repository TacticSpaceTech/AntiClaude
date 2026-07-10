import { describe, expect, it } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { compareReports, readScanReportJson } from '../compare'
import type { ScanReport, ScanResult } from '../types'

function result(id: string, leaked: boolean, confidence: number, error?: string): ScanResult {
  return {
    payloadId: id,
    payloadName: `Payload ${id}`,
    category: id.startsWith('spl') ? 'ASI07-system-prompt-leak' : 'ASI03-permission-abuse',
    owaspCategory: id.startsWith('spl') ? 'ASI07-system-prompt-leak' : 'ASI03-permission-abuse',
    severity: id.startsWith('spl') ? 'critical' : 'medium',
    prompt: 'test',
    request: {
      method: 'POST',
      url: 'http://127.0.0.1/test',
      adapter: 'generic-json',
      headers: { 'Content-Type': 'application/json' },
      body: { message: 'test' },
    },
    response: error ? '' : 'response',
    fullResponse: error ? '' : 'response',
    leaked,
    status: error ? 'error' : leaked ? 'breached' : 'blocked',
    confidence,
    confidenceSource: error ? 'none' : 'detector',
    indicators: leaked ? ['indicator'] : [],
    strategy: 'direct',
    generation: 1,
    requestDuration: 1,
    error,
  }
}

function report(id: string, score: number, results: ScanResult[]): ScanReport {
  return {
    reportVersion: 1,
    id,
    timestamp: '2026-05-09T00:00:00.000Z',
    targetEndpoint: 'http://127.0.0.1/test',
    target: {
      endpoint: 'http://127.0.0.1/test',
      adapter: 'generic-json',
      bodyField: 'message',
      hasAuthHeader: false,
      timeout: 1000,
      payloadCount: results.length,
      maxVariants: 0,
    },
    duration: 1,
    results,
    score,
    owaspCoverage: [
      {
        category: 'ASI07-system-prompt-leak',
        label: 'System Prompt Leakage',
        tested: 1,
        passed: results.some(r => r.payloadId === 'spl-001' && r.leaked) ? 0 : 1,
        failed: results.some(r => r.payloadId === 'spl-001' && r.leaked) ? 1 : 0,
        score: results.some(r => r.payloadId === 'spl-001' && r.leaked) ? 0 : 100,
      },
      {
        category: 'ASI03-permission-abuse',
        label: 'Permission Abuse & Escalation',
        tested: 1,
        passed: results.some(r => r.payloadId === 'pab-005' && r.leaked) ? 0 : 1,
        failed: results.some(r => r.payloadId === 'pab-005' && r.leaked) ? 1 : 0,
        score: results.some(r => r.payloadId === 'pab-005' && r.leaked) ? 0 : 100,
      },
    ],
    summary: {
      totalPayloads: results.length,
      totalAttempts: results.length,
      breaches: results.filter(r => r.leaked).length,
      blocked: results.filter(r => !r.leaked && !r.error).length,
      errors: results.filter(r => r.error).length,
    },
    reproduction: {
      command: 'anticlaude scan --endpoint http://127.0.0.1/test',
      config: {},
    },
  }
}

describe('compareReports', () => {
  it('detects breach, error, confidence, score, and category regressions', () => {
    const baseline = report('baseline', 95, [
      result('spl-001', false, 0),
      result('pab-005', true, 45),
      result('ta-001', false, 0, 'HTTP 500'),
    ])
    const current = report('current', 70, [
      result('spl-001', true, 75),
      result('pab-005', false, 10),
      result('ta-001', false, 0),
      result('pab-006', false, 0, 'HTTP 502'),
    ])

    const comparison = compareReports(baseline, current, {
      failOnScoreDrop: 10,
      failOnNewBreachSeverity: ['critical'],
      failOnNewError: true,
      failOnCategoryRegression: true,
    })

    expect(comparison.compareVersion).toBe(1)
    expect(comparison.scoreDelta).toBe(-25)
    expect(comparison.newBreaches.map(f => f.payloadId)).toEqual(['spl-001'])
    expect(comparison.fixedBreaches.map(f => f.payloadId)).toEqual(['pab-005'])
    expect(comparison.resolvedErrors.map(f => f.payloadId)).toEqual(['ta-001'])
    expect(comparison.newErrors.map(f => f.payloadId)).toEqual(['pab-006'])
    expect(comparison.changedConfidence.length).toBeGreaterThan(0)
    expect(comparison.categoryCoverageChanges.some(c => c.delta < 0)).toBe(true)
    expect(comparison.gates.failed).toBe(true)
    expect(comparison.gates.failures.length).toBeGreaterThanOrEqual(3)
  })

  it('rejects unsupported report versions', () => {
    expect(() => readScanReportJson(JSON.stringify({ reportVersion: 99, results: [], score: 100 }))).toThrow('Unsupported reportVersion')
  })

  it('compares committed example report fixtures', () => {
    const reportsDir = path.resolve(process.cwd(), '../../docs/examples/reports')
    const baseline = readScanReportJson(fs.readFileSync(path.join(reportsDir, 'baseline-safe.json'), 'utf-8'))
    const current = readScanReportJson(fs.readFileSync(path.join(reportsDir, 'current-vulnerable.json'), 'utf-8'))

    const comparison = compareReports(baseline, current, {
      failOnNewBreachSeverity: ['critical'],
      failOnCategoryRegression: true,
    })

    expect(comparison.newBreaches.map(f => f.payloadId)).toEqual(['spl-001'])
    expect(comparison.categoryCoverageChanges[0].delta).toBeLessThan(0)
    expect(comparison.gates.failed).toBe(true)
  })
})
