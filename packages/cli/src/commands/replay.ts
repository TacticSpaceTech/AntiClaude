import { Command } from 'commander'
import { readTraceFile, traceSummaryToMarkdown } from '@anticlaude/engine'

export const replayCommand = new Command('replay')
  .description('Replay a local AntiClaude JSONL trace file')
  .argument('<trace-file>', 'Trace JSONL or JSON file')
  .option('--output <format>', 'Output format: markdown, json', 'markdown')
  .action((traceFile: string, opts) => {
    const events = readTraceFile(traceFile)
    if (opts.output === 'json') {
      console.log(JSON.stringify({
        traceVersion: 1,
        events,
        eventCount: events.length,
        requestIds: Array.from(new Set(events.map(event => event.requestId))),
      }, null, 2))
      return
    }

    console.log(traceSummaryToMarkdown(events))
  })
