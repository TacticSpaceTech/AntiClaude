import { Command } from 'commander'
import chalk from 'chalk'
import {
  decideReviewRequest,
  getReviewRequest,
  listReviewRequests,
  type ReviewRequest,
  type ReviewStatus,
} from '@anticlaude/engine'

const statuses: ReviewStatus[] = ['pending', 'approved', 'denied', 'expired']
const defaultStore = 'reviews/anticlaude-reviews.jsonl'

export const reviewCommand = new Command('review')
  .description('Inspect and decide local AntiClaude runtime review requests')

reviewCommand
  .command('list')
  .description('List review requests from a local JSONL review store')
  .option('--store <file>', 'Review store JSONL or JSON file', defaultStore)
  .option('--status <status>', 'Filter by status: pending, approved, denied, expired')
  .option('--output <format>', 'Output format: text, json', 'text')
  .action((opts) => {
    const status = opts.status ? parseStatus(opts.status) : undefined
    const reviews = listReviewRequests(opts.store, status)
    if (opts.output === 'json') {
      console.log(JSON.stringify({ reviewVersion: 1, count: reviews.length, reviews }, null, 2))
      return
    }
    printReviewTable(reviews)
  })

reviewCommand
  .command('show')
  .description('Show one review request')
  .argument('<review-id>', 'Review request id')
  .option('--store <file>', 'Review store JSONL or JSON file', defaultStore)
  .option('--output <format>', 'Output format: text, json', 'text')
  .action((reviewId: string, opts) => {
    const review = getReviewRequest(opts.store, reviewId)
    if (opts.output === 'json') {
      console.log(JSON.stringify(review, null, 2))
      return
    }
    printReviewDetail(review)
  })

reviewCommand
  .command('approve')
  .description('Approve a pending review request with an audit reason')
  .argument('<review-id>', 'Review request id')
  .option('--store <file>', 'Review store JSONL or JSON file', defaultStore)
  .option('--reviewer <name>', 'Reviewer name', 'local-operator')
  .requiredOption('--reason <text>', 'Required approval reason')
  .action((reviewId: string, opts) => {
    const review = decideReviewRequest(opts.store, reviewId, {
      status: 'approved',
      reviewer: opts.reviewer,
      reason: opts.reason,
    })
    console.log(chalk.green(`Approved ${review.id}`))
    console.log(chalk.dim(`${review.policyDecision.policyId} ${review.toolCall.name}`))
  })

reviewCommand
  .command('deny')
  .description('Deny a pending review request with an audit reason')
  .argument('<review-id>', 'Review request id')
  .option('--store <file>', 'Review store JSONL or JSON file', defaultStore)
  .option('--reviewer <name>', 'Reviewer name', 'local-operator')
  .requiredOption('--reason <text>', 'Required denial reason')
  .action((reviewId: string, opts) => {
    const review = decideReviewRequest(opts.store, reviewId, {
      status: 'denied',
      reviewer: opts.reviewer,
      reason: opts.reason,
    })
    console.log(chalk.red(`Denied ${review.id}`))
    console.log(chalk.dim(`${review.policyDecision.policyId} ${review.toolCall.name}`))
  })

function parseStatus(value: string): ReviewStatus {
  if (!statuses.includes(value as ReviewStatus)) {
    console.error(`Error: --status must be one of ${statuses.join(', ')}, got: "${value}"`)
    process.exit(1)
  }
  return value as ReviewStatus
}

function printReviewTable(reviews: ReviewRequest[]): void {
  if (reviews.length === 0) {
    console.log(chalk.dim('No review requests found.'))
    return
  }

  for (const review of reviews) {
    const action = review.policyDecision.action.toUpperCase()
    const risk = review.policyDecision.riskLevel
    console.log(`${statusColor(review.status)(review.status.padEnd(8))} ${review.id}`)
    console.log(chalk.dim(`  ${action} ${risk} ${review.agentId}.${review.toolCall.name}`))
    console.log(chalk.dim(`  ${review.policyDecision.policyId}`))
    console.log(`  ${review.policyDecision.reason}`)
  }
}

function printReviewDetail(review: ReviewRequest): void {
  console.log(`${statusColor(review.status)(review.status.toUpperCase())} ${review.id}`)
  console.log(chalk.dim(`Request: ${review.requestId}`))
  console.log(chalk.dim(`Trace: ${review.traceId}`))
  console.log(chalk.dim(`Agent: ${review.agentId}`))
  console.log(chalk.dim(`Policy: ${review.policyDecision.policyId}`))
  console.log(chalk.dim(`Tool: ${review.toolCall.name}`))
  console.log('')
  console.log(review.policyDecision.reason)
  console.log('')
  console.log(JSON.stringify({
    arguments: review.toolCall.arguments,
    evidence: review.evidence,
    recommendedAction: review.policyDecision.recommendedAction,
    decision: review.decision,
  }, null, 2))
}

function statusColor(status: ReviewStatus): (value: string) => string {
  if (status === 'approved') return chalk.green
  if (status === 'denied') return chalk.red
  if (status === 'expired') return chalk.yellow
  return chalk.cyan
}
