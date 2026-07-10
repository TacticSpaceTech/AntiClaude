# Human Review Workflow

Human review is local JSONL storage for decisions that should not execute automatically.

## Create Reviews

When `guard` is started with `--review-store`, runtime `review` decisions are persisted:

```bash
node packages/cli/dist/index.js guard \
  --target http://127.0.0.1:4100/chat \
  --review-store /tmp/anticlaude-reviews.jsonl \
  --trace /tmp/anticlaude-runtime.jsonl
```

Review responses return HTTP `202` with a `reviewId`.

## Inspect And Decide

```bash
node packages/cli/dist/index.js review list --store /tmp/anticlaude-reviews.jsonl
node packages/cli/dist/index.js review show review_id --store /tmp/anticlaude-reviews.jsonl
node packages/cli/dist/index.js review approve review_id --store /tmp/anticlaude-reviews.jsonl --reason "Verified request and destination"
node packages/cli/dist/index.js review deny review_id --store /tmp/anticlaude-reviews.jsonl --reason "Destination not authorized"
```

Approve and deny require a reason. A decided request cannot be decided again.

## Stored Fields

Each review stores review id, request id, trace id, agent id, tool call, runtime policy decision, evidence, status, timestamps, and optional reviewer decision.

