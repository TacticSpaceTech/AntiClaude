# Target Adapters

AntiClaude supports four request adapters for scan and guard workflows.

## `generic-json`

Sends a JSON object with one prompt field.

```json
{ "message": "attack prompt" }
```

Options:

- `--body-field message`
- `authHeader`

## `openai-chat`

Sends an OpenAI-compatible chat request.

```json
{
  "model": "optional-model",
  "messages": [{ "role": "user", "content": "attack prompt" }]
}
```

Options:

- `--target-model`
- `authHeader`

## `anthropic-messages`

Sends an Anthropic-compatible messages request.

```json
{
  "model": "optional-model",
  "max_tokens": 1024,
  "messages": [{ "role": "user", "content": "attack prompt" }]
}
```

Options:

- `--target-model`
- `--max-tokens`
- `authHeader`

## `custom-json`

Renders a custom JSON template.

```bash
--body-template '{"input":{{promptJson}},"mode":"test"}'
```

Use `{{prompt}}` inside JSON strings and `{{promptJson}}` where a JSON string value should be inserted safely.

## Evidence And Redaction

Reports include request evidence with method, URL, adapter, redacted headers, and body. Authorization, token, API key, and secret-bearing headers are redacted.
