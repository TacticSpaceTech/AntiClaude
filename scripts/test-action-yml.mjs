import fs from 'node:fs'
import yaml from 'js-yaml'

const text = fs.readFileSync('action/action.yml', 'utf8')
const action = yaml.load(text)
const steps = action.runs.steps

function assert(condition, message) {
  if (!condition) {
    console.error(`Action test failed: ${message}`)
    process.exit(1)
  }
}

const runScan = steps.find(step => step.name === 'Run scan')
const parseResults = steps.find(step => step.name === 'Parse results')
const compare = steps.find(step => step.name === 'Run compare gates')
const prComment = steps.find(step => step.name === 'Post PR comment')
const compareThreshold = steps.find(step => step.name === 'Check compare gates')
const threshold = steps.find(step => step.name === 'Check threshold')

assert(runScan, 'Run scan step exists')
assert(parseResults, 'Parse results step exists')
assert(compare, 'Run compare gates step exists')
assert(prComment, 'Post PR comment step exists')
assert(compareThreshold, 'Check compare gates step exists')
assert(threshold, 'Check threshold step exists')

assert(runScan.run.includes('args=('), 'Run scan uses a bash argv array')
assert(runScan.run.includes('"${args[@]}"'), 'Run scan invokes CLI with quoted argv array')
assert(!runScan.run.includes('ARGS='), 'Run scan does not build a string command')
assert(!runScan.run.includes('|| true'), 'Run scan does not hide failures with || true')
assert(runScan.run.includes('scan_status=${PIPESTATUS[0]}'), 'Run scan records CLI pipe status')
assert(runScan.run.includes('--suite "${INPUT_SUITE}"'), 'Run scan passes suite input through quoted argv array')

assert(parseResults.run.includes('ANTICLAUDE_SUMMARY='), 'Parse results reads stable summary line')
assert(parseResults.run.includes('errors'), 'Parse results exposes error count')

assert(compare.run.includes('args=('), 'Run compare gates uses a bash argv array')
assert(compare.run.includes('"${args[@]}"'), 'Run compare gates invokes CLI with quoted argv array')
assert(compare.run.includes('compare_status=${PIPESTATUS[0]}'), 'Run compare gates records CLI pipe status')
assert(compare.run.includes('baseline-report requires output-format=json'), 'Run compare gates documents JSON report requirement')
assert(compare.run.includes('--fail-on-score-drop "${INPUT_FAIL_ON_SCORE_DROP}"'), 'Run compare gates passes score drop threshold safely')
assert(compare.run.includes('--fail-on-new-severity "${INPUT_FAIL_ON_NEW_SEVERITY}"'), 'Run compare gates passes severity threshold safely')
assert(compare.run.includes('--fail-on-new-error'), 'Run compare gates supports new error gate')
assert(compare.run.includes('--fail-on-category-regression'), 'Run compare gates supports category regression gate')

assert(prComment.run.includes('--body-file'), 'PR comment uses --body-file instead of interpolated --body')
assert(!prComment.run.includes('--body "${BODY}"'), 'PR comment does not pass interpolated body text')
assert(prComment.run.includes('Compare Report'), 'PR comment includes compare report when present')

assert(compareThreshold.run.includes('[[ "${COMPARE_EXIT_CODE}" =~ ^[0-9]+$ ]]'), 'Compare threshold validates compare exit code as numeric')
assert(compareThreshold.run.includes('(( COMPARE_EXIT_CODE != 0 ))'), 'Compare threshold fails deterministic compare gate failures')

assert(threshold.run.includes('[[ "${SCORE}" =~ ^[0-9]+$ ]]'), 'Threshold validates score as numeric')
assert(threshold.run.includes('(( SCORE < THRESHOLD ))'), 'Threshold uses deterministic arithmetic comparison')

for (const output of ['score', 'breaches', 'errors', 'report-path', 'compare-path']) {
  assert(action.outputs[output], `Output ${output} is declared`)
}

for (const input of ['suite', 'baseline-report', 'fail-on-score-drop', 'fail-on-new-severity', 'fail-on-new-error', 'fail-on-category-regression']) {
  assert(action.inputs[input], `Input ${input} is declared`)
}

console.log('Action YAML safety checks passed')
