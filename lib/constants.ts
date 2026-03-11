// OWASP Agentic category → legacy frontend category key
export const categoryMap: Record<string, string> = {
  'ASI07-system-prompt-leak': 'system_prompt_leak',
  'ASI01-agent-goal-hijack': 'jailbreak',
  'ASI02-tool-abuse': 'format_injection',
  'ASI04-supply-chain': 'supply_chain',
  'ASI08-human-agent-trust': 'trust_manipulation',
}

// OWASP Agentic category → human-readable label
export const categoryLabelMap: Record<string, string> = {
  'ASI07-system-prompt-leak': 'System Prompt Leak',
  'ASI01-agent-goal-hijack': 'Agent Goal Hijack',
  'ASI02-tool-abuse': 'Tool Abuse',
  'ASI04-supply-chain': 'Supply Chain',
  'ASI08-human-agent-trust': 'Trust Manipulation',
}

// Unbiased Fisher-Yates shuffle — returns a new array
export function fisherYatesShuffle<T>(arr: T[]): T[] {
  const result = [...arr]
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1))
    ;[result[i], result[j]] = [result[j], result[i]]
  }
  return result
}
