# AntiClaude Agent AI Product Upgrade Plan

Status note: this document is a forward-looking product plan. The currently shipped product is a local-first eval/audit/runtime-control beta made of the web scanner, `/control-plane` example inspection view, `@anticlaude/engine`, `anticlaude` CLI, payload library, deterministic eval suites, report comparison, MCP/skill auditors, GitHub Action gates, local Guard SDK/gateway, support-agent runtime policy, local review queue, local incident index, and JSONL audit replay. Hosted dashboards, billing, production runtime firewall deployment, and SOC 2/GDPR readiness are not shipped capabilities in the current repo.

## 1. Strategic Shift

Current state:
- The product behaves like an AI security demo and prompt-attack scanner.
- The strongest part is the attack experience and report presentation.
- The weakest part is product trust: simulated results, weak control-plane capability, and limited agent-era coverage.

Target state:
- Upgrade AntiClaude from a "scanner" into an "agent runtime security layer".
- Move from finding prompt leaks to controlling agent behavior, tool usage, data egress, and auditability.

New product definition:
- AntiClaude is a security control plane for tool-using AI agents.
- It helps teams evaluate, enforce, and audit agent behavior before and during production.

## 2. Product Thesis

The next wave of AI risk is not only model jailbreak.

The real enterprise problem is:
- Agents can call tools.
- Agents can access data.
- Agents can take actions.
- Teams need policy, approval, boundaries, and evidence.

So the product should focus on three layers:
- Eval: Can this agent be broken?
- Guard: Can this agent be stopped in runtime?
- Audit: Can the team explain what happened after an incident?

## 3. ICP and Entry Point

Ideal customer profile:
- Startups and mid-market teams building internal or external agents
- Agents connected to CRM, ticketing, docs, email, Slack, SQL, browser, or workflow tools
- Teams without a dedicated AI security engineer

Initial buyer:
- Founding engineer
- AI platform lead
- Security-minded CTO

Best initial use cases:
- Customer support agent
- Internal knowledge agent with tool access
- Ops agent that can send messages, query systems, or update records

## 4. Version 1 Product Scope

### Core modules

1. Eval Engine
- Run repeatable adversarial tests against agent endpoints
- Produce evidence-based findings, not simulated findings
- Support baseline comparisons across versions

2. Runtime Gateway
- Proxy requests between app and model/tool layers
- Score risk on prompt, tool call, and output
- Block or require approval for risky actions

3. Tool Governance
- Per-agent and per-tool policy controls
- Allow/deny/confirm modes
- Read-only vs write access boundaries

4. Audit and Replay
- Full trace of prompt, context summary, tool call, decision, and policy hit
- Incident replay for debugging and compliance review

### Explicitly out of scope for V1

- Full SOC 2 / GDPR positioning
- Broad multi-cloud enterprise platform claims
- Fine-tuned model security
- Browser agent hardening across every environment
- Autonomous remediation

## 5. Product Architecture Direction

### Control points

1. Pre-model input
- Detect prompt injection intent
- Detect role confusion and hidden instructions
- Normalize risky formatting patterns

2. Pre-tool execution
- Inspect requested tool name, arguments, destination, and risk level
- Enforce policy before the tool runs

3. Post-tool / pre-output
- Check for sensitive data leakage
- Check for untrusted output being returned to user or downstream systems

4. Audit layer
- Record what policy fired
- Record why the action was allowed, blocked, or escalated

### First integrations

- OpenAI-compatible chat endpoint
- Anthropic-compatible endpoint
- Generic HTTP tool
- Read-only SQL tool
- Slack or email action tool as a high-risk example

## 6. 90-Day Upgrade Roadmap

### Phase 0: Trust Reset (Week 1-2)

Goal:
- Stop presenting demo behavior as production security.

Deliverables:
- Remove simulated findings from real scan mode
- Add explicit demo mode vs real mode separation
- Add auth, rate limit, and outbound target restrictions
- Block private-network and localhost scanning
- Rewrite landing page claims to match actual capability

Success criteria:
- No false-positive "vulnerability found" result generated from fallback simulation
- Public deployment has basic abuse protection
- Product messaging becomes defensible

### Phase 1: Credible Eval Product (Week 3-6)

Goal:
- Ship a trustworthy red-team evaluator.

Deliverables:
- Provider adapters for OpenAI-compatible and Anthropic-compatible APIs
- Deterministic test suite with labeled payload families
- Evidence-first reporting with raw request/response trace
- Baseline comparison between scans
- CI entrypoint for pre-release evaluation

Success criteria:
- Teams can run the same suite twice and compare drift
- Findings include enough evidence to debug and reproduce

### Phase 2: Runtime Guard MVP (Week 7-10)

Goal:
- Move from detection to prevention.

Deliverables:
- Runtime gateway service
- Policy engine with `allow`, `block`, `review`
- Tool risk classification
- Sensitive data egress checks
- Manual approval flow for high-risk tool actions

Success criteria:
- At least one risky tool action can be blocked in real time
- At least one sensitive-output event can be intercepted before response delivery

### Phase 3: Beta Control Plane (Week 11-12)

Goal:
- Make the product usable by design partners.

Deliverables:
- Dashboard for incidents, traces, and policy hits
- Agent inventory and tool inventory views
- Basic policy templates by use case
- Onboarding flow for design partners

Success criteria:
- 3 to 5 beta teams can onboard without founder-only handholding

## 7. Week 1 Execution Plan

### Product

- Rewrite positioning from "LLM pentest platform" to "agent security control plane"
- Define one wedge use case: tool-using support agent
- Define one killer workflow: block unsafe tool execution with evidence

### Engineering

- Split demo scan and real scan paths
- Fail closed on network or provider errors
- Add outbound request validation and denylist/allowlist model
- Add basic API authentication for scanner access
- Add scan job logging with explicit `simulated=false/true`

### Design

- Replace "security score theater" with evidence-driven states
- Show "blocked action", "policy match", and "needs review" as core UX concepts
- Demote OWASP-style compliance framing in MVP

### GTM

- Build a 10-customer design partner list
- Target teams already shipping agents with tool access
- Prepare one live demo based on a support or ops agent

## 8. Key Metrics

### Product metrics

- Number of connected agents
- Number of protected tool actions
- Number of blocked or reviewed risky actions
- Time to investigate an incident

### Commercial metrics

- Design partner conversion rate
- Weekly active protected agents
- Expansion from eval-only to runtime-guard customers

### Quality metrics

- False positive rate on policy blocks
- False negative rate from red-team regression set
- Trace completeness rate

## 9. Risks

- Overbuilding the scanner and never reaching runtime control
- Overclaiming compliance before controls exist
- Supporting too many model and framework variants too early
- Building a dashboard product before policy enforcement is useful

## 10. Recommended Positioning Statement

Future positioning after the runtime layers are implemented: AntiClaude helps teams secure tool-using AI agents by combining adversarial evaluation, runtime policy enforcement, and full audit trails.

Short version:
- Find risky behavior before launch
- Block dangerous actions in production
- Prove what happened when something goes wrong

## 11. Immediate Next Documents

After this plan, create:
- `docs/agent-prd-v1.md`
- `docs/runtime-policy-model.md`
- `docs/design-partner-outreach.md`

## 12. First Principle

Do not try to prove that the agent is "safe".

Prove instead that:
- risky behavior can be observed,
- high-risk actions can be controlled,
- incidents can be explained,
- and defenses improve over time.
