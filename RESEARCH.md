# AI Agent 安全产品深度调研报告

> 调研日期: 2026-03-11 | 重点：产品形态、技术实现、开发者体验

---

## Executive Summary

AI Agent 安全领域正经历剧烈整合。2026年3月，**Promptfoo 被 OpenAI 收购**，加上此前 Robust Intelligence→Cisco、Protect AI→Palo Alto、Invariant Labs→Snyk、CalypsoAI→F5、Aim Security→Cato 的收购潮，独立的开发者安全工具正在快速减少。

当前产品格局可分为三个层次：
1. **企业级运行时防护平台**（Lakera、Pillar、Straiker、Lasso）
2. **开源 CLI 扫描/红队工具**（Promptfoo、Garak、Agentic Radar、AgentFence、AI-Infra-Guard）
3. **专项扫描工具**（Snyk Agent-Scan、MCP-Scan）

**关键发现：Snyk Agent-Scan 已经在做"Skill 安全扫描"，且发现 36% 的 Agent Skills 存在安全缺陷。这是我们最直接的竞品/参照物。**

---

## Part 1: 产品形态详细分析

### 1.1 Promptfoo — 开源 LLM 红队测试 CLI（被 OpenAI 收购）

**产品形态：CLI + YAML 配置 + Web 报告界面**

- 安装：`npm install -g promptfoo` / `brew install promptfoo` / `pip install promptfoo`
- 核心流程：
  1. `npx promptfoo@latest redteam init my-project --no-gui` 初始化项目
  2. 编辑 `promptfooconfig.yaml` 定义目标、攻击插件、策略
  3. `promptfoo redteam run` 执行攻击
  4. `promptfoo redteam report` 查看 Web 报告界面

- **YAML 配置示例**（MCP Agent 红队测试）：
  ```yaml
  providers:
    - id: anthropic:claude-opus-4-1-20250805
      config:
        mcp:
          enabled: true
          servers:
            - name: docker-mcp-toolkit
              command: docker
              args: ['mcp', 'gateway', 'run']
  ```
- **攻击插件**：支持 OWASP LLM Top 10 预设（`owasp:llm`），MCP 专用插件测试 tool calling 劫持
- **检测策略**：basic、best-of-n、jailbreak 等
- **商业模式**：MIT 开源，Community 版免费 10K probes/月，Enterprise 版联系销售
- **关键数据**：Fortune 500 中 127 家使用；GitHub 星标数千
- **最新动态**：2026年3月9日被 OpenAI 收购，将集成到 OpenAI Frontier 平台，开源版本承诺继续维护

**启示：**
- YAML 配置 + CLI 是开发者最接受的模式
- 插件化架构允许社区扩展攻击向量
- 被收购说明这个赛道有价值，但也意味着 Promptfoo 未来可能偏向 OpenAI 生态

---

### 1.2 Lakera Guard — LLM 防火墙 API

**产品形态：SaaS API + 控制台**

- 核心是一个 REST API，在应用和 LLM 之间做请求/响应拦截
- **集成代码**：
  ```python
  response = requests.post(
    "https://api.lakera.ai/v2/guard",
    json={"input": user_prompt},
    headers={"Authorization": f"Bearer {LAKERA_API_KEY}"}
  )
  if response.json()["results"][0]["flagged"]:
      # 拦截危险输入
  ```
- **检测能力**：prompt injection（直接+间接）、PII 泄露、有毒内容、恶意 URL、越狱
- **Agent 安全覆盖**：
  - 间接 prompt injection（扫描获取的 URL、附件、HTML、PDF 中的隐藏指令）
  - 工具调用拦截（检查 tool call 输入和返回内容）
  - 恶意链接检测

- **定价**：
  - Community：免费，10,000 请求/月，8K token/请求
  - Pro：联系销售
  - Enterprise：自定义（无限请求、私有部署、自定义模型）

- **差异化**：Gandalf 公开对抗游戏每天产生 10万+ 新攻击向量，持续更新威胁情报

**启示：**
- API 防火墙模式 = 运行时防护，和我们"开发时测试"的定位不冲突
- 免费 10K 请求/月是很好的 PLG 策略
- Gandalf 游戏化威胁情报收集是天才设计

---

### 1.3 Snyk Agent-Scan — Agent/Skill 安全扫描器 ⚠️ 最直接竞品

**产品形态：CLI 扫描器，扫描本地 Agent 配置**

- 继承自 Invariant Labs 的 MCP-Scan，Snyk 收购后扩展为 Agent-Scan
- **安装**：`uvx snyk-agent-scan@latest`
- **核心命令**：
  - `snyk-agent-scan` — 自动发现并扫描所有已知 MCP 配置
  - `snyk-agent-scan ~/custom/config.json` — 扫描指定配置文件
  - `uvx snyk-agent-scan@latest --skills ~/.claude/skills` — **扫描所有 Claude Skills**
- **自动发现平台**：Claude Code/Desktop、Cursor、Gemini CLI、Windsurf
- **检测 15+ 安全风险**：
  - MCP 侧：Prompt Injection、Tool Poisoning、Tool Shadowing、Toxic Flows、Rug Pull
  - Skills 侧：Prompt Injection、Malware Payloads、Untrusted Content、Credential Handling、Hardcoded Secrets
- **检测技术**：LLM judges + 确定性规则的混合引擎（因为 skill 是代码+自然语言的混合体）
- **关键研究**：ToxicSkills 研究发现 **36% 的 AI Agent Skills 存在安全缺陷**，包含 1,467 个存在漏洞的 skills 和活跃恶意载荷

- **还有 Web 版**：[labs.snyk.io/experiments/skill-scan](https://labs.snyk.io/experiments/skill-scan/) — Skill Inspector 在线工具

**启示：**
- **Snyk 已经在做 Skill 安全扫描了！** 这是最直接的竞品
- 但 Snyk 走的是企业路线（需要 Snyk API token），不够开发者友好
- 它的检测是被动扫描，不做主动红队攻击测试
- 36% Skills 有安全缺陷的数据证明了这个市场需求真实存在

---

### 1.4 原 MCP-Scan (Invariant Labs → Snyk)

**产品形态：CLI 工具 + 可选代理模式**

- **两种模式**：
  1. `mcp-scan scan` — 扫描 MCP server 的 tool description，检测投毒
  2. `mcp-scan proxy` — 代理模式，监控/记录/保护所有 MCP 流量
- **检测内容**：
  - Tool description 中的 prompt injection
  - Tool poisoning 攻击
  - Cross-origin 权限提升
  - **Tool Pinning**：通过哈希追踪工具完整性，检测 "Rug Pull"（工具先表现正常再变恶意）
- **本地运行**：`--local-only` 标志纯本地检查（但检测精度下降）
- **v0.2 更新**：静态+动态扫描、本地 guardrails、可自定义策略

**启示：**
- Tool Pinning（工具指纹/哈希）是个很好的安全概念
- 代理模式（proxy）能做运行时监控，但增加了部署复杂性
- 已经被 Snyk 整合为 agent-scan 的一部分

---

### 1.5 Garak (NVIDIA) — LLM 漏洞扫描器

**产品形态：Python CLI，类比 nmap/Metasploit 但面向 LLM**

- **安装**：`pip install garak` 或从 GitHub clone
- **使用**：
  ```bash
  garak --model_type huggingface --model_name gpt2 --probes dan
  garak --list_probes    # 列出可用探针
  garak --list_detectors # 列出检测器
  ```
- **架构**：Probe（探针）→ Generator（模型交互）→ Detector（检测器）→ Evaluator（评估器）
- **检测范围**：幻觉、数据泄露、prompt injection、错误信息、有毒内容、越狱
- **输出**：JSONL 日志文件，每条记录包含 entry_type（start_run/attempt/eval）
- **定位**：学术/研究导向，不是产品级工具

**启示：**
- 探针+检测器的模块化架构值得借鉴
- 但 UX 偏学术，不够产品化
- 专注 LLM 模型级，不覆盖 Agent 工作流

---

### 1.6 Agentic Radar (SPLX-AI) — Agent 工作流安全扫描

**产品形态：Python CLI，静态分析 Agent 代码**

- **安装**：`pip install agentic-radar`
- **核心命令**：
  1. `agentic-radar scan` — 静态扫描代码中的 agentic workflow，生成报告
  2. `agentic-radar test` — 动态测试 agent 漏洞（需要 OpenAI API Key）
- **支持框架**：LangGraph、CrewAI、n8n、OpenAI Agents、AutoGen
- **报告内容**：
  - 工作流可视化图（Agent 间交互拓扑）
  - 工具清单（外部/自定义工具列表）
  - MCP Server 检测
  - 漏洞映射表（工具 ↔ 已知漏洞）
- **隐私**：静态分析完全本地运行，代码不会外传

**启示：**
- 工作流可视化是很好的差异化功能
- 支持多框架（LangGraph/CrewAI/n8n）扩大了适用范围
- 但还是 Python 生态，不覆盖 JS/TS

---

### 1.7 AI-Infra-Guard (腾讯朱雀实验室) — 全栈 AI 红队平台

**产品形态：Web 平台 + API**

- **三大模块**：
  1. AI Infra Scan — 30+ AI 框架组件，近 400 个已知 CVE
  2. MCP Server Scan — AI Agent 驱动的 MCP 安全风险检测
  3. Jailbreak Evaluation — prompt 安全风险评估（含策划数据集）
- **技术特点**：使用 ReAct（Reasoning + Agent）框架，让 AI agent 自身驱动安全评估
- **运行方式**：本地部署，访问 `localhost:8088/docs/index.html` 查看 API 文档
- **开源**：GitHub 上可获取，Apache 2.0 许可

**启示：**
- 腾讯出品，说明大厂也在关注这个领域
- 用 AI Agent 来测试 AI Agent 的安全性是个很好的思路
- 但定位偏运维/安全团队，非开发者工具

---

### 1.8 AgentFence — 开源 Agent 安全自动测试

**产品形态：Python 库/CLI**

- **检测能力**：Prompt injection、Secret leakage、System instruction exposure、Role confusion
- **支持框架**：LangChain、OpenAI（初期）
- **定位**：安全研究者和合规团队的自动化对抗测试工具
- **开源**：GitHub 上可获取

**启示：**
- 功能相对基础，但方向正确
- 可扩展架构（易添加新 probe 和评估方法）

---

### 1.9 Pillar Security — 全生命周期 AI 安全平台

**产品形态：企业级 SaaS 平台**

- **四大模块**：
  1. **AI Workbench** — 安全沙箱/playground，部署前做威胁建模
  2. **Red Teaming** — 模拟攻击（prompt injection → 业务逻辑攻击）
  3. **RedGraph** — 运行时攻击面映射（实时与 Agent 交互，映射每个连接/权限/枢纽点）
  4. **Runtime Guardrails** — 自适应运行时防护
- **黑盒测试**：只需 URL + 凭证就能对第三方 AI 应用做渗透测试
- **反馈闭环**：红队发现 → 自动更新 guardrails

**启示：**
- RedGraph（运行时攻击面映射）是独特概念
- 黑盒测试只需 URL 的体验很好（类似我们现有 MVP）
- 但纯企业定位，开发者触达不到

---

### 1.10 Straiker — Agent-Native 安全平台

**产品形态：企业级 SaaS + CI/CD 集成**

- **Ascend AI（红队）**：
  - 自主红队代理，持续暴露漏洞
  - CI/CD 集成"一行代码"
  - 支持持续/定时/按需测试
  - 模型更新、system prompt 修改时自动触发安全评估
- **Defend AI（防护）**：
  - 实时检查每个 user prompt、模型推理步骤、tool call
  - 拦截 prompt injection、数据泄露、幻觉、agent 操控
  - 低延迟精准模型（小型微调模型组合）
- **协同机制**：Ascend 发现的攻击自动转化为 Defend 的新 guardrail 模式

**启示：**
- "攻击发现自动转化为防护规则"的闭环非常优雅
- 小型微调模型组合实现低延迟是实用的技术选择
- CI/CD 一行集成是好的 DX

---

### 1.11 Mindgard — 自动化 AI 红队平台

**产品形态：SaaS 平台 + GitHub Action + CLI**

- **五步流程**：
  1. 指向现有 AI 产品/环境
  2. 一键调度或执行安全测试
  3. 攻击库自动运行
  4. 分析风险场景
  5. 生成报告（集成到 SIEM）
- **集成方式**：CI/CD、IDE hooks、SIEM、ticketing 系统
- **GitHub Action**：每次运行自动拉取最新攻击技术
- **部署要求**：只需推理/API 端点
- **性能**：将安全测试从"数月"缩短到"数分钟"

**启示：**
- GitHub Action 集成是好的分发渠道
- "只需 API 端点"的低门槛接入值得学习

---

## Part 2: 参照模式分析

### 2.1 Nuclei (ProjectDiscovery) — 开源安全社区典范

**关键数据**：30K+ GitHub Stars，900+ 贡献者，12K+ 模板，5000万+月扫描

**成功模式**：
- **YAML-based DSL** 定义漏洞扫描模板，极低的贡献门槛
- **社区飞轮**：全球安全研究者持续贡献模板 → 扫描能力指数增长
- **MIT 开源** + 付费云平台（团队协作、报告、管理）
- 支持 HTTP、DNS、TCP、SSL、WebSocket 等多种协议

**对我们的启示**：
- YAML 模板模式可以直接借鉴到 Agent 攻击 payload 定义
- 社区贡献是最强壁垒
- 开源 CLI + 付费云是验证过的商业模式

### 2.2 Snyk — 开发者安全工具标杆

**产品模式**：
- CLI: `snyk test` / `snyk monitor` 扫描依赖漏洞
- IDE 集成：边写代码边发现漏洞
- PR 集成：合并前自动安全检查
- 自动修复：一键生成修复 PR
- 免费层吸引开发者 → 团队付费转化

**对我们的启示**：
- "左移安全"的典范——在开发阶段就发现问题
- 自动修复（不止发现问题，还给修复方案）是核心体验
- 免费 → 个人 → 团队的转化路径清晰

---

## Part 3: 开发者当前如何测试 Agent 安全？

### 现状

- **<40% 的组织**定期对 AI 模型或 Agent 工作流做安全测试
- **73%** 的生产部署在安全审计中发现 prompt injection 漏洞
- 没有成熟的 Agent 安全成熟度模型
- 现有工具（Guardrails AI、NeMo Guardrails）早期阶段，需要大量定制

### 开发者典型工作流（2026年初）

1. **手动测试**：在 playground 里手动尝试 prompt injection（最常见）
2. **Promptfoo**：用 YAML 配置自动化红队测试（开源，但刚被 OpenAI 收购）
3. **Snyk Agent-Scan**：扫描 MCP/Skill 配置（需要 Snyk 账号）
4. **什么都不做**：大量开发者完全不做安全测试（最多的情况）

### 痛点

- 没有像 ESLint/Prettier 那样"零配置即用"的 Agent 安全工具
- 现有工具要么太学术（Garak）、要么太企业（Lakera/Pillar）、要么太重（Promptfoo YAML 配置复杂）
- Promptfoo 被 OpenAI 收购后，独立的开源 LLM 安全 CLI 工具面临空白

---

## Part 4: 社区与生态

### 开发者社区在哪里？

- **GitHub Topics**：`llm-security`、`ai-security`、`prompt-injection`
- **Discord**：Agentic Radar Discord、HackingBuddyGPT Discord
- **资源聚合**：
  - [awesome-ai-security](https://github.com/ottosulin/awesome-ai-security)
  - [Awesome-LLMSecOps](https://github.com/wearetyomsmnv/Awesome-LLMSecOps)
  - [LLMSecurityGuide](https://github.com/requie/LLMSecurityGuide)（2026年2月更新）
  - [awesome-cybersecurity-agentic-ai](https://github.com/raphabot/awesome-cybersecurity-agentic-ai)
- **播客/Newsletter**：AI Security Podcast（CISO 受众最大）、Agentic Security Newsletter

---

## Part 5: 竞品产品形态总结对比

| 产品 | 类型 | 语言/安装 | Agent 安全 | 开源 | 定价 |
|------|------|----------|-----------|------|------|
| **Promptfoo** | CLI + YAML + Web | npm/pip/brew | 有（MCP plugin）| MIT | 免费 → Enterprise |
| **Snyk Agent-Scan** | CLI | pip (uvx) | **Skill 扫描** | 部分 | 需 Snyk 账号 |
| **Garak** | Python CLI | pip | 无（纯 LLM）| Apache 2.0 | 免费 |
| **Agentic Radar** | Python CLI | pip | 有（工作流分析）| 开源 | 免费 |
| **AgentFence** | Python 库 | pip | 有（基础）| 开源 | 免费 |
| **AI-Infra-Guard** | Web 平台 | 本地部署 | 有（MCP Scan）| Apache 2.0 | 免费 |
| **MCP-Scan** | CLI | pip | MCP 专项 | 开源→Snyk | 免费 |
| **Lakera Guard** | SaaS API | REST API | 间接注入+工具 | 否 | 免费10K/月→Enterprise |
| **Pillar** | SaaS 平台 | Web | 强 | 否 | Enterprise |
| **Straiker** | SaaS + CI/CD | Web + API | 强（Agent-native）| 否 | Enterprise |
| **Mindgard** | SaaS + GH Action | Web + CLI | 中强 | 否 | Enterprise |

---

## Part 6: 关键洞察与机会

### 1. Promptfoo 被收购后的真空

Promptfoo 是开发者最常用的开源 LLM 安全测试 CLI。被 OpenAI 收购后，虽然承诺继续开源，但长期必然偏向 OpenAI 生态。**这为一个独立的、模型无关的 Agent 安全 CLI 创造了机会。**

### 2. Snyk Agent-Scan 是最直接的参照

Snyk 已经在做 Skill 安全扫描，但：
- 需要 Snyk 账号和 API token（不够开放）
- 只做被动扫描（不做主动红队攻击）
- 企业定位（不够开发者友好）
- Snyk 自己发表了文章"为什么你的 Skill Scanner 可能只是虚假安全"——暗示被动扫描不够

### 3. 市场缺少的是：一个 **npm install** 即用的、开源的、主动红队 + 被动扫描结合的 Agent 安全 CLI

- Promptfoo 太重（YAML 配置复杂）且被 OpenAI 收购
- Snyk Agent-Scan 需要企业账号
- Garak 不覆盖 Agent
- Agentic Radar 只有 Python 版，只做静态分析
- 没有一个 **Node.js/npm 生态** 的 Agent 安全工具

### 4. 36% Skills 有安全缺陷 = 市场需求已被验证

Snyk 的 ToxicSkills 研究证明了这个市场的真实性。

### 5. OWASP Agentic Top 10 提供了标准化框架

可以直接对标 OWASP Agentic Top 10 构建检测能力，给报告增加权威性。

---

## References

- [Lakera Guard API Documentation](https://docs.lakera.ai/docs/api/guard)
- [Lakera Guard Getting Started](https://docs.lakera.ai/docs/quickstart)
- [Lakera Guard Pricing](https://platform.lakera.ai/pricing)
- [Promptfoo GitHub](https://github.com/promptfoo/promptfoo)
- [Promptfoo Red Team Guide](https://www.promptfoo.dev/docs/red-team/)
- [Promptfoo MCP Security Testing](https://www.promptfoo.dev/docs/red-team/mcp-security-testing/)
- [Promptfoo Pricing](https://www.promptfoo.dev/pricing/)
- [OpenAI acquires Promptfoo — TechCrunch](https://techcrunch.com/2026/03/09/openai-acquires-promptfoo-to-secure-its-ai-agents/)
- [NVIDIA Garak GitHub](https://github.com/NVIDIA/garak)
- [Garak CLI Reference](https://reference.garak.ai/en/stable/cliref.html)
- [Snyk Agent-Scan GitHub](https://github.com/snyk/agent-scan)
- [Snyk ToxicSkills Research](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)
- [Snyk Agent-Scan Skill Inspector](https://labs.snyk.io/experiments/skill-scan/)
- [Snyk + Vercel Securing Agent Skill Ecosystem](https://snyk.io/blog/snyk-vercel-securing-agent-skill-ecosystem/)
- [MCP-Scan Introduction — Invariant Labs](https://invariantlabs.ai/blog/introducing-mcp-scan)
- [MCP-Scan Scanning Documentation](https://explorer.invariantlabs.ai/docs/mcp-scan/scanning/)
- [Agentic Radar GitHub](https://github.com/splx-ai/agentic-radar)
- [AgentFence GitHub](https://github.com/agentfence/agentfence)
- [AI-Infra-Guard GitHub (Tencent)](https://github.com/Tencent/AI-Infra-Guard)
- [Pillar Security Platform](https://www.pillar.security/platform)
- [Pillar Security Product Walkthrough — The Hacker News](https://thehackernews.com/2025/07/product-walkthrough-look-inside-pillars.html)
- [Straiker Products](https://www.straiker.ai/products)
- [Straiker Ascend AI](https://www.straiker.ai/products/ascend-ai)
- [Straiker Defend AI](https://www.straiker.ai/products/defend-ai)
- [Mindgard Platform](https://mindgard.ai/)
- [Nuclei GitHub — ProjectDiscovery](https://github.com/projectdiscovery/nuclei)
- [Nuclei Community Templates](https://projectdiscovery.io/nuclei)
- [Snyk CLI GitHub](https://github.com/snyk/cli)
- [Snyk Pricing](https://snyk.io/plans/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic Top 10 — Practical DevSecOps](https://www.practical-devsecops.com/owasp-top-10-agentic-applications/)
- [Best LLM Security Tools & Frameworks 2026 — Deepchecks](https://www.deepchecks.com/top-llm-security-tools-frameworks/)
- [Awesome AI Security](https://github.com/ottosulin/awesome-ai-security)
- [LLMSecurityGuide](https://github.com/requie/LLMSecurityGuide)
- [Automated LLM Red Teaming with Promptfoo — NVISO Blog](https://blog.nviso.eu/2026/02/05/an-introduction-to-automated-llm-red-teaming/)
- [AI Agent Security Best Practices — IBM](https://www.ibm.com/think/tutorials/ai-agent-security)
- [AI Security Trends 2026 — Black Duck](https://www.blackduck.com/blog/2026-ai-security-appsec-predictions.html)
