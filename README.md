# Graph Reasoning Code Audit

一个基于图推理的 AI 代码审计 Skill。

这个项目面向 Claude Code、Codex 等 AI coding agent，目标不是再做一个扫描器，而是把 AI 代码审计组织成一套可分阶段执行、可恢复、可验证的图推理工作流。

## 环境要求

| 平台 | 说明 |
|------|------|
| Linux | 建议 |
| Windows | 支持 |

## 依赖工具

本项目会编排以下开源工具。具体是否必须安装，取决于当前审计阶段、目标项目语言和用户选择；工具不可用时，Skill 会记录降级或跳过原因。

| 序号 | 工具 | 仓库 | 用途 |
|:----:|------|------|------|
| 1 | Graphify | [safishamsi/graphify](https://github.com/safishamsi/graphify) | 将代码库构建为可查询的知识图谱 |
| 2 | Semgrep | [semgrep/semgrep](https://github.com/semgrep/semgrep) | 轻量级静态分析和第一层证据收集 |
| 3 | CodeQL CLI | [github/codeql-action](https://github.com/github/codeql-action) | 语义分析、标准查询包和定制查询验证 |
| 4 | Joern | [joernio/joern](https://github.com/joernio/joern) | 基于代码属性图 CPG 的静态分析 |
| 5 | Betterleaks | [betterleaks/betterleaks](https://github.com/betterleaks/betterleaks) | 密钥与敏感信息泄露扫描 |
| 6 | OSV-Scanner | [google/osv-scanner](https://github.com/google/osv-scanner) | 开源依赖漏洞扫描 |

## 核心设计

传统 AI 代码审计很容易变成：

```text
读源码 -> 找可疑点 -> 写报告
```

这种方式在小项目里可行，但在中大型项目里容易遇到几个问题：

- 上下文窗口被源码、扫描结果和推理过程迅速填满；
- 任务后期发生上下文压缩，模型容易遗忘前面的关键判断；
- 安全发现缺少统一的语义模型，容易只看到单点漏洞，看不到架构根因；
- 工具扫描结果、假设、源码验证和最终报告之间缺少清晰边界；
- 主 agent 长时间承担所有工作，注意力会逐渐下降。

本项目的设计是把代码审计变成：

```text
代码图 / AST / 结构上下文
  -> 安全语义模型
  -> 漏洞假设池
  -> 工具漏斗验证
  -> 源码验证
  -> 用户报告
```

## 图推理审计

项目使用 Graphify 或类似代码图能力，将代码库转化为结构化上下文：

- 文件、模块、类、函数、调用关系；
- Controller、Service、DAO、配置、安全组件等社区结构；
- 入口点、资源、角色、权限边界、敏感操作；
- 跨模块关系和潜在安全边界。

AI 不直接在海量源码里“凭感觉找漏洞”，而是先基于代码图和源码证据构建安全语义模型，再从模型中生成漏洞假设。

安全语义模型关注：

- 谁可以访问系统；
- 哪些资源有所有权或租户边界；
- 哪些入口点会触发敏感动作；
- 哪些状态转换必须保持业务不变量；
- 哪些 guard、filter、middleware、permission check 是真正有效的；
- 哪些地方存在全局架构缺失，例如缺少认证、授权、租户隔离或安全边界。

## 假设驱动

这个 Skill 不鼓励模型直接写“发现了漏洞”，而是先生成假设：

```text
H-001: 某资源 CRUD 可能缺少所有权校验
H-002: 文件下载路径可能存在路径遍历
H-003: 密码存储可能使用弱哈希
H-004: 系统可能缺少资源级授权架构
```

每个假设都需要有：

- 来源证据；
- 影响资源；
- 入口点；
- 期望的安全控制；
- 可疑缺口；
- 适合的验证路径。

这让审计从“模型即时判断”变成“模型提出假设，再逐步验证”。

## 分阶段上下文治理

项目的 2.0 版本重点解决 AI 审计流程过长的问题。

每个阶段只消费当前阶段需要的输入，并把产物写入 `.audit/`。下一个阶段读取上一个阶段的摘要和结构化产物，而不是依赖聊天记忆。

这样做的目的：

- 降低上下文窗口压力；
- 降低长任务后期的注意力下降；
- 让审计可以跨会话恢复；
- 让每一步都有明确产物和校验点；
- 让主 agent 可以把部分验证任务分派给 subagent。

核心阶段：

```text
工具预检
  -> 代码图构建
  -> SCA / Secret 辅助上下文
  -> 安全语义建模
  -> 漏洞假设生成
  -> 用户检查点
  -> 工具验证
  -> 源码验证
  -> 最终报告
```

## 验证漏斗

验证阶段采用漏斗模型，而不是把所有工具并行堆上去：

```text
Semgrep
  -> triage
  -> CodeQL 或 Joern
  -> source validation
```

Semgrep 用于第一层快速证据收集。

CodeQL 和 Joern 作为语义验证器，默认二选一，根据语言支持和项目情况选择。标准查询包或 querydb 只算广度覆盖；对高价值假设，还需要做假设驱动的深度验证。

最后一层永远是源码验证。工具结果只是证据，不直接等于漏洞结论。

## 主 Agent 与 Subagent

主 agent 的角色是 orchestrator：

- 控制阶段推进；
- 维护 `.audit/` 产物；
- 在检查点向用户汇报并等待确认；
- 分派边界清晰的 subagent；
- 合并和校验结果；
- 负责最终报告。

Subagent 只处理小范围任务，例如：

- 验证 1-3 条安全假设；
- 针对一个子系统做源码复核；
- 对某个语义验证器执行窄查询。

Subagent 不拥有整个审计流程，也不能写聚合报告。这是为了避免并发验证时多个 agent 修改同一个文件，或者在不同上下文里得出互相冲突的结论。

## 审计重点

这个项目关注可利用的源码安全问题，而不是普通代码质量问题。

重点包括：

- 身份认证与授权；
- IDOR 与资源所有权；
- 租户隔离；
- 工作流和状态机绕过；
- 业务逻辑漏洞；
- 注入和危险解释；
- 敏感数据暴露；
- Secret、密码学和 session 安全；
- 文件、网络和外部边界；
- 并发、一致性和资源耗尽；
- 架构级安全控制缺失。

SCA 和 Secret 扫描是辅助上下文，不会直接被当作源码漏洞。依赖漏洞需要证明可达性和触发条件，Secret 命中需要判断是否是有效运行时密钥。

## 项目结构

当前主线版本：

```text
2.0/graph-reasoning-code-audit/
├── SKILL.md
├── orchestrator/
├── scripts/
├── references/
└── templates/
```

其中：

- `SKILL.md`：Skill 入口和总控说明；
- `orchestrator/`：阶段状态机；
- `scripts/`：确定性辅助脚本；
- `references/`：各阶段审计协议、schema、工具策略；
- `templates/`：最终报告模板。

## 当前状态

2.0 版本已经实现：

- 基于 Graphify AST / code graph 的审计入口；
- 阶段化 runner；
- 工具预检和用户检查点；
- 安全语义模型；
- 假设池和验证批次；
- ARCH 架构根因类假设；
- Semgrep -> CodeQL/Joern -> 源码验证漏斗；
- CodeQL/Joern 广度覆盖与深度验证区分；
- Joern full CPG first, focused CPG fallback 策略；
- 并发源码验证的隔离目录和合并协议；
- 最终审计报告模板。

## Roadmap

- 小项目 quick mode；
- 更强的语言感知 Semgrep 规则生成；
- 更多 Joern / CodeQL 查询模板；
- 更完整的报告质量检查；
- LangGraph 或其他 agent graph 封装实验。

## License

MIT
