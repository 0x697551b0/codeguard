# CodeGuard 设计文档

> 软件工程实践 Homework 1 · 代码审查 Agent

本文说明 CodeGuard 的**架构决策、设计模式、控制流与失败处理**，以及开发过程中
真实遇到的工程问题与解决方式。

---

## 目录

1. [需求与目标](#1-需求与目标)
2. [总体架构](#2-总体架构)
3. [Agent 主循环](#3-agent-主循环)
4. [LLM 接入层](#4-llm-接入层)
5. [工具层](#5-工具层)
6. [事实层：静态分析引擎](#6-事实层静态分析引擎)
7. [数据结构与报告](#7-数据结构与报告)
8. [失败处理与降级](#8-失败处理与降级)
9. [安全设计](#9-安全设计)
10. [设计模式应用](#10-设计模式应用)
11. [测试策略](#11-测试策略)
12. [开发中遇到的工程问题](#12-开发中遇到的工程问题)
13. [已知局限与后续改进](#13-已知局限与后续改进)

---

## 1. 需求与目标

作业要求实现一个代码助手 Agent，核心能力是：**LLM 调用、Prompt 设计、工具集成**，
并推荐支持上下文记忆与错误处理重试。

CodeGuard 选择**代码审查**方向，并在此基础上明确了三条自己的设计目标：

| 目标 | 具体含义 | 为什么重要 |
| --- | --- | --- |
| **有据可查** | 每条问题都能指向真实存在的 `文件:行号` 与代码片段 | 代码审查工具一旦给出假行号就完全失去可信度 |
| **低误报** | 宁可少报，不可乱报；对安全写法主动排除 | 误报率是审查工具能否被真正采用的决定性因素 |
| **绝不空手而归** | 任何失败路径都要产出可用结果 | 用户等了几十秒却拿到一个异常栈是不可接受的 |

这三条目标直接决定了下文的架构选择，而不是先设计架构再补理由。

---

## 2. 总体架构

### 2.1 分层视图

```
┌────────────────────────────────────────────────────────────────────┐
│ 接口层  cli.py                                                      │
│   review / scan / chat / rules / info —— argparse，零额外依赖        │
└───────────────────────────────┬────────────────────────────────────┘
                                │
┌───────────────────────────────▼────────────────────────────────────┐
│ 编排层  agent.py :: CodeReviewAgent                                 │
│   · 循环编排（输入→推理→工具→观察→输出）                             │
│   · 预算控制（迭代轮数 / 工具调用总数）                              │
│   · 动态提示注入（Context Engineering）                              │
│   · 失败自愈与兜底收敛                                               │
└──────────┬──────────────────────────────────┬──────────────────────┘
           │                                  │
┌──────────▼──────────────────┐  ┌────────────▼──────────────────────┐
│ LLM 层  llm.py              │  │ 工具层  tools.py                   │
│  BaseLLMClient（抽象接口）   │  │  Tool / ToolRegistry              │
│   ├─ LLMClient   （真实）    │  │  Toolbox（注册表 + 侧信道）         │
│   └─ MockLLMClient（离线）   │  │  PathGuard（路径沙箱）              │
└──────────┬──────────────────┘  └────────────┬──────────────────────┘
           │                                  │
┌──────────▼──────────────────┐  ┌────────────▼──────────────────────┐
│ 外部服务                     │  │ 事实层  static_analysis.py          │
│  DeepSeek / OpenAI / 通义    │  │  ast 规则引擎（27 条规则）           │
│  （OpenAI 兼容协议）          │  │  纯标准库，确定性、可回归测试         │
└─────────────────────────────┘  └───────────────────────────────────┘

         横切关注点：models.py（领域模型） · report.py（渲染）
                     config.py（配置） · exceptions.py（异常） · compat.py（兼容）
```

### 2.2 依赖方向

依赖**单向向下**，且关键位置做了依赖倒置：

```
cli.py ──▶ agent.py ──▶ (BaseLLMClient 抽象) ◀── LLMClient / MockLLMClient
                   └──▶ (Toolbox)             ◀── build_default_registry
```

`agent.py` 只依赖 `BaseLLMClient` 抽象，因此：

- **测试可离线**：注入 `MockLLMClient` 即可完整测试 Agent 闭环，不消耗 token；
- **可扩展**：未来接入任何新服务商（甚至本地 vLLM）只需新增一个实现；
- **演示可离线**：助教无需 API Key 就能验证 Agent 是否真的"会自己决定做什么"。

### 2.3 模块职责

| 模块 | 行数量级 | 职责 | 不负责什么 |
| --- | --- | --- | --- |
| `agent.py` | ~600 | 循环编排、预算、提示注入、降级 | 不实现工具、不发 HTTP |
| `llm.py` | ~500 | HTTP 调用、重试退避、协议解析、Mock | 不知道"审查"是什么 |
| `tools.py` | ~800 | 工具定义/注册/分发、路径沙箱 | 不做语义判断 |
| `static_analysis.py` | ~1100 | AST 规则引擎 | 不做 I/O、不调 LLM |
| `prompts.py` | ~300 | Prompt 文本与渲染 | 不参与控制流 |
| `models.py` | ~450 | 领域模型与容错解析 | 无业务逻辑 |
| `report.py` | ~400 | Markdown/文本/JSON 渲染、CI 门禁 | 不修改报告数据 |
| `cli.py` | ~480 | 参数解析、模式分发、退出码 | 不含业务逻辑 |

---

## 3. Agent 主循环

### 3.1 单轮流程

```python
for iteration in 1..max_iterations:
    # 1. 按阶段注入动态提示（Context Engineering）
    if hint_kind: messages.append(user_hint(hint_kind))

    # 2. 调用 LLM（携带工具定义）
    response = llm.chat(messages, tools=registry.schemas())

    # 3. 记录 assistant 消息（含 tool_calls）
    messages.append(response.to_message())

    # 4. 分支
    if not response.tool_calls:
        if 从未用过工具 and 还有预算:  # 模型想凭空下结论
            hint_kind = "no_tool_used"; continue
        else:
            break                      # 视为最终答复

    # 5. 执行工具，结果作为 role=tool 回灌
    execute_tool_calls(response.tool_calls)

    # 6. 终止工具判定
    if toolbox.report is not None:
        report = toolbox.report
        report.merge_findings(静态分析发现)   # 合并补全
        break

    # 7. 更新阶段提示
    hint_kind = 根据剩余预算/轮次决定
```

### 3.2 三个关键设计

**（1）循环体只做编排，不做实现**

`_run_loop` 不做 HTTP、不解析 AST、不渲染报告。它读起来就是一张流程图，
这正是"架构清晰度"的体现 —— 审阅者能在 30 秒内理解 Agent 在做什么。

**（2）动态提示而非静态 Prompt**

约束的价值取决于时机。一开始就说"预算将尽要收敛"会让模型过早放弃调查；
未用工具时讲预算则毫无意义。因此把时效性约束从 System Prompt 中拿出来，
按状态注入（详见 [`docs/PROMPT_DESIGN.md`](docs/PROMPT_DESIGN.md)）。

**（3）结果合并而非直接采纳**

模型经常只挑重点写进报告。`report.merge_findings()` 把静态引擎的完整命中作为
补充合并进来，按 `(文件, 行号, 归一化标题)` 去重，并按严重级别重排。
这样既保留模型的语义判断，又不丢失规则引擎的客观发现。

### 3.3 预算控制

| 预算 | 默认值 | 控制点 |
| --- | --- | --- |
| 迭代轮数 | 12 | 外层 `for` 循环 |
| 工具调用总数 | 40 | 每次调用前检查，超限则回灌"预算已用尽" |
| 并发工具调用 | 由模型决定 | 单轮内模型可一次请求多个工具，按序执行 |
| 单次工具输出 | 20000 字符 | `dumps_tool_result` 截断 |
| 单文件读取 | 200000 字节 | 超限直接报错，引导改用 `search_code` |

---

## 4. LLM 接入层

### 4.1 为什么用原生 HTTP 而非官方 SDK

| 维度 | 原生 `httpx` | 官方 SDK |
| --- | --- | --- |
| 依赖 | 1 个 | 每个服务商 1 个，且互相冲突 |
| 协议可见性 | 请求/响应结构完全可见 | 被封装，调试需读 SDK 源码 |
| 跨服务商 | 改 `base_url` + `model` 即可 | 需换 SDK 与调用方式 |
| 作业契合度 | 符合"使用 LLM 原生 API" | — |

### 4.2 开放类设计

`BaseLLMClient` 是抽象基类（`ABC`），只有两个契约：

```python
class BaseLLMClient(ABC):
    @abstractmethod
    def chat(self, messages, *, tools=None, tool_choice=None) -> LLMResponse: ...
    @property
    @abstractmethod
    def model_name(self) -> str: ...
    def close(self) -> None: ...
```

这足以支撑真实实现、离线 Mock 以及未来的任意扩展。

### 4.3 重试策略

```
异常分类（exceptions.py 中用 retryable 类属性表达）
├─ LLMTimeoutError        retryable=True   （请求超时 / HTTP 408）
├─ LLMConnectionError     retryable=True   （连接失败）
├─ LLMRateLimitError      retryable=True   （HTTP 429 / 5xx 过载）
│    └─ 携带 retry_after，来自服务端 Retry-After 头
├─ LLMAuthError           retryable=False  （HTTP 401/403，重试无意义）
└─ LLMResponseError       retryable=False  （结构异常，重试也一样）
```

退避公式（指数退避 + 全抖动，避免多进程惊群）：

```python
if 服务端给了 Retry-After:
    delay = min(retry_after, backoff_max)
else:
    delay = min(backoff_base ** attempt, backoff_max) * (0.5 + random() * 0.5)
```

**"不可重试"的判断同样重要**：401 重试 3 次只会让用户多等 10 秒才看到
"API Key 无效"。测试 `test_auth_error_is_not_retried` 明确验证了这点。

### 4.4 协议解析的容错

真实服务端的行为比文档更"丰富"，因此解析层刻意写得宽松：

| 异常情况 | 处理方式 |
| --- | --- |
| `arguments` 不是合法 JSON | **不抛异常**，保留原文放入 `ToolCall.raw_arguments` |
| `arguments` 是对象而非字符串 | 重新序列化 |
| `content` 是分段数组 | 拼接各段的 `text` |
| `tool_calls[].id` 缺失 | 生成 `call_{index}` |
| HTTP 200 但 body 里有 `error` | 识别并抛出 `LLMResponseError` |
| body 不是 JSON | 抛出带原文片段的 `LLMResponseError` |

其中第一条最重要：参数解析失败时把错误**回灌给模型让它重新生成**，
比直接崩溃或静默忽略都更有价值（见 `agent.py::_execute_tool_calls`）。

---

## 5. 工具层

### 5.1 三个抽象

```python
@dataclass
class Tool:
    name: str
    description: str          # 给模型看 —— 写得好坏直接决定选对工具的概率
    parameters: dict          # JSON Schema（object 根）
    func: Callable
    requires_approval: bool = False
```

| 抽象 | 职责 |
| --- | --- |
| `Tool` | 单个工具：元数据 + Schema + 执行体；`to_openai_schema()` 生成协议定义 |
| `ToolRegistry` | 注册/查询/生成 schema 列表/分发调用/调用计数 |
| `Toolbox` | `ToolRegistry` + **侧信道**（`submission` / `tool_state`） |

### 5.2 侧信道设计（一个重要的工程教训）

**问题**：`submit_review` 必须给模型一句简短确认语（不能把整份报告再回吐一遍，
浪费 token），但 Agent 又需要拿到**结构化报告**。同理，`run_static_analysis` 的
文本结果受输出长度上限约束会被截断，无法再解析回 JSON。

**解决**：在 `Toolbox` 上开两个显式槽位：

```python
@dataclass
class Toolbox:
    registry: ToolRegistry
    submission: dict = field(default_factory=dict)   # submit_review 的报告
    tool_state: dict = field(default_factory=dict)   # 工具的完整结构化结果

    @property
    def report(self) -> ReviewReport | None: ...
    @property
    def last_static_analysis(self) -> dict | None: ...
```

这个设计最初并不存在 —— 早期版本让 `MockLLMClient` 去**解析对话历史里工具消息的
JSON 文本**来回填报告，结果因为文本被截断（字符串在 JSON 值中间被切断）导致
报告始终为空。修复方式就是把结构化数据走内存槽位，而不是在文本上做二次解析。
详见 [§12.3](#123-被截断的-json-与侧信道)。

### 5.3 路径沙箱

`PathGuard` 是所有文件类工具的必经之路：

```python
def resolve(self, raw_path, *, must_exist=True) -> Path:
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = self.root / candidate      # 相对路径基于工作区根，而非进程 cwd
    resolved = candidate.resolve()             # 解析符号链接，防绕过
    if not self._is_inside(resolved):
        raise ToolArgumentError(f"拒绝访问工作区之外的路径：{raw_path}")
    if must_exist and not resolved.exists():
        raise ToolArgumentError(f"路径不存在：{resolved}")
    return resolved
```

三个细节：

1. **相对基准是工作区根**而非 `os.getcwd()` —— 否则语义会随启动目录漂移；
2. **`resolve()` 后再校验** —— 防止 `a/../../etc/passwd` 与符号链接绕过；
3. **错误信息带可用路径** —— 帮助模型（和人）快速修正。

### 5.4 输出截断的分层处理

工具输出直接决定 token 成本，因此做了分层限制：

| 层次 | 限制 | 超限行为 |
| --- | --- | --- |
| 文件字节数 | 200 KB | 抛 `ToolError`，引导改用 `search_code` |
| 读取行数 | 由 `max_output_chars` 反推 | 缩短窗口并返回 `truncation_note` |
| 结果条目数 | 静态分析 findings ≤ 120 | 截断（截断后仍是合法 JSON） |
| 最终 JSON | 20000 字符 | 末级 `truncate` |

**关键原则：绝不在 JSON 值中间截断字符串。** 那会产生非法 JSON，
让模型（以及早期版本的 Mock 回填逻辑）拿到无法解析的内容。
正确做法是在**结构化层面**裁剪条目数 —— 截断后仍是合法 JSON。

---

## 6. 事实层：静态分析引擎

### 6.1 为什么自研而不是引入 bandit / flake8

| 维度 | 自研 `ast` 引擎 | 引入成熟工具 |
| --- | --- | --- |
| 依赖 | 0（纯标准库） | flake8 + 插件链，安装成本高 |
| 规则可控 | 完全可控，可精确调误报 | 受插件行为约束 |
| 输出结构 | 直接产出 `Finding` 对象 | 需解析文本输出 |
| 作业契合度 | 展示"工具集成"的实现能力 | 更像"调用别人的工具" |
| 教学价值 | 规则实现完全可见 | 黑盒 |

### 6.2 两阶段设计

```
阶段一：逐文件 AST 遍历（_FindingCollector，NodeVisitor）
    · visit_FunctionDef  → 函数级规则（长度/嵌套/参数/默认值/docstring/注解）
    · visit_Call         → 调用级规则（危险 API/TLS/SQL/弱随机/open）
    · visit_ExceptHandler→ 异常处理规则
    · visit_Compare      → 比较规则
    · visit_BinOp        → 除零
    · visit_Assign       → 硬编码密钥 / 遮蔽内置名
    · visit_Try          → finally 跳转
阶段二：跨语句检查（在 CodeAnalyzer 中）
    · 未使用导入（需要全局收集导入与引用）
    · 行级检查（行长度 / 行尾空白）
    · 重复字面量（需要全局计数）
```

**预扫描**：`precollect_sql_variables()` 在遍历前先收集"像 SQL 的变量"。

这解决了一个真实的顺序陷阱：`visit_Call`（调用点）可能在 `visit_Assign`
（定义点）之前被访问到 —— 因为赋值语句本身可能包含调用。与其维护复杂的
状态机，不如先一次性收集全部定义再做单次遍历。**实现更简单也更可靠。**

### 6.3 误报控制策略

误报是审查工具的头号杀手。每条规则都配有"主动排除"逻辑：

| 规则 | 会命中 | 主动排除 |
| --- | --- | --- |
| `CG102` Shell 注入 | `subprocess.run(cmd, shell=True)` | `subprocess.run(['ls','-l'], check=True)`（列表参数 + 无插值） |
| `CG105` 硬编码密钥 | `API_KEY = "sk-live-..."` | 变量名或值含 `your_`/`placeholder`/`example` |
| `CG106` SQL 注入 | `cursor.execute(f"... {uid}")` | `cursor.execute(sql, (uid,))`（传了额外参数 = 参数化） |
| `CG202` 宽泛捕获 | `except Exception: pass` | 有 `logger.exception(...)` 或 `raise` |
| `CG403` 未使用导入 | `import sys` 未使用 | `from __future__ import ...`、`import *`、字符串中出现 |
| `CG305` 重复字面量 | 同一字符串出现 ≥3 次 | 常见魔法值（`""`、`"utf-8"`、`0`、`1`…） |

测试套件中**约一半用例是负例（误报回归测试）**，例如
`test_subprocess_list_form_not_reported`、`test_parameterized_query_not_reported`、
`test_placeholder_password_not_reported`、`test_clean_code_has_no_high_severity_findings`。

### 6.4 语法错误的前置效应

`CG405`（语法错误）是一条特殊的"前置规则"：命中后**该文件其他所有规则全部跳过**，
因为后续语义分析都不可靠。

这不是理论问题 —— 开发中用示例代码演示时，示例文件里的
`def list = [1, 2, 3]`（本意是演示"遮蔽内置名"）意外写成语法错误，
导致该文件的 `eval`、SQL 注入等**全部 20 多条命中消失**，
`scan` 只报出"语法错误"一条。

这既说明规则设计正确（语法错误确实让分析失去意义），也说明
**示例代码本身也需要测试**：

```python
def _static_engine_check() -> str:
    rule_ids = {f.rule_id for f in summary.findings}
    expected = {"CG101", "CG102", "CG103", "CG105", "CG106", "CG201", "CG203"}
    missing = expected - rule_ids
    assert not missing, f"未命中预期规则：{sorted(missing)}"
```

`verify.py` 现在会显式断言示例代码必须命中所有预期规则 —— 这条检查的价值远高于
"能跑通"。

---

## 7. 数据结构与报告

### 7.1 领域模型

```
Finding（一条问题）
├─ title / severity / category / file / line
├─ evidence（原文摘录）/ explanation（为什么会出问题）/ suggestion（怎么改）
├─ rule_id（来自哪条规则）
├─ source（static = 规则引擎 / llm = 语义分析）   ← 如实标注来源
└─ confidence（模型可给出）

ReviewReport（一次审查）
├─ summary / overall_risk / score
├─ findings（按严重级别排序）
├─ positives / open_questions / files_reviewed
└─ meta（模型、耗时、token、迭代轮数、结束原因…）
```

**`source` 字段是刻意的诚实设计**：报告里必须区分"这是规则引擎的客观命中"
还是"这是模型的语义判断"，否则读者会误判结论的可信度。这一字段在 Mock 模式
回填时也如实标注为 `static`。

### 7.2 容错构造

模型输出的字段名不稳定（可能给 `说明`、`description` 或 `explanation`），
因此 `Finding.from_dict` 显式列出中英文别名，任何缺失字段都退化为空值而非抛异常：

```python
def pick(*names):                      # 依次尝试多个别名
    for name in names:
        if name in data and data[name] not in (None, ""):
            return data[name]
    return None

severity=Severity.coerce(pick("severity", "level", "级别", "严重程度")),  # 非法值降级为 INFO
line=安全转 int(pick("line", "line_number", "行号", "start_line"))       # 失败则为 None
```

**默认可用性优先于严格性**：模型偶尔给出非规范格式是常态，为此让整次审查失败
是不可接受的。

### 7.3 三种渲染共用同一份数据

| 渲染 | 用途 | 特点 |
| --- | --- | --- |
| `render_markdown` | 贴 PR 评论 / 写作业文档 | 表格、代码块、可选规则手册附录 |
| `render_text` | 终端 | CJK 宽度感知的折行（中文按 2 列计算）、emoji 级别标记 |
| `render_json` | 流水线 / 二次统计 | 全量字段，中文原样保留 |

`--min-severity` 只影响**终端展示**；`--report` 写出的 Markdown/JSON 始终全量，
避免"写进文件时丢信息"这种反直觉行为。

---

## 8. 失败处理与降级

Agent 系统里"失败"有多种形态，处理策略各不相同：

| 失败形态 | 处理策略 | 实现位置 |
| --- | --- | --- |
| **工具参数非法**（非法 JSON） | 回灌错误，让模型重新生成参数 | `_execute_tool_calls` |
| **工具名不存在** | 回灌错误 + **可用工具清单** | `ToolRegistry.get` |
| **工具执行失败**（路径不存在、文件过大） | 回灌错误信息，模型改参重试 | `Tool.execute` 包装 |
| **模型想跳过调查** | 注入 `no_tool_used` 提示拉回 | `_run_loop` |
| **模型空响应** | 注入 `empty_response` 提示 | `_run_loop` |
| **LLM 限流/超时** | 指数退避重试（尊重 `Retry-After`） | `LLMClient.chat` |
| **LLM 鉴权失败** | 立即抛出，不浪费重试次数 | `LLMClient._raise_for_status` |
| **LLM 最终失败** | **降级**：由静态分析合成报告 | `_fallback_report` |
| **预算耗尽仍未提交** | **降级**：由静态分析合成报告 | `_run_loop` 收尾 |
| **兜底时连历史都没有** | 直接对目标跑一次分析引擎 | `_analyze_target_directly` |

核心原则：**工具层的错误是可恢复的，必须回灌；LLM 层的失败是不可恢复的，
必须降级。**

兜底链的最后一步值得单独说明：如果模型从未调用过 `run_static_analysis`
（例如第一轮网络就失败），`_fallback_report` 会**直接调用分析引擎**补一份结果。
这样"绝不空手而归"这一承诺在任何失败路径上都成立，而不只是"通常成立"。

---

## 9. 安全设计

| 威胁 | 防护 | 位置 |
| --- | --- | --- |
| **路径穿越**（`../../etc/passwd`） | `resolve()` 后校验是否在工作区内 | `PathGuard` |
| **符号链接绕过** | 用 `Path.resolve()` 解析链接后再校验 | `PathGuard` |
| **正则拒绝服务**（恶意 pattern） | 限制 `max_results`、逐行 `search`、跳过超大文件 | `search_code` |
| **上下文爆炸**（超大文件/输出） | 多层截断（见 §5.4） | `tools.py` |
| **密钥泄露到报告** | 证据字段自动脱敏（`sk-l********`） | `_check_hardcoded_secret` |
| **密钥泄露到日志** | `Config.describe()` 只显示前 8 位；`.env` 在 `.gitignore` 中 | `config.py` |
| **无限循环** | 迭代轮数与工具调用双预算 | `agent.py` |
| **Prompt 注入**（代码中含恶意指令） | System Prompt 明确规定只依据工具返回的事实；被审代码始终以数据形式进入上下文 | `prompts.py` |

关于 Prompt 注入需要诚实说明：本项目**没有**做专门的防御性处理（例如对
被审代码做指令隔离标记）。审查场景下的风险相对可控（代码由用户自己提供），
但如果要审查第三方不可信代码，应当增加输入净化。这一点已列入
[§13 已知局限](#13-已知局限与后续改进)。

---

## 10. 设计模式应用

| 模式 | 应用位置 | 解决的问题 |
| --- | --- | --- |
| **策略 / 依赖倒置** | `BaseLLMClient` ← `LLMClient` / `MockLLMClient` | 可替换实现，使测试与演示完全离线 |
| **注册表** | `ToolRegistry` | 工具的注册、查找、Schema 生成、分发解耦 |
| **命令** | `Tool`（元数据 + 执行体） | 把"工具"封装成可序列化定义 + 可调用对象 |
| **模板方法** | `CodeAnalyzer.analyze_source` 固定流程（解析→遍历→跨语句检查→截断） | 新增规则只需加 `visit_*`，不改主流程 |
| **访问者** | `_FindingCollector(ast.NodeVisitor)` | 按节点类型分发规则，天然契合 AST 遍历 |
| **责任链** | Agent 循环的失败处理链（工具错误 → 回灌 → 提示 → 兜底） | 每层处理自己能力范围内的问题 |
| **门面** | `CodeReviewAgent` 对 CLI 暴露 `review()` / `followup()` | 隐藏循环、重试、合并等复杂度 |
| **值对象** | `Finding` / `ReviewReport` / `TokenUsage`（dataclass） | 数据结构清晰，易于序列化与比较 |
| **空对象 / 默认值** | `Finding.from_dict` 的字段降级、`Severity.coerce` 归一到 INFO | 模型输出不规范时不崩溃 |

---

## 11. 测试策略

### 11.1 分层

```
        ▲  端到端（verify.py）
       ╱ ╲   9 项检查：导入/编译/规则能力/误报回归/工具/闭环/渲染/CLI退出码/测试套件
      ╱   ╲
     ╱─────╲  集成测试（test_agent.py，17 例）
    ╱       ╲  完整 Agent 闭环、工具自愈、预算兜底、LLM 失败降级、上下文记忆
   ╱─────────╲
  ╱           ╲ 单元测试（其余 90 例）
 ╱─────────────╲  规则引擎正/负例、工具与沙箱、LLM 客户端、模型、报告、配置
╱───────────────╲
```

### 11.2 离线是第一原则

**全部 108 个用例不访问网络、不需要 API Key。** 实现方式：

| 被替换的依赖 | 替身 | 文件 |
| --- | --- | --- |
| 真实 LLM 服务 | `httpx.MockTransport` 注入伪造 HTTP 响应 | `test_llm.py` |
| 真实 LLM 客户端 | `MockLLMClient`（脚本化响应序列） | `test_agent.py` |
| 文件系统 | `writable_tempdir()` 临时工作区 | 各测试文件 |
| `time.sleep` | 打桩收集等待时长（验证退避策略而不真的等待） | `test_llm.py` |

好处：CI 可离线运行、测试秒级完成、结果确定、不消耗 token。

### 11.3 测试用例设计要点

**（1）负例与正例同等重要**

规则引擎的测试一半在验证"不误报"：

```python
def test_subprocess_list_form_not_reported():
    source = "import subprocess\n\ndef f():\n    subprocess.run(['ls', '-l'], check=True)\n"
    assert "CG102" not in rule_ids(source)
```

**（2）回归测试指向具体 bug**

每个修过的 bug 都补一条针对性回归测试，且注释说明"曾出过什么问题"：

```python
def test_dynamic_eval_is_detected():
    """回归：示例代码里 eval 必须被识别（曾因语法错误导致整文件跳过）。"""
```

**（3）断言"行为"而非"实现细节"**

```python
# ❌ 脆弱的断言
assert result.usage.total_tokens == 450
# ✅ 稳健的断言
assert result.usage.calls == 3 and result.usage.total_tokens > 0
```

**（4）零依赖运行器**

`run_tests.py` 用标准库实现用例发现与执行，因此即使环境装不上 pytest，
`python run_tests.py` 依然能跑全部测试。测试函数写成普通函数（无 fixture、
无特殊断言），同时对 pytest 完全兼容。

---

## 12. 开发中遇到的工程问题

这一节记录开发过程中**真实踩到**的坑。它们比架构图更能说明"健壮性来自哪里"。

### 12.1 Windows 控制台编码：GBK 让程序崩溃

**现象**：CLI 输出含 emoji 的报告时抛 `UnicodeEncodeError: 'gbk' codec can't
encode character '\u2717'`。

**根因**：Windows 默认控制台代码页是 GBK，向管道（或重定向文件）写入非 GBK 字符
会直接失败。

**解决**：`compat.enable_utf8_console()` 在所有入口调用，把 `stdout`/`stderr`
重配置为 UTF-8 并设 `errors="replace"`：

```python
reconfigure(encoding="utf-8", errors="replace")
```

**教训**：这类"只在特定平台出现"的问题，必须在**所有入口**统一处理，
而不是在报错的那一处打补丁。

### 12.2 临时目录不可写：受限环境的现实

**现象**：测试在不允许写系统 TEMP 的环境下全部失败（`PermissionError`）。

**排查过程**（这一步很关键，直接决定了修复方案）：

```
1. 改用项目内临时目录        → 仍然 PermissionError
2. 直接探测文件系统权限：
     root/zt1 mkdir                      OK
     root/zt1/sub mkdir                  OK
     tempfile.mkdtemp(...) 创建成功       OK
     mkdtemp 子目录 mkdir                 FAIL  ← 关键线索
     mkdtemp 里写文件                     FAIL
```

**根因**：`tempfile.mkdtemp` 在 Unix 语义下以 **0700** 权限创建目录。
某些沙箱/安全策略按权限位裁决访问，因此该目录下的子项被拒绝写入，
而用普通 `mkdir`（继承父目录权限）创建的目录则完全可写。

**解决**：`compat.writable_tempdir()` 不用 `mkdtemp`，而用 `mkdir` + 随机名，
并且**先真实探测可写性**再使用：

```python
def _is_writable(directory):
    probe = directory / f".cg_probe_{uuid4().hex}"
    probe.write_text("ok"); probe.unlink()     # 真实创建再删除，而不是相信 os.access
    return True
```

**教训**：① "能创建目录"不等于"能在里面写文件"，权限位比直觉更微妙；
② 探测能力时必须**真实执行操作**，而不是依赖 `os.access` 之类的间接判断；
③ 面对平台差异，正确的做法是"多候选 + 真实探测 + 优雅降级"。

### 12.3 被截断的 JSON 与侧信道

**现象**：`--mock` 模式的报告始终是空的（`findings` 为 0），但静态分析明明命中了 76 条。

**根因**：`MockLLMClient` 的实现试图**解析对话历史里工具消息的 JSON 文本来回填报告**。
而工具消息受 `max_output_chars` 限制，`json.dumps` 的字符串在**值中间**被截断，
得到的是非法 JSON，解析静默失败。

**解决**：不在文本上做二次解析，改为让工具把**完整结构化结果**放进侧信道：

```python
tool_state["run_static_analysis"] = result      # tools.py
state = toolbox.last_static_analysis            # 消费者读取
```

**教训**：这是典型的"用文本当接口"的反模式。当同一份数据既要给人/模型看、
又要给程序用时，应当**显式区分两条通道**，而不是让程序去解析面向人的那份表示。
与此同时，截断策略也要修正：应当在**结构化层面**裁剪条目数，而不是在序列化
字符串上切割 —— 截断后仍是合法 JSON。

### 12.4 SQL 注入规则漏掉了最常见的写法

**现象**：示例代码里明确写着拼接 SQL，规则引擎却没报。

**根因**：初版 `_check_sql_injection` 只检查**传给 `execute` 的表达式本身**
是否为插值。而真实代码里最常见的写法是：

```python
sql = "SELECT id FROM users WHERE email = '%s'" % email
cursor.execute(sql)          # ← 参数只是一个变量名，表达式本身"干净"
```

**解决**：增加"变量追踪" —— 预扫描阶段收集"像 SQL 的变量"，
在 `execute(变量)` 处按定义点判定。同时把三种写法（内联插值 / 变量间接 /
字面量未参数化）都纳入覆盖，并且**主动排除**参数化查询
（`execute(sql, (email,))` 传了额外参数 = 安全）。

**教训**：规则引擎的价值在于覆盖**真实代码的常见形态**，而不是纸上谈兵的形态。
写规则时应当先问"人们在实践中到底怎么写"，再决定匹配策略。

### 12.5 让"演示模式"说真话

**问题**：Mock 模式的报告如果靠编造，会让人误以为工具真的"理解"了代码。

**解决**：`MockLLMClient` 的最后一个脚本步骤会**读取前面 `run_static_analysis`
的真实返回结果**，把实际问题填进报告；`summary` 明确标注"离线 Mock 模式"；
每条 finding 的 `source` 如实标为 `static`（规则引擎）而非 `llm`（语义分析）。

这样演示报告与 `python -m codeguard scan` 的结论**完全一致、可交叉验证**。

**教训**：演示/降级路径的可信度同样重要。一个会说假话的 Mock 模式，
比一个诚实的空白报告危害更大 —— 它会让评审者高估系统的能力。

### 12.6 声明了却没实现的规则

**现象**：`RULES` 里登记了 `CG306`（使用 print 输出），但代码中并没有对应的
检测实现 —— 规则手册里能查到，实际却永远不触发。

**处理**：直接从规则表中删除，而不是留一条"文档存在、行为不存在"的规则。

**教训**：**声明与实现不一致是真实的缺陷**，它比"缺少功能"更糟 ——
因为使用者会基于文档产生错误预期。文档里写的东西必须是代码真的会做的事。

### 12.7 自证正确：当"自己的解析器"验证"自己写的格式"

**现象**：在没有 Git 的机器上创建仓库，需要用 Python 直接写 `.git/index`。
按流传最广的索引格式说明实现后，自研校验脚本 `tools/verify_repo.py` 全部通过 ——
条目边界、文件名长度、对齐填充、末尾 SHA-1 全部正确。但装上 GitHub Desktop
（自带 Git）后用真实 Git 一跑：

```
fatal: unknown index entry format 0x642f0000
```

**排查过程**（值得记录，因为它展示了错误的排查姿势）：

1. 怀疑对齐填充算错 → 改成 `-length % 8`，仍失败；
2. 怀疑行尾问题 → 发现 **`Path.write_text` 在 Windows 上把 `\n` 写成了 `\r\n`**，
   而 Git 把 ref 文件里的 `\r` 当成"垃圾字符"（`git fsck` 明确报了
   `trailingRefContent` 警告）。这是一个**真实 bug**，修掉后 `git log` 恢复正常；
3. 怀疑 stat 字段 → 全部写 0，仍失败；
4. 做大量对照实验，得到两条互相矛盾的线索：
   - 我写的第一条 `a.txt` 条目与 Git 生成的**逐字节完全相同**；
   - 但 Git 从第一个条目走到第二个条目的**步长是 80 字节**，而格式说明是 72。

**根因**：未能确定。在多种对齐假设都被真实 Git 证伪后，选择停止逆推。

**解决**：改用工程手段 —— **把索引这一处委托给 Git 的标准实现**：

```python
subprocess.run([git, "-C", root, "read-tree", self.tree_sha])
```

对象（blob / tree / commit）、引用、reflog、HEAD、config 仍全部由本脚本自己写
（这些格式都已用真实 Git 逐项验证通过），只有索引交给 `git read-tree`。
它只读对象库、不读工作区，因此既快又不会引入工作区差异。本机没有 Git 时
**不写索引**（而不是写一份格式存疑的）—— 对象与引用都正确，Git 首次运行时
会自动重建索引，脚本会明确提示这一点。

**教训（本项目最有价值的一条）**：

> **用自己写的解析器验证自己写的格式，等于没有验证。**

自研校验脚本之所以"全部通过"，是因为解析器与写入器共享同一个（错误的）格式假设 ——
典型的自证正确。真正的验证必须引入**独立实现**作为对照。这正是
`tools/verify_repo.py` 现在分两层的原因：第一层用标准库解码对象（无需 Git，
便于日常使用），第二层调用真实 Git 做权威判定（`git status` /
`git fsck --strict` / `git rev-parse`），**第二层不能省**。

顺带修出的 CRLF bug 也印证了同一点：自研校验脚本完全没发现它，
因为它按文本模式读回，根本不在意 `\r`。

### 12.8 推上去之后才发现：全都是"可执行文件"

**现象**：代码成功推送到 GitHub 后，在仓库页面上发现**每个文件旁边都标着
"executable file"** —— 包括 `.md`、`.py`、`.txt`。用 `git ls-files --stage` 一看，
37 个文件的权限全是 `100755`。

**根因**：`init_repo.py` 用 `os.access(path, os.X_OK)` 判断文件是否可执行，
再据此写 tree 条目的 mode。**在 Windows 上 `os.access(..., os.X_OK)` 对几乎所有
普通文件都返回 `True`**（Windows 不区分"可读"与"可执行"），于是整个仓库都被
打上了可执行位。

**关键点**：这个 bug **本地完全看不出来** —— 因为 `.git/config` 里设了
`filemode = false`（Windows 上的标准配置），`git status`、`git fsck` 全都不报错。
只有把仓库推到 GitHub、由服务端按 mode 渲染文件名时，问题才暴露出来。

**解决**：改用与平台无关的判据 —— 按扩展名识别脚本（`.sh`/`.ps1`/`.bat` 等，
`.py` 再看有无 shebang），仅在 POSIX 上叠加真实可执行位：

```python
def _is_executable(path: Path, relative: str) -> bool:
    if path.suffix.lower() in EXECUTABLE_SUFFIXES:
        return True
    if path.suffix.lower() in {".py", ""}:      # 看 shebang
        with path.open("rb") as handle:
            return handle.read(2) == b"#!"
    return os.name == "posix" and os.access(path, os.X_OK)
```

**教训**：

> **本地校验全绿，不代表交付正确 —— 要按"最终消费者"的视角验证。**

`git status` 干净、`git fsck` 通过，说明仓库在**本地**是健康的；但 GitHub
作为最终消费者，读的是 tree 条目的 mode 位，而 `core.filemode=false` 恰恰让
这一维度在本地完全不可见。这与 §12.7 是同一类错误的两个面：
**验证必须站在独立、且与目标一致的角度**。
现在的 `verify_repo.py` 增加了 mode 断言（不允许普通文件带可执行位）。

### 12.9 环境障碍与"另辟蹊径"

**现象**：开发机处于受限环境 —— 网络不通（TLS 凭证不可用）、
系统临时目录不可写、未安装 Git。

**处理**：把每个障碍都转化为项目内可复用的能力，而不是止步于"环境不支持"：

| 障碍 | 解决方案 | 复用价值 |
| --- | --- | --- |
| 控制台 GBK 编码 | `compat.enable_utf8_console()` | 所有入口统一处理，跨平台可用 |
| 临时目录不可写 | `compat.writable_tempdir()`（真实探测 + 多候选） | 测试在任何机器上都能跑 |
| 装不上 pytest | `run_tests.py`（标准库实现用例发现与执行） | 零依赖，同时对 pytest 兼容 |
| 未安装 Git | `tools/init_repo.py`（按 Git 对象格式写仓库） | 受限环境下仍能产出真实仓库 |
| 索引格式无法确定 | 委托 `git read-tree` 生成；无 Git 则不写并明确提示 | 只写有把握的部分，不假装正确 |

**教训**：环境限制应当推动**通用能力**的建设，而不是留下一次性补丁。
同时要诚实标注能力边界 —— 无 Git 时脚本会明确告知"未写索引，Git 首次运行时
会自动重建"，而不是假装一切正常。

---

## 13. 已知局限与后续改进

### 13.1 局限

| 局限 | 说明 |
| --- | --- |
| 静态规则仅支持 Python | 基于 `ast`，其他语言只能靠 LLM 阅读代码（工具与语言无关，规则引擎不是） |
| 单文件分析，无跨文件数据流 | 无法追踪"用户输入从 A 文件流到 B 文件的 SQL 拼接" |
| 无类型推断 | 无法判断 `x` 是否为字符串，因此对 `x + "SELECT ..."` 这类需要类型信息的场景判据不足 |
| Prompt 注入无专门防御 | 审查第三方不可信代码时缺少输入净化（见 §9） |
| 无增量审查 | 每次全量分析，未利用 git diff 只审查改动 |
| 同步阻塞 | `httpx.Client` 同步调用；审查大项目时耗时较长 |

### 13.2 改进方向

按"性价比"排序：

1. **跨文件数据流分析**：从"入口函数"出发追踪污染源到危险汇点，能显著减少
   "输入来自变量，需人工确认"这类 MEDIUM 噪声；
2. **增量审查**：接入 `git diff`，只审查改动行及其上下文，速度与信噪比双提升；
3. **并发工具执行**：单轮内模型请求多个工具时用线程池并发执行（当前为按序）；
4. **审查历史与对比**：保存历次报告，支持"本次修复了哪些问题、新引入了哪些"；
5. **多语言规则**：为 JS/TS 接入各自的解析器（如 `esprima`/`tree-sitter`）；
6. **流式输出**：改用 `stream=True`，让用户在长审查中看到实时进展。

### 13.3 如果重来一次

- **更早引入 `Toolbox` 侧信道**：这是被 bug 逼出来的设计，实际上应该是第一版
  就有的基础设施（"给程序的数据"与"给模型的数据"从一开始就该分通道）。
- **示例代码纳入测试**：示例文件里的语法错误让整个文件分析失效，而当时
  没有自动检查。现在 `verify.py` 的断言补齐了这个缺口 —— 示例代码也是代码，
  也需要测试。
- **规则与文档同步生成**：规则手册目前是手写的，存在与代码脱节的风险
  （`CG306` 就是这么暴露出来的）。更好的做法是由 `RULES` 元组自动生成文档，
  让"文档即代码"。

---

## 附录：关键文件速查

| 想了解… | 看这个文件 |
| --- | --- |
| Agent 怎么循环 | `codeguard/agent.py` 的 `_run_loop` |
| 怎么做重试 | `codeguard/llm.py` 的 `chat` 与 `_backoff_delay` |
| 怎么保证安全 | `codeguard/tools.py` 的 `PathGuard` |
| 规则怎么实现 | `codeguard/static_analysis.py` 的 `_FindingCollector` |
| Prompt 怎么设计 | `codeguard/prompts.py` + `docs/PROMPT_DESIGN.md` |
| 怎么降级 | `codeguard/agent.py` 的 `_fallback_report` |
| 怎么测试 | `tests/` + `run_tests.py` + `verify.py` |
