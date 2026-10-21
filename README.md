# CodeGuard

> 基于 LLM 工具调用的**代码审查 Agent** —— 软件工程实践 Homework 1
>
> **源码仓库**：<https://github.com/0x697551b0/codeguard>
> **作者**：刘浩天 / 2412190219

CodeGuard 是一个能自己决定"看哪些文件、跑哪些检查"的代码审查助手。它不是把整份代码塞给模型
让它泛泛点评，而是先跑**确定性静态分析**拿到客观事实，再自主阅读关键代码、剔除误报、补充
语义层面的缺陷，最后产出一份**带行号定位、原因分析、可执行修复建议**的结构化报告。

```
                     ┌──────────────────────────────────────────┐
   用户：审查 src/    │  输入 Input                              │
   ─────────────────▶│  "审查 src/，重点关注 SQL 注入"           │
                     └────────────────┬─────────────────────────┘
                                      ▼
                     ┌──────────────────────────────────────────┐
                     │  推理 Reasoning（LLM 决定下一步做什么）    │
                     └────────────────┬─────────────────────────┘
                                      ▼
                     ┌──────────────────────────────────────────┐
                     │  工具调用 Tool Calling                    │
                     │  run_static_analysis / read_file /        │
                     │  search_code / list_files / find_files …  │
                     └────────────────┬─────────────────────────┘
                                      ▼
                     ┌──────────────────────────────────────────┐
                     │  观察 Observation（结果回灌，形成闭环）    │
                     └────────────────┬─────────────────────────┘
                                      ▼
                     ┌──────────────────────────────────────────┐
                     │  输出 Output（submit_review → 结构化报告） │
                     └──────────────────────────────────────────┘
```

---

## 目录

- [快速开始](#快速开始)
- [效果预览](#效果预览)
- [命令行用法](#命令行用法)
- [**使用方法（详细）**](使用方法.md) —— 全部命令、参数、示例与 CI 接入
- [项目结构](#项目结构)
- [架构设计](#架构设计)
- [内置工具](#内置工具)
- [内置静态规则](#内置静态规则)
- [测试与自检](#测试与自检)
- [提交与仓库](#提交与仓库)
- [配置项](#配置项)
- [设计取舍](#设计取舍)
- [常见问题](#常见问题)

---

## 快速开始

### 环境要求

- Python **3.10+**（开发与验证环境为 3.14）
- 唯一第三方依赖：`httpx`（用于 HTTP 调用）

### 安装

```bash
# 1) 获取代码
cd codeguard

# 2) 安装依赖（二选一）
pip install -r requirements.txt
# 或安装为可执行命令（推荐）
pip install -e .

# 3) 配置 API Key
cp .env.example .env      # Windows: copy .env.example .env
# 编辑 .env，把 CODEGUARD_API_KEY 换成你自己的 Key
```

> **没有 API Key 也能跑。** 加 `--mock` 参数即可用内置脚本化模型完整演示
> Agent 闭环（推理 → 工具调用 → 观察 → 报告），全程不访问网络。

### 30 秒上手（无需 API Key）

```bash
python -m codeguard review examples/demo_buggy_code --mock --trace
```

`--trace` 会打印完整执行轨迹，可以直观看到 Agent 每一步在"想什么、调什么工具、
拿到了什么结果"。

### 用真实模型审查

```bash
# DeepSeek（默认）
export CODEGUARD_API_KEY=sk-xxxxxxxx        # Windows: set CODEGUARD_API_KEY=sk-xxxx
python -m codeguard review examples/demo_buggy_code --report report.md

# 换成通义千问（OpenAI 兼容模式）—— 无需改一行代码
python -m codeguard review ./src \
  --base-url https://dashscope.aliyuncs.com/compatible-mode/v1 \
  --model qwen-plus
```

---

## 效果预览

### 终端输出（`--min-severity high` 聚焦高危问题）

```
════════════════════════════════════════════════════════════════════════
 CodeGuard 代码审查报告
════════════════════════════════════════════════════════════════════════
 整体风险：🔴 CRITICAL    评分：5/100
 问题总数：76　(严重 6 / 高 8 / 中 7 / 低 29 / 提示 26)
────────────────────────────────────────────────────────────────────────
【问题清单】显示 14 条（另有 62 条低于 high 的记录，见 Markdown/JSON 报告）

  1. 🟥 [CRITICAL] 疑似硬编码密钥：API_TOKEN
     位置：examples/demo_buggy_code/user_service.py:22　来源：规则引擎
     代码：API_TOKEN = 'sk-l********'（已脱敏）
     说明：凭据硬编码在源码中，一旦进入版本库或日志即视为泄露，且无法按
      环境轮换。
     建议：改为 `os.environ['SERVICE_TOKEN']`，并通过 .env / 密钥管理服
      务注入；同时轮换已泄露的凭据。

  2. 🟥 [CRITICAL] 危险调用 `eval()`：任意代码执行（在 evaluate_filter 中）
     位置：examples/demo_buggy_code/user_service.py:64　来源：规则引擎
     代码：return eval(expression)
     建议：改用 `ast.literal_eval`，或使用显式解析器（json / int()）。

  9. 🟧 [HIGH] 拼接后的 SQL 变量被直接执行：sql（在 find_user_by_email 中）
     位置：examples/demo_buggy_code/user_service.py:55　来源：规则引擎
     代码：cursor.execute(sql)
     说明：变量 `sql` 由格式化/拼接构造（见第 54 行），再交给 `execute`
      执行，等价于拼接 SQL，存在注入风险。
     建议：把 SQL 写成固定模板并用驱动占位符传参：
      `sql = '... WHERE email = %s'` 然后 `cursor.execute(sql, (email,))`。
```

### 执行轨迹（`--trace`）

```
[1] 🧠 推理
    第一步：先对目标路径做确定性静态分析，拿到客观的规则命中清单。
[1] 🔧 工具调用 run_static_analysis(path='examples/demo_buggy_code')
    └─ { "files_analyzed": 3, "total_findings": 76,
         "counts_by_severity": {"critical": 6, "high": 8, "medium": 7, ...} }
[2] 🧠 推理
    第二步：静态规则的命中结果已拿到，接下来读取主要源文件，结合上下文判断真实影响面。
[2] 🔧 工具调用 read_file(path='examples/demo_buggy_code/user_service.py')
[3] 🧠 推理
    第三步：整合规则命中与阅读结论，提交结构化审查报告。
[3] 🔧 工具调用 submit_review(...)
```

完整示例报告见 [`examples/sample_report.md`](examples/sample_report.md)。

---

## 命令行用法

```
python -m codeguard <command> [options]
```

| 子命令 | 作用 | 是否需要 API Key |
| --- | --- | --- |
| `review <目标>` | **核心功能**：用 LLM 做完整 Agent 审查 | 需要（`--mock` 除外） |
| `scan <目标>` | 只跑内置静态规则，确定性输出，可用作 CI 质量门禁 | 不需要 |
| `chat <目标>` | 先审查，再进入交互式追问（验证上下文记忆） | 需要 |
| `rules` | 打印内置规则手册 | 不需要 |
| `info` | 版本与环境自检信息 | 不需要 |

### 常用示例

```bash
# 完整审查 + 输出 Markdown 报告 + 打印执行轨迹
python -m codeguard review ./src --report reports/review.md --trace

# 指定关注点（会写进 Prompt 引导模型重点检查）
python -m codeguard review ./src -f "SQL 注入" -f "并发安全" -f "异常处理"

# 输出 JSON（便于接入流水线）
python -m codeguard review ./src --json > review.json

# 只要高危问题，避免被风格问题淹没
python -m codeguard review ./src --min-severity high

# CI 质量门禁：存在 high 及以上问题时返回退出码 1
python -m codeguard scan ./src --fail-on high

# 只检查指定规则
python -m codeguard scan ./src --rules CG101,CG106,CG203

# 审查后就具体问题追问（复用上下文记忆，模型记得读过哪些文件）
python -m codeguard chat examples/demo_buggy_code
```

### 退出码约定

| 退出码 | 含义 |
| --- | --- |
| `0` | 成功，且通过质量门禁 |
| `1` | 审查完成，但命中门禁（`--fail-on`）或整体风险为 critical/high |
| `2` | 用法错误 / 配置错误（如缺少 API Key、路径不存在） |
| `3` | 运行期错误（网络异常、鉴权失败等） |

---

## 项目结构

```
codeguard/
├── codeguard/                      # 主包
│   ├── __init__.py                 # 对外公开 API
│   ├── __main__.py                 # python -m codeguard 入口
│   ├── agent.py                    # ★ Agent 主循环（输入→推理→工具→观察→输出）
│   ├── llm.py                      # ★ LLM 客户端（httpx + 重试退避 + 离线 Mock）
│   ├── tools.py                    # ★ 工具层（Tool / ToolRegistry / 路径沙箱 / 7 个工具）
│   ├── static_analysis.py          # ★ 静态分析引擎（ast，27 条规则）
│   ├── prompts.py                  # ★ Prompt 设计（System / 首轮 / 动态提示）
│   ├── models.py                   # 领域模型（Finding / ReviewReport / 消息 / 用量）
│   ├── report.py                   # 报告渲染（Markdown / 文本 / JSON / CI 门禁）
│   ├── config.py                   # 配置加载（环境变量 / .env / 校验）
│   ├── exceptions.py               # 异常体系（含 retryable 语义）
│   ├── compat.py                    # 跨平台兼容（UTF-8 控制台 / 可写临时目录）
│   └── cli.py                      # 命令行界面
├── tests/                          # 测试套件（108 个用例，全部离线）
│   ├── test_static_analysis.py     # 规则引擎：正例 + 负例（误报回归）
│   ├── test_tools.py               # 工具与路径沙箱
│   ├── test_llm.py                 # LLM 客户端（MockTransport，不联网）
│   ├── test_agent.py               # Agent 闭环、自愈、兜底
│   ├── test_report_and_models.py   # 报告渲染与领域模型
│   └── test_config.py              # 配置加载与校验
├── examples/
│   ├── demo_buggy_code/            # 故意包含缺陷的示例代码
│   │   ├── user_service.py         #   安全/可靠性/可维护性问题
│   │   ├── utils.py                #   较轻的问题，演示分级
│   │   └── good_reference.py       #   规范代码，用于验证低误报
│   └── sample_report.md            # 一份完整的示例报告
├── docs/
│   ├── RULES.md                    # 内置规则手册（27 条）
│   └── PROMPT_DESIGN.md            # Prompt 设计说明与迭代思路
├── tools/
│   ├── init_repo.py                # 无需安装 Git 也能创建真正的 Git 仓库
│   ├── verify_repo.py              # 用标准库解码 .git 对象，校验仓库完整性
│   └── make_backup.py              # 打包“学号姓名.zip”备份提交物
├── Design.md                       # ★ 设计文档（架构 / 模式 / 取舍）
├── 使用方法.md                      # 完整使用说明（命令、参数、示例、CI 接入）
├── README.md                       # 本文件
├── run_tests.py                    # 零依赖测试运行器（无需 pytest）
├── verify.py                       # 端到端自检脚本
├── requirements.txt
├── pyproject.toml
└── .env.example
```

★ = 核心文件

---

## 架构设计

### 分层

```
              ┌────────────────────────────────────────┐
   接口层      │  cli.py        （review/scan/chat）     │
              └───────────────┬────────────────────────┘
                              ▼
              ┌────────────────────────────────────────┐
   Agent 层    │  agent.py      CodeReviewAgent         │
              │  · 循环编排  · 预算控制  · 自愈  · 兜底  │
              └───────┬────────────────────┬───────────┘
                      ▼                    ▼
        ┌──────────────────────┐  ┌──────────────────────┐
   LLM 层│  llm.py              │  │  tools.py            │ 工具层
        │  BaseLLMClient（抽象）│  │  Tool / ToolRegistry │
        │   ├ LLMClient（真实） │  │  PathGuard（沙箱）    │
        │   └ MockLLMClient    │  │  7 个内置工具          │
        └──────────┬───────────┘  └──────────┬───────────┘
                   ▼                         ▼
        ┌──────────────────────┐  ┌──────────────────────┐
   外部  │ DeepSeek / OpenAI /  │  │ static_analysis.py   │ 事实层
        │ 通义（兼容协议）      │  │ ast 规则引擎（27 条）  │
        └──────────────────────┘  └──────────────────────┘
```

### 关键设计点

| 设计点 | 做法 | 解决的问题 |
| --- | --- | --- |
| **依赖倒置** | Agent 只依赖 `BaseLLMClient` 抽象 | 可无缝替换为 Mock 实现，使测试与演示完全离线 |
| **事实优先** | System Prompt 强制第一步调用 `run_static_analysis` | 抑制 LLM 幻觉，让结论有客观锚点 |
| **工具自愈** | 工具异常转成观察结果回灌，而非中断循环 | 模型可自行修正参数或换工具，提升鲁棒性 |
| **预算控制** | 迭代轮数上限 + 工具调用总数上限 + 分段提示 | 防止死循环与 token 成本失控 |
| **绝不空手而归** | LLM 失败 / 预算耗尽 → 由静态分析合成兜底报告 | 任何失败路径都有可用产出 |
| **路径沙箱** | `PathGuard` 校验解析后路径是否在工作区内 | 阻止 `../../../etc/passwd` 式越权读取 |
| **结构化侧信道** | `Toolbox.tool_state` 传递完整结果 | 避免依赖已被长度上限截断的 JSON 文本 |

细节见 [`Design.md`](Design.md)。

---

## 内置工具

Agent 通过 OpenAI function-calling 协议调用以下 7 个工具：

| 工具 | 作用 | 典型用法 |
| --- | --- | --- |
| `run_static_analysis` | 运行 27 条 AST 规则，返回带行号的命中清单 | 审查第一步，建立事实基础 |
| `read_file` | 读取文件（带行号，支持窗口切片） | 查看命中位置的上下文 |
| `search_code` | 正则搜索（grep），返回 `文件:行号` | 定位危险 API、跨文件调用点 |
| `list_files` | 列目录、按扩展名过滤 | 初期了解项目结构 |
| `find_files` | glob 查找文件 | 找测试文件、配置文件 |
| `list_rules` | 查询规则手册 | 解释问题依据 |
| `submit_review` | 提交结构化报告并**终止循环** | 收敛输出 |

所有文件类工具都受 `PathGuard` 约束：**只能访问工作区目录内**的路径。

---

## 内置静态规则

共 **27 条**规则，分四类。完整手册见 [`docs/RULES.md`](docs/RULES.md)。

| 类别 | 编号段 | 数量 | 示例 |
| --- | --- | --- | --- |
| 安全 | `CG1xx` | 8 | `CG101` eval/exec、`CG102` Shell 注入、`CG105` 硬编码密钥、`CG106` SQL 注入 |
| 可靠性 | `CG2xx` | 8 | `CG201` 裸 except、`CG203` 可变默认参数、`CG205` 除零、`CG206` 资源泄漏 |
| 可维护性 | `CG3xx` | 6 | `CG301` 函数过长、`CG302` 嵌套过深、`CG305` 重复字面量 |
| 风格 | `CG4xx` | 5 | `CG401` 行长度、`CG403` 未使用导入、`CG404` 遮蔽内置名 |

规则引擎刻意**只报有把握的形态**，宁缺毋滥：例如 `subprocess.run(['ls','-l'])` 这类
安全写法会被主动排除，参数化查询 `execute(sql, (uid,))` 也不会误报。
`tests/test_static_analysis.py` 里有一半用例是**负例（误报回归）**。

---

## 测试与自检

### 运行测试

```bash
# 方式一：零依赖运行器（环境装不上 pytest 时也能跑）
python run_tests.py          # 108 个用例
python run_tests.py -v       # 显示每个用例名
python run_tests.py test_agent   # 只跑某个文件

# 方式二：pytest（若已安装）
pytest -q
```

**全部测试均离线**，不访问网络、不需要 API Key —— LLM 层用 `httpx.MockTransport`
注入伪造响应，Agent 层用 `MockLLMClient` 脚本化模型。

### 端到端自检

```bash
python verify.py
```

一条命令验证 10 项：包导入、语法编译、规则引擎识别能力、**误报回归**、7 个工具可用性、
Agent 闭环、三种报告渲染、**报告路径规范性**、CLI 退出码约定、测试套件全绿。

```
CodeGuard 端到端自检
======================================================================
  ✓ 1. 包可导入且版本可读  v1.0.0
  ✓ 2. 全部模块通过语法编译  13 个模块
  ✓ 3. 静态规则引擎识别示例缺陷  76 条命中 / 6 critical
  ✓ 4. 规范代码不产生严重误报  0 条均为 low/info
  ✓ 5. 七个工具均可调用  7 个工具
  ✓ 6. Agent 闭环（mock 模型）产出结构化报告  3 轮 / 2 次工具调用
  ✓ 7. 报告三种格式均可渲染  76 条问题
  ✓ 8. 报告中的路径是相对工作区的  首个位置：examples/demo_buggy_code/user_service.py:22
  ✓ 9. CLI 子命令与退出码符合约定  info/scan/review/rules 均正常
  ✓ 10. tests/ 目录下的测试全部通过  结果：108/108 通过，全部通过
======================================================================
自检全部通过：10/10 项 ✅
```

### 覆盖的关键场景

- **Agent 闭环**：3 轮迭代完成 `run_static_analysis → read_file → submit_review`
- **工具自愈**：工具报错（路径不存在、工具名错误、参数非法 JSON）后模型改参重试
- **兜底路径**：迟迟不提交 / LLM 鉴权失败 → 仍产出基于静态分析的报告
- **幻觉抑制**：模型第一轮想直接下结论时被动态提示拉回
- **协议正确性**：回灌消息符合 OpenAI 协议（`tool` 消息带 `tool_call_id`）
- **重试策略**：429 尊重 `Retry-After`、5xx 指数退避、401 立即失败不重试
- **安全边界**：`../` 越权路径被拒绝；密钥证据自动脱敏
- **报告规范性**：报告中的路径全部为相对形式，不泄露本机目录结构

---

## 提交与仓库

### 创建本地仓库

如果开发环境已安装 Git，直接使用常规命令即可：

```bash
git init -b main
git add .
git commit -m "feat: CodeGuard —— 基于 LLM 工具调用的代码审查 Agent"
```

如果环境**装不上 Git**（企业策略 / 离线 / 无管理员权限），本项目提供了
纯标准库实现的等价方案 —— 它按 Git 的对象格式（zlib 压缩的 blob / tree / commit）
与引用格式直接写出 `.git`，在任意装有 Git 的机器上都能正常使用：

```bash
python tools/init_repo.py --name "张三" --email "zhangsan@example.com"

# 两层校验仓库完整性：
#   第一层  标准库解码 .git 对象、核对 SHA-1（不需要 Git）
#   第二层  调用真实 Git 做权威判定（git status / fsck --strict / rev-parse）
python tools/verify_repo.py
```

> **关于索引的诚实说明**：脚本把 `.git/index` 的生成委托给本机 Git
> （`git read-tree`），因为索引条目的对齐细节无法可靠复现 —— 手写版本能被
> 自研解析器读通，却被真实 Git 拒绝（详见 [`Design.md`](Design.md) §12.7）。
> 本机没有 Git 时脚本**不写索引**并明确提示：对象与引用都正确，
> Git 首次运行时会自动重建索引。

### 推送到 GitHub / Gitee

本仓库已发布：**<https://github.com/0x697551b0/codeguard>**

```bash
# 关联远程并首次推送
git remote add origin https://github.com/0x697551b0/codeguard.git
git branch -M main
git push -u origin main

# 后续更新
git add -A && git commit -m "docs: 更新说明" && git push origin main

# 若提示需要认证：GitHub 已不支持密码推送，请使用 Personal Access Token
#   生成：GitHub → Settings → Developer settings → Personal access tokens
#   推送时用户名填 GitHub 用户名，密码栏粘贴 Token
```

> 若本地仓库被 `tools/init_repo.py --force` 重建过，历史会与远程分叉，
> 需要用 `git push --force origin main` 覆盖。

### 打包备份提交物

作业要求提交“学号姓名”的压缩包（< 200 MB）：

```bash
python tools/make_backup.py --id 2412190219 --name 刘浩天
# 产出：dist/2412190219刘浩天.zip   （解压即用，内含自动生成的《提交说明.md》）
```

打包脚本会自动排除 `.git`、`__pycache__`、临时目录、测试残留与体积过大的文件，
并**确保不包含任何密钥**（`.env` 在排除列表中，只保留 `.env.example`）。

### 交付物对照

| 作业要求 | 本项目的交付物 |
| --- | --- |
| 提交物 1：源代码仓库 | **<https://github.com/0x697551b0/codeguard>**（另附 `dist/2412190219刘浩天.zip` 备份包） |
| 提交物 2：README / Design 文档 | [`README.md`](README.md)（使用说明）+ [`Design.md`](Design.md)（设计文档）+ [`docs/`](docs/)（规则手册与 Prompt 设计） |
| 提交物 3：演示视频（可选） | 建议录制：`python -m codeguard review examples/demo_buggy_code --mock --trace` |
| 备份提交 | `python tools/make_backup.py` 生成的 `学号姓名.zip` |

---

## 配置项

优先级：**命令行参数 > 环境变量 > `.env` 文件 > 默认值**

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CODEGUARD_API_KEY` | — | **必填**（`--mock` 与 `scan` 除外） |
| `CODEGUARD_BASE_URL` | `https://api.deepseek.com` | 服务根地址，兼容任意 OpenAI 协议服务商 |
| `CODEGUARD_MODEL` | `deepseek-chat` | 模型名 |
| `CODEGUARD_TEMPERATURE` | `0.2` | 采样温度（审查任务宜低，保持一致性与严谨） |
| `CODEGUARD_MAX_ITERATIONS` | `12` | Agent 最大迭代轮数 |
| `CODEGUARD_MAX_RETRIES` | `3` | LLM 请求最大重试次数 |
| `CODEGUARD_TIMEOUT` | `90` | 单次请求超时（秒） |
| `CODEGUARD_MAX_FILE_BYTES` | `200000` | 单文件读取上限 |
| `CODEGUARD_LANG` | `zh` | 报告与提示语言（`zh` / `en`） |
| `CODEGUARD_MOCK` | `0` | 置 `1` 启用离线演示模式 |

完整示例见 [`.env.example`](.env.example)。

---

## 设计取舍

| 决策 | 选择 | 理由 |
| --- | --- | --- |
| Agent 框架 | **不用** LangChain，自己实现循环 | 作业要求"体现 Agent 设计模式"。框架会把循环、消息协议、工具分发封装掉，反而不利于展示架构能力；自己实现也让依赖降到只剩 `httpx` |
| LLM 接入 | **原生 HTTP** 而非官方 SDK | 依赖最少、协议透明、跨服务商零改动迁移 |
| 数据模型 | **`dataclasses`** 而非 pydantic | 减少依赖；本项目字段少且有大量容错解析逻辑，手写更可控 |
| 静态分析 | **自研 27 条 `ast` 规则** 而非引入 bandit/flake8 | 零依赖、规则可控、能精确控制误报；也让"工具"与"Agent"的边界更清晰 |
| 工具结果传递 | 文本给模型 + **侧信道给 Agent** | 文本受长度上限约束会被截断；结构化数据走内存槽位才可靠 |
| 演示模式 | **诚实回填**真实分析结果 | Mock 报告不编造假结论，可与 `scan` 子命令交叉验证 |

---

## 常见问题

**Q：一定要有 API Key 才能评价这个作业吗？**
不需要。`python -m codeguard review examples/demo_buggy_code --mock --trace` 可完整展示
Agent 闭环；`python verify.py` 可一键验证全部功能。真实模型的差别在于能给出语义层面的
深入结论（逻辑缺陷、业务边界等）。

**Q：模型说"没发现问题"，但我知道代码有 bug？**
两件事可做：① 用 `-f` 明确关注点，例如 `-f "这个函数在并发下是否有竞态"`；
② 提高迭代预算 `--max-iterations 20`。此外 `scan` 子命令的确定性规则结果可作为交叉验证。

**Q：报告里 low/info 条目太多，看不清重点？**
用 `--min-severity high` 只看高危问题；`--report` 写出的 Markdown/JSON 始终是**全量**的。

**Q：能审查 JavaScript / Java 吗？**
可以。`read_file` / `search_code` / `list_files` 与语言无关，LLM 也能读懂任意语言。
只有 `run_static_analysis` 的规则引擎是 Python 专用的（基于 `ast`），对其他语言会跳过，
此时审查完全依赖模型阅读 —— 这也是 Agent 与纯规则工具的核心区别。

**Q：为什么 `verify.py` 里要检查"规范代码不产生严重误报"？**
误报率是代码审查工具能否被真正采用的决定性因素。一个会把好代码判成高危的工具没人会用，
所以这条检查与"能发现问题"同等重要。

---

## 许可

本项目为课程作业，采用 MIT 许可。

## 相关文档

- [`Design.md`](Design.md) —— 详细设计文档（架构、设计模式、Agent 循环、失败处理）
- [`使用方法.md`](使用方法.md) —— 完整使用说明（命令、参数、示例、CI 接入）
- [`docs/RULES.md`](docs/RULES.md) —— 内置规则手册（27 条）
- [`docs/PROMPT_DESIGN.md`](docs/PROMPT_DESIGN.md) —— Prompt 设计说明
- [`examples/sample_report.md`](examples/sample_report.md) —— 示例审查报告
