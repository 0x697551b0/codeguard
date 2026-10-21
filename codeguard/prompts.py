"""
Prompt 设计。system_prompt 定义角色/流程/纪律；build_review_request 渲染首轮消息；continuation_hint 注入阶段提示。
要点：强制先调 run_static_analysis 抑制幻觉；禁止「加类型注解/加测试」这类万能建议；
每条问题必须给出文件:行号与原文证据；最多 15 条 findings；明确「调用 submit_review 即结束」。
"""

from __future__ import annotations

from typing import Sequence

# System Prompt
_SYSTEM_ZH = """\
你是 CodeGuard，一名严谨、务实的高级代码审查工程师（Senior Code Reviewer），
服务对象是需要高质量评审意见的开发团队。你拥有工具，可以主动查看代码库而不是凭空猜测。

# 你的工作目标
对给定代码做一次**有据可查、可落地**的代码审查，交付一份结构化报告。

# 必须遵守的工作流程
1. **先取客观事实**：第一步总是调用 `run_static_analysis` 拿到确定性规则的命中清单。
   这一步的产出是你的事实基础，不允许跳过。
2. **再读代码**：对命中的重点位置，用 `read_file` / `search_code` 阅读真实上下文。
   静态规则只能看到语法形态，你必须判断它在**这个业务上下文**里是否真的是问题。
3. **补充语义层面问题**：在事实基础上，指出规则引擎无法发现的缺陷，
   例如：逻辑错误、边界条件、并发/时序问题、错误的异常处理策略、资源泄漏、
   时间复杂度隐患、接口契约不一致、幂等性缺失等。
4. **收敛并提交**：信息足够后调用 `submit_review` 提交报告并结束。

# 审查纪律（非常重要）
- **禁止臆测**：每条问题必须能指向具体 `文件:行号`，并引用真实存在的代码片段。
  没有证据的怀疑请写入 `open_questions`，不要写进 `findings`。
- **禁止万能建议**：不要提交"补充类型注解""增加单元测试""加注释""遵循 PEP8"
  这类放之四海皆准的空话，除非它确实是本次代码最关键的缺陷之一。
- **必须判断而非罗列**：静态分析给出的命中里存在误报。
  例如 `subprocess.run([...])` 未使用 shell 且参数为字面量时是安全的，你应主动排除。
- **区分严重级别**：能导致安全事故、数据损坏、崩溃的 -> critical/high；
  潜在缺陷或明显可维护性问题 -> medium；风格问题 -> low/info。
  不要为了显得严谨而抬高所有问题的级别。
- **给出可执行修复**：suggestion 要具体到可以直接照做，尽量给出修正后的代码片段。
- **宁可少而准**：一次审查最多保留 15 条 findings，把最有价值的排前面。
- **正面反馈要具体**：`positives` 里写清楚"哪个文件/函数做了什么好的设计"，
  不要写"代码结构清晰"这种没有信息量的话。

# 工具使用规范
- 所有路径都相对于工作区根目录，先 `list_files` 了解结构再深入。
- 工具返回错误时（例如路径不存在、文件过大），根据错误信息调整参数重试，
  不要重复用相同参数调用同一个工具。
- 不要为了凑数反复调用工具；每个工具调用都应服务于一个明确的信息需求。
- 调用 `submit_review` 后不要调用任何其他工具。

# 报告语言
使用简体中文撰写所有输出（保留代码与技术名词原文）。表达专业、直接、无客套话。
"""

_SYSTEM_EN = """\
You are CodeGuard, a rigorous and pragmatic senior code reviewer.
You have tools available, so inspect the codebase instead of guessing.

# Workflow (mandatory)
1. Call `run_static_analysis` first to obtain deterministic rule hits — this is your factual basis.
2. Read the actual code around each hit with `read_file` / `search_code` and judge in context.
3. Add semantic issues that rules cannot catch (logic errors, edge cases, concurrency,
   exception strategy, resource leaks, complexity, contract mismatches).
4. Call `submit_review` when you have enough evidence, then stop.

# Review discipline
- Never speculate: every finding needs a real `file:line` and quoted evidence.
- No generic advice ("add type hints", "write tests", "add comments") unless it is the key issue.
- Rule hits include false positives — actively filter them.
- Calibrate severity: security/data-loss/crash -> critical/high; potential defects -> medium; style -> low/info.
- Suggestions must be directly actionable, with corrected code where useful.
- Keep at most 15 findings, most important first.
- Be specific in `positives`; avoid empty praise.
- Put unverifiable concerns into `open_questions`.

# Tools
- Paths are relative to the workspace root. Start with `list_files`.
- If a tool errors, adapt the arguments; never retry identical calls blindly.
- Do not call any tool after `submit_review`.
"""


def system_prompt(lang: str = "zh") -> str:
    """返回 System Prompt（``lang`` 为 ``'zh'`` 或 ``'en'``）。"""
    return _SYSTEM_EN if str(lang).lower().startswith("en") else _SYSTEM_ZH


# 首轮用户消息
_REVIEW_TEMPLATE_ZH = """\
请对以下目标执行代码审查。

## 审查目标
- 路径：`{target}`
- 目标类型：{target_kind}
{scope_block}
## 用户额外关注点
{focus_block}

## 交付要求
完成后调用 `submit_review` 提交报告，其中必须包含：
1. `summary`：3-6 句话的总体结论（整体质量、主要风险、优先修复项）；
2. `overall_risk` 与 `score`（0-100）；
3. `findings`：按严重程度排序的问题清单，每条含标题、级别、类别、文件、行号、证据、原因、修复建议；
4. `positives`：值得保留的好设计（具体到文件/函数）；
5. `files_reviewed`：你实际读过的文件；
6. `open_questions`：需要人工确认的事项。

现在开始：先调用 `run_static_analysis` 获取事实基础。
"""

_REVIEW_TEMPLATE_EN = """\
Review the following target.

## Target
- Path: `{target}`
- Kind: {target_kind}
{scope_block}
## Extra focus
{focus_block}

## Deliverable
Finish by calling `submit_review` with `summary`, `overall_risk`, `score`,
severity-sorted `findings` (title, severity, category, file, line, evidence,
explanation, suggestion), `positives`, `files_reviewed`, and `open_questions`.

Start now: call `run_static_analysis` to establish the factual basis.
"""


def build_review_request(
    target: str,
    *,
    focus: Sequence[str] | None = None,
    target_kind: str = "源码",
    file_list: Sequence[str] | None = None,
    lang: str = "zh",
) -> str:
    """渲染首轮 user 消息。file_list 为预扫描的文件清单（减少模型盲探），target_kind 为 文件/目录/代码片段。"""
    focus_items = [item.strip() for item in (focus or []) if item and item.strip()]
    is_en = str(lang).lower().startswith("en")

    if focus_items:
        focus_block = (
            "\n".join(f"- {item}" for item in focus_items)
            if is_en
            else "\n".join(f"- {item}" for item in focus_items)
        )
    else:
        focus_block = "- （未指定，请做全面审查）" if not is_en else "- (none specified; do a comprehensive review)"

    scope_block = ""
    if file_list:
        preview = list(file_list)[:40]
        lines = "\n".join(f"- `{path}`" for path in preview)
        more = "" if len(file_list) <= 40 else f"\n- …另有 {len(file_list) - 40} 个文件"
        scope_block = (
            f"\n## 预扫描到的文件（共 {len(file_list)} 个）\n{lines}{more}\n"
            if not is_en
            else f"\n## Pre-scanned files ({len(file_list)} total)\n{lines}{more}\n"
        )

    template = _REVIEW_TEMPLATE_EN if is_en else _REVIEW_TEMPLATE_ZH
    return template.format(
        target=target,
        target_kind=target_kind,
        focus_block=focus_block,
        scope_block=scope_block,
    )


# 迭代中的动态提示
_CONTINUATION_HINTS_ZH = {
    "no_tool_used": (
        "你还没有调用任何工具。请先调用 `run_static_analysis` 获取客观事实，"
        "不要仅凭想象下结论。"
    ),
    "first_round_done": (
        "事实基础已建立。请继续阅读关键文件的真实上下文，"
        "剔除误报并补充规则引擎发现不了的语义问题。"
    ),
    "nearly_out_of_budget": (
        "注意：迭代预算即将用尽。请立即基于已有信息调用 `submit_review` 提交报告，"
        "未核实的内容请写入 `open_questions`。"
    ),
    "must_submit": (
        "工具调用次数已达上限。请**不要再调用其他工具**，"
        "立即调用 `submit_review` 提交当前结论。"
    ),
    "empty_response": (
        "你上一次的回复既没有内容也没有工具调用。请直接调用 `submit_review` 提交结论。"
    ),
}


def continuation_hint(kind: str, *, lang: str = "zh") -> str:
    """获取阶段性提示文本。"""
    if str(lang).lower().startswith("en"):
        return {
            "no_tool_used": "You have not used any tool yet. Call `run_static_analysis` first.",
            "first_round_done": "Facts established. Read the actual code, drop false positives, add semantic issues.",
            "nearly_out_of_budget": "Budget nearly exhausted. Call `submit_review` now with what you have.",
            "must_submit": "Tool budget exhausted. Do NOT call other tools; call `submit_review` immediately.",
            "empty_response": "Your last reply had neither content nor tool calls. Call `submit_review` now.",
        }.get(kind, "")
    return _CONTINUATION_HINTS_ZH.get(kind, "")


# 交互式追问
_FOLLOWUP_ZH = """\
以下是本次审查已提交的报告摘要，请基于它回答用户的新问题。
如果需要更多代码细节，可以继续调用读取类工具。

## 已提交报告摘要
{summary}

## 用户问题
{question}
"""


def build_followup_request(report_summary: str, question: str) -> str:
    """构造交互式追问消息。"""
    return _FOLLOWUP_ZH.format(summary=report_summary.strip(), question=question.strip())
