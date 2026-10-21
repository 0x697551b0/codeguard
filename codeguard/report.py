"""
报告渲染：把 ReviewReport 输出为 Markdown / 纯文本 / JSON。
CLI、交互会话、CI 共用同一套渲染；每条问题标注 static（规则引擎）或 llm（语义分析）以标明结论来源。
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from codeguard.models import Finding, ReviewReport, Severity

if TYPE_CHECKING:  # pragma: no cover - 仅用于类型检查，避免运行期无用导入
    from typing import Sequence

#: 各严重级别对应的 emoji，兼顾 GitHub 与终端显示
_SEVERITY_ICON = {
    Severity.CRITICAL: "🟥",
    Severity.HIGH: "🟧",
    Severity.MEDIUM: "🟨",
    Severity.LOW: "🟩",
    Severity.INFO: "⬜",
}

_RISK_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "clean": "✅",
    "unknown": "⚪",
}

_SOURCE_LABEL = {"static": "规则引擎", "llm": "语义分析"}


# Markdown
def render_markdown(report: ReviewReport, *, title: str = "CodeGuard 代码审查报告", include_rules_appendix: bool = False) -> str:
    """渲染为 Markdown。按章节拆成 _md_overview / _md_findings / _md_appendix 等小函数，便于单独调整。"""
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"> 生成时间：{report.generated_at}　|　模型：`{report.meta.get('model', 'N/A')}`")
    lines.append("")

    lines.extend(_md_overview(report))
    lines.extend(_md_findings(report))

    if report.positives:
        lines.append("## 三、值得肯定的设计")
        lines.append("")
        lines.extend(f"- {item}" for item in report.positives)
        lines.append("")

    if report.open_questions:
        lines.append("## 四、需要人工确认")
        lines.append("")
        lines.extend(f"- [ ] {item}" for item in report.open_questions)
        lines.append("")

    lines.extend(_md_appendix(report))
    if include_rules_appendix:
        lines.extend(_render_rules_appendix())

    lines.append("---")
    lines.append("")
    lines.append("_本报告由 CodeGuard 生成。规则引擎结果可能存在误报，语义结论请结合业务上下文复核。_")
    return "\n".join(lines)


def _md_overview(report: ReviewReport) -> list[str]:
    """渲染"总体结论 + 问题分布"章节。"""
    counts = report.counts_by_severity
    risk = report.overall_risk.lower()
    lines = [
        "## 一、总体结论",
        "",
        f"**整体风险等级：{_RISK_ICON.get(risk, '⚪')} {risk.upper()}**",
    ]
    if report.score is not None:
        lines.append(f"**代码质量评分：{report.score} / 100**")
    lines.append("")
    lines.append(report.summary.strip() if report.summary else "_（模型未提供总体结论）_")
    lines.append("")
    lines.extend(["### 问题分布", "", "| 严重级别 | 数量 |", "| --- | ---: |"])
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        lines.append(f"| {_SEVERITY_ICON[severity]} {severity.value.upper()} | {counts[severity.value]} |")
    lines.append(f"| **合计** | **{len(report.findings)}** |")
    lines.append("")
    return lines


def _md_findings(report: ReviewReport) -> list[str]:
    """渲染"问题清单"章节。"""
    total = len(report.findings)
    lines = [f"## 二、问题清单（{total} 条）", ""]
    if not report.findings:
        lines.extend(["✅ 未发现需要修改的问题。", ""])
        return lines
    for index, finding in enumerate(report.findings, start=1):
        lines.extend(_render_finding(index, finding))
    return lines


def _md_appendix(report: ReviewReport) -> list[str]:
    """渲染附录：审查范围与运行指标。"""
    lines = ["## 附录", "", "**审查范围：**", ""]
    for path in report.files_reviewed or ["（未记录）"]:
        lines.append(f"- `{path}`")
    lines.append("")

    usage = report.meta.get("usage") or {}
    lines.extend(["**运行指标：**", "", "| 指标 | 值 |", "| --- | --- |"])
    lines.append(f"| 迭代轮数 | {report.meta.get('iterations', 'N/A')} |")
    lines.append(f"| 工具调用次数 | {report.meta.get('tool_calls', 'N/A')} |")
    calls = report.meta.get("tool_call_breakdown") or {}
    if calls:
        breakdown = "、".join(f"{name}×{count}" for name, count in sorted(calls.items()) if count)
        lines.append(f"| 工具明细 | {breakdown} |")
    lines.append(
        f"| Token 用量 | {usage.get('total_tokens', 'N/A')}"
        f"（prompt {usage.get('prompt_tokens', 0)} / completion {usage.get('completion_tokens', 0)}） |"
    )
    lines.append(f"| 耗时 | {report.meta.get('elapsed_seconds', 'N/A')} 秒 |")
    lines.append(f"| 结束原因 | `{report.meta.get('stopped_reason', 'N/A')}` |")
    if report.meta.get("mock"):
        lines.append("| 模式 | 离线 Mock（未调用真实模型） |")
    lines.append("")
    return lines


def _render_finding(index: int, finding: Finding) -> list[str]:
    """渲染单条问题（Markdown）。"""
    icon = _SEVERITY_ICON.get(finding.severity, "⬜")
    source = _SOURCE_LABEL.get(finding.source, finding.source or "未知")
    rule = f" `{finding.rule_id}`" if finding.rule_id else ""
    lines = [
        f"### {index}. {icon} {finding.title}",
        "",
        f"- **位置：** `{finding.location}`",
        f"- **级别：** {finding.severity.value.upper()}　|　**类别：** {finding.category}　|　**来源：** {source}{rule}",
    ]
    if finding.confidence is not None:
        lines.append(f"- **置信度：** {finding.confidence:.2f}")
    lines.append("")

    if finding.evidence:
        lines.append("```python")
        lines.append(finding.evidence.strip())
        lines.append("```")
        lines.append("")
    if finding.explanation:
        lines.append(f"**问题说明：** {finding.explanation.strip()}")
        lines.append("")
    if finding.suggestion:
        lines.append(f"**修复建议：** {finding.suggestion.strip()}")
        lines.append("")
    return lines


def _render_rules_appendix() -> list[str]:
    """渲染规则手册附录。"""
    from codeguard.static_analysis import rules_table

    lines = ["## 附录：内置静态规则清单", "", "| 规则 ID | 标题 | 类别 | 默认级别 | 说明 |", "| --- | --- | --- | --- | --- |"]
    for rule in rules_table():
        lines.append(
            f"| `{rule['rule_id']}` | {rule['title']} | {rule['category']} | {rule['severity']} | {rule['description']} |"
        )
    lines.append("")
    return lines


# 终端文本（无 Markdown 依赖的降级渲染）
def render_text(report: ReviewReport, *, min_severity: str = "info") -> str:
    """
    渲染为彩色终端文本。
    min_severity 只显示不低于该级别的条目（low/info 过多时用 --min-severity medium 聚焦重点）。
    """
    visible, hidden = _filter_by_severity(report, min_severity)
    counts = report.counts_by_severity
    risk = report.overall_risk.lower()
    width = 72

    lines = [
        "═" * width,
        " CodeGuard 代码审查报告".ljust(width - 1),
        "═" * width,
        f" 整体风险：{_RISK_ICON.get(risk, '⚪')} {risk.upper()}"
        + (f"    评分：{report.score}/100" if report.score is not None else ""),
        f" 问题总数：{len(report.findings)}"
        f"　(严重 {counts['critical']} / 高 {counts['high']} / 中 {counts['medium']}"
        f" / 低 {counts['low']} / 提示 {counts['info']})",
        "─" * width,
        "",
        "【总体结论】",
        _wrap(report.summary or "（无）", width),
        "",
    ]
    lines.extend(_text_findings(visible, hidden, report, min_severity, width))

    if report.positives:
        lines.append("【值得肯定】")
        lines.extend(f"  · {item}" for item in report.positives)
        lines.append("")

    if report.open_questions:
        lines.append("【需要人工确认】")
        lines.extend(f"  ? {item}" for item in report.open_questions)
        lines.append("")

    usage = report.meta.get("usage") or {}
    lines.extend(
        [
            "─" * width,
            f" 迭代 {report.meta.get('iterations', '?')} 轮 | 工具调用 {report.meta.get('tool_calls', '?')} 次"
            f" | tokens {usage.get('total_tokens', '?')} | {report.meta.get('elapsed_seconds', '?')}s"
            f" | 结束原因 {report.meta.get('stopped_reason', '?')}",
            "═" * width,
        ]
    )
    return "\n".join(lines)


#: 严重级别的排序权重（越小越严重），用于 --min-severity 过滤
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _filter_by_severity(report: ReviewReport, min_severity: str) -> tuple[list[Finding], int]:
    """按 min_severity 过滤显示条目，返回 (可见条目, 被隐藏的条目数)。"""
    threshold = _SEVERITY_RANK.get(str(min_severity).lower(), 4)
    visible = [
        finding
        for finding in report.findings
        if _SEVERITY_RANK.get(finding.severity.value, 9) <= threshold
    ]
    return visible, len(report.findings) - len(visible)


def _text_findings(
    visible: list[Finding],
    hidden: int,
    report: ReviewReport,
    min_severity: str,
    width: int,
) -> list[str]:
    """渲染终端报告的问题清单段落。"""
    lines: list[str] = []
    if not visible:
        if report.findings:
            lines.append(
                f"✅ 在 {min_severity} 及以上级别未发现问题"
                f"（共 {len(report.findings)} 条更低级别记录）。"
            )
        else:
            lines.append("✅ 未发现需要修改的问题。")
        lines.append("")
        return lines

    header = f"【问题清单】显示 {len(visible)} 条"
    if hidden:
        header += f"（另有 {hidden} 条低于 {min_severity} 的记录，见 Markdown/JSON 报告）"
    lines.extend([header, ""])

    for index, finding in enumerate(visible, start=1):
        icon = _SEVERITY_ICON.get(finding.severity, "⬜")
        source = _SOURCE_LABEL.get(finding.source, "")
        lines.append(f"  {index}. {icon} [{finding.severity.value.upper()}] {finding.title}")
        lines.append(f"     位置：{finding.location}　来源：{source}")
        if finding.evidence:
            lines.append(f"     代码：{finding.evidence.strip().splitlines()[0][:100]}")
        if finding.explanation:
            lines.append(f"     说明：{_wrap(finding.explanation.strip(), width - 11).strip()}")
        if finding.suggestion:
            lines.append(f"     建议：{_wrap(finding.suggestion.strip(), width - 11).strip()}")
        lines.append("")
    return lines


def _wrap(text: str, width: int, *, indent: str = "      ") -> str:
    """按显示宽度折行（对中文字符按 2 列计算）。"""
    if width <= 8:
        width = 8
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        if not paragraph.strip():
            lines.append("")
            continue
        current = ""
        current_width = 0
        for char in paragraph:
            char_width = 2 if _is_wide(char) else 1
            if current_width + char_width > width:
                lines.append(indent + current)
                current, current_width = "", 0
            current += char
            current_width += char_width
        if current:
            lines.append(indent + current)
    return "\n".join(lines)


def _is_wide(char: str) -> bool:
    """判断字符是否占两个显示列（CJK 及全角标点）。"""
    code = ord(char)
    return (
        0x1100 <= code <= 0x115F
        or 0x2E80 <= code <= 0xA4CF
        or 0xAC00 <= code <= 0xD7A3
        or 0xF900 <= code <= 0xFAFF
        or 0xFE30 <= code <= 0xFE6F
        or 0xFF00 <= code <= 0xFF60
        or 0xFFE0 <= code <= 0xFFE6
    )


# JSON / SARIF 风格的结构化输出
def render_json(report: ReviewReport, *, indent: int = 2) -> str:
    """渲染为 JSON（UTF-8 原样保留中文）。"""
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=indent)


def render_ci_summary(report: ReviewReport, *, fail_on: str = "high") -> tuple[bool, str]:
    """生成 CI 质量门禁结论，返回 (是否通过, 一行结论)。fail_on 为 none 时关闭门禁。"""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    key = fail_on.strip().lower()
    if key in {"none", "off", "false", "disabled"}:
        # 关闭门禁：任何问题都不拦截（仍返回问题总数供参考）
        return True, f"✅ 质量门禁已关闭（--fail-on none）：共记录 {len(report.findings)} 条问题"
    threshold = order.get(key, 1)
    blocking = [f for f in report.findings if order.get(f.severity.value, 9) <= threshold]
    if blocking:
        return False, (
            f"❌ 质量门禁未通过：存在 {len(blocking)} 条不低于 {fail_on} 的问题"
            f"（最严重：{blocking[0].severity.value.upper()} {blocking[0].location} {blocking[0].title}）"
        )
    return True, f"✅ 质量门禁通过：无不低于 {fail_on} 的问题（共 {len(report.findings)} 条记录）"


def write_report(
    report: ReviewReport,
    path: str,
    *,
    fmt: str = "",
    include_rules_appendix: bool = False,
    min_severity: str = "info",
) -> str:
    """把报告写入文件并按扩展名推断格式。min_severity 只影响 txt 展示，Markdown/JSON 始终写全量。"""
    from pathlib import Path

    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    suffix = (fmt or file_path.suffix.lstrip(".")).lower()
    if suffix == "json":
        content = render_json(report)
    elif suffix in {"txt", "text"}:
        content = render_text(report, min_severity=min_severity)
    else:
        content = render_markdown(report, include_rules_appendix=include_rules_appendix)
    file_path.write_text(content, encoding="utf-8")
    return str(file_path)


def summarize_for_prompt(report: ReviewReport, *, max_findings: int = 10) -> str:
    """把报告压缩成一段摘要，用于后续追问时作为上下文。"""
    lines = [
        f"整体风险：{report.overall_risk}；问题数：{len(report.findings)}",
        f"总结：{report.summary[:800]}",
    ]
    for finding in report.findings[:max_findings]:
        lines.append(f"- [{finding.severity.value}] {finding.location} {finding.title}")
    return "\n".join(lines)
