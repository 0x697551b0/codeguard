"""
领域模型：审查发现、严重级别、审查报告、LLM 消息与用量统计。
静态分析产出 Finding，LLM 经 submit_review 产出 ReviewReport，report 模块负责渲染。全部用 dataclasses 保持零依赖。
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable

# 枚举


class Severity(str, Enum):
    """问题严重级别，与 :data:`SEVERITY_ORDER` 配合用于排序。"""

    CRITICAL = "critical"  # 安全漏洞 / 必崩
    HIGH = "high"  # 明确缺陷 / 生产事故风险
    MEDIUM = "medium"  # 潜在缺陷或可维护性问题
    LOW = "low"  # 风格与可读性
    INFO = "info"  # 提示与建议

    @classmethod
    def coerce(cls, value: Any) -> "Severity":
        """把模型返回的任意写法归一化到枚举；非法值降级为 ``INFO``。"""
        if isinstance(value, cls):
            return value
        text = str(value or "").strip().lower()
        aliases = {
            "crit": cls.CRITICAL,
            "blocker": cls.CRITICAL,
            "严重": cls.CRITICAL,
            "高": cls.HIGH,
            "error": cls.HIGH,
            "中": cls.MEDIUM,
            "warning": cls.MEDIUM,
            "warn": cls.MEDIUM,
            "低": cls.LOW,
            "minor": cls.LOW,
            "提示": cls.INFO,
            "suggestion": cls.INFO,
            "note": cls.INFO,
        }
        if text in aliases:
            return aliases[text]
        try:
            return cls(text)
        except ValueError:
            return cls.INFO

    @property
    def label_zh(self) -> str:
        return {
            Severity.CRITICAL: "严重",
            Severity.HIGH: "高",
            Severity.MEDIUM: "中",
            Severity.LOW: "低",
            Severity.INFO: "提示",
        }[self]

    @property
    def badge(self) -> str:
        """终端/Markdown 友好的彩色标记。"""
        return {
            Severity.CRITICAL: "🟥 CRITICAL",
            Severity.HIGH: "🟧 HIGH",
            Severity.MEDIUM: "🟨 MEDIUM",
            Severity.LOW: "🟩 LOW",
            Severity.INFO: "⬜ INFO",
        }[self]


#: 严重级别排序权重（越小越严重），用于报告排序
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# 发现
@dataclass
class Finding:
    """一条具体的代码问题。"""

    title: str
    severity: Severity = Severity.MEDIUM
    category: str = "general"
    file: str = ""
    line: int | None = None
    evidence: str = ""
    explanation: str = ""
    suggestion: str = ""
    #: 该条目的来源： ``static``（内置静态分析）/ ``llm``（模型阅读代码后得出）
    source: str = "llm"
    #: 静态规则 ID，例如 ``CG101``
    rule_id: str = ""
    #: 置信度 0~1，模型可给出
    confidence: float | None = None

    def __post_init__(self) -> None:
        self.severity = Severity.coerce(self.severity)
        if self.line is not None:
            try:
                self.line = int(self.line)
                if self.line <= 0:
                    self.line = None
            except (TypeError, ValueError):
                self.line = None

    @property
    def location(self) -> str:
        """``file:line`` 形式的定位字符串。"""
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        return self.file or "(未知位置)"

    @property
    def sort_key(self) -> tuple[int, str, int]:
        return (SEVERITY_ORDER.get(self.severity, 99), self.file, self.line or 0)

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, default_source: str = "llm") -> "Finding":
        """从（可能是模型生成的）字典宽松构造：显式列出中英文别名，缺失字段退化为空值而不抛异常。"""
        if not isinstance(data, dict):
            return cls(title=str(data), source=default_source)

        def pick(*names: str) -> Any:
            for name in names:
                if name in data and data[name] not in (None, ""):
                    return data[name]
            return None

        line_raw = pick("line", "line_number", "行号", "start_line")
        line: int | None
        try:
            line = int(line_raw) if line_raw is not None else None
        except (TypeError, ValueError):
            line = None

        confidence_raw = pick("confidence", "score", "置信度")
        confidence: float | None
        try:
            confidence = float(confidence_raw) if confidence_raw is not None else None
        except (TypeError, ValueError):
            confidence = None

        return cls(
            title=str(pick("title", "issue", "name", "问题", "标题") or "未命名问题"),
            severity=Severity.coerce(pick("severity", "level", "级别", "严重程度")),
            category=str(pick("category", "type", "类型", "类别") or "general"),
            file=str(pick("file", "path", "filename", "文件") or ""),
            line=line,
            evidence=str(pick("evidence", "snippet", "code", "证据", "代码片段") or ""),
            explanation=str(pick("explanation", "description", "detail", "说明", "描述") or ""),
            suggestion=str(pick("suggestion", "recommendation", "fix", "建议", "修复建议") or ""),
            source=str(pick("source") or default_source),
            rule_id=str(pick("rule_id", "rule") or ""),
            confidence=confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


# 报告
@dataclass
class ReviewReport:
    """一次代码审查的最终产出。"""

    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    positives: list[str] = field(default_factory=list)
    overall_risk: str = "unknown"
    #: 模型给出的总体评分（0~100），可选
    score: int | None = None
    #: 被审查的文件清单
    files_reviewed: list[str] = field(default_factory=list)
    #: 模型认为需要人工确认的开放问题
    open_questions: list[str] = field(default_factory=list)
    #: 运行时元数据：模型名、耗时、token 用量、迭代轮数等
    meta: dict[str, Any] = field(default_factory=dict)
    #: 报告生成时间（UTC，ISO 8601）
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "ReviewReport":
        """从 ``submit_review`` 工具参数构造报告。"""
        if not isinstance(payload, dict):
            return cls(summary=str(payload))

        findings_raw = payload.get("findings") or payload.get("issues") or []
        if isinstance(findings_raw, dict):
            findings_raw = [findings_raw]
        findings = [
            Finding.from_dict(item) for item in findings_raw if isinstance(item, (dict, str))
        ]
        findings.sort(key=lambda f: f.sort_key)

        def str_list(*names: str) -> list[str]:
            for name in names:
                value = payload.get(name)
                if isinstance(value, str) and value.strip():
                    return [value.strip()]
                if isinstance(value, list):
                    return [str(v).strip() for v in value if str(v).strip()]
            return []

        score_raw = payload.get("score") or payload.get("评分")
        try:
            score = int(score_raw) if score_raw is not None else None
            if score is not None:
                score = max(0, min(100, score))
        except (TypeError, ValueError):
            score = None

        return cls(
            summary=str(payload.get("summary") or payload.get("总结") or ""),
            findings=findings,
            positives=str_list("positives", "highlights", "优点"),
            overall_risk=str(payload.get("overall_risk") or payload.get("risk") or "unknown"),
            score=score,
            files_reviewed=str_list("files_reviewed", "files", "审查文件"),
            open_questions=str_list("open_questions", "questions", "待确认问题"),
        )

    def merge_findings(self, findings: Iterable[Finding], *, dedupe: bool = True) -> int:
        """合并外部发现（通常是静态分析结果），返回新增条数。去重键为 (file, line, 归一化标题)。"""
        if not dedupe:
            merged = list(findings)
            self.findings.extend(merged)
            return len(merged)

        seen = {self._dedupe_key(f) for f in self.findings}
        added = 0
        for finding in findings:
            key = self._dedupe_key(finding)
            if key in seen:
                continue
            seen.add(key)
            self.findings.append(finding)
            added += 1
        self.findings.sort(key=lambda f: f.sort_key)
        return added

    @staticmethod
    def _dedupe_key(finding: Finding) -> tuple[str, int | None, str]:
        title = "".join(ch for ch in finding.title.lower() if ch.isalnum() or "\u4e00" <= ch <= "\u9fff")
        return (finding.file, finding.line, title[:24])

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def has_blocking_issues(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "overall_risk": self.overall_risk,
            "score": self.score,
            "counts": self.counts_by_severity,
            "findings": [f.to_dict() for f in self.findings],
            "positives": self.positives,
            "files_reviewed": self.files_reviewed,
            "open_questions": self.open_questions,
            "meta": self.meta,
            "generated_at": self.generated_at,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


# LLM 消息与用量
@dataclass
class ToolCall:
    """模型请求的一次工具调用。"""

    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    #: 参数不是合法 JSON 时保留原始字符串，便于把错误回灌给模型
    raw_arguments: str = ""

    def to_message_part(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": self.raw_arguments
                or json.dumps(self.arguments, ensure_ascii=False),
            },
        }


@dataclass
class ChatMessage:
    """与 OpenAI /chat/completions 协议对齐的消息。to_payload 只输出协议需要的字段。"""

    role: str
    content: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"role": self.role}
        # assistant 带 tool_calls 时 content 允许为 null；其他情况输出字符串
        payload["content"] = self.content if self.content is not None else ("" if self.role != "assistant" else None)
        if self.tool_calls:
            payload["tool_calls"] = [tc.to_message_part() for tc in self.tool_calls]
        if self.tool_call_id:
            payload["tool_call_id"] = self.tool_call_id
        if self.name:
            payload["name"] = self.name
        return payload

    @property
    def tool_names(self) -> list[str]:
        return [tc.name for tc in self.tool_calls]


@dataclass
class TokenUsage:
    """累计 token 用量，用于展示成本与调试。"""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    calls: int = 0

    def add(self, other: "TokenUsage" | None) -> None:
        if other is None:
            return
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens or (other.prompt_tokens + other.completion_tokens)
        self.calls += other.calls or 1

    def to_dict(self) -> dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "calls": self.calls,
        }

    def __str__(self) -> str:
        return (
            f"{self.calls} 次调用 / prompt={self.prompt_tokens} "
            f"completion={self.completion_tokens} total={self.total_tokens}"
        )


@dataclass
class LLMResponse:
    """对 LLM 一次响应的规范化封装。"""

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: TokenUsage | None = None
    finish_reason: str = ""
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def truncated(self) -> bool:
        return self.finish_reason == "length"

    def to_message(self) -> ChatMessage:
        return ChatMessage(role="assistant", content=self.content or None, tool_calls=self.tool_calls)
