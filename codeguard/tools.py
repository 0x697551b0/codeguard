"""工具层：Agent 与外部世界交互的接口。

架构说明：
    * :class:`Tool`           —— 单个工具的定义（元数据 + JSON Schema + 执行体）
    * :class:`ToolRegistry`   —— 注册表，负责生成 OpenAI function-calling 定义并分发调用
    * :func:`build_default_registry` —— 组装 CodeGuard 的默认工具集

所有文件类工具都通过 :class:`~codeguard.tools.PathGuard` 做沙箱约束，
确保 Agent 只能读取授权的目录，避免 ``../../etc/passwd`` 式的越界访问。

工具执行失败一律抛出 :class:`~codeguard.exceptions.ToolError`，由 Agent
捕获后**作为观察结果回灌给模型**，实现“工具报错 → 模型自我修正”的闭环。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence
from codeguard.exceptions import ToolArgumentError, ToolError, ToolNotFoundError
from codeguard.models import Finding, ReviewReport, Severity
from codeguard.static_analysis import RULE_INDEX, CodeAnalyzer, rules_table

# --------------------------------------------------------------------------- #
# 基础抽象
# --------------------------------------------------------------------------- #
@dataclass
class Tool:
    """一个可供 LLM 调用的工具。

    Attributes:
        name: 工具名，需符合 ``^[a-zA-Z0-9_-]{1,64}$``，将出现在模型请求中。
        description: 给模型看的自然语言说明 —— 写得好坏直接决定模型选对工具的概率。
        parameters: JSON Schema（object 根），描述入参。
        func: 实际执行函数，接收关键字参数并返回任意可 JSON 序列化的结果。
        requires_approval: 是否属于有副作用的工具（本项目的审查工具全部只读）。
    """

    name: str
    description: str
    parameters: dict[str, Any]
    func: Callable[..., Any]
    requires_approval: bool = False

    def to_openai_schema(self) -> dict[str, Any]:
        """转成 OpenAI ``tools`` 数组里的单个元素。"""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def invoke(self, arguments: Mapping[str, Any] | None = None) -> Any:
        """执行工具，把底层异常统一包装成 :class:`ToolError`。"""
        kwargs = dict(arguments or {})
        try:
            return self.func(**kwargs)
        except ToolError:
            raise
        except TypeError as exc:
            raise ToolArgumentError(f"工具 {self.name} 参数不匹配：{exc}") from exc
        except Exception as exc:  # noqa: BLE001 - 工具层必须兜底，避免拖垮 Agent 循环
            raise ToolError(f"工具 {self.name} 执行失败（{type(exc).__name__}）：{exc}") from exc


class ToolRegistry:
    """工具注册表：注册、查询、生成 schema、分发调用。"""

    def __init__(self, tools: Sequence[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools or ():
            self.register(tool)
        #: 调用计数，用于统计与预算控制
        self.call_counts: dict[str, int] = {}

    # ------------------------------------------------------------------ #
    def register(self, tool: Tool) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", tool.name):
            raise ValueError(f"非法工具名：{tool.name!r}")
        if tool.name in self._tools:
            raise ValueError(f"工具名重复注册：{tool.name}")
        self._tools[tool.name] = tool
        self.call_counts.setdefault(tool.name, 0)

    def unregister(self, name: str) -> None:
        self._tools.pop(name, None)

    def get(self, name: str) -> Tool:
        tool = self._tools.get(name)
        if tool is None:
            available = ", ".join(sorted(self._tools)) or "(空)"
            raise ToolNotFoundError(f"未注册的工具 `{name}`。可用工具：{available}")
        return tool

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    @property
    def names(self) -> list[str]:
        return sorted(self._tools)

    def all(self) -> list[Tool]:
        return [self._tools[name] for name in self.names]

    def schemas(self, *, exclude: Sequence[str] = ()) -> list[dict[str, Any]]:
        """生成传给 LLM 的 ``tools`` 参数。"""
        excluded = set(exclude)
        return [tool.to_openai_schema() for tool in self.all() if tool.name not in excluded]

    def invoke(self, name: str, arguments: Mapping[str, Any] | None = None) -> Any:
        """按名字调用工具并记录计数。"""
        tool = self.get(name)
        self.call_counts[name] = self.call_counts.get(name, 0) + 1
        return tool.invoke(arguments)

    def total_calls(self) -> int:
        return sum(self.call_counts.values())


# --------------------------------------------------------------------------- #
# 路径沙箱
# --------------------------------------------------------------------------- #
class PathGuard:
    """路径安全护栏。

    所有文件工具都必须经由此类解析路径。它保证：
        * 相对路径基于 ``workspace_root`` 解析（而非进程 cwd，避免语义漂移）；
        * 解析后（含符号链接）必须仍位于 ``workspace_root`` 之内；
        * 可通过 ``allowed_roots`` 额外放行若干目录。
    """

    def __init__(self, workspace_root: str | Path, *, allowed_roots: Sequence[str | Path] = ()) -> None:
        self.root = Path(workspace_root).expanduser().resolve()
        self.allowed: list[Path] = []
        for extra in allowed_roots:
            try:
                self.allowed.append(Path(extra).expanduser().resolve())
            except OSError:  # pragma: no cover - 极端路径
                continue

    def resolve(self, raw_path: str, *, must_exist: bool = True) -> Path:
        """把用户/模型给的路径解析为绝对路径并做越界校验。"""
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ToolArgumentError("path 不能为空")

        candidate = Path(raw_path.strip()).expanduser()
        if not candidate.is_absolute():
            candidate = self.root / candidate

        try:
            resolved = candidate.resolve()
        except OSError as exc:
            raise ToolArgumentError(f"路径无法解析：{raw_path}（{exc}）") from exc

        if not self._is_inside(resolved):
            raise ToolArgumentError(
                f"拒绝访问工作区之外的路径：{raw_path}\n"
                f"允许的根目录为：{self.root}"
            )
        if must_exist and not resolved.exists():
            raise ToolArgumentError(f"路径不存在：{resolved}")
        return resolved

    def _is_inside(self, path: Path) -> bool:
        roots = [self.root, *self.allowed]
        for root in roots:
            if path == root or root in path.parents:
                return True
        return False

    def display(self, path: Path) -> str:
        """转成相对工作区的展示路径，让报告更易读。"""
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()


# --------------------------------------------------------------------------- #
# 截断辅助
# --------------------------------------------------------------------------- #
def truncate(text: str, limit: int, *, note: str = "…（内容过长，已截断）") -> str:
    """统一的输出截断，避免超长工具结果挤爆上下文窗口。"""
    if limit <= 0 or len(text) <= limit:
        return text
    return text[:limit] + f"\n{note} 原始长度 {len(text)} 字符，上限 {limit}。"


def _json_schema(properties: dict[str, Any], required: Sequence[str] = (), *, additional: bool = False) -> dict[str, Any]:
    """生成 object 根 JSON Schema 的小工具。"""
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": additional,
    }


# --------------------------------------------------------------------------- #
# 工具箱
# --------------------------------------------------------------------------- #
@dataclass
class Toolbox:
    """工具注册表 + 侧信道槽位。

    有些工具需要把**结构化结果**交给 Agent，但不能通过返回值传递
    （``submit_review`` 必须给模型一句简短确认语；``run_static_analysis``
    的文本结果可能因长度上限被截断，无法再解析回 JSON）。
    因此这里提供一个显式的内存槽位，让工具把原始数据"放"出来。
    """

    registry: ToolRegistry
    #: ``submit_review`` 提交的报告
    submission: dict[str, Any] = field(default_factory=dict)
    #: 工具执行过程中留下的结构化中间结果，键为工具名
    tool_state: dict[str, Any] = field(default_factory=dict)

    @property
    def report(self) -> ReviewReport | None:
        report = self.submission.get("report")
        return report if isinstance(report, ReviewReport) else None

    @property
    def last_static_analysis(self) -> dict[str, Any] | None:
        """最近一次 ``run_static_analysis`` 的完整结构化结果。"""
        state = self.tool_state.get("run_static_analysis")
        return state if isinstance(state, dict) else None

    def clear(self) -> None:
        self.submission.clear()
        self.tool_state.clear()


# --------------------------------------------------------------------------- #
# 默认工具集
# --------------------------------------------------------------------------- #
def build_default_registry(
    *,
    workspace_root: str | Path,
    max_file_bytes: int = 200_000,
    max_output_chars: int = 20_000,
    analyzer: CodeAnalyzer | None = None,
    allowed_roots: Sequence[str | Path] = (),
) -> Toolbox:
    """组装 CodeGuard 的默认工具集，返回 :class:`Toolbox`。

    工具清单（覆盖作业要求的“至少一种工具”，这里给出 7 种）：
        ==================== ==========================================
        工具                  作用
        ==================== ==========================================
        ``list_files``       浏览目录结构、按扩展名过滤
        ``read_file``        读取文件内容（行号窗口 / 范围切片）
        ``search_code``      正则搜索（grep），返回 ``file:line`` 命中
        ``find_files``       glob 查找文件
        ``run_static_analysis`` 对文件/目录运行内置 AST 规则引擎
        ``list_rules``       查询规则手册，便于模型解释依据
        ``submit_review``    提交结构化审查报告并终止循环
        ==================== ==========================================
    """
    guard = PathGuard(workspace_root, allowed_roots=allowed_roots)
    engine = analyzer or CodeAnalyzer()

    # ------------------------------------------------------------------ #
    # 工具函数定义
    #
    # 下面 7 个函数都是定义在 build_default_registry 内部的闭包，
    # 这样它们能直接捕获 guard / engine / submission 等上下文，
    # 无需把这些依赖在模块级传来传去。
    # 随后通过 Tool(...) 把"元数据 + JSON Schema + 执行体"注册进注册表 ——
    # 这种"一处定义、就近注册"的写法让新增工具只需照抄一个块。
    # （因此本函数较长：它是一张工具清单，而不是嵌套逻辑。）
    # ------------------------------------------------------------------ #
    # 1. list_files：浏览目录结构，掌握项目全貌
    # ------------------------------------------------------------------ #
    def list_files(
        path: str = ".",
        extension: str = ".py",
        max_entries: int = 100,
        recursive: bool = False,
    ) -> dict[str, Any]:
        """列出目录内容，可按扩展名过滤。"""
        directory = guard.resolve(path)
        if not directory.is_dir():
            raise ToolArgumentError(f"不是目录：{guard.display(directory)}")
        try:
            max_entries = max(1, min(int(max_entries), 500))
        except (TypeError, ValueError):
            max_entries = 100

        skip_dirs = {
            ".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache",
            ".pytest_cache", ".ruff_cache", "build", "dist", ".idea", ".vscode",
        }
        suffix = extension.strip()
        if suffix and not suffix.startswith("."):
            suffix = f".{suffix}"
        want_all = suffix.lower() in {"", ".", "*", "all"}

        files: list[dict[str, Any]] = []
        directories: list[str] = []
        iterator: Iterator[Path]
        if recursive:
            iterator = (
                p
                for p in sorted(directory.rglob("*"))
                if not any(part in skip_dirs for part in p.relative_to(directory).parts)
            )
        else:
            iterator = iter(sorted(directory.iterdir()))

        for entry in iterator:
            name = entry.name
            if entry.is_dir():
                if name in skip_dirs or name.startswith("."):
                    continue
                directories.append(guard.display(entry) + "/")
                continue
            if not want_all and entry.suffix != suffix:
                continue
            try:
                size = entry.stat().st_size
            except OSError:
                size = 0
            files.append({"path": guard.display(entry), "size_bytes": size})
            if len(files) >= max_entries:
                break

        return {
            "directory": guard.display(directory),
            "subdirectories": directories[:max_entries],
            "files": files,
            "file_count": len(files),
            "truncated": len(files) >= max_entries,
        }

    # ------------------------------------------------------------------ #
    # 2. read_file
    # ------------------------------------------------------------------ #
    def read_file(path: str, start_line: int = 1, end_line: int = 0, max_bytes: int = 0) -> dict[str, Any]:
        """读取文件内容，带行号。

        为避免单次工具结果撑爆上下文窗口，这里做**两级限制**：
            1. 先按行数窗口裁剪（模型可用 start_line/end_line 精确取段）；
            2. 再按输出字符上限裁剪行数，并在返回值里说明被裁剪的原因。
        关键点是**不能在 JSON 值中间截断字符串** —— 那样回灌给模型的就是
        非法 JSON，会引发难以排查的解析问题。
        """
        file_path = guard.resolve(path)
        if file_path.is_dir():
            raise ToolArgumentError(f"是目录而非文件：{guard.display(file_path)}")

        byte_limit = int(max_bytes) or max_file_bytes
        try:
            size = file_path.stat().st_size
        except OSError as exc:
            raise ToolError(f"无法读取文件信息：{exc}") from exc
        if size > byte_limit:
            raise ToolError(
                f"文件过大（{size} 字节 > 上限 {byte_limit} 字节）：{guard.display(file_path)}。"
                "请改用 search_code 精确定位，或调整 --max-file-bytes。"
            )

        text = _read_text(file_path)
        lines = text.splitlines()
        try:
            start = max(1, int(start_line))
            end = int(end_line) if end_line else len(lines)
        except (TypeError, ValueError):
            raise ToolArgumentError("start_line/end_line 必须是整数") from None
        if end < start:
            end = start

        window = lines[start - 1 : end]

        # 按输出预算裁剪行数（每行按平均行长估算，再逐步收缩直到满足上限）
        total_chars = sum(len(line) + 8 for line in window)
        trimmed_reason = ""
        if max_output_chars > 0 and total_chars > max_output_chars:
            average = max(1, total_chars // max(1, len(window)))
            keep = max(1, max_output_chars // average)
            window = window[:keep]
            end = start + len(window) - 1
            trimmed_reason = (
                f"输出上限 {max_output_chars} 字符，本次只返回 {len(window)} 行；"
                "请用 start_line/end_line 分段读取，或用 search_code 精确定位。"
            )

        numbered = "\n".join(f"{start + offset:>5} | {line}" for offset, line in enumerate(window))
        result: dict[str, Any] = {
            "path": guard.display(file_path),
            "total_lines": len(lines),
            "shown_range": [start, start + len(window) - 1] if window else [0, 0],
            "content": numbered,
            "truncated": end < len(lines),
        }
        if trimmed_reason:
            result["truncation_note"] = trimmed_reason
        return result

    # ------------------------------------------------------------------ #
    # 3. search_code
    # ------------------------------------------------------------------ #
    def search_code(
        path: str = ".",
        pattern: str = "",
        extension: str = ".py",
        max_results: int = 40,
        case_sensitive: bool = False,
        context_lines: int = 0,
    ) -> dict[str, Any]:
        """在文件中做正则搜索（grep）。"""
        if not pattern:
            raise ToolArgumentError("pattern 不能为空")
        try:
            regex = re.compile(pattern, 0 if case_sensitive else re.IGNORECASE)
        except re.error as exc:
            raise ToolArgumentError(f"正则表达式非法：{exc}") from None

        root = guard.resolve(path)
        try:
            max_results = max(1, min(int(max_results), 200))
            context_lines = max(0, min(int(context_lines), 5))
        except (TypeError, ValueError):
            max_results, context_lines = 40, 0

        suffix = extension.strip()
        if suffix and not suffix.startswith("."):
            suffix = f".{suffix}"
        want_all = suffix.lower() in {"", ".", "*", "all"}

        candidates: list[Path]
        if root.is_file():
            candidates = [root]
        else:
            candidates = [p for p in sorted(root.rglob("*")) if p.is_file()]
            if not want_all:
                candidates = [p for p in candidates if p.suffix == suffix]

        matches: list[dict[str, Any]] = []
        scanned = 0
        for file_path in candidates:
            if len(matches) >= max_results:
                break
            if any(part in {".git", "__pycache__", "node_modules", ".venv", "venv"} for part in file_path.parts):
                continue
            try:
                if file_path.stat().st_size > max_file_bytes:
                    continue
                text = _read_text(file_path)
            except (OSError, ToolError):
                continue
            scanned += 1
            lines = text.splitlines()
            for index, line in enumerate(lines, start=1):
                if regex.search(line):
                    item: dict[str, Any] = {
                        "file": guard.display(file_path),
                        "line": index,
                        "text": line.strip()[:240],
                    }
                    if context_lines:
                        lo = max(0, index - 1 - context_lines)
                        hi = min(len(lines), index + context_lines)
                        item["context"] = [f"{lo + i + 1:>5} | {lines[lo + i]}" for i in range(hi - lo)]
                    matches.append(item)
                    if len(matches) >= max_results:
                        break

        return {
            "pattern": pattern,
            "files_scanned": scanned,
            "match_count": len(matches),
            "truncated": len(matches) >= max_results,
            "matches": matches,
        }

    # ------------------------------------------------------------------ #
    # 4. find_files
    # ------------------------------------------------------------------ #
    def find_files(path: str = ".", pattern: str = "*.py", max_results: int = 100) -> dict[str, Any]:
        """按 glob 模式查找文件。"""
        root = guard.resolve(path)
        if not pattern or any(token in pattern for token in ("..", ":")):
            raise ToolArgumentError("pattern 必须是相对 glob 模式，例如 `**/*.py`")
        try:
            max_results = max(1, min(int(max_results), 500))
        except (TypeError, ValueError):
            max_results = 100

        found: list[str] = []
        skip_dirs = {".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache", ".pytest_cache"}
        for candidate in sorted(root.glob(pattern)):
            if any(part in skip_dirs for part in candidate.parts):
                continue
            if candidate.is_file():
                found.append(guard.display(candidate))
            if len(found) >= max_results:
                break
        return {"pattern": pattern, "root": guard.display(root), "count": len(found), "files": found}

    # ------------------------------------------------------------------ #
    # 5. run_static_analysis
    # ------------------------------------------------------------------ #
    def run_static_analysis(
        path: str = ".",
        rules: Sequence[str] | str | None = None,
        min_severity: str = "info",
        recursive: bool = True,
    ) -> dict[str, Any]:
        """对文件或目录运行内置 AST 规则引擎，返回客观命中清单。"""
        target = guard.resolve(path)

        rule_filter: Sequence[str] | None
        if isinstance(rules, str):
            rule_filter = [r.strip() for r in rules.split(",") if r.strip()]
        elif isinstance(rules, (list, tuple)):
            rule_filter = [str(r).strip() for r in rules if str(r).strip()]
        else:
            rule_filter = None

        if rule_filter:
            unknown = [r for r in rule_filter if r not in RULE_INDEX]
            if unknown:
                raise ToolArgumentError(
                    f"未知规则 ID：{', '.join(unknown)}。可用规则见 list_rules 工具。"
                )

        engine_for_call = CodeAnalyzer(rules=rule_filter) if rule_filter else engine
        summary = engine_for_call.analyze_path(target, recursive=bool(recursive))

        threshold = _severity_rank(min_severity)
        kept = [f for f in summary.findings if _severity_rank(f.severity.value) <= threshold]

        by_rule: dict[str, int] = {}
        for finding in kept:
            by_rule[finding.rule_id] = by_rule.get(finding.rule_id, 0) + 1

        result = {
            "target": guard.display(target),
            "files_analyzed": len(summary.files),
            "files_with_errors": [guard.display(Path(f.path)) for f in summary.files if f.parse_error],
            "skipped": summary.skipped,
            "total_findings": len(kept),
            "counts_by_severity": _count_by_severity(kept),
            "counts_by_rule": dict(sorted(by_rule.items())),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "category": f.category,
                    "title": f.title,
                    # 报告里统一用相对工作区的路径，避免泄露本机目录结构
                    "file": guard.display(Path(f.file)) if f.file else "",
                    "line": f.line,
                    "evidence": f.evidence,
                    "explanation": f.explanation,
                    "suggestion": f.suggestion,
                }
                for f in kept[:120]
            ],
            "note": "以上为确定性静态规则结果；请结合代码上下文判断是否为真实缺陷，避免误报。",
        }
        # 侧信道留一份完整结果：文本结果可能被长度上限截断，无法再解析回 JSON
        tool_state["run_static_analysis"] = result
        return result

    # ------------------------------------------------------------------ #
    # 6. list_rules
    # ------------------------------------------------------------------ #
    def list_rules(category: str = "", rule_id: str = "") -> dict[str, Any]:
        """查询内置规则手册。"""
        table = rules_table()
        if rule_id:
            rule = RULE_INDEX.get(rule_id.strip().upper())
            if rule is None:
                raise ToolArgumentError(f"未知规则 ID：{rule_id}")
            return {
                "rule": {
                    "rule_id": rule.rule_id,
                    "title": rule.title,
                    "category": rule.category,
                    "severity": rule.severity.value,
                    "description": rule.description,
                }
            }
        if category:
            table = [r for r in table if r["category"].lower() == category.strip().lower()]
        return {"count": len(table), "rules": table}

    # ------------------------------------------------------------------ #
    # 7. submit_review（终止工具）
    # ------------------------------------------------------------------ #
    #: 侧信道槽位：让工具把结构化结果交给 Agent，而不是塞进给模型看的文本里
    submission: dict[str, Any] = {}
    tool_state: dict[str, Any] = {}

    def submit_review(
        summary: str = "",
        findings: Sequence[Mapping[str, Any]] | None = None,
        positives: Sequence[str] | None = None,
        open_questions: Sequence[str] | None = None,
        files_reviewed: Sequence[str] | None = None,
        overall_risk: str = "unknown",
        score: int | None = None,
    ) -> dict[str, Any]:
        """提交最终审查报告（调用本工具即表示审查结束）。"""
        payload: dict[str, Any] = {
            "summary": summary,
            "findings": [dict(item) for item in (findings or []) if isinstance(item, Mapping)],
            "positives": list(positives or []),
            "open_questions": list(open_questions or []),
            "files_reviewed": list(files_reviewed or []),
            "overall_risk": overall_risk,
            "score": score,
        }
        report = ReviewReport.from_payload(payload)
        submission.clear()
        submission["report"] = report
        return {
            "status": "accepted",
            "findings_received": len(report.findings),
            "message": "报告已收到，审查流程结束。请用一句话向用户总结结论（无需重复报告全文）。",
        }

    # ------------------------------------------------------------------ #
    registry = ToolRegistry()
    registry.register(
        Tool(
            name="list_files",
            description=(
                "列出目录下的文件与子目录，可按扩展名过滤。"
                "用于在审查初期快速掌握项目结构。"
            ),
            parameters=_json_schema(
                {
                    "path": {"type": "string", "description": "目录路径，相对工作区根目录，默认 '.'"},
                    "extension": {"type": "string", "description": "扩展名过滤，例如 '.py'；传 '*' 表示不过滤", "default": ".py"},
                    "recursive": {"type": "boolean", "description": "是否递归子目录", "default": False},
                    "max_entries": {"type": "integer", "description": "返回条目上限（1-500）", "default": 100},
                },
            ),
            func=list_files,
        )
    )
    registry.register(
        Tool(
            name="read_file",
            description=(
                "读取单个文本文件的内容（带行号）。"
                "大文件请用 start_line/end_line 指定窗口，避免一次读入过多内容。"
            ),
            parameters=_json_schema(
                {
                    "path": {"type": "string", "description": "文件路径，相对工作区根目录"},
                    "start_line": {"type": "integer", "description": "起始行（从 1 开始）", "default": 1},
                    "end_line": {"type": "integer", "description": "结束行；0 表示到文件末尾", "default": 0},
                    "max_bytes": {"type": "integer", "description": "允许读取的最大字节数；0 表示使用默认上限", "default": 0},
                },
                ["path"],
            ),
            func=read_file,
        )
    )
    registry.register(
        Tool(
            name="search_code",
            description=(
                "在所有文件中用正则表达式搜索（类似 grep），返回 `文件:行号` 命中与匹配行内容。"
                "适合定位危险 API、配置项、TODO 或跨文件调用点。"
            ),
            parameters=_json_schema(
                {
                    "pattern": {"type": "string", "description": "Python 正则表达式，例如 'eval\\\\(|exec\\\\('"},
                    "path": {"type": "string", "description": "搜索起点（文件或目录），默认 '.'", "default": "."},
                    "extension": {"type": "string", "description": "只搜索该扩展名；'*' 表示全部", "default": ".py"},
                    "case_sensitive": {"type": "boolean", "description": "是否区分大小写", "default": False},
                    "max_results": {"type": "integer", "description": "最多返回多少条命中（1-200）", "default": 40},
                    "context_lines": {"type": "integer", "description": "每条命中附加上下文行数（0-5）", "default": 0},
                },
                ["pattern"],
            ),
            func=search_code,
        )
    )
    registry.register(
        Tool(
            name="find_files",
            description="按 glob 模式查找文件，例如 '**/test_*.py'、'src/*.ts'。",
            parameters=_json_schema(
                {
                    "pattern": {"type": "string", "description": "glob 模式，例如 '**/*.py'", "default": "*.py"},
                    "path": {"type": "string", "description": "查找根目录", "default": "."},
                    "max_results": {"type": "integer", "description": "结果上限（1-500）", "default": 100},
                },
            ),
            func=find_files,
        )
    )
    registry.register(
        Tool(
            name="run_static_analysis",
            description=(
                "对文件或目录运行内置 AST 静态规则引擎（含安全/可靠性/可维护性/风格共 30+ 条规则），"
                "返回带行号、规则 ID、严重级别的客观命中清单。"
                "这是最可靠的起点：先用它拿到事实，再结合上下文判断与补充语义层面问题。"
            ),
            parameters=_json_schema(
                {
                    "path": {"type": "string", "description": "文件或目录路径，默认 '.'", "default": "."},
                    "rules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "只运行指定规则 ID（如 ['CG101','CG203']）；不传表示全部规则",
                    },
                    "min_severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "只返回不低于该级别的结果，默认 info（全部）",
                        "default": "info",
                    },
                    "recursive": {"type": "boolean", "description": "目录是否递归分析", "default": True},
                },
            ),
            func=run_static_analysis,
        )
    )
    registry.register(
        Tool(
            name="list_rules",
            description="查询内置静态规则手册（规则 ID、标题、类别、默认严重级别、说明）。不传参数返回全部规则。",
            parameters=_json_schema(
                {
                    "category": {"type": "string", "description": "按类别过滤：security/reliability/maintainability/style"},
                    "rule_id": {"type": "string", "description": "查询单条规则，例如 'CG101'"},
                },
            ),
            func=list_rules,
        )
    )
    registry.register(
        Tool(
            name="submit_review",
            description=(
                "提交最终代码审查报告并结束整个审查流程。"
                "当你已完成必要的信息收集后调用本工具；调用后不要再调用其他工具。"
                "findings 只保留你有把握的真实问题，并按严重程度排序。"
            ),
            parameters=_json_schema(
                {
                    "summary": {"type": "string", "description": "3-6 句话的总体结论：代码整体质量、主要风险、最优先修复项"},
                    "overall_risk": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "clean"],
                        "description": "整体风险等级",
                    },
                    "score": {"type": "integer", "description": "代码质量评分 0-100（可选）"},
                    "positives": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "写得好的地方（具体到文件/函数，避免空泛夸奖）",
                    },
                    "files_reviewed": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "实际审查过的文件路径列表",
                    },
                    "open_questions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "需要人工确认或缺少上下文无法判断的问题",
                    },
                    "findings": {
                        "type": "array",
                        "description": "问题清单，按严重程度从高到低排列",
                        "items": _json_schema(
                            {
                                "title": {"type": "string", "description": "一句话问题描述"},
                                "severity": {
                                    "type": "string",
                                    "enum": ["critical", "high", "medium", "low", "info"],
                                    "description": "严重级别",
                                },
                                "category": {
                                    "type": "string",
                                    "description": "类别：security / reliability / maintainability / style / performance",
                                },
                                "file": {"type": "string", "description": "文件路径"},
                                "line": {"type": "integer", "description": "行号；无法确定时省略"},
                                "evidence": {"type": "string", "description": "相关代码片段（原文摘录，勿编造）"},
                                "explanation": {"type": "string", "description": "为什么会出问题，触发条件与后果"},
                                "suggestion": {"type": "string", "description": "可落地的修复建议，最好给出修正后的代码"},
                                "rule_id": {"type": "string", "description": "若来自静态分析，填写对应规则 ID 如 CG101"},
                                "confidence": {"type": "number", "description": "置信度 0-1"},
                            },
                            ["title", "severity"],
                        ),
                    },
                },
                ["summary", "findings"],
            ),
            func=submit_review,
        )
    )

    # 让 Agent 能在循环结束后取回报告
    return Toolbox(registry=registry, submission=submission, tool_state=tool_state)


# --------------------------------------------------------------------------- #
# 辅助函数
# --------------------------------------------------------------------------- #
_SEVERITY_RANK = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 3,
    Severity.INFO.value: 4,
}


def _severity_rank(value: str) -> int:
    return _SEVERITY_RANK.get(str(value).lower(), 4)


def _count_by_severity(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {sev.value: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def _read_text(path: Path) -> str:
    """读取文本，UTF-8 优先、GBK 兜底。"""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="gbk")
        except (UnicodeDecodeError, OSError) as exc:
            raise ToolError(f"文件编码无法识别：{path.name}（{exc}）") from exc
    except OSError as exc:
        raise ToolError(f"读取失败：{path.name}（{exc}）") from exc


def dumps_tool_result(result: Any, *, limit: int = 20_000) -> str:
    """把工具返回值序列化成回灌给模型的字符串。"""
    if isinstance(result, str):
        text = result
    else:
        try:
            text = json.dumps(result, ensure_ascii=False, indent=2, default=str)
        except (TypeError, ValueError):
            text = str(result)
    return truncate(text, limit)
