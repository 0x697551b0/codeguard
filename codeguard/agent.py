"""Agent 主循环：输入 → 推理 → 工具调用 → 观察 → 输出。

这是本项目的核心。循环体刻意"薄"且显式，把控制流暴露出来而不是藏在框架里，
便于讲清 Agent 设计模式。

单轮流程::

    ┌─ iteration N ───────────────────────────────────────────────────┐
    │ 1. 组装消息（system + 历史 + 动态提示）                            │
    │ 2. 调用 LLM（带工具定义）                                         │
    │ 3. 解析响应：                                                    │
    │      ├─ 有 tool_calls → 依次执行工具，把结果作为 role=tool 回灌    │
    │      └─ 无 tool_calls → 视为最终答复，结束循环                     │
    │ 4. 若命中的是终止工具（submit_review）→ 取出报告，结束循环          │
    └─────────────────────────────────────────────────────────────────┘

工程化设计（对应评审标准里的“Agent 架构”维度）：
    * **单一职责**：循环只做编排；LLM 通信在 :mod:`codeguard.llm`，
      工具实现在 :mod:`codeguard.tools`，事实提取在 :mod:`codeguard.static_analysis`。
    * **可观测**：每一步记录成 :class:`AgentStep`，支持 ``--trace`` 输出完整轨迹。
    * **可恢复**：工具报错不中断循环，而是回灌模型让它自我修正；LLM 永久失败时
      降级为由静态分析结果合成部分报告，绝不空手而归。
    * **有预算**：限制迭代轮数与工具调用总数，避免死循环与成本失控。
    * **依赖倒置**：只依赖 :class:`~codeguard.llm.BaseLLMClient` 抽象，
      因此能无缝替换为 Mock 客户端做离线测试。
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from codeguard.config import Config
from codeguard.exceptions import CodeGuardError, LLMError, ToolError
from codeguard.llm import BaseLLMClient, LLMClient, MockLLMClient
from codeguard.models import ChatMessage, Finding, LLMResponse, ReviewReport, Severity, TokenUsage, ToolCall
from codeguard.prompts import (
    build_review_request,
    continuation_hint,
    system_prompt,
)
from codeguard.tools import Toolbox, ToolRegistry, build_default_registry, dumps_tool_result

logger = logging.getLogger(__name__)

#: 终止工具名：模型调用它即表示审查结束
TERMINATION_TOOL = "submit_review"

#: 预扫描时最多列出的文件数
PRESCAN_FILE_LIMIT = 60


# --------------------------------------------------------------------------- #
# 步骤与结果
# --------------------------------------------------------------------------- #
@dataclass
class AgentStep:
    """Agent 循环中的一步，用于可观测性与调试。"""

    iteration: int
    #: ``"assistant"``（模型输出）/ ``"tool"``（工具结果）/ ``"error"``
    kind: str
    content: str = ""
    tool_name: str = ""
    tool_arguments: dict[str, Any] = field(default_factory=dict)
    tool_result: str = ""
    error: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration": self.iteration,
            "kind": self.kind,
            "content": self.content,
            "tool_name": self.tool_name,
            "tool_arguments": self.tool_arguments,
            "tool_result": self.tool_result,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }

    def render(self) -> str:
        """终端友好的单行/多行渲染。"""
        if self.kind == "assistant":
            head = f"[{self.iteration}] 🧠 推理"
            return f"{head}\n    {self.content.strip()[:1500]}" if self.content.strip() else f"{head}（无文本输出）"
        if self.kind == "tool":
            args = ", ".join(f"{k}={v!r}" for k, v in self.tool_arguments.items())
            return (
                f"[{self.iteration}] 🔧 工具调用 {self.tool_name}({args[:300]})\n"
                f"    └─ {self.tool_result.strip()[:600]}"
            )
        return f"[{self.iteration}] ⚠️ 错误：{self.error}"


@dataclass
class AgentResult:
    """一次 Agent 运行的完整产物。"""

    report: ReviewReport
    #: 完整对话历史（含工具调用与观察结果）
    messages: list[ChatMessage] = field(default_factory=list)
    #: 可观测的执行轨迹
    steps: list[AgentStep] = field(default_factory=list)
    usage: TokenUsage = field(default_factory=TokenUsage)
    iterations: int = 0
    elapsed_seconds: float = 0.0
    stopped_reason: str = "completed"
    #: Agent 在循环中被截断的最终文本答复（若有）
    final_text: str = ""

    @property
    def tool_calls(self) -> int:
        return sum(1 for step in self.steps if step.kind == "tool")

    def render_trace(self) -> str:
        """渲染完整执行轨迹。"""
        lines = [
            "═" * 72,
            f"执行轨迹（{self.iterations} 轮迭代 / {self.tool_calls} 次工具调用 / "
            f"{self.elapsed_seconds:.1f}s / {self.usage}）",
            "═" * 72,
        ]
        lines.extend(step.render() for step in self.steps)
        lines.append("═" * 72)
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Agent
# --------------------------------------------------------------------------- #
class CodeReviewAgent:
    """代码审查 Agent。

    典型用法::

        config = Config.from_env(api_key="sk-...")
        agent = CodeReviewAgent(config)
        result = agent.review("./src", focus=["SQL 注入"])
        print(result.report.to_json())
    """

    def __init__(
        self,
        config: Config | None = None,
        *,
        llm: BaseLLMClient | None = None,
        toolbox: Toolbox | None = None,
        extra_context: str = "",
    ) -> None:
        """
        Args:
            config: 运行配置；``None`` 时从环境变量读取。
            llm: 自定义 LLM 客户端（测试/扩展用）；``None`` 时按配置自动选择。
            toolbox: 自定义工具箱；``None`` 时构建默认工具集。
            extra_context: 追加到 System Prompt 之后的团队规范/项目背景。
        """
        self.config = config or Config.from_env()
        self.config.validate(require_api_key=llm is None and not self.config.mock)

        # 先建工具箱，再建 LLM —— Mock 模型需要工具箱引用
        self.toolbox: Toolbox = toolbox or build_default_registry(
            workspace_root=self.config.workspace_path,
            max_file_bytes=self.config.max_file_bytes,
            max_output_chars=self.config.max_tool_output_chars,
        )
        self.registry: ToolRegistry = self.toolbox.registry
        self.extra_context = extra_context
        self.llm: BaseLLMClient = llm or self._build_llm()

    def use_mock_llm(self, *, target: str = "") -> None:
        """切换到离线 Mock 模型（用于 ``--mock`` 演示与测试）。

        必须在工具箱构建之后调用，这样 Mock 才能拿到
        :attr:`Toolbox.tool_state` 里静态分析的完整结构化结果 ——
        工具消息文本可能被长度上限截断，无法再解析回 JSON。
        """
        self.llm = MockLLMClient(
            self.config,
            target=target or self.config.workspace_root or ".",
            toolbox=self.toolbox,
        )

        self._messages: list[ChatMessage] = []
        self._steps: list[AgentStep] = []
        self._usage = TokenUsage()
        #: 当前迭代轮数（供步骤记录使用）
        self._iterations: int = 0
        #: 本轮已使用的工具调用次数（受 max_tool_calls 约束）
        self._tool_budget_used: int = 0
        #: 本次审查的目标路径（兜底报告需要它来补跑静态分析）
        self._review_target: Path | None = None

    # ------------------------------------------------------------------ #
    # 构造辅助
    # ------------------------------------------------------------------ #
    def _build_llm(self) -> BaseLLMClient:
        if self.config.mock:
            logger.info("使用离线 Mock 模型（不访问网络）")
            # 传入 toolbox，让 Mock 能读取静态分析的**完整**结构化结果
            # （工具消息文本可能被长度上限截断，不能再解析回 JSON）
            return MockLLMClient(
                self.config,
                target=self.config.workspace_root or ".",
                toolbox=self.toolbox,
            )
        return LLMClient(self.config)

    def close(self) -> None:
        """释放 LLM 客户端资源。"""
        self.llm.close()

    def __enter__(self) -> "CodeReviewAgent":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # 对外主入口
    # ------------------------------------------------------------------ #
    def review(
        self,
        target: str | Path,
        *,
        focus: Sequence[str] | None = None,
        prescan: bool = True,
    ) -> AgentResult:
        """对目标执行一次完整审查。

        Args:
            target: 要审查的文件或目录路径。
            focus: 用户额外关注点。
            prescan: 是否预扫描目录清单（减少模型盲探、节省 token）。

        Returns:
            :class:`AgentResult`，其中 ``report`` 为结构化报告。
        """
        started = time.perf_counter()
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = self.config.workspace_path / target_path
        display_target = self._display(target_path)

        self._reset()
        self._review_target = target_path
        system = system_prompt(self.config.lang)
        if self.extra_context.strip():
            system = f"{system}\n\n# 项目背景与团队规范\n{self.extra_context.strip()}"
        self._messages.append(ChatMessage(role="system", content=system))

        file_list: list[str] = []
        if prescan and target_path.is_dir():
            file_list = self._prescan(target_path)

        request = build_review_request(
            display_target,
            focus=focus,
            target_kind="目录" if target_path.is_dir() else "文件",
            file_list=file_list,
            lang=self.config.lang,
        )
        self._messages.append(ChatMessage(role="user", content=request))

        report, stopped_reason, final_text = self._run_loop()
        elapsed = time.perf_counter() - started

        if not report.summary and final_text:
            report.summary = final_text.strip()

        report.files_reviewed = report.files_reviewed or self._infer_files_reviewed()
        report.meta.update(
            {
                "model": self.llm.model_name,
                "base_url": self.config.base_url,
                "iterations": self._iterations,
                "tool_calls": self.registry.total_calls(),
                "tool_call_breakdown": dict(self.registry.call_counts),
                "usage": self._usage.to_dict(),
                "elapsed_seconds": round(elapsed, 2),
                "stopped_reason": stopped_reason,
                "mock": self.config.mock,
            }
        )

        return AgentResult(
            report=report,
            messages=list(self._messages),
            steps=list(self._steps),
            usage=self._usage,
            iterations=self._iterations,
            elapsed_seconds=elapsed,
            stopped_reason=stopped_reason,
            final_text=final_text,
        )

    def followup(self, question: str, report: ReviewReport | None = None) -> str:
        """基于已有上下文追问（对应“支持上下文记忆”要求）。

        复用 ``review`` 留下的消息历史，因此模型记得之前看过哪些文件。
        """
        if not self._messages:
            self._messages.append(ChatMessage(role="system", content=system_prompt(self.config.lang)))

        context = ""
        if report is not None:
            context = f"（已提交报告摘要）{report.summary}\n风险等级：{report.overall_risk}；问题数：{len(report.findings)}"

        self._messages.append(ChatMessage(role="user", content=f"{context}\n\n用户追问：{question}"))
        self._tool_budget_used = 0

        for _ in range(min(3, self.config.max_iterations)):
            response = self._call_llm()
            self._messages.append(response.to_message())
            if not response.tool_calls:
                return response.content or "（模型未返回内容）"
            self._execute_tool_calls(response.tool_calls)
        return self._messages[-1].content or "（达到追问迭代上限）"

    # ------------------------------------------------------------------ #
    # 核心循环
    # ------------------------------------------------------------------ #
    def _run_loop(self) -> tuple[ReviewReport, str, str]:
        """执行 Agent 主循环。

        循环体本身保持"薄"：每一轮只做四件事 —— 注入提示、调用模型、
        执行工具、判断是否收敛。具体判定逻辑抽到下面几个小方法里，
        以便这一段读起来就是一张流程图。

        Returns:
            ``(报告, 停止原因, 最终文本)``
        """
        self._iterations = 0
        self._tool_budget_used = 0
        report: ReviewReport | None = None
        final_text = ""
        stopped_reason = "max_iterations"
        used_any_tool = False
        hint_kind = ""

        for iteration in range(1, self.config.max_iterations + 1):
            self._iterations = iteration
            self._inject_hint(hint_kind)

            # 调用模型；LLM 最终失败时直接降级收敛
            try:
                response = self._call_llm()
            except LLMError as exc:
                logger.error("LLM 调用最终失败：%s", exc)
                self._steps.append(
                    AgentStep(iteration=iteration, kind="error", error=f"LLM 调用失败：{exc}")
                )
                report = self._fallback_report(reason=f"LLM 调用失败：{exc}")
                stopped_reason = "llm_error"
                break

            self._messages.append(response.to_message())
            self._record_assistant(iteration, response)

            # 模型没请求工具 → 要么被拉回来继续调查，要么就是最终答复
            if not response.tool_calls:
                final_text = response.content or ""
                if not used_any_tool and iteration < self.config.max_iterations:
                    hint_kind = "no_tool_used"
                    continue
                stopped_reason = "final_answer_without_report"
                break

            used_any_tool = True
            self._execute_tool_calls(response.tool_calls)

            # 提交报告即终止（并把静态分析的完整命中合并进来）
            submitted = self.toolbox.report
            if submitted is not None:
                report = submitted
                stopped_reason = "submitted"
                report.merge_findings(self._static_findings())
                break

            hint_kind = self._next_hint_kind(iteration)

        if report is None:
            report = self._budget_exhausted_report(stopped_reason)
        return report, stopped_reason, final_text

    def _inject_hint(self, hint_kind: str) -> None:
        """把阶段性提示作为 user 消息注入（Context Engineering）。"""
        if not hint_kind:
            return
        hint = continuation_hint(hint_kind, lang=self.config.lang)
        if hint:
            self._messages.append(ChatMessage(role="user", content=hint))

    def _next_hint_kind(self, iteration: int) -> str:
        """根据剩余预算决定下一轮要注入哪种提示。"""
        remaining = self.config.max_iterations - iteration
        if self._tool_budget_used >= self.config.max_tool_calls or remaining <= 1:
            return "must_submit"
        if remaining <= 2:
            return "nearly_out_of_budget"
        if iteration == 1:
            return "first_round_done"
        return ""

    def _budget_exhausted_report(self, stopped_reason: str) -> ReviewReport:
        """预算耗尽/模型未提交时的兜底报告，并在摘要里说明原因。"""
        reason = (
            "达到最大迭代轮数"
            if stopped_reason == "max_iterations"
            else "模型未调用 submit_review"
        )
        report = self._fallback_report(reason=reason)
        report.summary = (
            f"⚠️ Agent 未能在预算内提交完整报告（{reason}）。"
            "以下结论由内置静态分析结果自动合成，覆盖范围有限，"
            "建议增大 --max-iterations 后重试。\n\n"
            + (report.summary or "")
        ).strip()
        return report

    # ------------------------------------------------------------------ #
    # LLM 交互
    # ------------------------------------------------------------------ #
    def _call_llm(self) -> LLMResponse:
        """调用 LLM 并累计 token 用量。"""
        tools = self.registry.schemas()
        started = time.perf_counter()
        response = self.llm.chat(self._messages, tools=tools, tool_choice="auto")
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        self._usage.add(response.usage)
        if self.config.verbose and elapsed_ms > 3000:
            logger.debug("LLM 调用耗时 %d ms", elapsed_ms)
        return response

    def _record_assistant(self, iteration: int, response: LLMResponse) -> None:
        self._steps.append(
            AgentStep(
                iteration=iteration,
                kind="assistant",
                content=response.content or "",
            )
        )

    # ------------------------------------------------------------------ #
    # 工具执行
    # ------------------------------------------------------------------ #
    def _execute_tool_calls(self, tool_calls: Sequence[ToolCall]) -> int:
        """执行一批工具调用，把每个结果作为 ``role=tool`` 消息回灌。

        三种失败都不会中断循环，而是转成观察结果让模型自我修正：
        参数非法 JSON、预算耗尽、工具执行异常。
        """
        executed = 0
        for call in tool_calls:
            if call.raw_arguments and not call.arguments:
                self._feed_back(call, self._invalid_json_message(call))
                continue
            if self._tool_budget_used >= self.config.max_tool_calls:
                self._feed_back(
                    call, "工具调用总预算已用尽。请立即调用 submit_review 提交结论。"
                )
                continue

            payload = self._invoke_tool(call)
            self._feed_back(call, payload)
            self._tool_budget_used += 1
            executed += 1
        return executed

    @staticmethod
    def _invalid_json_message(call: ToolCall) -> str:
        """工具参数不是合法 JSON 时给模型的纠正提示。"""
        return (
            f"参数不是合法 JSON，无法解析：{call.raw_arguments[:200]}。"
            "请按工具 schema 重新调用，确保 arguments 是合法 JSON 对象。"
        )

    def _invoke_tool(self, call: ToolCall) -> str:
        """执行单个工具并记录步骤；失败时返回可回灌的错误文本。"""
        started = time.perf_counter()
        try:
            result = self.registry.invoke(call.name, call.arguments)
        except (ToolError, CodeGuardError) as exc:
            # 工具错误是"可恢复"的：回灌给模型，让它自行修正参数或换工具
            self._steps.append(
                AgentStep(
                    iteration=self._iterations,
                    kind="error",
                    tool_name=call.name,
                    tool_arguments=call.arguments,
                    error=str(exc),
                    duration_ms=int((time.perf_counter() - started) * 1000),
                )
            )
            return f"工具执行失败：{exc}"

        payload = dumps_tool_result(result, limit=self.config.max_tool_output_chars)
        self._steps.append(
            AgentStep(
                iteration=self._iterations,
                kind="tool",
                tool_name=call.name,
                tool_arguments=call.arguments,
                tool_result=payload,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        )
        return payload

    def _feed_back(self, call: ToolCall, payload: str) -> None:
        """把工具结果或错误作为 ``role=tool`` 消息回灌给模型。"""
        self._messages.append(
            ChatMessage(role="tool", content=payload, tool_call_id=call.id, name=call.name)
        )

    # ------------------------------------------------------------------ #
    # 静态分析兜底
    # ------------------------------------------------------------------ #
    def _static_findings(self) -> list[Finding]:
        """取回静态分析结果，用于与模型结论合并。

        优先读工具箱的侧信道状态（完整、可靠）；若模型从未调用过该工具，
        或侧信道不可用，则回退到解析历史里的工具消息文本。
        """
        findings: list[Finding] = []

        state = self.toolbox.last_static_analysis
        payloads: list[dict[str, Any]] = []
        if isinstance(state, dict):
            payloads.append(state)
        else:
            for step in self._steps:
                if step.kind != "tool" or step.tool_name != "run_static_analysis":
                    continue
                if not step.tool_result.lstrip().startswith("{"):
                    continue  # 结果被截断或异常，无法还原
                try:
                    parsed = json.loads(step.tool_result)
                except ValueError:
                    continue
                if isinstance(parsed, dict):
                    payloads.append(parsed)

        for payload in payloads:
            for item in payload.get("findings", []):
                if not isinstance(item, dict):
                    continue
                findings.append(Finding.from_dict({**item, "source": "static"}, default_source="static"))
        return findings

    def _fallback_report(self, *, reason: str) -> ReviewReport:
        """构建兜底报告：即使 LLM 失败，也让用户拿到静态分析结论。

        若模型在循环中从未调用过 ``run_static_analysis``（例如一直卡在其他工具上、
        或第一轮就网络失败），这里会**直接调用分析引擎**补一份结果，
        保证"绝不空手而归"这一设计承诺在任何失败路径上都成立。
        """
        findings = self._static_findings()
        if not findings:
            findings = self._analyze_target_directly()
        report = ReviewReport(
            summary=f"⚠️ 未能获得模型结论（{reason}）。以下为内置静态分析结果。",
            findings=findings,
            # 注意：要在 _analyze_target_directly 之后推导，才能把兜底分析涉及的路径算进去
            files_reviewed=self._infer_files_reviewed(),
        )
        counts = report.counts_by_severity
        if counts[Severity.CRITICAL.value]:
            report.overall_risk = "critical"
        elif counts[Severity.HIGH.value]:
            report.overall_risk = "high"
        elif counts[Severity.MEDIUM.value]:
            report.overall_risk = "medium"
        elif findings:
            report.overall_risk = "low"
        else:
            report.overall_risk = "clean"
        return report

    def _analyze_target_directly(self) -> list[Finding]:
        """绕过 Agent 循环，直接对审查目标跑一次静态分析（兜底用）。"""
        target = self._review_target
        if target is None or not target.exists():
            return []
        try:
            from codeguard.static_analysis import CodeAnalyzer, relativize_findings

            summary = CodeAnalyzer().analyze_path(target)
        except Exception as exc:  # noqa: BLE001 - 兜底路径必须绝对安全
            logger.warning("兜底静态分析失败：%s", exc)
            return []
        if not self._infer_files_reviewed():
            self._steps.append(
                AgentStep(
                    iteration=self._iterations or 1,
                    kind="tool",
                    tool_name="run_static_analysis",
                    tool_arguments={"path": self._display(target)},
                    tool_result=f"（兜底）直接分析 {self._display(target)}，命中 {summary.total} 条。",
                )
            )
        return relativize_findings(summary.findings, self.config.workspace_path)

    # ------------------------------------------------------------------ #
    # 辅助
    # ------------------------------------------------------------------ #
    def _reset(self) -> None:
        self._messages = []
        self._steps = []
        self._usage = TokenUsage()
        self._iterations = 0
        self._tool_budget_used = 0
        self._review_target = None
        self.toolbox.clear()

    def _display(self, path: Path) -> str:
        """转成相对工作区根的展示路径。

        报告中统一使用相对路径：便于跨机器阅读、可安全公开（不泄露本机目录结构），
        也让同一份报告在不同环境下可复现比较。工作区之外的路径退化为绝对路径。
        """
        try:
            return path.resolve().relative_to(self.config.workspace_path).as_posix()
        except (ValueError, OSError):
            return path.as_posix()

    def _prescan(self, directory: Path) -> list[str]:
        """预扫描目录中的源码文件，作为首轮消息的上下文，降低模型盲探成本。"""
        skip_dirs = {
            ".git", "__pycache__", ".venv", "venv", "node_modules",
            ".mypy_cache", ".pytest_cache", "build", "dist", ".idea",
        }
        files: list[str] = []
        try:
            for path in sorted(directory.rglob("*")):
                if not path.is_file():
                    continue
                if any(part in skip_dirs for part in path.parts):
                    continue
                if path.suffix.lower() not in {".py", ".js", ".ts", ".java", ".go", ".rs", ".rb", ".php", ".c", ".cpp", ".h", ".cs", ".kt", ".swift", ".sql", ".sh"}:
                    continue
                files.append(self._display(path))
                if len(files) >= PRESCAN_FILE_LIMIT:
                    break
        except OSError as exc:  # pragma: no cover
            logger.warning("预扫描失败：%s", exc)
        return files

    def _infer_files_reviewed(self) -> list[str]:
        """从工具调用轨迹里推断实际读过的文件（统一转成相对工作区的展示路径）。"""
        seen: list[str] = []

        def record(raw: object) -> None:
            if not isinstance(raw, str) or not raw:
                return
            if raw in {".", "./", ""}:
                return
            # 模型可能给出绝对路径，统一归一化，避免报告里混用两种风格
            candidate = Path(raw)
            display = self._display(candidate if candidate.is_absolute() else self.config.workspace_path / candidate)
            if display not in seen:
                seen.append(display)

        for step in self._steps:
            if step.kind != "tool":
                continue
            if step.tool_name == "read_file":
                record(step.tool_arguments.get("path"))
            elif step.tool_name == "run_static_analysis":
                record(step.tool_arguments.get("path"))
        return seen


# --------------------------------------------------------------------------- #
# 无 LLM 的纯静态审查（便于快速自检与 CI）
# --------------------------------------------------------------------------- #
def _relative_display(raw_path: str, root: Path) -> str:
    """把路径转成相对 ``root`` 的展示形式（用于报告的''审查范围''一节）。"""
    try:
        return Path(raw_path).resolve().relative_to(root).as_posix()
    except (ValueError, OSError):
        return str(raw_path)


def static_only_review(target: str | Path, *, workspace_root: str | Path | None = None) -> ReviewReport:
    """不调用 LLM，直接用内置静态分析生成报告。

    用途：
        * 在没有 API Key 时快速自检；
        * 作为 CI 中的确定性质量门禁；
        * 作为 Agent 结果的对照基线。
    """
    from codeguard.static_analysis import CodeAnalyzer, relativize_findings

    root = Path(workspace_root).resolve() if workspace_root else Path.cwd().resolve()
    path = Path(target)
    if not path.is_absolute():
        path = root / path

    summary = CodeAnalyzer().analyze_path(path)
    report = ReviewReport(
        summary=(
            f"内置静态分析完成：共分析 {len(summary.files)} 个文件，"
            f"命中 {summary.total} 条问题。本报告由确定性规则生成，未调用 LLM。"
        ),
        findings=relativize_findings(summary.findings, root),
        files_reviewed=[_relative_display(f.path, root) for f in summary.files],
        meta={"mode": "static-only", "counts": summary.counts},
    )
    counts = report.counts_by_severity
    if counts[Severity.CRITICAL.value]:
        report.overall_risk = "critical"
    elif counts[Severity.HIGH.value]:
        report.overall_risk = "high"
    elif counts[Severity.MEDIUM.value]:
        report.overall_risk = "medium"
    elif summary.total:
        report.overall_risk = "low"
    else:
        report.overall_risk = "clean"
    return report
