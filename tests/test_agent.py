"""
Agent 循环测试（离线，不访问网络）。
覆盖：完整闭环、submit_review 终止、未用工具时被提示拉回、工具报错回灌自愈、参数非法 JSON 容错、预算耗尽兜底、上下文记忆。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeguard.agent import CodeReviewAgent, static_only_review
from codeguard.compat import writable_tempdir
from codeguard.config import Config
from codeguard.llm import MockLLMClient
from codeguard.models import ChatMessage, LLMResponse, ReviewReport, Severity, TokenUsage, ToolCall

BUGGY = '''"""示例"""
PASSWORD = "hardcoded_pass_1234"


def risky(user_input):
    return eval(user_input)


def loop(items=[]):
    items.append(1)
    return items
'''


class Workspace:
    """临时工作区（位于项目内，避免受限环境下系统 TEMP 不可写）。"""

    def __enter__(self) -> "Workspace":
        self._ctx = writable_tempdir("agent_")
        self.root = self._ctx.__enter__()
        (self.root / "app.py").write_text(BUGGY, encoding="utf-8")
        (self.root / "clean.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._ctx.__exit__(*exc_info)


def scripted(responses: list[LLMResponse]) -> MockLLMClient:
    return MockLLMClient(Config(mock=True), script=responses)


def call(call_id: str, name: str, arguments: dict) -> ToolCall:
    return ToolCall(id=call_id, name=name, arguments=arguments)


def response(content: str = "", *tools: ToolCall, finish: str = "tool_calls") -> LLMResponse:
    return LLMResponse(
        content=content,
        tool_calls=list(tools),
        finish_reason=finish,
        usage=TokenUsage(100, 50, 150, 1),
    )


def make_agent(root: Path, llm: MockLLMClient, **overrides: object) -> CodeReviewAgent:
    settings: dict[str, object] = {"mock": True, "workspace_root": str(root), "max_iterations": 8}
    settings.update(overrides)
    config = Config(**settings)  # type: ignore[arg-type]
    return CodeReviewAgent(config, llm=llm)


def test_full_loop_with_termination_tool() -> None:
    with Workspace() as workspace:
        llm = scripted(
            [
                response("先跑静态分析。", call("c1", "run_static_analysis", {"path": "app.py"})),
                response("再看源码。", call("c2", "read_file", {"path": "app.py"})),
                response(
                    "提交报告。",
                    call(
                        "c3",
                        "submit_review",
                        {
                            "summary": "存在任意代码执行与硬编码凭据，必须优先修复。",
                            "overall_risk": "critical",
                            "score": 35,
                            "findings": [
                                {
                                    "title": "eval 导致任意代码执行",
                                    "severity": "critical",
                                    "category": "security",
                                    "file": "app.py",
                                    "line": 6,
                                    "evidence": "return eval(user_input)",
                                    "explanation": "不可信输入被当作代码执行。",
                                    "suggestion": "改用 ast.literal_eval。",
                                }
                            ],
                            "positives": ["模块只有一个文件，边界清晰"],
                            "files_reviewed": ["app.py"],
                        },
                    ),
                ),
            ]
        )
        with make_agent(workspace.root, llm) as agent:
            result = agent.review("app.py")

        assert result.stopped_reason == "submitted"
        assert result.iterations == 3
        assert result.tool_calls == 3
        assert result.usage.calls == 3
        assert result.usage.total_tokens > 0
        assert result.report.overall_risk == "critical"
        assert result.report.score == 35
        assert result.report.findings, "报告应包含问题"
        assert any("eval" in f.title for f in result.report.findings)
        # 静态分析结果应与模型结论合并（模型只写了 1 条，静态引擎会补充更多）
        assert len(result.report.findings) > 1
        assert any(f.source == "static" for f in result.report.findings)
        # 元数据应完整
        assert result.report.meta["tool_calls"] == 3
        assert result.report.meta["stopped_reason"] == "submitted"
        assert result.report.meta["mock"] is True


def test_model_nudged_when_no_tool_used() -> None:
    """模型第一轮就想下结论时，Agent 应注入提示并继续循环。"""
    with Workspace() as workspace:
        llm = scripted(
            [
                response("我觉得代码没问题。", finish="stop"),  # 无工具调用
                response("我先看看。", call("c1", "run_static_analysis", {"path": "app.py"})),
                response(
                    "提交。",
                    call("c2", "submit_review", {"summary": "已完成审查。", "findings": []}),
                ),
            ]
        )
        with make_agent(workspace.root, llm) as agent:
            result = agent.review("app.py")

        assert result.stopped_reason == "submitted"
        # 应能看到那条"必须先调用工具"的提示出现在消息历史里
        hints = [m.content or "" for m in result.messages if m.role == "user"]
        assert any("run_static_analysis" in hint for hint in hints)


def test_tool_error_is_fed_back_and_recovered() -> None:
    """工具报错后模型换参数重试，循环不应中断。"""
    with Workspace() as workspace:
        llm = scripted(
            [
                response("读一下文件。", call("c1", "read_file", {"path": "does_not_exist.py"})),
                response("路径错了，换成静态分析。", call("c2", "run_static_analysis", {"path": "app.py"})),
                response("提交。", call("c3", "submit_review", {"summary": "完成。", "findings": []})),
            ]
        )
        with make_agent(workspace.root, llm) as agent:
            result = agent.review("app.py")

        assert result.stopped_reason == "submitted"
        errors = [step for step in result.steps if step.kind == "error"]
        assert errors, "应记录一次工具错误"
        assert "不存在" in errors[0].error
        # 错误必须作为 tool 消息回灌给模型
        tool_messages = [m for m in result.messages if m.role == "tool"]
        assert any("工具执行失败" in (m.content or "") for m in tool_messages)


def test_unknown_tool_is_recoverable() -> None:
    with Workspace() as workspace:
        llm = scripted(
            [
                response("调用不存在的工具。", call("c1", "analyze_code", {"path": "app.py"})),
                response("换正确的工具。", call("c2", "run_static_analysis", {"path": "app.py"})),
                response("提交。", call("c3", "submit_review", {"summary": "完成。", "findings": []})),
            ]
        )
        with make_agent(workspace.root, llm) as agent:
            result = agent.review("app.py")

        assert result.stopped_reason == "submitted"
        tool_payloads = [m.content or "" for m in result.messages if m.role == "tool"]
        assert any("未注册的工具" in payload for payload in tool_payloads)


def test_invalid_tool_arguments_json_is_handled() -> None:
    with Workspace() as workspace:
        bad_call = ToolCall(
            id="c1",
            name="read_file",
            arguments={},
            raw_arguments="{path: broken json",
        )
        llm = scripted(
            [
                response("调一下。", bad_call),
                response("提交。", call("c2", "submit_review", {"summary": "完成。", "findings": []})),
            ]
        )
        with make_agent(workspace.root, llm) as agent:
            result = agent.review("app.py")

        assert result.stopped_reason == "submitted"
        payloads = [m.content or "" for m in result.messages if m.role == "tool"]
        assert any("不是合法 JSON" in payload for payload in payloads)


def test_budget_exhausted_falls_back_to_static_report() -> None:
    """模型一直不提交时，Agent 必须给出兜底报告而不是空结果。"""
    with Workspace() as workspace:
        # 每轮都只做无关的工具调用，永不提交
        script = [
            response("继续调查。", call(f"c{index}", "list_files", {"path": "."}))
            for index in range(10)
        ]
        llm = scripted(script)
        with make_agent(workspace.root, llm, max_iterations=3) as agent:
            result = agent.review("app.py")

        assert result.stopped_reason in {"max_iterations", "final_answer_without_report"}
        assert result.report.findings, "兜底报告应包含静态分析发现"
        assert "静态分析" in result.report.summary
        assert result.report.overall_risk in {"critical", "high", "medium", "low"}


def test_llm_failure_produces_fallback_report() -> None:
    """LLM 永久失败时也要产出报告（降级但不崩）。"""
    from codeguard.exceptions import LLMAuthError

    class FailingLLM(MockLLMClient):
        def chat(self, messages, *, tools=None, tool_choice=None):  # type: ignore[override]
            raise LLMAuthError("invalid api key")

    with Workspace() as workspace:
        agent = make_agent(workspace.root, FailingLLM(Config(mock=True)))
        result = agent.review("app.py")

        assert result.stopped_reason == "llm_error"
        assert "LLM 调用失败" in result.report.summary
        assert result.report.meta["stopped_reason"] == "llm_error"


def test_followup_keeps_context() -> None:
    with Workspace() as workspace:
        llm = scripted(
            [
                response("静态分析。", call("c1", "run_static_analysis", {"path": "app.py"})),
                response("提交。", call("c2", "submit_review", {"summary": "已完成。", "findings": []})),
                # 追问阶段的回复
                response("根据刚才读到的 app.py，第 6 行的 eval 是最大风险。", finish="stop"),
            ]
        )
        with make_agent(workspace.root, llm) as agent:
            result = agent.review("app.py")
            answer = agent.followup("哪一行最危险？", report=result.report)

        assert "eval" in answer
        # 追问时模型应看到完整历史（system + 之前的 user/assistant/tool）
        last_call = llm.received[-1]
        roles = {message.role for message in last_call}
        assert {"system", "user", "assistant", "tool"} <= roles


def test_static_only_review_without_llm() -> None:
    with Workspace() as workspace:
        report = static_only_review("app.py", workspace_root=workspace.root)
        assert isinstance(report, ReviewReport)
        assert report.meta["mode"] == "static-only"
        rule_ids = {f.rule_id for f in report.findings}
        assert "CG101" in rule_ids
        assert "CG105" in rule_ids
        assert report.overall_risk == "critical"
        assert report.files_reviewed


def test_static_only_review_honours_rules_filter() -> None:
    """回归：--rules 曾只被解析、从不传给分析引擎（文档写了但静默失效）。"""
    with Workspace() as workspace:
        only_eval = static_only_review("app.py", workspace_root=workspace.root, rules=["CG101"])
        assert {f.rule_id for f in only_eval.findings} == {"CG101"}, "只应保留 CG101"
        assert only_eval.meta["rules"] == ["CG101"]

        # 全量结果应比过滤后更多，证明过滤真的生效了
        everything = static_only_review("app.py", workspace_root=workspace.root)
        assert len(everything.findings) > len(only_eval.findings)


def test_static_only_review_rejects_unknown_rule() -> None:
    from codeguard.exceptions import ToolArgumentError

    with Workspace() as workspace:
        try:
            static_only_review("app.py", workspace_root=workspace.root, rules=["CG999"])
        except ToolArgumentError as exc:
            assert "CG999" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("未知规则应报错，而不是静默忽略")


def test_agent_result_trace_is_renderable() -> None:
    with Workspace() as workspace:
        llm = scripted(
            [
                response("分析中。", call("c1", "run_static_analysis", {"path": "app.py"})),
                response("提交。", call("c2", "submit_review", {"summary": "完成。", "findings": []})),
            ]
        )
        with make_agent(workspace.root, llm) as agent:
            result = agent.review("app.py")

        trace = result.render_trace()
        assert "执行轨迹" in trace
        assert "run_static_analysis" in trace
        # 每一步都能序列化成字典（便于写 trajectory 文件）
        for step in result.steps:
            assert isinstance(step.to_dict(), dict)


def test_agent_requires_api_key_when_not_mock() -> None:
    from codeguard.exceptions import ConfigError

    with Workspace() as workspace:
        try:
            CodeReviewAgent(Config(api_key="", workspace_root=str(workspace.root), mock=False))
        except ConfigError as exc:
            assert "API Key" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("缺少 API Key 且非 mock 模式应当报错")


def test_toolbox_side_channel_exposes_full_static_result() -> None:
    """侧信道必须保存**完整**结构化结果（文本结果可能被长度上限截断）。"""
    with Workspace() as workspace:
        llm = scripted(
            [
                response("分析。", call("c1", "run_static_analysis", {"path": "app.py"})),
                response("提交。", call("c2", "submit_review", {"summary": "完成。", "findings": []})),
            ]
        )
        small_budget = {"max_tool_output_chars": 300}
        with make_agent(workspace.root, llm, **small_budget) as agent:
            agent.review("app.py")
            state = agent.toolbox.last_static_analysis

        assert isinstance(state, dict), "侧信道应保存静态分析结果"
        assert state["total_findings"] >= 2
        assert state["target"].endswith("app.py")


def test_mock_cli_path_produces_findings_in_report() -> None:
    """回归：``--mock`` 模式下报告必须包含真实静态分析发现，而不是空清单。"""
    from codeguard.tools import build_default_registry

    with Workspace() as workspace:
        config = Config(mock=True, workspace_root=str(workspace.root))
        toolbox = build_default_registry(workspace_root=workspace.root)
        agent = CodeReviewAgent(config, toolbox=toolbox)
        try:
            # 走与 CLI 相同的路径：先建 toolbox，再切 mock 模型
            agent.use_mock_llm(target="app.py")
            result = agent.review("app.py")
        finally:
            agent.close()

        assert result.stopped_reason == "submitted"
        assert result.report.findings, "Mock 模式的报告不应为空"
        assert "Mock" in result.report.summary or "离线" in result.report.summary
        # 报告里的问题应当来自真实规则引擎
        assert any(f.rule_id for f in result.report.findings)
        assert result.report.overall_risk in {"critical", "high", "medium", "low"}


def test_messages_are_protocol_shaped() -> None:
    """回灌给模型的消息必须符合 OpenAI 协议（tool 消息带 tool_call_id）。"""
    with Workspace() as workspace:
        llm = scripted(
            [
                response("分析。", call("call_xyz", "run_static_analysis", {"path": "app.py"})),
                response("提交。", call("c2", "submit_review", {"summary": "完成。", "findings": []})),
            ]
        )
        with make_agent(workspace.root, llm) as agent:
            result = agent.review("app.py")

        payloads = [message.to_payload() for message in result.messages]
        for payload in payloads:
            assert payload["role"] in {"system", "user", "assistant", "tool"}
            if payload["role"] == "tool":
                assert payload.get("tool_call_id"), "tool 消息必须带 tool_call_id"
        assistant_with_tools = [p for p in payloads if p.get("tool_calls")]
        assert assistant_with_tools, "应存在带 tool_calls 的 assistant 消息"
        assert assistant_with_tools[0]["tool_calls"][0]["function"]["name"] == "run_static_analysis"
        # 序列化后应为合法 JSON
        json.dumps(payloads, ensure_ascii=False)
