"""工具层测试：注册表、路径沙箱、以及 7 个内置工具的行为。

关键验证点：
    * 路径越界（``../``）必须被拒绝 —— 安全边界；
    * 工具异常必须转成 ``ToolError``（而不是让 Agent 崩溃）；
    * 未知工具给出清晰的可用列表；
    * ``submit_review`` 能正确产出结构化报告。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeguard.compat import writable_tempdir
from codeguard.exceptions import ToolArgumentError, ToolError, ToolNotFoundError
from codeguard.models import Severity
from codeguard.tools import (
    PathGuard,
    Tool,
    ToolRegistry,
    build_default_registry,
    dumps_tool_result,
    truncate,
)

SAMPLE = '''"""doc"""
import os


def risky(user_input):
    return eval(user_input)


def loop(items=[]):
    items.append(1)
    return items
'''


class Workspace:
    """创建临时工作区，包含若干示例文件（位于项目内，避免 TEMP 权限问题）。"""

    def __enter__(self) -> "Workspace":
        self._ctx = writable_tempdir("tools_")
        self.root = self._ctx.__enter__()
        (self.root / "pkg").mkdir()
        (self.root / "pkg" / "a.py").write_text(SAMPLE, encoding="utf-8")
        (self.root / "pkg" / "b.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.root / "README.md").write_text("# demo\n", encoding="utf-8")
        (self.root / "notes.txt").write_text("hello world\n", encoding="utf-8")
        # 工作区之外的文件，用于验证沙箱
        self.outside = self.root.parent / "outside_secret.txt"
        self.outside.write_text("TOP SECRET\n", encoding="utf-8")
        return self

    def __exit__(self, *exc_info: object) -> None:
        try:
            self.outside.unlink()
        except OSError:
            pass
        self._ctx.__exit__(*exc_info)


def make_toolbox(root: Path):
    return build_default_registry(workspace_root=root, max_output_chars=5000)


def test_registry_basics() -> None:
    registry = ToolRegistry()
    registry.register(
        Tool(
            name="echo",
            description="echo back",
            parameters={"type": "object", "properties": {}},
            func=lambda text="": {"echo": text},
        )
    )
    assert "echo" in registry
    assert len(registry) == 1
    assert registry.names == ["echo"]
    assert registry.invoke("echo", {"text": "hi"}) == {"echo": "hi"}
    assert registry.total_calls() == 1
    assert registry.schemas()[0]["function"]["name"] == "echo"


def test_registry_rejects_duplicate_and_invalid_names() -> None:
    registry = ToolRegistry()
    registry.register(Tool(name="ok", description="d", parameters={}, func=lambda: None))
    try:
        registry.register(Tool(name="ok", description="d", parameters={}, func=lambda: None))
    except ValueError as exc:
        assert "重复" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("重复注册应当报错")

    try:
        registry.register(Tool(name="bad name!", description="d", parameters={}, func=lambda: None))
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("非法工具名应当报错")


def test_registry_unknown_tool_lists_available() -> None:
    registry = ToolRegistry()
    registry.register(Tool(name="alpha", description="d", parameters={}, func=lambda: None))
    try:
        registry.get("beta")
    except ToolNotFoundError as exc:
        assert "alpha" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("未注册工具应当报错")


def test_tool_wraps_unexpected_exception() -> None:
    def boom() -> None:
        raise RuntimeError("kaboom")

    tool = Tool(name="boom", description="d", parameters={}, func=boom)
    try:
        tool.invoke({})
    except ToolError as exc:
        assert "kaboom" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("工具异常应当被包装为 ToolError")


def test_tool_wraps_type_error_as_argument_error() -> None:
    tool = Tool(name="needs_arg", description="d", parameters={}, func=lambda required: required)
    try:
        tool.invoke({})
    except ToolArgumentError as exc:
        assert "参数不匹配" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("缺少参数应当报 ToolArgumentError")


def test_path_guard_blocks_escape() -> None:
    with Workspace() as workspace:
        guard = PathGuard(workspace.root)
        assert guard.resolve("pkg/a.py").name == "a.py"
        for evil in ("../outside_secret.txt", "pkg/../../outside_secret.txt"):
            try:
                guard.resolve(evil)
            except ToolArgumentError as exc:
                assert "拒绝访问" in str(exc)
            else:  # pragma: no cover
                raise AssertionError(f"越界路径应当被拒绝：{evil}")


def test_path_guard_rejects_empty_and_missing() -> None:
    with Workspace() as workspace:
        guard = PathGuard(workspace.root)
        for bad in ("", "   "):
            try:
                guard.resolve(bad)
            except ToolArgumentError:
                pass
            else:  # pragma: no cover
                raise AssertionError("空路径应当被拒绝")
        try:
            guard.resolve("does_not_exist.py")
        except ToolArgumentError as exc:
            assert "不存在" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("不存在的路径应当被拒绝")


def test_list_files_filters_by_extension() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        result = toolbox.registry.invoke("list_files", {"path": ".", "extension": ".py", "recursive": True})
        paths = {item["path"] for item in result["files"]}
        assert "pkg/a.py" in paths
        assert "pkg/b.py" in paths
        assert "README.md" not in paths
        assert result["file_count"] >= 2


def test_read_file_returns_numbered_window() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        result = toolbox.registry.invoke("read_file", {"path": "pkg/a.py", "start_line": 1, "end_line": 3})
        assert result["path"] == "pkg/a.py"
        assert result["total_lines"] > 3
        assert result["truncated"] is True
        assert " 1 | " in result["content"], "应带行号"
        assert result["shown_range"] == [1, 3]


def test_read_file_rejects_oversized_file() -> None:
    with Workspace() as workspace:
        big = workspace.root / "big.py"
        big.write_text("x = 1\n" * 50_000, encoding="utf-8")
        toolbox = make_toolbox(workspace.root)
        try:
            toolbox.registry.invoke("read_file", {"path": "big.py"})
        except ToolError as exc:
            assert "文件过大" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("超大文件应当报错")


def test_search_code_finds_matches_with_line_numbers() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        result = toolbox.registry.invoke("search_code", {"pattern": r"eval\(", "path": "."})
        assert result["match_count"] >= 1
        match = result["matches"][0]
        assert match["file"] == "pkg/a.py"
        assert isinstance(match["line"], int) and match["line"] > 0


def test_search_code_rejects_invalid_regex() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        try:
            toolbox.registry.invoke("search_code", {"pattern": "([unclosed"})
        except ToolArgumentError as exc:
            assert "正则" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("非法正则应当报错")


def test_find_files_glob() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        result = toolbox.registry.invoke("find_files", {"pattern": "**/*.py", "path": "."})
        assert "pkg/a.py" in result["files"]
        assert result["count"] >= 2


def test_run_static_analysis_reports_rules() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        result = toolbox.registry.invoke("run_static_analysis", {"path": "pkg/a.py"})
        rule_ids = {item["rule_id"] for item in result["findings"]}
        assert "CG101" in rule_ids, "eval 应被检测到"
        assert "CG203" in rule_ids, "可变默认参数应被检测到"
        assert result["counts_by_rule"]["CG101"] >= 1


def test_run_static_analysis_severity_filter() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        only_high = toolbox.registry.invoke(
            "run_static_analysis", {"path": "pkg/a.py", "min_severity": "critical"}
        )
        severities = {item["severity"] for item in only_high["findings"]}
        assert severities <= {"critical"}


def test_run_static_analysis_rejects_unknown_rule() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        try:
            toolbox.registry.invoke("run_static_analysis", {"path": "pkg/a.py", "rules": ["CG999"]})
        except ToolArgumentError as exc:
            assert "CG999" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("未知规则应当报错")


def test_list_rules_returns_handbook() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        all_rules = toolbox.registry.invoke("list_rules", {})
        assert all_rules["count"] >= 25
        one = toolbox.registry.invoke("list_rules", {"rule_id": "cg101"})
        assert one["rule"]["rule_id"] == "CG101"
        security = toolbox.registry.invoke("list_rules", {"category": "security"})
        assert all(item["category"] == "security" for item in security["rules"])


def test_submit_review_builds_report_and_terminates() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        result = toolbox.registry.invoke(
            "submit_review",
            {
                "summary": "整体尚可，但存在命令注入风险。",
                "overall_risk": "high",
                "score": 62,
                "findings": [
                    {
                        "title": "eval 导致任意代码执行",
                        "severity": "critical",
                        "category": "security",
                        "file": "pkg/a.py",
                        "line": 6,
                        "evidence": "return eval(user_input)",
                        "explanation": "输入不可信时会执行任意代码。",
                        "suggestion": "改用 ast.literal_eval。",
                    },
                    {"title": "次要问题", "severity": "low", "file": "pkg/a.py"},
                ],
                "positives": ["模块划分清晰"],
                "open_questions": ["是否需要兼容 Python 2？"],
                "files_reviewed": ["pkg/a.py"],
            },
        )
        assert result["status"] == "accepted"
        assert result["findings_received"] == 2

        report = toolbox.report
        assert report is not None
        assert report.overall_risk == "high"
        assert report.score == 62
        assert report.findings[0].severity is Severity.CRITICAL, "严重问题应排在最前"
        assert report.findings[0].location == "pkg/a.py:6"
        assert report.positives == ["模块划分清晰"]


def test_default_registry_has_expected_tools() -> None:
    with Workspace() as workspace:
        toolbox = make_toolbox(workspace.root)
        assert set(toolbox.registry.names) == {
            "list_files",
            "read_file",
            "search_code",
            "find_files",
            "run_static_analysis",
            "list_rules",
            "submit_review",
        }
        # 每个工具都必须有合法的 JSON Schema 根
        for schema in toolbox.registry.schemas():
            assert schema["type"] == "function"
            params = schema["function"]["parameters"]
            assert params["type"] == "object"
            assert isinstance(params["properties"], dict)


def test_truncate_and_dumps_helpers() -> None:
    assert truncate("abc", 10) == "abc"
    truncated = truncate("a" * 100, 10)
    assert truncated.startswith("a" * 10)
    assert "截断" in truncated

    text = dumps_tool_result({"中文": "内容"})
    assert "中文" in text and "内容" in text
    parsed = json.loads(text)
    assert parsed["中文"] == "内容"
