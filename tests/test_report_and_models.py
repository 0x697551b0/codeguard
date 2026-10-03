"""领域模型与报告渲染测试。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeguard.compat import writable_tempdir
from codeguard.models import (
    ChatMessage,
    Finding,
    ReviewReport,
    Severity,
    TokenUsage,
    ToolCall,
)
from codeguard.report import (
    render_ci_summary,
    render_json,
    render_markdown,
    render_text,
    summarize_for_prompt,
    write_report,
)


def make_report() -> ReviewReport:
    return ReviewReport.from_payload(
        {
            "summary": "代码整体结构清晰，但存在一处严重的安全问题需要立即修复。",
            "overall_risk": "high",
            "score": 71,
            "findings": [
                {
                    "title": "SQL 注入",
                    "severity": "critical",
                    "category": "security",
                    "file": "app/db.py",
                    "line": 42,
                    "evidence": 'cursor.execute("... %s" % email)',
                    "explanation": "外部输入被拼进 SQL。",
                    "suggestion": "使用参数化查询。",
                },
                {
                    "title": "魔法数字过多",
                    "severity": "low",
                    "category": "maintainability",
                    "file": "app/db.py",
                    "line": 10,
                },
            ],
            "positives": ["app/db.py 的连接生命周期管理使用了上下文管理器"],
            "open_questions": ["是否存在历史数据迁移脚本？"],
            "files_reviewed": ["app/db.py"],
        }
    )


def test_severity_coercion_and_aliases() -> None:
    assert Severity.coerce("CRITICAL") is Severity.CRITICAL
    assert Severity.coerce("  High ") is Severity.HIGH
    assert Severity.coerce("严重") is Severity.CRITICAL
    assert Severity.coerce("warning") is Severity.MEDIUM
    assert Severity.coerce("nonsense") is Severity.INFO
    assert Severity.coerce(None) is Severity.INFO
    assert Severity.coerce(Severity.LOW) is Severity.LOW


def test_finding_from_dict_tolerates_model_variants() -> None:
    chinese = Finding.from_dict(
        {
            "标题": "硬编码密钥",
            "级别": "高",
            "文件": "config.py",
            "行号": "12",
            "证据": "API_KEY = 'sk-xxx'",
            "建议": "改用环境变量",
        }
    )
    assert chinese.title == "硬编码密钥"
    assert chinese.severity is Severity.HIGH
    assert chinese.file == "config.py"
    assert chinese.line == 12
    assert chinese.location == "config.py:12"

    # 缺字段不应抛异常
    minimal = Finding.from_dict({"title": "只有标题"})
    assert minimal.severity is Severity.INFO
    assert minimal.location == "(未知位置)"

    # 非法行号退化为 None
    weird = Finding.from_dict({"title": "x", "line": "not-a-number"})
    assert weird.line is None


def test_finding_normalizes_invalid_severity_and_line() -> None:
    finding = Finding(title="t", severity="bogus", line=-5)  # type: ignore[arg-type]
    assert finding.severity is Severity.INFO
    assert finding.line is None


def test_report_from_payload_coerces_and_sorts() -> None:
    report = make_report()
    assert len(report.findings) == 2
    assert report.findings[0].severity is Severity.CRITICAL
    assert report.findings[1].severity is Severity.LOW
    assert report.score == 71
    assert report.has_blocking_issues is True
    assert report.counts_by_severity["critical"] == 1
    assert report.counts_by_severity["low"] == 1


def test_report_score_is_clamped() -> None:
    assert ReviewReport.from_payload({"score": 999}).score == 100
    assert ReviewReport.from_payload({"score": -3}).score == 0
    assert ReviewReport.from_payload({"score": "abc"}).score is None


def test_report_merge_findings_dedupes() -> None:
    report = make_report()
    duplicate = Finding(
        title="SQL 注入",
        severity=Severity.CRITICAL,
        file="app/db.py",
        line=42,
        source="static",
        rule_id="CG106",
    )
    fresh = Finding(title="资源未关闭", severity=Severity.MEDIUM, file="app/io.py", line=8, source="static")
    added = report.merge_findings([duplicate, fresh])
    assert added == 1, "重复条目应被去重"
    assert len(report.findings) == 3
    assert any(f.rule_id == "CG106" for f in report.findings) is False  # 重复项被丢弃


def test_report_json_roundtrip() -> None:
    report = make_report()
    payload = json.loads(render_json(report))
    assert payload["summary"] == report.summary
    assert payload["counts"]["critical"] == 1
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["line"] == 42


def test_markdown_contains_key_sections() -> None:
    markdown = render_markdown(make_report())
    for expected in (
        "# CodeGuard 代码审查报告",
        "## 一、总体结论",
        "## 二、问题清单",
        "## 三、值得肯定的设计",
        "## 四、需要人工确认",
        "app/db.py:42",
        "SQL 注入",
        "使用参数化查询",
        "71 / 100",
    ):
        assert expected in markdown, f"Markdown 缺少：{expected}"


def test_markdown_rules_appendix() -> None:
    markdown = render_markdown(make_report(), include_rules_appendix=True)
    assert "内置静态规则清单" in markdown
    assert "CG101" in markdown


def test_text_renderer_handles_empty_report() -> None:
    empty = ReviewReport(summary="没有发现问题。", overall_risk="clean")
    text = render_text(empty)
    assert "CLEAN" in text
    assert "未发现需要修改的问题" in text
    markdown = render_markdown(empty)
    assert "未发现需要修改的问题" in markdown


def test_ci_gate_evaluation() -> None:
    report = make_report()
    passed, message = render_ci_summary(report, fail_on="critical")
    assert passed is False and "critical" in message
    passed, message = render_ci_summary(report, fail_on="none")
    assert passed is True, "fail_on=none 时不应拦截"

    clean = ReviewReport(summary="ok", findings=[Finding(title="小问题", severity=Severity.INFO)])
    assert render_ci_summary(clean, fail_on="high")[0] is True


def test_write_report_infers_format_from_extension() -> None:
    report = make_report()
    with writable_tempdir("report_") as tmp:
        md_path = write_report(report, str(tmp / "nested" / "report.md"))
        assert Path(md_path).exists()
        assert Path(md_path).read_text(encoding="utf-8").startswith("# CodeGuard")

        json_path = write_report(report, str(tmp / "report.json"))
        assert json.loads(Path(json_path).read_text(encoding="utf-8"))["overall_risk"] == "high"

        txt_path = write_report(report, str(tmp / "report.txt"))
        assert "代码审查报告" in Path(txt_path).read_text(encoding="utf-8")


def test_summarize_for_prompt_is_compact() -> None:
    summary = summarize_for_prompt(make_report(), max_findings=1)
    assert "整体风险：high" in summary
    assert summary.count("- [") == 1


def test_token_usage_accumulation() -> None:
    total = TokenUsage()
    total.add(TokenUsage(10, 5, 15, 1))
    total.add(TokenUsage(20, 10, 30, 1))
    total.add(None)
    assert total.prompt_tokens == 30
    assert total.completion_tokens == 15
    assert total.total_tokens == 45
    assert total.calls == 2
    assert "45" in str(total)


def test_message_payload_shapes() -> None:
    user = ChatMessage(role="user", content="你好")
    assert user.to_payload() == {"role": "user", "content": "你好"}

    assistant = ChatMessage(
        role="assistant",
        content=None,
        tool_calls=[ToolCall(id="c1", name="read_file", arguments={"path": "a.py"})],
    )
    payload = assistant.to_payload()
    assert payload["content"] is None
    assert payload["tool_calls"][0]["function"]["arguments"] == '{"path": "a.py"}'
    assert assistant.tool_names == ["read_file"]

    tool_message = ChatMessage(role="tool", content="result", tool_call_id="c1", name="read_file")
    assert tool_message.to_payload()["tool_call_id"] == "c1"
