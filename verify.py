"""
端到端自检：一条命令验证整个项目能否跑通。用法：python verify.py

10 项检查全部离线（不访问网络、不需要 API Key）：包导入、语法编译、规则引擎识别缺陷、规范代码无误报、
7 个工具可用、Agent 闭环产出报告、三种报告渲染、报告路径规范、CLI 退出码、测试套件。任一项失败返回非零。
"""

from __future__ import annotations

import compileall
import io
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from codeguard.compat import enable_utf8_console  # noqa: E402

enable_utf8_console()

PASSED: list[str] = []
FAILED: list[tuple[str, str]] = []


def check(name: str):
    """装饰器：把一个检查项登记到结果列表。"""

    def decorator(func):
        try:
            detail = func() or ""
        except Exception as exc:  # noqa: BLE001 - 自检脚本需要汇总所有失败
            FAILED.append((name, f"{type(exc).__name__}: {exc}"))
            print(f"  ✗ {name}")
        else:
            PASSED.append(name)
            print(f"  ✓ {name}" + (f"  {detail}" if detail else ""))
        return func

    return decorator


def run_cli(*args: str) -> tuple[int, str]:
    """以子进程方式运行 CLI，返回 (退出码, 合并输出)。"""
    process = subprocess.run(
        [sys.executable, "-m", "codeguard", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return process.returncode, (process.stdout or "") + (process.stderr or "")


def run_cli_stdout(*args: str) -> tuple[int, str]:
    """只返回 stdout —— 用于校验 --json 的输出是否纯净。"""
    process = subprocess.run(
        [sys.executable, "-m", "codeguard", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return process.returncode, process.stdout or ""


print("CodeGuard 端到端自检")
print("=" * 70)

DEMO = "examples/demo_buggy_code"


@check("1. 包可导入且版本可读")
def _import_check() -> str:
    import codeguard

    assert codeguard.__version__, "版本号为空"
    assert codeguard.CodeReviewAgent and codeguard.ReviewReport
    return f"v{codeguard.__version__}"


@check("2. 全部模块通过语法编译")
def _compile_check() -> str:
    ok = compileall.compile_dir(str(ROOT / "codeguard"), quiet=2, force=True, legacy=False)
    assert ok, "存在无法编译的模块，详见上方 compileall 输出"
    py_files = len(list((ROOT / "codeguard").rglob("*.py")))
    return f"{py_files} 个模块"


@check("3. 静态规则引擎识别示例缺陷")
def _static_engine_check() -> str:
    from codeguard.static_analysis import CodeAnalyzer

    summary = CodeAnalyzer().analyze_path(ROOT / DEMO)
    assert len(summary.files) >= 3, "示例目录文件数不足"
    assert summary.total >= 20, f"命中问题过少：{summary.total}"
    counts = summary.counts
    assert counts["critical"] >= 1, "应至少命中 1 条 critical"
    assert counts["high"] >= 1, "应至少命中 1 条 high"
    rule_ids = {f.rule_id for f in summary.findings}
    expected = {"CG101", "CG102", "CG103", "CG105", "CG106", "CG201", "CG203"}
    missing = expected - rule_ids
    assert not missing, f"未命中预期规则：{sorted(missing)}"
    return f"{summary.total} 条命中 / {counts['critical']} critical"


@check("4. 规范代码不产生严重误报")
def _low_false_positive_check() -> str:
    from codeguard.models import Severity
    from codeguard.static_analysis import CodeAnalyzer

    analysis = CodeAnalyzer().analyze_path(ROOT / DEMO / "good_reference.py")
    serious = [f for f in analysis.findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    assert not serious, f"规范代码出现中等级别以上误报：{[(f.rule_id, f.title) for f in serious]}"
    return f"{len(analysis.findings)} 条均为 low/info"


@check("5. 七个工具均可调用")
def _tools_check() -> str:
    from codeguard.tools import build_default_registry

    toolbox = build_default_registry(workspace_root=ROOT)
    registry = toolbox.registry
    expected_tools = {
        "list_files",
        "read_file",
        "search_code",
        "find_files",
        "run_static_analysis",
        "list_rules",
        "submit_review",
    }
    assert set(registry.names) == expected_tools, f"工具集不一致：{registry.names}"

    listing = registry.invoke("list_files", {"path": DEMO})
    assert listing["file_count"] >= 3
    read = registry.invoke("read_file", {"path": f"{DEMO}/utils.py", "end_line": 5})
    assert "1 | " in read["content"], "read_file 应返回带行号内容"
    search = registry.invoke("search_code", {"pattern": r"except:", "path": DEMO})
    assert search["match_count"] >= 1
    found = registry.invoke("find_files", {"pattern": "**/*.py", "path": DEMO})
    assert found["count"] >= 3
    static = registry.invoke("run_static_analysis", {"path": DEMO, "min_severity": "high"})
    assert static["total_findings"] >= 1
    handbook = registry.invoke("list_rules", {})
    assert handbook["count"] >= 25

    # 沙箱：越权路径必须被拒绝
    try:
        registry.invoke("read_file", {"path": "../../../Windows/System32/drivers/etc/hosts"})
    except Exception:
        pass
    else:
        raise AssertionError("越界读取未被拒绝")
    return f"{len(registry.names)} 个工具"


@check("6. Agent 闭环（mock 模型）产出结构化报告")
def _agent_check() -> str:
    from codeguard.agent import CodeReviewAgent
    from codeguard.config import Config
    from codeguard.llm import MockLLMClient

    config = Config(mock=True, workspace_root=str(ROOT))
    llm = MockLLMClient(config, target=str(ROOT / DEMO))
    with CodeReviewAgent(config, llm=llm) as agent:
        result = agent.review(DEMO)

    assert result.stopped_reason == "submitted", f"未正常收敛：{result.stopped_reason}"
    assert result.report.summary, "报告摘要为空"
    assert result.report.findings, "报告缺少问题清单"
    assert result.report.meta["tool_calls"] >= 2
    # 报告必须能被序列化为合法 JSON
    json.dumps(result.report.to_dict(), ensure_ascii=False)
    return f"{result.iterations} 轮 / {result.tool_calls} 次工具调用"


@check("7. 报告三种格式均可渲染")
def _report_check() -> str:
    from codeguard.agent import static_only_review
    from codeguard.report import render_ci_summary, render_json, render_markdown, render_text

    report = static_only_review(ROOT / DEMO, workspace_root=ROOT)
    markdown = render_markdown(report, include_rules_appendix=True)
    text = render_text(report)
    payload = json.loads(render_json(report))
    assert "# CodeGuard" in markdown and "规则 ID" in markdown
    assert "代码审查报告" in text
    assert payload["counts"]["critical"] >= 1
    passed, _ = render_ci_summary(report, fail_on="high")
    assert passed is False, "存在 high 问题时门禁应拦下"
    passed_none, _ = render_ci_summary(report, fail_on="none")
    assert passed_none is True
    return f"{len(report.findings)} 条问题"


@check("8. 报告中的路径是相对工作区的")
def _relative_path_check() -> str:
    """报告可跨机器阅读：不出现本机绝对路径。"""
    from codeguard.agent import static_only_review

    report = static_only_review(ROOT / DEMO, workspace_root=ROOT)
    assert report.findings, "示例代码应有命中"
    for finding in report.findings:
        if finding.file:
            assert not Path(finding.file).is_absolute(), f"报告出现绝对路径：{finding.file}"
            assert ".." not in Path(finding.file).parts, f"报告出现越界相对路径：{finding.file}"
    for path in report.files_reviewed:
        assert not Path(path).is_absolute(), f"审查范围出现绝对路径：{path}"
    return f"首个位置：{report.findings[0].location}"


@check("9. CLI 子命令与退出码符合约定")
def _cli_check() -> str:
    code, output = run_cli("info")
    assert code == 0, f"info 退出码 {code}"
    assert "CodeGuard" in output

    code, output = run_cli("scan", DEMO, "--fail-on", "none")
    assert code == 0, f"scan --fail-on none 退出码应为 0，实际 {code}"

    code, output = run_cli("scan", DEMO, "--fail-on", "high")
    assert code == 1, f"scan --fail-on high 退出码应为 1，实际 {code}"

    code, output = run_cli("scan", "不存在的路径")
    assert code == 2, f"路径不存在应返回用法错误码 2，实际 {code}"

    code, output = run_cli("review", DEMO, "--mock", "--quiet", "--json")
    assert code in (0, 1), f"review --mock 退出码异常：{code}\n{output[:500]}"
    payload = json.loads(output[output.index("{") :])
    assert payload["summary"], "review 输出缺少 summary"

    # --json 的 stdout 必须是**纯 JSON**：横幅/目标/耗时等过程信息应走 stderr。
    # 回归：早期版本把「扫描目标：…」也打进 stdout，导致 `| jq` 直接解析失败。
    for command in (("scan", DEMO, "--json"), ("review", DEMO, "--mock", "--json")):
        code, stdout = run_cli_stdout(*command)
        assert stdout.lstrip().startswith("{"), (
            f"{command[0]} --json 的 stdout 不是以 '{{' 开头：{stdout[:120]!r}"
        )
        parsed = json.loads(stdout)  # 解析失败即视为污染
        assert parsed.get("counts"), f"{command[0]} --json 缺少 counts 字段"

    # --rules 必须真正生效（回归：曾只被解析、从不传给分析引擎）
    code, stdout = run_cli_stdout("scan", DEMO, "--json", "--rules", "CG101")
    only_cg101 = {f["rule_id"] for f in json.loads(stdout)["findings"]}
    assert only_cg101 == {"CG101"}, f"--rules CG101 未生效，实际命中：{sorted(only_cg101)}"

    code, output = run_cli("scan", DEMO, "--rules", "CG999")
    assert code == 2, f"未知规则应返回用法错误码 2，实际 {code}"

    code, output = run_cli("rules")
    assert code == 0 and "CG101" in output
    return "info/scan/review/rules 均正常"


@check("10. tests/ 目录下的测试全部通过")
def _test_suite_check() -> str:
    process = subprocess.run(
        [sys.executable, str(ROOT / "run_tests.py")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert process.returncode == 0, f"测试未通过：\n{(process.stdout or '')[-1500:]}"
    summary = next(
        (line for line in (process.stdout or "").splitlines() if line.startswith("结果：")),
        "结果：未知",
    )
    return summary.strip()


print("=" * 70)
total = len(PASSED) + len(FAILED)
if FAILED:
    print(f"自检失败：{len(PASSED)}/{total} 项通过\n")
    for name, detail in FAILED:
        print(f"  ✗ {name}\n      {detail}")
    sys.exit(1)

print(f"自检全部通过：{len(PASSED)}/{total} 项 ✅")
sys.exit(0)
