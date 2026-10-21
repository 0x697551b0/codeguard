"""静态分析引擎测试：每类规则的正例（必须命中）与负例（不得误报）、严重级别、多文件扫描、语法错误、条目截断、规则过滤。"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codeguard.models import Severity
from codeguard.static_analysis import (
    CodeAnalyzer,
    RULES,
    count_lines,
    rules_table,
)


def rule_ids(source: str) -> set[str]:
    """分析源码并返回命中的规则 ID 集合。"""
    analysis = CodeAnalyzer().analyze_source(source, path="sample.py")
    return {finding.rule_id for finding in analysis.findings}


def findings_of(source: str) -> dict[str, object]:
    analysis = CodeAnalyzer().analyze_source(source, path="sample.py")
    return {finding.rule_id: finding for finding in analysis.findings}


def test_dangerous_dynamic_execution() -> None:
    source = "def f(x):\n    return eval(x)\n"
    assert "CG101" in rule_ids(source)
    assert findings_of(source)["CG101"].severity is Severity.CRITICAL


def test_pickle_and_yaml_deserialization() -> None:
    assert "CG103" in rule_ids("import pickle\n\ndef f(b):\n    return pickle.loads(b)\n")
    assert "CG103" in rule_ids("import yaml\n\ndef f(t):\n    return yaml.load(t)\n")
    # safe_load 不应命中
    assert "CG103" not in rule_ids("import yaml\n\ndef f(t):\n    return yaml.safe_load(t)\n")


def test_os_system_shell_injection() -> None:
    source = "import os\n\ndef f(name):\n    os.system('ls ' + name)\n"
    assert "CG102" in rule_ids(source)


def test_subprocess_shell_true_reported() -> None:
    source = "import subprocess\n\ndef f(cmd):\n    subprocess.call(cmd, shell=True)\n"
    assert "CG102" in rule_ids(source)


def test_subprocess_list_form_not_reported() -> None:
    """安全写法（列表参数 + shell=False）不应误报命令注入。"""
    source = "import subprocess\n\ndef f():\n    subprocess.run(['ls', '-l'], check=True)\n"
    assert "CG102" not in rule_ids(source)


def test_verify_false_disables_tls() -> None:
    source = "import httpx\n\ndef f(url):\n    return httpx.get(url, verify=False)\n"
    assert "CG104" in rule_ids(source)


def test_hardcoded_secret() -> None:
    source = 'API_KEY = "sk-live-1234567890abcdef"\n'
    hits = findings_of(source)
    assert "CG105" in hits
    assert hits["CG105"].severity is Severity.CRITICAL
    # 证据必须脱敏，不能把密钥原文写进报告
    assert "1234567890abcdef" not in hits["CG105"].evidence


def test_placeholder_password_not_reported() -> None:
    """占位符不应被当作泄露的密钥。"""
    source = 'password = "your_password_here"\nPASSWORD_PLACEHOLDER = "changeme_please"\n'
    assert "CG105" not in rule_ids(source)


def test_sql_injection_via_formatting() -> None:
    assert "CG106" in rule_ids("def f(c, email):\n    c.execute(\"SELECT * FROM u WHERE e = '%s'\" % email)\n")
    assert "CG106" in rule_ids('def f(c, uid):\n    c.execute(f"SELECT * FROM u WHERE id = {uid}")\n')


def test_sql_injection_via_variable_indirection() -> None:
    """最容易被漏掉的写法：SQL 先存到变量，再整条传给 execute。"""
    source = (
        "def find(cursor, email):\n"
        "    sql = \"SELECT id FROM users WHERE email = '%s'\" % email\n"
        "    cursor.execute(sql)\n"
    )
    hits = findings_of(source)
    assert "CG106" in hits, "变量间接传参的拼接 SQL 必须被检测到"
    assert "拼接" in hits["CG106"].title
    assert hits["CG106"].line == 3, "应定位到 execute 调用所在行"


def test_sql_literal_variable_is_flagged_as_needs_review() -> None:
    """字面量 SQL 存变量后执行：无法静态确认，列为待确认（medium）。"""
    source = "def f(cursor):\n    sql = 'SELECT id FROM t'\n    cursor.execute(sql)\n"
    hits = findings_of(source)
    assert "CG106" in hits
    assert hits["CG106"].severity is Severity.MEDIUM

    # 参数化查询（模板 + 参数）不应命中
    safe = (
        "def f(cursor, email):\n"
        "    sql = 'SELECT id FROM t WHERE email = %s'\n"
        "    cursor.execute(sql, (email,))\n"
    )
    assert "CG106" not in rule_ids(safe)

    # 内联模板 + 参数同样不命中
    inline = 'def f(cursor, email):\n    cursor.execute("SELECT id FROM t WHERE email = %s", (email,))\n'
    assert "CG106" not in rule_ids(inline)


def test_dynamic_eval_is_detected() -> None:
    """回归：示例代码里 eval 必须被识别（曾因语法错误导致整文件跳过）。"""
    source = 'def evaluate_filter(expression):\n    """doc"""\n    return eval(expression)\n'
    hits = findings_of(source)
    assert "CG101" in hits
    assert hits["CG101"].severity is Severity.CRITICAL


def test_future_import_is_not_reported_as_unused() -> None:
    """回归：``from __future__ import annotations`` 是编译指示，不应报未使用导入。"""
    source = "from __future__ import annotations\n\n\ndef f(x: int) -> int:\n    return x\n"
    assert "CG403" not in rule_ids(source)


def test_parameterized_query_not_reported() -> None:
    source = 'def f(cursor, uid):\n    cursor.execute("SELECT * FROM u WHERE id = ?", (uid,))\n'
    assert "CG106" not in rule_ids(source)


def test_weak_random_for_token() -> None:
    source = "import random\n\ndef f():\n    token = random.randint(100000, 999999)\n    return token\n"
    assert "CG107" in rule_ids(source)


def test_mktemp_race() -> None:
    source = "import tempfile\n\ndef f():\n    return tempfile.mktemp()\n"
    assert "CG108" in rule_ids(source)


def test_bare_except() -> None:
    source = "def f():\n    try:\n        pass\n    except:\n        pass\n"
    hits = findings_of(source)
    assert "CG201" in hits
    assert hits["CG201"].severity is Severity.HIGH


def test_broad_except_without_logging() -> None:
    assert "CG202" in rule_ids("def f():\n    try:\n        pass\n    except Exception:\n        pass\n")

    # 记录了日志就不应再报
    logging_version = (
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception:\n"
        "        logger.exception('boom')\n"
    )
    assert "CG202" not in rule_ids(logging_version)


def test_mutable_default_argument() -> None:
    hits = findings_of("def f(items=[]):\n    items.append(1)\n")
    assert "CG203" in hits
    assert hits["CG203"].severity is Severity.HIGH


def test_none_comparison_uses_is() -> None:
    assert "CG204" in rule_ids("def f(x):\n    return x == None\n")
    assert "CG204" not in rule_ids("def f(x):\n    return x is None\n")


def test_division_by_zero_literal() -> None:
    hits = findings_of("def f(a):\n    return a / 0\n")
    assert "CG205" in hits
    assert hits["CG205"].severity is Severity.CRITICAL


def test_open_without_context_manager() -> None:
    assert "CG206" in rule_ids("def f(p):\n    fh = open(p)\n    return fh.read()\n")
    assert "CG206" not in rule_ids("def f(p):\n    with open(p) as fh:\n        return fh.read()\n")


def test_assert_on_external_input() -> None:
    assert "CG207" in rule_ids("def f(request):\n    assert request.user_id\n    return 1\n")


def test_long_function_and_deep_nesting() -> None:
    # 阈值是 80 行，这里造一个 90 行的函数
    long_body = "def f(x):\n" + "".join(f"    y{index} = {index}\n" for index in range(90)) + "    return x\n"
    assert "CG301" in rule_ids(long_body)

    # 刚过 50 行但未到 80 行的函数不应命中（避免低级噪声）
    medium_body = "def g(x):\n" + "".join(f"    z{index} = {index}\n" for index in range(55)) + "    return x\n"
    assert "CG301" not in rule_ids(medium_body)

    # 真嵌套：循环 → 条件 → 循环 → 条件 → 循环 = 5 层，超过阈值 4
    deep = (
        "def f(a):\n"
        "    for i in a:\n"
        "        if i:\n"
        "            while i:\n"
        "                if i > 1:\n"
        "                    for j in a:\n"
        "                        pass\n"
    )
    assert "CG302" in rule_ids(deep)


def test_nested_depth_ignores_elif_chains() -> None:
    """
    长 elif 链是扁平分支，不应被判为嵌套过深。
    回归：早期实现把 elif（AST 中嵌套的 ast.If）逐层计数，导致按类型分发的扁平函数报出十几层深度。
    """
    flat = (
        "def dispatch(x):\n"
        "    if x == 1:\n"
        "        return 1\n"
        + "".join(f"    elif x == {index}:\n        return {index}\n" for index in range(2, 15))
        + "    return 0\n"
    )
    assert "CG302" not in rule_ids(flat)

    # 循环里套一层 if 仍然只有 2 层，也不应命中
    loop_if = "def g(a):\n    for i in a:\n        if i:\n            pass\n"
    assert "CG302" not in rule_ids(loop_if)

    # 但 if 体里再套循环就该算了：if → for → while = 3 层仍安全，
    # 这里验证"分支内的嵌套确实被计入"
    branch_then_loops = (
        "def h(a, flag):\n"
        "    if flag:\n"
        "        for i in a:\n"
        "            while i:\n"
        "                if i:\n"
        "                    for j in a:\n"
        "                        pass\n"
    )
    assert "CG302" in rule_ids(branch_then_loops)


def test_too_many_parameters() -> None:
    assert "CG303" in rule_ids("def f(a, b, c, d, e, g, h):\n    return a\n")


def test_missing_docstring_and_return_annotation() -> None:
    hits = findings_of("def public_api(x):\n    return x\n")
    assert "CG304" in hits
    assert "CG307" in hits
    # 私有函数与带注解函数不应命中
    assert "CG304" not in rule_ids("def _internal(x):\n    return x\n")
    assert "CG307" not in rule_ids("def public_api(x) -> int:\n    return x\n")


def test_unused_import_and_shadowed_builtin() -> None:
    assert "CG403" in rule_ids("import json\nimport os\n\n\ndef f():\n    return json.dumps({})\n")
    assert "CG404" in rule_ids("def f():\n    list = [1, 2]\n    return list\n")


def test_duplicate_literal() -> None:
    source = (
        "def a():\n    return 'application/json'\n"
        "def b():\n    return 'application/json'\n"
        "def c():\n    return 'application/json'\n"
    )
    assert "CG305" in rule_ids(source)


def test_syntax_error_is_reported() -> None:
    analysis = CodeAnalyzer().analyze_source("def f(:\n    pass\n", path="broken.py")
    assert not analysis.ok
    assert analysis.parse_error
    assert any(f.rule_id == "CG405" for f in analysis.findings)
    assert analysis.findings[0].severity is Severity.CRITICAL


def test_finally_return_swallows_exception() -> None:
    source = "def f():\n    try:\n        raise ValueError('x')\n    finally:\n        return True\n"
    assert "CG208" in rule_ids(source)


def test_clean_code_has_no_high_severity_findings() -> None:
    """核对规范代码的误报情况：不应出现 medium 及以上级别的问题。"""
    root = Path(__file__).resolve().parents[1]
    analysis = CodeAnalyzer().analyze_path(root / "examples" / "demo_buggy_code" / "good_reference.py")
    assert analysis.total >= 0
    serious = [
        f
        for f in analysis.findings
        if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
    ]
    assert serious == [], f"规范代码出现严重误报：{[(f.rule_id, f.title) for f in serious]}"


def test_rule_filter_only_runs_selected_rules() -> None:
    source = "def f(x):\n    return eval(x)\n"
    analysis = CodeAnalyzer(rules=["CG101"]).analyze_source(source, path="s.py")
    assert {f.rule_id for f in analysis.findings} <= {"CG101"}
    assert any(f.rule_id == "CG101" for f in analysis.findings)


def test_directory_scan_collects_all_python_files() -> None:
    root = Path(__file__).resolve().parents[1]
    summary = CodeAnalyzer().analyze_path(root / "examples" / "demo_buggy_code")
    assert len(summary.files) >= 3
    assert summary.total > 20, "示例代码应命中大量规则"
    assert "critical" in summary.counts


def test_max_findings_per_file_truncates() -> None:
    analyzer = CodeAnalyzer(max_findings_per_file=3)
    source = "\n".join(f"def f{index}():\n    return eval('1')\n" for index in range(20))
    analysis = analyzer.analyze_source(source, path="big.py")
    assert len(analysis.findings) <= 4  # 3 条 + 1 条截断提示
    assert any("截断" in f.title for f in analysis.findings)


def test_rules_table_is_consistent() -> None:
    table = rules_table()
    assert len(table) == len(RULES)
    assert {row["rule_id"] for row in table} == {rule.rule_id for rule in RULES}
    for row in table:
        assert row["severity"] in {s.value for s in Severity}


def test_count_lines_statistics() -> None:
    total, code, comments = count_lines("# comment\n\nx = 1\n")
    assert total == 3
    assert comments >= 1
    assert code <= 3
