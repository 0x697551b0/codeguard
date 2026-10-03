"""内置静态分析器（纯标准库 ``ast``，零依赖、零网络）。

设计定位：
    这是 Agent 的**确定性事实来源**。LLM 容易漏看、幻觉或前后不一致，
    因此 Agent 的第一步总是先跑这一层，拿到客观命中清单，再让模型
    结合上下文做语义判断并给出修复建议。二者互补：
        * 静态分析 → 客观、可复现、可回归测试，但不懂业务语义；
        * LLM 审查 → 懂语义与意图，但需要事实锚点。

规则编号约定：
    ====== ============================== ==========
    编号    类别                            默认级别
    ====== ============================== ==========
    CG1xx  安全（Security）                critical/high
    CG2xx  可靠性（Reliability）           high/medium
    CG3xx  可维护性（Maintainability）     medium/low
    CG4xx  风格与规范（Style）             low/info
    ====== ============================== ==========
"""

from __future__ import annotations

import ast
import io
import tokenize
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from codeguard.models import Finding, SEVERITY_ORDER, Severity

# --------------------------------------------------------------------------- #
# 常量表
# --------------------------------------------------------------------------- #
#: ``eval``/``exec`` 一类会把字符串当代码执行的函数
DANGEROUS_CALLS: dict[str, tuple[Severity, str]] = {
    "eval": (Severity.CRITICAL, "任意代码执行"),
    "exec": (Severity.CRITICAL, "任意代码执行"),
    "compile": (Severity.HIGH, "动态编译可用于绕过检查"),
    "__import__": (Severity.HIGH, "动态导入可绕过静态检查"),
    "os.system": (Severity.CRITICAL, "Shell 注入"),
    "os.popen": (Severity.HIGH, "Shell 注入"),
    "os.execv": (Severity.HIGH, "进程替换风险"),
    "os.execve": (Severity.HIGH, "进程替换风险"),
    "os.spawnl": (Severity.HIGH, "进程启动风险"),
    "os.remove": (Severity.MEDIUM, "文件删除，需确认路径可信"),
    "os.rmdir": (Severity.MEDIUM, "目录删除，需确认路径可信"),
    "shutil.rmtree": (Severity.HIGH, "递归删除，误删代价极高"),
    "pickle.loads": (Severity.CRITICAL, "反序列化可执行任意代码"),
    "pickle.load": (Severity.CRITICAL, "反序列化可执行任意代码"),
    "marshal.loads": (Severity.HIGH, "反序列化不可信字节码"),
    "yaml.load": (Severity.HIGH, "应使用 yaml.safe_load"),
    "subprocess.run": (Severity.MEDIUM, "需确认未开启 shell=True 且参数已校验"),
    "subprocess.call": (Severity.MEDIUM, "需确认未开启 shell=True 且参数已校验"),
    "subprocess.Popen": (Severity.MEDIUM, "需确认未开启 shell=True 且参数已校验"),
    "subprocess.check_output": (Severity.MEDIUM, "需确认未开启 shell=True 且参数已校验"),
    "tempfile.mktemp": (Severity.HIGH, "存在 TOCTOU 竞态，应使用 mkstemp"),
    "input": (Severity.INFO, "Python 2 语义下等价于 eval，确认运行环境"),
}

#: 应使用 ``secrets`` 替代的伪随机函数
WEAK_RANDOM_CALLS = {"random.random", "random.randint", "random.randrange", "random.choice", "random.shuffle"}

#: 请求库函数：非 ``requests.*`` 结尾的调用才会检查 ``verify=False``
HTTP_LIB_PREFIXES = ("requests.", "httpx.", "aiohttp.")

#: 需要检查 ``shell=True`` 的子进程函数短名
SUBPROCESS_FUNCS = {"run", "call", "Popen", "check_output", "check_call"}

#: 默认视为“硬编码密钥”的敏感变量名关键字（小写匹配）
SECRET_NAME_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "credential",
    "auth",
)

#: 允许出现“疑似密钥”字面量的变量名白名单（这些通常是占位/示例）
SECRET_NAME_ALLOWLIST = ("placeholder", "example", "dummy", "sample", "todo", "your_", "xxx", "<")

#: 密钥形态的正则（用 ``re`` 之前先做 ``in`` 判断，避免误报普通字符串）
SECRET_VALUE_HINTS = ("sk-", "ghp_", "gho_", "AKIA", "-----BEGIN", "Bearer ")

#: 过长的函数体（行数）阈值。
#: 取 80 而非更激进的 50：真实项目里数据映射、报告渲染这类"平铺直叙"的函数
#: 天然较长，把它们全都报出来只会稀释真正重要的问题（低级噪声会淹没高级缺陷）。
LONG_FUNCTION_LINES = 80
#: 需要计入嵌套深度的复合语句（循环与异常处理）。
#: ``if``/``match`` 单独处理：``elif`` 虽然会被解析成嵌套的 ``ast.If``，
#: 但它在写法上是扁平的分支链（如按类型分发的 dispatch 函数），
#: 按每层 +1 计算会把这类清晰代码误判为"嵌套过深"。
NESTING_STATEMENTS = (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)
#: 过深的嵌套阈值
DEEP_NESTING_LIMIT = 4
#: 函数最多参数个数
MAX_FUNCTION_PARAMS = 6
#: 一行最长字符数
MAX_LINE_LENGTH = 120


# --------------------------------------------------------------------------- #
# 规则元数据
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Rule:
    """一条静态规则的元数据（用于文档生成与报告呈现）。"""

    rule_id: str
    title: str
    category: str
    severity: Severity
    description: str


RULES: tuple[Rule, ...] = (
    Rule("CG101", "危险的动态执行调用", "security", Severity.CRITICAL, "eval/exec/compile 等可将字符串作为代码执行，输入不可信时导致 RCE。"),
    Rule("CG102", "Shell 注入风险", "security", Severity.CRITICAL, "os.system/os.popen 或 subprocess 的 shell=True 直接拼接命令，存在命令注入。"),
    Rule("CG103", "不安全的反序列化", "security", Severity.CRITICAL, "pickle/marshal/yaml.load 反序列化不可信数据可导致任意代码执行。"),
    Rule("CG104", "关闭 TLS 校验", "security", Severity.HIGH, "verify=False 会失去中间人攻击防护。"),
    Rule("CG105", "硬编码密钥", "security", Severity.HIGH, "密钥/口令直接写在源码中，一旦入库即泄露，应改用环境变量或密钥管理服务。"),
    Rule("CG106", "SQL 注入风险", "security", Severity.HIGH, "使用字符串拼接/格式化构造 SQL，应改为参数化查询。"),
    Rule("CG107", "弱随机数用于安全场景", "security", Severity.MEDIUM, "random 模块非密码学安全，口令/令牌应使用 secrets。"),
    Rule("CG108", "临时文件竞态", "security", Severity.HIGH, "tempfile.mktemp 存在 TOCTOU 竞态，应使用 mkstemp/NamedTemporaryFile。"),

    Rule("CG201", "裸 except", "reliability", Severity.HIGH, "except: 会吞掉 KeyboardInterrupt/SystemExit 等，掩盖真实错误。"),
    Rule("CG202", "捕获过于宽泛的异常", "reliability", Severity.MEDIUM, "except Exception 后未记录日志或未重新抛出，会静默失败难以排查。"),
    Rule("CG203", "可变默认参数", "reliability", Severity.HIGH, "函数默认参数在定义时求值并跨调用共享，造成状态污染。"),
    Rule("CG204", "直接比较 None/True/False", "reliability", Severity.LOW, "应使用 is None / is True，避免 __eq__ 重载带来的歧义。"),
    Rule("CG205", "除法未做零值保护", "reliability", Severity.MEDIUM, "除数可能为 0 时抛 ZeroDivisionError，需显式校验。"),
    Rule("CG206", "资源未使用 with 管理", "reliability", Severity.MEDIUM, "open() 未使用上下文管理器，异常路径下文件句柄会泄漏。"),
    Rule("CG207", "assert 用于运行时校验", "reliability", Severity.MEDIUM, "python -O 会移除 assert，不能用于业务校验。"),
    Rule("CG208", "return 与 finally 混用", "reliability", Severity.MEDIUM, "finally 中的 return/break 会吞掉异常，行为反直觉。"),

    Rule("CG301", "函数过长", "maintainability", Severity.MEDIUM, f"单个函数超过 {LONG_FUNCTION_LINES} 行，职责过多，难以测试与复用，建议拆分。"),
    Rule("CG302", "嵌套过深", "maintainability", Severity.MEDIUM, "控制流嵌套过深会显著降低可读性，建议早返回或提取函数。"),
    Rule("CG303", "函数参数过多", "maintainability", Severity.LOW, "参数过多通常意味着缺少抽象，建议用数据类聚合。"),
    Rule("CG304", "模块/函数缺少文档字符串", "maintainability", Severity.LOW, "公共接口缺少 docstring，影响可维护性与自动文档生成。"),
    Rule("CG305", "重复的字面量", "maintainability", Severity.LOW, "同一字面量反复出现，应提取为具名常量。"),
    Rule("CG307", "类型注解缺失", "maintainability", Severity.INFO, "函数缺少返回值/参数注解，降低静态检查与 IDE 辅助能力。"),

    Rule("CG401", "行长度超限", "style", Severity.INFO, f"单行超过 {MAX_LINE_LENGTH} 字符，建议按 PEP 8 折行。"),
    Rule("CG402", "行尾空白", "style", Severity.INFO, "行尾存在多余空白字符。"),
    Rule("CG403", "未使用的导入", "style", Severity.LOW, "导入了但未使用的模块，属于死代码。"),
    Rule("CG404", "变量遮蔽内置名称", "style", Severity.LOW, "使用 list/dict/str 等内置名做变量，会遮蔽内置对象。"),
    Rule("CG405", "语法错误", "style", Severity.CRITICAL, "文件无法被解析为合法 Python 语法。"),
)

RULE_INDEX: dict[str, Rule] = {rule.rule_id: rule for rule in RULES}

#: Python 内置名，用作局部变量时提示
BUILTIN_NAMES = frozenset(
    """
    abs all any ascii bin bool bytearray bytes callable chr classmethod compile complex delattr dict dir divmod
    enumerate eval exec filter float format frozenset getattr globals hasattr hash help hex id input int isinstance
    issubclass iter len list locals map max memoryview min next object oct open ord pow print property range repr
    reversed round set setattr slice sorted staticmethod str sum super tuple type vars zip
    """.split()
)

#: 允许重复出现的“魔法”字面量（不纳入 CG305）
REPEATED_LITERAL_ALLOWLIST = frozenset({"", "utf-8", "\n", " ", "0", "1", "-1", "True", "False", "None", ",", "."})

#: 可能执行 SQL 的方法名（小写），用于 CG106 的调用点识别
SQL_CALLER_NAMES = frozenset({"execute", "executemany", "executescript", "executedict", "raw", "query"})

#: 判定字符串"像 SQL"的关键字（小写）
SQL_KEYWORDS = (
    "select ", "insert into", "update ", "delete from", "drop table",
    "create table", "alter table", " from ", " where ", " values ",
)

#: SQL 变量名的提示词（小写）—— 用于避免把普通字符串误判成 SQL
SQL_VARIABLE_NAME_HINTS = ("sql", "query", "stmt", "statement", "select", "insert", "update", "delete")


# --------------------------------------------------------------------------- #
# 分析结果
# --------------------------------------------------------------------------- #
@dataclass
class FileAnalysis:
    """单个文件的静态分析结果。"""

    path: str
    findings: list[Finding] = field(default_factory=list)
    #: 解析失败时的原因（例如语法错误）
    parse_error: str | None = None
    #: 文件统计信息
    stats: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.parse_error is None


@dataclass
class AnalysisSummary:
    """一次多文件分析的汇总。"""

    files: list[FileAnalysis] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        merged: list[Finding] = []
        for file_analysis in self.files:
            merged.extend(file_analysis.findings)
        merged.sort(key=lambda f: f.sort_key)
        return merged

    @property
    def counts(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def total(self) -> int:
        return sum(len(f.findings) for f in self.files)

    def to_dict(self) -> dict[str, object]:
        return {
            "total_findings": self.total,
            "counts": self.counts,
            "files": [
                {
                    "path": f.path,
                    "findings": len(f.findings),
                    "parse_error": f.parse_error,
                    "stats": f.stats,
                }
                for f in self.files
            ],
            "skipped": self.skipped,
        }


# --------------------------------------------------------------------------- #
# 主体分析器
# --------------------------------------------------------------------------- #
class CodeAnalyzer:
    """把 Python 源码字符串解析为一条条 :class:`Finding`。"""

    def __init__(self, *, rules: Sequence[str] | None = None, max_findings_per_file: int = 200) -> None:
        """
        Args:
            rules: 只启用这些规则 ID；``None`` 表示全部启用。
            max_findings_per_file: 单文件最多保留的条目数，防止大文件刷屏。
        """
        self.enabled = set(rules) if rules else {r.rule_id for r in RULES}
        self.max_findings_per_file = max_findings_per_file

    # ------------------------------------------------------------------ #
    def analyze_source(self, source: str, *, path: str = "<string>") -> FileAnalysis:
        """分析源码字符串。"""
        result = FileAnalysis(path=path)
        lines = source.splitlines()
        result.stats["lines"] = len(lines)
        result.stats["characters"] = len(source)

        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            result.parse_error = f"{exc.msg} (line {exc.lineno})"
            rule = RULE_INDEX["CG405"]
            result.findings.append(
                Finding(
                    title=f"{rule.title}：{exc.msg}",
                    severity=rule.severity,
                    category=rule.category,
                    file=path,
                    line=exc.lineno,
                    evidence=(lines[exc.lineno - 1].strip() if exc.lineno and exc.lineno <= len(lines) else ""),
                    explanation="该文件无法被解析，后续所有语义分析均不可靠，请先修复语法。",
                    suggestion="修复语法错误后重新审查。",
                    source="static",
                    rule_id=rule.rule_id,
                )
            )
            return result

        result.stats["functions"] = sum(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) for n in ast.walk(tree)
        )
        result.stats["classes"] = sum(isinstance(n, ast.ClassDef) for n in ast.walk(tree))

        collector = _FindingCollector(self.enabled, path, lines)
        collector.precollect_sql_variables(tree)
        collector.visit(tree)
        self._check_unused_imports(tree, path, lines, collector)
        self._check_line_level(lines, path, collector)
        self._check_duplicate_literals(tree, path, collector)

        findings = sorted(collector.findings, key=lambda f: f.sort_key)
        if len(findings) > self.max_findings_per_file:
            trimmed = findings[: self.max_findings_per_file]
            trimmed.append(
                Finding(
                    title=f"条目过多，已截断（共 {len(findings)} 条）",
                    severity=Severity.INFO,
                    category="meta",
                    file=path,
                    source="static",
                    rule_id="CG000",
                    explanation="为避免报告过长，单文件条目超过上限后仅保留最严重的部分。",
                    suggestion="建议拆分该文件以降低复杂度。",
                )
            )
            findings = trimmed
        result.findings = findings
        return result

    # ------------------------------------------------------------------ #
    def analyze_file(self, path: str | Path) -> FileAnalysis:
        """分析单个文件（自动处理编码与超大文件）。"""
        file_path = Path(path)
        try:
            source = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                source = file_path.read_text(encoding="gbk")
            except (UnicodeDecodeError, OSError) as exc:
                return FileAnalysis(path=str(file_path), parse_error=f"编码无法识别：{exc}")
        except OSError as exc:
            return FileAnalysis(path=str(file_path), parse_error=f"读取失败：{exc}")
        return self.analyze_source(source, path=str(file_path))

    def analyze_path(self, path: str | Path, *, recursive: bool = True) -> AnalysisSummary:
        """分析文件或目录（目录默认递归收集 ``*.py``）。"""
        target = Path(path)
        summary = AnalysisSummary()
        if not target.exists():
            summary.skipped.append(f"{target}：路径不存在")
            return summary

        if target.is_file():
            summary.files.append(self.analyze_file(target))
            return summary

        for file_path in _iter_python_files(target, recursive=recursive):
            summary.files.append(self.analyze_file(file_path))
        if not summary.files:
            summary.skipped.append(f"{target}：未找到 .py 文件")
        return summary

    # ------------------------------------------------------------------ #
    # 跨语句检查
    # ------------------------------------------------------------------ #
    def _check_unused_imports(self, tree: ast.AST, path: str, lines: list[str], collector: "_FindingCollector") -> None:
        """CG403：导入但未使用的名称。

        只对 AST 做**一次**遍历，同时收集"导入了什么"与"引用了什么"。
        早期版本分三次 ``ast.walk`` 分别收集导入、标识符、字符串，虽然结果
        相同，但三次遍历既慢又让代码嵌套更深 —— 一次遍历更简单也更高效。
        """
        if "CG403" not in self.enabled:
            return

        scan = _ImportUsageScan()
        for node in ast.walk(tree):
            if scan.observe(node) is False:
                return  # 存在星号导入，无法判断

        rule = RULE_INDEX["CG403"]
        for name, lineno in sorted(scan.imported.items(), key=lambda item: item[1]):
            if name in scan.used or name.startswith("_"):
                continue
            collector.add(
                rule,
                title=f"未使用的导入：{name}",
                line=lineno,
                evidence=lines[lineno - 1].strip() if lineno <= len(lines) else "",
                explanation=f"导入的 `{name}` 在文件中未被引用，属于死代码。",
                suggestion=f"删除 `import {name}`；若属于可选依赖，改为在函数内延迟导入。",
                severity=rule.severity,
                category=rule.category,
            )

    def _check_line_level(self, lines: list[str], path: str, collector: "_FindingCollector") -> None:
        """CG401/CG402：基于行的检查（跳过字符串字面量内部的误报，这里采用保守策略）。"""
        if "CG401" in self.enabled and lines:
            long_lines = [i + 1 for i, line in enumerate(lines) if len(line) > MAX_LINE_LENGTH]
            rule = RULE_INDEX["CG401"]
            for lineno in long_lines[:3]:
                collector.add(
                    rule,
                    title=f"行长度超限（{len(lines[lineno - 1])} > {MAX_LINE_LENGTH}）",
                    line=lineno,
                    evidence=lines[lineno - 1][:200],
                    explanation="超长行影响可读性，且在代码评审/diff 中难以并排查看。",
                    suggestion="按 PEP 8 折行，或提取中间变量以缩短表达式。",
                    severity=rule.severity,
                    category=rule.category,
                )

        if "CG402" in self.enabled:
            trailing = [i + 1 for i, line in enumerate(lines) if line != line.rstrip() and line.strip()]
            for lineno in trailing[:5]:
                rule = RULE_INDEX["CG402"]
                collector.add(
                    rule,
                    title="行尾空白",
                    line=lineno,
                    evidence=lines[lineno - 1][:120] + "␠",
                    explanation="行尾空白会污染 diff，部分工具链还会因此报错。",
                    suggestion="配置编辑器 trim trailing whitespace，或运行 `ruff format` / `black`。",
                    severity=rule.severity,
                    category=rule.category,
                )

    def _check_duplicate_literals(self, tree: ast.AST, path: str, collector: "_FindingCollector") -> None:
        """CG305：同一字符串/数字字面量重复出现 3 次以上。"""
        if "CG305" not in self.enabled:
            return

        occurrences: dict[object, list[int]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float)) and not isinstance(node.value, bool):
                if isinstance(node.value, str) and (node.value in REPEATED_LITERAL_ALLOWLIST or len(node.value) < 4):
                    continue
                if isinstance(node.value, (int, float)) and node.value in (0, 1, -1, 2):
                    continue
                occurrences.setdefault(node.value, []).append(node.lineno)

        rule = RULE_INDEX["CG305"]
        for value, linenos in occurrences.items():
            if len(linenos) < 3:
                continue
            preview = repr(value)[:60]
            collector.add(
                rule,
                title=f"字面量重复出现 {len(linenos)} 次：{preview}",
                line=min(linenos),
                evidence=preview,
                explanation=f"同一个字面量在 {len(linenos)} 处硬编码，修改时容易遗漏。",
                suggestion="提取为模块级常量（如 `MAX_RETRY = 3`），或放入配置文件。",
                severity=rule.severity,
                category=rule.category,
            )
            break  # 只报最典型的一处，避免噪声


class _ImportUsageScan:
    """一次 AST 遍历内同时收集"导入了什么"与"引用了什么"。

    单独成类（而非嵌在遍历循环里）是为了把导入/引用的判定规则集中在一处，
    新增"哪种写法算作使用"时只需改这里。
    """

    def __init__(self) -> None:
        #: 导入名 → 行号
        self.imported: dict[str, int] = {}
        #: 文件中出现过的名称（含字符串，以覆盖字符串注解与 __all__）
        self.used: set[str] = set()
        #: 是否遇到无法静态判断的星号导入
        self.star_import = False

    def observe(self, node: ast.AST) -> bool:
        """观察一个 AST 节点；返回 ``False`` 表示整体无法判断（星号导入）。"""
        if isinstance(node, ast.Import):
            self._register_import(node)
        elif isinstance(node, ast.ImportFrom):
            self._register_import_from(node)
        elif isinstance(node, ast.Name):
            self.used.add(node.id)
        elif isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                self.used.add(root.id)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            self.used.add(node.value)
        return not self.star_import

    def _register_import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imported.setdefault(alias.asname or alias.name.split(".")[0], node.lineno)

    def _register_import_from(self, node: ast.ImportFrom) -> None:
        # __future__ 导入是编译指示，没有可引用的名称，天然"未被使用"
        if node.module == "__future__":
            return
        for alias in node.names:
            if alias.name == "*":
                self.star_import = True
                return
            self.imported.setdefault(alias.asname or alias.name, node.lineno)


class _FindingCollector(ast.NodeVisitor):
    """遍历 AST 并累积发现。"""

    def __init__(self, enabled: set[str], path: str, lines: list[str]) -> None:
        self.enabled = enabled
        self.path = path
        self.lines = lines
        self.findings: list[Finding] = []
        #: 当前所在函数名，用于生成更可读的标题
        self._function_stack: list[str] = []
        #: 已处于 ``with`` 上下文中的 ``open()`` 调用节点 id（由 visit_With 填充）
        self._with_managed: set[int] = set()
        #: 变量名 → 定义行号；值为正数表示该变量由拼接/格式化构造，``0`` 表示只是"像 SQL"
        self._sql_like_variables: dict[str, int] = {}
        #: 已产出发现的身份集合，用于去重
        self._seen: set[tuple[str, int | None, str]] = set()

    # ------------------------------------------------------------------ #
    def enabled_rule(self, rule_id: str) -> bool:
        return rule_id in self.enabled

    def add(
        self,
        rule: Rule,
        *,
        title: str,
        line: int | None = None,
        evidence: str = "",
        explanation: str = "",
        suggestion: str = "",
        severity: Severity | None = None,
        category: str | None = None,
    ) -> None:
        if not self.enabled_rule(rule.rule_id):
            return
        # 同一位置的同一条规则只报告一次。
        # 某些 AST 节点会被多个检查路径覆盖（例如同一行既有 ``input()``
        # 又有其他被检查的调用），没有这层保护就会产生重复条目，
        # 让报告显得不可信。
        identity = (rule.rule_id, line, title)
        if identity in self._seen:
            return
        self._seen.add(identity)
        self.findings.append(
            Finding(
                title=title,
                severity=severity or rule.severity,
                category=category or rule.category,
                file=self.path,
                line=line,
                evidence=evidence.strip()[:300],
                explanation=explanation,
                suggestion=suggestion,
                source="static",
                rule_id=rule.rule_id,
            )
        )

    def snippet(self, lineno: int | None, *, limit: int = 200) -> str:
        if not lineno or lineno < 1 or lineno > len(self.lines):
            return ""
        return self.lines[lineno - 1].strip()[:limit]

    @property
    def context(self) -> str:
        return f"（在 {self._function_stack[-1]} 中）" if self._function_stack else ""

    # ------------------------------------------------------------------ #
    # 函数级检查
    # ------------------------------------------------------------------ #
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """对函数定义执行全部函数级规则。

        每条规则抽成独立的 ``_check_*`` 方法：新增规则只需加一行调用，
        也便于按规则单独测试与调整阈值。
        """
        self._function_stack.append(node.name)
        try:
            self._check_mutable_defaults(node)
            self._check_function_length(node)
            self._check_nesting_depth(node)
            self._check_param_count(node)
            self._check_docstring(node)
            self._check_return_annotation(node)
            self.generic_visit(node)
        finally:
            self._function_stack.pop()

    def _check_mutable_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """CG203：可变默认参数（``[]`` / ``{}`` / ``set()``）。"""
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        if not any(isinstance(default, (ast.List, ast.Dict, ast.Set)) for default in defaults):
            return
        self.add(
            RULE_INDEX["CG203"],
            title=f"可变默认参数：{node.name}(){self.context}",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation="默认参数在函数定义时求值一次并被所有调用共享，就地修改会污染后续调用。",
            suggestion="改用 `None` 哨兵：`def f(items=None): items = [] if items is None else items`。",
        )

    def _check_function_length(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """CG301：函数体过长。"""
        end_lineno = getattr(node, "end_lineno", None)
        if not end_lineno:
            return
        length = end_lineno - node.lineno
        if length <= LONG_FUNCTION_LINES:
            return
        self.add(
            RULE_INDEX["CG301"],
            title=f"函数过长：{node.name} 共 {length} 行{self.context}",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation=f"超过 {LONG_FUNCTION_LINES} 行，通常承担了多个职责。",
            suggestion="按“单一职责”拆分为若干小函数，并为其补充单元测试。",
        )

    def _check_nesting_depth(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """CG302：控制流嵌套过深。"""
        depth = _max_control_depth(node)
        if depth <= DEEP_NESTING_LIMIT:
            return
        self.add(
            RULE_INDEX["CG302"],
            title=f"嵌套过深：{node.name} 最大深度 {depth}{self.context}",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation=f"控制流嵌套达到 {depth} 层（阈值 {DEEP_NESTING_LIMIT}）。",
            suggestion="使用卫语句（early return）或把内层逻辑提取为独立函数。",
        )

    def _check_param_count(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """CG303：函数参数过多。"""
        args = node.args
        count = len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
        if count <= MAX_FUNCTION_PARAMS:
            return
        self.add(
            RULE_INDEX["CG303"],
            title=f"函数参数过多：{node.name} 有 {count} 个参数{self.context}",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation="参数过多通常意味着缺少一个聚合抽象。",
            suggestion="使用 `@dataclass` 定义参数对象，或采用“配置对象 + 关键字参数”模式。",
        )

    def _check_docstring(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """CG304：公共函数缺少 docstring。"""
        if ast.get_docstring(node) or node.name.startswith("_"):
            return
        self.add(
            RULE_INDEX["CG304"],
            title=f"缺少文档字符串：{node.name}{self.context}",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation="公共函数没有 docstring，调用方难以了解契约与副作用。",
            suggestion="补充简要说明用户意图的 docstring（推荐 Google 风格）。",
            severity=Severity.LOW if node.name != "__init__" else Severity.INFO,
        )

    def _check_return_annotation(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """CG307：公共函数缺少返回值注解。"""
        if node.returns or node.name.startswith("_"):
            return
        self.add(
            RULE_INDEX["CG307"],
            title=f"缺少返回值类型注解：{node.name}{self.context}",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation="无返回注解会降低 mypy 等静态检查的有效性。",
            suggestion="补充 `-> ReturnType`，必要时使用 `typing.Optional` / `|` 联合类型。",
        )

    # ------------------------------------------------------------------ #
    # 调用级检查
    # ------------------------------------------------------------------ #
    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        short = dotted.rsplit(".", 1)[-1] if dotted else ""

        if dotted in DANGEROUS_CALLS:
            severity, reason = DANGEROUS_CALLS[dotted]
            self._check_call_guards(node, dotted, severity, reason)
        elif short in SUBPROCESS_FUNCS and (dotted.startswith("subprocess.") or dotted == short):
            self._check_call_guards(node, dotted or short, Severity.MEDIUM, "Shell 注入")

        self._check_verify_false(node, dotted)
        self._check_sql_injection(node, dotted)
        self._check_weak_random(node, dotted)
        self._check_open_without_with(node, dotted)

        self.generic_visit(node)

    def _check_call_guards(self, node: ast.Call, dotted: str, severity: Severity, reason: str) -> None:
        """危险调用的统一报告逻辑。"""
        keyword_map = {kw.arg: kw.value for kw in node.keywords if kw.arg}
        is_subprocess = dotted.startswith("subprocess.") or dotted in SUBPROCESS_FUNCS
        first_arg = node.args[0] if node.args else None

        if is_subprocess:
            shell_flag = keyword_map.get("shell")
            shell_is_true = isinstance(shell_flag, ast.Constant) and shell_flag.value is True
            shell_is_false = isinstance(shell_flag, ast.Constant) and shell_flag.value is False
            literal_command = isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str)
            literal_list = isinstance(first_arg, (ast.List, ast.Tuple))
            interpolated = first_arg is not None and _is_interpolated(first_arg)

            # 明确的列表参数（或已显式 shell=False）+ 无插值 —— 安全写法，不报
            if (literal_list or shell_is_false) and not interpolated:
                return
            if not shell_is_true and literal_command and not interpolated:
                return
            if shell_is_true:
                self.add(
                    RULE_INDEX["CG102"],
                    title=f"shell=True 存在命令注入风险{self.context}",
                    line=node.lineno,
                    evidence=self.snippet(node.lineno),
                    explanation="shell=True 时命令交由系统 shell 解析，用户可控输入可注入任意命令。",
                    suggestion="改为列表参数并保持 shell=False：`subprocess.run(['ls', '-l'], check=True)`。",
                    severity=Severity.CRITICAL,
                )
                return
            if interpolated:
                self.add(
                    RULE_INDEX["CG102"],
                    title=f"命令参数由字符串拼接/格式化构造{self.context}",
                    line=node.lineno,
                    evidence=self.snippet(node.lineno),
                    explanation="通过 f-string/format/% 拼接命令参数，输入未校验时会造成参数注入。",
                    suggestion="传列表参数，并对每个参数做白名单校验；避免 shell 解析。",
                    severity=Severity.HIGH,
                )
                return

            # 动态变量直接作为命令、且未声明 shell 行为 —— 无法静态判定，
            # 仅在有明确风险信号（关键字参数里出现 shell 或命令来自函数参数）时提示
            if shell_flag is not None:
                self.add(
                    RULE_INDEX["CG102"],
                    title=f"子进程的 shell 参数非常量，请确认{self.context}",
                    line=node.lineno,
                    evidence=self.snippet(node.lineno),
                    explanation="shell 参数不是字面量，无法静态确认是否会交由 shell 解析。",
                    suggestion="把 shell 明确写死为 `False`；命令用列表形式传入。",
                    severity=Severity.MEDIUM,
                )
            return

        # os.system / eval / exec 等
        rule_id = "CG102" if dotted.startswith("os.") else "CG101"
        if dotted in ("pickle.load", "pickle.loads", "marshal.loads", "yaml.load"):
            rule_id = "CG103"
        elif dotted == "tempfile.mktemp":
            rule_id = "CG108"
        rule = RULE_INDEX[rule_id]
        self.add(
            rule,
            title=f"危险调用 `{dotted}()`：{reason}{self.context}",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation=f"`{dotted}` 的输入若来自用户或外部数据，会被直接当作代码/命令执行。",
            suggestion={
                "eval": "改用 `ast.literal_eval`，或使用显式解析器（json / int()）。",
                "exec": "避免动态执行；若必须，请使用受限命名空间并做白名单校验。",
                "pickle.loads": "改用 JSON、MessagePack 等安全格式，或对数据做签名校验。",
                "yaml.load": "改用 `yaml.safe_load`。",
                "tempfile.mktemp": "改用 `tempfile.mkstemp` 或 `NamedTemporaryFile`。",
            }.get(dotted.rsplit(".", 1)[-1], "改用不执行字符串的安全 API，并对输入做白名单校验。"),
            severity=severity,
        )

    def _check_verify_false(self, node: ast.Call, dotted: str) -> None:
        """CG104：``verify=False`` / ``ssl_verify=False``。"""
        for kw in node.keywords:
            if kw.arg in {"verify", "ssl_verify", "check_hostname"} and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                rule = RULE_INDEX["CG104"]
                self.add(
                    rule,
                    title=f"关闭 TLS 校验：{dotted or '调用'}(verify=False){self.context}",
                    line=node.lineno,
                    evidence=self.snippet(node.lineno),
                    explanation="关闭证书校验后无法防御中间人攻击，抓包即可窃取凭据。",
                    suggestion="移除 verify=False；自签证书场景请通过 `verify='/path/ca.pem'` 指定 CA。",
                )

    def _check_sql_injection(self, node: ast.Call, dotted: str) -> None:
        """CG106：SQL 语句由拼接/格式化/变量间接传参构造。

        覆盖三种常见写法：

        1. 直接内联插值：``cursor.execute(f"... {uid}")``
        2. 变量间接传参：``sql = "SELECT ... % (email,)"; cursor.execute(sql)``
           —— 这是真实代码里最常见的形式，只看参数表达式会整个漏掉；
        3. 字面量占位符未参数化：``execute("... WHERE id = %s")``（只传了 1 个参数）
        """
        short = dotted.rsplit(".", 1)[-1].lower() if dotted else ""
        if short not in SQL_CALLER_NAMES or not node.args:
            return

        first = node.args[0]
        rule = RULE_INDEX["CG106"]

        # ① 内联插值（f-string / % 格式化 / 字符串相加 / .format）
        if _is_interpolated(first):
            self.add(
                rule,
                title=f"SQL 语句由拼接/格式化构造{self.context}",
                line=node.lineno,
                evidence=self.snippet(node.lineno),
                explanation="把外部输入直接拼进 SQL 会造成 SQL 注入，输入可完全控制查询语义。",
                suggestion="使用参数化查询：`cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))`。",
            )
            return

        # ② 变量间接传参：查询该变量是否为拼接出来的 SQL
        if isinstance(first, ast.Name):
            self._report_sql_variable(node, first.id)
            return

        # ③ 字面量 SQL：含占位符却只传了一个参数，说明占位符没走参数化
        is_literal_sql = (
            isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and any(keyword in first.value.lower() for keyword in SQL_KEYWORDS)
        )
        if is_literal_sql and len(node.args) == 1 and _contains_sql_format_marker(first):
            self.add(
                rule,
                title=f"SQL 使用字符串格式化占位但未传参{self.context}",
                line=node.lineno,
                evidence=self.snippet(node.lineno),
                explanation="SQL 中含 `%s`/`{}` 等占位符却没有作为参数传给驱动，占位符不会被安全替换。",
                suggestion="改为参数化查询：`execute('... WHERE id = %s', (uid,))`。",
            )

    def _report_sql_variable(self, node: ast.Call, variable: str) -> None:
        """②分支的补充：报告"SQL 变量被直接执行"。

        ``origin`` 为该变量的定义行号：正数表示确实由拼接构造（HIGH），
        ``0`` 表示只是"像 SQL"的字面量（MEDIUM，需人工确认）。
        """
        origin = self._sql_like_variables.get(variable)
        if origin is None:
            return
        rule = RULE_INDEX["CG106"]
        # 传了额外参数说明走的是驱动占位符参数化 —— 这是安全写法，不报
        parameterized = len(node.args) > 1 or bool(node.keywords)

        if origin:
            self.add(
                rule,
                title=f"拼接后的 SQL 变量被直接执行：{variable}{self.context}",
                line=node.lineno,
                evidence=self.snippet(node.lineno),
                explanation=(
                    f"变量 `{variable}` 由格式化/拼接构造（见第 {origin} 行），再交给 `execute` 执行，"
                    "等价于拼接 SQL，存在注入风险。"
                ),
                suggestion=(
                    "把 SQL 写成固定模板并用驱动占位符传参："
                    f"`{variable} = '... WHERE email = %s'` 然后 `cursor.execute({variable}, (email,))`。"
                ),
            )
        elif not parameterized:
            self.add(
                rule,
                title=f"SQL 变量被直接执行，需确认来源：{variable}{self.context}",
                line=node.lineno,
                evidence=self.snippet(node.lineno),
                explanation=(
                    f"变量 `{variable}` 的取值无法静态确认，且未传任何参数，"
                    "若其中含外部输入即构成注入。本条目列为需人工确认的提示。"
                ),
                suggestion="确认该 SQL 是固定模板且参数经驱动占位符传入；否则改为参数化查询。",
                severity=Severity.MEDIUM,
            )

    def _check_weak_random(self, node: ast.Call, dotted: str) -> None:
        """CG107：``random`` 用于疑似安全场景。"""
        if dotted not in WEAK_RANDOM_CALLS:
            return
        line_text = self.snippet(node.lineno).lower()
        security_hint = any(kw in line_text for kw in ("token", "password", "secret", "salt", "session", "nonce", "key"))
        if not security_hint:
            return
        rule = RULE_INDEX["CG107"]
        self.add(
            rule,
            title=f"疑似用弱随机数生成安全凭据：{dotted}{self.context}",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation="`random` 基于梅森旋转算法，可被预测，不能用于安全敏感值。",
            suggestion="改用 `secrets.token_urlsafe(32)` / `secrets.token_hex(16)`。",
        )

    def visit_Assert(self, node: ast.Assert) -> None:
        """CG207：``assert`` 在校验外部输入。"""
        text = ast.unparse(node.test) if hasattr(ast, "unparse") else self.snippet(node.lineno)
        external_hint = any(kw in text for kw in ("input", "request", "args", "json", "param", "user"))
        if not external_hint:
            self.generic_visit(node)
            return
        rule = RULE_INDEX["CG207"]
        self.add(
            rule,
            title="使用 assert 校验外部输入",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation="`python -O` 会移除所有 assert，校验随之失效，可能造成安全或数据问题。",
            suggestion="改为显式判断并抛出 `ValueError`/自定义异常。",
        )
        self.generic_visit(node)

    def _check_open_without_with(self, node: ast.Call, dotted: str) -> None:
        """CG206：``open()`` 未使用上下文管理器（启发式：父节点不是 with）。"""
        if dotted != "open":
            return
        # 通过记录在 visit_With 中已处理的节点来判定
        if id(node) in self._with_managed:
            return
        rule = RULE_INDEX["CG206"]
        self.add(
            rule,
            title="open() 未使用 with 上下文管理器",
            line=node.lineno,
            evidence=self.snippet(node.lineno),
            explanation="异常路径下文件句柄不会及时释放，长驻进程会造成句柄泄漏。",
            suggestion="改为 `with open(path, encoding='utf-8') as fh: ...`。",
        )

    #: 处于 ``with`` 上下文中的节点 id 集合（由 :meth:`visit_With` 填充）
    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if isinstance(item.context_expr, ast.Call):
                self._with_managed.add(id(item.context_expr))
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)  # type: ignore[arg-type]

    # ------------------------------------------------------------------ #
    # 语句级检查
    # ------------------------------------------------------------------ #
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        line_text = self.snippet(node.lineno)
        # CG201 裸 except
        if node.type is None:
            rule = RULE_INDEX["CG201"]
            self.add(
                rule,
                title="裸 except 会吞掉所有异常",
                line=node.lineno,
                evidence=line_text,
                explanation="`except:` 会连 `KeyboardInterrupt`、`SystemExit` 一起吞掉，导致程序无法中断、错误被掩盖。",
                suggestion="捕获具体异常类型（如 `except ValueError as exc:`），或至少 `except Exception:` 并记录日志后重新抛出。",
            )
        else:
            type_name = _dotted_name(node.type) or ""
            broad = type_name in {"Exception", "BaseException"}
            has_logging = any(
                isinstance(child, ast.Call) and (".error" in (_dotted_name(child.func) or "") or ".exception" in (_dotted_name(child.func) or "") or "logging" in (_dotted_name(child.func) or ""))
                for child in ast.walk(node)
            )
            re_raises = any(isinstance(child, ast.Raise) for child in ast.walk(node))
            if broad and not has_logging and not re_raises:
                rule = RULE_INDEX["CG202"]
                self.add(
                    rule,
                    title=f"捕获 `{type_name}` 后静默忽略",
                    line=node.lineno,
                    evidence=line_text,
                    explanation="宽泛捕获且既不记录日志也不重新抛出，故障会被完全静默，线上问题极难定位。",
                    suggestion="记录 `logger.exception(...)` 后重新抛出，或收窄捕获类型并给出降级逻辑。",
                )
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        """CG204：``== None`` / ``== True`` 等。"""
        for op, comparator in zip(node.ops, node.comparators):
            if not isinstance(op, (ast.Eq, ast.NotEq)):
                continue
            for side in (node.left, comparator):
                if isinstance(side, ast.Constant) and (side.value is None or isinstance(side.value, bool)):
                    literal = "None" if side.value is None else str(side.value)
                    rule = RULE_INDEX["CG204"]
                    self.add(
                        rule,
                        title=f"应使用 `is`/`is not` 比较 {literal}",
                        line=node.lineno,
                        evidence=self.snippet(node.lineno),
                        explanation="`==` 会调用重载的 `__eq__`，语义上不可靠；单例比较应使用 `is`。",
                        suggestion=f"改写为 `x is {literal}` / `x is not {literal}`。",
                    )
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """CG205：字面量 0 作除数。"""
        if isinstance(node.op, (ast.Div, ast.FloorDiv, ast.Mod)) and isinstance(node.right, ast.Constant) and node.right.value == 0:
            rule = RULE_INDEX["CG205"]
            self.add(
                rule,
                title="除数为字面量 0",
                line=node.lineno,
                evidence=self.snippet(node.lineno),
                explanation="该表达式必然抛出 `ZeroDivisionError`，属于确定性缺陷。",
                suggestion="确认除数来源；若来自输入需显式校验并给出业务错误。",
                severity=Severity.CRITICAL,
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_hardcoded_secret(node)
        self._check_shadowed_builtin(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_hardcoded_secret(node)
        self._check_shadowed_builtin(node)
        self.generic_visit(node)

    # ------------------------------------------------------------------ #
    # 预扫描
    # ------------------------------------------------------------------ #
    def precollect_sql_variables(self, tree: ast.AST) -> None:
        """预扫描"像 SQL 的变量"，供 CG106 在 ``execute(变量)`` 处判定。

        为什么需要预扫描：``visit_Call``（调用点）可能在 ``visit_Assign``（定义点）
        之前被访问到（例如赋值语句自身包含调用）。与其维护复杂的状态机，
        不如先一次性收集全部定义，再做单次遍历 —— 实现更简单也更可靠。

        记录两种信号：
            * 值为字符串插值（f-string / % / + / .format）且静态片段像 SQL
              → 记为定义行号（明确是拼接而成）；
            * 值只是含 SQL 关键字的字面量 → 记为 ``0``（存在但未拼接，列为待确认）。
        """
        if "CG106" not in self.enabled:
            return

        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue

            value = node.value
            interpolated = _is_interpolated(value)
            static_text = _static_string_parts(value).lower()
            if not (interpolated or static_text):
                continue
            if not any(keyword in static_text for keyword in SQL_KEYWORDS):
                continue

            for name in _assign_target_names(node):
                if not any(hint in name.lower() for hint in SQL_VARIABLE_NAME_HINTS):
                    continue
                self._sql_like_variables[name] = node.lineno if interpolated else 0

    def _check_hardcoded_secret(self, node: ast.Assign | ast.AnnAssign) -> None:
        """CG105：硬编码密钥。"""
        value = node.value
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        literal = value.value
        length = len(literal)
        strong_hint = any(hint in literal for hint in SECRET_VALUE_HINTS)
        if not (strong_hint or 8 <= length <= 120):
            return

        target_names = _assign_target_names(node)
        for name in target_names:
            lowered = name.lower()
            # 变量名或字面量命中"占位/示例"关键字时放过 —— 例如
            #   password = "your_password_here"      （值含 your_）
            #   API_KEY_PLACEHOLDER = "changeme"     （名含 placeholder）
            if any(allow in lowered for allow in SECRET_NAME_ALLOWLIST):
                return
            if any(allow in literal.lower() for allow in SECRET_NAME_ALLOWLIST):
                return
            if not any(keyword in lowered for keyword in SECRET_NAME_KEYWORDS):
                continue
            masked = literal[:4] + "*" * max(0, min(8, length - 4))
            rule = RULE_INDEX["CG105"]
            self.add(
                rule,
                title=f"疑似硬编码密钥：{name}",
                line=node.lineno,
                evidence=f"{name} = {masked!r}（已脱敏）",
                explanation="凭据硬编码在源码中，一旦进入版本库或日志即视为泄露，且无法按环境轮换。",
                suggestion="改为 `os.environ['SERVICE_TOKEN']`，并通过 .env / 密钥管理服务注入；同时轮换已泄露的凭据。",
                severity=Severity.CRITICAL if strong_hint else Severity.HIGH,
            )
            return

    def _check_shadowed_builtin(self, node: ast.Assign | ast.AnnAssign) -> None:
        """CG404：变量遮蔽内置名。"""
        for name in _assign_target_names(node):
            if name not in BUILTIN_NAMES:
                continue
            rule = RULE_INDEX["CG404"]
            self.add(
                rule,
                title=f"变量遮蔽内置名称：{name}",
                line=node.lineno,
                evidence=self.snippet(node.lineno),
                explanation=f"以 `{name}` 作为变量名会遮蔽同名内置对象，后续代码无法再正常使用它。",
                suggestion=f"改名，例如 `{name}_value` / `items`（list）等语义化名称。",
            )

    def visit_Return(self, node: ast.Return) -> None:
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        """CG208：``finally`` 中出现 ``return``/``break``/``continue`` 会吞掉异常。"""
        if "CG208" in self.enabled:
            for child in node.finalbody:
                offender = None
                for sub in ast.walk(child):
                    if isinstance(sub, (ast.Return, ast.Break, ast.Continue)):
                        offender = sub
                        break
                if offender is not None:
                    keyword = "return" if isinstance(offender, ast.Return) else ("break" if isinstance(offender, ast.Break) else "continue")
                    rule = RULE_INDEX["CG208"]
                    self.add(
                        rule,
                        title=f"`finally` 中使用 `{keyword}` 会吞掉异常",
                        line=offender.lineno,
                        evidence=self.snippet(offender.lineno),
                        explanation="`finally` 中的跳转语句会覆盖正在传播的异常，导致异常被静默丢弃、调用方拿到错误的正常返回值。",
                        suggestion="把清理逻辑只放在 `finally` 中，跳转语句移出 `finally`（或改为 `else` 分支）。",
                    )
                    break
        self.generic_visit(node)


# --------------------------------------------------------------------------- #
# 辅助函数
# --------------------------------------------------------------------------- #
def _dotted_name(node: ast.AST | None) -> str:
    """把 ``a.b.c`` 形式的属性链还原成点号字符串。"""
    if node is None:
        return ""
    parts: list[str] = []
    current: ast.AST | None = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    elif isinstance(current, ast.Call):
        return _dotted_name(current.func)
    else:
        return ""
    return ".".join(reversed(parts))


def _assign_target_names(node: ast.Assign | ast.AnnAssign) -> list[str]:
    """提取赋值语句左侧的简单名称列表。"""
    targets: Iterable[ast.AST]
    if isinstance(node, ast.Assign):
        targets = node.targets
    else:
        targets = [node.target]
    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Name):
            names.append(target.id)
    return names


def _is_interpolated(node: ast.AST) -> bool:
    """判断表达式是否为字符串拼接/格式化（f-string、%、+、.format）。"""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            return True
        if isinstance(node.op, ast.Add):
            return _is_interpolated(node.left) or _is_interpolated(node.right)
    if isinstance(node, ast.Call):
        dotted = _dotted_name(node.func)
        if dotted.endswith(".format") or dotted == "format":
            return True
        if dotted in {"f", "F", "fstring", "Template"}:
            return True
        # "a" + b 之类的嵌套
        return any(_is_interpolated(arg) for arg in node.args)
    return False


def _contains_sql_format_marker(node: ast.AST) -> bool:
    """字面量 SQL 中是否含 ``%s`` / ``{}`` 之类的占位符。"""
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
        return False
    text = node.value
    return ("%s" in text) or ("{}" in text) or ("%(" in text)


def _static_string_parts(node: ast.AST) -> str:
    """提取 f-string / 字符串拼接中的**静态文本片段**，忽略插值部分。

    用于判断 ``f"SELECT * FROM t WHERE id = {uid}"`` 里是否出现 SQL 关键字。
    """
    if isinstance(node, ast.JoinedStr):
        return "".join(
            part.value for part in node.values if isinstance(part, ast.Constant) and isinstance(part.value, str)
        )
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp):
        return _static_string_parts(node.left) + _static_string_parts(node.right)
    return ""


def _max_control_depth(node: ast.AST, depth: int = 0) -> int:
    """计算函数体内控制流的最大嵌套深度。

    计数规则（刻意区分"分支"与"嵌套"）：

    * 循环（``for`` / ``while``）、``with``、``try`` —— 每层 +1，
      它们的函数体是真正内嵌的执行上下文；
    * ``if`` / ``match`` —— **一整条 ``if/elif/else`` 链只计 1 层**。

    为什么 ``if`` 链要特殊处理：Python 把 ``elif`` 解析成嵌套的
    ``ast.If``（位于父节点的 ``orelse`` 中）。若逐层 +1，一个"按类型分发"
    的扁平函数（十几个 ``elif``）会被算出十几层深度，报出毫无意义的
    "嵌套过深"。真正降低可读性的是**复合嵌套**（循环里套条件、条件里再套
    循环），而不是长的分支链。

    实现要点：``ast.iter_child_nodes`` 会把 ``body``/``orelse`` 这类
    **语句列表**当作一个子节点返回，而列表本身没有类型信息，因此必须
    显式下钻各字段，否则递归会停在第一层。
    """
    best = depth
    # 语句列表字段：body / orelse / finalbody / handlers
    for field_name in ("body", "orelse", "finalbody"):
        statements = getattr(node, field_name, None)
        if isinstance(statements, list):
            best = max(best, _walk_statements(statements, depth))

    if isinstance(node, (ast.For, ast.AsyncFor, ast.While, ast.With, ast.AsyncWith, ast.Try)):
        # 这些语句的函数体是真正的嵌套上下文：整体 +1
        best = max(best, _walk_body(node, depth + 1))
    elif isinstance(node, ast.If):
        # if/elif 链共享同一层深度
        best = max(best, depth + 1, _walk_if_chain(node.body, depth + 1),
                   _walk_if_chain(node.orelse, depth + 1))
    elif isinstance(node, ast.Match):
        best = max(
            best,
            depth + 1,
            *(_max_control_depth(case, depth + 1) for case in node.cases),
        )
    return best


def _walk_if_chain(statements: list[ast.stmt], depth: int) -> int:
    """遍历 if/elif 链中的语句：``elif`` 属于同一条链，不增加深度。"""
    best = depth
    for statement in statements:
        if isinstance(statement, ast.If):
            best = max(
                best,
                _walk_if_chain(statement.body, depth),
                _walk_if_chain(statement.orelse, depth),
            )
        else:
            best = max(best, _max_control_depth(statement, depth))
    return best


def _walk_statements(statements: list[ast.stmt], depth: int) -> int:
    """以当前深度遍历一组语句。"""
    best = depth
    for statement in statements:
        best = max(best, _max_control_depth(statement, depth))
    return best


def _walk_body(node: ast.AST, depth: int) -> int:
    """以 ``depth`` 深度遍历节点的全部语句列表字段（含 except 处理器）。"""
    best = depth
    for field_name in ("body", "orelse", "finalbody"):
        statements = getattr(node, field_name, None)
        if isinstance(statements, list):
            best = max(best, _walk_statements(statements, depth))
    handlers = getattr(node, "handlers", None)
    if isinstance(handlers, list):
        best = max(best, _walk_statements(handlers, depth))
    return best


def _iter_python_files(root: Path, *, recursive: bool) -> Iterator[Path]:
    """遍历目录下的 Python 文件，跳过虚拟环境与缓存目录。"""
    skip_dirs = {
        ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "env", "node_modules",
        ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", "dist", ".tox", ".eggs",
        "site-packages", ".idea", ".vscode", "migrations",
    }
    if not recursive:
        yield from sorted(root.glob("*.py"))
        return
    for path in sorted(root.rglob("*.py")):
        if any(part in skip_dirs for part in path.parts):
            continue
        yield path


def analyze_path(path: str | Path, *, rules: Sequence[str] | None = None, recursive: bool = True) -> AnalysisSummary:
    """模块级便捷函数：分析文件或目录。"""
    return CodeAnalyzer(rules=rules).analyze_path(path, recursive=recursive)


def analyze_source(source: str, *, path: str = "<string>", rules: Sequence[str] | None = None) -> FileAnalysis:
    """模块级便捷函数：分析源码字符串。"""
    return CodeAnalyzer(rules=rules).analyze_source(source, path=path)


def rules_table() -> list[dict[str, str]]:
    """以字典列表返回规则表，便于生成文档或报告附录。"""
    return [
        {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "category": rule.category,
            "severity": rule.severity.value,
            "description": rule.description,
        }
        for rule in sorted(RULES, key=lambda r: (SEVERITY_ORDER[r.severity], r.rule_id))
    ]


def relativize_findings(findings: Sequence[Finding], root: str | Path) -> list[Finding]:
    """把发现中的文件路径改写为相对 ``root`` 的形式。

    报告里统一使用相对路径的好处：可跨机器阅读、不泄露本机目录结构、
    同一份代码在不同环境下的报告可直接 diff 比较。

    路径已在 ``root`` 之外的条目保持原样（此时绝对路径才是有效信息）。
    """
    base = Path(root).resolve()
    normalized: list[Finding] = []
    for finding in findings:
        if not finding.file:
            normalized.append(finding)
            continue
        try:
            finding.file = Path(finding.file).resolve().relative_to(base).as_posix()
        except (ValueError, OSError):
            pass
        normalized.append(finding)
    return normalized


def count_lines(source: str) -> tuple[int, int, int]:
    """返回 ``(总行数, 代码行数, 注释行数)``。"""
    lines = source.splitlines()
    blank = 0
    comment = 0
    try:
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            if token.type == tokenize.COMMENT:
                comment += 1
            elif token.type == tokenize.NL and not token.string.strip():
                blank += 1
    except (tokenize.TokenError, IndentationError):
        # 语法不完整时退化为简单统计
        comment = sum(1 for line in lines if line.strip().startswith("#"))
        blank = sum(1 for line in lines if not line.strip())
    return len(lines), len(lines) - blank, comment
