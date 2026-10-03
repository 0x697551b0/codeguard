"""CodeGuard 命令行界面（argparse 实现，零额外依赖）。

三种模式::

    # 1) LLM 审查（核心功能）
    python -m codeguard review examples/demo_buggy_code

    # 2) 纯静态审查（无需 API Key，可用作 CI 质量门禁）
    python -m codeguard scan examples/demo_buggy_code --fail-on high

    # 3) 交互式追问（验证上下文记忆）
    python -m codeguard chat examples/demo_buggy_code

退出码约定（便于接入 CI）::

    0  成功且通过质量门禁
    1  审查完成但命中门禁（---fail-on）
    2  用法错误 / 配置错误
    3  运行期错误（网络、鉴权等）
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Sequence

from codeguard import __version__
from codeguard.agent import CodeReviewAgent, static_only_review
from codeguard.compat import enable_utf8_console
from codeguard.config import Config
from codeguard.exceptions import CodeGuardError, ConfigError, LLMAuthError
from codeguard.report import (
    render_ci_summary,
    render_json,
    render_text,
    summarize_for_prompt,
    write_report,
)

#: 退出码
EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_USAGE = 2
EXIT_RUNTIME = 3

logger = logging.getLogger("codeguard")

_DESCRIPTION = """\
CodeGuard —— 基于 LLM 工具调用的代码审查 Agent

它会自己决定"看哪些文件、跑哪些检查"，逐步收集证据后产出一份带
行号定位、原因分析与修复建议的结构化审查报告。
"""

_EPILOG = """\
使用示例:
  # 用内置示例代码体验完整 Agent 闭环（无需 API Key，离线脚本化模型）
  python -m codeguard review examples/demo_buggy_code --mock

  # 真实模型审查，并输出 Markdown 报告
  set CODEGUARD_API_KEY=sk-xxxx
  python -m codeguard review examples/demo_buggy_code --report report.md --trace

  # 只跑确定性静态规则，作为提交前自检
  python -m codeguard scan .

  # 审查后追问（复用上下文记忆）
  python -m codeguard chat examples/demo_buggy_code

环境变量:
  CODEGUARD_API_KEY      LLM API Key（必填，--mock 与 scan 模式除外）
  CODEGUARD_BASE_URL     服务根地址，默认 https://api.deepseek.com
  CODEGUARD_MODEL        模型名，默认 deepseek-chat
  CODEGUARD_MAX_ITERATIONS  最大迭代轮数，默认 12
"""


# --------------------------------------------------------------------------- #
# 参数解析
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """构造 argparse 解析器。"""
    parser = argparse.ArgumentParser(
        prog="codeguard",
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"CodeGuard {__version__}")

    # ---- 全局选项（放在子命令之前或之后都可用的部分，使用 parents 挂载）----
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--api-key", default=None, help="LLM API Key（默认读取 CODEGUARD_API_KEY）")
    common.add_argument("--base-url", default=None, help="服务根地址，如 https://api.deepseek.com")
    common.add_argument("--model", default=None, help="模型名，如 deepseek-chat")
    common.add_argument("--workspace", default=None, help="工作区根目录（工具只能访问该目录内），默认当前目录")
    common.add_argument("--lang", choices=["zh", "en"], default=None, help="报告与提示语言，默认 zh")
    common.add_argument("--max-iterations", type=int, default=None, help="Agent 最大迭代轮数，默认 12")
    common.add_argument("--max-retries", type=int, default=None, help="LLM 请求失败后的最大重试次数，默认 3")
    common.add_argument("--timeout", type=float, default=None, help="单次 LLM 请求超时秒数，默认 90")
    common.add_argument("--temperature", type=float, default=None, help="采样温度，默认 0.2")
    common.add_argument("--max-file-bytes", type=int, default=None, help="单文件读取上限字节数")
    common.add_argument("--mock", action="store_true", help="离线 Mock 模式：不访问网络，用脚本化模型演示 Agent 闭环")
    common.add_argument("--min-severity", default="info", choices=["critical", "high", "medium", "low", "info"], help="终端只显示不低于该级别的条目，默认 info（全部）")
    common.add_argument("--verbose", "-v", action="store_true", help="输出调试日志")
    common.add_argument("--quiet", "-q", action="store_true", help="只输出报告正文，不打印过程信息")

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # ---- review ----
    review = subparsers.add_parser(
        "review",
        parents=[common],
        help="用 LLM 审查代码（核心功能）",
        description="对指定文件或目录执行一次完整 Agent 审查。",
    )
    review.add_argument("target", help="要审查的文件或目录路径")
    review.add_argument("--focus", "-f", action="append", default=[], metavar="关注点", help="额外关注点，可重复，如 -f 'SQL 注入' -f '并发'")
    review.add_argument("--report", default=None, metavar="文件", help="把报告写入文件（按扩展名推断 md/json/txt）")
    review.add_argument("--json", action="store_true", help="把 JSON 报告打印到标准输出")
    review.add_argument("--trace", action="store_true", help="打印完整执行轨迹（推理 → 工具 → 观察）")
    review.add_argument("--no-prescan", action="store_true", help="不做目录预扫描（直接交给模型探索）")
    review.add_argument("--rules-appendix", action="store_true", help="在 Markdown 报告中附上内置规则手册")

    # ---- scan ----
    scan = subparsers.add_parser(
        "scan",
        parents=[common],
        help="只跑内置静态规则（无需 API Key，可用于 CI）",
        description="不调用 LLM，直接用确定性规则引擎输出报告。",
    )
    scan.add_argument("target", help="要扫描的文件或目录路径")
    scan.add_argument("--report", default=None, metavar="文件", help="把报告写入文件")
    scan.add_argument("--json", action="store_true", help="打印 JSON 报告")
    scan.add_argument("--fail-on", default="none", choices=["critical", "high", "medium", "low", "none"], help="达到该级别即返回退出码 1，默认 none（不拦截）")
    scan.add_argument("--rules", default=None, help="只启用指定规则，逗号分隔，如 CG101,CG203")
    scan.add_argument("--rules-appendix", action="store_true", help="在 Markdown 报告中附上规则手册")

    # ---- chat ----
    chat = subparsers.add_parser(
        "chat",
        parents=[common],
        help="审查后就代码追问（验证上下文记忆）",
        description="先审查目标，然后进入交互式问答，模型记得之前读过的代码。",
    )
    chat.add_argument("target", help="要审查的文件或目录路径")
    chat.add_argument("--focus", "-f", action="append", default=[], metavar="关注点", help="额外关注点，可重复")
    chat.add_argument("--trace", action="store_true", help="打印完整执行轨迹")

    # ---- rules ----
    rules = subparsers.add_parser(
        "rules",
        parents=[common],
        help="打印内置静态规则手册",
        description="列出所有内置规则的编号、标题、类别、默认级别与说明。",
    )
    rules.add_argument("--json", action="store_true", help="以 JSON 输出")

    # ---- info ----
    subparsers.add_parser(
        "info",
        parents=[common],
        help="显示版本与运行环境自检信息",
        description="输出版本、Python 版本、依赖可用性与配置摘要（不显示 API Key 明文）。",
    )

    return parser


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def main(argv: Sequence[str] | None = None) -> int:
    """CLI 入口。"""
    # Windows 控制台默认 GBK，含 emoji/表格字符的输出会崩，先切 UTF-8
    enable_utf8_console()
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    _setup_logging(verbose=args.verbose, quiet=args.quiet)

    try:
        if args.command == "info":
            return _cmd_info(args)
        if args.command == "rules":
            return _cmd_rules(args)
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "review":
            return _cmd_review(args)
        if args.command == "chat":
            return _cmd_chat(args)
    except LLMAuthError as exc:
        _error(f"鉴权失败：{exc}")
        return EXIT_RUNTIME
    except ConfigError as exc:
        _error(str(exc))
        return EXIT_USAGE
    except CodeGuardError as exc:
        _error(f"{type(exc).__name__}: {exc}")
        return EXIT_RUNTIME
    except KeyboardInterrupt:
        _error("已中断")
        return 130

    parser.print_help()
    return EXIT_USAGE


# --------------------------------------------------------------------------- #
# 各子命令实现
# --------------------------------------------------------------------------- #
def _build_config(args: argparse.Namespace, *, require_api_key: bool = True) -> Config:
    """从命令行参数 + 环境变量构造配置。"""
    config = Config.from_env(
        ".env",
        api_key=args.api_key,
        base_url=args.base_url,
        model=args.model,
        lang=args.lang,
        max_iterations=args.max_iterations,
        max_retries=args.max_retries,
        timeout=args.timeout,
        temperature=args.temperature,
        max_file_bytes=args.max_file_bytes,
        verbose=args.verbose,
        mock=True if args.mock else None,
        workspace_root=args.workspace,
    )
    if args.workspace:
        config.workspace_root = str(Path(args.workspace).expanduser().resolve())
    config.verbose = args.verbose
    config.validate(require_api_key=require_api_key)
    return config


def _cmd_info(args: argparse.Namespace) -> int:
    """打印版本与自检信息。"""
    import platform

    try:
        import httpx

        httpx_version = httpx.__version__
    except ImportError:  # pragma: no cover
        httpx_version = "未安装（请执行 pip install httpx）"

    config = Config.from_env(
        ".env",
        api_key=args.api_key,
        base_url=args.base_url,
        model=args.model,
        lang=args.lang,
        workspace_root=args.workspace,
    )
    if args.mock:
        config.mock = True

    from codeguard.static_analysis import RULES

    print(f"CodeGuard {__version__}")
    print(f"Python        : {platform.python_version()} ({platform.system()} {platform.release()})")
    print(f"httpx         : {httpx_version}")
    print(f"内置规则数量  : {len(RULES)}")
    print(f"工作区根目录  : {config.workspace_path}")
    print()
    print("配置摘要：")
    for line in config.describe().splitlines():
        print(f"  {line}")
    if not config.api_key and not config.mock:
        print()
        print("提示：未检测到 API Key。可先运行 `python -m codeguard review examples/demo_buggy_code --mock`")
        print("      体验离线演示，或参考 .env.example 配置 CODEGUARD_API_KEY。")
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    """打印内置规则手册。"""
    from codeguard.static_analysis import rules_table

    table = rules_table()
    if args.json:
        print(_json_dumps(table))
        return EXIT_OK

    print(f"内置静态规则共 {len(table)} 条")
    print("─" * 100)
    print(f"{'规则ID':<8}{'级别':<10}{'类别':<18}{'标题':<28}说明")
    print("─" * 100)
    for rule in table:
        print(
            f"{rule['rule_id']:<8}{rule['severity']:<10}{rule['category']:<18}"
            f"{rule['title'][:26]:<28}{rule['description'][:46]}"
        )
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    """纯静态扫描（不调用 LLM）。"""
    config = _build_config(args, require_api_key=False)
    target = _resolve_target(args.target, config)

    report = static_only_review(target, workspace_root=config.workspace_path)

    passed, message = render_ci_summary(report, fail_on=args.fail_on)
    if not args.quiet:
        print(f"扫描目标：{_display_target(target, config.workspace_path)}")
        print()

    if args.json:
        print(render_json(report))
    else:
        print(render_text(report, min_severity=args.min_severity))

    if args.report:
        path = write_report(report, args.report, include_rules_appendix=args.rules_appendix, min_severity=args.min_severity)
        if not args.quiet:
            print(f"\n📄 报告已写入：{path}")

    if not args.quiet:
        print(message)
    return EXIT_OK if passed else EXIT_GATE_FAILED


def _cmd_review(args: argparse.Namespace) -> int:
    """LLM 审查主流程。"""
    config = _build_config(args, require_api_key=not args.mock)

    if config.mock:
        config.mock = True
    target = _resolve_target(args.target, config)

    if not args.quiet:
        _banner()
        print(f"🎯 审查目标：{_display_target(target, config.workspace_path)}")
        if args.focus:
            print(f"🔍 关注点　：{'、'.join(args.focus)}")
        print(f"🤖 模型　　：{config.model if not config.mock else 'mock-scripted-model（离线，不访问网络）'}")
        print()

    with CodeReviewAgent(config) as agent:
        if config.mock:
            agent.use_mock_llm(target=str(target))
        result = agent.review(target, focus=args.focus, prescan=not args.no_prescan)

    if args.trace and not args.quiet:
        print(result.render_trace())
        print()

    if args.json:
        print(render_json(result.report))
    else:
        print(render_text(result.report, min_severity=args.min_severity))

    if args.report:
        path = write_report(result.report, args.report, include_rules_appendix=args.rules_appendix, min_severity=args.min_severity)
        if not args.quiet:
            print(f"\n📄 报告已写入：{path}")

    if not args.quiet:
        print(f"⏱️  {result.elapsed_seconds:.1f}s | {result.iterations} 轮迭代 | "
              f"{result.tool_calls} 次工具调用 | {result.usage}")

    # 整体风险为 critical/high 时返回 1，方便在 CI 中拦截
    if result.report.overall_risk.lower() in {"critical", "high"}:
        return EXIT_GATE_FAILED
    return EXIT_OK


def _cmd_chat(args: argparse.Namespace) -> int:
    """审查 + 交互式追问。"""
    config = _build_config(args, require_api_key=not args.mock)
    target = _resolve_target(args.target, config)

    _banner()
    print(f"🎯 审查目标：{_display_target(target, config.workspace_path)}")
    print()

    with CodeReviewAgent(config) as agent:
        if config.mock:
            agent.use_mock_llm(target=str(target))
        result = agent.review(target, focus=args.focus)
        if args.trace:
            print(result.render_trace())
            print()
        print(render_text(result.report, min_severity=args.min_severity))
        print()

        if config.mock:
            print("（离线 Mock 模式下追问由脚本化模型回答）")

        print("进入交互模式：可就本次审查继续提问。输入 exit / quit / 空行 退出。")
        context = summarize_for_prompt(result.report)
        while True:
            try:
                question = input("\n❓ 追问 > ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not question or question.lower() in {"exit", "quit", "q", "退出"}:
                break
            try:
                answer = agent.followup(question, report=result.report)
            except CodeGuardError as exc:
                print(f"⚠️ {exc}")
                continue
            print(f"\n💡 {answer}")

    return EXIT_OK


# --------------------------------------------------------------------------- #
# 辅助
# --------------------------------------------------------------------------- #
def _display_target(raw: str, workspace: Path) -> str:
    """把审查目标显示为相对工作区的路径。

    报告中统一使用相对路径：更简洁、可跨机器复现、也不会泄露本机目录结构。
    """
    try:
        return Path(raw).resolve().relative_to(workspace).as_posix()
    except (ValueError, OSError):
        return str(raw)


def _resolve_target(raw: str, config: Config) -> str:
    """解析用户给的审查目标路径，并校验是否在工作区之外。"""
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise ConfigError(f"路径无法解析：{raw}（{exc}）") from exc

    if not resolved.exists():
        raise ConfigError(f"审查目标不存在：{resolved}")
    return str(resolved)


def _setup_logging(*, verbose: bool, quiet: bool) -> None:
    """配置日志：默认 WARNING，-v 为 DEBUG，-q 为 ERROR；一律输出到 stderr。"""
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
        force=True,
    )


def _banner() -> None:
    """打印启动横幅。"""
    print("╔" + "═" * 60 + "╗")
    print("║" + f" CodeGuard v{__version__} —— LLM 代码审查 Agent".ljust(59) + "║")
    print("╚" + "═" * 60 + "╝")


def _error(message: str) -> None:
    print(f"❌ {message}", file=sys.stderr)


def _json_dumps(data: object) -> str:
    import json

    return json.dumps(data, ensure_ascii=False, indent=2)


def run() -> None:
    """``console_scripts`` 入口包装：把返回值转成退出码。"""
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    run()
