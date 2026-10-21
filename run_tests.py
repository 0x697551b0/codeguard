"""
零依赖测试运行器：不装 pytest 也能跑完整测试套件。
用法：python run_tests.py [-v] [关键字]。用例写成 test_xxx() 普通函数（兼容 pytest），本运行器负责发现、执行与报告。
"""

from __future__ import annotations

import importlib.util
import sys
import traceback
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent
TESTS_DIR = ROOT / "tests"

sys.path.insert(0, str(ROOT))

from codeguard.compat import enable_utf8_console, workspace_tempdir  # noqa: E402

enable_utf8_console()


class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for name in ("GREEN", "RED", "YELLOW", "DIM", "BOLD", "RESET"):
            setattr(cls, name, "")


def load_module(path: Path):
    """按文件路径加载模块（不用 import 语句，避免包名冲突）。"""
    module_name = f"codeguard_tests_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ImportError(f"无法加载测试模块：{path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    sys.path.insert(0, str(ROOT))
    spec.loader.exec_module(module)
    return module


def discover(filter_keyword: str = "") -> list[tuple[str, Callable[[], object]]]:
    """收集所有 ``test_*`` 函数。"""
    cases: list[tuple[str, Callable[[], object]]] = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if filter_keyword and filter_keyword not in path.stem:
            continue
        module = load_module(path)
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            func = getattr(module, name)
            if callable(func):
                cases.append((f"{path.stem}::{name}", func))
    return cases


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    verbose = "-v" in args or "--verbose" in args
    filter_keyword = next((a for a in args if not a.startswith("-")), "")

    if not sys.stdout.isatty():
        Colors.disable()

    print(f"{Colors.BOLD}CodeGuard 测试套件{Colors.RESET}  (Python {sys.version.split()[0]})")
    print(f"目录：{TESTS_DIR}")
    print("─" * 70)

    try:
        cases = discover(filter_keyword)
    except Exception:  # noqa: BLE001 - 收集阶段失败也要给出清晰输出
        print(f"{Colors.RED}测试收集失败：{Colors.RESET}")
        traceback.print_exc()
        return 2

    if not cases:
        print(f"{Colors.YELLOW}未发现测试用例{Colors.RESET}")
        return 1

    passed = 0
    failures: list[tuple[str, str]] = []
    for name, func in cases:
        try:
            func()
        except Exception:  # noqa: BLE001 - 运行器需要捕获所有失败
            failures.append((name, traceback.format_exc()))
            print(f"  {Colors.RED}✗{Colors.RESET} {name}")
        else:
            passed += 1
            if verbose:
                print(f"  {Colors.GREEN}✓{Colors.RESET} {name}")

    print("─" * 70)
    if failures:
        print(f"\n{Colors.BOLD}失败详情（{len(failures)} 个）{Colors.RESET}")
        for name, tb in failures:
            print(f"\n{Colors.RED}✗ {name}{Colors.RESET}")
            for line in tb.strip().splitlines()[-12:]:
                print(f"  {Colors.DIM}{line}{Colors.RESET}")

    total = len(cases)
    color = Colors.GREEN if not failures else Colors.RED
    print(
        f"\n{color}{Colors.BOLD}结果：{passed}/{total} 通过"
        f"{f'，{len(failures)} 失败' if failures else '，全部通过'}{Colors.RESET}"
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
