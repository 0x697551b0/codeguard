"""打包备份提交物。

作业要求：把代码、文档打包成“学号姓名”的压缩包（<200M），提交到课程平台。

用法::

    python tools/make_backup.py                      # 自动探测姓名
    python tools/make_backup.py --id 10086 --name 张三
    python tools/make_backup.py --student "10086张三"   # 直接指定完整文件名

产出::

    <项目根>/dist/10086张三.zip

包内结构（顶层就是项目目录，解压即用）::

    10086张三/
    ├── README.md / Design.md / requirements.txt / pyproject.toml
    ├── codeguard/   tests/   examples/   docs/   tools/
    ├── run_tests.py   verify.py
    └── 提交说明.md          ← 自动生成，说明如何运行与验收

排除内容：``.git``、``__pycache__``、临时目录、测试残留、虚拟环境、报告产物。
**不会**打包任何密钥文件（``.env`` 在排除列表中，只保留 ``.env.example``）。
"""

from __future__ import annotations

import argparse
import fnmatch
import sys
import zipfile
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from codeguard.compat import enable_utf8_console  # noqa: E402

enable_utf8_console()

#: 无论在哪一层出现都要跳过的目录名
EXCLUDED_DIRS = {
    ".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".codeguard_tmp", ".testtmp", ".venv", "venv", "env", "node_modules",
    "build", "dist", ".idea", ".vscode", ".eggs", "htmlcov", ".tox",
}

#: 需要排除的文件模式
EXCLUDED_PATTERNS = (
    "*.pyc", "*.pyo", "*.pyd", "*.log", "*.tmp", "*.bak",
    "*.egg-info", ".coverage", ".DS_Store", "Thumbs.db",
    ".env",            # 真实密钥绝不入库
    "*.trajectory.jsonl",
    "report.json",
    "testout.txt",
    "scan.json",
    "提交指南.md",      # 面向本地交付流程，含个人信息，不进交付包
)

#: 测试运行器在受限环境下无法清理的临时目录前缀
EXCLUDED_DIR_PREFIXES = ("agent_", "tools_", "report_", "dotenv_", "cg_", "chk_")

#: 单文件大小上限（避免把意外生成的大文件打进去）
MAX_FILE_BYTES = 20 * 1024 * 1024


def should_skip_dir(name: str) -> bool:
    """目录是否应被排除。"""
    if name in EXCLUDED_DIRS:
        return True
    return any(name.startswith(prefix) for prefix in EXCLUDED_DIR_PREFIXES)


def should_skip_file(path: Path) -> bool:
    """文件是否应被排除。"""
    name = path.name
    for pattern in EXCLUDED_PATTERNS:
        if fnmatch.fnmatch(name, pattern):
            return True
    # reports/ 是 Agent 输出产物，示例报告在 examples/ 里已有
    if "reports" in path.parts:
        return True
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return True
    except OSError:
        return True
    return False


def collect_files(root: Path) -> tuple[list[Path], list[str]]:
    """收集要打包的文件，返回 ``(文件列表, 跳过说明)``。"""
    files: list[Path] = []
    skipped: list[str] = []

    for path in sorted(root.rglob("*")):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(should_skip_dir(part) for part in relative.parts[:-1]):
            continue
        if any(part in EXCLUDED_DIRS or part.startswith(EXCLUDED_DIR_PREFIXES) for part in relative.parts):
            skipped.append(f"{relative.as_posix()}（临时/缓存目录）")
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            continue
        if should_skip_file(path):
            skipped.append(f"{relative.as_posix()}（被排除的文件模式或体积过大）")
            continue
        files.append(path)
    return files, skipped


def build_readme(student: str, files: list[Path]) -> str:
    """生成包内的《提交说明.md》。"""
    total_bytes = sum(f.stat().st_size for f in files)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""# 提交说明

- **姓名/学号**：{student}
- **项目名称**：CodeGuard —— 基于 LLM 工具调用的代码审查 Agent
- **打包时间**：{timestamp}
- **文件数**：{len(files)} 个（解压后约 {total_bytes / 1024:.0f} KB）

---

## 一、这是什么

一个代码审查 Agent：先跑确定性静态分析拿到客观事实，再自主阅读关键代码、
剔除误报、补充语义层面的缺陷，最终产出带行号定位与修复建议的结构化报告。

实现的是作业要求的完整 Agent 闭环：

```
输入 Input → 推理 Reasoning → 工具调用 Tool Calling → 观察 Observation → 输出 Output
```

## 二、如何验证（无需 API Key，全程离线）

环境要求：Python 3.10+（已验证 3.14），仅需一个第三方依赖 `httpx`。

```bash
# 1) 安装依赖
pip install -r requirements.txt

# 2) 一条命令跑通端到端自检（10 项检查，含 107 个单元测试）
python verify.py

# 3) 体验完整 Agent 闭环，并打印"推理 → 工具 → 观察"执行轨迹
python -m codeguard review examples/demo_buggy_code --mock --trace

# 4) 只跑确定性静态规则（无需任何配置，可作为 CI 质量门禁）
python -m codeguard scan examples/demo_buggy_code --fail-on high
```

## 三、如何用真实模型运行

```bash
# 配置 API Key（DeepSeek，也支持任意 OpenAI 兼容服务商）
set CODEGUARD_API_KEY=sk-xxxxxxxx        # Linux/macOS: export CODEGUARD_API_KEY=...
python -m codeguard review ./your_code --report report.md
```

换服务商只需改 `--base-url` 与 `--model`，代码零改动。

## 四、包内结构

```
{student}/
├── README.md            项目说明、安装、用法
├── Design.md            设计文档：架构、Agent 循环、失败处理、设计取舍
├── docs/
│   ├── RULES.md         内置静态规则手册（27 条）
│   └── PROMPT_DESIGN.md Prompt 设计说明与迭代记录
├── codeguard/           源代码（13 个模块）
├── tests/               测试套件（107 个用例，全部离线）
├── examples/
│   ├── demo_buggy_code/ 演示用示例代码（含规范代码作对照）
│   └── sample_report.md 示例审查报告
├── tools/               仓库初始化与备份打包脚本
├── verify.py            端到端自检
└── run_tests.py         零依赖测试运行器（无需 pytest）
```

## 五、说明

- 所有测试与自检**不访问网络、不需要 API Key**，助教可直接复现。
- `--mock` 模式产出的报告，其问题清单取自内置规则引擎在示例代码上的**真实输出**，
  可与 `scan` 子命令交叉验证，不存在编造的结论。
- 本包**不包含任何密钥**：`.env` 已被排除，只保留 `.env.example` 模板。
- 完整源码仓库：https://github.com/0x697551b0/codeguard
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="make_backup.py",
        description="打包作业备份提交物（学号姓名.zip）",
    )
    parser.add_argument("--id", dest="student_id", default="", help="学号")
    parser.add_argument("--name", default="", help="姓名")
    parser.add_argument("--student", default="", help="直接指定“学号姓名”，覆盖 --id/--name")
    parser.add_argument("--out", default="", help="输出目录，默认 <项目根>/dist")
    parser.add_argument("--root", default=str(REPO_ROOT), help="要打包的项目根目录")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"❌ 目录不存在：{root}", file=sys.stderr)
        return 2

    if args.student:
        student = args.student.strip()
    elif args.student_id and args.name:
        student = f"{args.student_id}{args.name}"
    else:
        print("❌ 需要指定提交人名。示例：", file=sys.stderr)
        print("   python tools/make_backup.py --id 10086 --name 张三", file=sys.stderr)
        print("   python tools/make_backup.py --student 10086张三", file=sys.stderr)
        return 2

    if any(char in student for char in '\\/:*?"<>|'):
        print(f"❌ 提交人名含非法文件名字符：{student}", file=sys.stderr)
        return 2

    out_dir = Path(args.out).resolve() if args.out else root / "dist"
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{student}.zip"

    print(f"正在打包：{root}")
    files, skipped = collect_files(root)
    if not files:
        print("❌ 未收集到任何文件", file=sys.stderr)
        return 1

    total_bytes = sum(f.stat().st_size for f in files)
    readme = build_readme(student, files)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for file_path in files:
            arcname = f"{student}/{file_path.relative_to(root).as_posix()}"
            archive.write(file_path, arcname)
        archive.writestr(f"{student}/提交说明.md", readme)

    size = zip_path.stat().st_size
    limit = 200 * 1024 * 1024
    print()
    print(f"✅ 已生成：{zip_path}")
    print(f"   文件数　：{len(files)} 个（压缩前 {total_bytes / 1024:.0f} KB）")
    print(f"   压缩后　：{size / 1024:.0f} KB")
    if skipped:
        print(f"   已排除　：{len(skipped)} 项")
        for item in skipped[:8]:
            print(f"      · {item}")
        if len(skipped) > 8:
            print(f"      …另有 {len(skipped) - 8} 项")
    if size > limit:
        print(f"\n⚠️ 超过 200MB 限制（{size / 1024 / 1024:.1f}MB），请检查是否误打包了大文件")
        return 1
    print("\n可直接提交到课程平台的“001Homework1”下。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
