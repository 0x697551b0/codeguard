"""
校验 tools/init_repo.py 生成的 Git 仓库是否真的可用，分两层。

第一层（无需 Git）：标准库解码 .git 对象，核对结构齐全、对象 SHA-1 完整、HEAD 与 reflog 格式、tree 可遍历、索引头合法。
第二层（若本机有 Git）：git status 工作区干净、git fsck --strict 无错、git rev-parse 与引用一致、
git ls-files 权限正确。第二层不可省 —— 自研解析器与写入器共享错误假设，必须引入独立实现才能发现问题。
用法：python tools/verify_repo.py（任一项失败返回非零退出码）
"""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import sys
import zlib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from codeguard.compat import enable_utf8_console  # noqa: E402

enable_utf8_console()

FAILURES: list[str] = []


def check(condition: bool, message: str) -> bool:
    if condition:
        print(f"  ✓ {message}")
    else:
        print(f"  ✗ {message}")
        FAILURES.append(message)
    return condition


# 底层读取
def read_object(git_dir: Path, sha: str) -> tuple[str, bytes]:
    """按 SHA 读取并解压对象，返回 ``(类型, 内容)``。"""
    path = git_dir / "objects" / sha[:2] / sha[2:]
    if not path.is_file():
        raise FileNotFoundError(f"对象文件不存在：{path}")
    raw = zlib.decompress(path.read_bytes())
    header, _, body = raw.partition(b"\x00")
    obj_type, _, size = header.decode().partition(" ")
    if int(size) != len(body):
        raise ValueError(f"对象 {sha} 声明长度 {size} 与实际 {len(body)} 不符")
    # 重新计算哈希，验证内容完整性
    digest = hashlib.sha1(header + b"\x00" + body).hexdigest()
    if digest != sha:
        raise ValueError(f"对象 {sha} 内容哈希不匹配（实际 {digest}）")
    return obj_type, body


def parse_tree(body: bytes) -> list[tuple[str, str, str]]:
    """解析 tree 对象，返回 ``[(mode, name, sha), ...]``。"""
    entries: list[tuple[str, str, str]] = []
    index = 0
    while index < len(body):
        space = body.index(b" ", index)
        mode = body[index:space].decode()
        nul = body.index(b"\x00", space)
        name = body[space + 1 : nul].decode("utf-8")
        sha = body[nul + 1 : nul + 21].hex()
        entries.append((mode, name, sha))
        index = nul + 21
    return entries


def walk_tree(git_dir: Path, sha: str, prefix: str = "") -> list[str]:
    """递归遍历 tree，返回仓库内所有文件路径。"""
    obj_type, body = read_object(git_dir, sha)
    if obj_type != "tree":
        raise ValueError(f"{sha} 应为 tree，实际为 {obj_type}")
    files: list[str] = []
    for mode, name, child_sha in parse_tree(body):
        path = f"{prefix}{name}"
        if mode == "40000":
            files.extend(walk_tree(git_dir, child_sha, prefix=f"{path}/"))
        else:
            # 校验 blob 可读且完整
            blob_type, _ = read_object(git_dir, child_sha)
            if blob_type != "blob":
                raise ValueError(f"{path} 指向 {child_sha}，类型为 {blob_type} 而非 blob")
            files.append(path)
    return files


# 检查项
def main() -> int:
    git_dir = REPO_ROOT / ".git"
    print("CodeGuard Git 仓库校验（纯标准库实现，无需安装 Git）")
    print("=" * 70)

    # ---- 1. 结构 ----
    print("\n[1] 仓库结构")
    if not check(git_dir.is_dir(), f".git 目录存在：{git_dir}"):
        print("\n无法继续：仓库不存在。请先运行 python tools/init_repo.py", file=sys.stderr)
        return 1
    for relative in ("HEAD", "config", "objects", "refs", "index"):
        check((git_dir / relative).exists(), f".git/{relative} 存在")

    # ---- 2. HEAD 与分支 ----
    print("\n[2] HEAD 与分支")
    head_text = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    if not check(head_text.startswith("ref: refs/heads/"), f"HEAD 格式正确（{head_text}）"):
        return 1
    branch = head_text.split("refs/heads/", 1)[1]
    ref_file = git_dir / "refs" / "heads" / branch
    if not check(ref_file.is_file(), f"分支引用存在：refs/heads/{branch}"):
        return 1
    commit_sha = ref_file.read_text(encoding="utf-8").strip()
    check(len(commit_sha) == 40, f"commit SHA 长度合法（{commit_sha[:12]}…）")

    # reflog 不是必需文件，但部分 Git GUI（libgit2 封装）会依赖它
    for relative in ("logs/HEAD", f"logs/refs/heads/{branch}"):
        log_file = git_dir / relative
        check(log_file.is_file(), f"reflog 存在：.git/{relative}")
        if log_file.is_file():
            first = log_file.read_text(encoding="utf-8").splitlines()[0]
            check(
                commit_sha in first and first.startswith("0" * 40),
                f"reflog 首行格式正确（初始提交）",
            )

    # ---- 3. commit 对象 ----
    print("\n[3] commit 对象")
    try:
        obj_type, body = read_object(git_dir, commit_sha)
    except (OSError, ValueError) as exc:
        check(False, f"读取 commit 失败：{exc}")
        return 1
    if not check(obj_type == "commit", f"对象类型为 commit（实际 {obj_type}）"):
        return 1

    text = body.decode("utf-8", errors="replace")
    headers, _, message = text.partition("\n\n")
    tree_sha = ""
    author_line = ""
    for line in headers.splitlines():
        if line.startswith("tree "):
            tree_sha = line[5:]
        elif line.startswith("author "):
            author_line = line[7:]
    check(bool(tree_sha), f"commit 含 tree 引用（{tree_sha[:12]}…）")
    check(bool(author_line), f"commit 含 author（{author_line}）")
    check(bool(message.strip()), f"commit 含提交信息：{message.strip().splitlines()[0][:60]!r}")

    # ---- 4. tree 遍历 ----
    print("\n[4] tree 遍历与文件清单")
    try:
        files = walk_tree(git_dir, tree_sha)
    except (OSError, ValueError) as exc:
        check(False, f"遍历 tree 失败：{exc}")
        return 1
    check(len(files) > 0, f"共 {len(files)} 个文件")
    for expected in ("README.md", "Design.md", "pyproject.toml", "verify.py", "run_tests.py"):
        check(expected in files, f"包含必需文件 {expected}")
    for expected_dir in ("codeguard/", "tests/", "docs/", "examples/"):
        check(any(f.startswith(expected_dir) for f in files), f"包含目录 {expected_dir}")
    check(not any(f.startswith(".git/") for f in files), "未把 .git 自身纳入版本控制")
    check(
        not any(f.startswith(("agent_", "tools_", "report_", "dotenv_", "cg_")) for f in files),
        "未纳入测试残留的临时目录",
    )
    check(
        not any(f.endswith((".pyc", ".log")) for f in files),
        "未纳入编译缓存或日志",
    )

    # ---- 5. 索引 ----
    print("\n[5] 索引文件")
    index_bytes = (git_dir / "index").read_bytes()
    if check(index_bytes[:4] == b"DIRC", "索引魔数 DIRC 正确"):
        version, count = struct.unpack(">II", index_bytes[4:12])
        check(version == 2, f"索引版本为 2（实际 {version}）")
        check(count == len(files), f"索引条目数 {count} 与 tree 文件数 {len(files)} 一致")
        expected_digest = hashlib.sha1(index_bytes[:-20]).digest()
        check(expected_digest == index_bytes[-20:], "索引末尾 SHA-1 校验通过")
        check(
            all(len(p) > 0 for p in files),
            "所有条目路径非空",
        )

    print("\n" + "=" * 70)
    if FAILURES:
        print(f"校验失败：{len(FAILURES)} 项未通过")
        for item in FAILURES:
            print(f"  ✗ {item}")
        return 1
    print(f"✅ 第一层校验通过（纯标准库）：{len(files)} 个文件，commit {commit_sha[:12]}")

    # ---- 6. 真实 Git 交叉验证（若本机有 Git）----
    if not _verify_with_real_git(commit_sha):
        return 1
    return 0


def _verify_with_real_git(expected_head: str) -> bool:
    """用真实 Git 做权威验证；本机没有 Git 时跳过（不算失败）。"""
    from tools.init_repo import _find_git

    executable = _find_git()
    print("\n[6] 真实 Git 交叉验证")
    if executable is None:
        print("  ⚠ 本机未检测到 Git，跳过这一层（对象与引用已由第一层验证）")
        return True
    print(f"  使用：{executable}")

    def run(*args: str) -> tuple[int, str]:
        completed = subprocess.run(
            [executable, "-C", str(REPO_ROOT), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        return completed.returncode, ((completed.stdout or "") + (completed.stderr or "")).strip()

    # status：工作区必须干净（索引与工作区一致）
    code, output = run("status", "--porcelain")
    check(code == 0, f"git status 执行成功（退出码 {code}）")
    if code == 0:
        check(output == "", f"工作区干净，无未提交改动（实际输出 {output[:120]!r}）")

    # fsck：对象库必须无错
    code, output = run("fsck", "--strict")
    check(code == 0, f"git fsck --strict 通过（退出码 {code}）")
    if output:
        check(False, f"git fsck 有告警：{output[:200]}")

    # rev-parse：HEAD 必须与引用文件一致
    code, output = run("rev-parse", "HEAD")
    check(code == 0 and output.strip() == expected_head,
          f"git rev-parse HEAD == 引用文件（{output.strip()[:12]}）")

    # ls-files --stage：文件权限必须正确
    # 回归：曾因 Windows 上 os.access(X_OK) 恒为 True，导致所有文件（含 .md/.py）
    # 都被写成 100755，GitHub 上每个文件名旁都显示"executable file"标记。
    # 这个错误在本地完全不可见（core.filemode=false 让 Git 忽略权限差异），
    # 只有按最终消费者的视角检查才会暴露。
    code, output = run("ls-files", "--stage")
    if check(code == 0, "git ls-files --stage 可读取"):
        modes: dict[str, list[str]] = {}
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            mode = parts[0].split()[0]
            modes.setdefault(mode, []).append(parts[1])
        executables = modes.get("100755", [])
        check(
            not executables,
            f"没有普通文件被误标为可执行（若列出则为误标：{executables[:5]}）",
        )
        check("100644" in modes, f"绝大多数文件权限为 100644（{len(modes.get('100644', []))} 个）")

    # log：提交必须可读、作者信息正确
    code, output = run("log", "-1", "--format=%an <%ae>%n%s")
    check(code == 0, "git log 可读取提交")
    if code == 0:
        lines = output.splitlines()
        check(len(lines) >= 2 and "@" in lines[0], f"提交作者格式正确（{lines[0][:60] if lines else ''}）")
    return True


if __name__ == "__main__":
    sys.exit(main())
