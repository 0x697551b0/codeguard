"""
在没有安装 Git 的机器上创建真正的 Git 仓库（纯标准库）。

用 Python 直接写出符合 Git 规范的对象与引用，之后在任意装有 Git 的机器上 git log / git push 均正常。
写入内容：HEAD、config、objects（zlib 压缩的 blob/tree/commit）、refs、reflogs、description；
索引交给本机 Git 生成（见 write_index 说明），无 Git 时不写并提示。
用法：python tools/init_repo.py [--branch main] [--name 姓名] [--email 邮箱] [--force]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: 不被纳入版本控制的目录名（无论如何都跳过）
HARD_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".idea", ".vscode"}


def _is_executable(path: Path, relative: str) -> bool:
    """
    判断文件是否应记为可执行（Git 的 100755）。
    不能用 os.access(X_OK)：Windows 上它对几乎所有普通文件都返回 True，会让 .md/.py 全被打上可执行位；改用扩展名 + shebang 判断。
    """
    #: 常见的可执行扩展名
    executable_suffixes = {
        ".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".bat", ".cmd",
        ".exe", ".com", ".py",  # .py 带 shebang 时通常可执行，但需进一步判断
    }
    suffix = path.suffix.lower()
    if suffix in {".sh", ".bash", ".zsh", ".ksh", ".fish", ".ps1", ".bat", ".cmd", ".exe", ".com"}:
        return True
    # .py 只有带 shebang 才视为可执行脚本（大多数项目里的 .py 是库模块）
    if suffix == ".py":
        try:
            with path.open("rb") as handle:
                return handle.read(2) == b"#!"
        except OSError:
            return False
    # 无扩展名的脚本：看 shebang
    if not suffix:
        try:
            with path.open("rb") as handle:
                return handle.read(2) == b"#!"
        except OSError:
            return False
    # Unix 上尊重真实的可执行位（Windows 上 os.access 不可靠，已在上方单独处理）
    if os.name == "posix":
        return os.access(path, os.X_OK)
    return False


def _find_git() -> str | None:
    """定位可用的 git 可执行文件。除 PATH 外还检查 GitHub Desktop 自带的 Git（常被安装但不加入 PATH）。"""
    found = shutil.which("git")
    if found:
        return found
    candidates = [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Git" / "cmd" / "git.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Git" / "cmd" / "git.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Git" / "cmd" / "git.exe",
    ]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.extend(sorted(Path(local).glob("GitHubDesktop/app-*/resources/app/git/cmd/git.exe"), reverse=True))
    for candidate in candidates:
        try:
            if candidate.is_file():
                return str(candidate)
        except OSError:
            continue
    return None


# Git 对象读写
def hash_object(obj_type: str, content: bytes) -> tuple[str, bytes]:
    """计算对象 SHA-1 并返回 zlib 压缩内容。地址 = SHA1('<type> <length>\0' + content)，存于 objects/<前2位>/<后38位>。"""
    header = f"{obj_type} {len(content)}".encode() + b"\x00"
    payload = header + content
    digest = hashlib.sha1(payload).hexdigest()
    return digest, zlib.compress(payload, 9)


class ObjectStore:
    """把对象写进 ``.git/objects``（仅实现写入，不做去重的复杂优化）。"""

    def __init__(self, git_dir: Path) -> None:
        self.git_dir = git_dir
        self.written: dict[str, str] = {}

    def write(self, obj_type: str, content: bytes) -> str:
        digest, compressed = hash_object(obj_type, content)
        if digest in self.written:
            return digest
        target = self.git_dir / "objects" / digest[:2] / digest[2:]
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(compressed)
        self.written[digest] = obj_type
        return digest

    def write_blob(self, data: bytes) -> str:
        return self.write("blob", data)

    def write_tree(self, entries: list["TreeEntry"]) -> str:
        """写 tree 对象。条目格式 <mode> <name>\0<20 字节二进制 SHA>，且必须按 name 的字节序排序，否则 git fsck 报错。"""
        payload = bytearray()
        for entry in sorted(entries, key=lambda e: e.sort_key):
            payload += entry.mode.encode() + b" " + entry.name.encode("utf-8") + b"\x00"
            payload += bytes.fromhex(entry.sha)
        return self.write("tree", bytes(payload))

    def write_commit(
        self,
        tree_sha: str,
        parents: list[str],
        author: str,
        email: str,
        message: str,
        timestamp: int,
        timezone_offset: str,
    ) -> str:
        """写 commit 对象。"""
        lines = [f"tree {tree_sha}"]
        for parent in parents:
            lines.append(f"parent {parent}")
        identity = f"{author} <{email}> {timestamp} {timezone_offset}"
        lines.append(f"author {identity}")
        lines.append(f"committer {identity}")
        lines.append("")
        body = "\n".join(lines) + "\n" + message.rstrip("\n") + "\n"
        return self.write("commit", body.encode("utf-8"))


@dataclass
class TreeEntry:
    """tree 中的一个条目。"""

    name: str
    mode: str  # "100644" 普通文件 / "100755" 可执行 / "40000" 目录
    sha: str

    @property
    def sort_key(self) -> bytes:
        """Git 对目录名按“目录名 + /”排序，这里用等价规则近似实现。"""
        suffix = b"/" if self.mode == "40000" else b""
        return self.name.encode("utf-8") + suffix


# .gitignore 匹配
class IgnoreMatcher:
    """把 .gitignore 编译成正则判断路径是否忽略。顺序敏感：后出现的规则优先，故 !pattern 可取反。"""

    def __init__(self, patterns: list[str] | None = None) -> None:
        self.rules: list[tuple[re.Pattern[str], bool, bool]] = []
        for raw in patterns or []:
            self.add(raw)

    def add(self, raw: str) -> None:
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            return
        negated = line.startswith("!")
        if negated:
            line = line[1:]
        if not line:
            return

        anchored = line.startswith("/")
        if anchored:
            line = line[1:]
        dir_only = line.endswith("/")
        if dir_only:
            line = line[:-1]

        regex = self._translate(line, anchored=anchored, dir_only=dir_only)
        self.rules.append((re.compile(regex), negated, dir_only))

    @staticmethod
    def _translate(pattern: str, *, anchored: bool, dir_only: bool) -> str:
        """把 glob 语法翻译成正则。"""
        out: list[str] = []
        index = 0
        length = len(pattern)
        while index < length:
            char = pattern[index]
            if char == "*":
                if pattern[index : index + 2] == "**":
                    # ** 跨目录；**/ 表示"任意层级"
                    if pattern[index : index + 3] == "**/":
                        out.append("(?:.*/)?")
                        index += 3
                        continue
                    out.append(".*")
                    index += 2
                    continue
                out.append("[^/]*")
            elif char == "?":
                out.append("[^/]")
            elif char == "[":
                end = pattern.find("]", index + 1)
                if end == -1:
                    out.append(re.escape(char))
                else:
                    body = pattern[index + 1 : end]
                    if body.startswith("!"):
                        body = "^" + body[1:]
                    out.append(f"[{body}]")
                    index = end
            else:
                out.append(re.escape(char))
            index += 1

        joined = "".join(out)
        # 未锚定的模式可以匹配任意层级；目录模式还要能匹配其下所有内容
        prefix = "" if anchored else "(?:.*/)?"
        suffix = "(?:/.*)?" if dir_only else "(?:/.*)?"
        return f"^{prefix}{joined}{suffix}$"

    def match(self, rel_path: str) -> bool:
        """判断相对路径是否被忽略（后出现的规则优先）。"""
        path = rel_path.replace("\\", "/").rstrip("/")
        ignored = False
        for regex, negated, _dir_only in self.rules:
            if regex.match(path):
                ignored = not negated
        return ignored

    @classmethod
    def from_file(cls, path: Path) -> "IgnoreMatcher":
        if not path.is_file():
            return cls([])
        return cls(path.read_text(encoding="utf-8", errors="replace").splitlines())


# 工作区扫描与提交
@dataclass
class RepoBuilder:
    """读取工作区、构造 tree、创建首个提交。"""

    root: Path
    branch: str = "main"
    author: str = "CodeGuard Developer"
    email: str = "developer@example.com"
    message: str = ""
    max_file_bytes: int = 5 * 1024 * 1024
    extra_ignores: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.git_dir = self.root / ".git"
        self.store = ObjectStore(self.git_dir)
        # 忽略规则来自 .gitignore，并叠加运行时产物与调用方传入的额外模式
        self.matcher = IgnoreMatcher.from_file(self.root / ".gitignore")
        for pattern in (".git/", "*.pyc", ".codeguard_tmp/", *self.extra_ignores):
            self.matcher.add(pattern)
        # 提交时间在构造时固定，供 commit 对象与 reflog 共用，
        # 避免两处时间戳不一致而让 git status 产生多余判断
        now = datetime.now().astimezone()
        self.timestamp = int(now.timestamp())
        self.timezone_offset = now.strftime("%z") or "+0000"
        #: 由 :meth:`build_tree` 填充，供 ``git read-tree`` 生成索引使用
        self.tree_sha: str = ""
        #: 索引是否由真实 Git 生成（False 表示本机没有 Git，索引待 Git 首次运行时重建）
        self.index_written_by_git: bool = True

    def build_tree(self, directory: Path) -> str:
        """递归构造目录对应的 tree 对象。目录本身也要先做忽略判断，否则 .codeguard_tmp/ 之类仍会被递归进去。"""
        entries: list[TreeEntry] = []
        try:
            children = sorted(directory.iterdir(), key=lambda p: p.name)
        except OSError as exc:
            self.skipped.append(f"{self._show(directory)}（无法读取：{exc}）")
            return self.store.write_tree([])

        for child in children:
            if child.name in HARD_SKIP_DIRS:
                continue
            relative = child.relative_to(self.root).as_posix()
            if self.matcher.match(relative):
                continue
            if child.is_symlink():
                self.skipped.append(f"{relative}（符号链接，跳过）")
                continue
            if child.is_dir():
                sub_sha = self.build_tree(child)
                entries.append(TreeEntry(name=child.name, mode="40000", sha=sub_sha))
                continue
            if not child.is_file():
                self.skipped.append(f"{relative}（非普通文件，跳过）")
                continue
            if not self._stage_file(child, relative, entries):
                continue
        return self.store.write_tree(entries)

    def _show(self, path: Path) -> str:
        """把路径显示为相对仓库根的形式，避免日志里出现本机绝对路径。"""
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def _stage_file(self, child: Path, relative: str, entries: list[TreeEntry]) -> bool:
        """读取文件并写入 blob，成功则追加 tree 条目。"""
        try:
            size = child.stat().st_size
        except OSError as exc:
            self.skipped.append(f"{relative}（无法读取大小：{exc}）")
            return False
        if size > self.max_file_bytes:
            self.skipped.append(f"{relative}（{size} 字节，超过单文件上限）")
            return False
        try:
            data = child.read_bytes()
        except OSError as exc:
            self.skipped.append(f"{relative}（读取失败：{exc}）")
            return False
        # 二进制内容对 Git 完全合法，这里不做文本假设
        blob_sha = self.store.write_blob(data)
        mode = "100755" if _is_executable(child, relative) else "100644"
        entries.append(TreeEntry(name=child.name, mode=mode, sha=blob_sha))
        return True

    def write_metadata(self, commit_sha: str) -> None:
        """
        写 HEAD / config / refs / logs / description 等元数据。
        所有 Git 元数据文件必须用 LF 行尾：Windows 上 write_text 会写成 CRLF，而 Git 把多余的 \r 当作垃圾字符并报警。
        """
        self.git_dir.mkdir(parents=True, exist_ok=True)
        for sub in ("objects", "refs/heads", "refs/tags", "info", "hooks", "logs/refs/heads"):
            (self.git_dir / sub).mkdir(parents=True, exist_ok=True)

        self._write_text("HEAD", f"ref: refs/heads/{self.branch}\n")
        self._write_text(f"refs/heads/{self.branch}", f"{commit_sha}\n")
        self._write_text("description", "CodeGuard —— 基于 LLM 工具调用的代码审查 Agent\n")
        self._write_text(
            "config",
            "[core]\n"
            "\trepositoryformatversion = 0\n"
            "\tfilemode = false\n"
            "\tbare = false\n"
            "\tlogallrefupdates = true\n"
            "\tsymlinks = false\n"
            "\tignorecase = true\n"
            f"[user]\n\tname = {self.author}\n\temail = {self.email}\n",
        )
        self._write_text("info/exclude", "# 由 tools/init_repo.py 生成\n*.pyc\n__pycache__/\n")
        self._write_reflogs(commit_sha)

    def _write_text(self, relative: str, content: str) -> None:
        """按 Git 的要求写文本文件：UTF-8 无 BOM、LF 行尾。"""
        target = self.git_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content.encode("utf-8"))

    def _write_reflogs(self, commit_sha: str) -> None:
        """
        写 reflog。reflog 非必需，但部分 GUI（libgit2 封装）依赖它判断分支状态。
        格式：<旧 SHA> <新 SHA> <作者> <时间戳> <时区>\t<说明>；时间戳与 commit 保持一致。
        """
        identity = f"{self.author} <{self.email}> {self.timestamp} {self.timezone_offset}"
        zero = "0" * 40
        entry = f"{zero} {commit_sha} {identity}\tcommit (initial): {self.subject}\n"
        self._write_text("logs/HEAD", entry)
        self._write_text(f"logs/refs/heads/{self.branch}", entry)

    @property
    def subject(self) -> str:
        """提交信息的第一行（用作 reflog 说明）。"""
        message = self.message or "feat: CodeGuard —— 基于 LLM 工具调用的代码审查 Agent"
        return message.strip().splitlines()[0]

    def write_index(self) -> int:
        """
        生成索引，使 git status 立即显示为干净。索引交给 Git 自己写（git read-tree），而不是手写。
        踩坑记录：索引条目「固定区 62 字节 + 文件名补齐到 8 字节」看似正确，自研解析器能完美读回，
        但真实 Git 以不同步长前进并报 fatal: unknown index entry format —— 解析器与写入器共享同一错误假设，属于自证正确。
        故委托 Git 生成索引（只读对象库、不读工作区）；本机无 Git 时不写索引，Git 首次运行时会自动重建。
        """
        file_count = self._collect_index_paths()
        if not self._index_via_git():
            self.index_written_by_git = False
        return file_count

    def _collect_index_paths(self) -> int:
        """统计应纳入索引的文件数（供输出提示使用）。"""
        count = 0
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            relative = path.relative_to(self.root).as_posix()
            if self.matcher.match(relative):
                continue
            try:
                if path.stat().st_size > self.max_file_bytes:
                    continue
            except OSError:
                continue
            count += 1
        return count

    def _index_via_git(self) -> bool:
        """调用 ``git read-tree`` 生成索引。成功返回 True。"""
        executable = _find_git()
        if executable is None or not self.tree_sha:
            return False
        try:
            completed = subprocess.run(
                [executable, "-C", str(self.root), "read-tree", self.tree_sha],
                capture_output=True,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0

    def create_commit(self) -> tuple[str, int, list[str]]:
        """构造 tree 与首个 commit，返回 ``(commit_sha, 文件数, 跳过列表)``。"""
        tree_sha = self.build_tree(self.root)
        self.tree_sha = tree_sha
        message = self.message or "feat: CodeGuard —— 基于 LLM 工具调用的代码审查 Agent"
        commit_sha = self.store.write_commit(
            tree_sha=tree_sha,
            parents=[],
            author=self.author,
            email=self.email,
            message=message,
            timestamp=self.timestamp,
            timezone_offset=self.timezone_offset,
        )
        self.write_metadata(commit_sha)
        file_count = self.write_index()
        return commit_sha, file_count, self.skipped


# CLI
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="init_repo.py",
        description="在没有安装 Git 的机器上创建真正的 Git 仓库（纯标准库实现）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "创建完成后，在装有 Git 的机器上即可直接使用：\n"
            "  git log --oneline\n"
            "  git remote add origin https://github.com/<用户名>/<仓库名>.git\n"
            "  git push -u origin main\n"
        ),
    )
    parser.add_argument("--root", default=str(REPO_ROOT), help="仓库根目录，默认脚本所在项目")
    parser.add_argument("--branch", default="main", help="初始分支名，默认 main")
    parser.add_argument("--name", default="", help="提交者姓名（默认从环境变量或占位值）")
    parser.add_argument("--email", default="", help="提交者邮箱")
    parser.add_argument("--message", default="", help="提交信息")
    parser.add_argument("--force", action="store_true", help="若 .git 已存在则先删除再重建")
    parser.add_argument("--ignore", action="append", default=[], metavar="模式", help="额外忽略模式，可重复")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"❌ 目录不存在：{root}", file=sys.stderr)
        return 2

    git_dir = root / ".git"
    if git_dir.exists():
        if not args.force:
            print(f"❌ {git_dir} 已存在。如需重建请加 --force", file=sys.stderr)
            return 2
        import shutil

        shutil.rmtree(git_dir, ignore_errors=True)

    author = args.name or os.environ.get("GIT_AUTHOR_NAME") or "CodeGuard Developer"
    email = args.email or os.environ.get("GIT_AUTHOR_EMAIL") or "developer@example.com"

    builder = RepoBuilder(
        root=root,
        branch=args.branch,
        author=author,
        email=email,
        message=args.message,
        extra_ignores=list(args.ignore),
    )
    commit_sha, file_count, skipped = builder.create_commit()

    print(f"✅ 已创建 Git 仓库：{git_dir}")
    print(f"   分支　　：{args.branch}")
    print(f"   提交　　：{commit_sha[:12]}  {author} <{email}>")
    print(f"   纳入文件：{file_count} 个")
    if builder.index_written_by_git:
        print("   索引　　：已由本机 Git 生成（可直接 `git status` 看到干净工作区）")
    else:
        print("   索引　　：本机未检测到 Git，未写索引")
        print("             （对象与引用均正确；Git 首次运行时会自动重建索引）")
    if skipped:
        print(f"   跳过文件：{len(skipped)} 个")
        for item in skipped[:10]:
            print(f"      · {item}")
        if len(skipped) > 10:
            print(f"      …另有 {len(skipped) - 10} 个")
    print()
    print("下一步（在装有 Git 的机器上执行）：")
    print("   git log --oneline")
    print("   git fsck")
    print("   git remote add origin https://github.com/<用户名>/<仓库名>.git")
    print("   git push -u origin " + args.branch)
    return 0


if __name__ == "__main__":
    sys.exit(main())
