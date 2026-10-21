"""
跨平台兼容辅助：控制台编码、可写临时目录、打印降级。

1) enable_utf8_console：Windows 默认 GBK，输出 emoji/表格会抛 UnicodeEncodeError，所有入口统一切 UTF-8；
2) writable_tempdir：受限环境下系统 TEMP 可能不可写，且 mkdtemp 在 Unix 建 0700 目录会被沙箱拒绝写入子项，
   改为用普通 mkdir 在「已验证可写」的候选根下创建；3) safe_print：无法切换编码时也不让程序崩溃。
"""

from __future__ import annotations

import os
import shutil
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

#: 项目根目录（本文件位于 ``<root>/codeguard/compat.py``）
PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: 已解析出的临时目录根缓存
_TEMP_ROOT: Path | None = None


def enable_utf8_console() -> None:
    """把 stdout/stderr 切为 UTF-8 并设 errors='replace'；不支持 reconfigure 的流保持原样。"""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - 取决于宿主环境
            continue


def _is_writable(directory: Path) -> bool:
    """真实地验证目录可写（创建并写入一个探测文件后清理）。"""
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / f".cg_probe_{uuid.uuid4().hex}"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True
    except (OSError, PermissionError):
        return False


def _temp_candidates() -> Iterator[Path]:
    """生成临时目录候选位置（按优先级）。统一放在 .codeguard_tmp/ 下，一条 .gitignore 规则即可排除干净。"""
    base = PROJECT_ROOT / ".codeguard_tmp"
    for env_name in ("CODEGUARD_TMPDIR", "TMPDIR", "TEMP", "TMP"):
        value = os.environ.get(env_name)
        if value:
            yield Path(value) / "codeguard"
    yield base


def resolve_temp_root() -> Path:
    """返回第一个真正可写的临时目录根并缓存。系统 TEMP 优先，回退项目内 .codeguard_tmp/，都不可写则明确抛错。"""
    global _TEMP_ROOT
    if _TEMP_ROOT is not None and _TEMP_ROOT.is_dir():
        return _TEMP_ROOT

    tried: list[str] = []
    for candidate in _temp_candidates():
        tried.append(str(candidate))
        if _is_writable(candidate):
            _TEMP_ROOT = candidate
            return candidate

    raise OSError(  # pragma: no cover - 极端受限环境
        "找不到可写的临时目录。已尝试：\n  - " + "\n  - ".join(tried)
    )


@contextmanager
def writable_tempdir(prefix: str = "cg_") -> Iterator[Path]:
    """
    创建确实可写的临时目录，退出时尽力清理。
    与 tempfile.TemporaryDirectory 的区别：用 mkdir 而非 mkdtemp（避免 0700 权限），清理失败不抛异常。
    """
    root = resolve_temp_root()
    for _ in range(20):
        path = root / f"{prefix}{uuid.uuid4().hex[:12]}"
        try:
            path.mkdir()
        except FileExistsError:  # pragma: no cover - 随机名冲突概率极低
            continue
        except OSError:  # pragma: no cover - 磁盘/权限问题
            break
        try:
            yield path
        finally:
            shutil.rmtree(path, ignore_errors=True)
        return

    raise OSError(f"无法在 {root} 下创建临时目录")  # pragma: no cover


#: 兼容别名：早期版本叫 workspace_tempdir
workspace_tempdir = writable_tempdir


def safe_print(text: str = "") -> None:
    """打印文本，遇到编码问题自动降级为可显示字符。"""
    try:
        print(text)
    except UnicodeEncodeError:  # pragma: no cover - 仅在异常环境下触发
        encoding = getattr(sys.stdout, "encoding", None) or "ascii"
        print(text.encode(encoding, errors="replace").decode(encoding, errors="replace"))


def is_ci() -> bool:
    """判断是否运行在 CI 环境（用于跳过需要网络的测试）。"""
    return any(os.environ.get(name) for name in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL"))


