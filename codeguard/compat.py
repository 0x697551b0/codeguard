"""跨平台兼容辅助：控制台编码、临时目录、ASCII 回退。

该模块解决三类在真实环境中反复出现、但很容易被忽视的问题：

1. **控制台编码**：Windows 默认代码页是 GBK，向管道写入 emoji 或表格字符会抛
   ``UnicodeEncodeError``。本项目输出大量中文与 emoji，因此所有入口都统一调用
   :func:`enable_utf8_console` 把标准流切换为 UTF-8。

2. **可写的临时目录**：``tempfile.TemporaryDirectory`` 在部分受限环境（企业策略、
   容器只读挂载、某些沙箱）下不可用 —— 系统 TEMP 可能拒绝写入，而
   ``tempfile.mkdtemp`` 会在 Unix 上创建 **0700** 权限的目录，遇到按权限位
   裁决的沙箱时其子目录会被拒绝写入。:func:`writable_tempdir` 改为用普通
   ``mkdir``（继承父目录权限）在**已验证可写**的候选根下创建目录，因此适应性更强。

3. **打印降级**：无法切换编码时，:func:`safe_print` 保证不会因为一个字符让程序崩溃。
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
    """把 stdout/stderr 切换为 UTF-8；不支持时静默忽略。

    对不支持 ``reconfigure`` 的流（例如被包装的重定向对象）保持原样，
    并设置 ``errors='replace'`` 保证任何字符都不会导致崩溃。
    """
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
    """生成临时目录候选位置（按优先级）。

    候选都统一放在项目的 ``.codeguard_tmp/`` 之下（而不是散落在仓库根目录），
    这样只需一条 ``.gitignore`` 规则就能把全部临时产物排除干净。
    """
    base = PROJECT_ROOT / ".codeguard_tmp"
    for env_name in ("CODEGUARD_TMPDIR", "TMPDIR", "TEMP", "TMP"):
        value = os.environ.get(env_name)
        if value:
            yield Path(value) / "codeguard"
    yield base


def resolve_temp_root() -> Path:
    """返回第一个真正可写的临时目录根（结果会被缓存）。

    优先使用系统临时目录；不可用时回退到项目内的 ``.codeguard_tmp/``。
    两者都不可写时抛错 —— 与其在后续代码里抛出难以定位的异常，
    不如在这里明确失败。
    """
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
    """创建**确实可写**的临时目录，退出时尽力清理。

    与 ``tempfile.TemporaryDirectory`` 的两点差异：
        * 使用 ``mkdir`` 而非 ``mkdtemp``，避免 0700 权限在受限沙箱下无法写入子项；
        * 清理失败不会抛异常（受限环境拒绝删除是常态，不应视为测试失败）。
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


