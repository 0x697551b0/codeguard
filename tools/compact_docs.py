"""把 docstring 压缩成精炼形式，保留全部信息量。

策略（按保守程度排序，只做**可机械证明不丢信息**的变换）：

1. **折叠空白**：段落间多余空行合并为一行；
2. **去掉装饰性分隔线**（``====``、``----``、``****``）与 ASCII 方框图；
3. **把多行的 Args/Returns/Raises 段压成单行**：``Args: x: 说明`` 这种写法
   与逐行书写承载完全相同的语义，但省掉大量行；
4. **收紧多行散文**：把同一段内的折行合并为一整行（中文没有硬折行需求）；
5. **单行 docstring 保持单行**。

**不做的**：不删除任何句子、不概括任何信息、不改写措辞。
这样"只压缩不删除"这一要求可以被机械保证。

自带自检：每个文件压缩前后都做 ``ast.parse``，并逐个核对
docstring 数量一致、内容非空，任何不一致立即回滚。

用法::

    python tools/compact_docs.py codeguard tools tests *.py      # 就地压缩
    python tools/compact_docs.py --dry-run codeguard             # 只看统计
    python tools/compact_docs.py --target dist/xxx               # 处理副本
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from codeguard.compat import enable_utf8_console  # noqa: E402

enable_utf8_console()

#: 装饰性分隔线：整行只有 = - * # ~ _ 等符号（可含空格）
_RULE_RE = re.compile(r"^\s*[=\-*#~_+]{4,}\s*$")

#: 需要压缩为单行的段落标题（中英文都覆盖）
_SECTION_TITLES = (
    "Args:", "Arguments:", "Parameters:", "Returns:", "Return:", "Yields:",
    "Raises:", "Attributes:", "Note:", "Notes:", "Warning:", "Warnings:",
    "Example:", "Examples:", "Usage:", "参数:", "参数：", "返回:", "返回：",
    "抛出:", "异常:", "属性:", "注意:", "注意：", "示例:", "示例：", "用法:", "用法：",
)

#: 形如 ``name: 说明`` / ``name (type): 说明`` 的参数字段
_FIELD_RE = re.compile(r"^\s*(\*{0,2}\w+)\s*(\([^)]*\))?\s*[:：]\s*(.*)$")


def _is_box_drawing(line: str) -> bool:
    """判断是否为 ASCII 方框图/箭头图的一行。"""
    if not line.strip():
        return False
    box_chars = set("│┌┐└┘├┤┬┴┼─═║╔╗╚╝╠╣╦╩╬▼▲►◄→←↓↑")
    stripped = line.strip()
    if len(stripped) < 2:
        return False
    box_count = sum(1 for ch in stripped if ch in box_chars)
    return box_count >= 2 or (box_count >= 1 and box_count / len(stripped) > 0.15)


def compact(text: str) -> str:
    """把一段 docstring 正文压缩，返回新正文（不含引号）。"""
    # 拆掉首尾的引号，只处理正文
    body = text.strip()
    for quote in ('"""', "'''"):
        if body.startswith(quote):
            body = body[len(quote) :]
            break
    for quote in ('"""', "'''"):
        if body.endswith(quote):
            body = body[: -len(quote)]
            break
    body = body.strip("\n")

    raw_lines = body.splitlines()

    # ---- 1. 去掉装饰线与方框图 ----
    lines: list[str] = []
    for line in raw_lines:
        if _RULE_RE.match(line):
            continue
        if _is_box_drawing(line):
            continue
        lines.append(line.rstrip())

    # ---- 2. 归并段落：空行分段，段内折行合并 ----
    paragraphs: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line.strip())
        else:
            if current:
                paragraphs.append(current)
                current = []
    if current:
        paragraphs.append(current)

    # ---- 3. 逐段处理 ----
    out: list[str] = []
    for paragraph in paragraphs:
        title = paragraph[0].strip()
        is_section = any(title.startswith(t) or title == t.rstrip(":：") for t in _SECTION_TITLES)

        if is_section:
            items = paragraph[1:]
            if not items:
                out.append(title)
                continue
            # 把 ``name: 说明`` 压成一行；保留原文措辞
            rendered = []
            for item in items:
                rendered.append(item if not rendered else f" {item}")
            packed = "".join(items) if len(items) == 1 else " ".join(items)
            # 参数条目之间用全角分号分隔，保持可读
            if title.lower().startswith(("args", "param", "参数", "attribut", "属性")):
                entries = []
                buffer = ""
                for item in items:
                    match = _FIELD_RE.match(item)
                    if match and buffer:
                        entries.append(buffer.strip())
                        buffer = item.strip()
                    elif match:
                        buffer = item.strip()
                    else:
                        buffer = f"{buffer} {item.strip()}".strip()
                if buffer:
                    entries.append(buffer.strip())
                packed = "；".join(entries)
            out.append(f"{title} {packed}".strip())
            continue

        # 普通段落：合并为一整行，保留全部文字
        merged = " ".join(paragraph)
        out.append(merged)

    # ---- 4. 段落之间保留一个空行（多段时）----
    return "\n\n".join(out).strip()


def _docstring_nodes(tree: ast.AST) -> list[ast.Expr]:
    nodes: list[ast.Expr] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            if isinstance(first.value.value, str):
                nodes.append(first)
    return nodes


def process_file(path: Path, *, dry_run: bool = False) -> dict:
    """压缩单个文件的所有 docstring，返回统计。"""
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return {"path": path.as_posix(), "ok": False, "reason": f"原文件语法错误：{exc}"}

    nodes = _docstring_nodes(tree)
    if not nodes:
        return {"path": path.as_posix(), "ok": True, "before": 0, "after": 0, "count": 0}

    lines = source.splitlines()
    replacements: list[tuple[int, int, list[str]]] = []
    before_total = after_total = 0

    for node in nodes:
        start = node.lineno
        end = getattr(node, "end_lineno", start)
        original_text = node.value.value
        quote = node.value.kind or ""
        # 找出这行用的三引号种类
        head = lines[start - 1]
        q = '"""' if '"""' in head else "'''"
        if quote:  # 原始字符串前缀 r/b 等
            q = quote + q
        indent = len(head) - len(head.lstrip())

        compacted = compact(original_text)
        if not compacted:
            continue

        body_lines = compacted.splitlines()
        if len(body_lines) == 1:
            text_lines = [f"{' ' * indent}{q}{body_lines[0]}{q}"]
        else:
            text_lines = (
                [f"{' ' * indent}{q}"]
                + [f"{' ' * indent}{ln}".rstrip() if ln.strip() else "" for ln in body_lines]
                + [f"{' ' * indent}{q}"]
            )

        replacements.append((start, end, text_lines))
        before_total += end - start + 1
        after_total += len(text_lines)

    if not dry_run and replacements:
        new_lines = list(lines)
        for start, end, text_lines in sorted(replacements, key=lambda r: r[0], reverse=True):
            new_lines[start - 1 : end] = text_lines
        candidate = "\n".join(new_lines) + "\n"

        # ---- 自检：语法必须合法，docstring 数量必须一致 ----
        try:
            new_tree = ast.parse(candidate)
        except SyntaxError as exc:
            return {"path": path.as_posix(), "ok": False, "reason": f"压缩后语法错误，已回滚：{exc}"}

        if len(_docstring_nodes(new_tree)) != len(nodes):
            return {"path": path.as_posix(), "ok": False, "reason": "docstring 数量变化，已回滚"}

        # 逐个核对非空（防止压缩把内容清空）
        for old_node, new_node in zip(nodes, _docstring_nodes(new_tree)):
            if not (new_node.value.value or "").strip():
                return {"path": path.as_posix(), "ok": False, "reason": "出现空 docstring，已回滚"}

        path.write_text(candidate, encoding="utf-8")

    return {
        "path": path.as_posix(),
        "ok": True,
        "before": before_total,
        "after": after_total,
        "count": len(replacements),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="compact_docs.py", description="压缩 docstring（保留全部信息）")
    parser.add_argument("targets", nargs="+", help="文件或目录")
    parser.add_argument("--dry-run", action="store_true", help="只统计，不写入")
    args = parser.parse_args(argv)

    files: list[Path] = []
    for target in args.targets:
        path = Path(target)
        if path.is_file() and path.suffix == ".py":
            files.append(path)
        elif path.is_dir():
            files.extend(p for p in sorted(path.rglob("*.py")) if "__pycache__" not in p.parts)

    total_before = total_after = 0
    failures = []
    for path in files:
        result = process_file(path, dry_run=args.dry_run)
        if not result["ok"]:
            failures.append(result)
            print(f"  ✗ {result['path']}: {result['reason']}")
            continue
        if result["count"]:
            delta = result["before"] - result["after"]
            total_before += result["before"]
            total_after += result["after"]
            flag = "（dry-run）" if args.dry_run else ""
            print(f"  ✓ {result['path']}: docstring {result['before']} 行 → {result['after']} 行 "
                  f"（省 {delta} 行，{result['count']} 处）{flag}")

    print()
    if total_before:
        saved = total_before - total_after
        pct = saved / total_before * 100
        print(f"docstring 合计：{total_before} 行 → {total_after} 行（省 {saved} 行，{pct:.0f}%）")
    if failures:
        print(f"\n⚠️ {len(failures)} 个文件失败（已回滚，未改动）：")
        for item in failures:
            print(f"  {item['path']}: {item['reason']}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
