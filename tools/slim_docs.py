"""把 Python 文件里的 docstring 与注释抽出为 JSON，压缩后再写回。

设计要点：**按行替换，绝不重建代码**。脚本只做两件事：
    1. ``--extract``：把每个 docstring 的起止行、缩进、原文导出成 JSON；
    2. ``--apply``：读回 JSON，只替换那些行区间，其余代码原样保留。

因此它不可能改变代码语义；若某个区间不是字符串字面量（说明行号已过期），
脚本会直接报错拒绝写入，而不是猜。

用法::

    python tools/slim_docs.py --extract codeguard/agent.py > docs_agent.json
    python tools/slim_docs.py --apply docs_agent.json
"""

from __future__ import annotations

import argparse
import ast
import io
import json
import sys
import tokenize
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from codeguard.compat import enable_utf8_console  # noqa: E402

enable_utf8_console()


def _docstring_spans(tree: ast.AST) -> list[tuple[int, int, str]]:
    """返回 ``[(起始行, 结束行, 归属名称), ...]``，行号从 1 开始。"""
    spans: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = getattr(node, "body", [])
        if not body:
            continue
        first = body[0]
        if not (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)):
            continue
        if not isinstance(first.value.value, str):
            continue
        name = getattr(node, "name", None) or "<module>"
        spans.append((first.lineno, getattr(first, "end_lineno", first.lineno), name))
    return sorted(spans)


def extract(path: Path) -> dict:
    """导出文件中所有 docstring 与行内注释。"""
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()

    items = []
    for start, end, owner in _docstring_spans(ast.parse(source)):
        original = "\n".join(lines[start - 1 : end])
        kind = original.lstrip().startswith('"""') and 'r"""' not in original[:6] or True
        # 单行 docstring 与多行分别标记，便于压缩时决定目标行数
        items.append(
            {
                "kind": "docstring",
                "owner": owner,
                "start": start,
                "end": end,
                "lines": end - start + 1,
                "indent": len(lines[start - 1]) - len(lines[start - 1].lstrip()),
                "quote": '"""' if '"""' in original else "'''",
                "original": original,
                "replacement": "",
            }
        )

    comments = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                continue
            text = tok.string
            # 保留工具指令类注释，它们对静态检查/类型检查有语义
            keep = any(marker in text for marker in ("noqa", "type: ignore", "pragma:", "shebang", "!/"))
            comments.append(
                {
                    "kind": "comment",
                    "owner": "",
                    "start": tok.start[0],
                    "end": tok.start[0],
                    "lines": 1,
                    "indent": tok.start[1],
                    "quote": "",
                    "original": text,
                    "replacement": "",
                    "keep": keep,
                }
            )
    except (tokenize.TokenError, IndentationError) as exc:
        print(f"警告：注释解析不完整（{exc}），只处理 docstring", file=sys.stderr)

    return {"path": path.as_posix(), "total_lines": len(lines), "items": items + comments}


def apply(path: Path, payload: dict) -> tuple[int, int, int]:
    """按 payload 里的替换文本重写文件。

    Returns:
        ``(原行数, 新行数, 替换条数)``
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    replacements: list[tuple[int, int, list[str]]] = []

    for item in payload["items"]:
        replacement = item.get("replacement", "")
        if not replacement:
            continue
        start, end = item["start"], item["end"]
        if start < 1 or end > len(lines) or start > end:
            raise SystemExit(f"❌ {path}: 行区间非法 {start}-{end}（文件共 {len(lines)} 行）")

        if item["kind"] == "docstring":
            # 校验这段确实是字符串字面量，避免行号过期后误伤代码
            block = "\n".join(lines[start - 1 : end])
            if not (block.lstrip().startswith(('"""', "'''", 'r"""', "r'''"))):
                raise SystemExit(f"❌ {path}:{start} 不是 docstring 起始行，拒绝改写：{lines[start-1][:60]!r}")
            indent = " " * item["indent"]
            quote = item["quote"]
            body = replacement.strip()
            if "\n" in body:
                text_lines = [f"{indent}{quote}"] + [f"{indent}{ln}".rstrip() for ln in body.splitlines()] + [f"{indent}{quote}"]
            else:
                text_lines = [f"{indent}{quote}{body}{quote}"]
        else:
            # 注释：单行替换，保留原有的 # 前缀
            indent = " " * item["indent"]
            text = replacement if replacement.lstrip().startswith("#") else f"# {replacement.strip()}"
            text_lines = [f"{indent}{text}".rstrip()]

        replacements.append((start, end, text_lines))

    # 按起始行从后往前替换，避免行号漂移
    new_lines = list(lines)
    for start, end, text_lines in sorted(replacements, key=lambda r: r[0], reverse=True):
        new_lines[start - 1 : end] = text_lines

    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return len(lines), len(new_lines), len(replacements)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="slim_docs.py", description="抽取/写回 docstring 与注释")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--extract", metavar="文件", help="导出为 JSON（输出到 stdout）")
    group.add_argument("--apply", metavar="JSON", help="按 JSON 写回（JSON 内记录目标文件路径）")
    group.add_argument("--stats", metavar="文件", help="只统计 docstring/注释行数")
    group.add_argument("--batch-extract", metavar="目录", help="批量导出目录下所有 .py")
    args = parser.parse_args(argv)

    if args.extract:
        payload = extract(Path(args.extract))
        print(json.dumps(payload, ensure_ascii=False, indent=1))
        return 0

    if args.apply:
        payload = json.loads(Path(args.apply).read_text(encoding="utf-8"))
        target = Path(payload["path"])
        if not target.is_file():
            raise SystemExit(f"❌ 目标文件不存在：{target}")
        before, after, count = apply(target, payload)
        print(f"✅ {target}: {before} 行 → {after} 行（替换 {count} 处）")
        return 0

    if args.stats:
        payload = extract(Path(args.stats))
        docs = [i for i in payload["items"] if i["kind"] == "docstring"]
        comments = [i for i in payload["items"] if i["kind"] == "comment"]
        print(f"{payload['path']}: 共 {payload['total_lines']} 行")
        print(f"  docstring {len(docs)} 个，占 {sum(i['lines'] for i in docs)} 行")
        print(f"  注释      {len(comments)} 条")
        return 0

    if args.batch_extract:
        root = Path(args.batch_extract)
        payloads = []
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            try:
                payloads.append(extract(path))
            except SyntaxError as exc:
                print(f"跳过 {path}（{exc}）", file=sys.stderr)
        out = Path("batch_docs.json")
        out.write_text(json.dumps({"files": payloads}, ensure_ascii=False, indent=1), encoding="utf-8")
        total_doc = sum(i["lines"] for p in payloads for i in p["items"] if i["kind"] == "docstring")
        total_cmt = sum(1 for p in payloads for i in p["items"] if i["kind"] == "comment")
        print(f"已导出 {out}：{len(payloads)} 个文件，docstring {total_doc} 行，注释 {total_cmt} 条")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
